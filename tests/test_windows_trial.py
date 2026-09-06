"""Experimental Windows path must never silently reuse macOS/ambient defaults."""

import getpass
import json
from types import SimpleNamespace

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.direct_network import DirectNetworkUnavailable


def test_shared_tcp_network_requires_platform_binding():
    from litechecker.direct_network import TCPDirectNetwork, MacDirectNetwork
    assert issubclass(MacDirectNetwork, TCPDirectNetwork)
    with pytest.raises(NotImplementedError):
        TCPDirectNetwork()._validate_interface()


@pytest.mark.asyncio
async def test_explicit_network_failure_never_uses_mac_or_measures(monkeypatch):
    from litechecker import direct_check
    called = []

    async def unavailable():
        called.append("windows")
        raise DirectNetworkUnavailable("interface_changed")

    async def forbidden(*args, **kwargs):
        pytest.fail("must not use a different platform or start measurement")

    monkeypatch.setattr(direct_check.MacDirectNetwork, "discover", forbidden)
    monkeypatch.setattr(direct_check, "measure_cycle", forbidden)
    settings = SimpleNamespace(identity=AgentIdentity("test", "City", "PC", 600))
    result = await direct_check.run_trial(
        settings, network_factory=unavailable, platform_label="Windows · эксперимент",
    )
    assert called == ["windows"]
    assert not result.available
    assert "Windows" in result.text
    assert "не выполнена" in result.text


def test_windows_local_settings_need_no_telegram_and_ignore_environment(tmp_path, monkeypatch):
    from litechecker.windows_trial import load_settings, save_configuration
    monkeypatch.setenv("LC_SUBSCRIPTION_URL", "https://wrong.invalid/sub")
    monkeypatch.setenv("LC_TELEGRAM_BOT_TOKEN", "must-not-be-used")
    save_configuration(tmp_path, {"subscription_url": "https://example.com/test"})
    settings = load_settings(tmp_path, "xray.exe")
    assert settings.agent.subscription_url.get_secret_value() == "https://example.com/test"
    assert settings.telegram_bot_token is None
    assert settings.telegram_chat_id is None
    assert settings.state_dir == tmp_path / "windows-state"
    again = load_settings(tmp_path, "xray.exe")
    assert again.identity.agent_id == settings.identity.agent_id
    assert settings.agent.allow_private_targets is False
    assert settings.agent.max_concurrency == 4


def test_windows_configuration_rejects_unsafe_input_without_printing_secrets(tmp_path):
    from litechecker.windows_trial import save_configuration
    for payload in (
        {"subscription_url": "http://secret.invalid/private"},
        {"subscription_url": "https://example.com", "allow_private_targets": True},
        {"subscription_url": "https://user:password@example.com/private"},
        {"subscription_url": "https://@example.com/private"},
        {"subscription_url": "https://:@example.com/private"},
    ):
        with pytest.raises(ValueError) as error:
            save_configuration(tmp_path, payload)
        assert "private" not in str(error.value)
    assert not (tmp_path / "windows-state" / "settings.json").exists()


def test_windows_configuration_uses_visible_input_without_redisplaying_values(tmp_path, monkeypatch, capsys):
    from litechecker import windows_trial

    subscription = "https://subscription.invalid/private"
    token = "123456:" + "A" * 30
    proxy = "socks5://user:private-password@proxy.invalid:1080"
    responses = iter((subscription, token, "12345", proxy))
    prompts = []

    def visible_input(prompt):
        prompts.append(prompt)
        return next(responses)

    monkeypatch.setattr("builtins.input", visible_input)
    monkeypatch.setattr(getpass, "getpass", lambda _prompt: pytest.fail("Windows input must be visible"))
    windows_trial.configure(tmp_path, telegram=True)

    assert json.loads((tmp_path / "windows-state" / "settings.json").read_bytes()) == {
        "subscription_url": subscription,
        "telegram_bot_token": token,
        "telegram_chat_id": "12345",
        "telegram_proxy_url": proxy,
    }
    output = capsys.readouterr().out
    assert output.index("Ссылка подписки") < output.index("Токен бота") < output.index("ID чата") < output.index("Прокси Telegram")
    assert "скрыт" not in output
    assert all(value not in output for value in (subscription, token, proxy))


def test_windows_cli_rejects_non_windows_before_setup_or_network(tmp_path, monkeypatch, capsys):
    from litechecker import windows_trial
    monkeypatch.setattr(windows_trial.sys, "platform", "darwin")
    assert windows_trial.main(["--root", str(tmp_path)]) == 2
    assert "Windows" in capsys.readouterr().out
    assert not (tmp_path / "windows-state").exists()


def test_atomic_state_write_without_unix_fchmod(tmp_path, monkeypatch):
    import json
    from litechecker import state
    monkeypatch.delattr(state.os, "fchmod", raising=False)
    destination = tmp_path / "state.json"
    state._atomic_write_json(destination, {"ok": True})
    assert json.loads(destination.read_text()) == {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", [False, True])
async def test_windows_trial_end_validation_invalidates_even_successful_results(tmp_path, monkeypatch, changed):
    import json
    from datetime import UTC, datetime
    from litechecker import direct_check
    from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus

    class Network:
        interface = "Ethernet"
        def _validate_interface(self):
            if changed:
                raise DirectNetworkUnavailable("interface_changed")

    class Relay:
        proxy_url = "socks5://fake:fake@127.0.0.1:1"
        def __init__(self, network):
            assert isinstance(network, Network)
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass

    async def factory():
        return Network()

    async def exit_lookup(**kwargs):
        return direct_check.ExitObservation("1.1.1.1")

    async def measured(*args):
        return AgentReport(
            event_id="test:boot:1", agent_id="test", boot_id="boot", sequence=1,
            observed_at=datetime.now(UTC), duration_ms=1, control_status=ResultStatus.UP,
            results=[ProbeResult(target_id="one", label="Test", address="1.1.1.1",
                                 port=443, status=ResultStatus.UP, stage=ProbeStage.E2E)],
        )

    monkeypatch.setattr(direct_check, "DirectRelay", Relay)
    monkeypatch.setattr(direct_check, "lookup_exit", exit_lookup)
    monkeypatch.setattr(direct_check, "scoped_dependencies", lambda *args: object())
    monkeypatch.setattr(direct_check, "measure_cycle", measured)
    settings = SimpleNamespace(agent=object(), identity=AgentIdentity("test", "City", "PC", 600), state_dir=tmp_path)
    result = await direct_check.run_trial(
        settings, network_factory=factory, platform_label="Windows · эксперимент", validate_after=True,
    )
    assert "Windows" in result.text
    assert "macOS" not in result.text
    assert result.available is (not changed)
    assert result.report.results[0].status is (ResultStatus.UNKNOWN if changed else ResultStatus.UP)
    saved = json.loads((tmp_path / "last-observation.json").read_text())
    assert saved["vpn_bypass_confirmed"] is False
    if changed:
        assert saved["report"]["run_reason"] == "direct-interface-changed"
        assert saved["report"]["results"][0]["latency_ms"] is None


@pytest.mark.asyncio
async def test_windows_execute_opt_in_factory_and_removes_stale_success(tmp_path, monkeypatch):
    from litechecker import windows_trial, windows_network
    from litechecker.direct_check import TrialResult
    windows_trial.save_configuration(tmp_path, {"subscription_url": "https://example.com/test"})
    settings = windows_trial.load_settings(tmp_path, "xray.exe")
    old = settings.state_dir / "last-observation.json"
    old.write_text('{"old":true}')
    calls = []

    async def trial(received, **kwargs):
        assert not old.exists()
        calls.append(kwargs)
        assert received is settings
        return TrialResult("Windows: не выполнена", False)

    monkeypatch.setattr(windows_trial, "run_trial", trial)
    result = await windows_trial.execute(settings)
    assert result.available is False
    assert calls[0]["send"] is False
    assert calls[0]["network_factory"] == windows_network.WindowsDirectNetwork.discover
    assert calls[0]["validate_after"] is True
    assert (settings.state_dir / "last-report.txt").read_text(encoding="utf-8") == result.text + "\n"
    assert not old.exists()


@pytest.mark.asyncio
async def test_missing_telegram_configuration_refuses_before_measurement(tmp_path, monkeypatch):
    from litechecker import windows_trial
    windows_trial.save_configuration(tmp_path, {"subscription_url": "https://example.com/test"})
    settings = windows_trial.load_settings(tmp_path, "xray.exe")
    async def forbidden(*args, **kwargs):
        pytest.fail("no measurement when requested delivery is not configured")
    monkeypatch.setattr(windows_trial, "run_trial", forbidden)
    with pytest.raises(ValueError, match="Telegram"):
        await windows_trial.execute(settings, send=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("delivery", ["accepted", "error", "timeout", "not-requested"])
async def test_windows_delivery_preserves_current_report_and_records_acceptance(tmp_path, monkeypatch, delivery):
    import asyncio
    from litechecker import windows_trial
    from litechecker.direct_check import TrialResult

    token = "123456:" + "A" * 30
    proxy = "socks5://user:private-password@proxy.example:1080"
    windows_trial.save_configuration(tmp_path, {
        "subscription_url": "https://example.com/test",
        "telegram_bot_token": token, "telegram_chat_id": "12345",
        "telegram_proxy_url": proxy,
    })
    settings = windows_trial.load_settings(tmp_path, "xray.exe")
    report_file = settings.state_dir / "last-report.txt"
    report_file.write_text("previous report must disappear")
    current = TrialResult("🧪 Текущий отчёт Windows\nРезультат текущей проверки", True, report=object())
    calls = []
    interrupted = []

    async def trial(received, **kwargs):
        assert received is settings
        assert kwargs["send"] is False
        assert not report_file.exists()
        (settings.state_dir / "last-observation.json").write_text('{"current":true}')
        return current

    class Sender:
        def __init__(self, **kwargs):
            # Persist exactly this measurement before any Telegram setup/send.
            assert report_file.read_text(encoding="utf-8") == current.text + "\n"
            calls.append(kwargs)

        async def send_chunks(self, chunks):
            assert list(chunks) == [current.text]
            assert report_file.read_text(encoding="utf-8") == current.text + "\n"
            if delivery == "error":
                raise RuntimeError(f"secret URL: {token} {proxy}")
            if delivery == "timeout":
                try:
                    await asyncio.Future()
                finally:
                    interrupted.append(True)

    monkeypatch.setattr(windows_trial, "run_trial", trial)
    monkeypatch.setattr(windows_trial, "TelegramClient", Sender, raising=False)
    monkeypatch.setattr(windows_trial, "_TELEGRAM_SEND_TIMEOUT_SECONDS", 0.01, raising=False)
    result = await windows_trial.execute(settings, send=delivery != "not-requested")
    assert result.text == current.text
    assert result.report is current.report
    assert result.available is True
    assert report_file.read_text(encoding="utf-8") == current.text + "\n"
    assert (settings.state_dir / "last-observation.json").read_text() == '{"current":true}'
    assert result.delivery_accepted is (None if delivery == "not-requested" else delivery == "accepted")
    if delivery == "not-requested":
        assert calls == []
    else:
        assert calls == [{"token": token, "chat_id": "12345", "topic_id": None, "proxy_url": proxy, "max_attempts": 1}]
    assert interrupted == ([True] if delivery == "timeout" else [])


@pytest.mark.parametrize("accepted,available,expected_code", [(True, True, 0), (False, True, 1), (True, False, 1)])
def test_windows_cli_prints_saved_report_and_truthful_delivery_status(tmp_path, monkeypatch, capsys, accepted, available, expected_code):
    from litechecker import windows_trial
    from litechecker.direct_check import TrialResult

    token = "123456:" + "A" * 30
    proxy = "socks5://user:private-password@proxy.example:1080"
    windows_trial.save_configuration(tmp_path, {
        "subscription_url": "https://example.com/test",
        "telegram_bot_token": token, "telegram_chat_id": "12345",
        "telegram_proxy_url": proxy,
    })
    current = "🧪 Актуальный отчёт после измерения"

    async def trial(*args, **kwargs):
        return TrialResult(current, available)

    class Sender:
        def __init__(self, **kwargs):
            pass

        async def send_chunks(self, chunks):
            if not accepted:
                raise RuntimeError(f"{token} {proxy}")

    monkeypatch.setattr(windows_trial.sys, "platform", "win32")
    monkeypatch.setattr(windows_trial, "run_trial", trial)
    monkeypatch.setattr(windows_trial, "TelegramClient", Sender, raising=False)
    assert windows_trial.main(["--root", str(tmp_path), "--send"]) == expected_code
    output = capsys.readouterr()
    assert current in output.out
    assert str(tmp_path / "windows-state" / "last-report.txt") in output.out
    assert ("Telegram: отчёт принят." in output.out) is accepted
    if not accepted:
        assert "отправка не подтверждена" in output.out
    assert token not in output.out + output.err
    assert proxy not in output.out + output.err
    assert "private-password" not in output.out + output.err

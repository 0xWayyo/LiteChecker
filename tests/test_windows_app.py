import asyncio
import base64
from collections import deque
import json
from pathlib import Path
import subprocess
import sys


class FakeControls:
    def __init__(self, states, *, start_result=None, stop_result=None, update_result=None):
        self.states = deque(states)
        self.current = states[-1]
        self.calls = []
        self.start_result = start_result or {"status": "started"}
        self.stop_result = stop_result or {"status": "stopped"}
        self.update_result = update_result or {"status": "current"}

    def status(self, root):
        if self.states:
            self.current = self.states.popleft()
        return dict(self.current)

    async def start(self, root):
        self.calls.append(("start", Path(root)))
        return self.start_result

    async def stop(self, root):
        self.calls.append(("stop", Path(root)))
        return self.stop_result

    async def request_update(self, root):
        self.calls.append(("update", Path(root)))
        return self.update_result


def answers(*items):
    values = iter(items)
    return lambda _prompt="": next(values)


def test_real_isolated_entry_normalizes_redirected_ansi_streams_before_onboarding(tmp_path):
    entry = Path(__file__).resolve().parents[1] / "scripts" / "windows-app-entry.py"
    wrapper = (
        "import io,runpy,sys;"
        "sys.stdin=io.TextIOWrapper(sys.stdin.buffer,encoding='utf-8');"
        "sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='cp1251');"
        "sys.stderr=io.TextIOWrapper(sys.stderr.buffer,encoding='cp1251');"
        "sys.argv=[sys.argv[1],'menu','--root',sys.argv[2]];"
        "runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", wrapper, str(entry), str(tmp_path)],
        input=b"https://subscription.invalid/test\n\n0\n",
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "┌─ LiteChecker Windows" in result.stdout.decode("utf-8")
    assert "Ссылка подписки HTTPS" in result.stderr.decode("utf-8")
    assert b"https://subscription.invalid/test" not in result.stdout + result.stderr
    assert (tmp_path / "windows-state" / "settings.json").is_file()


def test_main_menu_dynamic_start_stop_and_close_does_not_stop(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([
        {"state": "stopped", "version": "0.5.0"},
        {"state": "running", "version": "0.5.0", "pid": 42},
        {"state": "running", "version": "0.5.0", "pid": 42},
    ])
    output = []

    assert run_menu(tmp_path, controls=controls, input_fn=answers("1", "1", "0"), output_fn=output.append) == 0
    assert controls.calls == [("start", tmp_path), ("stop", tmp_path)]
    text = "\n".join(output)
    assert "Запустить мониторинг" in text
    assert "Остановить мониторинг" in text


def test_menu_eof_and_invalid_choice_are_safe(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([{"state": "stopped"}] * 3)
    values = iter(("wrong",))

    def input_fn(_prompt=""):
        try:
            return next(values)
        except StopIteration:
            raise EOFError

    output = []
    assert run_menu(tmp_path, controls=controls, input_fn=input_fn, output_fn=output.append) == 0
    assert controls.calls == []
    assert "Нет такого пункта" in output


def test_main_and_settings_menus_use_bounded_actions(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([{"state": "stopped"}] * 8)
    calls = []
    output = []

    async def diagnostics(root):
        calls.append(("diagnostics", Path(root)))

    def configure(root, *, telegram=False):
        calls.append(("telegram" if telegram else "subscription", Path(root)))

    run_menu(
        tmp_path,
        controls=controls,
        input_fn=answers("4", "3", "1", "2", "3", "0", "0"),
        output_fn=output.append,
        configure_fn=configure,
        diagnostics_fn=diagnostics,
    )

    assert calls == [
        ("subscription", tmp_path),
        ("telegram", tmp_path),
        ("diagnostics", tmp_path),
    ]
    assert ("update", tmp_path) in controls.calls


def test_first_run_prompts_once_but_existing_settings_do_not(tmp_path):
    from litechecker.windows_app import ensure_initial_settings

    calls = []
    ensure_initial_settings(
        tmp_path, configure_fn=lambda root, telegram=False: calls.append((Path(root), telegram)),
        input_fn=lambda _prompt: "",
    )
    assert calls == [(tmp_path, False)]
    state = tmp_path / "windows-state"
    state.mkdir()
    (state / "settings.json").write_text("{}")
    ensure_initial_settings(
        tmp_path, configure_fn=lambda root, telegram=False: calls.append((Path(root), telegram)),
        input_fn=lambda _prompt: "1",
    )
    assert calls == [(tmp_path, False)]


def test_first_run_can_optionally_configure_telegram(tmp_path):
    from litechecker.windows_app import ensure_initial_settings

    calls = []
    ensure_initial_settings(
        tmp_path, configure_fn=lambda root, telegram=False: calls.append(telegram),
        input_fn=lambda _prompt: "1",
    )
    assert calls == [False, True]


def test_subscription_menu_preserves_telegram_secrets(tmp_path, monkeypatch):
    import json
    from litechecker.windows_app import run_menu
    from litechecker.windows_trial import save_configuration

    token = "123456:" + "A" * 30
    save_configuration(tmp_path, {
        "subscription_url": "https://old.example/sub",
        "telegram_bot_token": token,
        "telegram_chat_id": "12345",
    })
    monkeypatch.setattr("litechecker.windows_trial.getpass.getpass", lambda _prompt: "https://new.example/sub")
    controls = FakeControls([{"state": "stopped"}] * 4)

    run_menu(tmp_path, controls=controls, input_fn=answers("3", "1", "0", "0"), output_fn=lambda _line: None)

    values = json.loads((tmp_path / "windows-state" / "settings.json").read_text())
    assert values["subscription_url"] == "https://new.example/sub"
    assert values["telegram_bot_token"] == token
    assert values["telegram_chat_id"] == "12345"


def test_settings_stop_running_monitor_and_leave_it_stopped(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([
        {"state": "running"},
        {"state": "running"},
        {"state": "stopped"},
        {"state": "stopped"},
    ])
    configured = []
    run_menu(
        tmp_path, controls=controls, input_fn=answers("3", "1", "0", "0"),
        output_fn=lambda _line: None,
        configure_fn=lambda root, telegram=False: configured.append(telegram),
    )
    assert controls.calls == [("stop", tmp_path)]
    assert configured == [False]


def test_settings_do_not_change_when_stop_fails(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([{"state": "running"}] * 3, stop_result={"status": "failed"})
    configured = []
    output = []
    run_menu(
        tmp_path, controls=controls, input_fn=answers("3", "1", "0", "0"),
        output_fn=output.append,
        configure_fn=lambda root, telegram=False: configured.append(telegram),
    )
    assert configured == []
    assert any(line.startswith("Настройки не изменены") for line in output)


def test_unknown_status_refreshes_instead_of_starting(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([{"state": "unknown"}] * 2)
    output = []
    run_menu(tmp_path, controls=controls, input_fn=answers("1", "0"), output_fn=output.append)
    assert controls.calls == []
    assert "Обновить статус" in "\n".join(output)


def test_failed_update_is_not_reported_as_success(tmp_path):
    from litechecker.windows_app import run_menu

    controls = FakeControls([{"state": "stopped"}] * 2, update_result={"status": "failed"})
    output = []
    run_menu(tmp_path, controls=controls, input_fn=answers("4", "0"), output_fn=output.append)
    assert "Не получилось проверить обновления" in output


def channel(key: bytes) -> bytes:
    return json.dumps({
        "schema": 1,
        "enabled": True,
        "public_key": base64.b64encode(key).decode(),
        "manifest_urls": ["https://updates.example/release.json"],
    }).encode()


def test_bundled_channel_initializes_once_without_replacing_trust(tmp_path):
    from litechecker.windows_app import ensure_update_channel

    source = tmp_path / "update-channel.json"
    source.write_bytes(channel(b"a" * 32))
    assert ensure_update_channel(tmp_path) is True
    installed = tmp_path / ".updates" / "channel.json"
    assert json.loads(installed.read_bytes())["public_key"] == base64.b64encode(b"a" * 32).decode()

    installed.write_bytes(channel(b"b" * 32))
    source.write_bytes(channel(b"c" * 32))
    assert ensure_update_channel(tmp_path) is False
    assert json.loads(installed.read_bytes())["public_key"] == base64.b64encode(b"b" * 32).decode()


def test_missing_bundled_channel_stays_gracefully_unconfigured(tmp_path):
    from litechecker.windows_app import ensure_update_channel

    assert ensure_update_channel(tmp_path) is False
    assert not (tmp_path / ".updates").exists()


def test_busy_update_message_explains_stopped_monitor_state():
    from litechecker.windows_app import _update_message

    assert _update_message({"status": "busy"}) == (
        "Обновление выполняется. Запустите мониторинг после его завершения"
    )

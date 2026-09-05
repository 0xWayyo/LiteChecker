"""The trial must not label scoped traffic as a proven ISP/VPN bypass."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


def report():
    return AgentReport(
        event_id="test:boot:1", agent_id="test", boot_id="boot", sequence=1,
        observed_at=datetime(2026, 9, 5, tzinfo=UTC), duration_ms=20,
        control_status=ResultStatus.UP,
        results=[ProbeResult(target_id="one", label="Test", address="1.1.1.1",
                             port=443, status=ResultStatus.UP, stage=ProbeStage.E2E)],
    )


def test_successful_scoped_report_never_claims_isp_or_vpn_bypass():
    from litechecker.direct_check import ExitObservation, format_trial
    identity = AgentIdentity("test", "City", "Computer", 600)
    observation = ExitObservation("1.1.1.1", "City", "AS123 Network")
    text = format_trial(report(), identity, "en0", observation, observation)
    assert "Всё доступно" not in text
    assert "Обход VPN не подтверждён" in text
    assert "совпадает" in text
    assert "доступны: 1" in text
    assert "en0" in text


def test_different_public_ip_still_not_proof_for_every_target():
    from litechecker.direct_check import ExitObservation, format_trial
    text = format_trial(report(), AgentIdentity("test", "City", "PC", 600), "en0",
                        ExitObservation("1.1.1.1"), ExitObservation("8.8.8.8"))
    assert "отличается" in text
    assert "Обход VPN не подтверждён" in text


def test_route_failures_are_unknown_not_server_down():
    from litechecker.direct_check import uncertain_results
    original = report().results[0].model_copy(update={
        "status": ResultStatus.DOWN, "stage": ProbeStage.TCP,
        "error_code": "tcp-timeout", "latency_ms": 4,
    })
    result = uncertain_results([original], {"one": "direct-tcp:interface_binding_failed"})[0]
    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.POLICY
    assert result.error_code == "direct-tcp:interface_binding_failed"
    assert result.latency_ms is None
    assert original.status is ResultStatus.DOWN


def test_incomplete_trial_never_returns_success_exit():
    from litechecker.direct_check import trial_completed
    assert trial_completed(report())
    assert not trial_completed(report().model_copy(update={
        "run_status": ResultStatus.UNKNOWN, "run_reason": "xray-version-mismatch",
    }))
    assert not trial_completed(report().model_copy(update={"results": uncertain_fixture()}))


def test_scoped_pipeline_uses_variant_aware_subscription_parser(tmp_path):
    from litechecker.direct_check import scoped_dependencies, trial_settings
    from litechecker.direct_subscription import parse_trial_subscription
    from litechecker.config import StandaloneSettings
    from litechecker.models import SnapshotDiff
    from litechecker.config import AgentSettings
    from pydantic import SecretStr
    settings = StandaloneSettings(
        agent=AgentSettings(agent_id="test", agent_token="lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
                            collector_url="https://collector.example.com", subscription_url="https://example.com/s",
                            state_key="k" * 32),
        identity=AgentIdentity("test", "City", "PC", 600), state_dir=tmp_path,
        telegram_bot_token=SecretStr("123456789:abcdefghijklmnopqrstuvwxyz12345"), telegram_chat_id="-1234",
    )
    class Relay:
        proxy_url = "socks5://user:password@127.0.0.1:10001"
    dependencies = scoped_dependencies(settings, object(), Relay())
    assert dependencies.parser is parse_trial_subscription


def uncertain_fixture():
    return [report().results[0].model_copy(update={
        "status": ResultStatus.UNKNOWN, "stage": ProbeStage.POLICY,
        "error_code": "direct-route-unavailable",
    })]


@pytest.mark.asyncio
async def test_discovery_failure_does_not_start_probes_and_can_notify(monkeypatch):
    from litechecker import direct_check
    from litechecker.config import StandaloneSettings
    from litechecker.direct_network import DirectNetworkUnavailable

    async def unavailable():
        raise DirectNetworkUnavailable("direct-interface-unavailable")

    class Telegram:
        chunks = []
        async def send_chunks(self, chunks):
            self.chunks.extend(chunks)

    monkeypatch.setattr(direct_check.MacDirectNetwork, "discover", unavailable)
    settings = StandaloneSettings.model_construct(identity=AgentIdentity("test", "City", "PC", 600))
    telegram = Telegram()
    result = await direct_check.run_trial(settings, send=True, telegram=telegram)
    assert result.available is False
    assert "не выполнена" in result.text
    assert "VPN" in result.text
    assert telegram.chunks == [result.text]


def test_trial_configuration_is_separate_and_does_not_execute_dotenv(tmp_path):
    from litechecker.direct_check import trial_settings
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir(mode=0o700)
    for name, value in (("telegram_bot_token", "123456789:abcdefghijklmnopqrstuvwxyz12345"),
                        ("subscription_url", "https://example.com/sub-private")):
        path = secret_dir / name
        path.write_text(value)
        path.chmod(0o600)
    (tmp_path / ".env.standalone").write_text("LC_AGENT_ID='other-device'\nMALICIOUS=$(touch owned)\n")
    settings = trial_settings(tmp_path, "/path/xray", environment={})
    assert settings.state_dir == tmp_path / "state" / "direct-trial"
    assert settings.identity.agent_id != "other-device"
    assert not (tmp_path / "owned").exists()
    assert not (tmp_path / "state" / "standalone").exists()


@pytest.mark.asyncio
async def test_ipinfo_invalid_or_redirect_does_not_become_exit_identity():
    import httpx
    from litechecker.direct_check import lookup_exit
    for response in (httpx.Response(302, headers={"location": "https://untrusted.invalid"}),
                     httpx.Response(200, json={"ip": "127.0.0.1"}),
                     httpx.Response(200, json={"ip": "not-ip"})):
        assert await lookup_exit(transport=httpx.MockTransport(lambda request: response)) is None


@pytest.mark.asyncio
async def test_ipinfo_payload_is_bounded():
    import httpx
    from litechecker.direct_check import lookup_exit
    response = httpx.Response(200, content=b" " * 9000)
    assert await lookup_exit(transport=httpx.MockTransport(lambda request: response)) is None

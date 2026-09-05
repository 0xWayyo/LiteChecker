"""DIRECT failures describe their observed phase, not an invented Xray fault."""

from datetime import UTC, datetime

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


def report_with(code):
    return AgentReport(
        event_id="test:boot:1", agent_id="test", boot_id="boot", sequence=1,
        observed_at=datetime(2026, 9, 5, tzinfo=UTC), duration_ms=20,
        control_status=ResultStatus.UP,
        results=[ProbeResult(target_id="test-config", label="Test", address="example.com", port=443,
                             status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY, error_code=code)],
    )


def render(report):
    from litechecker.direct_check import ExitObservation, format_trial
    return format_trial(report, AgentIdentity("test", "City", "PC", 600), "en0",
                        ExitObservation("1.1.1.1"), ExitObservation("8.8.8.8"))


def test_dns_timeout_is_explained_as_dns_not_xray_or_destination_safety():
    text = render(report_with("direct-dns:direct_dns_timeout"))
    assert "DNS" in text
    assert "время ожидания" in text
    assert "direct_dns_timeout" in text
    assert "ошибка локального Xray" not in text
    assert "адрес не прошёл проверку безопасности" not in text


def test_local_binding_failure_does_not_claim_server_down():
    text = render(report_with("direct-tcp:interface_binding_failed"))
    assert "привязать" in text
    assert "интерфейсу" in text
    assert "отказ сервера не установлен" in text


def test_unknown_result_warns_about_incomplete_coverage_even_if_run_status_up():
    text = render(report_with("direct-dns:direct_dns_timeout"))
    assert "неполный" in text


def test_unrecognized_error_code_is_not_echoed_as_a_diagnostic():
    secret = "123456789:untrusted-secret-value"
    text = render(report_with("direct-dns:" + secret))
    assert secret not in text


@pytest.mark.asyncio
async def test_completed_cycle_is_saved_before_telegram_send_fails(tmp_path, monkeypatch):
    import json
    from litechecker import direct_check
    from litechecker.config import StandaloneSettings

    class Network:
        interface = "en0"

    class Relay:
        proxy_url = "socks5://user:password@127.0.0.1:10001"

        def __init__(self, network):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def discover():
        return Network()

    async def lookup_exit(**kwargs):
        return direct_check.ExitObservation("1.1.1.1")

    async def cycle(*args):
        return report_with("direct-dns:direct_dns_timeout")

    class Telegram:
        async def send_chunks(self, chunks):
            raise RuntimeError("test-delivery-unavailable")

    monkeypatch.setattr(direct_check.MacDirectNetwork, "discover", discover)
    monkeypatch.setattr(direct_check, "DirectRelay", Relay)
    monkeypatch.setattr(direct_check, "lookup_exit", lookup_exit)
    monkeypatch.setattr(direct_check, "scoped_dependencies", lambda *args: object())
    monkeypatch.setattr(direct_check, "measure_cycle", cycle)
    settings = StandaloneSettings.model_construct(
        state_dir=tmp_path, identity=AgentIdentity("test", "City", "PC", 600), agent=object(),
    )
    with pytest.raises(RuntimeError, match="test-delivery-unavailable"):
        await direct_check.run_trial(settings, send=True, telegram=Telegram())
    path = tmp_path / "last-observation.json"
    assert path.is_file(), "An unsuccessful Telegram send must not lose the measured result"
    assert json.loads(path.read_text())["report"]["results"][0]["error_code"] == "direct-dns:direct_dns_timeout"

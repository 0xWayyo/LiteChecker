"""Production DIRECT reports describe the measured exit, not the host VPN exit."""

from datetime import UTC, datetime

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message
from litechecker.direct_check import ExitObservation
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


NOW = datetime(2026, 9, 5, 2, 0, tzinfo=UTC)
IDENTITY = AgentIdentity("device-fixture", "Frankfurt", "Test Mac", 600)
SCOPED = ExitObservation("1.1.1.1", "Yerevan", "AS123 Test ISP")
ORDINARY = ExitObservation("8.8.8.8", "Frankfurt", "AS456 VPN")


def make_report(*, results=None, **changes):
    return AgentReport(
        event_id="device-fixture:boot:1", agent_id="device-fixture", boot_id="boot", sequence=1,
        observed_at=NOW, duration_ms=500, control_status=ResultStatus.UP,
        results=results if results is not None else [
            ProbeResult(target_id="vpn", label="Successful server", address="1.1.1.1", port=443,
                        status=ResultStatus.UP, stage=ProbeStage.E2E),
            ProbeResult(target_id="sni", label="Successful domain", address="example.com", port=443,
                        status=ResultStatus.UP, stage=ProbeStage.TLS, check_kind="sni"),
        ], **changes,
    )


def render(report, *, scoped=SCOPED, ordinary=ORDINARY):
    from litechecker.direct_reporting import format_direct
    return format_direct(report, IDENTITY, "en0", scoped, ordinary)


def test_healthy_report_is_short_and_never_uses_vpn_city_as_its_location():
    text = render(make_report())
    assert "DIRECT" in text and "macOS" in text and "пробный" not in text
    assert "Всё доступно" in text
    assert "Yerevan" in text and "AS123 · Test ISP" in text
    assert "Frankfurt" not in text and "AS456 VPN" not in text
    assert "en0" in text and "1.1.1.1" in text
    assert "Successful server" not in text and "Successful domain" not in text
    assert "VPN 1/1" in text and "SNI 1/1" in text
    assert "device-fixture" in text and "05.09.2026 02:00:00 UTC" in text
    assert len(text) < 350


@pytest.mark.parametrize("changes", [
    {"refresh_state": "STALE", "snapshot_age_seconds": 700},
    {"refresh_state": "UNAVAILABLE"},
    {"run_status": ResultStatus.UNKNOWN, "run_reason": "probe-incomplete"},
    {"dropped_report_count": 1},
    {"results": []},
])
def test_incomplete_evidence_does_not_claim_everything_available(changes):
    assert "Всё доступно" not in render(make_report(**changes))


def test_missing_scoped_exit_cannot_be_replaced_by_the_ordinary_vpn_exit():
    text = render(make_report(), scoped=None)
    assert "Всё доступно" not in text
    assert "Frankfurt" not in text
    assert "выход" in text.lower() and "не определ" in text.lower()


def test_mixed_report_separates_target_failure_from_local_dns_failure():
    results = [
        ProbeResult(target_id="failed-vpn", label="VPN failed", address="2.2.2.2", port=443,
                    status=ResultStatus.DOWN, stage=ProbeStage.VLESS_E2E, error_code="canary-timeout"),
        ProbeResult(target_id="unknown-sni", label="SNI", address="domain.example", port=443,
                    status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY, check_kind="sni",
                    error_code="direct-dns:direct_dns_timeout"),
    ]
    text = render(make_report(results=results))
    assert "Всё доступно" not in text
    assert "2.2.2.2:443" in text and "domain.example:443" in text
    assert "Не проверено: DNS — таймаут" in text
    assert "SNI: 1 · не проверены: 1" in text
    assert "ошибка локального Xray" not in text
    assert "SNI" in text and "VPN" in text


def test_matching_exit_does_not_claim_vpn_bypass():
    text = render(make_report(), ordinary=SCOPED)
    assert "совпадает" in text
    assert "Всё доступно · VPN 1/1 · SNI 1/1" in text
    assert "обход VPN" not in text


@pytest.mark.parametrize("sni_failed", [False, True])
def test_report_ends_with_device_id_without_generic_footnotes(sni_failed):
    report = make_report()
    if sni_failed:
        report = report.model_copy(update={"results": [
            report.results[0],
            report.results[1].model_copy(update={
                "status": ResultStatus.DOWN, "stage": ProbeStage.TLS_CERTIFICATE,
                "error_code": "tls-certificate",
            }),
        ]})
    text = render(report)
    assert "Привязка к интерфейсу" not in text
    assert "сам по себе не означает" not in text
    assert text.endswith("\n\nID: device-fixture · v?")
    if sni_failed:
        assert "SNI — проблемы через en0" in text
        assert "TLS: сертификат не прошёл проверку" in text
        assert "Всё доступно" not in text


def test_unavailable_report_carries_identity_and_time_but_not_raw_exception():
    from litechecker.direct_reporting import format_unavailable
    text = format_unavailable(IDENTITY, "secret-failure-http://test:private@example.com", NOW)
    assert "DIRECT" in text and "Test Mac" in text and "device-fixture" in text
    assert "05.09.2026 02:00:00 UTC" in text
    assert "Всё доступно" not in text and "не выполнена" in text
    assert "private" not in text and "secret-failure" not in text
    assert "отказ серверов не установлен" in text


def test_many_failure_results_remain_telegram_chunkable_without_losing_endpoints():
    results = [ProbeResult(target_id=f"domain-{i}", label=f"Problem {i}", address=f"test{i}.example", port=443,
                           status=ResultStatus.DOWN, stage=ProbeStage.TCP, error_code="tcp-timeout")
               for i in range(70)]
    chunks = chunk_message(render(make_report(results=results)))
    assert len(chunks) > 1 and all(len(chunk) <= 3500 for chunk in chunks)
    assert all(f"test{i}.example:443" in "".join(chunks) for i in range(70))


def test_failure_report_groups_context_and_keeps_each_explanation_with_its_target():
    results = [
        ProbeResult(target_id="a", label="Hong Kong", address="hk.example", port=443,
                    status=ResultStatus.DOWN, stage=ProbeStage.VLESS_E2E, error_code="canary-timeout"),
        ProbeResult(target_id="b", label="Mobile", address="2.2.2.2", port=443,
                    status=ResultStatus.DOWN, stage=ProbeStage.VLESS_E2E, error_code="canary-failed"),
    ]
    text = render(make_report(results=results))
    blocks = text.split("\n\n")
    assert blocks[0] == "⚠️ LiteChecker · Yerevan\nTest Mac · macOS · 05.09.2026 02:00:00 UTC"
    assert blocks[1] == (
        "DIRECT: en0 · 1.1.1.1 · AS123 · Test ISP\n"
        "Обычный выход: 8.8.8.8 — отличается"
    )
    assert blocks[2].startswith("- VPN: 2 (IP: 1 / домены: 1)")
    assert "\n- SNI: 0" in blocks[2]
    assert "VPN — проблемы:\n🔴 Hong Kong · hk.example:443\n│ " in text
    assert "\n\n🔴 Mobile · 2.2.2.2:443\n│ " in text
    assert "ID: device-fixture" in text


def test_unavailable_report_uses_compact_header_and_separate_explanation():
    from litechecker.direct_reporting import format_unavailable
    text = format_unavailable(IDENTITY, "direct-exit-unavailable", NOW)
    header, explanation, footer = text.split("\n\n")
    assert header == "⚠️ LiteChecker\nTest Mac · macOS · 05.09.2026 02:00:00 UTC"
    assert explanation.startswith("DIRECT: проверка не выполнена.\n")
    assert "Контроль выхода не прошёл" in explanation
    assert footer.startswith("ID: device-fixture · v")

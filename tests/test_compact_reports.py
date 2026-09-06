"""Compact reports retain identity, route, true counts and uncertain evidence."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message, format_report
from litechecker.direct_check import ExitObservation
from litechecker.direct_reporting import format_direct, format_unavailable
from litechecker.models import ProbeResult, ProbeStage, ResultStatus, SnapshotDiff
from test_direct_production_reporting import make_report


IDENTITY = AgentIdentity("device-fixture", "VPN city must not leak", "Mac Nikita", 600)
EXIT = ExitObservation("5.18.180.45", "Санкт-Петербург", "AS41733 JSC ER-Telecom Holding")
OTHER = ExitObservation("64.130.40.58")


@pytest.mark.parametrize("platform", ["macOS", "Windows"])
def test_healthy_direct_has_one_count_line_and_versioned_identity(platform):
    report = make_report(app_version="0.7.2").model_copy(update={
        "observed_at": datetime(2026, 9, 6, 23, 56, 23, tzinfo=timezone(timedelta(hours=2))),
    })
    text = format_direct(report, IDENTITY, "en0", EXIT, OTHER, platform_label=platform)
    assert text == (
        "✅ LiteChecker · Санкт-Петербург\n"
        f"Mac Nikita · {platform} · 06.09.2026 21:56:23 UTC\n\n"
        "DIRECT: en0 · 5.18.180.45 · AS41733 · JSC ER-Telecom Holding\n"
        "Обычный выход: 64.130.40.58 — отличается\n\n"
        "Всё доступно · VPN 1/1 · SNI 1/1\n\n"
        "ID: device-fixture · v0.7.2"
    )
    assert len(chunk_message(text)) == 1


def test_problem_counts_are_computed_not_copied_from_example():
    vpn = [ProbeResult(
        target_id=f"vpn-{i}", label=f"Server {i}", address=f"node-{i}.example", port=443,
        status=ResultStatus.UP, stage=ProbeStage.E2E,
    ) for i in range(44)]
    vpn[0] = vpn[0].model_copy(update={"status": ResultStatus.DOWN, "stage": ProbeStage.VLESS_E2E,
                                     "error_code": "canary-timeout"})
    vpn[1] = vpn[1].model_copy(update={"status": ResultStatus.DOWN, "stage": ProbeStage.VLESS_E2E,
                                     "error_code": "canary-failed"})
    sni = [ProbeResult(
        target_id=f"sni-{i}", label="SNI", address=f"sni-{i}.example", port=443, check_kind="sni",
        status=ResultStatus.UP, stage=ProbeStage.TLS,
    ) for i in range(20)]
    sni[0] = sni[0].model_copy(update={"status": ResultStatus.DOWN, "stage": ProbeStage.TLS_HANDSHAKE,
                                     "error_code": "tls-timeout"})
    text = format_direct(make_report(results=vpn+sni), IDENTITY, "en0", EXIT, OTHER)
    assert "VPN: 44 (IP: 0 / домены: 44) · доступны: 42, недоступны: 2" in text
    assert "SNI: 20 · доступны: 19, недоступны: 1" in text
    assert "Порт отвечает, VPN: таймаут" in text
    assert "Порт отвечает, VPN: контрольный HTTPS не прошёл" in text
    assert "Порт отвечает, TLS: таймаут" in text
    assert "node-2.example" not in text and "sni-1.example" not in text
    assert "Есть недоступные адреса" not in text


@pytest.mark.parametrize("changes,important", [
    ({"refresh_state": "STALE", "snapshot_age_seconds": 700}, "STALE"),
    ({"refresh_state": "UNAVAILABLE"}, "UNAVAILABLE"),
    ({"control_status": ResultStatus.UNKNOWN}, "Контрольный"),
    ({"run_status": ResultStatus.UNKNOWN, "run_reason": "deadline"}, "лимит времени"),
    ({"dropped_report_count": 2}, "потеряно отчётов: 2"),
    ({"results": []}, "неполная"),
])
def test_compaction_never_turns_incomplete_data_green(changes, important):
    text = format_direct(make_report().model_copy(update=changes), IDENTITY, "en0", EXIT, OTHER)
    assert text.startswith("⚠️") and "Всё доступно" not in text
    assert important in text


def test_unknown_dns_stays_unchecked_not_down_without_internal_code_noise():
    result = ProbeResult(target_id="unknown", label="DNS", address="sni.example", port=443,
                         check_kind="sni", status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY,
                         error_code="direct-dns:direct_dns_timeout")
    text = format_direct(make_report(results=[result], run_status=ResultStatus.UNKNOWN,
                                    run_reason="probe-incomplete"), IDENTITY, "en0", EXIT, OTHER)
    assert "❔ sni.example:443" in text
    assert "Не проверено: DNS — таймаут" in text
    assert "SNI: 1 · не проверены: 1" in text and "недоступны:" not in text
    assert "direct_dns_timeout" not in text


def test_changes_and_missing_ordinary_exit_remain_visible():
    report = make_report(diff=SnapshotDiff(added=["a"], removed=["b"], changed=["c"]))
    text = format_direct(report, IDENTITY, "en0", EXIT, None)
    assert "Подписка: +1 · −1 · изменено: 1" in text
    assert "Обычный выход: не определён" in text
    assert "совпадает" not in text and "отличается" not in text
    assert text.endswith("ID: device-fixture · v?")


def test_unavailable_is_short_and_cannot_claim_old_registry_city():
    text = format_unavailable(IDENTITY, "direct-network-changed", datetime(2026, 9, 6, tzinfo=UTC))
    assert text.startswith("⚠️ LiteChecker\nMac Nikita · macOS · 06.09.2026 00:00:00 UTC\n\n")
    assert "DIRECT: проверка не выполнена" in text
    assert "Сеть изменилась" in text and "отброшены" in text
    assert "VPN city" not in text and "Всё доступно" not in text
    assert len(text) < 360


def test_non_direct_success_is_compact_without_invented_route_or_platform():
    report = make_report(app_version="0.7.2")
    text = format_report(report, IDENTITY, received_at=report.observed_at)
    assert "Всё доступно · VPN 1/1 · SNI 1/1" in text
    assert "Mac Nikita · 05.09.2026 02:00:00 UTC" in text
    assert "DIRECT:" not in text and "macOS" not in text
    assert text.endswith("ID: device-fixture · v0.7.2")


def test_windows_interface_change_remains_visible_in_compact_unknown_report():
    report = make_report().model_copy(update={
        "run_status": ResultStatus.UNKNOWN, "run_reason": "direct-interface-changed",
        "results": [ProbeResult(
            target_id="one", address="node.example", port=443, label="Node",
            status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY, error_code="direct-interface-changed",
        )],
    })
    text = format_direct(report, IDENTITY, "Ethernet", EXIT, OTHER, platform_label="Windows")
    assert "Не проверено: интерфейс изменился" in text
    assert "Всё доступно" not in text and "не проверены: 1" in text
    assert "безопасност" not in text


@pytest.mark.parametrize("platform", ["Windows", "macOS"])
def test_automatic_device_os_suffix_is_not_repeated(platform):
    agent = AgentIdentity("agent-1", "City", f"Device ({platform})", 600)
    text = format_direct(make_report(), agent, "Ethernet", EXIT, OTHER, platform_label=platform)
    assert text.splitlines()[1].startswith(f"Device · {platform} · ")
    assert text.count(platform) == 1


def test_compact_fields_and_unknown_causes_still_redact_untrusted_content():
    agent = AgentIdentity("device-1", "Unused", "Device\nInjected\u202e", 600)
    scoped = ExitObservation("1.1.1.1", "City\nInjected", "AS123 Bearer secret-value")
    result = ProbeResult(target_id="one", label="Node", address="node.example", port=443,
                         status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY,
                         error_code="direct-dns:secret-token")
    text = format_direct(make_report(results=[result]), agent, "en0", scoped, None)
    assert "secret-value" not in text and "secret-token" not in text and "\u202e" not in text
    assert "City Injected" in text
    assert "Не проверено: DNS" in text

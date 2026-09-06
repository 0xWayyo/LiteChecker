from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message, format_offline, format_report
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus, SnapshotDiff


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
AGENT = AgentIdentity("agent-1", "Tbilisi", "Home ISP", 600)


def _result(
    number: int, status: ResultStatus, stage: ProbeStage, label: str, *, check_kind="vpn"
) -> ProbeResult:
    return ProbeResult(
        target_id=f"target-{number}",
        label=label,
        address=f"node-{number}.example",
        port=443,
        status=status,
        stage=stage,
        check_kind=check_kind,
        latency_ms=17 if status is ResultStatus.UP else None,
        error_code="proxy-connect" if status is not ResultStatus.UP else None,
    )


def _report() -> AgentReport:
    return AgentReport(
        event_id="event-1",
        agent_id="agent-1",
        boot_id="boot-1",
        sequence=7,
        observed_at=NOW,
        subscription_revision="abcdef0123456789" * 4,
        refresh_state="STALE",
        snapshot_age_seconds=601,
        diff=SnapshotDiff(added=["target-3"], removed=["target-0"], changed=["target-2"]),
        results=[
            _result(3, ResultStatus.UP, ProbeStage.E2E, "Success"),
            _result(2, ResultStatus.UNKNOWN, ProbeStage.XRAY, "Unknown"),
            _result(1, ResultStatus.DOWN, ProbeStage.TCP, "Failure"),
        ],
        control_status=ResultStatus.UP,
        duration_ms=321,
    )


def test_report_is_compact_russian_and_shows_only_failures():
    """Operators see failed checks and warnings without a successful-target dump."""
    rendered = format_report(
        _report(), AGENT, received_at=NOW, recovered=True
    )

    assert rendered.startswith("⚠️ LiteChecker · Tbilisi\n")
    assert "Home ISP" in rendered and "ID: agent-1 · v?" in rendered
    assert "04.09.2026 12:00:00 UTC" in rendered
    assert "(STALE): проверен сохранённый список, возраст 10 мин" in rendered
    assert "VPN: 3 (IP: 0 / домены: 3) · доступны: 1, недоступны: 1, не проверены: 1" in rendered
    assert "Агент снова на связи" in rendered
    assert "Подписка: +1 · −1 · изменено: 1" in rendered
    assert rendered.index("🔴 Failure") < rendered.index("❔ Unknown")
    assert "Success" not in rendered
    assert "node-3.example" not in rendered
    assert "target-3" not in rendered
    assert "Успешно:" not in rendered
    assert format_report(_report(), AGENT, received_at=NOW, recovered=True) == rendered


def test_report_strips_controls_and_redacts_credentials_from_display_fields():
    """Registry or probe display text must never turn into control sequences or credentials."""
    report = _report().model_copy(
        update={
            "results": [
                _result(
                    1,
                    ResultStatus.DOWN,
                    ProbeStage.TCP,
                    "Bad\u202e vless://user:pass@example/?token=secret Bearer private",
                )
            ]
        }
    )
    agent = AgentIdentity("agent-1", "Tbilisi\x00", "Home\nISP", 600)

    rendered = format_report(report, agent, received_at=NOW)

    assert "\x00" not in rendered
    assert "\u202e" not in rendered
    assert "vless://" not in rendered
    assert "secret" not in rendered
    assert "Bearer private" not in rendered
    assert "[URL REDACTED]" in rendered
    assert "Bearer [REDACTED]" in rendered


def test_chunks_are_numbered_and_under_3500_unicode_characters():
    """Chunk numbering itself must not push Telegram messages over the safety cap."""
    long_report = "\n".join(f"Строка {index}: " + "я" * 500 for index in range(30))

    chunks = chunk_message(long_report, limit=3500)

    assert len(chunks) > 1
    assert all(len(chunk) <= 3500 for chunk in chunks)
    assert chunks[0].startswith(f"[1/{len(chunks)}]\n")
    assert chunks[-1].startswith(f"[{len(chunks)}/{len(chunks)}]\n")
    restored = "".join(chunk.split("\n", 1)[1] for chunk in chunks)
    assert restored == long_report


def test_chunker_hard_splits_one_oversized_unicode_line_without_corruption():
    """A single long target label must be split by Unicode characters, never bytes."""
    text = "🚦" * 101

    chunks = chunk_message(text, limit=40)

    assert len(chunks) > 1
    assert all(len(chunk) <= 40 for chunk in chunks)
    assert "".join(chunk.split("\n", 1)[1] for chunk in chunks) == text


def test_offline_message_uses_trusted_agent_and_utc_times():
    """Offline alerts need actionable identity and timing without report-controlled labels."""
    text = format_offline(
        AGENT,
        last_seen=NOW,
        offline_since=datetime(2026, 9, 4, 12, 25, tzinfo=UTC),
    )

    assert text == (
        "OFFLINE\n"
        "Город: Tbilisi\n"
        "Агент: Home ISP (agent-1)\n"
        "Последний отчет: 2026-09-04 12:00:00 UTC\n"
        "Обнаружено: 2026-09-04 12:25:00 UTC"
    )


def test_zero_row_report_renders_control_evidence_and_run_unknown_reason():
    """`UNKNOWN 0` alone hides whether control worked and why targets are absent."""
    report = AgentReport(
        event_id="agent-1:boot-1:8",
        agent_id="agent-1",
        boot_id="boot-1",
        sequence=8,
        observed_at=NOW,
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UP,
        run_status=ResultStatus.UNKNOWN,
        run_reason="no-valid-snapshot",
        duration_ms=10,
    )

    rendered = format_report(report, AGENT, received_at=NOW)

    assert "Доступность не проверена: нет результатов." in rendered
    assert "Подписка недоступна (UNAVAILABLE)" in rendered
    assert "Проверка не выполнена: нет актуального снимка подписки." in rendered
    assert "старые адреса не проверялись" in rendered
    assert "Всё доступно" not in rendered


def test_deadline_incomplete_run_reason_is_visible_in_report():
    """Operators must see that aggregate UNKNOWN rows came from an incomplete run."""
    report = AgentReport(
        event_id="agent-1:boot-1:9",
        agent_id="agent-1",
        boot_id="boot-1",
        sequence=9,
        observed_at=NOW,
        refresh_state="FRESH",
        results=[_result(1, ResultStatus.UNKNOWN, ProbeStage.DEADLINE, "Timed out")],
        control_status=ResultStatus.UP,
        run_status=ResultStatus.UNKNOWN,
        run_reason="deadline",
        duration_ms=10,
    )

    rendered = format_report(report, AGENT, received_at=NOW)

    assert "Проверка завершена не полностью: исчерпан общий лимит времени." in rendered
    assert "❔ Timed out" in rendered
    assert "Всё доступно" not in rendered


def _healthy_report() -> AgentReport:
    return _report().model_copy(update={
        "refresh_state": "FRESH",
        "snapshot_age_seconds": 0,
        "diff": SnapshotDiff(),
        "results": [
            _result(1, ResultStatus.UP, ProbeStage.E2E, "Hidden VPN name")
            .model_copy(update={"address": "203.0.113.1"}),
            _result(2, ResultStatus.UP, ProbeStage.E2E, "Hidden domain name"),
            _result(3, ResultStatus.UP, ProbeStage.TLS, "Hidden SNI name", check_kind="sni"),
        ],
    })


def test_all_healthy_is_short_and_counts_vpn_ip_domains_and_sni():
    rendered = format_report(_healthy_report(), AGENT, received_at=NOW)

    assert rendered.startswith("✅ LiteChecker · Tbilisi\nHome ISP · ")
    assert "Всё доступно · VPN 2/2 · SNI 1/1" in rendered
    assert len(rendered) < 220
    assert "Hidden" not in rendered
    assert "Подписка:" not in rendered
    assert "Обнаружены проблемы" not in rendered


@pytest.mark.parametrize("changes,warning", [
    ({"refresh_state": "STALE", "snapshot_age_seconds": 720}, "STALE"),
    ({"refresh_state": "UNAVAILABLE"}, "UNAVAILABLE"),
    ({"control_status": ResultStatus.UNKNOWN}, "Контрольный интернет-запрос"),
    ({"run_status": ResultStatus.UNKNOWN, "run_reason": "mass-removal-quarantine"}, "повторного подтверждения"),
    ({"dropped_report_count": 3}, "потеряно отчётов: 3"),
])
def test_up_rows_with_freshness_or_agent_warning_are_not_reported_as_all_good(changes, warning):
    report = _healthy_report().model_copy(update=changes)

    rendered = format_report(report, AGENT, received_at=NOW)

    assert rendered.startswith("⚠️ LiteChecker")
    assert "Всё доступно" not in rendered
    assert warning in rendered
    assert "Hidden" not in rendered


def test_delayed_healthy_report_states_observation_time_and_is_not_current_all_good():
    rendered = format_report(
        _healthy_report(), AGENT, received_at=NOW + timedelta(minutes=20)
    )

    assert "04.09.2026 12:00:00 UTC" in rendered
    assert "с задержкой 20 мин" in rendered
    assert "это состояние на время проверки" in rendered
    assert "Всё доступно" not in rendered


def test_failed_vpn_explains_timeout_and_does_not_present_tcp_latency_as_vpn_speed():
    report = _healthy_report().model_copy(update={"results": [
        _result(1, ResultStatus.DOWN, ProbeStage.VLESS_E2E,
                "🇳🇱 Амстердам #2 | Vless | 🔁 Автоматический выбор | Vless")
        .model_copy(update={"latency_ms": 71, "error_code": "canary-timeout"}),
        _result(2, ResultStatus.DOWN, ProbeStage.TCP, "🇫🇷 Париж #1")
        .model_copy(update={"error_code": "tcp-timeout"}),
    ]})

    rendered = format_report(report, AGENT, received_at=NOW)

    assert "🔴 🇳🇱 Амстердам #2 · node-1.example:443" in rendered
    assert "Порт отвечает, VPN: таймаут" in rendered
    assert "TCP: таймаут" in rendered
    assert "71 мс" not in rendered
    assert "Vless" not in rendered
    assert "Автоматический выбор" not in rendered
    assert "\\" not in rendered
    assert "блокиров" not in rendered


def test_failed_sni_is_separate_from_healthy_vpn_and_explains_certificate_error():
    report = _healthy_report().model_copy(update={"results": [
        _result(1, ResultStatus.UP, ProbeStage.E2E, "Healthy VPN"),
        _result(2, ResultStatus.DOWN, ProbeStage.TLS_CERTIFICATE, "SNI", check_kind="sni"),
    ]})

    rendered = format_report(report, AGENT, received_at=NOW)

    assert "VPN: 1 (IP: 0 / домены: 1) · доступны: 1" in rendered
    assert "SNI: 1 · недоступны: 1" in rendered
    assert "SNI — проблемы:" in rendered
    assert "TLS: сертификат не прошёл проверку" in rendered
    assert "сам по себе не означает" not in rendered
    assert "TLS: сертификат не прошёл проверку\n\nID: agent-1 · v?" in rendered
    assert "Healthy VPN" not in rendered


@pytest.mark.parametrize("stage,error_code,explanation", [
    (ProbeStage.DNS, "dns-failed", "DNS: IP-адрес не получен"),
    (ProbeStage.TCP, "tcp-refused", "TCP: подключение отклонено"),
    (ProbeStage.TLS_HANDSHAKE, "tls-timeout", "Порт отвечает, TLS: таймаут"),
])
def test_domain_diagnostic_failure_has_human_explanation(stage, error_code, explanation):
    result = _result(1, ResultStatus.DOWN, stage, "SNI", check_kind="sni").model_copy(
        update={"error_code": error_code}
    )
    report = _healthy_report().model_copy(update={"results": [result]})

    assert explanation in format_report(report, AGENT, received_at=NOW)


@pytest.mark.parametrize("error_code,explanation", [
    ("tls-local-error", "локальная ошибка TLS"),
    ("probe-error", "локальная ошибка проверки"),
    ("dns-answer-limit", "слишком много IP в ответе DNS"),
    ("forbidden-address", "IP не разрешён для проверки"),
])
def test_unknown_policy_result_preserves_specific_reason(error_code, explanation):
    result = _result(1, ResultStatus.UNKNOWN, ProbeStage.POLICY, "SNI", check_kind="sni").model_copy(
        update={"error_code": error_code}
    )
    report = _healthy_report().model_copy(update={"results": [result]})

    rendered = format_report(report, AGENT, received_at=NOW)

    assert explanation in rendered
    assert "не проверены: 1" in rendered
    assert "недоступны: 1" not in rendered

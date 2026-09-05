"""Deterministic, bounded, plain-text Telegram reporting."""

from __future__ import annotations

import ipaddress
import unicodedata
from datetime import UTC, datetime

from litechecker.collector.auth import AgentIdentity
from litechecker.models import AgentReport, ProbeResult, ResultStatus
from litechecker.security import redact


_STATUS_ORDER = {
    ResultStatus.DOWN: 0,
    ResultStatus.UNKNOWN: 1,
    ResultStatus.UP: 2,
}


def format_report(
    report: AgentReport,
    agent: AgentIdentity,
    *,
    received_at: datetime,
    recovered: bool = False,
) -> str:
    """Render a report without serializing models or local-only configuration."""
    ordered = sorted(
        report.results,
        key=lambda result: (_STATUS_ORDER[result.status], result.target_id, result.label),
    )
    failures = [result for result in ordered if result.status is not ResultStatus.UP]
    vpn = [result for result in ordered if result.check_kind == "vpn"]
    sni = [result for result in ordered if result.check_kind == "sni"]
    delay = max(0, int((received_at - report.observed_at).total_seconds()))
    delayed = delay > agent.expected_interval_seconds
    healthy = bool(ordered) and not failures and (
        report.refresh_state == "FRESH"
        and report.run_status is ResultStatus.UP
        and report.control_status is ResultStatus.UP
        and not report.dropped_report_count
        and not delayed
    )
    icon = "✅" if healthy else "⚠️"
    lines = [f"{icon} LiteChecker · {_clean_field(agent.city, 128)}"]
    if healthy:
        lines.append("Всё доступно.")
    elif not ordered:
        lines.append("Доступность не проверена: нет результатов.")
    elif not failures:
        lines.append("Проверенные адреса доступны, но есть предупреждения.")
    else:
        lines.append("Обнаружены проблемы:")
    if ordered:
        ip_count = sum(_is_ip(result.address) for result in vpn)
        domain_count = len(vpn) - ip_count
        lines.append(
            f"VPN: {len(vpn)} (IP: {ip_count} / домены: {domain_count})"
            + (f" · {_status_summary(vpn)}" if not healthy and vpn else "")
        )
        if sni:
            lines.append(
                f"SNI: {len(sni)}"
                + (f" · {_status_summary(sni)}" if not healthy else "")
            )
    lines.append(
        f"{_utc_text(report.observed_at)} · "
        f"{_clean_field(agent.name, 128)} ({_clean_field(agent.agent_id, 128)})"
    )
    if recovered:
        lines.append("🟢 Агент снова на связи.")
    warnings = _report_warnings(report)
    if delayed:
        warnings.append(
            f"Отчёт пришёл с задержкой {_age_text(delay)}; "
            "это состояние на время проверки."
        )
    lines.extend(f"⚠️ {warning}" for warning in warnings)
    changes = [
        f"{label}: {len(values)}"
        for label, values in (
            ("добавлено", report.diff.added),
            ("удалено", report.diff.removed),
            ("изменено", report.diff.changed),
        )
        if values
    ]
    if changes:
        lines.append("Подписка: " + ", ".join(changes) + ".")
    for kind, heading in (
        ("vpn", "VPN — IP и домены"),
        ("sni", "SNI — доступность доменов напрямую"),
    ):
        group = [result for result in failures if result.check_kind == kind]
        if group:
            lines.extend(["", heading])
            lines.extend(_result_line(result) for result in group)
    if any(result.check_kind == "sni" for result in failures):
        lines.extend(["", "Сбой домена SNI сам по себе не означает, что VPN не работает."])
    return "\n".join(lines)


def format_offline(
    agent: AgentIdentity,
    *,
    last_seen: datetime,
    offline_since: datetime,
    never_seen: bool = False,
) -> str:
    evidence_label = "Активация" if never_seen else "Последний отчет"
    return "\n".join(
        [
            "OFFLINE",
            f"Город: {_clean_field(agent.city, 128)}",
            f"Агент: {_clean_field(agent.name, 128)} ({_clean_field(agent.agent_id, 128)})",
            f"{evidence_label}: {_utc_text(last_seen)}",
            f"Обнаружено: {_utc_text(offline_since)}",
        ]
    )


def format_recovery(agent: AgentIdentity, *, recovered_at: datetime) -> str:
    return "\n".join(
        [
            "RECOVERY",
            f"Город: {_clean_field(agent.city, 128)}",
            f"Агент: {_clean_field(agent.name, 128)} ({_clean_field(agent.agent_id, 128)})",
            f"Восстановлено: {_utc_text(recovered_at)}",
        ]
    )


def chunk_message(message: str, *, limit: int = 3_500) -> list[str]:
    """Split by lines when possible and hard-split by Unicode code point otherwise."""
    if not isinstance(message, str):
        raise TypeError("message must be text")
    cleaned = _clean_message(message)
    if not cleaned:
        cleaned = "(пустой отчет)"
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 16:
        raise ValueError("chunk limit is too small")
    if len(cleaned) <= limit:
        return [cleaned]

    expected_count = 2
    while True:
        overhead = len(f"[{expected_count}/{expected_count}]\n")
        parts = _split_payload(cleaned, limit - overhead)
        actual_count = len(parts)
        if len(str(actual_count)) == len(str(expected_count)):
            break
        expected_count = actual_count
    return [f"[{index}/{actual_count}]\n{part}" for index, part in enumerate(parts, 1)]


def _split_payload(text: str, maximum: int) -> list[str]:
    if maximum < 1:
        raise ValueError("chunk limit is too small")
    parts: list[str] = []
    offset = 0
    while offset < len(text):
        end = min(len(text), offset + maximum)
        if end < len(text):
            newline = text.rfind("\n", offset, end)
            if newline >= offset:
                end = newline + 1
        if end == offset:
            end = min(len(text), offset + maximum)
        parts.append(text[offset:end])
        offset = end
    return parts


def _result_line(result: ProbeResult) -> str:
    label = _short_label(result.label)
    address = _clean_field(result.address, 255)
    endpoint = f"[{address}]:{result.port}" if ":" in address else f"{address}:{result.port}"
    icon = "🔴" if result.status is ResultStatus.DOWN else "❔"
    title = endpoint if result.check_kind == "sni" or label == address else f"{label} · {endpoint}"
    return f"{icon} {title}\n   {_explanation(result)}"


def _short_label(value: str) -> str:
    parts = _clean_field(value, 256).split("|")
    meaningful = [
        part.strip()
        for part in parts
        if part.strip().casefold() not in {
            "", "vless", "🔁 автоматический выбор", "автоматический выбор",
        }
    ]
    return meaningful[0] if meaningful else "VPN"


def _explanation(result: ProbeResult) -> str:
    stage = result.stage.value
    code = result.error_code or ""
    if stage == "DNS":
        return "DNS: не удалось получить IP-адрес домена."
    if stage == "TCP":
        if code in {"tcp-timeout", "connect-timeout"}:
            return "TCP: порт не ответил за время ожидания."
        if code == "tcp-refused":
            return "TCP: сервер отклонил подключение к порту."
        return "TCP: не удалось подключиться к порту."
    if stage == "VLESS_E2E":
        detail = (
            "истекло время ожидания"
            if code == "canary-timeout"
            else "контрольный HTTPS-запрос не прошёл"
        )
        return f"Порт отвечает, но VPN-проверка не прошла: {detail}."
    if stage == "TLS_CERTIFICATE":
        return "TLS: сертификат домена не прошёл проверку."
    if stage == "TLS_HANDSHAKE":
        if code == "tls-timeout":
            return "Порт отвечает, но истекло время ожидания TLS-соединения с доменом."
        return "Порт отвечает, но TLS-соединение с доменом не установлено."
    if stage == "AGENT_NETWORK":
        return "Не проверено: контрольный интернет-запрос с этого агента не прошёл."
    if stage == "XRAY":
        return "Не проверено: ошибка локального Xray на агенте."
    if stage == "DEADLINE":
        return "Не проверено: исчерпан общий лимит времени проверки."
    if stage == "POLICY":
        if code == "tls-local-error":
            return "Не проверено: локальная ошибка TLS на агенте."
        if code == "probe-error":
            return "Не проверено: локальная ошибка проверки на агенте."
        if code == "dns-answer-limit":
            return "Не проверено: число IP в ответе DNS превышает допустимый лимит."
        if code == "forbidden-address":
            return "Не проверено: адрес не является разрешённым публичным IP."
        return "Не проверено: адрес не прошёл проверку безопасности назначения."
    return "Результат проверки не определён."


def _status_summary(results: list[ProbeResult]) -> str:
    return ", ".join(
        f"{label}: {count}"
        for status, label in (
            (ResultStatus.UP, "доступны"),
            (ResultStatus.DOWN, "недоступны"),
            (ResultStatus.UNKNOWN, "не проверены"),
        )
        if (count := sum(result.status is status for result in results))
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _age_text(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} с"
    if seconds < 3600:
        return f"{seconds // 60} мин"
    return f"{seconds // 3600} ч {(seconds % 3600) // 60} мин"


def _report_warnings(report: AgentReport) -> list[str]:
    warnings: list[str] = []
    if report.refresh_state == "STALE":
        age = (
            f", возраст {_age_text(report.snapshot_age_seconds)}"
            if report.snapshot_age_seconds is not None else ""
        )
        warnings.append(f"Подписка не обновилась (STALE): проверен сохранённый список{age}.")
    elif report.refresh_state == "UNAVAILABLE":
        warnings.append("Подписка недоступна (UNAVAILABLE): актуальный список не получен; старые адреса не проверялись.")
    if report.control_status is ResultStatus.UNKNOWN:
        warnings.append("Контрольный интернет-запрос с агента не прошёл; причина на его стороне не исключена.")
    reasons = {
        "no-valid-snapshot": "Проверка не выполнена: нет актуального снимка подписки.",
        "agent-network": "Не удалось проверить серверы из-за сбоя контрольного интернет-запроса.",
        "xray-version-unavailable": "Проверка VPN не выполнена: Xray недоступен на агенте.",
        "xray-version-mismatch": "Проверка VPN не выполнена: версия Xray не соответствует настройкам.",
        "deadline": "Проверка завершена не полностью: исчерпан общий лимит времени.",
        "probe-incomplete": "Проверка завершена не полностью: произошла ошибка на агенте.",
        "mass-removal-quarantine": "Резкое сокращение подписки требует повторного подтверждения; сохранён прежний список.",
    }
    if report.run_reason:
        warnings.append(reasons[report.run_reason])
    if report.dropped_report_count:
        warnings.append(f"Из локальной очереди потеряно отчётов: {report.dropped_report_count}.")
    return warnings


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be UTC-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _clean_field(value: object, maximum: int) -> str:
    text = "".join(
        " " if character in "\r\n\t" else character
        for character in str(value)
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
        or character in "\r\n\t"
    )
    return " ".join(redact(text).split())[:maximum]


def _clean_message(value: str) -> str:
    return "".join(
        character
        for character in value.replace("\r\n", "\n").replace("\r", "\n")
        if character == "\n" or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )

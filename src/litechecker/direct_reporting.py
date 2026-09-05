"""Production DIRECT text: scoped observations, no claims about universal VPN bypass."""

from __future__ import annotations

from datetime import datetime

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import (
    _clean_field, _is_ip, _report_warnings, _status_summary, _utc_text,
)
from litechecker.models import AgentReport, ResultStatus


def format_direct(report: AgentReport, identity: AgentIdentity, interface: str,
                  scoped_exit, ordinary_exit, *, platform_label="macOS") -> str:
    # Import lazily: the shared measurement runner selects this formatter only
    # for production; the original one-shot trial retains its own presentation.
    from litechecker.direct_check import _direct_result_line

    failures = sorted((r for r in report.results if r.status is not ResultStatus.UP),
                      key=lambda r: (r.status is ResultStatus.UNKNOWN, r.check_kind, r.target_id))
    complete = (bool(report.results) and scoped_exit is not None
                and report.refresh_state == "FRESH" and report.run_status is ResultStatus.UP
                and report.control_status is ResultStatus.UP and not report.dropped_report_count
                and not any(r.status is ResultStatus.UNKNOWN for r in report.results))
    healthy = complete and not failures
    city = scoped_exit.city if scoped_exit and scoped_exit.city else "город не определён"
    interface = _clean_field(interface, 32)
    lines = [
        f"{'✅' if healthy else '⚠️'} LiteChecker · DIRECT ({_clean_field(platform_label, 32)}) · {_clean_field(city, 112)}"
        f" · {_utc_text(report.observed_at)} · {_clean_field(identity.name, 128)}",
        "",
    ]
    if healthy:
        verdict = "Всё доступно через выбранное подключение."
    elif not complete:
        verdict = "Проверка неполная — доступность всех адресов не подтверждена."
    else:
        verdict = "Есть недоступные адреса через выбранное подключение."
    if scoped_exit:
        lines.append(f"Маршрут: {interface} · выход {_clean_field(scoped_exit.ip, 64)}")
        if scoped_exit.provider:
            lines.append(f"Сеть по IP: {_clean_field(scoped_exit.provider, 80)}")
    else:
        lines.append(f"Маршрут: {interface} · выход не определён")
    if ordinary_exit and scoped_exit:
        if ordinary_exit.ip == scoped_exit.ip:
            lines.append(f"IP проверок совпадает с обычным выходом ({_clean_field(ordinary_exit.ip, 64)}).")
        else:
            lines.append(f"IP проверок отличается от обычного выхода ({_clean_field(ordinary_exit.ip, 64)}).")
    lines.extend(["", verdict, ""])

    vpn = [r for r in report.results if r.check_kind == "vpn"]
    sni = [r for r in report.results if r.check_kind == "sni"]
    ip_count = sum(_is_ip(r.address) for r in vpn)
    lines.append(f"- VPN: {len(vpn)} (IP: {ip_count} / домены: {len(vpn) - ip_count})"
                 + (f" · {_status_summary(vpn)}" if vpn and not healthy else ""))
    lines.append(f"- SNI: {len(sni)}" + (f" · {_status_summary(sni)}" if sni and not healthy else ""))
    warnings = [f"⚠️ {warning}" for warning in _report_warnings(report)]
    changes = [f"{label}: {len(items)}" for label, items in (
        ("добавлено", report.diff.added), ("удалено", report.diff.removed),
        ("изменено", report.diff.changed),
    ) if items]
    if changes:
        warnings.append("Изменения подписки: " + ", ".join(changes) + ".")
    if any(r.status is ResultStatus.UNKNOWN for r in report.results):
        warnings.append("❔ Для непроверенных адресов отказ сервера не установлен.")
    if warnings:
        lines.extend(["", *warnings])
    for kind, heading in (("vpn", "VPN — проблемы"), ("sni", f"SNI — проблемы через {interface}")):
        group = [r for r in failures if r.check_kind == kind]
        if group:
            lines.extend(["", f"{heading}:"])
            for index, result in enumerate(group):
                if index:
                    lines.append("")
                title, *details = _direct_result_line(result).splitlines()
                lines.append(title)
                lines.extend(f"│ {detail.lstrip()}" for detail in details)
    lines.extend(["", f"ID: {_clean_field(identity.agent_id, 128)}"])
    return "\n".join(lines)


def format_unavailable(identity: AgentIdentity, reason: str, observed_at: datetime, *, platform_label="macOS") -> str:
    explanations = {
        "direct-interface-unavailable": "Физический интерфейс или его DNS недоступен/неоднозначен.",
        "direct-exit-unavailable": "Не удалось проверить выход через физический интерфейс (сеть/DNS/IPinfo).",
        "cycle-timeout": "Проверка не уложилась в установленный лимит времени.",
        "cycle-failed": "Локальная проверка завершилась с ошибкой.",
    }
    return "\n".join([
        f"⚠️ LiteChecker · DIRECT ({_clean_field(platform_label, 32)}) · {_utc_text(observed_at)} · {_clean_field(identity.name, 128)}",
        "",
        "Проверка через физическое подключение не выполнена.",
        explanations.get(reason, "Локальная проверка недоступна; отказ серверов не установлен."),
        "На обычный маршрут или Telegram-прокси проверки не переключались.",
        "",
        f"ID: {_clean_field(identity.agent_id, 128)}",
    ])

"""Production DIRECT text: scoped observations, no claims about universal VPN bypass."""

from __future__ import annotations

from datetime import datetime
import re

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import (
    _clean_field, _is_ip, _report_warnings, _status_summary, _report_time,
    _success_summary, _subscription_changes, report_identity,
)
from litechecker.models import AgentReport, ResultStatus
from litechecker.app_version import running_version


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
        f"{'✅' if healthy else '⚠️'} LiteChecker · {_clean_field(city, 112)}",
        _device_line(identity, platform_label, report.observed_at),
        "",
    ]
    if scoped_exit:
        route = f"DIRECT: {interface} · {_clean_field(scoped_exit.ip, 64)}"
        if scoped_exit.provider:
            provider = _clean_field(scoped_exit.provider, 80)
            provider = re.sub(r"^(AS[0-9]+)\s+", r"\1 · ", provider)
            route += f" · {provider}"
        lines.append(route)
    else:
        lines.append(f"DIRECT: {interface} · выход не определён")
    if ordinary_exit and scoped_exit:
        relation = "совпадает" if ordinary_exit.ip == scoped_exit.ip else "отличается"
        lines.append(f"Обычный выход: {_clean_field(ordinary_exit.ip, 64)} — {relation}")
    elif ordinary_exit:
        lines.append(f"Обычный выход: {_clean_field(ordinary_exit.ip, 64)} — сравнение недоступно")
    else:
        lines.append("Обычный выход: не определён")
    lines.append("")

    vpn = [r for r in report.results if r.check_kind == "vpn"]
    sni = [r for r in report.results if r.check_kind == "sni"]
    ip_count = sum(_is_ip(r.address) for r in vpn)
    if healthy:
        lines.append(_success_summary(vpn, sni))
    else:
        if not complete:
            lines.extend(["Проверка неполная — доступность всех адресов не подтверждена.", ""])
        lines.append(f"- VPN: {len(vpn)} (IP: {ip_count} / домены: {len(vpn) - ip_count})"
                     + (f" · {_status_summary(vpn)}" if vpn else ""))
        lines.append(f"- SNI: {len(sni)}" + (f" · {_status_summary(sni)}" if sni else ""))
    warnings = [f"⚠️ {warning}" for warning in _report_warnings(report)]
    changes = _subscription_changes(report)
    if changes:
        warnings.append(changes)
    if warnings:
        lines.extend(["", *warnings])
    for kind, heading in (("vpn", "VPN — проблемы"), ("sni", f"SNI — проблемы через {interface}")):
        group = [r for r in failures if r.check_kind == kind]
        if group:
            lines.extend(["", f"{heading}:"])
            for index, result in enumerate(group):
                if index:
                    lines.append("")
                title, *details = _direct_result_line(result, compact=True).splitlines()
                lines.append(title)
                lines.extend(f"│ {detail.lstrip()}" for detail in details)
    lines.extend(["", report_identity(identity.agent_id, report.app_version)])
    return "\n".join(lines)


def format_unavailable(identity: AgentIdentity, reason: str, observed_at: datetime, *, platform_label="macOS") -> str:
    explanations = {
        "direct-interface-unavailable": "Не удалось определить физический интерфейс или его DNS.",
        "direct-exit-unavailable": "Контроль выхода не прошёл (сеть/DNS/IPinfo).",
        "cycle-timeout": "Исчерпан общий лимит времени.",
        "cycle-failed": "Локальная ошибка проверки; отказ серверов не установлен.",
        "direct-network-changed": "Сеть изменилась, повтор не завершён. Старые результаты отброшены.",
        "direct-network-unverifiable": "Подключение не подтверждено, повтор не завершён. Старые результаты отброшены.",
    }
    return "\n".join([
        "⚠️ LiteChecker",
        _device_line(identity, platform_label, observed_at),
        "",
        "DIRECT: проверка не выполнена.",
        explanations.get(reason, "Локальная ошибка проверки; отказ серверов не установлен."),
        "",
        report_identity(identity.agent_id, running_version()),
    ])


def _device_line(identity: AgentIdentity, platform_label: str, observed_at: datetime) -> str:
    name = _clean_field(identity.name, 128)
    platform_label = _clean_field(platform_label, 32)
    suffix = f" ({platform_label})"
    if name.endswith(suffix) and len(name) > len(suffix):
        name = name[:-len(suffix)]
    return f"{name} · {platform_label} · {_report_time(observed_at)}"

"""Bounded, opt-in Windows control-path diagnosis. No subscription or VPN changes.

Uses the same bound sockets as the trial, observing adapter DNS and DoH
separately. Stages are not a replay or proof of the previous failure.
Only fixed control hosts are contacted; raw exceptions and HTTP bodies are not
included in the report.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import certifi
import dns.rdatatype

from litechecker.direct_network import DirectNetworkUnavailable, TCPDirectNetwork, _numeric
from litechecker.network_identity import _safe_label


_STEP_TIMEOUT = 5
_TOTAL_TIMEOUT = 60
_IPINFO_BODY_LIMIT = 8192


@dataclass(frozen=True)
class Step:
    stage: str
    status: str
    target: str = ""
    detail: str = ""
    code: str | None = None
    winerror: int | None = None
    errno: int | None = None
    elapsed_ms: int = 0


@dataclass(frozen=True)
class Diagnosis:
    text: str
    ok: bool
    steps: tuple[Step, ...]


class DiagnosticError(Exception):
    pass


def _error(exc):
    # Preserve numeric OS evidence across our wrappers, never str(exception).
    code = "local_error"
    winerror = number = None
    seen = set()
    for _ in range(8):
        if exc is None or id(exc) in seen:
            break
        seen.add(id(exc))
        if isinstance(exc, (DiagnosticError, DirectNetworkUnavailable)) and code == "local_error":
            candidate = exc.code if isinstance(exc, DirectNetworkUnavailable) else exc.args[0]
            if isinstance(candidate, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", candidate):
                code = candidate
        if isinstance(exc, ssl.SSLCertVerificationError):
            code = "tls_certificate_error"
        elif isinstance(exc, ssl.SSLError) and code == "local_error":
            code = "tls_error"
        elif isinstance(exc, TimeoutError) and code == "local_error":
            code = "timeout"
        for field in ("winerror", "errno"):
            value = getattr(exc, field, None)
            if type(value) is int and 0 <= value <= 0xFFFFFFFF:
                if field == "winerror" and winerror is None:
                    winerror = value
                elif field == "errno" and number is None:
                    number = value
        exc = exc.__cause__ or exc.__context__
    return code, winerror, number


async def _close(writer):
    writer.close()
    try:
        async with asyncio.timeout(1):
            await writer.wait_closed()
    except (OSError, TimeoutError):
        pass


def _tls_context():
    return ssl.create_default_context(cafile=certifi.where())


def _public_ip(body):
    try:
        if not isinstance(body, bytes) or len(body) > _IPINFO_BODY_LIMIT:
            raise ValueError("invalid body")
        payload = json.loads(body.decode("utf-8"))
        if (not isinstance(payload, dict) or "error" in payload
                or payload.get("bogon", False) is not False):
            raise ValueError("invalid response")
        return str(_numeric(payload.get("ip")))
    except (ValueError, UnicodeError, DirectNetworkUnavailable):
        raise DiagnosticError("invalid_ipinfo_response") from None


class _Probe:
    def __init__(self):
        self.steps = []
        self.metadata = []
        self.public_ip = None

    async def attempt(self, stage, target, operation, describe=lambda value: ""):
        started = time.monotonic()
        try:
            async with asyncio.timeout(_STEP_TIMEOUT):
                value = await operation()
            detail = describe(value)
        except Exception as exc:
            code, winerror, number = _error(exc)
            self.steps.append(Step(stage, "error", target, code=code, winerror=winerror,
                                   errno=number, elapsed_ms=int((time.monotonic() - started) * 1000)))
            return False, None
        self.steps.append(Step(stage, "ok", target, detail=detail,
                               elapsed_ms=int((time.monotonic() - started) * 1000)))
        return True, value

    def skip(self, stage, reason):
        self.steps.append(Step(stage, "skipped", detail=reason))

    async def https(self, network, address, hostname, prefix):
        writer = None
        target = f"{address}:443"
        ok, connection = await self.attempt(
            prefix + " TCP", target, lambda: network._connect_ip(address, 443))
        if not ok:
            self.skip(prefix + " TLS", "TCP-соединение не установлено")
            return False
        _, writer = connection
        try:
            async def handshake():
                await writer.start_tls(_tls_context(), server_hostname=hostname,
                                       ssl_handshake_timeout=_STEP_TIMEOUT)

            ok, _ = await self.attempt(prefix + " TLS", hostname, handshake,
                                       lambda _: "сертификат проверен")
            return ok
        finally:
            await _close(writer)

    async def run(self, factory):
        from litechecker import windows_doh

        ok, network = await self.attempt("Адаптер", "", factory)
        if not ok:
            return
        self.metadata = [
            "Интерфейс: " + _safe_label(network.interface, 128),
            "Локальные IP: " + ", ".join(str(ipaddress.ip_address(ip)) for ip in network.source_addresses),
            "DNS адаптера: " + ", ".join(str(ipaddress.ip_address(ip)) for ip in network.dns_servers),
        ]
        has_v4 = any(ipaddress.ip_address(ip).version == 4 for ip in network.source_addresses)
        control = "1.1.1.1" if has_v4 else "2606:4700:4700::1111"

        async def binding():
            sock = network._socket(ipaddress.ip_address(control))
            sock.close()

        ok, _ = await self.attempt("Привязка сокета", control, binding,
                                   lambda _: "интерфейс и исходный адрес заданы; пакеты ещё не отправлялись")
        if not ok:
            return
        resolver = network.dns_servers[0]

        async def dns_tcp():
            _, writer = await network._connect_ip(resolver, 53, infrastructure=True)
            await _close(writer)

        await self.attempt("DNS TCP", f"{resolver}:53", dns_tcp)
        for kind in (dns.rdatatype.A, dns.rdatatype.AAAA):
            async def adapter_query():
                # WindowsDirectNetwork._query uses DoH. These observations must
                # still diagnose the original adapter resolver over TCP/53.
                return await TCPDirectNetwork._query(network, "ipinfo.io", kind)

            await self.attempt("DNS " + kind.name, f"ipinfo.io → {resolver}:53", adapter_query,
                               lambda values: ", ".join(values[:8]) if values else "адресов этого типа нет")

        addresses = []
        for kind in (dns.rdatatype.A, dns.rdatatype.AAAA):
            async def doh_query():
                return [str(_numeric(ip)) for ip in await windows_doh.query(network, "ipinfo.io", kind)]

            ok, values = await self.attempt("DoH " + kind.name, "ipinfo.io → Cloudflare DoH:443", doh_query,
                                           lambda values: ", ".join(values[:8]) if values else "адресов этого типа нет")
            if ok:
                addresses.extend(values)
        families = {ipaddress.ip_address(ip).version for ip in network.source_addresses}
        addresses = [ip for ip in addresses if ipaddress.ip_address(ip).version in families]
        if addresses:
            # This is a small diagnostic, not an exhaustive availability check.
            address = addresses[0]
            tls_ok = await self.https(network, address, "ipinfo.io", "IPinfo")
            if tls_ok:
                async def ipinfo_request():
                    # A separate bound TLS request validates the complete HTTP
                    # response. Only its numeric public IP is retained.
                    body = await windows_doh.request(network, address, "ipinfo.io", "/json",
                                                     accept="application/json")
                    return _public_ip(body)

                ok, public_ip = await self.attempt("IPinfo HTTP", "ipinfo.io/json", ipinfo_request,
                                                   lambda ip: "HTTP 200; публичный IP: " + ip)
                if ok:
                    self.public_ip = public_ip
            else:
                self.skip("IPinfo HTTP", "TLS-соединение не установлено")
        else:
            for stage in ("TCP", "TLS", "HTTP"):
                self.skip("IPinfo " + stage, "DoH не вернул публичный IP подходящего типа для адаптера")
        # Independent control only: never replaces a failed subscription probe
        # or switches to the ordinary route. It also uses the physical binding.
        await self.https(network, control, control, "Контроль без DNS")

        async def revalidate():
            network._validate_interface()

        await self.attempt("Адаптер после проверки", "", revalidate)


async def diagnose(*, network_factory=None):
    if network_factory is None:
        from litechecker.windows_network import WindowsDirectNetwork
        network_factory = WindowsDirectNetwork.discover
    started = datetime.now(UTC)
    probe = _Probe()
    try:
        async with asyncio.timeout(_TOTAL_TIMEOUT):
            await probe.run(network_factory)
    except Exception as exc:
        code, winerror, number = _error(exc)
        probe.steps.append(Step("Диагностика", "error", code=code, winerror=winerror, errno=number))
    ok = bool(probe.steps) and all(step.status == "ok" for step in probe.steps)
    lines = ["🧪 LiteChecker · диагностика Windows · D2",
             started.strftime("%Y-%m-%d %H:%M:%S UTC"), *probe.metadata,
             "Отдельный прогон: настройки сети не меняются. Подписка и серверы не проверялись.",
             "DNS TCP/A/AAAA — первый сервер адаптера через TCP/53. DoH A/AAAA — Cloudflare через HTTPS/443.",
             "IPinfo — первый IP подходящего типа из DoH. Контроль без DNS — Cloudflare.",
             "Этапы используют отдельные соединения; HTTP проверяет JSON и публичный IP, наблюдаемый IPinfo.", ""]
    for step in probe.steps:
        icon = {"ok": "✅", "error": "❌", "skipped": "⏭"}[step.status]
        line = f"{icon} {step.stage}" + (f" · {step.target}" if step.target else "")
        details = [step.detail] if step.detail else []
        if step.code:
            details.append(step.code)
        if step.winerror is not None:
            details.append(f"WinError={step.winerror}")
        if step.errno is not None:
            details.append(f"errno={step.errno}")
        if step.status != "skipped":
            details.append(f"{step.elapsed_ms} мс")
        lines.extend([line, "   " + "; ".join(details)])
    lines.extend(["", "Контрольные этапы прошли." if ok else "Есть ошибки или пропущенные этапы."])
    if probe.public_ip is not None:
        lines.append("Наблюдаемый публичный выход IPinfo: " + probe.public_ip + ".")
        if any(step.stage in ("DNS TCP", "DNS A", "DNS AAAA") and step.status == "error"
               for step in probe.steps):
            lines.append("DNS адаптера через TCP/53 не прошёл проверку; отдельный запрос через DoH/HTTPS получил публичный IP.")
    lines.extend(["Публичный IP относится к этому запросу и не доказывает обход любого VPN.",
                  "Пришлите только last-diagnostics.txt. Файл содержит локальные IP, DNS и наблюдаемый публичный IP; настроек подписки и токенов в нём нет."])
    return Diagnosis("\n".join(lines), ok, tuple(probe.steps))

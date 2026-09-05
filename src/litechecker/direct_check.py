"""Opt-in native macOS trial; interface binding is NOT proof of ISP egress."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from filelock import AsyncFileLock

from litechecker.measurement import SubscriptionFetcher, make_measurement_dependencies, measure_cycle
from litechecker.collector.reporting import _result_line, chunk_message
from litechecker.collector.telegram import TelegramClient
from litechecker.config import StandaloneSettings
from litechecker.direct_network import DirectNetworkUnavailable, MacDirectNetwork
from litechecker.direct_observation import save_last_observation
from litechecker.direct_relay import DirectRelay
from litechecker.direct_subscription import parse_trial_subscription
from litechecker.models import ProbeStage, ResultStatus
from litechecker.network_identity import _safe_label
from litechecker.probe import (
    DEFAULT_CANARIES, ControlResult, DiagnosticResult, TunnelResult, XrayProcess, XrayTunnel,
    check_control, probe_all,
)
from litechecker.runtime import run_with_signals


@dataclass(frozen=True)
class ExitObservation:
    ip: str
    city: str | None = None
    provider: str | None = None


@dataclass(frozen=True)
class TrialResult:
    text: str
    available: bool
    report: object | None = None
    reason: str | None = None
    observed_at: datetime | None = None
    interface: str | None = None
    delivery_accepted: bool | None = None


def trial_completed(report):
    return (bool(report.results) and report.control_status is ResultStatus.UP
            and report.run_status is ResultStatus.UP
            and report.refresh_state == "FRESH"
            and all(result.status is not ResultStatus.UNKNOWN for result in report.results))


async def lookup_exit(*, proxy_url=None, transport=None) -> ExitObservation | None:
    """Bounded IPinfo observation. Never infer 'not a VPN' from this response."""
    try:
        async with asyncio.timeout(6):
            async with httpx.AsyncClient(
                transport=transport, proxy=proxy_url, trust_env=False,
                follow_redirects=False, timeout=5,
            ) as client:
                async with client.stream("GET", "https://ipinfo.io/json", headers={
                    "Accept-Encoding": "identity", "Accept": "application/json",
                }) as response:
                    if response.status_code != 200:
                        return None
                    if response.headers.get("content-encoding", "identity") != "identity":
                        return None
                    body = bytearray()
                    async for data in response.aiter_bytes():
                        if len(body) + len(data) > 8192:
                            return None
                        body.extend(data)
                    payload = json.loads(body)
                    if not isinstance(payload, dict) or payload.get("bogon") or "error" in payload:
                        return None
                    raw_ip = payload.get("ip")
                    if not isinstance(raw_ip, str) or "%" in raw_ip:
                        return None
                    address = ipaddress.ip_address(raw_ip)
                    if not address.is_global or address.is_multicast:
                        return None
                    return ExitObservation(str(address), _safe_label(payload.get("city"), 112),
                                           _safe_label(payload.get("org"), 80))
    except asyncio.CancelledError:
        raise
    except Exception:
        return None


def uncertain_results(results, faults):
    """A local scoped-transport fault must not become a server DOWN assertion."""
    return [result.model_copy(update={
        "status": ResultStatus.UNKNOWN, "stage": ProbeStage.POLICY,
        "error_code": faults[result.target_id], "latency_ms": None,
    }) if result.status is ResultStatus.DOWN and result.target_id in faults
        else result for result in results]


def format_trial(report, identity, interface, scoped_exit, ordinary_exit, *, platform_label="macOS"):
    # No normal 'all available' banner: host/router filters can still redirect
    # scoped sockets, even when getsockopt confirms the requested interface.
    lines = [f"🧪 LiteChecker · пробный DIRECT ({platform_label})",
             f"Устройство: {identity.name} ({identity.agent_id})",
             f"Интерфейс проверок: {interface}"]
    if scoped_exit:
        lines.append(f"Выход проверок: {scoped_exit.ip}")
        if scoped_exit.city or scoped_exit.provider:
            lines.append("По IPinfo: " + " · ".join(
                value for value in (scoped_exit.city, scoped_exit.provider) if value))
    if ordinary_exit and scoped_exit:
        relation = "совпадает" if ordinary_exit.ip == scoped_exit.ip else "отличается"
        comparison = "совпадает с выходом проверок" if relation == "совпадает" else "отличается от выхода проверок"
        lines.append(f"Обычный выход: {ordinary_exit.ip} — {comparison}.")
    lines.extend([
        report.observed_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        f"Подписка: {report.refresh_state}; проверок: {len(report.results)}.",
        "Результаты: " + ", ".join(f"{label}: {sum(r.status is status for r in report.results)}"
            for status, label in ((ResultStatus.UP, "доступны"), (ResultStatus.DOWN, "не прошли"),
                                  (ResultStatus.UNKNOWN, "не определены"))),
    ])
    if report.run_status is ResultStatus.UNKNOWN or any(r.status is ResultStatus.UNKNOWN for r in report.results):
        lines.append("⚠️ Цикл неполный или контроль сети не прошёл; вывод о доступности всех адресов недопустим.")
    if any(r.status is ResultStatus.UNKNOWN for r in report.results):
        lines.append("Для неопределённых результатов отказ сервера не установлен.")
    for result in report.results:
        if result.error_code == "direct-route-unavailable":
            lines.append(f"• UNKNOWN · {result.address}:{result.port} — прямой маршрут не удалось проверить; это не доказательство отказа сервера.")
        elif result.status is not ResultStatus.UP:
            lines.append(_direct_result_line(result))
    if report.refresh_state != "FRESH":
        lines.append("⚠️ Свежесть подписки не подтверждена.")
    return "\n".join(lines)


def _direct_result_line(result):
    line = _result_line(result)
    phase, _, code = (result.error_code or "").partition(":")
    phases = {"direct-dns": "DNS", "direct-tcp": "TCP", "direct-tls": "TLS",
              "direct-relay": "внешнее соединение VLESS"}
    if phase not in phases:
        return line
    explanations = {
        "direct_dns_timeout": "истекло время ожидания DNS-сервера",
        "direct_dns_failed": "DNS-сервер подключения не ответил корректно",
        "direct_dns_invalid_response": "получен некорректный ответ DNS",
        "direct_doh_connection_failed": "не удалось подключиться к DNS через HTTPS",
        "direct_doh_tls_failed": "не удалось подтвердить защищённое соединение с DNS через HTTPS",
        "direct_doh_tls_protocol": "DNS через HTTPS выбрал неподдерживаемый протокол",
        "direct_doh_http_failed": "DNS через HTTPS вернул ошибку HTTP",
        "direct_doh_invalid_http": "DNS через HTTPS вернул некорректный или неполный ответ",
        "direct_doh_response_too_large": "ответ DNS через HTTPS превышает допустимый размер",
        "direct_doh_invalid_request": "не удалось подготовить запрос DNS через HTTPS",
        "dhcp_dns_unavailable": "DNS подключения недоступен",
        "interface_binding_failed": "не удалось привязать соединение к физическому интерфейсу",
        "interface_changed": "физический интерфейс изменился во время проверки",
        "interface_address_family_unavailable": "на интерфейсе нет нужного IPv4/IPv6-адреса",
        "direct_connection_unreachable": "система сообщила, что маршрут недоступен",
        "direct_connection_failed": "причину ошибки подключения определить не удалось",
        "unsafe_direct_address": "получен непубличный или запрещённый адрес",
        "direct_network_unavailable": "локальный транспорт проверки завершился с ошибкой",
        "direct_relay_start_failed": "не удалось запустить локальный транспорт Xray",
    }
    reason = explanations.get(code, "проверку через физическое подключение завершить не удалось")
    detail = f"{reason} [{code}]" if code in _DIRECT_ERROR_CODES else reason
    return f"{line.splitlines()[0]}\n   Не проверено: {phases[phase]} — {detail}."


async def _close(writer):
    if writer is not None:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1)


_DIRECT_ERROR_CODES = frozenset({
    "direct_network_unavailable", "interface_discovery_failed",
    "unsafe_direct_address", "direct_dns_invalid_response", "direct_dns_cname_loop",
    "direct_dns_unsupported_answer", "direct_dns_ambiguous_cname",
    "direct_dns_too_many_addresses", "direct_dns_cname_limit",
    "direct_platform_unsupported", "interface_address_invalid",
    "physical_interface_ambiguous_or_unavailable", "dhcp_dns_unavailable",
    "interface_changed", "interface_address_family_unavailable",
    "interface_binding_failed", "invalid_direct_port", "invalid_direct_host",
    "direct_connection_failed", "direct_connection_refused", "direct_connection_reset",
    "direct_connection_timeout", "direct_connection_unreachable",
    "direct_dns_no_addresses", "direct_dns_failed", "direct_dns_timeout",
    "direct_dns_nxdomain", "direct_relay_start_failed",
    "direct_doh_connection_failed", "direct_doh_tls_failed", "direct_doh_tls_protocol",
    "direct_doh_http_failed", "direct_doh_invalid_http", "direct_doh_response_too_large",
    "direct_doh_invalid_request",
})
_REMOTE_CONNECT_CODES = {
    "direct_connection_timeout": "tcp-timeout",
    "direct_connection_refused": "tcp-refused",
    "direct_connection_reset": "tcp-connect",
}


def _direct_error_code(exc):
    if isinstance(exc, DirectNetworkUnavailable):
        return exc.code if exc.code in _DIRECT_ERROR_CODES else "direct_network_unavailable"
    if isinstance(exc, TimeoutError):
        return "direct_connection_timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "direct_connection_refused"
    if isinstance(exc, ConnectionResetError):
        return "direct_connection_reset"
    return "direct_network_unavailable"


class _ScopedDiagnostics:
    def __init__(self, network, *, tcp_timeout: float):
        self.network = network
        self.tcp_timeout = tcp_timeout
        self.faults: dict[str, str] = {}

    def record_failure(self, target, phase, exc):
        code = _direct_error_code(exc)
        # Remote TCP failure is useful target evidence after a successful bind.
        # The DHCP resolver failing is instead local DNS infrastructure evidence.
        remote = (code in _REMOTE_CONNECT_CODES and phase != "dns") or code in {
            "direct_dns_nxdomain", "direct_dns_no_addresses",
        }
        if not remote:
            self.faults[target.target_id] = f"direct-{phase}:{code}"
        return code

    async def resolve(self, target):
        try:
            return await self.network.resolve(target.address)
        except Exception as exc:
            code = self.record_failure(target, "dns", exc)
            if code == "direct_dns_no_addresses":
                return []
            # probe_target handles OSError as DNS evidence. It must not escape
            # as RuntimeError and be mislabeled as an Xray process failure.
            raise OSError("direct-dns-failed") from None

    async def check(self, target, addresses):
        writer = None
        started = time.monotonic()
        try:
            async with asyncio.timeout(self.tcp_timeout):
                _, writer = await self.network.connect(addresses[0], target.port)
                return DiagnosticResult(ok=True, latency_ms=int((time.monotonic() - started) * 1000))
        except Exception as exc:
            code = self.record_failure(target, "tcp", exc)
            return DiagnosticResult(ok=False, error_code=_REMOTE_CONNECT_CODES.get(code, "tcp-failed"))
        finally:
            await _close(writer)


class _ScopedTls:
    def __init__(self, diagnostics, *, timeout: float):
        self.diagnostics = diagnostics
        self.timeout = timeout
        self.context = ssl.create_default_context()

    async def check(self, target, address):
        writer = None
        started = time.monotonic()
        connected = False
        try:
            async with asyncio.timeout(self.timeout):
                _, writer = await self.diagnostics.network.connect(address, target.port)
                connected = True
                await writer.start_tls(self.context, server_hostname=target.address,
                                       ssl_handshake_timeout=self.timeout)
                return DiagnosticResult(ok=True, latency_ms=int((time.monotonic() - started) * 1000))
        except ssl.SSLCertVerificationError:
            return DiagnosticResult(ok=False, error_code="tls-certificate")
        except Exception as exc:
            if not connected or not isinstance(exc, (
                ssl.SSLError, TimeoutError, ConnectionResetError,
                ConnectionAbortedError, BrokenPipeError,
            )):
                self.diagnostics.record_failure(target, "tls", exc)
            code = "tls-timeout" if isinstance(exc, TimeoutError) or (
                isinstance(exc, DirectNetworkUnavailable) and exc.code == "direct_connection_timeout"
            ) else "tls-handshake"
            return DiagnosticResult(ok=False, error_code=code)
        finally:
            await _close(writer)


class _TargetNetwork:
    """Attribute relay dial failures to the exact configuration, never its IP."""

    def __init__(self, diagnostics, target):
        self.diagnostics = diagnostics
        self.target = target

    async def connect(self, host, port):
        try:
            return await self.diagnostics.network.connect(host, port)
        except Exception as exc:
            self.diagnostics.record_failure(self.target, "relay", exc)
            raise


class _ScopedTunnel:
    def __init__(self, diagnostics, settings):
        self.diagnostics = diagnostics
        self.settings = settings

    async def check(self, target):
        # Each Xray invocation has its own relay, so concurrent variants and
        # subscription/control sockets cannot contribute another target's faults.
        async with contextlib.AsyncExitStack() as stack:
            try:
                relay = await stack.enter_async_context(DirectRelay(_TargetNetwork(self.diagnostics, target)))
            except Exception:
                self.diagnostics.record_failure(
                    target, "relay", DirectNetworkUnavailable("direct_relay_start_failed"),
                )
                return TunnelResult(canary_ok=False, error_code="proxy-connect")
            return await XrayTunnel(
                XrayProcess(self.settings.xray_binary, dialer_proxy=relay.xray_outbound),
                timeout=self.settings.probe_timeout_seconds,
            ).check(target)


def scoped_dependencies(settings, network, relay):
    dependencies = make_measurement_dependencies(settings.agent, state_dir=settings.state_dir)
    dependencies.parser = parse_trial_subscription
    dependencies.fetcher = SubscriptionFetcher(
        settings.agent.subscription_url.get_secret_value(),
        max_bytes=settings.agent.max_subscription_bytes,
        transport=httpx.AsyncHTTPTransport(proxy=relay.proxy_url, retries=0),
    )
    async def control():
        async with httpx.AsyncClient(proxy=relay.proxy_url, trust_env=False,
                                     follow_redirects=False, timeout=5) as client:
            async def request(canary, timeout):
                response = await client.get(canary.url, timeout=timeout)
                return response.status_code
            return await check_control(requester=request)

    async def prober(targets, control, deadline):
        diagnostics = _ScopedDiagnostics(network, tcp_timeout=settings.agent.tcp_timeout_seconds)
        results = await probe_all(
            targets, control=control, deadline_seconds=deadline,
            max_concurrency=settings.agent.max_concurrency,
            resolver=diagnostics, tcp=diagnostics,
            tls=_ScopedTls(diagnostics, timeout=settings.agent.probe_timeout_seconds),
            tunnel=_ScopedTunnel(diagnostics, settings.agent),
        )
        return uncertain_results(results, diagnostics.faults)

    dependencies.control_checker = control
    dependencies.prober = prober
    return dependencies


async def run_trial(settings, *, send=False, telegram=None, production=False,
                    network_factory=None, platform_label="macOS", validate_after=False):
    """One bounded experiment; never silently fall back to the ordinary route."""
    if production and send:
        raise ValueError("production-direct-delivery-owned-by-service")

    async def deliver(text):
        if send:
            client = telegram or TelegramClient(
                token=settings.telegram_bot_token.get_secret_value(),
                chat_id=settings.telegram_chat_id, topic_id=settings.telegram_topic_id,
                proxy_url=settings.telegram_proxy_url.get_secret_value() if settings.telegram_proxy_url else None,
            )
            # Reporting uses its own optional Telegram proxy, or the ordinary
            # route when unconfigured. Never part of probe availability evidence.
            await client.send_chunks(chunk_message(text))

    try:
        network = await (network_factory or MacDirectNetwork.discover)()
    except DirectNetworkUnavailable:
        observed_at = datetime.now(UTC)
        if production:
            from litechecker.direct_reporting import format_unavailable

            text = format_unavailable(
                settings.identity, "direct-interface-unavailable", observed_at,
                platform_label=platform_label,
            )
            return TrialResult(
                text, False, reason="direct-interface-unavailable", observed_at=observed_at,
            )
        text = (f"🧪 LiteChecker · пробный DIRECT ({platform_label})\n"
                "⚠️ Проверка через физическое подключение не выполнена.\n"
                "Интерфейс или его DNS недоступен/неоднозначен. VPN мог запретить прямой выход.\n"
                "Настройки VPN не изменены; обычный маршрут для проверок не использован.")
        await deliver(text)
        return TrialResult(text, False)
    async with DirectRelay(network) as relay:
        scoped_exit, ordinary_exit = await asyncio.gather(
            lookup_exit(proxy_url=relay.proxy_url), lookup_exit(),
        )
        if scoped_exit is None:
            observed_at = datetime.now(UTC)
            if production:
                from litechecker.direct_reporting import format_unavailable

                text = format_unavailable(
                    settings.identity, "direct-exit-unavailable", observed_at,
                    platform_label=platform_label,
                )
                return TrialResult(
                    text, False, reason="direct-exit-unavailable",
                    observed_at=observed_at, interface=network.interface,
                )
            text = (f"🧪 LiteChecker · пробный DIRECT ({platform_label}) · {network.interface}\n"
                    "⚠️ Проверка не выполнена: контроль выхода через физический интерфейс не прошёл.\n"
                    "Возможны блокировка VPN, сбой DNS, IPinfo или сети. На обычный маршрут проверки не переключались.")
            await deliver(text)
            return TrialResult(text, False)
        dependencies = scoped_dependencies(settings, network, relay)
        report = await measure_cycle(settings.agent, dependencies)
        if validate_after:
            try:
                network._validate_interface()
            except DirectNetworkUnavailable:
                # A changed adapter invalidates attribution even for open flows
                # which completed successfully. Do not retain green data.
                report = report.model_copy(update={
                    "run_status": ResultStatus.UNKNOWN,
                    "run_reason": "direct-interface-changed",
                    "results": [result.model_copy(update={
                        "status": ResultStatus.UNKNOWN, "stage": ProbeStage.POLICY,
                        "error_code": "direct-interface-changed", "latency_ms": None,
                    }) for result in report.results],
                })
        save_last_observation(settings.state_dir, report, interface=network.interface,
                              scoped_exit=scoped_exit, ordinary_exit=ordinary_exit)
        if production:
            from litechecker.direct_reporting import format_direct

            text = format_direct(
                report, settings.identity, network.interface, scoped_exit, ordinary_exit,
                platform_label=platform_label,
            )
        else:
            text = format_trial(
                report, settings.identity, network.interface, scoped_exit, ordinary_exit,
                platform_label=platform_label,
            )
        await deliver(text)
        return TrialResult(
            text,
            trial_completed(report),
            report=report,
            observed_at=report.observed_at,
            interface=network.interface,
        )


def trial_settings(root: Path, xray: str, *, environment=None):
    # Intentionally do not source the Docker .env or reuse another running
    # agent's state/identity. This is a separate, labelled experiment.
    env = dict(os.environ if environment is None else environment)
    env.pop("LC_AGENT_ID", None)
    env.pop("LC_CONTAINER_MODE", None)
    env.update(
        LC_STATE_DIR=str(root / "state" / "direct-trial"), LC_XRAY_BINARY=xray,
        LC_TELEGRAM_BOT_TOKEN_FILE=str(root / "secrets" / "telegram_bot_token"),
        LC_SUBSCRIPTION_URL_FILE=str(root / "secrets" / "subscription_url"),
    )
    env.setdefault("LC_TELEGRAM_CHAT_ID", "-5361201677")
    proxy_file = root / "secrets" / "telegram_proxy_url"
    if "LC_TELEGRAM_PROXY_URL" not in env and "LC_TELEGRAM_PROXY_URL_FILE" not in env:
        if proxy_file.exists() or proxy_file.is_symlink():
            env["LC_TELEGRAM_PROXY_URL_FILE"] = str(proxy_file)
    return StandaloneSettings.from_env(env)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Experimental macOS scoped-interface check; no universal VPN bypass")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--xray", default="xray")
    parser.add_argument("--send", action="store_true", help="send ONE explicitly experimental Telegram report")
    args = parser.parse_args(argv)

    async def execute():
        settings = trial_settings(args.root.resolve(), args.xray)
        async with AsyncFileLock(settings.state_dir / "trial.lock", timeout=0, mode=0o600):
            async with asyncio.timeout(settings.agent.run_deadline_seconds + 60):
                result = await run_trial(settings, send=args.send)
                print(result.text)
                if args.send:
                    print("Telegram: отчёт принят.")
                return 0 if result.available else 1
    try:
        return asyncio.run(run_with_signals(execute()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Пробная проверка остановлена.")
        return 130
    except Exception:
        print("Пробная проверка не завершена. Проверьте зависимости, доступ к сети и файлам secrets. Доставка Telegram не подтверждена.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

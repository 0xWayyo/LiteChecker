"""Honest target diagnostics and end-to-end probe classification."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import ipaddress
import json
import secrets
import socket
import ssl
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from os import PathLike
from typing import Any, Protocol

import httpx
import psutil

from litechecker.models import ProbeResult, ProbeStage, ResultStatus, TargetConfig
from litechecker.security import is_forbidden_ip
from litechecker.probe_policy import PROBE_TIMEOUT_SECONDS, TCP_TIMEOUT_SECONDS
from litechecker.runtime import join_owned_tasks


@dataclass(frozen=True)
class Canary:
    url: str
    expected_status: int = 204


DEFAULT_CANARIES = (
    Canary("https://www.gstatic.com/generate_204"),
    Canary("https://cp.cloudflare.com/generate_204"),
)
_MAX_RESOLVED_ADDRESSES = 64


@dataclass(frozen=True)
class ControlResult:
    ok: bool
    latency_ms: int | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class DiagnosticResult:
    ok: bool
    latency_ms: int | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class TunnelResult:
    canary_ok: bool
    latency_ms: int | None = None
    error_code: str | None = None


class XrayUnavailable(RuntimeError):
    """Xray failed before it yielded target-specific tunnel evidence."""

    def __init__(self, error_code: str):
        super().__init__(error_code)
        self.error_code = error_code


class ListenerOwner(Protocol):
    async def owns_listener(self, host: str, port: int) -> bool: ...


ListenerOwnerFactory = Callable[[int], ListenerOwner]


class XraySession(str):
    """A proxy URL coupled to the exact per-open process lease that created it."""

    def __new__(cls, url: str, lease: "_XrayLease") -> "XraySession":
        session = super().__new__(cls, url)
        session._lease = lease
        return session

    async def ensure_healthy(self) -> None:
        await self._lease.ensure_healthy()


class XrayProcess:
    """Own one minimal, short-lived Xray process and its loopback SOCKS listener."""

    def __init__(
        self,
        binary: str | PathLike[str] = "xray",
        *,
        startup_timeout: float = 3.0,
        shutdown_timeout: float = 1.0,
        stderr_limit: int = 4096,
        owner_factory: ListenerOwnerFactory | None = None,
        dialer_proxy: dict | None = None,
    ):
        self._binary = str(binary)
        self._startup_timeout = startup_timeout
        self._shutdown_timeout = shutdown_timeout
        self._stderr_limit = stderr_limit
        self._owner_factory = owner_factory or _PsutilListenerOwner
        self._dialer_proxy = copy.deepcopy(dialer_proxy)

    @contextlib.asynccontextmanager
    async def open(self, target: TargetConfig) -> AsyncIterator[XraySession]:
        port = _unused_loopback_port()
        inbound_tag = f"lc-in-{secrets.token_hex(8)}"
        outbound_tag = f"lc-out-{secrets.token_hex(8)}"
        username = secrets.token_hex(16)
        password = secrets.token_hex(16)
        try:
            payload = _minimal_xray_config(
                target,
                port,
                inbound_tag,
                outbound_tag,
                username,
                password,
                dialer_proxy=self._dialer_proxy,
            )
        except (TypeError, ValueError):
            raise XrayUnavailable("xray-config") from None

        try:
            process = await asyncio.create_subprocess_exec(
                self._binary,
                "run",
                "-config",
                "stdin:",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                creationflags=0x08000000 if sys.platform == "win32" else 0,  # CREATE_NO_WINDOW
            )
        except FileNotFoundError:
            raise XrayUnavailable("xray-missing") from None
        except OSError:
            raise XrayUnavailable("xray-start") from None

        stderr_task = asyncio.create_task(
            _consume_bounded(process.stderr, self._stderr_limit)
        )
        try:
            try:
                owner = self._owner_factory(process.pid)
            except Exception:
                raise XrayUnavailable("xray-ownership") from None
            lease = _XrayLease(
                process=process,
                owner=owner,
                port=port,
                username=username,
                password=password,
            )
            if process.stdin is None:
                raise XrayUnavailable("xray-stdin")
            try:
                process.stdin.write(payload)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()

            await _wait_for_owned_listener(lease, self._startup_timeout)
            session = XraySession(
                f"socks5://{username}:{password}@127.0.0.1:{port}",
                lease,
            )
            yield session
            await session.ensure_healthy()
        finally:
            async def cleanup():
                try:
                    await _stop_process(process, self._shutdown_timeout)
                finally:
                    try:
                        await asyncio.wait_for(stderr_task, timeout=self._shutdown_timeout)
                    except TimeoutError:
                        await join_owned_tasks((stderr_task,), cancel=True)
            cleanup_task = asyncio.create_task(cleanup())
            await join_owned_tasks((cleanup_task,))
            cleanup_task.result()


class XrayTunnel:
    """Require an expected HTTPS response sent through one Xray SOCKS listener."""

    def __init__(
        self,
        process: XrayProcess,
        *,
        canaries: Sequence[Canary] = DEFAULT_CANARIES,
        timeout: float = PROBE_TIMEOUT_SECONDS,
        client_factory: Callable[..., Any] = httpx.AsyncClient,
        verify: ssl.SSLContext | bool = True,
    ):
        self._process = process
        self._canaries = tuple(canaries)
        self._timeout = timeout
        self._client_factory = client_factory
        self._verify = verify

    async def check(self, target: TargetConfig) -> TunnelResult:
        async with self._process.open(target) as proxy_url:
            had_timeout = False
            try:
                async with asyncio.timeout(self._timeout):
                    deadline = asyncio.get_running_loop().time() + self._timeout
                    async with self._client_factory(
                        proxy=proxy_url,
                        trust_env=False,
                        timeout=self._timeout,
                        verify=self._verify,
                    ) as client:
                        for index, canary in enumerate(self._canaries):
                            await proxy_url.ensure_healthy()
                            started_ns = time.monotonic_ns()
                            try:
                                # Reserve a share of the total budget for every canary.
                                # One stalled provider must not prevent trying the next.
                                remaining = deadline - asyncio.get_running_loop().time()
                                budget = max(0.0, remaining) / (len(self._canaries) - index)
                                async with asyncio.timeout(budget):
                                    response = await client.get(canary.url)
                            except (TimeoutError, httpx.TimeoutException):
                                had_timeout = True
                                await proxy_url.ensure_healthy()
                                continue
                            except Exception:
                                await proxy_url.ensure_healthy()
                                continue
                            await proxy_url.ensure_healthy()
                            if response.status_code == canary.expected_status:
                                return TunnelResult(
                                    canary_ok=True,
                                    latency_ms=max(
                                        0,
                                        (time.monotonic_ns() - started_ns) // 1_000_000,
                                    ),
                                )
                        await proxy_url.ensure_healthy()
            except TimeoutError:
                await proxy_url.ensure_healthy()
                return TunnelResult(
                    canary_ok=False,
                    error_code="canary-timeout",
                )
        return TunnelResult(
            canary_ok=False,
            error_code="canary-timeout" if had_timeout else "canary-failed",
        )


class Resolver(Protocol):
    async def resolve(self, target: TargetConfig) -> list[str]: ...


class TcpDiagnostic(Protocol):
    async def check(
        self, target: TargetConfig, addresses: list[str]
    ) -> DiagnosticResult: ...


class TlsDiagnostic(Protocol):
    async def check(self, target: TargetConfig, address: str) -> DiagnosticResult: ...


class TunnelProbe(Protocol):
    async def check(self, target: TargetConfig) -> TunnelResult: ...


ControlRequester = Callable[[Canary, float], Awaitable[int]]


class _SystemResolver:
    async def resolve(self, target: TargetConfig) -> list[str]:
        if target.address_kind == "ip":
            return [str(ipaddress.ip_address(target.address))]
        loop = asyncio.get_running_loop()
        answers = await loop.getaddrinfo(
            target.address,
            target.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return list(dict.fromkeys(answer[4][0] for answer in answers))


class _TcpDiagnostic:
    def __init__(self, timeout: float):
        self._timeout = timeout

    async def check(
        self, target: TargetConfig, addresses: list[str]
    ) -> DiagnosticResult:
        last_error = "tcp-failed"
        for address in addresses:
            started_ns = time.monotonic_ns()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, target.port),
                    timeout=self._timeout,
                )
                del reader
                latency_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
                writer.close()
                await writer.wait_closed()
                return DiagnosticResult(ok=True, latency_ms=latency_ms)
            except TimeoutError:
                last_error = "tcp-timeout"
            except (ConnectionError, OSError):
                last_error = "tcp-connect"
        return DiagnosticResult(ok=False, error_code=last_error)


class _TlsDiagnostic:
    """Verify a domain's TLS certificate while dialing only a validated IP."""

    def __init__(self, timeout: float, *, context: ssl.SSLContext | None = None):
        self._timeout = timeout
        self._context = context or ssl.create_default_context()
        if not self._context.check_hostname or self._context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS diagnostics require certificate and hostname verification")

    async def check(self, target: TargetConfig, address: str) -> DiagnosticResult:
        writer: asyncio.StreamWriter | None = None
        started_ns = time.monotonic_ns()
        try:
            async with asyncio.timeout(self._timeout):
                reader, writer = await asyncio.open_connection(
                    address,
                    target.port,
                    ssl=self._context,
                    server_hostname=target.address,
                    ssl_handshake_timeout=self._timeout,
                    ssl_shutdown_timeout=min(1.0, self._timeout),
                )
                del reader
                return DiagnosticResult(
                    ok=True,
                    latency_ms=max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
                )
        except ssl.SSLCertVerificationError:
            return DiagnosticResult(ok=False, error_code="tls-certificate")
        except TimeoutError:
            return DiagnosticResult(ok=False, error_code="tls-timeout")
        except (ssl.SSLError, ConnectionError, OSError):
            return DiagnosticResult(ok=False, error_code="tls-handshake")
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=min(1.0, self._timeout))


async def check_control(
    *,
    canaries: Sequence[Canary] = DEFAULT_CANARIES,
    timeout: float = 5.0,
    requester: ControlRequester | None = None,
) -> ControlResult:
    """Accept control when either independent direct canary responds as expected."""
    if requester is None:
        async with httpx.AsyncClient(
            trust_env=False,
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            async def request(canary: Canary, request_timeout: float) -> int:
                del request_timeout
                response = await client.get(canary.url)
                return response.status_code

            return await check_control(
                canaries=canaries,
                timeout=timeout,
                requester=request,
            )

    started_ns = time.monotonic_ns()
    for canary in canaries:
        try:
            status = await requester(canary, timeout)
        except Exception:
            continue
        if status == canary.expected_status:
            return ControlResult(
                ok=True,
                latency_ms=max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
            )
    return ControlResult(ok=False, error_code="control-failed")


async def probe_target(
    target: TargetConfig,
    *,
    control: ControlResult,
    resolver: Resolver | None = None,
    tcp: TcpDiagnostic | None = None,
    tls: TlsDiagnostic | None = None,
    tunnel: TunnelProbe | None = None,
    allow_private_targets: bool = False,
    tcp_timeout: float = TCP_TIMEOUT_SECONDS,
    probe_timeout: float = PROBE_TIMEOUT_SECONDS,
    xray_binary: str | PathLike[str] = "xray",
    canaries: Sequence[Canary] = DEFAULT_CANARIES,
) -> ProbeResult:
    """Classify one target without promoting DNS or TCP diagnostics to UP."""
    if not control.ok:
        return _result(
            target,
            ResultStatus.UNKNOWN,
            ProbeStage.AGENT_NETWORK,
            error_code=_map_error_code(
                control.error_code,
                _CONTROL_ERROR_CODES,
                "control-failed",
            ),
        )

    try:
        raw_addresses = await (resolver or _SystemResolver()).resolve(target)
    except OSError:
        return _result(
            target,
            ResultStatus.DOWN,
            ProbeStage.DNS,
            error_code="dns-failed",
        )
    except (TypeError, ValueError):
        return _result(
            target,
            ResultStatus.UNKNOWN,
            ProbeStage.POLICY,
            error_code="dns-invalid",
        )
    if not raw_addresses:
        return _result(
            target,
            ResultStatus.DOWN,
            ProbeStage.DNS,
            error_code="dns-empty",
        )
    if len(raw_addresses) > _MAX_RESOLVED_ADDRESSES:
        return _result(
            target,
            ResultStatus.UNKNOWN,
            ProbeStage.POLICY,
            error_code="dns-answer-limit",
        )
    try:
        parsed_addresses = [ipaddress.ip_address(address) for address in raw_addresses]
        all_addresses = [
            str(address)
            for address in sorted(
                set(parsed_addresses), key=lambda item: (item.version, int(item))
            )
        ]
        if any(
            is_forbidden_ip(address, allow_private=allow_private_targets)
            for address in all_addresses
        ):
            return _result(
                target,
                ResultStatus.UNKNOWN,
                ProbeStage.POLICY,
                resolved_ips=all_addresses[:16],
                error_code="forbidden-address",
            )
    except (TypeError, ValueError):
        return _result(
            target,
            ResultStatus.UNKNOWN,
            ProbeStage.POLICY,
            error_code="dns-invalid",
        )

    resolved_ips = all_addresses[:16]
    tcp_probe = tcp or _TcpDiagnostic(tcp_timeout)
    if target.check_kind == "sni":
        return await _probe_sni(
            target,
            addresses=all_addresses,
            tcp=tcp_probe,
            tls=tls or _TlsDiagnostic(probe_timeout),
        )
    if tunnel is None:
        tunnel = XrayTunnel(
            XrayProcess(xray_binary),
            canaries=canaries,
            timeout=probe_timeout,
        )
    tcp_succeeded = False
    last_tcp = DiagnosticResult(ok=False, error_code="tcp-failed")
    last_tunnel = TunnelResult(canary_ok=False, error_code="canary-failed")
    for address in all_addresses:
        last_tcp = await tcp_probe.check(target, [address])
        if not last_tcp.ok:
            continue
        tcp_succeeded = True
        bound_target = _bound_target(target, address)
        try:
            last_tunnel = await tunnel.check(bound_target)
        except XrayUnavailable as exc:
            return _result(
                target,
                ResultStatus.UNKNOWN,
                ProbeStage.XRAY,
                resolved_ips=resolved_ips,
                latency_ms=last_tcp.latency_ms,
                error_code=_map_error_code(
                    exc.error_code,
                    _XRAY_ERROR_CODES,
                    "xray-error",
                ),
            )
        except Exception:
            return _result(
                target,
                ResultStatus.UNKNOWN,
                ProbeStage.XRAY,
                resolved_ips=resolved_ips,
                latency_ms=last_tcp.latency_ms,
                error_code="xray-error",
            )
        if last_tunnel.canary_ok:
            return _result(
                target,
                ResultStatus.UP,
                ProbeStage.E2E,
                resolved_ips=resolved_ips,
                latency_ms=last_tunnel.latency_ms,
            )
    if not tcp_succeeded:
        return _result(
            target,
            ResultStatus.DOWN,
            ProbeStage.TCP,
            resolved_ips=resolved_ips,
            latency_ms=last_tcp.latency_ms,
            error_code=_map_error_code(
                last_tcp.error_code,
                _TCP_ERROR_CODES,
                "tcp-failed",
            ),
        )
    return _result(
        target,
        ResultStatus.DOWN,
        ProbeStage.VLESS_E2E,
        resolved_ips=resolved_ips,
        latency_ms=last_tcp.latency_ms,
        error_code=_map_error_code(
            last_tunnel.error_code,
            _TUNNEL_ERROR_CODES,
            "canary-failed",
        ),
    )


async def _probe_sni(
    target: TargetConfig,
    *,
    addresses: list[str],
    tcp: TcpDiagnostic,
    tls: TlsDiagnostic,
) -> ProbeResult:
    """Check the SNI domain's direct TLS service independently of its VPN use."""
    resolved_ips = addresses[:16]
    tcp_succeeded = False
    last_tcp = DiagnosticResult(ok=False, error_code="tcp-failed")
    last_tls = DiagnosticResult(ok=False, error_code="tls-handshake")
    for address in addresses:
        last_tcp = await tcp.check(target, [address])
        if not last_tcp.ok:
            continue
        tcp_succeeded = True
        try:
            last_tls = await tls.check(target, address)
        except Exception:
            return _result(
                target,
                ResultStatus.UNKNOWN,
                ProbeStage.POLICY,
                resolved_ips=resolved_ips,
                error_code="tls-local-error",
            )
        if last_tls.ok:
            return _result(
                target,
                ResultStatus.UP,
                ProbeStage.TLS,
                resolved_ips=resolved_ips,
                latency_ms=last_tls.latency_ms,
            )
    if not tcp_succeeded:
        return _result(
            target,
            ResultStatus.DOWN,
            ProbeStage.TCP,
            resolved_ips=resolved_ips,
            error_code=_map_error_code(last_tcp.error_code, _TCP_ERROR_CODES, "tcp-failed"),
        )
    error_code = _map_error_code(last_tls.error_code, _TLS_ERROR_CODES, "tls-handshake")
    return _result(
        target,
        ResultStatus.DOWN,
        ProbeStage.TLS_CERTIFICATE if error_code == "tls-certificate" else ProbeStage.TLS_HANDSHAKE,
        resolved_ips=resolved_ips,
        error_code=error_code,
    )


def _bound_target(target: TargetConfig, address: str) -> TargetConfig:
    """Bind the dial address to one already-validated DNS answer, preserving SNI."""
    outbound = copy.deepcopy(target.outbound)
    try:
        server = outbound["settings"]["vnext"][0]
        if not isinstance(server, dict):
            raise TypeError
        server["address"] = str(ipaddress.ip_address(address))
    except (KeyError, IndexError, TypeError, ValueError):
        raise XrayUnavailable("xray-config") from None
    return target.model_copy(update={"outbound": outbound})


async def probe_all(
    targets: Sequence[TargetConfig],
    *,
    control: ControlResult,
    max_concurrency: int,
    deadline_seconds: float,
    resolver: Resolver | None = None,
    tcp: TcpDiagnostic | None = None,
    tls: TlsDiagnostic | None = None,
    tunnel: TunnelProbe | None = None,
    allow_private_targets: bool = False,
    tcp_timeout: float = TCP_TIMEOUT_SECONDS,
    probe_timeout: float = PROBE_TIMEOUT_SECONDS,
    xray_binary: str | PathLike[str] = "xray",
    canaries: Sequence[Canary] = DEFAULT_CANARIES,
) -> list[ProbeResult]:
    """Probe a bounded target set and explicitly classify unfinished deadline work."""
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be positive")
    if not targets:
        return []
    semaphore = asyncio.Semaphore(max_concurrency)

    async def run_one(target: TargetConfig) -> ProbeResult:
        async with semaphore:
            return await probe_target(
                target,
                control=control,
                resolver=resolver,
                tcp=tcp,
                tls=tls,
                tunnel=tunnel,
                allow_private_targets=allow_private_targets,
                tcp_timeout=tcp_timeout,
                probe_timeout=probe_timeout,
                xray_binary=xray_binary,
                canaries=canaries,
            )

    tasks = [asyncio.create_task(run_one(target)) for target in targets]
    done: set[asyncio.Task[ProbeResult]] = set()
    pending: set[asyncio.Task[ProbeResult]] = set(tasks)
    try:
        done, pending = await asyncio.wait(
            tasks,
            timeout=max(0.0, deadline_seconds),
        )
    finally:
        await join_owned_tasks(tasks, cancel=True)

    results: list[ProbeResult] = []
    for target, task in zip(targets, tasks, strict=True):
        if task not in done or task.cancelled():
            results.append(
                _result(
                    target,
                    ResultStatus.UNKNOWN,
                    ProbeStage.DEADLINE,
                    error_code="deadline",
                )
            )
            continue
        try:
            results.append(task.result())
        except Exception:
            results.append(
                _result(
                    target,
                    ResultStatus.UNKNOWN,
                    ProbeStage.POLICY if target.check_kind == "sni" else ProbeStage.XRAY,
                    error_code="probe-error",
                )
            )
    return results


def _result(
    target: TargetConfig,
    status: ResultStatus,
    stage: ProbeStage,
    *,
    latency_ms: int | None = None,
    resolved_ips: list[str] | None = None,
    error_code: str | None = None,
) -> ProbeResult:
    return ProbeResult(
        target_id=target.target_id,
        check_kind=target.check_kind,
        label=target.label,
        address=target.address,
        port=target.port,
        status=status,
        stage=stage,
        latency_ms=latency_ms,
        resolved_ips=resolved_ips or [],
        error_code=error_code,
    )


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _minimal_xray_config(
    target: TargetConfig,
    port: int,
    inbound_tag: str,
    outbound_tag: str,
    username: str,
    password: str,
    dialer_proxy: dict | None = None,
) -> bytes:
    outbound = copy.deepcopy(target.outbound)
    outbound["tag"] = outbound_tag
    outbounds = [outbound]
    if dialer_proxy is not None:
        # Only our one authenticated loopback endpoint may carry the outer
        # transport. Subscription proxy chains and mux must not compete with it.
        helper = _direct_dialer_outbound(dialer_proxy)
        helper["tag"] = f"lc-direct-{secrets.token_hex(16)}"
        outbound.pop("proxySettings", None)
        outbound.pop("mux", None)
        stream = outbound.setdefault("streamSettings", {})
        if not isinstance(stream, dict):
            raise ValueError("invalid target transport")
        sockopt = stream.setdefault("sockopt", {})
        if not isinstance(sockopt, dict):
            raise ValueError("invalid target socket options")
        sockopt["dialerProxy"] = helper["tag"]
        outbounds.append(helper)
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": username, "pass": password}],
                    "udp": False,
                },
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [inbound_tag],
                    "outboundTag": outbound_tag,
                }
            ]
        },
    }
    return json.dumps(config, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _direct_dialer_outbound(value: dict) -> dict:
    """Accept only the generated local SOCKS helper, without alternate routes."""
    try:
        if not isinstance(value, dict) or set(value) - {"tag", "protocol", "settings"}:
            raise ValueError
        if value.get("protocol") != "socks":
            raise ValueError
        settings = value["settings"]
        if not isinstance(settings, dict) or set(settings) != {"servers"}:
            raise ValueError
        servers = settings["servers"]
        if not isinstance(servers, list) or len(servers) != 1:
            raise ValueError
        server = servers[0]
        if not isinstance(server, dict) or set(server) != {"address", "port", "users"}:
            raise ValueError
        if server["address"] != "127.0.0.1":
            raise ValueError
        port = server["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError
        users = server["users"]
        if not isinstance(users, list) or len(users) != 1:
            raise ValueError
        account = users[0]
        if not isinstance(account, dict) or set(account) != {"user", "pass"}:
            raise ValueError
        if any(
            not isinstance(account[key], str) or not 1 <= len(account[key].encode("utf-8")) <= 255
            for key in ("user", "pass")
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise ValueError("invalid direct relay configuration") from None
    return copy.deepcopy(value)


class _PsutilListenerOwner:
    """Bind ownership checks to psutil's PID-plus-creation-time process identity."""

    def __init__(self, pid: int):
        self._process = psutil.Process(pid)
        self._create_time = self._process.create_time()

    async def owns_listener(self, host: str, port: int) -> bool:
        return await asyncio.to_thread(self._owns_listener, host, port)

    def _owns_listener(self, host: str, port: int) -> bool:
        if not self._process.is_running():
            return False
        if self._process.create_time() != self._create_time:
            return False
        expected_address = ipaddress.ip_address(host)
        if not expected_address.is_loopback:
            return False
        matches = []
        for connection in self._process.net_connections(kind="tcp"):
            if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                continue
            local_host = getattr(connection.laddr, "ip", connection.laddr[0])
            local_port = getattr(connection.laddr, "port", connection.laddr[1])
            try:
                local_address = ipaddress.ip_address(local_host)
            except ValueError:
                continue
            if local_address == expected_address and local_port == port:
                matches.append(connection)
        if not self._process.is_running():
            return False
        if self._process.create_time() != self._create_time:
            return False
        return len(matches) == 1


@dataclass(frozen=True)
class _XrayLease:
    process: asyncio.subprocess.Process
    owner: ListenerOwner
    port: int
    username: str
    password: str

    async def ensure_healthy(self) -> None:
        await asyncio.sleep(0)
        if self.process.returncode is not None:
            raise XrayUnavailable("xray-exit")
        try:
            authenticated = await asyncio.wait_for(
                _authenticate_socks(self.port, self.username, self.password),
                timeout=0.25,
            )
        except (ConnectionError, OSError, TimeoutError):
            authenticated = False
        await asyncio.sleep(0)
        if self.process.returncode is not None:
            raise XrayUnavailable("xray-exit")
        if not authenticated:
            raise XrayUnavailable("xray-ownership")
        try:
            owns_listener = await self.owner.owns_listener("127.0.0.1", self.port)
        except Exception:
            raise XrayUnavailable("xray-ownership") from None
        await asyncio.sleep(0)
        if self.process.returncode is not None:
            raise XrayUnavailable("xray-exit")
        if not owns_listener:
            raise XrayUnavailable("xray-ownership")


async def _wait_for_owned_listener(
    lease: _XrayLease,
    timeout: float,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    listener_seen = False
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0)
        if lease.process.returncode is not None:
            raise XrayUnavailable("xray-exit")
        try:
            await lease.ensure_healthy()
        except XrayUnavailable as exc:
            if exc.error_code == "xray-exit":
                raise
            listener_seen = listener_seen or await _listener_present(lease.port)
            await asyncio.sleep(0.01)
            continue
        return
    if lease.process.returncode is not None:
        raise XrayUnavailable("xray-exit")
    if listener_seen:
        raise XrayUnavailable("xray-ownership")
    raise XrayUnavailable("xray-startup-timeout")


async def _listener_present(port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=0.05,
        )
    except (ConnectionError, OSError, TimeoutError):
        return False
    del reader
    writer.close()
    await writer.wait_closed()
    return True


async def _authenticate_socks(port: int, username: str, password: str) -> bool:
    accepted = await _socks_auth_status(port, username, password)
    if accepted != "accepted":
        return False
    replacement = "0" if password[-1] != "0" else "1"
    wrong_password = f"{password[:-1]}{replacement}"
    rejected = await _socks_auth_status(port, username, wrong_password)
    return rejected == "rejected"


async def _socks_auth_status(port: int, username: str, password: str) -> str:
    user_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    if not 1 <= len(user_bytes) <= 255 or not 1 <= len(password_bytes) <= 255:
        return "invalid"
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x02":
            return "invalid"
        writer.write(
            bytes((1, len(user_bytes)))
            + user_bytes
            + bytes((len(password_bytes),))
            + password_bytes
        )
        await writer.drain()
        response = await reader.readexactly(2)
        if response == b"\x01\x00":
            return "accepted"
        if response[:1] == b"\x01":
            return "rejected"
        return "invalid"
    except asyncio.IncompleteReadError:
        return "invalid"
    finally:
        writer.close()
        await writer.wait_closed()


async def _stop_process(process: asyncio.subprocess.Process, timeout: float) -> None:
    if process.returncode is not None:
        await process.wait()
        return
    with contextlib.suppress(ProcessLookupError):
        process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
        return
    except TimeoutError:
        pass
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=timeout)


async def _consume_bounded(
    stream: asyncio.StreamReader | None,
    limit: int,
) -> bytes:
    if stream is None:
        return b""
    captured = bytearray()
    while chunk := await stream.read(4096):
        remaining = max(0, limit - len(captured))
        if remaining:
            captured.extend(chunk[:remaining])
    return bytes(captured)


_CONTROL_ERROR_CODES = frozenset({"control-failed"})
_TCP_ERROR_CODES = frozenset(
    {"tcp-connect", "tcp-failed", "tcp-refused", "tcp-timeout"}
)
_TUNNEL_ERROR_CODES = frozenset(
    {"canary-failed", "canary-timeout", "proxy-connect"}
)
_TLS_ERROR_CODES = frozenset({"tls-certificate", "tls-timeout", "tls-handshake"})
_XRAY_ERROR_CODES = frozenset(
    {
        "xray-config",
        "xray-error",
        "xray-exit",
        "xray-missing",
        "xray-ownership",
        "xray-start",
        "xray-startup-timeout",
        "xray-stdin",
    }
)


def _map_error_code(
    value: str | None,
    allowed: frozenset[str],
    fallback: str,
) -> str:
    if value in allowed:
        assert value is not None
        return value
    return fallback

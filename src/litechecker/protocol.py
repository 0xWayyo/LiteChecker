"""Bounded authenticated delivery from an agent to the central collector."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from litechecker.models import AgentReport
from litechecker.security import is_valid_agent_token


_SUCCESS_STATUSES = frozenset({200, 202})
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


class DeliveryError(RuntimeError):
    """A collector delivery failure represented only by a closed error code."""

    def __init__(self, error_code: str):
        super().__init__(error_code)
        self.error_code = error_code


@dataclass(frozen=True)
class DeliveryResult:
    accepted: bool
    duplicate: bool
    attempts: int


class CollectorClient:
    """Send one bounded report over HTTPS, retrying the same bytes at most once."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        max_payload_bytes: int = 1_048_576,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        allow_insecure_loopback: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] | None = None,
    ):
        self._url = _report_url(
            base_url,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        if not is_valid_agent_token(token):
            raise ValueError("agent token is invalid")
        if max_payload_bytes < 1:
            raise ValueError("max payload size must be positive")
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("collector timeouts must be positive")
        self._token = token
        self._max_payload_bytes = max_payload_bytes
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._transport = transport
        self._sleep = sleep
        self._jitter = jitter or (lambda: random.uniform(0.1, 0.3))

    async def send(self, report: AgentReport) -> DeliveryResult:
        payload = json.dumps(
            report.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(payload) > self._max_payload_bytes:
            raise DeliveryError("collector-payload-too-large")

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            timeout=self._timeout,
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for attempt in (1, 2):
                try:
                    async with client.stream(
                        "POST",
                        self._url,
                        content=payload,
                        headers=headers,
                    ) as response:
                        status_code = response.status_code
                except httpx.TimeoutException:
                    error_code = "collector-timeout"
                except httpx.TransportError:
                    error_code = "collector-network"
                except Exception:
                    error_code = "collector-network"
                else:
                    if status_code in _SUCCESS_STATUSES:
                        return DeliveryResult(
                            accepted=True,
                            duplicate=status_code == 200,
                            attempts=attempt,
                        )
                    error_code = f"collector-http-{status_code}"
                    if status_code not in _RETRYABLE_STATUSES:
                        raise DeliveryError(error_code)

                if attempt == 2:
                    raise DeliveryError(error_code)
                await self._sleep(max(0.0, float(self._jitter())))

        raise DeliveryError("collector-network")


def _report_url(base_url: str, *, allow_insecure_loopback: bool = False) -> str:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("collector URL is invalid") from None
    del port
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("collector URL must be credential-free HTTPS")
    if parsed.scheme == "https":
        pass
    elif not (
        parsed.scheme == "http"
        and allow_insecure_loopback
        and _is_loopback_host(parsed.hostname)
    ):
        raise ValueError("collector URL must be credential-free HTTPS")
    path = f"{parsed.path.rstrip('/')}/v1/reports"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _is_loopback_host(host: str) -> bool:
    if "%" in host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

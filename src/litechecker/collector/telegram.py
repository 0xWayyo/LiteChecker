"""Bounded Telegram Bot API client with closed, sanitized failures."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable

import httpx
from filelock import AsyncFileLock, Timeout as FileLockTimeout

from litechecker.async_state import state_call
from litechecker.collector.db import ClaimedNotification, CollectorDB
from litechecker.collector.telegram_formatting import report_entities
from litechecker.telegram_proxy import validate_telegram_proxy_url


_TOKEN_RE = re.compile(r"[0-9]{3,20}:[A-Za-z0-9_-]{16,200}\Z")
_CHAT_RE = re.compile(r"-?[0-9]{1,32}\Z")
_ERROR_CODE_RE = re.compile(
    r"telegram-(?:network|server-error|rate-limited|rate-limit-invalid|"
    r"response-invalid|response-too-large|content-encoding-invalid|"
    r"message-invalid|send-timeout|unknown|"
    r"http-[1-5][0-9]{2})\Z"
)
_MAX_RESPONSE_BYTES = 65_536
_MAX_RETRY_AFTER = 60.0
_RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 429})
_LOGGER = logging.getLogger(__name__)


class _SocksSetupTraceFilter(logging.Filter):
    """Keep SOCKS setup event names while removing authentication and error details."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "httpcore.socks" and isinstance(record.msg, str):
            event = record.msg.partition(" ")[0]
            if event in {
                "setup_socks5_connection.started",
                "setup_socks5_connection.complete",
                "setup_socks5_connection.failed",
            }:
                record.msg = record.message = event
                record.args = ()
                record.exc_info = None
                record.exc_text = None
                record.stack_info = None
        return True


# A single logger-side filter runs before its handlers and inherited root handlers.
# HTTPcore's setup trace includes raw proxy auth even on successful connections.
_SOCKS_SETUP_TRACE_FILTER = _SocksSetupTraceFilter()
logging.getLogger("httpcore.socks").addFilter(_SOCKS_SETUP_TRACE_FILTER)


class NotificationDispatchError(RuntimeError):
    """Closed supervisor-visible failure at a durable outbox boundary."""

    def __init__(self) -> None:
        super().__init__("notification-dispatch-failed")


class TelegramError(RuntimeError):
    """Closed error code that never embeds request URLs, tokens, or response bodies."""

    def __init__(self, error_code: str):
        if not isinstance(error_code, str) or _ERROR_CODE_RE.fullmatch(error_code) is None:
            raise ValueError("Telegram error code is invalid")
        super().__init__(error_code)
        self.error_code = error_code


class TelegramTransientError(TelegramError):
    """A closed delivery failure that may succeed when retried later."""


class TelegramPermanentError(TelegramError):
    """A closed delivery failure that requires operator intervention."""


def telegram_client_options(settings) -> dict[str, str | int | None]:
    """Extract explicit delivery settings for a caller-owned Telegram client."""
    proxy = settings.telegram_proxy_url
    return {
        "token": settings.telegram_bot_token.get_secret_value(),
        "chat_id": settings.telegram_chat_id,
        "topic_id": settings.telegram_topic_id,
        "proxy_url": proxy.get_secret_value() if proxy is not None else None,
    }


class TelegramClient:
    def __init__(
        self,
        *,
        token: str,
        chat_id: str,
        topic_id: int | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        max_attempts: int = 3,
        proxy_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
            raise ValueError("Telegram token is invalid")
        if not isinstance(chat_id, str) or _CHAT_RE.fullmatch(chat_id) is None:
            raise ValueError("Telegram chat id is invalid")
        if topic_id is not None and (
            not isinstance(topic_id, int) or isinstance(topic_id, bool) or topic_id < 1
        ):
            raise ValueError("Telegram topic id is invalid")
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("Telegram timeouts must be positive")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 5:
            raise ValueError("Telegram retry count is invalid")
        if proxy_url is not None:
            proxy_url = validate_telegram_proxy_url(proxy_url)
            if transport is not None:
                raise ValueError("Telegram proxy and custom transport cannot be combined")
        self._url = "https://api.telegram.org/sendMessage"
        self._chat_id = chat_id
        self._topic_id = topic_id
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._max_attempts = max_attempts
        self._transport = _TokenRoutingTransport(token, transport, proxy_url=proxy_url)
        self._sleep = sleep

    async def send_chunks(self, chunks: Iterable[str]) -> None:
        async with httpx.AsyncClient(
            timeout=self._timeout,
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for chunk in chunks:
                if not isinstance(chunk, str) or not chunk or len(chunk) > 4_096:
                    raise TelegramPermanentError("telegram-message-invalid")
                await self._send_one(client, chunk)

    async def _send_one(self, client: httpx.AsyncClient, text: str) -> None:
        payload: dict[str, object] = {"chat_id": self._chat_id, "text": text}
        entities = report_entities(text)
        if entities:
            payload["entities"] = entities
        if self._topic_id is not None:
            payload["message_thread_id"] = self._topic_id
        body = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
        for attempt in range(1, self._max_attempts + 1):
            try:
                async with client.stream(
                    "POST",
                    self._url,
                    content=body,
                    headers={
                        "Accept-Encoding": "identity",
                        "Content-Type": "application/json",
                    },
                ) as response:
                    status = response.status_code
                    if status == 429:
                        try:
                            response_body = await _read_bounded(response)
                        except TelegramPermanentError:
                            response_body = None
                    elif status in _RETRYABLE_HTTP_STATUSES or 500 <= status <= 599:
                        response_body = None
                    else:
                        response_body = await _read_bounded(response)
            except (httpx.TimeoutException, httpx.TransportError):
                error_code = "telegram-network"
                retry_delay = _backoff(attempt)
            except TelegramError:
                raise
            except Exception:
                error_code = "telegram-network"
                retry_delay = _backoff(attempt)
            else:
                parsed = _parse_json(response_body) if response_body is not None else None
                if status == 200:
                    if _accepted(parsed):
                        return
                    raise TelegramPermanentError("telegram-response-invalid")
                if status == 429:
                    retry_after = _retry_after(parsed)
                    error_code = "telegram-rate-limited"
                    retry_delay = retry_after if retry_after is not None else _backoff(attempt)
                elif status in _RETRYABLE_HTTP_STATUSES or 500 <= status <= 599:
                    error_code = "telegram-server-error"
                    retry_delay = _backoff(attempt)
                else:
                    raise TelegramPermanentError(f"telegram-http-{status}")
            if attempt == self._max_attempts:
                raise TelegramTransientError(error_code)
            await self._sleep(retry_delay)


class NotificationDispatcher:
    """Drain one globally ordered SQLite outbox with per-chunk acknowledgements."""

    def __init__(
        self,
        db: CollectorDB,
        sender,
        *,
        clock: Callable[[], object],
        owner: str | None = None,
        lease_seconds: float = 180.0,
        send_timeout_seconds: float = 120.0,
        lease_margin_seconds: float = 5.0,
        max_delivery_attempts: int = 5,
        retry_delay_seconds: float = 60.0,
        dispatch_lock_timeout_seconds: float = 0.25,
    ):
        numeric = (
            lease_seconds,
            send_timeout_seconds,
            lease_margin_seconds,
            retry_delay_seconds,
            dispatch_lock_timeout_seconds,
        )
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in numeric):
            raise ValueError("notification dispatcher timing is invalid")
        if not 1 <= lease_seconds <= 300 or send_timeout_seconds <= 0 or lease_margin_seconds < 0 or send_timeout_seconds + lease_margin_seconds >= lease_seconds:
            raise ValueError("notification send deadline must be safely below lease")
        if retry_delay_seconds < 0 or retry_delay_seconds > 3600:
            raise ValueError("notification retry delay is invalid")
        if not 0 <= dispatch_lock_timeout_seconds <= 10:
            raise ValueError("dispatcher lock timeout is invalid")
        if isinstance(max_delivery_attempts, bool) or not isinstance(max_delivery_attempts, int) or not 1 <= max_delivery_attempts <= 100:
            raise ValueError("notification attempt limit is invalid")
        self._db = db
        self._sender = sender
        self._clock = clock
        self._owner = owner or uuid.uuid4().hex
        self._lease_seconds = lease_seconds
        self._send_timeout_seconds = send_timeout_seconds
        self._max_delivery_attempts = max_delivery_attempts
        self._retry_delay_seconds = retry_delay_seconds
        self._dispatch_lock_timeout_seconds = float(dispatch_lock_timeout_seconds)
        self._lock = asyncio.Lock()

    async def drain(self) -> None:
        async with self._lock:
            lock = AsyncFileLock(
                self._db.dispatch_lock_path,
                timeout=self._dispatch_lock_timeout_seconds,
                mode=0o600,
                preserve_lock_file=True,
                run_in_executor=True,
            )
            try:
                async with lock:
                    try:
                        await state_call(self._db.reset_notification_leases)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        raise NotificationDispatchError() from None
                    await self._drain_locked()
            except FileLockTimeout:
                return

    async def _drain_locked(self) -> None:
        while True:
            try:
                claim = await state_call(
                    self._db.claim_notification,
                    self._owner,
                    self._clock(),
                    lease_seconds=self._lease_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.error("notification-dispatch-database-failed")
                raise NotificationDispatchError() from None
            if claim is None:
                return
            try:
                async with asyncio.timeout(self._send_timeout_seconds):
                    await self._sender.send_chunks([claim.body])
            except asyncio.CancelledError:
                raise
            except TelegramPermanentError as exc:
                terminal = await self._record_failure(claim, exc.error_code, permanent=True)
                _LOGGER.error("telegram-notify-permanent-failed")
                if terminal:
                    continue
                return
            except TelegramTransientError as exc:
                terminal = await self._record_failure(claim, exc.error_code, permanent=False)
                _LOGGER.error("telegram-notify-transient-failed")
                if terminal:
                    continue
                return
            except TimeoutError:
                terminal = await self._record_failure(claim, "telegram-send-timeout", permanent=False)
                _LOGGER.error("telegram-notify-transient-failed")
                if terminal:
                    continue
                return
            except TelegramError as exc:
                terminal = await self._record_failure(claim, exc.error_code, permanent=False)
                _LOGGER.error("telegram-notify-transient-failed")
                if terminal:
                    continue
                return
            except Exception:
                terminal = await self._record_failure(claim, "telegram-unknown", permanent=False)
                _LOGGER.error("telegram-notify-transient-failed")
                if terminal:
                    continue
                return
            try:
                await state_call(
                    self._db.acknowledge_chunk, claim, self._owner, self._clock()
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.error("notification-dispatch-database-failed")
                raise NotificationDispatchError() from None

    async def _record_failure(self, claim: ClaimedNotification, error_code: str, *, permanent: bool) -> bool:
        try:
            return await state_call(
                self._db.record_notification_failure,
                claim,
                self._owner,
                error_code,
                self._clock(),
                permanent=permanent,
                max_attempts=self._max_delivery_attempts,
                retry_delay_seconds=self._retry_delay_seconds,
            )
        except Exception:
            _LOGGER.error("notification-dispatch-database-failed")
            raise NotificationDispatchError() from None


async def _read_bounded(response: httpx.Response) -> bytes:
    """Read capped identity wire bytes; consumed test responses supply those bytes directly."""
    content_encodings = [
        value.strip().lower()
        for value in response.headers.get_list("content-encoding", split_commas=True)
    ]
    if content_encodings and content_encodings != ["identity"]:
        raise TelegramPermanentError("telegram-content-encoding-invalid")
    content_lengths = response.headers.get_list("content-length")
    if content_lengths:
        if len(content_lengths) != 1 or re.fullmatch(r"[0-9]+", content_lengths[0]) is None:
            raise TelegramPermanentError("telegram-response-invalid")
        if int(content_lengths[0]) > _MAX_RESPONSE_BYTES:
            raise TelegramPermanentError("telegram-response-too-large")
    if response.is_stream_consumed:
        body = response.content
        if len(body) > _MAX_RESPONSE_BYTES:
            raise TelegramPermanentError("telegram-response-too-large")
        return body
    body = bytearray()
    async for chunk in response.aiter_raw():
        if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
            raise TelegramPermanentError("telegram-response-too-large")
        body.extend(chunk)
    return bytes(body)


class _TokenRoutingTransport(httpx.AsyncBaseTransport):
    """Keep the secret Bot API path below HTTPX's request logging layer."""

    def __init__(
        self,
        token: str,
        transport: httpx.AsyncBaseTransport | None,
        *,
        proxy_url: str | None = None,
    ):
        self._target_url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            self._transport = transport if transport is not None else httpx.AsyncHTTPTransport(
                proxy=proxy_url, trust_env=False,
            )
        except Exception:
            raise ValueError("Telegram transport configuration is invalid") from None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        routed = httpx.Request(
            request.method,
            self._target_url,
            headers=request.headers,
            content=request.content,
            extensions=request.extensions,
        )
        return await self._transport.handle_async_request(routed)

    async def aclose(self) -> None:
        try:
            await self._transport.aclose()
        except Exception:
            raise TelegramTransientError("telegram-network") from None


def _parse_json(body: bytes) -> object:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _accepted(payload: object) -> bool:
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return False
    result = payload.get("result")
    message_id = result.get("message_id") if isinstance(result, dict) else None
    return isinstance(message_id, int) and not isinstance(message_id, bool)


def _retry_after(payload: object) -> float | None:
    if not isinstance(payload, dict):
        return None
    parameters = payload.get("parameters")
    value = parameters.get("retry_after") if isinstance(parameters, dict) else None
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 <= float(value) <= _MAX_RETRY_AFTER
    ):
        return None
    return float(value)


def _backoff(attempt: int) -> float:
    return min(1.0, 0.25 * (2 ** (attempt - 1)))

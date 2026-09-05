from __future__ import annotations

import asyncio
import gzip
import logging
import tracemalloc
from collections.abc import Iterable

import httpx
import pytest

from litechecker.collector.telegram import (
    TelegramClient,
    TelegramError,
    TelegramPermanentError,
    TelegramTransientError,
    _read_bounded,
)


FAKE_TOKEN = "123456:example-token-for-tests-only"


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, outcomes: Iterable[httpx.Response | Exception]):
        self.outcomes = iter(outcomes)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        self.requests.append(request)
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        outcome.request = request
        return outcome


def _ok(message_id=1):
    return httpx.Response(200, json={"ok": True, "result": {"message_id": message_id}})


@pytest.mark.asyncio
async def test_telegram_posts_plain_text_with_optional_topic_and_no_redirects():
    """Telegram delivery must use the intended method and preserve thread routing."""
    transport = RecordingTransport([_ok()])
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        topic_id=42,
        transport=transport,
    )

    await client.send_chunks(["Отчет"])

    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"/bot{FAKE_TOKEN}/sendMessage"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["content-type"].startswith("application/json")
    assert request.content == (
        b'{"chat_id":"-1001234567890","text":"\\u041e\\u0442\\u0447\\u0435\\u0442",'
        b'"message_thread_id":42}'
    )


@pytest.mark.asyncio
async def test_http_stack_logging_never_contains_bot_token(caplog):
    """The token-bearing Bot API path must not reach HTTPX, HTTPCore, app, or root logs."""
    caplog.set_level(logging.DEBUG)
    transport = RecordingTransport([_ok()])

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=transport,
    )
    await client.send_chunks(["report"])

    rendered_records: list[str] = []
    for record in caplog.records:
        rendered = " | ".join(
            (
                record.getMessage(),
                repr(record.args),
                repr(record.exc_info),
                repr(record),
            )
        )
        rendered_records.append(rendered)
        assert FAKE_TOKEN not in rendered
    assert any(
        "https://api.telegram.org/sendMessage" in rendered
        for rendered in rendered_records
    )
    assert FAKE_TOKEN not in repr(client)


@pytest.mark.asyncio
async def test_retry_and_exception_log_records_never_contain_bot_token(caplog):
    """Retries and transport failures must use the same token-free logging boundary."""
    caplog.set_level(logging.DEBUG)
    request = httpx.Request("POST", "https://safe.invalid")
    transport = RecordingTransport(
        [
            httpx.Response(500, json={"ok": False}),
            httpx.ConnectError("temporary", request=request),
            _ok(),
        ]
    )

    async def no_sleep(delay):
        pass

    await TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=transport,
        sleep=no_sleep,
    ).send_chunks(["report"])

    for record in caplog.records:
        assert FAKE_TOKEN not in " | ".join(
            (record.getMessage(), repr(record.args), repr(record.exc_info), repr(record))
        )


@pytest.mark.asyncio
async def test_token_bearing_inner_transport_exception_is_closed_and_never_logged(caplog):
    """Even an exception carrying the routed URL must not escape the client boundary."""
    caplog.set_level(logging.DEBUG)

    class TokenBearingFailure(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            assert request.url.path == f"/bot{FAKE_TOKEN}/sendMessage"
            raise httpx.ConnectError(f"failed {request.url!s}", request=request)

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=TokenBearingFailure(),
        max_attempts=1,
    )

    with pytest.raises(TelegramTransientError, match="^telegram-network$") as raised:
        await client.send_chunks(["report"])

    rendered = "\n".join(
        " | ".join(
            (record.getMessage(), repr(record.args), repr(record.exc_info), repr(record))
        )
        for record in caplog.records
    )
    assert FAKE_TOKEN not in rendered
    assert FAKE_TOKEN not in repr(raised.value)


@pytest.mark.asyncio
async def test_real_loopback_httpcore_debug_records_never_contain_routed_token(caplog):
    """The real HTTPCore stack may see the path, but its DEBUG records stay token-free."""
    captured_request = bytearray()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        headers = await reader.readuntil(b"\r\n\r\n")
        captured_request.extend(headers)
        content_length = 0
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1])
        captured_request.extend(await reader.readexactly(content_length))
        body = b'{"ok":true,"result":{"message_id":1}}'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=httpx.AsyncHTTPTransport(),
        max_attempts=1,
    )
    client._transport._target_url = (
        f"http://127.0.0.1:{port}/bot{FAKE_TOKEN}/sendMessage"
    )
    caplog.set_level(logging.DEBUG)
    try:
        await client.send_chunks(["report"])
    finally:
        server.close()
        await server.wait_closed()

    assert f"POST /bot{FAKE_TOKEN}/sendMessage HTTP/1.1".encode() in captured_request
    rendered = "\n".join(
        " | ".join(
            (record.getMessage(), repr(record.args), repr(record.exc_info), repr(record))
        )
        for record in caplog.records
    )
    assert FAKE_TOKEN not in rendered
    assert "https://api.telegram.org/sendMessage" in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(400, json={"ok": False, "description": "chat not found"}),
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json={"ok": False}),
    ],
)
async def test_permanent_bot_api_failures_have_explicit_closed_type(response):
    """Invalid destination and malformed accepted responses cannot heal by retrying."""
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=RecordingTransport([response]),
        max_attempts=1,
    )

    with pytest.raises(TelegramPermanentError) as raised:
        await client.send_chunks(["report"])

    assert str(raised.value) in {"telegram-http-400", "telegram-response-invalid"}
    assert "chat not found" not in str(raised.value)


@pytest.mark.asyncio
async def test_two_maximum_retry_after_sleeps_end_as_transient_failure():
    """The worst Bot API retry path remains explicitly transient and bounded."""
    responses = [
        httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 60}})
        for _ in range(3)
    ]
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=RecordingTransport(responses),
        sleep=fake_sleep,
        max_attempts=3,
    )

    with pytest.raises(TelegramTransientError, match="^telegram-rate-limited$"):
        await client.send_chunks(["report"])

    assert sleeps == [60.0, 60.0]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 425, 500, 502, 503])
async def test_retryable_status_is_transient_before_malformed_body_classification(status):
    """Retry semantics come from status even when an upstream error body is not JSON."""
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=RecordingTransport([httpx.Response(status, content=b"not-json")]),
        max_attempts=1,
    )

    with pytest.raises(TelegramTransientError):
        await client.send_chunks(["report"])


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 500, 502, 503])
async def test_retryable_status_with_oversized_body_stays_transient_and_closes_stream(status):
    """A hostile retryable response cannot turn a temporary outage into a dead letter."""
    oversized = b"x" * 10_000_000

    class OversizedStream(httpx.AsyncByteStream):
        def __init__(self):
            self.closed = False

        async def __aiter__(self):
            yield oversized

        async def aclose(self):
            self.closed = True

    stream = OversizedStream()
    transport = RecordingTransport(
        [httpx.Response(status, stream=stream), _ok()]
    )
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=transport,
        max_attempts=2,
    )

    tracemalloc.start()
    try:
        await client.send_chunks(["report"])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert stream.closed is True
    assert len(transport.requests) == 2
    assert peak < 1_000_000


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first",
    [
        httpx.Response(429, text="not-json"),
        httpx.Response(429, json={"ok": False}),
        httpx.Response(429, json={"ok": False, "parameters": {"retry_after": "bad"}}),
    ],
)
async def test_429_without_valid_retry_after_uses_safe_backoff_then_recovers(first):
    """Missing or malformed retry metadata remains a recoverable rate limit."""
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=RecordingTransport([first, _ok()]),
        sleep=fake_sleep,
        max_attempts=2,
    )

    await client.send_chunks(["report"])

    assert sleeps == [0.25]


@pytest.mark.asyncio
async def test_response_cap_checks_chunk_length_before_copying_it():
    """A hostile raw wire chunk must not be copied or decoded before the cap rejects it."""
    oversized = b"x" * 10_000_000

    class Response:
        headers = httpx.Headers()
        is_stream_consumed = False
        raw_iterated = False
        decoded_iterated = False

        async def aiter_raw(self):
            self.raw_iterated = True
            yield oversized

        async def aiter_bytes(self):
            self.decoded_iterated = True
            yield oversized

    response = Response()
    tracemalloc.start()
    try:
        with pytest.raises(TelegramError, match="telegram-response-too-large"):
            await _read_bounded(response)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert response.raw_iterated is True
    assert response.decoded_iterated is False
    assert peak < 1_000_000


@pytest.mark.asyncio
async def test_response_content_length_cap_rejects_before_stream_iteration():
    """An oversized declared wire body must be rejected without touching its stream."""

    class Response:
        headers = httpx.Headers({"Content-Length": "65537"})
        is_stream_consumed = False
        iterated = False

        async def aiter_raw(self):
            self.iterated = True
            yield b"should-not-be-read"

        async def aiter_bytes(self):
            self.iterated = True
            yield b"should-not-be-read"

    response = Response()
    with pytest.raises(TelegramPermanentError, match="telegram-response-too-large"):
        await _read_bounded(response)

    assert response.iterated is False


@pytest.mark.asyncio
async def test_consumed_synthetic_identity_response_is_treated_as_supplied_raw_bytes():
    """Injected HTTPX responses define consumed identity content as the bounded wire body."""
    body = b'{"ok":true,"result":{"message_id":7}}'
    response = httpx.Response(
        200,
        content=body,
        headers={"Content-Encoding": "identity"},
    )

    assert await _read_bounded(response) == body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error_type", "error_code"),
    [
        (200, TelegramPermanentError, "telegram-content-encoding-invalid"),
        (429, TelegramTransientError, "telegram-rate-limited"),
    ],
)
async def test_loopback_compressed_expansion_is_never_decoded_and_keeps_status_classification(
    caplog, status, error_type, error_code
):
    """A server ignoring identity negotiation cannot inflate memory or change retryability."""
    expanded = b'{"ok":false,"padding":"' + (b"x" * 10_000_000) + b'"}'
    compressed = gzip.compress(expanded)
    captured_request = bytearray()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        headers = await reader.readuntil(b"\r\n\r\n")
        captured_request.extend(headers)
        content_length = 0
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1])
        await reader.readexactly(content_length)
        writer.write(
            f"HTTP/1.1 {status} Test\r\n".encode("ascii")
            + b"Content-Encoding: gzip\r\nContent-Length: "
            + str(len(compressed)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + compressed
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=httpx.AsyncHTTPTransport(),
        max_attempts=1,
    )
    client._transport._target_url = (
        f"http://127.0.0.1:{port}/bot{FAKE_TOKEN}/sendMessage"
    )
    caplog.set_level(logging.DEBUG)
    tracemalloc.start()
    try:
        with pytest.raises(error_type, match=f"^{error_code}$"):
            await client.send_chunks(["report"])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        server.close()
        await server.wait_closed()

    lowered_request = bytes(captured_request).lower()
    assert b"accept-encoding: identity\r\n" in lowered_request
    assert peak < 2_000_000
    rendered = "\n".join(
        " | ".join(
            (record.getMessage(), repr(record.args), repr(record.exc_info), repr(record))
        )
        for record in caplog.records
    )
    assert FAKE_TOKEN not in rendered


@pytest.mark.asyncio
async def test_telegram_honors_sane_retry_after():
    """Ignoring a bounded Bot API retry delay would amplify rate limiting."""
    transport = RecordingTransport(
        [
            httpx.Response(
                429,
                json={"ok": False, "parameters": {"retry_after": 2}},
            ),
            _ok(),
        ]
    )
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=transport,
        sleep=sleep,
    )

    await client.send_chunks(["report"])

    assert sleeps == [pytest.approx(2, abs=0.2)]
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_telegram_rejects_malformed_or_unsuccessful_api_responses():
    """HTTP 200 alone is not proof that Telegram accepted the message."""
    responses = [
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json={"ok": False}),
        httpx.Response(200, json={"ok": True, "result": {}}),
    ]
    for response in responses:
        client = TelegramClient(
            token=FAKE_TOKEN,
            chat_id="-1001234567890",
            transport=RecordingTransport([response]),
            max_attempts=1,
        )
        with pytest.raises(TelegramError, match="telegram-response-invalid"):
            await client.send_chunks(["report"])


@pytest.mark.asyncio
async def test_telegram_bounds_retries_and_never_exposes_token_or_upstream_text():
    """Arbitrary transport and response details must not escape a token-bearing boundary."""
    request = httpx.Request("POST", "https://example.invalid")
    transport = RecordingTransport(
        [
            httpx.ConnectError(f"Bearer private {FAKE_TOKEN}", request=request),
            httpx.Response(500, text=f"private {FAKE_TOKEN}"),
            httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 9999}}),
        ]
    )
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    client = TelegramClient(
        token=FAKE_TOKEN,
        chat_id="-1001234567890",
        transport=transport,
        sleep=sleep,
        max_attempts=3,
    )

    with pytest.raises(TelegramError) as raised:
        await client.send_chunks(["report"])

    assert FAKE_TOKEN not in str(raised.value)
    assert "private" not in str(raised.value)
    assert len(transport.requests) == 3
    assert sleeps == [0.25, 0.5]


@pytest.mark.parametrize(
    ("token", "chat_id", "topic_id"),
    [
        ("real-looking-without-colon", "-1001", None),
        (FAKE_TOKEN + "\n", "-1001", None),
        (FAKE_TOKEN, "chat id", None),
        (FAKE_TOKEN, "-1001", 0),
    ],
)
def test_telegram_rejects_unsafe_configuration(token, chat_id, topic_id):
    """Malformed routing values must not alter the URL or request semantics."""
    with pytest.raises(ValueError):
        TelegramClient(token=token, chat_id=chat_id, topic_id=topic_id)


def test_telegram_error_types_accept_only_closed_codes():
    """Callers cannot smuggle credentials into a typed exception's public message."""
    with pytest.raises(ValueError, match="error code"):
        TelegramPermanentError(f"private-{FAKE_TOKEN}")

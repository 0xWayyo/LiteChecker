from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import socket
import ssl
import traceback
from contextlib import asynccontextmanager, suppress

import httpx
import pytest
import trustme

from litechecker.collector.telegram import TelegramClient, TelegramTransientError


TOKEN = "123456:example-token-for-proxy-tests"
USERNAME = "proxy-user"
PASSWORD = "proxy:p@ssword"
ENCODED_PASSWORD = "proxy%3Ap%40ssword"


def _assert_no_secrets(text: str) -> None:
    for secret in (TOKEN, USERNAME, PASSWORD, ENCODED_PASSWORD, base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()):
        assert secret not in text


def _assert_logs_have_no_secrets(caplog) -> None:
    _assert_no_secrets(caplog.text)
    for record in caplog.records:
        _assert_no_secrets(" | ".join((record.getMessage(), repr(record.args), repr(record.exc_info), repr(record.exc_text), repr(record))))


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost:8080",
        "https://proxy.example:443/",
        "socks5://proxy-user:proxy%3Ap%40ssword@127.0.0.1:1080",
        "socks5h://proxy-user:proxy%3Ap%40ssword@[::1]:1080",
        "http://proxy.example",
    ],
)
def test_proxy_validation_preserves_valid_encoded_credentials(value):
    """Rejecting supported URLs or decoding userinfo would break authenticated routing."""
    from litechecker.telegram_proxy import validate_telegram_proxy_url

    assert validate_telegram_proxy_url(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "", "proxy.example:1080", "ftp://proxy.example:1080", "http:///",
        "http://proxy-user:proxy%3Ap%40ssword@:1080",
        "http://proxy-user:proxy%3Ap%40ssword@host:0",
        "http://proxy-user:proxy%3Ap%40ssword@host:65536",
        "http://proxy-user:proxy%3Ap%40ssword@host:secret-port",
        "http://proxy-user:proxy%3Ap%40ssword@host:",
        "http://proxy-user:proxy%3Ap%40ssword@host/path",
        "http://proxy-user:proxy%3Ap%40ssword@host?",
        "http://proxy-user:proxy%3Ap%40ssword@host#",
        "http://proxy-user:proxy%3Ap%40ssword@host\n",
        " http://proxy-user:proxy%3Ap%40ssword@host",
        "http://proxy-user:proxy%3Ap%40ssword@bad host",
        "http://proxy-user:proxy%3Ap%40ssword@[broken",
        "http://proxy-user:proxy%3Ap%40ssword@host@other",
        "http://proxy-user@host", "http://:password@host", "http://user:@host",
        "http://user:bad%ZZ@host", "http://user:bad%00@host",
        "http://user:bad\\password@host", "http://%65xample.com:8080",
        "http://-host.example:8080",
    ],
)
def test_invalid_proxy_validation_does_not_disclose_url_in_traceback(value, caplog):
    """Malformed credentials and URL parser failures must stay outside logged exceptions."""
    from litechecker.telegram_proxy import validate_telegram_proxy_url

    with pytest.raises(ValueError):
        try:
            validate_telegram_proxy_url(value)
        except ValueError:
            logging.getLogger(__name__).exception("invalid proxy configuration")
            raise

    _assert_no_secrets(caplog.text)


def test_proxy_cannot_be_silently_ignored_by_custom_transport():
    with pytest.raises(ValueError):
        TelegramClient(
            token=TOKEN, chat_id="-1001234567890",
            proxy_url="socks5://127.0.0.1:1080",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_transport_construction_failure_has_no_secret_exception_chain(monkeypatch, caplog):
    """HTTPX constructor failures cannot expose proxy userinfo through logger.exception."""
    def fail_transport(*args, **kwargs):
        raise ValueError(f"bad transport {USERNAME} {PASSWORD} {TOKEN}")

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", fail_transport)
    with pytest.raises(ValueError):
        try:
            TelegramClient(
                token=TOKEN, chat_id="-1001234567890",
                proxy_url=f"socks5://{USERNAME}:{ENCODED_PASSWORD}@127.0.0.1:1080",
            )
        except ValueError:
            logging.getLogger(__name__).exception("cannot create notification transport")
            raise

    _assert_no_secrets(caplog.text)


@asynccontextmanager
async def _local_proxy(scheme: str, *, reject: bool = False, tls: ssl.SSLContext | None = None):
    """A real loopback proxy terminating HTTP locally; it never opens upstream sockets."""
    received = []
    tasks = set()

    async def handle(reader, writer):
        tasks.add(asyncio.current_task())
        try:
            if scheme.startswith("socks5"):
                version, count = await reader.readexactly(2)
                methods = await reader.readexactly(count)
                assert version == 5 and 2 in methods
                writer.write(b"\x05\x02")
                await writer.drain()
                version, size = await reader.readexactly(2)
                username = await reader.readexactly(size)
                size = (await reader.readexactly(1))[0]
                password = await reader.readexactly(size)
                assert version == 1
                received.append((username, password))
                writer.write(b"\x01\x00")
                await writer.drain()
                version, command, reserved, address_type = await reader.readexactly(4)
                assert (version, command, reserved) == (5, 1, 0)
                if address_type == 3:
                    size = (await reader.readexactly(1))[0]
                    host = await reader.readexactly(size)
                else:
                    assert address_type in (1, 4)
                    address = await reader.readexactly(4 if address_type == 1 else 16)
                    host = str(ipaddress.ip_address(address)).encode("ascii")
                port = int.from_bytes(await reader.readexactly(2), "big")
                received.append((host, port))
                writer.write(b"\x05" + (b"\x05" if reject else b"\x00") + b"\x00\x01\x7f\x00\x00\x01\x00\x00")
                await writer.drain()
                if reject:
                    return
                if tls is not None:
                    await writer.start_tls(tls)
            headers = await reader.readuntil(b"\r\n\r\n")
            received.append(headers)
            if tls is not None and scheme == "http":
                assert headers.startswith(b"CONNECT api.telegram.org:443 HTTP/1.1")
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await writer.start_tls(tls)
                headers = await reader.readuntil(b"\r\n\r\n")
                received.append(headers)
            if reject:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            else:
                for line in headers.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        await reader.readexactly(int(line.split(b":", 1)[1]))
                body = b'{"ok":true,"result":{"message_id":1}}'
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"{scheme}://{USERNAME}:{ENCODED_PASSWORD}@127.0.0.1:{port}", received
    finally:
        server.close()
        await server.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["socks5", "socks5h", "http"])
async def test_real_authenticated_proxy_routes_telegram_without_local_target_dns(scheme, caplog):
    """Omitting the inner proxy breaks delivery to an unresolvable fixture domain."""
    caplog.set_level(logging.DEBUG)
    async with _local_proxy(scheme) as (proxy_url, received):
        client = TelegramClient(token=TOKEN, chat_id="-1001234567890", proxy_url=proxy_url, max_attempts=1)
        client._transport._target_url = f"http://telegram-proxy-fixture.invalid/bot{TOKEN}/sendMessage"
        await client.send_chunks(["proxy report"])

    if scheme.startswith("socks5"):
        assert received[:2] == [(USERNAME.encode(), PASSWORD.encode()), (b"telegram-proxy-fixture.invalid", 80)]
        assert received[2].startswith(f"POST /bot{TOKEN}/sendMessage HTTP/1.1".encode())
    else:
        assert received[0].startswith(f"POST http://telegram-proxy-fixture.invalid/bot{TOKEN}/sendMessage HTTP/1.1".encode())
        assert b"Proxy-Authorization: Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()) in received[0]
    assert "https://api.telegram.org/sendMessage" in caplog.text
    _assert_logs_have_no_secrets(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["socks5", "socks5h", "http"])
async def test_real_proxy_carries_verified_telegram_tls_and_hides_credentials(scheme, monkeypatch, caplog):
    """The actual HTTPS destination must tunnel through proxy authentication with TLS intact."""
    ca = trustme.CA()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("api.telegram.org").configure_cert(server_context)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca.configure_trust(client_context)
    real_transport = httpx.AsyncHTTPTransport

    def trust_fixture_ca(**kwargs):
        return real_transport(verify=client_context, **kwargs)

    real_getaddrinfo = socket.getaddrinfo

    def local_resolution_only(host, *args, **kwargs):
        assert host in ("127.0.0.1", b"127.0.0.1")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", trust_fixture_ca)
    monkeypatch.setattr(socket, "getaddrinfo", local_resolution_only)
    caplog.set_level(logging.DEBUG)
    async with _local_proxy(scheme, tls=server_context) as (proxy_url, received):
        client = TelegramClient(token=TOKEN, chat_id="-1001234567890", proxy_url=proxy_url, max_attempts=1)
        await client.send_chunks(["encrypted proxy report"])

    if scheme.startswith("socks5"):
        assert received[:2] == [(USERNAME.encode(), PASSWORD.encode()), (b"api.telegram.org", 443)]
    else:
        assert b"Proxy-Authorization: Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()) in received[0]
    assert received[-1].startswith(f"POST /bot{TOKEN}/sendMessage HTTP/1.1".encode())
    assert b"proxy-authorization" not in received[-1].lower()
    _assert_logs_have_no_secrets(caplog)


def test_socks_setup_failure_details_are_redacted_before_logging_handlers(caplog):
    """Secret-bearing setup errors must not survive in formatted or raw log records."""
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("httpcore.socks")
    try:
        raise RuntimeError(f"proxy setup failed: {TOKEN} {USERNAME} {PASSWORD}")
    except RuntimeError as exc:
        logger.debug("setup_socks5_connection.failed exception=%r", exc, exc_info=True)
    logger.debug("connect_tcp.complete return_value=available")

    assert "setup_socks5_connection.failed" in caplog.text
    assert "connect_tcp.complete return_value=available" in caplog.text
    _assert_logs_have_no_secrets(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy_url", [None, "http://127.0.0.1:12345"])
async def test_telegram_transport_ignores_ambient_tls_configuration(proxy_url, monkeypatch):
    """Environment certificate paths must not affect either direct or proxied Telegram clients."""
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/litechecker-test-ambient-ca.pem")
    client = TelegramClient(token=TOKEN, chat_id="-1001234567890", proxy_url=proxy_url)
    await client.send_chunks([])


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["socks5", "http"])
async def test_proxy_failure_never_falls_back_to_reachable_direct_target(scheme, caplog):
    """A refused proxy must not trigger a direct TCP connection, even with retries."""
    caplog.set_level(logging.DEBUG)
    direct_connections = []

    async def direct(reader, writer):
        direct_connections.append(True)
        writer.close()
        await writer.wait_closed()

    async def no_sleep(delay):
        return None

    server = await asyncio.start_server(direct, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with _local_proxy(scheme, reject=True) as (proxy_url, received):
            client = TelegramClient(token=TOKEN, chat_id="-1001234567890", proxy_url=proxy_url, max_attempts=2, sleep=no_sleep)
            client._transport._target_url = f"https://127.0.0.1:{port}/bot{TOKEN}/sendMessage"
            with pytest.raises(TelegramTransientError, match="^telegram-network$") as caught:
                await client.send_chunks(["report"])
            _assert_no_secrets("".join(traceback.format_exception(caught.value)))
            assert len(received) == (4 if scheme.startswith("socks5") else 2)
    finally:
        server.close()
        await server.wait_closed()

    assert direct_connections == []
    _assert_logs_have_no_secrets(caplog)


@pytest.mark.asyncio
async def test_transport_cleanup_failure_is_closed_for_exception_logging(caplog):
    class FailingCleanup(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

        async def aclose(self):
            raise httpx.CloseError(f"close failed {USERNAME} {PASSWORD} {TOKEN}")

    client = TelegramClient(token=TOKEN, chat_id="-1001234567890", transport=FailingCleanup())
    with pytest.raises(TelegramTransientError, match="^telegram-network$"):
        try:
            await client.send_chunks(["report"])
        except TelegramTransientError:
            logging.getLogger(__name__).exception("notification failed")
            raise
    _assert_no_secrets(caplog.text)

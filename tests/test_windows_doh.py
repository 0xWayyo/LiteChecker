"""Windows DoH must use bound TCP/TLS, validate DNS, and fail closed."""

import asyncio
import base64
import ipaddress
import ssl
from urllib.parse import parse_qs, urlsplit

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from litechecker.direct_network import DirectNetworkUnavailable
from litechecker.windows_network import WindowsDirectNetwork


def response(body, *, status=b"200 OK", media=b"application/dns-message", chunked=False):
    headers = b"HTTP/1.1 " + status + b"\r\nContent-Type: " + media + b"\r\n"
    if chunked:
        return headers + b"Transfer-Encoding: chunked\r\n\r\n" + hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
    return headers + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


class Peer:
    """Only replace the external bound socket; use real HTTP and DNS codecs."""

    def __init__(self, *, sources=("192.168.0.155",), transform=None, raw=None, tls_error=None):
        self.sources, self.transform, self.raw, self.tls_error = sources, transform, raw, tls_error
        self.connections, self.writers, self.queries = [], [], []
        self.valid = True

    def validate(self, network):
        if not self.valid:
            raise DirectNetworkUnavailable("interface_changed")

    def install(self, monkeypatch):
        monkeypatch.setattr(WindowsDirectNetwork, "_validate_interface", lambda network: self.validate(network))
        async def connect(network, address, port, *, infrastructure=False):
            self.validate(network)
            self.connections.append((address, port, infrastructure))
            # Any adapter DNS/fallback dial is a regression, not a test fixture.
            assert port == 443 and not infrastructure
            assert address in ("1.1.1.1", "2606:4700:4700::1111")
            reader = asyncio.StreamReader()
            peer = self

            class Writer:
                closed = False
                sent = b""
                async def start_tls(self, context, *, server_hostname, ssl_handshake_timeout):
                    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
                    assert server_hostname == "cloudflare-dns.com"
                    if peer.tls_error:
                        raise peer.tls_error
                def get_extra_info(self, name):
                    return None
                def write(self, data):
                    self.sent += data
                async def drain(self):
                    path = self.sent.split(b" ", 2)[1].decode()
                    encoded = parse_qs(urlsplit(path).query)["dns"][0]
                    assert "=" not in encoded
                    query = dns.message.from_wire(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
                    peer.queries.append(query)
                    answer = dns.message.make_response(query)
                    if query.question[0].rdtype == dns.rdatatype.A:
                        answer.answer.append(dns.rrset.from_text("ipinfo.io.", 30, "IN", "A", "34.117.59.81"))
                    if peer.transform:
                        peer.transform(answer)
                    reader.feed_data(peer.raw if peer.raw is not None else response(answer.to_wire(), chunked=True))
                    reader.feed_eof()
                def close(self):
                    self.closed = True
                async def wait_closed(self):
                    pass

            writer = Writer()
            self.writers.append(writer)
            return reader, writer
        monkeypatch.setattr(WindowsDirectNetwork, "_connect_ip", connect)
        return WindowsDirectNetwork("Ethernet", 14, self.sources, ("192.168.0.1",), 1, "guid", 14, 27)


@pytest.mark.asyncio
async def test_windows_resolution_uses_bound_https_not_blocked_adapter_dns(monkeypatch):
    # Replacing the Windows resolver with inherited TCP53 must fail this test.
    peer = Peer()
    network = peer.install(monkeypatch)
    assert await network.resolve("ipinfo.io") == ["34.117.59.81"]
    assert peer.connections == [("1.1.1.1", 443, False)] * 2
    assert [q.question[0].rdtype for q in peer.queries] == [1, 28]
    assert all(q.id == 0 for q in peer.queries)
    assert all(writer.closed for writer in peer.writers)


@pytest.mark.asyncio
async def test_slow_doh_connection_gets_six_seconds_without_fallback(monkeypatch):
    # Scale only deadline timers: a 4-second dial must fit the new DNS budget.
    peer = Peer()
    network = peer.install(monkeypatch)
    connect = WindowsDirectNetwork._connect_ip
    timeout = asyncio.timeout
    monkeypatch.setattr(asyncio, "timeout", lambda seconds: timeout(seconds / 10))
    async def slow(self, *args, **kwargs):
        await asyncio.sleep(0.4)
        return await connect(self, *args, **kwargs)
    monkeypatch.setattr(WindowsDirectNetwork, "_connect_ip", slow)
    assert await network.resolve("ipinfo.io") == ["34.117.59.81"]
    assert len(peer.connections) == 2
    assert all(writer.closed for writer in peer.writers)


@pytest.mark.asyncio
async def test_ipv6_only_uses_numeric_ipv6_doh_bootstrap(monkeypatch):
    peer = Peer(sources=("2606:4700::abcd",))
    network = peer.install(monkeypatch)
    assert await network.resolve("ipinfo.io") == ["34.117.59.81"]
    assert peer.connections == [("2606:4700:4700::1111", 443, False)] * 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation,code", [
    (lambda r: setattr(r, "id", 55), "direct_dns_invalid_response"),
    (lambda r: setattr(r, "flags", r.flags | dns.flags.TC), "direct_dns_invalid_response"),
    (lambda r: r.set_rcode(dns.rcode.SERVFAIL), "direct_dns_failed"),
    (lambda r: r.set_rcode(dns.rcode.NXDOMAIN), "direct_dns_nxdomain"),
    (lambda r: r.answer.__setitem__(0, dns.rrset.from_text("ipinfo.io.", 30, "IN", "A", "192.168.1.1")), "unsafe_direct_address"),
    (lambda r: r.question.__setitem__(0, dns.rrset.from_text("wrong.invalid.", 0, "IN", "A")), "direct_dns_invalid_response"),
])
async def test_doh_dns_validation_is_not_weakened(monkeypatch, mutation, code):
    peer = Peer(transform=mutation)
    network = peer.install(monkeypatch)
    with pytest.raises(DirectNetworkUnavailable, match=code):
        await network.resolve("ipinfo.io")
    assert len(peer.connections) == 1  # Never retry via adapter/ambient resolver.
    assert peer.writers[0].closed


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [
    response(b"redirect", status=b"302 Found"),
    response(b"limited", status=b"429 Too Many Requests"),
    response(b"wrong body", media=b"text/html"),
    response(b"broken DNS"),
    response(b"x" * 65536),
    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Type: application/dns-message\r\n\r\nshort",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nX-Huge: " + b"x" * 9000 + b"\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
    b"HTTP/1.1 103 Early Hints\r\n\r\n" * 10000,
], ids=["redirect", "rate-limit", "mime", "dns-wire", "body-limit", "truncated", "headers-limit", "compression", "informational-flood"])
async def test_bad_http_or_dns_fails_closed_and_closes_socket(monkeypatch, raw):
    peer = Peer(raw=raw)
    network = peer.install(monkeypatch)
    with pytest.raises(DirectNetworkUnavailable):
        await network.resolve("ipinfo.io")
    assert len(peer.connections) == 1
    assert peer.writers[0].closed


@pytest.mark.asyncio
async def test_tls_failure_never_sends_dns_plaintext_or_falls_back(monkeypatch):
    peer = Peer(tls_error=ssl.SSLCertVerificationError("untrusted certificate"))
    network = peer.install(monkeypatch)
    with pytest.raises(DirectNetworkUnavailable, match="tls"):
        await network.resolve("ipinfo.io")
    assert len(peer.connections) == 1
    assert peer.writers[0].closed and not peer.writers[0].sent


@pytest.mark.asyncio
async def test_changed_adapter_invalidates_doh_response(monkeypatch):
    peer = Peer()
    peer.transform = lambda r: setattr(peer, "valid", False)
    network = peer.install(monkeypatch)
    with pytest.raises(DirectNetworkUnavailable, match="interface_changed"):
        await network.resolve("ipinfo.io")
    assert peer.writers[0].closed


@pytest.mark.asyncio
@pytest.mark.parametrize("trusted", [True, False])
async def test_request_real_tls_and_chunked_body(monkeypatch, trusted):
    from litechecker import windows_doh
    import trustme
    ca = trustme.CA()
    certificate = ca.issue_cert("ipinfo.io")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    if trusted:
        ca.configure_trust(client_context)
    monkeypatch.setattr(windows_doh, "_tls_context", lambda: client_context)
    completed = asyncio.Event()
    seen = []
    body = b'{"ip":"217.113.13.181"}'
    async def handler(reader, writer):
        try:
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(response(body, media=b"application/json", chunked=True))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            completed.set()
    async with await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context) as server:
        port = server.sockets[0].getsockname()[1]
        class Network:
            def _validate_interface(self):
                pass
            async def _connect_ip(self, address, target_port):
                assert address == "34.117.59.81" and target_port == 443
                return await asyncio.open_connection("127.0.0.1", port)
        if trusted:
            assert await windows_doh.request(Network(), "34.117.59.81", "ipinfo.io", "/json", accept="application/json") == body
            await asyncio.wait_for(completed.wait(), 2)
        else:
            with pytest.raises(DirectNetworkUnavailable, match="direct_doh_tls_failed"):
                await windows_doh.request(Network(), "34.117.59.81", "ipinfo.io", "/json", accept="application/json")
    if trusted:
        assert b"GET /json HTTP/1.1\r\n" in seen[0]
        assert b"Host: ipinfo.io\r\n" in seen[0]
    else:
        assert not seen  # No HTTP payload over unauthenticated TLS.


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_request_timeout_and_cancellation_close_bound_stream(monkeypatch, cancel):
    from litechecker import windows_doh
    monkeypatch.setattr(windows_doh, "_TIMEOUT", 0.02)
    reader = asyncio.StreamReader()
    ready = asyncio.Event()
    class Writer:
        closed = False
        async def start_tls(self, *args, **kwargs):
            ready.set()
            await asyncio.Event().wait()
        def close(self):
            self.closed = True
        async def wait_closed(self):
            pass
    writer = Writer()
    class Network:
        def _validate_interface(self):
            pass
        async def _connect_ip(self, *args):
            return reader, writer
    task = asyncio.create_task(windows_doh.request(Network(), "1.1.1.1", "cloudflare-dns.com", "/dns-query?dns=AA", accept="application/dns-message"))
    await ready.wait()
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else DirectNetworkUnavailable):
        await task
    assert writer.closed

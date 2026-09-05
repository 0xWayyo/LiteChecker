"""Diagnostic errors must remain attributable, bounded and free of secrets."""

import asyncio
import base64
import ipaddress
import json
import ssl
from types import SimpleNamespace

import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from litechecker.direct_network import DirectNetworkUnavailable


def dns_answer(wire, answers):
    question = dns.message.from_wire(wire)
    response = dns.message.make_response(question)
    record = question.question[0]
    values = answers.get(record.rdtype, [])
    if values:
        response.answer.append(dns.rrset.from_text(record.name, 60, "IN", record.rdtype, *values))
    return response.to_wire()


def http_response(body, content_type):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + content_type.encode("ascii")
            + b"\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


class FakeWriter:
    def __init__(self, tls_error=None, on_write=None):
        self.closed = False
        self.requests = []
        self.tls_error = tls_error
        self.on_write = on_write

    async def start_tls(self, context, *, server_hostname, ssl_handshake_timeout):
        assert context.check_hostname
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert server_hostname in ("ipinfo.io", "cloudflare-dns.com", "1.1.1.1", "2606:4700:4700::1111")
        if self.tls_error:
            raise self.tls_error

    def write(self, data):
        self.requests.append(data)
        if data and self.on_write:
            self.on_write(data)

    def get_extra_info(self, name):
        assert name == "ssl_object"
        return None

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeNetwork:
    interface = "{physical-guid}"
    source_addresses = ("192.168.1.10",)
    dns_servers = ("192.168.1.1",)
    ipv4_index = 12
    ipv6_index = 0

    def __init__(self, *, dns_error=None, tcp_error=None, tls_error=None, headers=None):
        self.dns_error, self.tcp_error, self.tls_error = dns_error, tcp_error, tls_error
        self.headers = headers
        self.json_body = b'{"ip":"217.113.13.181"}'
        self.doh_error = None
        self.adapter_answers = {dns.rdatatype.A: ["8.8.8.8"], dns.rdatatype.AAAA: []}
        self.doh_answers = {dns.rdatatype.A: ["8.8.4.4"], dns.rdatatype.AAAA: []}
        self.connections, self.writers, self.sockets = [], [], []
        self.changed = False

    def _validate_interface(self):
        if self.changed:
            raise DirectNetworkUnavailable("interface_changed")

    def _socket(self, address):
        self._validate_interface()
        sock = SimpleNamespace(closed=False)
        sock.close = lambda: setattr(sock, "closed", True)
        self.sockets.append(sock)
        return sock

    async def _query(self, host, kind):
        pytest.fail("diagnostic must explicitly select TCP adapter DNS and DoH, not network._query")

    async def _connect_ip(self, ip, port, *, infrastructure=False):
        self.connections.append((ip, port, infrastructure))
        families = {ipaddress.ip_address(value).version for value in self.source_addresses}
        assert ipaddress.ip_address(ip).version in families, "must use a matching address family"
        controls = {"1.1.1.1", "2606:4700:4700::1111"}
        ipinfo_addresses = {ip for values in self.doh_answers.values() for ip in values}
        assert ((port == 53 and infrastructure and ip == self.dns_servers[0])
                or (port == 443 and not infrastructure and ip in controls | ipinfo_addresses))
        if self.dns_error and port == 53:
            raise self.dns_error
        if self.tcp_error and ip in ipinfo_addresses:
            raise self.tcp_error
        reader = asyncio.StreamReader()

        def respond(data):
            if port == 53:
                response = dns_answer(data[2:], self.adapter_answers)
                response = len(response).to_bytes(2, "big") + response
            elif data.startswith(b"GET /dns-query?dns="):
                if self.doh_error:
                    raise self.doh_error
                encoded = data.split(b" ", 2)[1].split(b"=", 1)[1]
                wire = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
                response = http_response(dns_answer(wire, self.doh_answers), "application/dns-message")
            else:
                assert data.startswith(b"GET /json HTTP/1.1\r\n")
                response = self.headers if self.headers is not None else http_response(self.json_body, "application/json")
            reader.feed_data(response)
            reader.feed_eof()

        writer = FakeWriter(self.tls_error if ip in ipinfo_addresses else None, respond)
        self.writers.append(writer)
        return reader, writer


async def run(network):
    from litechecker.windows_diagnostics import diagnose

    async def discover():
        return network

    return await diagnose(network_factory=discover)


def event(result, stage):
    matching = [item for item in result.steps if item.stage == stage]
    assert len(matching) == 1, f"expected exactly one diagnostic stage: {stage}"
    return matching[0]


@pytest.mark.asyncio
async def test_dns_failure_stays_dns_and_independent_numeric_control_still_runs():
    # A DNS error must not become an unexplained generic failure or prevent
    # the explicitly labelled numeric control (not a fallback for measurement).
    network = FakeNetwork(dns_error=DirectNetworkUnavailable("direct_dns_timeout"))
    result = await run(network)
    assert not result.ok
    assert event(result, "DNS A").code == "direct_dns_timeout"
    assert event(result, "DoH A").status == "ok"
    assert event(result, "IPinfo HTTP").status == "ok"
    assert event(result, "Контроль без DNS TCP").status == "ok"
    assert event(result, "Контроль без DNS TLS").status == "ok"
    assert network.connections.count(("192.168.1.1", 53, True)) == 3
    assert network.connections.count(("1.1.1.1", 443, False)) == 3
    assert all(writer.closed for writer in network.writers)
    assert all(sock.closed for sock in network.sockets)


@pytest.mark.asyncio
async def test_chained_windows_error_is_preserved_without_exception_message():
    native = OSError(13, "password SECRET https://user:pass@host/subscription")
    native.winerror = 10013
    wrapped = DirectNetworkUnavailable("direct_connection_failed")
    wrapped.__cause__ = native
    result = await run(FakeNetwork(tcp_error=wrapped))
    failed = event(result, "IPinfo TCP")
    assert failed.code == "direct_connection_failed"
    assert failed.winerror == 10013
    assert failed.errno == 13
    assert "10013" in result.text
    assert "SECRET" not in result.text
    assert "user:pass" not in result.text
    assert event(result, "IPinfo TLS").status == "skipped"


@pytest.mark.asyncio
async def test_tls_error_does_not_become_tcp_or_http_success():
    result = await run(FakeNetwork(tls_error=ssl.SSLCertVerificationError(1, "secret cert text")))
    assert event(result, "IPinfo TCP").status == "ok"
    assert event(result, "IPinfo TLS").code == "tls_certificate_error"
    assert event(result, "IPinfo HTTP").status == "skipped"
    assert "secret cert text" not in result.text
    assert not result.ok


@pytest.mark.asyncio
@pytest.mark.parametrize("headers,code", [
    (b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n", "direct_doh_http_failed"),
    (b"not http\r\n\r\n", "direct_doh_invalid_http"),
    (b"HTTP/1.1 200 OK\r\nX: " + b"x" * 9000 + b"\r\n\r\n", "direct_doh_response_too_large"),
], ids=["rate-limit", "malformed", "oversized-headers"])
async def test_http_failures_do_not_masquerade_as_dns_or_tls_errors(headers, code):
    result = await run(FakeNetwork(headers=headers))
    assert event(result, "IPinfo TLS").status == "ok"
    assert event(result, "IPinfo HTTP").code == code
    assert not result.ok


@pytest.mark.asyncio
async def test_success_reports_only_control_health_not_subscription_or_vpn_bypass():
    network = FakeNetwork()
    result = await run(network)
    assert result.ok
    assert event(result, "IPinfo HTTP").detail == "HTTP 200; публичный IP: 217.113.13.181"
    assert event(result, "DNS A").detail == "8.8.8.8"
    assert event(result, "DoH A").detail == "8.8.4.4"
    assert "Подписка и серверы не проверялись" in result.text
    assert "обход VPN подтверждён" not in result.text
    assert "{physical-guid}" in result.text
    assert "192.168.1.1" in result.text
    requests = [request for writer in network.writers for request in writer.requests]
    assert any(request.startswith(b"GET /json HTTP/1.1\r\nHost: ipinfo.io\r\n") for request in requests)
    assert all(writer.closed for writer in network.writers)
    assert all(sock.closed for sock in network.sockets)


@pytest.mark.asyncio
async def test_interface_discovery_failure_has_no_traffic_and_keeps_exact_code():
    from litechecker.windows_diagnostics import diagnose

    async def unavailable():
        raise DirectNetworkUnavailable("interface_ambiguous")

    result = await diagnose(network_factory=unavailable)
    assert not result.ok
    assert event(result, "Адаптер").code == "interface_ambiguous"
    assert len(result.steps) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["adapter-dns", "doh", "ipinfo-http"])
async def test_cancellation_propagates_from_active_io_and_sockets_close(stage):
    network = FakeNetwork()
    original = network._connect_ip
    waiting = asyncio.Event()

    async def connect(ip, port, **kwargs):
        reader, writer = await original(ip, port, **kwargs)
        if ((stage == "adapter-dns" and port == 53)
                or (stage == "doh" and ip == "1.1.1.1")
                or (stage == "ipinfo-http" and ip == "8.8.4.4")):
            # Leave the reader pending after a real query/request was written.
            writer.on_write = lambda _: waiting.set()
        return reader, writer

    network._connect_ip = connect
    task = asyncio.create_task(run(network))
    await asyncio.wait_for(waiting.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert network.writers
    assert all(writer.closed for writer in network.writers)
    assert all(sock.closed for sock in network.sockets)


@pytest.mark.asyncio
async def test_total_deadline_stops_pending_io_and_closes_writer(monkeypatch):
    from litechecker import windows_diagnostics

    assert windows_diagnostics._TOTAL_TIMEOUT == 60
    monkeypatch.setattr(windows_diagnostics, "_TOTAL_TIMEOUT", 0.02)
    network = FakeNetwork()
    original = network._connect_ip

    async def connect(ip, port, **kwargs):
        reader, writer = await original(ip, port, **kwargs)
        if port == 53:
            writer.on_write = None  # DNS read remains pending until total deadline.
        return reader, writer

    network._connect_ip = connect
    result = await asyncio.wait_for(run(network), timeout=1)
    assert not result.ok
    assert event(result, "Диагностика").code == "timeout"
    assert all(port == 53 for _, port, _ in network.connections)
    assert all(writer.closed for writer in network.writers)


@pytest.mark.asyncio
async def test_changed_interface_invalidates_overall_result():
    network = FakeNetwork()
    original = network._connect_ip

    async def connect(ip, port, **kwargs):
        value = await original(ip, port, **kwargs)
        if ip == "1.1.1.1":
            network.changed = True
        return value

    network._connect_ip = connect
    result = await run(network)
    assert not result.ok
    assert event(result, "Адаптер после проверки").code == "interface_changed"


@pytest.mark.asyncio
async def test_ipv6_only_adapter_diagnoses_matching_address_family():
    network = FakeNetwork()
    network.source_addresses = ("2001:4860::1234",)
    network.dns_servers = ("2001:4860:4860::8888",)

    network.doh_answers[dns.rdatatype.AAAA] = ["2001:4860:4860::8844"]
    result = await run(network)
    assert result.ok
    assert ("2001:4860:4860::8844", 443, False) in network.connections


@pytest.mark.asyncio
async def test_d2_keeps_failed_adapter_dns_when_doh_and_public_exit_succeed():
    native = OSError(5, "private exception text SECRET")
    native.winerror = 5
    failure = DirectNetworkUnavailable("direct_dns_failed")
    failure.__cause__ = native
    network = FakeNetwork(dns_error=failure)
    network.json_body = b'{"ip":"217.113.13.181","org":"SECRET response field"}'

    result = await run(network)

    assert event(result, "DNS A").winerror == 5
    assert event(result, "DNS AAAA").winerror == 5
    assert event(result, "DoH A").status == "ok"
    assert event(result, "DoH AAAA").status == "ok"
    assert "217.113.13.181" in event(result, "IPinfo HTTP").detail
    assert not result.ok  # The adapter DNS failure is not repainted as success.
    assert "TCP/53" in result.text
    assert "DoH" in result.text
    assert "D2" in result.text
    assert "SECRET" not in result.text
    assert "Подписка и серверы не проверялись" in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    b"{}", b"[]", b"not JSON SECRET", b'{"ip":"192.168.0.1"}',
    b'{"ip":"127.0.0.1"}', b'{"ip":"224.0.0.1"}',
    b'{"ip":"217.113.13.181","bogon":true}',
    b'{"ip":"217.113.13.181","error":"SECRET"}',
    b'{"ip":"fe80::1%12"}', b'{"ip":123}',
    b'\xff', json.dumps({"ip": "217.113.13.181", "padding": "x" * 8192}).encode(),
], ids=["empty", "array", "invalid-json", "private", "loopback", "multicast",
        "bogon", "error", "scope", "numeric", "invalid-utf8", "oversized-json"])
async def test_d2_http_200_without_valid_public_exit_is_not_success(body):
    network = FakeNetwork()
    network.json_body = body
    result = await run(network)
    assert not result.ok
    assert event(result, "IPinfo HTTP").code == "invalid_ipinfo_response"
    assert "SECRET" not in result.text


@pytest.mark.asyncio
async def test_d2_failed_doh_does_not_fall_back_to_adapter_dns_answers():
    network = FakeNetwork()
    network.doh_error = DirectNetworkUnavailable("direct_doh_failed")
    result = await run(network)
    assert event(result, "DNS A").status == "ok"
    assert event(result, "DoH A").code == "direct_doh_failed"
    assert event(result, "IPinfo TCP").status == "skipped"
    assert event(result, "IPinfo HTTP").status == "skipped"
    assert event(result, "Контроль без DNS TLS").status == "ok"
    assert not result.ok
    assert not any(ip in {"8.8.8.8", "8.8.4.4"} for ip, _, _ in network.connections)
    assert all(writer.closed for writer in network.writers)


@pytest.mark.asyncio
@pytest.mark.parametrize("trusted", [True, False])
async def test_real_stream_tls_certificate_and_http_headers(monkeypatch, trusted):
    import trustme
    from litechecker import windows_diagnostics, windows_doh

    ca = trustme.CA()
    certificate = ca.issue_cert("ipinfo.io", "cloudflare-dns.com", "1.1.1.1")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    requests = []
    handlers = set()
    network = FakeNetwork()

    async def handler(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        try:
            data = await reader.readuntil(b"\r\n\r\n")
            requests.append(data)
            if data.startswith(b"GET /dns-query?dns="):
                encoded = data.split(b" ", 2)[1].split(b"=", 1)[1]
                wire = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
                response = http_response(dns_answer(wire, network.doh_answers), "application/dns-message")
            else:
                response = http_response(network.json_body, "application/json")
            writer.write(response)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            handlers.discard(task)

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    original = network._connect_ip

    async def connect(ip, target_port, **kwargs):
        if target_port == 53:
            return await original(ip, target_port, **kwargs)
        assert ip in ("8.8.4.4", "1.1.1.1")
        return await asyncio.open_connection("127.0.0.1", port)

    network._connect_ip = connect
    context = ssl.create_default_context()
    ca.configure_trust(context)
    # DoH has its own real TLS handshake. Keep it trusted in both cases so
    # the untrusted variant reaches, and specifically tests, the IPinfo TLS step.
    monkeypatch.setattr(windows_doh, "_tls_context", lambda: context)
    if trusted:
        monkeypatch.setattr(windows_diagnostics, "_tls_context", lambda: context)
    try:
        result = await run(network)
        assert result.ok is trusted
        assert len([request for request in requests if request.startswith(b"GET /dns-query?dns=")]) == 2
        ipinfo_requests = [request for request in requests if request.startswith(b"GET /json ")]
        if trusted:
            assert ipinfo_requests == [b"GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"]
            assert "217.113.13.181" in event(result, "IPinfo HTTP").detail
        else:
            assert event(result, "IPinfo TLS").code == "tls_certificate_error"
            assert ipinfo_requests == []
    finally:
        server.close()
        await server.wait_closed()
        if handlers:
            await asyncio.gather(*tuple(handlers))


@pytest.mark.asyncio
async def test_interrupted_diagnostic_replaces_stale_success_without_touching_settings(tmp_path, monkeypatch):
    from litechecker import windows_trial, windows_diagnostics
    state = tmp_path / "windows-state"
    state.mkdir()
    saved = state / "last-diagnostics.txt"
    saved.write_text("old successful diagnosis")
    settings = state / "settings.json"
    settings.write_text("private-data-do-not-read")
    report = state / "last-report.txt"
    report.write_text("old measurement do not replace")

    async def cancelled():
        assert "old successful" not in saved.read_text(encoding="utf-8")
        raise asyncio.CancelledError()

    monkeypatch.setattr(windows_diagnostics, "diagnose", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await windows_trial.execute_diagnostics(tmp_path)
    assert "остановлена" in saved.read_text(encoding="utf-8")
    assert settings.read_text() == "private-data-do-not-read"
    assert report.read_text() == "old measurement do not replace"


def test_diagnostic_cli_needs_no_subscription_and_saves_its_own_file(tmp_path, monkeypatch, capsys):
    from litechecker import windows_trial, windows_diagnostics
    monkeypatch.setattr(windows_trial.sys, "platform", "win32")

    async def probe():
        return SimpleNamespace(text="DNS A: direct_dns_timeout; WinError=10013", ok=False)

    def forbidden(*args, **kwargs):
        pytest.fail("diagnosis must not read subscription or configure Telegram")

    monkeypatch.setattr(windows_diagnostics, "diagnose", probe)
    monkeypatch.setattr(windows_trial, "configure", forbidden)
    monkeypatch.setattr(windows_trial, "load_settings", forbidden)
    assert windows_trial.main(["--root", str(tmp_path), "--diagnose"]) == 1
    saved = tmp_path / "windows-state" / "last-diagnostics.txt"
    assert "10013" in saved.read_text(encoding="utf-8")
    assert str(saved) in capsys.readouterr().out
    assert not (saved.parent / "settings.json").exists()
    assert not (saved.parent / "last-report.txt").exists()

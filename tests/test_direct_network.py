"""Direct checks must stop before an unbound or non-public connection escapes."""

from __future__ import annotations

import asyncio
import errno
import socket
from contextlib import asynccontextmanager

import pytest


HARDWARE = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:11:22:33:44:55

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:11:22:33:44:66

Hardware Port: USB Ethernet
Device: en5
Ethernet Address: 00:11:22:33:44:77
"""
ACTIVE = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
    inet6 fe80::abcd%en0 prefixlen 64 secured scopeid 0xe
    status: active
"""


def network(monkeypatch):
    from litechecker import macos_network as module

    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.socket, "if_nametoindex", lambda name: 14)
    monkeypatch.setattr(module.socket, "if_indextoname", lambda index: "en0")
    return module.MacDirectNetwork("en0", 14, ("192.168.1.20",), ("192.168.1.1",))


@pytest.mark.asyncio
async def test_discover_selects_only_active_physical_interface_and_its_dhcp_dns(monkeypatch):
    from litechecker import macos_network as module

    network(monkeypatch)
    outputs = {
        ("/usr/sbin/networksetup", "-listallhardwareports"): HARDWARE,
        ("/sbin/ifconfig", "en0"): ACTIVE,
        ("/sbin/ifconfig", "en5"): ACTIVE.replace("status: active", "status: inactive"),
        ("/usr/sbin/ipconfig", "getoption", "en0", "domain_name_server"): "192.168.1.1\n8.8.8.8\n",
    }

    async def run(*args):
        return outputs[args]

    monkeypatch.setattr(module, "_run", run)
    direct = await module.MacDirectNetwork.discover()
    assert direct.interface == "en0"
    assert direct.interface_index == 14
    assert direct.source_addresses == ("192.168.1.20", "fe80::abcd")
    assert direct.dns_servers == ("192.168.1.1", "8.8.8.8")


@pytest.mark.asyncio
async def test_discover_refuses_multiple_active_interfaces(monkeypatch):
    from litechecker import macos_network as module

    network(monkeypatch)

    async def run(*args):
        return HARDWARE if args[0].endswith("networksetup") else ACTIVE

    monkeypatch.setattr(module, "_run", run)
    with pytest.raises(module.DirectNetworkUnavailable):
        await module.MacDirectNetwork.discover()


@pytest.mark.asyncio
@pytest.mark.parametrize("dns", ["", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "dns.example", "8.8.8.8%en0"])
async def test_discover_refuses_unusable_dhcp_dns_without_system_fallback(monkeypatch, dns):
    from litechecker import macos_network as module

    network(monkeypatch)

    async def run(*args):
        if args[0].endswith("networksetup"):
            return HARDWARE.split("Hardware Port: USB Ethernet")[0]
        if args[0].endswith("ifconfig"):
            return ACTIVE
        return dns

    monkeypatch.setattr(module, "_run", run)
    with pytest.raises(module.DirectNetworkUnavailable):
        await module.MacDirectNetwork.discover()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "224.0.0.1", "::1", "fe80::1", "2001:db8::1", "::ffff:8.8.8.8", "8.8.8.8%en0", "", "bad name"])
async def test_resolve_refuses_non_public_or_invalid_targets(monkeypatch, host):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    with pytest.raises(module.DirectNetworkUnavailable):
        await direct.resolve(host)


@pytest.mark.asyncio
async def test_resolve_numeric_public_address_never_calls_host_resolver(monkeypatch):
    direct = network(monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("system DNS must not be used")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert await direct.resolve("8.8.8.8") == ["8.8.8.8"]
    assert await direct.resolve("2606:4700:4700::1111") == ["2606:4700:4700::1111"]


@pytest.mark.asyncio
async def test_invalid_dns_name_does_not_send_a_query(monkeypatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)

    async def forbidden_query(*args, **kwargs):
        raise AssertionError("invalid name must not leave the process")

    monkeypatch.setattr(module.MacDirectNetwork, "_query", forbidden_query)
    with pytest.raises(module.DirectNetworkUnavailable):
        await direct.resolve("example.com..")


@pytest.mark.asyncio
async def test_invalid_port_does_not_trigger_dns(monkeypatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)

    async def forbidden_resolve(*args, **kwargs):
        raise AssertionError("invalid port must be rejected before DNS")

    monkeypatch.setattr(module.MacDirectNetwork, "resolve", forbidden_resolve)
    with pytest.raises(module.DirectNetworkUnavailable):
        await direct.connect("example.com", 0)


@pytest.mark.asyncio
async def test_changed_interface_index_stops_before_connect(monkeypatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    monkeypatch.setattr(module.socket, "if_nametoindex", lambda name: 27)
    with pytest.raises(module.DirectNetworkUnavailable, match="^interface_changed$"):
        await direct.connect("8.8.8.8", 443)


@pytest.mark.asyncio
async def test_reused_interface_index_stops_before_connect(monkeypatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    monkeypatch.setattr(module.socket, "if_indextoname", lambda index: "utun7")
    with pytest.raises(module.DirectNetworkUnavailable, match="^interface_changed$"):
        await direct.connect("8.8.8.8", 443)


class SocketFailure:
    def __init__(self, *, mismatch=False):
        self.closed = False
        self.mismatch = mismatch

    def setsockopt(self, *args):
        if not self.mismatch:
            raise OSError("binding refused")

    def getsockopt(self, *args):
        return 0

    def close(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", [False, True])
async def test_binding_error_or_readback_mismatch_closes_socket(monkeypatch, mismatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    failed = SocketFailure(mismatch=mismatch)
    monkeypatch.setattr(module.socket, "socket", lambda *args, **kwargs: failed)
    with pytest.raises(module.DirectNetworkUnavailable, match="^interface_binding_failed$"):
        await direct.connect("8.8.8.8", 443)
    assert failed.closed


class BoundSocket:
    def __init__(self):
        self.closed = False
        self.option = None
        self.source = None
        self.blocking = True

    def setsockopt(self, level, option, index):
        self.option = (level, option, index)

    def getsockopt(self, level, option):
        assert self.option[:2] == (level, option)
        return self.option[2]

    def bind(self, source):
        self.source = source

    def setblocking(self, blocking):
        self.blocking = blocking

    def close(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize(("failure", "code"), [
    (ConnectionRefusedError(errno.ECONNREFUSED, "private detail"), "direct_connection_refused"),
    (TimeoutError("private detail"), "direct_connection_timeout"),
    (OSError(errno.ETIMEDOUT, "private detail"), "direct_connection_timeout"),
    (OSError(errno.ENETUNREACH, "private detail"), "direct_connection_unreachable"),
    (OSError(errno.EHOSTUNREACH, "private detail"), "direct_connection_unreachable"),
    (ConnectionResetError(errno.ECONNRESET, "private detail"), "direct_connection_reset"),
    (OSError(errno.EIO, "private detail"), "direct_connection_failed"),
])
async def test_connect_preserves_transport_cause_and_bound_socket_without_fallback(monkeypatch, failure, code):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    bound = BoundSocket()
    loop = asyncio.get_running_loop()

    async def fail_connect(sock, destination):
        assert sock is bound
        assert destination == ("8.8.8.8", 443)
        assert bound.option == (socket.IPPROTO_IP, 25, 14)
        assert bound.source == ("192.168.1.20", 0)
        assert bound.blocking is False
        raise failure

    def forbidden(*args, **kwargs):
        raise AssertionError("failed bound connection must not use ambient DNS or connections")

    monkeypatch.setattr(module.socket, "socket", lambda *args, **kwargs: bound)
    monkeypatch.setattr(loop, "sock_connect", fail_connect)
    monkeypatch.setattr(module.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(module.asyncio, "open_connection", forbidden)
    with pytest.raises(module.DirectNetworkUnavailable) as caught:
        await direct.connect("8.8.8.8", 443)
    assert caught.value.code == code
    assert str(caught.value) == code
    assert bound.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("last_code", ["direct_connection_timeout", "interface_binding_failed"])
async def test_all_addresses_failed_preserves_last_attempt_code(monkeypatch, last_code):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    attempts = []

    async def resolve(self, host):
        return ["8.8.8.8", "1.1.1.1"]

    async def fail_connect(self, ip, port):
        attempts.append(ip)
        code = "direct_connection_refused" if ip == "8.8.8.8" else last_code
        raise module.DirectNetworkUnavailable(code)

    monkeypatch.setattr(module.MacDirectNetwork, "resolve", resolve)
    monkeypatch.setattr(module.MacDirectNetwork, "_connect_ip", fail_connect)
    with pytest.raises(module.DirectNetworkUnavailable) as caught:
        await direct.connect("example.com", 443)
    assert caught.value.code == last_code
    assert attempts == ["8.8.8.8", "1.1.1.1"]


@pytest.mark.asyncio
async def test_discover_refuses_other_platforms(monkeypatch):
    from litechecker import macos_network as module

    monkeypatch.setattr(module.sys, "platform", "linux")
    with pytest.raises(module.DirectNetworkUnavailable):
        await module.MacDirectNetwork.discover()


@pytest.mark.asyncio
async def test_failed_native_command_is_unavailable():
    from litechecker import macos_network as module

    with pytest.raises(module.DirectNetworkUnavailable):
        await module._run("/usr/bin/false")


@asynccontextmanager
async def dns_fixture(monkeypatch, direct, response_builder):
    import dns.message

    from litechecker import macos_network as module

    requests = []
    finished = asyncio.Event()

    async def handler(reader, writer):
        try:
            length = int.from_bytes(await reader.readexactly(2), "big")
            query = dns.message.from_wire(await reader.readexactly(length))
            requests.append(query)
            reply = response_builder(query)
            if reply is None:
                await reader.read()
            else:
                wire = reply if isinstance(reply, bytes) else reply.to_wire()
                writer.write(len(wire).to_bytes(2, "big") + wire)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def local_dns(self, ip, target_port, *, infrastructure=False):
        if ip != "192.168.1.1" or target_port != 53 or not infrastructure:
            raise AssertionError("DNS escaped the explicit infrastructure destination")
        return await asyncio.open_connection("127.0.0.1", port)

    monkeypatch.setattr(module.MacDirectNetwork, "_connect_ip", local_dns)
    try:
        yield requests, finished
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_dns_tcp_resolves_owned_cname_chain_and_both_address_families(monkeypatch):
    import dns.message
    import dns.rdatatype
    import dns.rrset

    direct = network(monkeypatch)

    def reply(query):
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("example.com.", 30, "IN", "CNAME", "edge.example.net."))
        kind, value = ("A", "8.8.8.8") if query.question[0].rdtype == dns.rdatatype.A else ("AAAA", "2606:4700:4700::1111")
        response.answer.append(dns.rrset.from_text("edge.example.net.", 30, "IN", kind, value))
        # Unrelated additional data must never become a destination.
        response.additional.append(dns.rrset.from_text("attacker.example.", 30, "IN", "A", "127.0.0.1"))
        return response

    def forbidden(*args, **kwargs):
        raise AssertionError("system DNS must not be used")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    async with dns_fixture(monkeypatch, direct, reply) as (requests, _):
        assert await direct.resolve("example.com") == ["8.8.8.8", "2606:4700:4700::1111"]
    assert [(str(query.question[0].name), query.question[0].rdtype) for query in requests] == [
        ("example.com.", 1), ("example.com.", 28),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["id", "question", "rcode", "truncated", "malformed", "foreign_owner", "private", "cname_loop", "too_many", "cname_and_address", "empty"])
async def test_dns_rejects_mismatched_unsafe_or_unusable_answers(monkeypatch, fault):
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rrset

    from litechecker import macos_network as module

    direct = network(monkeypatch)

    def reply(query):
        response = dns.message.make_response(query)
        owner = "foreign.example." if fault == "foreign_owner" else "example.com."
        response.answer.append(dns.rrset.from_text(owner, 30, "IN", "A", "127.0.0.1" if fault == "private" else "8.8.8.8"))
        if fault == "id":
            response.id ^= 1
        elif fault == "question":
            response.question = dns.message.make_query("other.example.", "A").question
        elif fault == "rcode":
            response.set_rcode(dns.rcode.SERVFAIL)
        elif fault == "truncated":
            response.flags |= dns.flags.TC
        elif fault == "malformed":
            return b"not dns"
        elif fault == "cname_loop":
            response.answer = [dns.rrset.from_text("example.com.", 30, "IN", "CNAME", "example.com.")]
        elif fault == "too_many":
            response.answer = [dns.rrset.from_text("example.com.", 30, "IN", "A", *(f"8.8.8.{n}" for n in range(1, 66)))]
        elif fault == "cname_and_address":
            response.answer.append(dns.rrset.from_text("example.com.", 30, "IN", "CNAME", "edge.example."))
        elif fault == "empty":
            response.answer = []
        return response

    async with dns_fixture(monkeypatch, direct, reply) as (requests, _):
        with pytest.raises(module.DirectNetworkUnavailable):
            await direct.resolve("example.com")
        assert requests, "the response must reach the production DNS parser"


@pytest.mark.asyncio
@pytest.mark.parametrize(("fault", "code"), [
    ("nxdomain", "direct_dns_nxdomain"),
    ("nxdomain_wrong_id", "direct_dns_invalid_response"),
    ("servfail", "direct_dns_failed"),
    ("short", "direct_dns_invalid_response"),
    ("malformed", "direct_dns_invalid_response"),
])
async def test_dns_distinguishes_negative_answer_from_invalid_response_without_fallback(monkeypatch, fault, code):
    import dns.message
    import dns.rcode

    from litechecker import macos_network as module

    direct = network(monkeypatch)

    def reply(query):
        if fault == "short":
            return b"not dns"
        if fault == "malformed":
            # One question declared in a header with no question body.
            return b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL if fault == "servfail" else dns.rcode.NXDOMAIN)
        if fault == "nxdomain_wrong_id":
            response.id ^= 1
        return response

    def forbidden(*args, **kwargs):
        raise AssertionError("DNS errors must not use the system resolver")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    async with dns_fixture(monkeypatch, direct, reply) as (requests, _):
        with pytest.raises(module.DirectNetworkUnavailable) as caught:
            await direct.resolve("example.com")
        assert caught.value.code == code
        assert str(caught.value) == code
        assert len(requests) == 1


@pytest.mark.asyncio
async def test_dns_internal_timeout_preserves_cause_and_closes_stream_without_fallback(monkeypatch):
    from litechecker import macos_network as module

    direct = network(monkeypatch)
    timeout = asyncio.timeout
    monkeypatch.setattr(module.asyncio, "timeout", lambda delay: timeout(0.05))

    def forbidden(*args, **kwargs):
        raise AssertionError("DNS timeout must not use the system resolver")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    async with dns_fixture(monkeypatch, direct, lambda query: None) as (requests, finished):
        with pytest.raises(module.DirectNetworkUnavailable) as caught:
            await direct.resolve("example.com")
        assert caught.value.code == "direct_dns_timeout"
        await asyncio.wait_for(finished.wait(), 1)
        assert len(requests) == 1


@pytest.mark.asyncio
async def test_slow_bound_dns_connection_gets_six_seconds(monkeypatch):
    import dns.message
    import dns.rrset
    from litechecker.macos_network import MacDirectNetwork

    direct = network(monkeypatch)
    def response(query):
        answer = dns.message.make_response(query)
        if query.question[0].rdtype == 1:
            answer.answer.append(dns.rrset.from_text("example.com.", 30, "IN", "A", "8.8.8.8"))
        return answer
    async with dns_fixture(monkeypatch, direct, response) as (requests, finished):
        connect = MacDirectNetwork._connect_ip
        timeout = asyncio.timeout
        monkeypatch.setattr(asyncio, "timeout", lambda seconds: timeout(seconds / 10))
        async def slow(self, *args, **kwargs):
            await asyncio.sleep(0.4)
            return await connect(self, *args, **kwargs)
        monkeypatch.setattr(MacDirectNetwork, "_connect_ip", slow)
        assert await direct.resolve("example.com") == ["8.8.8.8"]
        assert len(requests) == 2


@pytest.mark.asyncio
async def test_dns_allows_one_empty_family_but_does_not_cache(monkeypatch):
    import dns.message
    import dns.rdatatype
    import dns.rrset

    direct = network(monkeypatch)
    answers = iter(["8.8.8.8", "1.1.1.1"])

    def reply(query):
        response = dns.message.make_response(query)
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text("example.com.", 30, "IN", "A", next(answers)))
        return response

    async with dns_fixture(monkeypatch, direct, reply):
        assert await direct.resolve("example.com") == ["8.8.8.8"]
        assert await direct.resolve("example.com") == ["1.1.1.1"]


@pytest.mark.asyncio
async def test_cancelled_dns_closes_connected_stream(monkeypatch):
    direct = network(monkeypatch)
    async with dns_fixture(monkeypatch, direct, lambda query: None) as (_, finished):
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.05):
                await direct.resolve("example.com")
        await asyncio.wait_for(finished.wait(), 1)


@pytest.mark.asyncio
@pytest.mark.skipif(__import__("sys").platform != "darwin", reason="Darwin bound-interface socket option")
async def test_connect_returns_streams_after_real_socket_interface_binding(monkeypatch):
    from litechecker import macos_network as module

    index = socket.if_nametoindex("lo0")
    direct = module.MacDirectNetwork("en0", index, ("127.0.0.1",), ("192.168.1.1",))
    monkeypatch.setattr(module.MacDirectNetwork, "_validate_interface", lambda self: None)
    completed = asyncio.Event()

    async def echo(reader, writer):
        try:
            writer.write(await reader.readexactly(4))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            completed.set()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    loop = asyncio.get_running_loop()
    native_connect = loop.sock_connect

    async def remap(sock, address):
        if address != ("8.8.8.8", 443):
            raise AssertionError("unexpected destination")
        assert sock.getsockopt(socket.IPPROTO_IP, 25) == index
        assert sock.getsockname()[0] == "127.0.0.1"
        await native_connect(sock, ("127.0.0.1", port))

    monkeypatch.setattr(loop, "sock_connect", remap)
    try:
        reader, writer = await direct.connect("8.8.8.8", 443)
        writer.write(b"ping")
        await writer.drain()
        assert await reader.readexactly(4) == b"ping"
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(completed.wait(), 1)
    finally:
        server.close()
        await server.wait_closed()

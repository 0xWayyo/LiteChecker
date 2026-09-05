"""Exercise the prototype relay against real loopback streams, never the Internet."""

import asyncio
import contextlib
import ipaddress
from urllib.parse import urlsplit

import pytest

from litechecker.direct_relay import DirectRelay


class LocalNetwork:
    interface = "test-only"

    def __init__(self, port):
        self.port = port
        self.destinations = []

    async def connect(self, host, port):
        self.destinations.append((host, port))
        if (host, port) != ("edge.example", 443):
            raise OSError("unexpected test destination")
        return await asyncio.open_connection("127.0.0.1", self.port)


@contextlib.asynccontextmanager
async def echo_server():
    writers = set()
    closed = asyncio.Event()

    async def echo(reader, writer):
        writers.add(writer)
        try:
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
        finally:
            writers.discard(writer)
            writer.close()
            await writer.wait_closed()
            closed.set()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], closed
    finally:
        server.close()
        await server.wait_closed()
        for writer in tuple(writers):
            writer.close()
            await writer.wait_closed()


@contextlib.asynccontextmanager
async def client(relay):
    url = urlsplit(relay.proxy_url)
    reader, writer = await asyncio.open_connection(url.hostname, url.port)
    try:
        yield reader, writer, url
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def authenticate(reader, writer, url, *, password=None):
    writer.write(b"\x05\x02\x00\x02")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x02"
    username = url.username.encode()
    secret = (url.password if password is None else password).encode()
    writer.write(bytes((1, len(username))) + username + bytes((len(secret),)) + secret)
    await writer.drain()
    return await reader.readexactly(2)


async def connect_request(reader, writer, *, command=1, host="edge.example", port=443):
    try:
        address = ipaddress.ip_address(host)
        encoded = bytes((1 if address.version == 4 else 4,)) + address.packed
    except ValueError:
        encoded = bytes((3, len(host))) + host.encode("ascii")
    writer.write(bytes((5, command, 0)) + encoded + port.to_bytes(2, "big"))
    await writer.drain()
    return await reader.readexactly(10)


@pytest.mark.asyncio
async def test_anonymous_clients_are_denied_before_any_dial():
    """Enabling no-auth would turn this into an open local proxy."""
    network = LocalNetwork(1)
    async with DirectRelay(network) as relay, client(relay) as (reader, writer, _):
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\xff"
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert network.destinations == []


@pytest.mark.asyncio
async def test_wrong_credentials_are_denied_before_any_dial():
    """Accepting an incorrect password would defeat per-run authentication."""
    network = LocalNetwork(1)
    async with DirectRelay(network) as relay, client(relay) as (reader, writer, url):
        assert await authenticate(reader, writer, url, password="incorrect") != b"\x01\x00"
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert network.destinations == []


@pytest.mark.asyncio
async def test_authenticated_connect_keeps_domain_resolution_inside_bound_network():
    """Resolving through the ambient OS or bypassing network.connect breaks direct isolation."""
    async with echo_server() as (port, _):
        network = LocalNetwork(port)
        async with DirectRelay(network) as relay, client(relay) as (reader, writer, url):
            assert url.hostname == "127.0.0.1"
            assert await authenticate(reader, writer, url) == b"\x01\x00"
            assert await connect_request(reader, writer) == b"\x05\x00\x00\x01" + b"\x00" * 6
            writer.write(b"only-the-bound-network")
            await writer.drain()
            assert await reader.readexactly(22) == b"only-the-bound-network"
            assert network.destinations == [("edge.example", 443)]
            assert relay.failures == 0


@pytest.mark.asyncio
async def test_network_failure_never_falls_back_to_reachable_ambient_destination():
    """A failed bound dial must not retry the otherwise reachable loopback destination."""
    class UnavailableNetwork:
        async def connect(self, host, port):
            raise OSError("bound interface unavailable")

    async with echo_server() as (port, _):
        async with DirectRelay(UnavailableNetwork()) as relay, client(relay) as (reader, writer, url):
            assert await authenticate(reader, writer, url) == b"\x01\x00"
            assert (await connect_request(reader, writer, host="127.0.0.1", port=port))[1] != 0
            assert await asyncio.wait_for(reader.read(), 1) == b""
            assert relay.failures == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("command", [2, 3])
async def test_bind_and_udp_are_rejected(command):
    """Supporting BIND or UDP would expand the prototype beyond bounded TCP CONNECT."""
    network = LocalNetwork(1)
    async with DirectRelay(network) as relay, client(relay) as (reader, writer, url):
        assert await authenticate(reader, writer, url) == b"\x01\x00"
        assert (await connect_request(reader, writer, command=command))[1] == 7
        assert network.destinations == []


@pytest.mark.asyncio
async def test_partial_handshake_expires():
    """A stalled client must not retain a relay slot indefinitely."""
    async with DirectRelay(LocalNetwork(1), handshake_timeout=0.03) as relay:
        async with client(relay) as (reader, writer, _):
            writer.write(b"\x05")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 1) == b""


@pytest.mark.asyncio
async def test_connection_limit_rejects_excess_clients():
    """Queueing unlimited clients would retain unbounded tasks and sockets."""
    async with DirectRelay(LocalNetwork(1), max_clients=1) as relay:
        async with client(relay) as (first_reader, first_writer, _):
            first_writer.write(b"\x05\x01\x02")
            await first_writer.drain()
            assert await first_reader.readexactly(2) == b"\x05\x02"
            async with client(relay) as (reader, _, _):
                assert await asyncio.wait_for(reader.read(), 1) == b""


@pytest.mark.asyncio
async def test_connection_lifetime_closes_both_sides():
    """A connected but idle tunnel must not outlive its bounded lifetime."""
    async with echo_server() as (port, closed):
        async with DirectRelay(LocalNetwork(port), connection_timeout=0.08) as relay:
            async with client(relay) as (reader, writer, url):
                assert await authenticate(reader, writer, url) == b"\x01\x00"
                assert (await connect_request(reader, writer))[1] == 0
                assert await asyncio.wait_for(reader.read(), 1) == b""
                await asyncio.wait_for(closed.wait(), 1)


@pytest.mark.asyncio
async def test_cancelled_owner_closes_listener_and_established_upstream():
    """Cancelling a run must reap child relays and their upstream connections."""
    connected = asyncio.Event()
    captured = {}
    async with echo_server() as (port, closed):
        async def owner():
            async with DirectRelay(LocalNetwork(port)) as relay:
                captured["url"] = urlsplit(relay.proxy_url)
                async with client(relay) as (reader, writer, url):
                    assert await authenticate(reader, writer, url) == b"\x01\x00"
                    assert (await connect_request(reader, writer))[1] == 0
                    connected.set()
                    await asyncio.Event().wait()

        task = asyncio.create_task(owner())
        await asyncio.wait_for(connected.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(closed.wait(), 1)
        with pytest.raises(OSError):
            await asyncio.open_connection(captured["url"].hostname, captured["url"].port)


@pytest.mark.asyncio
async def test_new_context_rotates_credentials_and_supplies_authenticated_xray_outbound():
    """Reusing credentials across sessions or omitting Xray auth defeats run isolation."""
    relay = DirectRelay(LocalNetwork(1))
    async with relay:
        old = urlsplit(relay.proxy_url)
    async with relay:
        current = urlsplit(relay.proxy_url)
        assert (old.username, old.password) != (current.username, current.password)
        outbound = relay.xray_outbound
        assert outbound["protocol"] == "socks"
        assert outbound["settings"]["servers"] == [{
            "address": "127.0.0.1", "port": current.port,
            "users": [{"user": current.username, "pass": current.password}],
        }]
        async with client(relay) as (reader, writer, _):
            assert await authenticate(reader, writer, old) != b"\x01\x00"

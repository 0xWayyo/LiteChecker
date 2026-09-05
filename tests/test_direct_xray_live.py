"""Manual, loopback-only integration for an explicitly supplied real Xray binary.

Run with:
    PYTHONPATH=src .venv/bin/python tests/test_direct_xray_live.py /path/to/xray

This is intentionally not a skipped default-suite test: it runs only when a
caller supplies a binary. Neither scenario needs or contacts an external host.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from urllib.parse import urlsplit

from litechecker.direct_relay import DirectRelay
from litechecker.models import TargetConfig
from litechecker.probe import XrayProcess


class LoopbackCapture:
    def __init__(self):
        self.connections = 0
        self.payloads: list[bytes] = []
        self.received = asyncio.Event()
        self.tasks: set[asyncio.Task] = set()
        self.writers: set[asyncio.StreamWriter] = set()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])
        return self

    def accept(self, reader, writer):
        self.connections += 1
        self.writers.add(writer)
        task = asyncio.create_task(self.read(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def read(self, reader, writer):
        try:
            async with asyncio.timeout(2):
                self.payloads.append(await reader.read(8192))
                self.received.set()
        finally:
            self.writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def __aexit__(self, exc_type, exc, traceback):
        self.server.close()
        await self.server.wait_closed()
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class RedirectedLoopbackNetwork:
    """Use distinct destination/capture ports so bypassing the helper is visible."""

    def __init__(self, advertised_port, capture_port):
        self.advertised_port = advertised_port
        self.capture_port = capture_port
        self.destinations: list[tuple[str, int]] = []

    async def connect(self, host, port):
        assert (host, port) == ("127.0.0.1", self.advertised_port)
        self.destinations.append((host, port))
        return await asyncio.open_connection("127.0.0.1", self.capture_port)


def target_for(port):
    return TargetConfig(
        target_id="real-xray-loopback", config_fingerprint="synthetic-loopback",
        label="Synthetic loopback only", address="127.0.0.1", port=port,
        address_kind="ip",
        outbound={
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": port,
                "users": [{
                    "id": "11111111-1111-4111-8111-111111111111",
                    "encryption": "none",
                }],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    # X25519 base point: a public synthetic value, not a secret.
                    "publicKey": "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "serverName": "loopback-test.invalid",
                    "fingerprint": "chrome", "shortId": "",
                },
            },
        },
    )


async def request_through_xray(proxy_url):
    proxy = urlsplit(proxy_url)
    reader, writer = await asyncio.open_connection(proxy.hostname, proxy.port)
    try:
        async with asyncio.timeout(10):
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x02"
            username, password = proxy.username.encode(), proxy.password.encode()
            writer.write(bytes((1, len(username))) + username + bytes((len(password),)) + password)
            await writer.drain()
            assert await reader.readexactly(2) == b"\x01\x00"
            # Destination metadata is also loopback, even if the implementation
            # incorrectly dials the requested destination without VLESS.
            writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09")
            writer.write(b"synthetic-client-payload")
            await writer.drain()
            return await reader.read()
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def run(binary):
    version_process = await asyncio.create_subprocess_exec(
        binary, "version", stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await version_process.communicate()
    version = stdout.decode().splitlines()[0]
    assert version_process.returncode == 0
    assert version.startswith("Xray 26.3.27 "), version
    async with asyncio.timeout(30):
        async with LoopbackCapture() as trap, LoopbackCapture() as capture:
            network = RedirectedLoopbackNetwork(trap.port, capture.port)
            target = target_for(trap.port)
            async with DirectRelay(network) as relay:
                helper = relay.xray_outbound
                async with XrayProcess(binary, dialer_proxy=helper).open(target) as proxy:
                    await request_through_xray(proxy)
                    await asyncio.wait_for(capture.received.wait(), 2)
                    await proxy.ensure_healthy()
                # REALITY may retry its deliberately unanswered handshake;
                # every retry must still take this same authenticated helper.
                assert network.destinations
                assert set(network.destinations) == {("127.0.0.1", trap.port)}
                assert capture.connections == len(network.destinations)
                positive_connections = capture.connections
                assert trap.connections == 0, "Xray bypassed the bound-network helper"
                payload = capture.payloads[0]
                assert payload[:1] == b"\x16", "expected a TLS ClientHello transport record"
                assert b"loopback-test.invalid" in payload
                helper_port = urlsplit(relay.proxy_url).port

            # The original destination is still reachable, but the previously
            # authenticated helper no longer exists. A fallback would hit trap.
            try:
                _, unexpected_writer = await asyncio.open_connection("127.0.0.1", helper_port)
            except OSError:
                pass
            else:
                unexpected_writer.close()
                await unexpected_writer.wait_closed()
                raise AssertionError("closed helper is still listening")
            async with XrayProcess(binary, dialer_proxy=helper).open(target) as proxy:
                await request_through_xray(proxy)
                await proxy.ensure_healthy()
            assert trap.connections == 0, "Xray fell back after the helper closed"
            assert capture.connections == positive_connections
            return {
                "binary": version,
                "authenticated_helper_outer_transport": "passed",
                "outer_transport": "REALITY TLS ClientHello",
                "captured_transport_bytes": len(payload),
                "bound_network_dials": len(network.destinations),
                "closed_helper_no_fallback": "passed",
                "ambient_destination_connections": trap.connections,
                "external_requests": 0,
            }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_direct_xray_live.py /path/to/xray")
    print(json.dumps(asyncio.run(run(sys.argv[1])), indent=2))

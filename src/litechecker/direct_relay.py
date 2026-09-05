"""Experimental, per-run loopback SOCKS relay for an explicitly bound network.

This is a bounded diagnostic transport, not an arbitrary VPN bypass. The only
upstream dial path is the supplied network; this module never resolves or opens
an upstream socket itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import secrets
from typing import Protocol


class BoundNetwork(Protocol):
    async def connect(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]: ...


class DirectRelay:
    """Own an authenticated loopback listener and all its short-lived clients."""

    def __init__(
        self,
        network: BoundNetwork,
        *,
        handshake_timeout: float = 3.0,
        connection_timeout: float = 60.0,
        max_clients: int = 64,
    ):
        if not 0 < handshake_timeout <= 3.0:
            raise ValueError("handshake timeout must be within (0, 3]")
        if not 0 < connection_timeout <= 60.0:
            raise ValueError("connection timeout must be within (0, 60]")
        if isinstance(max_clients, bool) or not isinstance(max_clients, int) or not 1 <= max_clients <= 64:
            raise ValueError("max clients must be within [1, 64]")
        self._network = network
        self._handshake_timeout = handshake_timeout
        self._connection_timeout = connection_timeout
        self._max_clients = max_clients
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._username = ""
        self._password = ""
        self._port = 0
        self._closing = True
        self.failures = 0

    async def __aenter__(self) -> DirectRelay:
        if self._server is not None:
            raise RuntimeError("relay context is already open")
        self._username = secrets.token_hex(16)
        self._password = secrets.token_hex(32)
        self._server = await asyncio.start_server(
            self._accept, "127.0.0.1", 0, limit=4096, backlog=self._max_clients
        )
        self._port = int(self._server.sockets[0].getsockname()[1])
        self._closing = False
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        self._closing = True
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Close sockets before cancellation so no child can keep either end alive.
        for writer in tuple(self._writers):
            writer.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._username = self._password = ""
        self._port = 0

    @property
    def proxy_url(self) -> str:
        self._ensure_open()
        return f"socks5://{self._username}:{self._password}@127.0.0.1:{self._port}"

    @property
    def xray_outbound(self) -> dict:
        self._ensure_open()
        return {
            "tag": "litechecker-direct-relay",
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": self._port,
                    "users": [{"user": self._username, "pass": self._password}],
                }]
            },
        }

    def _ensure_open(self) -> None:
        if self._closing or self._server is None:
            raise RuntimeError("relay context is not open")

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closing or len(self._tasks) >= self._max_clients:
            writer.close()
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream: asyncio.StreamWriter | None = None
        dialing = False
        try:
            async with asyncio.timeout(self._connection_timeout):
                async with asyncio.timeout(self._handshake_timeout):
                    destination = await self._handshake(reader, writer)
                if destination is None:
                    return
                dialing = True
                try:
                    upstream_reader, upstream = await self._network.connect(*destination)
                except Exception:
                    self.failures += 1
                    dialing = False
                    await self._reply(writer, 1)
                    return
                self._writers.add(upstream)
                await self._reply(writer, 0)
                async with asyncio.TaskGroup() as pipes:
                    pipes.create_task(self._pipe(reader, upstream))
                    pipes.create_task(self._pipe(upstream_reader, writer))
        except (TimeoutError, ConnectionError, OSError, asyncio.IncompleteReadError, UnicodeError):
            if dialing:
                self.failures += 1
        except ExceptionGroup:
            # Stream failures in either direction invalidate this direct session.
            self.failures += 1
        finally:
            for connection in (writer, upstream):
                if connection is not None:
                    self._writers.discard(connection)
                    connection.close()
                    with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                        await asyncio.wait_for(connection.wait_closed(), timeout=1.0)

    async def _handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[str, int] | None:
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5 or 2 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None
        writer.write(b"\x05\x02")
        await writer.drain()
        auth_version, username_length = await reader.readexactly(2)
        username = await reader.readexactly(username_length)
        password_length = (await reader.readexactly(1))[0]
        password = await reader.readexactly(password_length)
        valid_user = secrets.compare_digest(username, self._username.encode("ascii"))
        valid_password = secrets.compare_digest(password, self._password.encode("ascii"))
        if auth_version != 1 or not (valid_user and valid_password):
            writer.write(b"\x01\x01")
            await writer.drain()
            return None
        writer.write(b"\x01\x00")
        await writer.drain()
        version, command, reserved, address_type = await reader.readexactly(4)
        if version != 5 or reserved != 0 or command != 1:
            await self._reply(writer, 7)
            return None
        if address_type in (1, 4):
            size = 4 if address_type == 1 else 16
            host = str(ipaddress.ip_address(await reader.readexactly(size)))
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
            if not 1 <= length <= 253:
                await self._reply(writer, 8)
                return None
            host = (await reader.readexactly(length)).decode("ascii")
            if any(character.isspace() or ord(character) < 33 for character in host):
                await self._reply(writer, 8)
                return None
        else:
            await self._reply(writer, 8)
            return None
        port = int.from_bytes(await reader.readexactly(2), "big")
        if port == 0:
            await self._reply(writer, 1)
            return None
        return host, port

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int) -> None:
        writer.write(bytes((5, status, 0, 1)) + b"\x00" * 6)
        await writer.drain()

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(65_536):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()

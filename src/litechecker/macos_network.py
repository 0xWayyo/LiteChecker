"""macOS interface-scoped sockets; no unbound fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import sys
from dataclasses import dataclass

from litechecker.direct_network import DirectNetworkUnavailable, TCPDirectNetwork, _numeric
from litechecker.runtime import join_owned_tasks


async def _run(*args: str) -> str:
    process = None
    try:
        async with asyncio.timeout(3):
            process = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            output, _ = await process.communicate()
        if process.returncode != 0 or len(output) > 131072:
            raise DirectNetworkUnavailable("interface_discovery_failed")
        return output.decode("utf-8", errors="strict")
    except asyncio.CancelledError:
        raise
    except (OSError, TimeoutError, UnicodeError) as exc:
        raise DirectNetworkUnavailable("interface_discovery_failed") from exc
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await join_owned_tasks((asyncio.create_task(process.wait()),))


@dataclass(frozen=True)
class MacDirectNetwork(TCPDirectNetwork):
    interface: str
    interface_index: int
    source_addresses: tuple[str, ...]
    dns_servers: tuple[str, ...]

    @classmethod
    async def discover(cls) -> MacDirectNetwork:
        if sys.platform != "darwin":
            raise DirectNetworkUnavailable("direct_platform_unsupported")
        hardware = await _run("/usr/sbin/networksetup", "-listallhardwareports")
        candidates: list[tuple[str, tuple[str, ...]]] = []
        interfaces: set[str] = set()
        for block in re.split(r"\n\s*\n", hardware):
            port = re.search(r"^Hardware Port: (.+)$", block, re.MULTILINE)
            device = re.search(r"^Device: (en[0-9]+)$", block, re.MULTILINE)
            if not port or not device or not re.search(r"Wi-Fi|WiFi|AirPort|Ethernet|\bLAN\b", port[1], re.IGNORECASE):
                continue
            interface = device[1]
            if interface in interfaces:
                continue
            interfaces.add(interface)
            state = await _run("/sbin/ifconfig", interface)
            if not re.search(r"^\s*status:\s*active\s*$", state, re.MULTILINE):
                continue
            flags = re.search(r"^[^\n]*flags=[0-9]+<([^>]+)>", state)
            if not flags or "UP" not in flags[1].split(","):
                continue
            sources = []
            for value in re.findall(r"^\s*inet6?\s+(\S+)", state, re.MULTILINE):
                raw, *scope = value.split("%")
                if scope and scope != [interface]:
                    raise DirectNetworkUnavailable("interface_address_invalid")
                address = _numeric(raw, infrastructure=True)
                sources.append(str(address))
            if sources:
                candidates.append((interface, tuple(dict.fromkeys(sources))))
        if len(candidates) != 1:
            raise DirectNetworkUnavailable("physical_interface_ambiguous_or_unavailable")
        interface, sources = candidates[0]
        resolvers = await _run("/usr/sbin/ipconfig", "getoption", interface, "domain_name_server")
        servers = tuple(dict.fromkeys(str(_numeric(value, infrastructure=True)) for value in resolvers.split()))
        if not servers or len(servers) > 16:
            raise DirectNetworkUnavailable("dhcp_dns_unavailable")
        try:
            index = socket.if_nametoindex(interface)
        except OSError as exc:
            raise DirectNetworkUnavailable("interface_changed") from exc
        direct = cls(interface, index, sources, servers)
        direct._validate_interface()
        return direct

    async def validate_snapshot(self) -> None:
        """Re-read physical attachment data; en0/index alone survives Wi-Fi switches.

        This detects observable adapter/address/DNS changes, not every possible
        upstream change which leaves all local configuration identical.
        """
        current = await type(self).discover()
        if (current.interface != self.interface
                or current.interface_index != self.interface_index
                or current.source_addresses != self.source_addresses
                or current.dns_servers != self.dns_servers):
            raise DirectNetworkUnavailable("interface_changed")

    def _validate_interface(self) -> None:
        try:
            if (
                sys.platform != "darwin" or re.fullmatch(r"en[0-9]+", self.interface) is None
                or self.interface_index <= 0
                or socket.if_nametoindex(self.interface) != self.interface_index
                or socket.if_indextoname(self.interface_index) != self.interface
            ):
                raise DirectNetworkUnavailable("interface_changed")
        except OSError as exc:
            raise DirectNetworkUnavailable("interface_changed") from exc

    def _socket(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> socket.socket:
        self._validate_interface()
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        sources = [ipaddress.ip_address(value) for value in self.source_addresses]
        source = next((value for value in sources if value.version == address.version and (not value.is_link_local or address.is_link_local)), None)
        if source is None:
            raise DirectNetworkUnavailable("interface_address_family_unavailable")
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            # Public Darwin socket options; Python does not expose them on all builds.
            level, option = (socket.IPPROTO_IP, 25) if address.version == 4 else (socket.IPPROTO_IPV6, 125)
            sock.setsockopt(level, option, self.interface_index)
            if sock.getsockopt(level, option) != self.interface_index:
                raise DirectNetworkUnavailable("interface_binding_failed")
            source_sockaddr = (str(source), 0) if address.version == 4 else (str(source), 0, 0, self.interface_index if source.is_link_local else 0)
            sock.bind(source_sockaddr)
            sock.setblocking(False)
            return sock
        except BaseException as exc:
            if sock is not None:
                sock.close()
            if isinstance(exc, OSError):
                raise DirectNetworkUnavailable("interface_binding_failed") from exc
            raise

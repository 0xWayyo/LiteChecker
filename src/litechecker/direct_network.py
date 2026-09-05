"""Experimental macOS interface-scoped connections with no unbound fallback.

This selects a physical interface; it does not prove an ISP identity or bypass
router VPNs and macOS Network Extension policy. Callers own connection deadlines.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import re
import socket
import sys
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype


class DirectNetworkUnavailable(RuntimeError):
    """The requested direct path could not be established safely."""

    def __init__(self, code: str = "direct_network_unavailable") -> None:
        self.code = code
        super().__init__(code)


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
            await process.wait()


def _numeric(value: str, *, infrastructure: bool = False) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("scoped or non-string address")
        address = ipaddress.ip_address(value)
        if (
            address.is_unspecified or address.is_loopback or address.is_multicast
            or address.is_reserved
            or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
            or (not infrastructure and not address.is_global)
        ):
            raise ValueError("unsupported address")
        return address
    except ValueError as exc:
        raise DirectNetworkUnavailable("unsafe_direct_address") from exc


def _dns_answers(query: dns.message.Message, response: dns.message.Message) -> list[str]:
    if (
        response.id != query.id or response.question != query.question
        or not query.is_response(response) or response.flags & dns.flags.TC
    ):
        raise DirectNetworkUnavailable("direct_dns_invalid_response")
    if response.rcode() == dns.rcode.NXDOMAIN:
        raise DirectNetworkUnavailable("direct_dns_nxdomain")
    if response.rcode() != dns.rcode.NOERROR:
        raise DirectNetworkUnavailable("direct_dns_failed")
    question = query.question[0]
    current = question.name
    seen = set()
    for _ in range(17):
        if current in seen:
            raise DirectNetworkUnavailable("direct_dns_cname_loop")
        seen.add(current)
        records = [rrset for rrset in response.answer if rrset.name == current]
        if any(rrset.rdclass != dns.rdataclass.IN or rrset.rdtype == dns.rdatatype.DNAME for rrset in records):
            raise DirectNetworkUnavailable("direct_dns_unsupported_answer")
        aliases = [rrset for rrset in records if rrset.rdtype == dns.rdatatype.CNAME]
        addresses = [rrset for rrset in records if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)]
        if aliases:
            if len(aliases) != 1 or len(aliases[0]) != 1 or addresses:
                raise DirectNetworkUnavailable("direct_dns_ambiguous_cname")
            current = aliases[0][0].target
            continue
        result = []
        for rrset in addresses:
            if rrset.rdtype == question.rdtype:
                for item in rrset:
                    result.append(str(_numeric(item.address)))
                    if len(result) > 64:
                        raise DirectNetworkUnavailable("direct_dns_too_many_addresses")
        return list(dict.fromkeys(result))
    raise DirectNetworkUnavailable("direct_dns_cname_limit")


class TCPDirectNetwork:
    """DNS and TCP protocol shared by strictly interface-bound platform backends."""

    interface: str
    interface_index: int
    source_addresses: tuple[str, ...]
    dns_servers: tuple[str, ...]

    def _validate_interface(self) -> None:
        raise NotImplementedError

    def _socket(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> socket.socket:
        raise NotImplementedError

    async def _connect_ip(self, ip: str, port: int, *, infrastructure: bool = False) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        address = _numeric(ip, infrastructure=infrastructure)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise DirectNetworkUnavailable("invalid_direct_port")
        sock = self._socket(address)
        try:
            target = (str(address), port) if address.version == 4 else (str(address), port, 0, self.interface_index if address.is_link_local else 0)
            await asyncio.get_running_loop().sock_connect(sock, target)
            self._validate_interface()
            return await asyncio.open_connection(sock=sock)
        except BaseException as exc:
            sock.close()
            if isinstance(exc, OSError):
                code = "direct_connection_timeout" if isinstance(exc, TimeoutError) else {
                    errno.ECONNREFUSED: "direct_connection_refused",
                    errno.ETIMEDOUT: "direct_connection_timeout",
                    errno.ENETUNREACH: "direct_connection_unreachable",
                    errno.EHOSTUNREACH: "direct_connection_unreachable",
                    errno.ECONNRESET: "direct_connection_reset",
                }.get(exc.errno, "direct_connection_failed")
                raise DirectNetworkUnavailable(code) from exc
            raise

    async def resolve(self, host: str) -> list[str]:
        if not isinstance(host, str) or not host or "%" in host:
            raise DirectNetworkUnavailable("invalid_direct_host")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return [str(_numeric(host))]
        try:
            hostname = host.encode("idna").decode("ascii").rstrip(".").lower()
        except UnicodeError as exc:
            raise DirectNetworkUnavailable("invalid_direct_host") from exc
        if not hostname or len(hostname) > 253 or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
            for label in hostname.split(".")
        ):
            raise DirectNetworkUnavailable("invalid_direct_host")
        self._validate_interface()
        addresses = []
        for kind in (dns.rdatatype.A, dns.rdatatype.AAAA):
            addresses.extend(await self._query(hostname, kind))
            if len(addresses) > 64:
                raise DirectNetworkUnavailable("direct_dns_too_many_addresses")
        if not addresses:
            raise DirectNetworkUnavailable("direct_dns_no_addresses")
        return list(dict.fromkeys(addresses))

    async def _query(self, host: str, kind: dns.rdatatype.RdataType) -> list[str]:
        if not self.dns_servers:
            raise DirectNetworkUnavailable("dhcp_dns_unavailable")
        # TCP deliberately avoids fragmentation and UDP fallback. The DHCP
        # resolver must support standard DNS over TCP or the trial stops closed.
        query = dns.message.make_query(host + ".", kind, use_edns=False)
        payload = query.to_wire()
        writer = None
        try:
            async with asyncio.timeout(3):
                resolver = str(_numeric(self.dns_servers[0], infrastructure=True))
                reader, writer = await self._connect_ip(resolver, 53, infrastructure=True)
                writer.write(len(payload).to_bytes(2, "big") + payload)
                await writer.drain()
                length = int.from_bytes(await reader.readexactly(2), "big")
                if length < 12:
                    raise DirectNetworkUnavailable("direct_dns_invalid_response")
                wire = await reader.readexactly(length)
                response = dns.message.from_wire(wire, ignore_trailing=False)
                return _dns_answers(query, response)
        except TimeoutError as exc:
            raise DirectNetworkUnavailable("direct_dns_timeout") from exc
        except (dns.exception.DNSException, EOFError, ValueError) as exc:
            raise DirectNetworkUnavailable("direct_dns_invalid_response") from exc
        except OSError as exc:
            raise DirectNetworkUnavailable("direct_dns_failed") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def connect(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise DirectNetworkUnavailable("invalid_direct_port")
        addresses = await self.resolve(host)
        last_code = "direct_connection_failed"
        for ip in addresses:
            try:
                return await self._connect_ip(ip, port)
            except DirectNetworkUnavailable as exc:
                last_code = exc.code
        # Keep the final attempt's cause without changing address retry order.
        raise DirectNetworkUnavailable(last_code)


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

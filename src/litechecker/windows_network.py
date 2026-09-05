"""Experimental read-only Windows x64 adapter-scoped TCP backend.

Adapter DNS is configured DNS, not proof of ISP ownership. Binding cannot
override Windows Filtering Platform/VPN policy or a VPN on the upstream router.
Scoped/link-local addresses are deliberately unsupported in this first build.

ABI references (Microsoft Windows SDK):
https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
"""

from __future__ import annotations

import asyncio
import ctypes as C
import ipaddress
import socket
import struct
import sys
import uuid
from dataclasses import dataclass

from .direct_network import DirectNetworkUnavailable, TCPDirectNetwork, _numeric


# Windows is LLP64: ULONG and WCHAR stay 4 and 2 bytes on 64-bit Windows.
# Fixed-width fields also permit ABI fixture tests on a non-Windows host.
U8, U16, U32, U64 = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64


class _SocketAddress(C.Structure):
    _fields_ = [("lpSockaddr", C.c_void_p), ("iSockaddrLength", C.c_int32)]


class _UnicastAddress(C.Structure):
    pass


_UnicastAddress._fields_ = [
    ("Length", U32), ("Flags", U32), ("Next", C.POINTER(_UnicastAddress)),
    ("Address", _SocketAddress), ("PrefixOrigin", U32), ("SuffixOrigin", U32),
    ("DadState", U32), ("ValidLifetime", U32), ("PreferredLifetime", U32),
    ("LeaseLifetime", U32), ("OnLinkPrefixLength", U8),
]


class _DnsAddress(C.Structure):
    pass


_DnsAddress._fields_ = [
    ("Length", U32), ("Reserved", U32), ("Next", C.POINTER(_DnsAddress)),
    ("Address", _SocketAddress),
]


class _AdapterAddresses(C.Structure):
    pass


_AdapterAddresses._fields_ = [
    ("Length", U32), ("IfIndex", U32), ("Next", C.POINTER(_AdapterAddresses)),
    ("AdapterName", C.c_char_p), ("FirstUnicastAddress", C.POINTER(_UnicastAddress)),
    ("FirstAnycastAddress", C.c_void_p), ("FirstMulticastAddress", C.c_void_p),
    ("FirstDnsServerAddress", C.POINTER(_DnsAddress)), ("DnsSuffix", C.c_void_p),
    ("Description", C.c_void_p), ("FriendlyName", C.c_void_p),
    ("PhysicalAddress", U8 * 8), ("PhysicalAddressLength", U32), ("Flags", U32),
    ("Mtu", U32), ("IfType", U32), ("OperStatus", U32), ("Ipv6IfIndex", U32),
    ("ZoneIndices", U32 * 16), ("FirstPrefix", C.c_void_p),
    ("TransmitLinkSpeed", U64), ("ReceiveLinkSpeed", U64),
    ("FirstWinsServerAddress", C.c_void_p), ("FirstGatewayAddress", C.c_void_p),
    ("Ipv4Metric", U32), ("Ipv6Metric", U32), ("Luid", U64),
    ("Dhcpv4Server", _SocketAddress), ("CompartmentId", U32),
    ("NetworkGuid", U8 * 16), ("ConnectionType", U32), ("TunnelType", U32),
    ("Dhcpv6Server", _SocketAddress), ("Dhcpv6ClientDuid", U8 * 130),
    ("Dhcpv6ClientDuidLength", U32), ("Dhcpv6Iaid", U32), ("FirstDnsSuffix", C.c_void_p),
]


class _MibIfRow2(C.Structure):
    _fields_ = [
        ("InterfaceLuid", U64), ("InterfaceIndex", U32), ("InterfaceGuid", U8 * 16),
        ("Alias", U16 * 257), ("Description", U16 * 257),
        ("PhysicalAddressLength", U32), ("PhysicalAddress", U8 * 32),
        ("PermanentPhysicalAddress", U8 * 32), ("Mtu", U32), ("Type", U32),
        ("TunnelType", U32), ("MediaType", U32), ("PhysicalMediumType", U32),
        ("AccessType", U32), ("DirectionType", U32),
        ("InterfaceAndOperStatusFlags", U8), ("OperStatus", U32),
        ("AdminStatus", U32), ("MediaConnectState", U32), ("NetworkGuid", U8 * 16),
        ("ConnectionType", U32), ("TransmitLinkSpeed", U64), ("ReceiveLinkSpeed", U64),
    ] + [(name, U64) for name in (
        "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors",
        "InUnknownProtos", "InUcastOctets", "InMulticastOctets", "InBroadcastOctets",
        "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards", "OutErrors",
        "OutUcastOctets", "OutMulticastOctets", "OutBroadcastOctets", "OutQLen",
    )]


def _load_ip_helper():
    # No DLL loading on import; only supported pointer width enters native code.
    if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
        raise DirectNetworkUnavailable("direct_platform_unsupported")
    try:
        dll = C.WinDLL("iphlpapi.dll", winmode=0x00000800)  # System32 only.
        dll.GetAdaptersAddresses.argtypes = [U32, U32, C.c_void_p, C.POINTER(_AdapterAddresses), C.POINTER(U32)]
        dll.GetAdaptersAddresses.restype = U32
        dll.GetIfEntry2.argtypes = [C.POINTER(_MibIfRow2)]
        dll.GetIfEntry2.restype = U32
        return dll
    except (OSError, AttributeError) as exc:
        raise DirectNetworkUnavailable("interface_discovery_failed") from exc


def _nodes(pointer, minimum_length: int):
    seen = set()
    while pointer:
        location = C.cast(pointer, C.c_void_p).value
        if location in seen or len(seen) >= 256:
            raise DirectNetworkUnavailable("interface_discovery_failed")
        seen.add(location)
        node = pointer.contents
        if node.Length < minimum_length:
            raise DirectNetworkUnavailable("interface_discovery_failed")
        yield node
        pointer = node.Next


def _address(value: _SocketAddress) -> str | None:
    if not value.lpSockaddr or value.iSockaddrLength not in (16, 28):
        return None
    data = C.string_at(value.lpSockaddr, value.iSockaddrLength)
    family = int.from_bytes(data[:2], "little")
    if family == 2 and len(data) == 16:  # Windows AF_INET
        address = ipaddress.ip_address(data[4:8])
    elif family == 23 and len(data) == 28 and data[24:28] == bytes(4):  # Windows AF_INET6
        address = ipaddress.ip_address(data[8:24])
    else:
        return None
    try:
        checked = _numeric(str(address), infrastructure=True)
    except DirectNetworkUnavailable:
        return None
    return None if checked.is_link_local else str(checked)


@dataclass(frozen=True)
class _Adapter:
    name: str
    luid: int
    guid: str
    ipv4_index: int
    ipv6_index: int
    sources: tuple[str, ...]
    dns: tuple[str, ...]


def _inventory() -> tuple[_Adapter, ...]:
    dll = _load_ip_helper()
    size = U32(15360)  # Recommended initial allocation; bounded race retries.
    for _ in range(3):
        if not 0 < size.value <= 1024 * 1024:
            raise DirectNetworkUnavailable("interface_discovery_failed")
        buffer = C.create_string_buffer(size.value)
        head = C.cast(buffer, C.POINTER(_AdapterAddresses))
        # Skip anycast + multicast + friendly name, retaining unicast and DNS.
        status = dll.GetAdaptersAddresses(0, 2 | 4 | 32, None, head, C.byref(size))
        if status != 111:  # ERROR_BUFFER_OVERFLOW
            break
    if status == 232:  # ERROR_NO_DATA
        return ()
    if status != 0:
        raise DirectNetworkUnavailable("interface_discovery_failed")
    candidates = []
    for node in _nodes(head, _AdapterAddresses.TunnelType.offset + 4):
        if node.IfType not in (6, 71) or node.OperStatus != 1 or node.TunnelType != 0 or not node.Luid:
            continue
        row = _MibIfRow2()
        row.InterfaceLuid = node.Luid
        if dll.GetIfEntry2(C.byref(row)) != 0:
            raise DirectNetworkUnavailable("interface_discovery_failed")
        # Hardware + connector; all other status bits (filter, unauthenticated,
        # disconnected, paused, low power, endpoint) must be clear.
        if (
            row.InterfaceLuid != node.Luid or row.InterfaceIndex != (node.IfIndex or node.Ipv6IfIndex)
            or row.InterfaceAndOperStatusFlags != 5 or row.Type != node.IfType
            or row.TunnelType != 0 or row.OperStatus != 1
            or row.AdminStatus != 1 or row.MediaConnectState != 1
            or row.DirectionType != 0 or node.Flags & 8  # SendReceive; not ReceiveOnly.
            or not any(row.InterfaceGuid) or not node.AdapterName
            or node.IfIndex >= 1 << 24 or not (node.IfIndex or node.Ipv6IfIndex)
        ):
            continue
        sources = []
        for item in _nodes(node.FirstUnicastAddress, C.sizeof(_UnicastAddress)):
            # IpDadStatePreferred only, no cluster/transient addresses.
            if item.DadState != 4 or item.Flags & 2 or not item.ValidLifetime or not item.PreferredLifetime:
                continue
            address = _address(item.Address)
            if address and ((":" in address and node.Ipv6IfIndex) or (":" not in address and node.IfIndex)):
                sources.append(address)
        sources = tuple(dict.fromkeys(sources))
        families = {ipaddress.ip_address(value).version for value in sources}
        dns = []
        for item in _nodes(node.FirstDnsServerAddress, C.sizeof(_DnsAddress)):
            address = _address(item.Address)
            if address and ipaddress.ip_address(address).version in families:
                dns.append(address)
        dns = tuple(dict.fromkeys(dns))
        if not sources or not dns or len(dns) > 16:
            continue
        try:
            name = node.AdapterName.decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise DirectNetworkUnavailable("interface_discovery_failed") from exc
        candidates.append(_Adapter(name, node.Luid, str(uuid.UUID(bytes_le=bytes(row.InterfaceGuid))), node.IfIndex, node.Ipv6IfIndex, sources, dns))
    return tuple(candidates)


def _selected() -> _Adapter:
    if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
        raise DirectNetworkUnavailable("direct_platform_unsupported")
    try:
        candidates = _inventory()
    except OSError as exc:
        raise DirectNetworkUnavailable("interface_discovery_failed") from exc
    if len(candidates) != 1:
        raise DirectNetworkUnavailable("physical_interface_ambiguous_or_unavailable")
    return candidates[0]


@dataclass(frozen=True)
class WindowsDirectNetwork(TCPDirectNetwork):
    interface: str
    interface_index: int
    source_addresses: tuple[str, ...]
    dns_servers: tuple[str, ...]
    luid: int
    guid: str
    ipv4_index: int
    ipv6_index: int

    async def _query(self, host, kind) -> list[str]:
        # Explicit Windows policy: DoH on the same bound sockets as probes.
        # Adapter DNS/53 is still observed separately by windows_diagnostics.
        from .windows_doh import query
        return await query(self, host, kind)

    @classmethod
    async def discover(cls) -> WindowsDirectNetwork:
        # Guard before dispatch too: unsupported platforms must not load DLLs.
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise DirectNetworkUnavailable("direct_platform_unsupported")
        adapter = await asyncio.to_thread(_selected)
        return cls(adapter.name, adapter.ipv4_index or adapter.ipv6_index,
                   adapter.sources, adapter.dns, adapter.luid, adapter.guid,
                   adapter.ipv4_index, adapter.ipv6_index)

    def _validate_interface(self) -> None:
        expected = _Adapter(self.interface, self.luid, self.guid, self.ipv4_index,
                            self.ipv6_index, self.source_addresses, self.dns_servers)
        try:
            if self.interface_index != (self.ipv4_index or self.ipv6_index) or _selected() != expected:
                raise DirectNetworkUnavailable("interface_changed")
        except DirectNetworkUnavailable as exc:
            raise DirectNetworkUnavailable("interface_changed") from exc

    def _socket(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> socket.socket:
        self._validate_interface()
        # Shared TCP layer validates measurement targets as public; adapter DNS
        # may be private. Repeat infrastructure checks at this socket boundary.
        address = _numeric(str(address), infrastructure=True)
        if address.is_link_local:
            raise DirectNetworkUnavailable("unsafe_direct_address")
        index = self.ipv4_index if address.version == 4 else self.ipv6_index
        source = next((value for value in self.source_addresses if ipaddress.ip_address(value).version == address.version), None)
        if not index or source is None:
            raise DirectNetworkUnavailable("interface_address_family_unavailable")
        sock = None
        try:
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            sock = socket.socket(family, socket.SOCK_STREAM)
            level = socket.IPPROTO_IP if address.version == 4 else socket.IPPROTO_IPV6
            # Both constants are 31 in ws2ipdef.h. IPv4 SET is network order;
            # IPv6 SET and BOTH GETs are host order (Microsoft Winsock docs).
            value = struct.pack("!I" if address.version == 4 else "=I", index)
            sock.setsockopt(level, 31, value)
            if sock.getsockopt(level, 31, 4) != struct.pack("=I", index):
                raise DirectNetworkUnavailable("interface_binding_failed")
            sock.bind((source, 0) if address.version == 4 else (source, 0, 0, 0))
            sock.setblocking(False)
            return sock
        except BaseException as exc:
            if sock is not None:
                sock.close()
            if isinstance(exc, OSError):
                raise DirectNetworkUnavailable("interface_binding_failed") from exc
            raise

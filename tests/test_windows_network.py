"""Read-only Windows IP Helper/Winsock boundary fixtures; no network traffic."""

from __future__ import annotations

import ctypes as C
import importlib.util
import ipaddress
import socket
import struct
from types import SimpleNamespace
import uuid

import pytest


def test_windows_backend_is_available_without_loading_windows_dlls():
    assert importlib.util.find_spec("litechecker.windows_network") is not None


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class NativeAPI:
    """Populate the actual ABI structs at the two IP Helper API boundaries."""

    def __init__(self, module, adapters=None):
        self.m = module
        self.adapters = adapters if adapters is not None else [{}]
        self.keepalive = []
        self.rows = {}
        self.calls = 0
        self.error = 0
        self.row_error = 0
        self.overflow = False
        self.GetAdaptersAddresses = Function(self.inventory)
        self.GetIfEntry2 = Function(self.row)

    def sockaddr(self, text):
        raw, _, scope = text.partition("%")
        ip = ipaddress.ip_address(raw)
        # Winsock AF_INET6 is 23, independently of the host running these tests.
        payload = (struct.pack("<HH", 2, 0) + ip.packed + bytes(8)) if ip.version == 4 else (
            struct.pack("<HHI", 23, 0, 0) + ip.packed + struct.pack("<I", int(scope or 0))
        )
        buf = C.create_string_buffer(payload)
        self.keepalive.append(buf)
        return self.m._SocketAddress(C.addressof(buf), len(payload))

    def chain(self, values, unicast):
        nodes = []
        cls = self.m._UnicastAddress if unicast else self.m._DnsAddress
        for value in values:
            node = cls()
            node.Length = C.sizeof(cls)
            node.Address = self.sockaddr(value)
            if unicast:
                node.DadState = 4
                node.ValidLifetime = node.PreferredLifetime = 3600
            if nodes:
                nodes[-1].Next = C.pointer(node)
            nodes.append(node)
        self.keepalive.extend(nodes)
        return C.pointer(nodes[0]) if nodes else C.POINTER(cls)()

    def inventory(self, family, flags, reserved, output, size):
        self.calls += 1
        assert family == 0
        assert flags & 8 == 0  # GAA_FLAG_SKIP_DNS_SERVER would break adapter DNS.
        assert not reserved
        if self.overflow:
            self.overflow = False
            C.cast(size, C.POINTER(C.c_uint32))[0] = 32768
            return 111
        if self.error:
            return self.error
        self.keepalive = []
        self.rows = {}
        nodes = []
        for index, data in enumerate(self.adapters):
            node = self.m._AdapterAddresses()
            node.Length = data.get("length", C.sizeof(type(node)))
            node.IfIndex = data.get("ipv4_index", 14 + index)
            node.Ipv6IfIndex = data.get("ipv6_index", 27 + index)
            node.Luid = data.get("luid", 100 + index)
            node.AdapterName = data.get("name", f"adapter-{index}").encode()
            node.IfType = data.get("type", 71)
            node.OperStatus = data.get("status", 1)
            node.TunnelType = data.get("tunnel", 0)
            node.Flags = data.get("adapter_flags", 128 | 256)
            node.FirstUnicastAddress = self.chain(data.get("sources", ("192.168.1.20", "2606:4700::abcd")), True)
            node.FirstDnsServerAddress = self.chain(data.get("dns", ("192.168.1.1",)), False)
            if node.FirstUnicastAddress:
                node.FirstUnicastAddress.contents.DadState = data.get("dad", 4)
                node.FirstUnicastAddress.contents.Flags = data.get("source_flags", 0)
            row = self.m._MibIfRow2()
            row.InterfaceLuid = data.get("row_luid", node.Luid)
            row.InterfaceIndex = data.get("row_index", node.IfIndex or node.Ipv6IfIndex)
            row.InterfaceGuid[:] = uuid.UUID(data.get("guid", "11111111-2222-3333-4444-555555555555")).bytes_le
            alias = data.get("alias", "").encode("utf-16-le", errors="surrogatepass")
            units = list(struct.unpack("<" + "H" * (len(alias) // 2), alias))
            row.Alias[:len(units)] = units
            row.Type = node.IfType
            row.TunnelType = node.TunnelType
            row.InterfaceAndOperStatusFlags = data.get("hardware_flags", 5)
            row.OperStatus = data.get("row_status", 1)
            row.AdminStatus = data.get("admin", 1)
            row.MediaConnectState = data.get("media", 1)
            row.DirectionType = data.get("direction", 0)
            self.rows[node.Luid] = row
            if nodes:
                nodes[-1].Next = C.pointer(node)
            nodes.append(node)
        self.keepalive.extend(nodes)
        if not nodes:
            return 232  # ERROR_NO_DATA
        C.memmove(output, C.byref(nodes[0]), C.sizeof(nodes[0]))
        return 0

    def row(self, output):
        if self.row_error:
            return self.row_error
        pointer = C.cast(output, C.POINTER(self.m._MibIfRow2))
        row = self.rows[pointer.contents.InterfaceLuid]
        C.memmove(output, C.byref(row), C.sizeof(row))
        return 0


@pytest.fixture
def native(monkeypatch):
    from litechecker import windows_network as m
    api = NativeAPI(m)
    # Proactor uses isinstance(..., socket.socket) for its own wake-up pipe.
    # Keep test socket overrides local to the measured network module.
    monkeypatch.setattr(m, "socket", SimpleNamespace(**vars(socket)))
    monkeypatch.setattr(m.sys, "platform", "win32")
    monkeypatch.setattr(m, "_load_ip_helper", lambda: api)
    return m, api


def test_winsock_boundary_fixture_does_not_replace_asyncio_stdlib_socket(native, monkeypatch):
    m, _ = native
    original = socket.socket
    monkeypatch.setattr(m.socket, "socket", lambda *args: None)
    assert socket.socket is original, "Windows Proactor must retain the real stdlib socket class"
    assert isinstance(socket.socket, type)


@pytest.mark.asyncio
async def test_discover_uses_hardware_identity_family_indices_and_adapter_dns(native):
    m, api = native
    api.adapters += [{"hardware_flags": 0}, {"status": 2}, {"type": 131}]
    direct = await m.WindowsDirectNetwork.discover()
    assert direct.interface == "adapter-0"
    assert direct.interface_index == direct.ipv4_index == 14
    assert direct.ipv6_index == 27
    assert direct.luid == 100
    assert direct.guid == "11111111-2222-3333-4444-555555555555"
    assert direct.source_addresses == ("192.168.1.20", "2606:4700::abcd")
    assert direct.dns_servers == ("192.168.1.1",)


@pytest.mark.asyncio
@pytest.mark.parametrize("alias,kind,expected", [
    ("Wi-Fi", 71, "Wi-Fi"),
    ("Ethernet 2", 6, "Ethernet 2"),
    ("Домашнее подключение 📶", 71, "Домашнее подключение 📶"),
    ("  Кабель  ", 6, "Кабель"),
    ("", 71, "Wi-Fi"),
    ("   ", 6, "Ethernet"),
    ("\ud800", 71, "Wi-Fi"),
    ("\x1b\u202e", 71, "Wi-Fi"),
    ("x" * 257, 6, "Ethernet"),  # Native buffer without a NUL terminator.
    ("Wi-Fi\0\ud800", 71, "Wi-Fi"),  # Ignore unused storage after terminator.
])
async def test_display_alias_does_not_replace_bound_adapter_identity(native, alias, kind, expected):
    m, api = native
    guid = "{11111111-2222-4333-8444-555555555555}"
    api.adapters = [{"name": guid, "alias": alias, "type": kind}]
    direct = await m.WindowsDirectNetwork.discover()
    assert direct.display_interface == expected
    assert direct.interface == guid
    assert direct.interface_index == 14
    direct._validate_interface()


@pytest.mark.asyncio
async def test_adapter_alias_rename_does_not_invalidate_same_bound_connection(native, monkeypatch):
    m, api = native
    api.adapters = [{"alias": "Wi-Fi"}]
    direct = await m.WindowsDirectNetwork.discover()
    api.adapters[0]["alias"] = "Домашний Wi-Fi"
    sock = Winsock(14)
    monkeypatch.setattr(m.socket, "socket", lambda *args: sock)
    assert direct._socket(ipaddress.ip_address("8.8.8.8")) is sock
    assert ("bind", ("192.168.1.20", 0)) in sock.events


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    {"hardware_flags": 0}, {"hardware_flags": 7}, {"hardware_flags": 13},
    {"hardware_flags": 21}, {"hardware_flags": 37}, {"hardware_flags": 69},
    {"hardware_flags": 133}, {"type": 24}, {"type": 131}, {"tunnel": 1},
    {"status": 2}, {"row_status": 2}, {"admin": 2}, {"media": 2},
    {"sources": ()}, {"dns": ()}, {"ipv4_index": 0, "ipv6_index": 0},
    {"luid": 0}, {"row_luid": 999}, {"row_index": 999},
    {"guid": "00000000-0000-0000-0000-000000000000"},
    {"ipv4_index": 0x1000000},
    {"adapter_flags": 128 | 256 | 8}, {"direction": 1}, {"direction": 2},
])
async def test_discovery_rejects_nonphysical_or_unusable_adapter(native, data):
    m, api = native
    api.adapters = [data]
    with pytest.raises(m.DirectNetworkUnavailable):
        await m.WindowsDirectNetwork.discover()


@pytest.mark.asyncio
async def test_discovery_refuses_two_eligible_adapters(native):
    m, api = native
    api.adapters = [{}, {"type": 6}]
    with pytest.raises(m.DirectNetworkUnavailable, match="ambiguous"):
        await m.WindowsDirectNetwork.discover()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1", "::", "::1", "ff02::1", "fe80::1", "2606:4700::1111%14", "::ffff:8.8.8.8"])
@pytest.mark.parametrize("key", ["sources", "dns"])
async def test_discovery_filters_unsafe_and_scoped_addresses(native, key, value):
    m, api = native
    api.adapters = [{key: (value,)}]
    with pytest.raises(m.DirectNetworkUnavailable):
        await m.WindowsDirectNetwork.discover()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [{"dad": 1}, {"dad": 3}, {"source_flags": 2}])
async def test_discovery_ignores_unready_or_transient_sources(native, change):
    m, api = native
    api.adapters = [{"sources": ("192.168.1.20",), **change}]
    with pytest.raises(m.DirectNetworkUnavailable):
        await m.WindowsDirectNetwork.discover()


@pytest.mark.asyncio
async def test_scoped_resolver_is_filtered_and_ipv6_resolver_requires_ipv6_source(native):
    m, api = native
    api.adapters = [{"sources": ("192.168.1.20",), "dns": ("fe80::1%27", "2606:4700::1111", "192.168.1.1")}]
    direct = await m.WindowsDirectNetwork.discover()
    assert direct.dns_servers == ("192.168.1.1",)


@pytest.mark.asyncio
async def test_ipv6_only_adapter_is_supported(native):
    m, api = native
    api.adapters = [{"ipv4_index": 0, "sources": ("2606:4700::abcd",), "dns": ("2606:4700::1111",)}]
    direct = await m.WindowsDirectNetwork.discover()
    assert direct.interface_index == direct.ipv6_index == 27


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"luid": 999}, {"guid": "21111111-2222-3333-4444-555555555555"},
    {"ipv4_index": 15}, {"ipv6_index": 28}, {"name": "replacement"},
    {"sources": ("192.168.1.21",)}, {"dns": ("8.8.8.8",)}, {"status": 2},
])
async def test_socket_rejects_stale_identity_indices_sources_or_dns_before_creation(native, monkeypatch, change):
    m, api = native
    direct = await m.WindowsDirectNetwork.discover()
    api.adapters = [change]
    monkeypatch.setattr(m.socket, "socket", lambda *args: pytest.fail("socket opened on stale adapter"))
    with pytest.raises(m.DirectNetworkUnavailable, match="interface_changed"):
        direct._socket(ipaddress.ip_address("8.8.8.8"))


class Winsock:
    def __init__(self, index, fail=None):
        self.index = index
        self.fail = fail
        self.events = []
        self.closed = False

    def setsockopt(self, level, option, value):
        self.events.append(("set", level, option, value))
        if self.fail == "set":
            raise OSError("option unavailable")

    def getsockopt(self, level, option, length):
        self.events.append(("get", level, option, length))
        if self.fail == "get":
            raise OSError("option unavailable")
        return struct.pack("<I", 0 if self.fail == "mismatch" else self.index)

    def bind(self, address):
        self.events.append(("bind", address))
        if self.fail == "bind":
            raise OSError("source disappeared")

    def setblocking(self, value):
        self.events.append(("blocking", value))
        if self.fail == "blocking":
            raise OSError("socket failed")

    def close(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("ip,index,family,level,wire,source", [
    ("8.8.8.8", 14, socket.AF_INET, socket.IPPROTO_IP, b"\x00\x00\x00\x0e", ("192.168.1.20", 0)),
    ("2606:4700::1111", 27, socket.AF_INET6, socket.IPPROTO_IPV6, b"\x1b\x00\x00\x00", ("2606:4700::abcd", 0, 0, 0)),
])
async def test_socket_pins_correct_family_index_byte_order_and_source(native, monkeypatch, ip, index, family, level, wire, source):
    m, api = native
    direct = await m.WindowsDirectNetwork.discover()
    sock = Winsock(index)
    creations = []
    def create(*args):
        creations.append(args)
        return sock
    monkeypatch.setattr(m.socket, "socket", create)
    before = api.calls
    assert direct._socket(ipaddress.ip_address(ip)) is sock
    assert api.calls > before
    assert creations == [(family, socket.SOCK_STREAM)]
    assert sock.events == [("set", level, 31, wire), ("get", level, 31, 4), ("bind", source), ("blocking", False)]
    assert not sock.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["set", "get", "mismatch", "bind", "blocking"])
async def test_socket_closes_on_any_binding_or_verification_failure(native, monkeypatch, failure):
    m, _ = native
    direct = await m.WindowsDirectNetwork.discover()
    sock = Winsock(14, fail=failure)
    monkeypatch.setattr(m.socket, "socket", lambda *args: sock)
    with pytest.raises(m.DirectNetworkUnavailable, match="interface_binding_failed"):
        direct._socket(ipaddress.ip_address("8.8.8.8"))
    assert sock.closed


@pytest.mark.asyncio
async def test_non_windows_discovery_never_loads_native_api(monkeypatch):
    from litechecker import windows_network as m
    monkeypatch.setattr(m.sys, "platform", "darwin")
    monkeypatch.setattr(m, "_load_ip_helper", lambda: pytest.fail("Windows DLL loaded"))
    with pytest.raises(m.DirectNetworkUnavailable, match="platform_unsupported"):
        await m.WindowsDirectNetwork.discover()


@pytest.mark.asyncio
async def test_inventory_retries_buffer_growth_and_fails_closed_on_native_error(native):
    m, api = native
    api.overflow = True
    assert (await m.WindowsDirectNetwork.discover()).interface == "adapter-0"
    assert api.calls >= 2
    api.error = 5
    with pytest.raises(m.DirectNetworkUnavailable, match="discovery_failed"):
        await m.WindowsDirectNetwork.discover()
    api.error = 0
    api.row_error = 1168
    with pytest.raises(m.DirectNetworkUnavailable):
        await m.WindowsDirectNetwork.discover()


def test_windows_x64_abi_layouts_do_not_depend_on_host_long_or_wchar_width():
    from litechecker import windows_network as m
    assert C.sizeof(m._SocketAddress) == 16
    assert C.sizeof(m._UnicastAddress) == 64
    assert C.sizeof(m._DnsAddress) == 32
    # SDK layout: 80-byte prefix before PhysicalAddress[8], then fields through
    # ZoneIndices[16] at 112; FirstPrefix at 176 and two metrics at 216/220.
    assert m._AdapterAddresses.Luid.offset == 224
    assert m._AdapterAddresses.TunnelType.offset == 272
    assert C.sizeof(m._AdapterAddresses) == 448
    assert C.sizeof(m._MibIfRow2) == 1352
    assert m._MibIfRow2.InterfaceAndOperStatusFlags.offset == 1152
    assert m._MibIfRow2.TransmitLinkSpeed.offset == 1192


@pytest.mark.asyncio
async def test_new_eligible_adapter_invalidates_existing_path(native):
    m, api = native
    direct = await m.WindowsDirectNetwork.discover()
    api.adapters.append({"type": 6})
    with pytest.raises(m.DirectNetworkUnavailable, match="interface_changed"):
        direct._validate_interface()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["127.0.0.1", "192.168.1.1", "::1", "fe80::1%27", "224.0.0.1", "::ffff:8.8.8.8"])
async def test_shared_transport_refuses_unsafe_measurement_ip_without_socket(native, monkeypatch, value):
    m, _ = native
    direct = await m.WindowsDirectNetwork.discover()
    monkeypatch.setattr(m.socket, "socket", lambda *args: pytest.fail("unsafe socket created"))
    monkeypatch.setattr(m.socket, "getaddrinfo", lambda *args: pytest.fail("system DNS called"))
    with pytest.raises(m.DirectNetworkUnavailable):
        await direct._connect_ip(value, 443)


@pytest.mark.asyncio
async def test_unavailable_target_family_does_not_create_socket(native, monkeypatch):
    m, api = native
    api.adapters = [{"ipv6_index": 0, "sources": ("192.168.1.20",)}]
    direct = await m.WindowsDirectNetwork.discover()
    monkeypatch.setattr(m.socket, "socket", lambda *args: pytest.fail("missing family socket created"))
    with pytest.raises(m.DirectNetworkUnavailable, match="address_family_unavailable"):
        direct._socket(ipaddress.ip_address("2606:4700::1111"))


@pytest.mark.asyncio
async def test_unsupported_short_native_struct_fails_closed(native):
    m, api = native
    api.adapters = [{"length": 64}]
    with pytest.raises(m.DirectNetworkUnavailable, match="discovery_failed"):
        await m.WindowsDirectNetwork.discover()


def test_native_loader_declares_read_only_windows_api_signatures(monkeypatch):
    from litechecker import windows_network as m
    api = NativeAPI(m)
    loaded = []
    def loader(name, **kwargs):
        loaded.append((name, kwargs))
        return api
    monkeypatch.setattr(m.sys, "platform", "win32")
    monkeypatch.setattr(m.C, "WinDLL", loader, raising=False)
    assert m._load_ip_helper() is api
    assert loaded == [("iphlpapi.dll", {"winmode": 0x00000800})]
    assert api.GetAdaptersAddresses.restype is C.c_uint32
    assert api.GetIfEntry2.argtypes == [C.POINTER(m._MibIfRow2)]

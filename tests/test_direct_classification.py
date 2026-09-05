"""Scoped transport evidence belongs only to the target that experienced it."""

import asyncio
import errno
import ssl

import pytest
from pydantic import SecretStr

from litechecker import direct_check
from litechecker.collector.auth import AgentIdentity
from litechecker.config import AgentSettings, StandaloneSettings
from litechecker.direct_network import DirectNetworkUnavailable
from litechecker.direct_relay import DirectRelay
from litechecker.models import ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import ControlResult, TunnelResult, XrayUnavailable


@pytest.fixture
def settings(tmp_path):
    return StandaloneSettings(
        agent=AgentSettings(
            agent_id="test", agent_token="lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
            collector_url="https://collector.example.com", subscription_url="https://example.com/s",
            state_key="k" * 32, max_concurrency=1,
        ),
        identity=AgentIdentity("test", "City", "PC", 600), state_dir=tmp_path,
        telegram_bot_token=SecretStr("123456789:abcdefghijklmnopqrstuvwxyz12345"),
        telegram_chat_id="-1234",
    )


def target(target_id, address="1.1.1.1", *, kind="vpn"):
    return TargetConfig(
        target_id=target_id, config_fingerprint=target_id, label=target_id,
        address=address, address_kind="domain" if kind == "sni" else "ip",
        port=443, check_kind=kind,
        outbound={"protocol": "vless", "settings": {"vnext": [{
            "address": address, "port": 443,
            "users": [{"id": "11111111-1111-4111-8111-111111111111"}],
        }]}},
    )


class Writer:
    async def start_tls(self, *args, **kwargs):
        raise ssl.SSLCertVerificationError("fixture certificate rejection")

    def close(self):
        pass

    async def wait_closed(self):
        pass


class Network:
    async def resolve(self, host):
        return [host if host[0].isdigit() else "8.8.8.8"]

    async def connect(self, host, port):
        return None, Writer()


class FailedCanary:
    def __init__(self, process, **kwargs):
        self.process = process

    async def check(self, target):
        return TunnelResult(canary_ok=target.target_id == "up", error_code="canary-failed")


async def run_probes(settings, network, targets):
    # Keep the actual loopback relay and production probe pipeline; only remote
    # sockets and the external Xray process are replaced with controlled fixtures.
    async with DirectRelay(network) as relay:
        dependencies = direct_check.scoped_dependencies(settings, network, relay)
        return await dependencies.prober(targets, ControlResult(ok=True), 5)


@pytest.mark.asyncio
@pytest.mark.parametrize("code, status, stage, reason", [
    ("direct_dns_timeout", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-dns:direct_dns_timeout"),
    ("direct_dns_failed", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-dns:direct_dns_failed"),
    ("direct_dns_nxdomain", ResultStatus.DOWN, ProbeStage.DNS, "dns-failed"),
    ("private-token-looking-error", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-dns:direct_network_unavailable"),
])
async def test_dns_failures_never_become_xray_errors(settings, code, status, stage, reason):
    """Rethrowing the DNS RuntimeError must fail this test with XRAY/probe-error."""
    class DnsFailure(Network):
        async def resolve(self, host):
            raise DirectNetworkUnavailable(code)

    result, = await run_probes(settings, DnsFailure(), [target("dns", "edge.example")])
    assert (result.status, result.stage, result.error_code) == (status, stage, reason)


@pytest.mark.asyncio
@pytest.mark.parametrize("code, status, stage, reason", [
    ("interface_binding_failed", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-tcp:interface_binding_failed"),
    ("direct_connection_unreachable", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-tcp:direct_connection_unreachable"),
    ("direct_connection_timeout", ResultStatus.DOWN, ProbeStage.TCP, "tcp-timeout"),
    ("direct_connection_refused", ResultStatus.DOWN, ProbeStage.TCP, "tcp-refused"),
    ("direct_connection_reset", ResultStatus.DOWN, ProbeStage.TCP, "tcp-connect"),
    ("direct_connection_failed", ResultStatus.UNKNOWN, ProbeStage.POLICY, "direct-tcp:direct_connection_failed"),
])
async def test_bound_connect_failure_distinguishes_route_fault_from_remote_failure(
    settings, code, status, stage, reason,
):
    """A successful binding followed by remote refusal/timeout is still TCP evidence."""
    class TcpFailure(Network):
        async def connect(self, host, port):
            raise DirectNetworkUnavailable(code)

    result, = await run_probes(settings, TcpFailure(), [target("tcp")])
    assert (result.status, result.stage, result.error_code) == (status, stage, reason)


@pytest.mark.asyncio
async def test_local_fault_does_not_taint_other_tcp_tls_canary_or_success_results(settings, monkeypatch):
    """Replacing per-target evidence with any shared failure counter breaks the batch."""
    class MixedNetwork(Network):
        async def connect(self, host, port):
            if host == "9.9.9.9":
                raise DirectNetworkUnavailable("interface_binding_failed")
            if host == "8.8.4.4":
                raise DirectNetworkUnavailable("direct_connection_refused")
            return await super().connect(host, port)

    monkeypatch.setattr(direct_check, "XrayTunnel", FailedCanary)
    results = await run_probes(settings, MixedNetwork(), [
        target("local", "9.9.9.9"), target("refused", "8.8.4.4"),
        target("certificate", "cert.example", kind="sni"), target("canary"), target("up"),
    ])
    assert [(r.target_id, r.status, r.stage) for r in results] == [
        ("local", ResultStatus.UNKNOWN, ProbeStage.POLICY),
        ("refused", ResultStatus.DOWN, ProbeStage.TCP),
        ("certificate", ResultStatus.DOWN, ProbeStage.TLS_CERTIFICATE),
        ("canary", ResultStatus.DOWN, ProbeStage.VLESS_E2E),
        ("up", ResultStatus.UP, ProbeStage.E2E),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure, status, stage, reason", [
    (OSError(errno.ENETUNREACH, "fixture route failure"), ResultStatus.UNKNOWN,
     ProbeStage.POLICY, "direct-tls:direct_network_unavailable"),
    (PermissionError(errno.EPERM, "fixture policy failure"), ResultStatus.UNKNOWN,
     ProbeStage.POLICY, "direct-tls:direct_network_unavailable"),
    (RuntimeError("private-token-looking-error"), ResultStatus.UNKNOWN,
     ProbeStage.POLICY, "direct-tls:direct_network_unavailable"),
    (ssl.SSLError("fixture handshake rejection"), ResultStatus.DOWN,
     ProbeStage.TLS_HANDSHAKE, "tls-handshake"),
    (ssl.SSLCertVerificationError("fixture certificate rejection"), ResultStatus.DOWN,
     ProbeStage.TLS_CERTIFICATE, "tls-certificate"),
    (TimeoutError(), ResultStatus.DOWN, ProbeStage.TLS_HANDSHAKE, "tls-timeout"),
    (ConnectionResetError(), ResultStatus.DOWN, ProbeStage.TLS_HANDSHAKE, "tls-handshake"),
    (ConnectionAbortedError(), ResultStatus.DOWN, ProbeStage.TLS_HANDSHAKE, "tls-handshake"),
    (BrokenPipeError(), ResultStatus.DOWN, ProbeStage.TLS_HANDSHAKE, "tls-handshake"),
])
async def test_tls_local_failure_after_connect_does_not_claim_server_handshake_failure(
    settings, failure, status, stage, reason,
):
    """Binding success cannot turn a later local route/policy failure into TLS DOWN."""
    class TlsWriter(Writer):
        async def start_tls(self, *args, **kwargs):
            raise failure

    class TlsNetwork(Network):
        async def connect(self, host, port):
            return None, TlsWriter()

    result, = await run_probes(settings, TlsNetwork(), [target("sni", "edge.example", kind="sni")])
    assert (result.status, result.stage, result.error_code) == (status, stage, reason)


async def relay_request(outbound, *, host="1.1.1.1", port=443):
    """Make the real authenticated SOCKS request emitted by a simulated Xray dial."""
    endpoint = outbound["settings"]["servers"][0]
    auth = endpoint["users"][0]
    reader, writer = await asyncio.open_connection(endpoint["address"], endpoint["port"])
    try:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x02"
        username, password = auth["user"].encode(), auth["pass"].encode()
        writer.write(bytes((1, len(username))) + username + bytes((len(password),)) + password)
        await writer.drain()
        assert await reader.readexactly(2) == b"\x01\x00"
        hostname = host.encode()
        writer.write(bytes((5, 1, 0, 3, len(hostname))) + hostname + port.to_bytes(2, "big"))
        await writer.drain()
        return (await reader.readexactly(10))[1]
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("code, first_status", [
    ("interface_binding_failed", ResultStatus.UNKNOWN),
    ("direct_connection_reset", ResultStatus.DOWN),
])
async def test_real_relay_fault_isolated_between_variants_at_the_same_ip(
    settings, monkeypatch, code, first_status,
):
    """Sharing one relay's failure evidence or keying faults by IP taints variant two."""
    class NetworkWithRelayFailure(Network):
        calls = 0

        async def connect(self, host, port):
            self.calls += 1
            if self.calls == 2:  # First variant's relay, after its TCP diagnostic.
                raise DirectNetworkUnavailable(code)
            return await super().connect(host, port)

    class DialFailedVariant(FailedCanary):
        async def check(self, target):
            if target.target_id == "variant-one":
                assert await relay_request(self.process._dialer_proxy) != 0
            return await super().check(target)

    monkeypatch.setattr(direct_check, "XrayTunnel", DialFailedVariant)
    results = await run_probes(settings, NetworkWithRelayFailure(), [
        target("variant-one"), target("variant-two"),
    ])
    assert [r.status for r in results] == [first_status, ResultStatus.DOWN]
    assert results[1].stage is ProbeStage.VLESS_E2E
    assert results[1].error_code == "canary-failed"
    if first_status is ResultStatus.UNKNOWN:
        assert results[0].error_code == "direct-relay:interface_binding_failed"


@pytest.mark.asyncio
async def test_later_success_survives_earlier_local_fault(settings, monkeypatch):
    """A failed first DNS address must never erase a later positive E2E response."""
    class RecoveringNetwork(Network):
        async def resolve(self, host):
            return ["1.1.1.1", "8.8.8.8"]

        async def connect(self, host, port):
            if host == "1.1.1.1":
                raise DirectNetworkUnavailable("interface_binding_failed")
            return await super().connect(host, port)

    monkeypatch.setattr(direct_check, "XrayTunnel", FailedCanary)
    result, = await run_probes(settings, RecoveringNetwork(), [target("up")])
    assert (result.status, result.stage, result.error_code) == (ResultStatus.UP, ProbeStage.E2E, None)


@pytest.mark.asyncio
async def test_genuine_xray_failure_keeps_its_stage_after_a_local_fault(settings, monkeypatch):
    """Treating every exception as a scoped transport fault hides real Xray failure."""
    class RecoveringNetwork(Network):
        async def resolve(self, host):
            return ["1.1.1.1", "8.8.8.8"]

        async def connect(self, host, port):
            if host == "1.1.1.1":
                raise DirectNetworkUnavailable("interface_binding_failed")
            return await super().connect(host, port)

    class BrokenXray(FailedCanary):
        async def check(self, target):
            raise XrayUnavailable("xray-missing")

    monkeypatch.setattr(direct_check, "XrayTunnel", BrokenXray)
    result, = await run_probes(settings, RecoveringNetwork(), [target("broken")])
    assert (result.status, result.stage, result.error_code) == (ResultStatus.UNKNOWN, ProbeStage.XRAY, "xray-missing")

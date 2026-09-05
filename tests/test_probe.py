import asyncio
from dataclasses import dataclass

import pytest

from litechecker.models import ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import (
    Canary,
    ControlResult,
    DiagnosticResult,
    TunnelResult,
    check_control,
    probe_all,
    probe_target,
)


@pytest.fixture
def target() -> TargetConfig:
    return TargetConfig(
        target_id="target-1",
        config_fingerprint="local-only-fingerprint",
        label="Tbilisi edge",
        address="vpn.example",
        port=443,
        address_kind="domain",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "vpn.example",
                        "port": 443,
                        "users": [{"id": "11111111-1111-4111-8111-111111111111"}],
                    }
                ]
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {"serverName": "example.com"},
            },
        },
    )


class FakeResolver:
    def __init__(self, addresses: list[str] | None = None, error: str | None = None):
        self.addresses = addresses or []
        self.error = error

    async def resolve(self, target: TargetConfig) -> list[str]:
        if self.error:
            raise OSError(self.error)
        return self.addresses


@dataclass
class FakeTcp:
    ok: bool
    latency_ms: int | None = None
    error: str | None = None
    accepted_address: str | None = None

    def __post_init__(self):
        self.calls: list[list[str]] = []

    async def check(self, target: TargetConfig, addresses: list[str]) -> DiagnosticResult:
        self.calls.append(list(addresses))
        ok = self.ok and (
            self.accepted_address is None or addresses == [self.accepted_address]
        )
        return DiagnosticResult(
            ok=ok,
            latency_ms=self.latency_ms,
            error_code=self.error,
        )


@dataclass
class FakeTunnel:
    canary_ok: bool
    latency_ms: int | None = None
    error: str | None = None

    async def check(self, target: TargetConfig) -> TunnelResult:
        return TunnelResult(
            canary_ok=self.canary_ok,
            latency_ms=self.latency_ms,
            error_code=self.error,
        )


@pytest.mark.asyncio
async def test_tcp_success_without_tunnel_canary_is_down_not_up(target):
    """Removing the tunnel-success requirement would let TCP-only reachability report UP."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True, latency_ms=12),
        tunnel=FakeTunnel(canary_ok=False, error="proxy-connect"),
    )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.VLESS_E2E
    assert result.latency_ms == 12
    assert result.error_code == "proxy-connect"


@pytest.mark.asyncio
async def test_boundary_error_text_never_enters_probe_result(target):
    """Passing arbitrary dependency errors through would leak URLs or credentials in reports."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=FakeTunnel(canary_ok=False, error="private-token-like-code"),
    )

    assert result.error_code == "canary-failed"


@pytest.mark.asyncio
async def test_external_control_error_slug_maps_to_fixed_code(target):
    """Allowing plausible-looking slugs would still let injected secrets enter reports."""
    result = await probe_target(
        target,
        control=ControlResult(ok=False, error_code="private-token-like-code"),
    )

    assert result.error_code == "control-failed"


@pytest.mark.asyncio
async def test_external_tcp_error_slug_maps_to_fixed_code(target):
    """TCP dependency text must map through the stage-specific closed code set."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=False, error="private-token-like-code"),
    )

    assert result.error_code == "tcp-failed"


@pytest.mark.asyncio
async def test_external_xray_error_slug_maps_to_fixed_code(target):
    """Xray exceptions may carry only explicitly recognized process codes."""

    class BrokenTunnel:
        async def check(self, target: TargetConfig) -> TunnelResult:
            from litechecker.probe import XrayUnavailable

            raise XrayUnavailable("11111111-1111-4111-8111-111111111111")

    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=BrokenTunnel(),
    )

    assert result.error_code == "xray-error"


@pytest.mark.asyncio
async def test_agent_control_failure_makes_target_unknown(target):
    """Probing through a failed local network control would fabricate a target outage."""
    result = await probe_target(target, control=ControlResult(ok=False))

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.AGENT_NETWORK


@pytest.mark.asyncio
async def test_only_tunnel_canary_success_marks_target_up(target):
    """Dropping the positive tunneled canary branch would hide a usable target."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True, latency_ms=12),
        tunnel=FakeTunnel(canary_ok=True, latency_ms=41),
    )

    assert result.status is ResultStatus.UP
    assert result.stage is ProbeStage.E2E
    assert result.latency_ms == 41
    assert result.resolved_ips == ["1.1.1.1"]


@pytest.mark.asyncio
async def test_forbidden_dns_answer_stops_before_tcp(target):
    """Skipping answer validation would allow Xray probes into private networks."""
    tcp = FakeTcp(ok=True)
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["127.0.0.1"]),
        tcp=tcp,
        tunnel=FakeTunnel(canary_ok=True),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.POLICY
    assert result.error_code == "forbidden-address"


@pytest.mark.asyncio
async def test_resolution_failure_is_down_when_control_works(target):
    """Treating a target DNS failure as agent uncertainty would lose useful evidence."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(error="resolver leaked detail"),
    )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.DNS
    assert result.error_code == "dns-failed"


@pytest.mark.asyncio
async def test_malformed_resolver_data_is_unknown_policy_not_down(target):
    """Malformed resolver output is a local evidence-policy refusal, not target downtime."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["not-an-ip"]),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.POLICY
    assert result.error_code == "dns-invalid"


@pytest.mark.asyncio
async def test_probe_attempts_answer_seventeen_but_caps_report_evidence(target):
    """The 16-item report cap must not silently become a connectivity attempt cap."""
    addresses = [f"1.1.1.{index}" for index in range(1, 18)]
    tcp = FakeTcp(ok=True, accepted_address=addresses[-1])
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(addresses),
        tcp=tcp,
        tunnel=FakeTunnel(canary_ok=True, latency_ms=8),
    )

    assert result.status is ResultStatus.UP
    assert tcp.calls[-1] == [addresses[-1]]
    assert len(tcp.calls) == 17
    assert result.resolved_ips == addresses[:16]


@pytest.mark.asyncio
async def test_resolver_answer_overflow_is_unknown_policy_before_network(target):
    """An answer set beyond the defensive maximum cannot be classified as target DOWN."""
    addresses = [f"1.1.{index // 250}.{index % 250 + 1}" for index in range(65)]
    tcp = FakeTcp(ok=True)
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(addresses),
        tcp=tcp,
        tunnel=FakeTunnel(canary_ok=True),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.POLICY
    assert result.error_code == "dns-answer-limit"
    assert tcp.calls == []


@pytest.mark.asyncio
async def test_each_xray_attempt_is_bound_to_the_validated_ip_and_keeps_reality_sni(target):
    """Dialing the original hostname after validation permits a DNS-rebind SSRF."""
    attempted: list[tuple[str, str]] = []

    class BoundTunnel:
        async def check(self, selected: TargetConfig) -> TunnelResult:
            outbound = selected.outbound
            address = outbound["settings"]["vnext"][0]["address"]
            server_name = outbound["streamSettings"]["realitySettings"]["serverName"]
            attempted.append((address, server_name))
            return TunnelResult(canary_ok=address == "1.1.1.2")

    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1", "1.1.1.2"]),
        tcp=FakeTcp(ok=True),
        tunnel=BoundTunnel(),
    )

    assert result.status is ResultStatus.UP
    assert attempted == [
        ("1.1.1.1", "example.com"),
        ("1.1.1.2", "example.com"),
    ]
    assert target.outbound["settings"]["vnext"][0]["address"] == "vpn.example"


@pytest.mark.asyncio
async def test_tcp_failure_is_down_when_control_works(target):
    """Continuing past failed direct TCP diagnostics would misclassify the evidence stage."""
    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=False, error="tcp-refused"),
    )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.TCP
    assert result.error_code == "tcp-refused"


@pytest.mark.asyncio
async def test_default_dns_and_tcp_diagnostics_work_against_loopback(target):
    """Replacing the real diagnostics with optimistic defaults would let dead targets reach E2E."""
    server = await asyncio.start_server(
        lambda reader, writer: writer.close(),
        "127.0.0.1",
        0,
    )
    port = server.sockets[0].getsockname()[1]
    loopback_target = target.model_copy(
        update={"address": "localhost", "port": port, "address_kind": "domain"}
    )
    try:
        result = await probe_target(
            loopback_target,
            control=ControlResult(ok=True),
            tunnel=FakeTunnel(canary_ok=True, latency_ms=7),
            allow_private_targets=True,
            tcp_timeout=0.5,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.status is ResultStatus.UP
    assert result.stage is ProbeStage.E2E
    assert any(address in {"127.0.0.1", "::1"} for address in result.resolved_ips)


@pytest.mark.asyncio
async def test_xray_startup_failure_is_unknown(target):
    """Calling a local Xray failure DOWN would falsely blame the selected target."""

    class BrokenTunnel:
        async def check(self, target: TargetConfig) -> TunnelResult:
            from litechecker.probe import XrayUnavailable

            raise XrayUnavailable("xray-exit")

    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=BrokenTunnel(),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.XRAY
    assert result.error_code == "xray-exit"


@pytest.mark.asyncio
async def test_control_accepts_expected_response_from_either_canary():
    """Requiring both independent controls would report agent outages during one-provider failure."""
    requested: list[str] = []

    async def requester(canary: Canary, timeout: float) -> int:
        requested.append(canary.url)
        return 503 if "first" in canary.url else 204

    result = await check_control(
        canaries=(
            Canary("https://first.example/check", 204),
            Canary("https://second.example/check", 204),
        ),
        requester=requester,
        timeout=0.5,
    )

    assert result.ok is True
    assert requested == ["https://first.example/check", "https://second.example/check"]


@pytest.mark.asyncio
async def test_probe_all_marks_work_left_at_global_deadline_unknown(target):
    """Waiting past the run deadline would block reporting and erase explicit uncertainty."""

    class SlowTunnel:
        async def check(self, target: TargetConfig) -> TunnelResult:
            await asyncio.sleep(10)
            return TunnelResult(canary_ok=True)

    targets = [target, target.model_copy(update={"target_id": "target-2"})]
    results = await probe_all(
        targets,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=SlowTunnel(),
        max_concurrency=1,
        deadline_seconds=0.01,
    )

    assert [result.target_id for result in results] == ["target-1", "target-2"]
    assert {result.status for result in results} == {ResultStatus.UNKNOWN}
    assert {result.stage for result in results} == {ProbeStage.DEADLINE}


@pytest.mark.asyncio
async def test_probe_all_accepts_an_empty_snapshot():
    """Calling asyncio.wait with no targets would crash an otherwise valid no-work run."""
    results = await probe_all(
        [],
        control=ControlResult(ok=True),
        max_concurrency=1,
        deadline_seconds=1,
    )

    assert results == []


@pytest.mark.asyncio
async def test_probe_all_never_exceeds_configured_concurrency(target):
    """Dropping the semaphore would let a large subscription create an Xray process spike."""

    class CountingTunnel:
        def __init__(self):
            self.active = 0
            self.maximum = 0

        async def check(self, target: TargetConfig) -> TunnelResult:
            self.active += 1
            self.maximum = max(self.maximum, self.active)
            await asyncio.sleep(0.02)
            self.active -= 1
            return TunnelResult(canary_ok=True)

    tunnel = CountingTunnel()
    targets = [
        target.model_copy(update={"target_id": f"target-{index}"})
        for index in range(4)
    ]
    results = await probe_all(
        targets,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=tunnel,
        max_concurrency=2,
        deadline_seconds=1,
    )

    assert tunnel.maximum == 2
    assert {result.status for result in results} == {ResultStatus.UP}


@pytest.mark.asyncio
async def test_probe_all_external_cancellation_reaps_every_spawned_probe(target):
    """Cancelling the batch owner must not orphan target tasks or Xray contexts."""

    class CleanupTunnel:
        def __init__(self):
            self.active = 0
            self.started = asyncio.Event()
            self.cleaned = 0

        async def check(self, selected: TargetConfig) -> TunnelResult:
            del selected
            self.active += 1
            if self.active == 2:
                self.started.set()
            try:
                await asyncio.sleep(10)
                return TunnelResult(canary_ok=True)
            finally:
                self.active -= 1
                self.cleaned += 1

    tunnel = CleanupTunnel()
    targets = [target, target.model_copy(update={"target_id": "target-2"})]
    batch = asyncio.create_task(
        probe_all(
            targets,
            control=ControlResult(ok=True),
            resolver=FakeResolver(["1.1.1.1"]),
            tcp=FakeTcp(ok=True),
            tunnel=tunnel,
            max_concurrency=2,
            deadline_seconds=100,
        )
    )
    await asyncio.wait_for(tunnel.started.wait(), timeout=1)

    batch.cancel()
    with pytest.raises(asyncio.CancelledError):
        await batch

    assert tunnel.active == 0
    assert tunnel.cleaned == 2


@pytest.mark.asyncio
async def test_probe_all_preserves_completed_evidence_and_deadlines_only_unfinished(target):
    """A batch deadline must not erase a target that completed with E2E evidence."""

    class MixedTunnel:
        def __init__(self):
            self.active = 0

        async def check(self, selected: TargetConfig) -> TunnelResult:
            self.active += 1
            try:
                if selected.target_id == "target-1":
                    return TunnelResult(canary_ok=True, latency_ms=4)
                await asyncio.sleep(10)
                return TunnelResult(canary_ok=True)
            finally:
                self.active -= 1

    tunnel = MixedTunnel()
    targets = [target, target.model_copy(update={"target_id": "target-2"})]

    results = await probe_all(
        targets,
        control=ControlResult(ok=True),
        resolver=FakeResolver(["1.1.1.1"]),
        tcp=FakeTcp(ok=True),
        tunnel=tunnel,
        max_concurrency=2,
        deadline_seconds=0.02,
    )

    assert [(result.status, result.stage) for result in results] == [
        (ResultStatus.UP, ProbeStage.E2E),
        (ResultStatus.UNKNOWN, ProbeStage.DEADLINE),
    ]
    assert tunnel.active == 0

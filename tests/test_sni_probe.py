import asyncio
import contextlib
import ssl

import pytest
import trustme

from litechecker.models import ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import (
    Canary,
    ControlResult,
    DiagnosticResult,
    XrayTunnel,
    _TlsDiagnostic,
    probe_all,
    probe_target,
)


@pytest.fixture
def sni_target():
    return TargetConfig(
        target_id="sni-test",
        config_fingerprint="sni-fingerprint",
        label="SNI domain",
        address="sni.example.invalid",
        address_kind="domain",
        port=443,
        outbound={},
        check_kind="sni",
    )


class Resolver:
    def __init__(self, addresses):
        self.addresses = addresses

    async def resolve(self, target):
        return self.addresses


class NoTunnel:
    def __init__(self):
        self.calls = 0

    async def check(self, target):
        self.calls += 1
        raise AssertionError("SNI checks must not use Xray")


class Tcp:
    def __init__(self, ok=True):
        self.ok = ok

    async def check(self, target, addresses):
        return DiagnosticResult(ok=self.ok, error_code=None if self.ok else "tcp-timeout")


@contextlib.asynccontextmanager
async def origin(*, hostname="sni.example.invalid", trusted=True, tls=True):
    authority = trustme.CA()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    authority.issue_cert(hostname).configure_cert(server_context)
    client_context = ssl.create_default_context()
    if trusted:
        authority.configure_trust(client_context)
    names = []
    server_context.set_servername_callback(lambda socket, name, context: names.append(name))
    received = []
    tasks = set()

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            # No application response is needed; even an origin returning 403 is
            # reachable if its authenticated TLS handshake succeeds.
            received.append(await reader.read())
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(
        serve, "127.0.0.1", 0, ssl=server_context if tls else None
    )
    try:
        yield server.sockets[0].getsockname()[1], client_context, names, received
    finally:
        server.close()
        await server.wait_closed()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)


@pytest.mark.asyncio
async def test_sni_uses_validated_ip_original_server_name_and_no_http_or_xray(sni_target):
    async with origin() as (port, context, names, received):
        tunnel = NoTunnel()
        result = await probe_target(
            sni_target.model_copy(update={"port": port}),
            control=ControlResult(ok=True),
            resolver=Resolver(["127.0.0.1"]),
            tls=_TlsDiagnostic(1, context=context),
            tunnel=tunnel,
            allow_private_targets=True,
        )
        await asyncio.sleep(0)

    assert result.status is ResultStatus.UP
    assert result.stage is ProbeStage.TLS
    assert result.check_kind == "sni"
    assert result.resolved_ips == ["127.0.0.1"]
    assert result.latency_ms is not None
    assert names == ["sni.example.invalid"]
    assert received == [b""]
    assert tunnel.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hostname,trusted", [("other.example.invalid", True), ("sni.example.invalid", False)]
)
async def test_sni_rejects_wrong_hostname_and_untrusted_certificate(sni_target, hostname, trusted):
    async with origin(hostname=hostname, trusted=trusted) as (port, context, _, __):
        result = await probe_target(
            sni_target.model_copy(update={"port": port}),
            control=ControlResult(ok=True),
            resolver=Resolver(["127.0.0.1"]),
            tls=_TlsDiagnostic(1, context=context),
            allow_private_targets=True,
        )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.TLS_CERTIFICATE
    assert result.error_code == "tls-certificate"


@pytest.mark.asyncio
async def test_sni_stalled_tls_is_bounded_and_closes_connection(sni_target):
    async with origin(tls=False) as (port, context, _, received):
        result = await asyncio.wait_for(
            probe_target(
                sni_target.model_copy(update={"port": port}),
                control=ControlResult(ok=True),
                resolver=Resolver(["127.0.0.1"]),
                tls=_TlsDiagnostic(0.05, context=context),
                allow_private_targets=True,
            ),
            timeout=1,
        )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.TLS_HANDSHAKE
    assert result.error_code == "tls-timeout"
    assert len(received) == 2  # TCP diagnostic and cancelled TLS connection both closed.


@pytest.mark.asyncio
async def test_sni_run_deadline_cancels_tls_without_leaking_connection(sni_target):
    async with origin(tls=False) as (port, context, _, received):
        results = await probe_all(
            [sni_target.model_copy(update={"port": port})],
            control=ControlResult(ok=True),
            resolver=Resolver(["127.0.0.1"]),
            tls=_TlsDiagnostic(10, context=context),
            allow_private_targets=True,
            max_concurrency=1,
            deadline_seconds=0.05,
        )

    assert results[0].status is ResultStatus.UNKNOWN
    assert results[0].stage is ProbeStage.DEADLINE
    assert results[0].check_kind == "sni"
    assert len(received) == 2


@pytest.mark.asyncio
async def test_sni_tries_alternative_validated_addresses(sni_target):
    attempted = []

    class Tls:
        async def check(self, target, address):
            attempted.append(address)
            return DiagnosticResult(
                ok=address == "1.1.1.2", latency_ms=11, error_code="tls-certificate"
            )

    result = await probe_target(
        sni_target,
        control=ControlResult(ok=True),
        resolver=Resolver(["1.1.1.1", "1.1.1.2"]),
        tcp=Tcp(),
        tls=Tls(),
    )

    assert attempted == ["1.1.1.1", "1.1.1.2"]
    assert result.status is ResultStatus.UP
    assert result.stage is ProbeStage.TLS
    assert result.latency_ms == 11


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "control,addresses,stage",
    [(False, ["1.1.1.1"], ProbeStage.AGENT_NETWORK), (True, ["127.0.0.1"], ProbeStage.POLICY)],
)
async def test_sni_no_network_probe_without_control_or_public_ip(sni_target, control, addresses, stage):
    class MustNotProbe:
        async def check(self, *args):
            raise AssertionError("Network probe not permitted")

    result = await probe_target(
        sni_target,
        control=ControlResult(ok=control),
        resolver=Resolver(addresses),
        tcp=MustNotProbe(),
        tls=MustNotProbe(),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is stage
    assert result.check_kind == "sni"


@pytest.mark.asyncio
async def test_sni_closed_tcp_does_not_claim_tls_failure(sni_target):
    result = await probe_target(
        sni_target,
        control=ControlResult(ok=True),
        resolver=Resolver(["1.1.1.1"]),
        tcp=Tcp(ok=False),
    )

    assert result.status is ResultStatus.DOWN
    assert result.stage is ProbeStage.TCP
    assert result.error_code == "tcp-timeout"


@pytest.mark.asyncio
async def test_sni_local_exception_is_unknown_without_leaking_error(sni_target):
    class BrokenTls:
        async def check(self, target, address):
            raise ValueError("secret-error-value")

    result = await probe_target(
        sni_target,
        control=ControlResult(ok=True),
        resolver=Resolver(["1.1.1.1"]),
        tcp=Tcp(),
        tls=BrokenTls(),
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.POLICY
    assert result.error_code == "tls-local-error"


def test_sni_diagnostic_refuses_disabled_certificate_verification():
    with pytest.raises(ValueError, match="certificate and hostname"):
        _TlsDiagnostic(1, context=ssl._create_unverified_context())


@pytest.mark.asyncio
async def test_hanging_first_canary_leaves_budget_for_second(sni_target):
    class Proxy(str):
        async def ensure_healthy(self):
            pass

    class Process:
        @contextlib.asynccontextmanager
        async def open(self, target):
            yield Proxy("socks5://127.0.0.1:1")

    attempted = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url):
            attempted.append(url)
            if len(attempted) == 1:
                await asyncio.sleep(10)
            return type("Response", (), {"status_code": 204})()

    tunnel = XrayTunnel(
        Process(),
        canaries=[Canary("https://first.invalid"), Canary("https://second.invalid")],
        timeout=0.1,
        client_factory=Client,
    )
    result = await asyncio.wait_for(tunnel.check(sni_target), timeout=0.5)

    assert result.canary_ok
    assert attempted == ["https://first.invalid", "https://second.invalid"]

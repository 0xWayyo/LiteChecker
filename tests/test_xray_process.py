import asyncio
import copy
import json
import os
import shutil
import ssl
import subprocess
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest
import trustme

import litechecker.probe as probe_module
from litechecker.models import ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import (
    Canary,
    ControlResult,
    DiagnosticResult,
    XrayProcess,
    XrayTunnel,
    XrayUnavailable,
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
            "tag": "subscription-route",
            "settings": {
                "vnext": [
                    {
                        "address": "vpn.example",
                        "port": 443,
                        "users": [
                            {
                                "id": "11111111-1111-4111-8111-111111111111",
                                "encryption": "none",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {"serverName": "example.com", "publicKey": "private"},
            },
        },
    )


@dataclass
class FakeXray:
    executable: Path
    captured_config: Path
    captured_args: Path
    pid_file: Path
    connects_file: Path


@pytest.fixture(scope="session")
def fake_xray_executable(tmp_path_factory: pytest.TempPathFactory) -> Path:
    source = Path(__file__).parent / "fakes" / "fake_xray.py"
    executable = tmp_path_factory.mktemp("fake-xray") / "fake-xray"
    shutil.copyfile(source, executable)
    executable.chmod(0o700)
    # macOS cold execution of a new script can consume a whole startup deadline.
    # Prepare one executable before timing real, independently owned child runs.
    ready = subprocess.run(
        [str(executable), "--fixture-ready"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert ready.stdout == "fake-xray-ready\n"
    return executable


@pytest.fixture
def fake_xray(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_xray_executable: Path
) -> FakeXray:
    executable = fake_xray_executable
    captured_config = tmp_path / "config.json"
    captured_args = tmp_path / "args.json"
    pid_file = tmp_path / "xray.pid"
    connects_file = tmp_path / "connects"
    monkeypatch.setenv("FAKE_XRAY_CAPTURE", str(captured_config))
    monkeypatch.setenv("FAKE_XRAY_ARGS", str(captured_args))
    monkeypatch.setenv("FAKE_XRAY_PID", str(pid_file))
    monkeypatch.setenv("FAKE_XRAY_CONNECTS", str(connects_file))
    monkeypatch.delenv("FAKE_XRAY_MODE", raising=False)
    monkeypatch.delenv("FAKE_XRAY_EXIT_DELAY", raising=False)
    return FakeXray(executable, captured_config, captured_args, pid_file, connects_file)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.asyncio
async def test_cancellation_during_natural_xray_shutdown_still_kills_and_reaps(target, fake_xray, monkeypatch):
    """A network watcher can cancel a successful probe while it is already closing Xray."""
    monkeypatch.setenv("FAKE_XRAY_MODE", "ignore-term")
    stopping = asyncio.Event()
    owned = []
    original = probe_module._stop_process
    async def traced(process, timeout):
        owned.append(process)
        stopping.set()
        await original(process, timeout)
    monkeypatch.setattr(probe_module, "_stop_process", traced)
    async def operation():
        async with XrayProcess(fake_xray.executable, startup_timeout=1, shutdown_timeout=0.05).open(target):
            pass
    task = asyncio.create_task(operation())
    try:
        async with asyncio.timeout(2):
            await stopping.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert owned[0].returncode is not None, "natural finalizer was interrupted before kill/reap"
        assert not _process_exists(owned[0].pid)
    finally:
        # Only the child created by this fixture, never a PID from user state.
        for process in owned:
            if process.returncode is None:
                process.kill()
                await process.wait()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_xray_startup_deadline_rejects_a_child_without_listener(
    target, fake_xray, monkeypatch
):
    """A live child that never listens must not outlive its startup allowance."""
    monkeypatch.setenv("FAKE_XRAY_MODE", "no-listen")

    with pytest.raises(XrayUnavailable) as raised:
        async with asyncio.timeout(1):
            async with XrayProcess(
                fake_xray.executable,
                startup_timeout=0.2,
                shutdown_timeout=0.1,
            ).open(target):
                pytest.fail("a child without a listener cannot open a tunnel")

    assert raised.value.error_code == "xray-startup-timeout"


@pytest.mark.asyncio
async def test_xray_config_has_loopback_socks_and_only_selected_outbound(target, fake_xray):
    """Copying subscription routing or extra outbounds would escape the selected tunnel."""
    original = copy.deepcopy(target.outbound)

    async with XrayProcess(fake_xray.executable, startup_timeout=1).open(target) as proxy_url:
        parsed_proxy = urlsplit(proxy_url)
        assert parsed_proxy.scheme == "socks5"
        assert parsed_proxy.hostname == "127.0.0.1"
        assert parsed_proxy.username
        assert parsed_proxy.password

    raw_config = fake_xray.captured_config.read_bytes()
    config = json.loads(raw_config)
    assert config["inbounds"][0]["listen"] == "127.0.0.1"
    assert config["inbounds"][0]["protocol"] == "socks"
    assert config["inbounds"][0]["settings"]["auth"] == "password"
    assert config["inbounds"][0]["settings"]["accounts"] == [
        {"user": parsed_proxy.username, "pass": parsed_proxy.password}
    ]
    assert len(config["outbounds"]) == 1
    assert config["outbounds"][0]["settings"]["vnext"][0]["address"] == target.address
    expected_outbound = copy.deepcopy(original)
    expected_outbound["tag"] = config["outbounds"][0]["tag"]
    assert config["outbounds"][0] == expected_outbound
    assert config["outbounds"][0]["tag"].startswith("lc-out-")
    assert set(config) == {"log", "inbounds", "outbounds", "routing"}
    assert config["log"] == {"loglevel": "none"}
    assert config["routing"]["rules"] == [
        {
            "type": "field",
            "inboundTag": [config["inbounds"][0]["tag"]],
            "outboundTag": config["outbounds"][0]["tag"],
        }
    ]
    assert b": " not in raw_config
    assert json.loads(fake_xray.captured_args.read_text()) == [
        "run",
        "-config",
        "stdin:",
    ]
    assert target.outbound == original
    assert not _process_exists(int(fake_xray.pid_file.read_text()))


@pytest.fixture
def direct_dialer():
    return {
        "tag": "test-helper",
        "protocol": "socks",
        "settings": {
            "servers": [{
                "address": "127.0.0.1", "port": 19001,
                "users": [{"user": "ephemeral-user", "pass": "ephemeral-pass"}],
            }]
        },
    }


@pytest.mark.asyncio
async def test_direct_xray_uses_helper_for_outer_transport_and_preserves_reality(
    target, fake_xray, direct_dialer
):
    """Using proxySettings instead of dialerProxy would chain VLESS at the wrong layer."""
    original = copy.deepcopy(target.outbound)
    helper_original = copy.deepcopy(direct_dialer)
    async with XrayProcess(
        fake_xray.executable, startup_timeout=1, dialer_proxy=direct_dialer
    ).open(target):
        pass
    config = json.loads(fake_xray.captured_config.read_bytes())
    assert len(config["outbounds"]) == 2
    selected, helper = config["outbounds"]
    assert selected["protocol"] == "vless"
    assert selected["settings"] == original["settings"]
    assert selected["streamSettings"]["realitySettings"] == original["streamSettings"]["realitySettings"]
    assert selected["streamSettings"]["security"] == "reality"
    assert selected["streamSettings"]["network"] == "tcp"
    assert selected["streamSettings"]["sockopt"]["dialerProxy"] == helper["tag"]
    assert helper["tag"] not in {selected["tag"], config["inbounds"][0]["tag"]}
    assert helper["protocol"] == "socks"
    assert helper["settings"] == helper_original["settings"]
    assert config["routing"]["rules"] == [{
        "type": "field", "inboundTag": [config["inbounds"][0]["tag"]],
        "outboundTag": selected["tag"],
    }]
    assert target.outbound == original
    assert direct_dialer == helper_original


def test_direct_xray_removes_competing_subscription_chains(target, direct_dialer):
    """Leaving source proxySettings or mux active can bypass the required transport dialer."""
    outbound = copy.deepcopy(target.outbound)
    outbound["proxySettings"] = {"tag": "subscription-proxy", "transportLayer": True}
    outbound["mux"] = {"enabled": True}
    outbound["streamSettings"]["sockopt"] = {
        "dialerProxy": "subscription-dialer", "tcpKeepAliveInterval": 30,
    }
    modified = target.model_copy(update={"outbound": outbound})
    config = json.loads(probe_module._minimal_xray_config(
        modified, 19000, "inbound", "outbound", "user", "pass",
        dialer_proxy=direct_dialer,
    ))
    selected, helper = config["outbounds"]
    assert "proxySettings" not in selected
    assert not selected.get("mux", {}).get("enabled", False)
    assert selected["streamSettings"]["sockopt"] == {
        "dialerProxy": helper["tag"], "tcpKeepAliveInterval": 30,
    }
    assert modified.outbound["proxySettings"]["tag"] == "subscription-proxy"
    assert modified.outbound["mux"]["enabled"] is True
    assert modified.outbound["streamSettings"]["sockopt"]["dialerProxy"] == "subscription-dialer"


@pytest.mark.parametrize("kind", ["non-socks", "non-loopback", "anonymous", "extra-server", "chain", "stream"])
def test_direct_xray_rejects_helpers_that_could_escape_local_authenticated_relay(
    target, direct_dialer, kind
):
    """Accepting an alternate or unauthenticated helper would escape the per-run socket."""
    if kind == "non-socks":
        direct_dialer["protocol"] = "freedom"
    elif kind == "non-loopback":
        direct_dialer["settings"]["servers"][0]["address"] = "1.1.1.1"
    elif kind == "anonymous":
        direct_dialer["settings"]["servers"][0].pop("users")
    elif kind == "extra-server":
        direct_dialer["settings"]["servers"].append({"address": "1.1.1.1", "port": 1080})
    elif kind == "chain":
        direct_dialer["proxySettings"] = {"tag": "unexpected-chain"}
    elif kind == "stream":
        direct_dialer["streamSettings"] = {"sockopt": {"dialerProxy": "unexpected-chain"}}
    with pytest.raises(ValueError):
        probe_module._minimal_xray_config(
            target, 19000, "inbound", "outbound", "user", "pass",
            dialer_proxy=direct_dialer,
        )


@pytest.mark.asyncio
async def test_xray_early_exit_is_sanitized_and_reaped(fake_xray, monkeypatch):
    """Returning process stderr or leaving the child alive would leak secrets and resources."""
    monkeypatch.setenv("FAKE_XRAY_MODE", "exit")
    target = TargetConfig(
        target_id="target-1",
        config_fingerprint="fingerprint",
        label="edge",
        address="1.1.1.1",
        port=443,
        address_kind="ip",
        outbound={"protocol": "vless", "settings": {"vnext": []}},
    )

    with pytest.raises(XrayUnavailable) as raised:
        async with XrayProcess(fake_xray.executable, startup_timeout=1).open(target):
            pytest.fail("an exited process cannot expose a proxy")

    assert raised.value.error_code == "xray-exit"
    assert "private stderr" not in str(raised.value)
    assert not _process_exists(int(fake_xray.pid_file.read_text()))


@pytest.mark.asyncio
async def test_xray_cleanup_kills_a_child_that_ignores_terminate(
    target,
    fake_xray,
    monkeypatch,
):
    """Omitting the bounded kill fallback would leak a child that ignores SIGTERM."""
    monkeypatch.setenv("FAKE_XRAY_MODE", "ignore-term")

    async with XrayProcess(
        fake_xray.executable,
        startup_timeout=1,
        shutdown_timeout=0.02,
    ).open(target):
        pass

    assert not _process_exists(int(fake_xray.pid_file.read_text()))


@pytest.mark.asyncio
async def test_xray_tunnel_uses_socks_without_environment_and_accepts_either_canary(
    target, fake_xray
):
    """Ignoring the proxy or requiring every canary would make the E2E verdict dishonest."""
    init_calls: list[dict] = []
    requested: list[str] = []

    class Response:
        def __init__(self, status_code: int):
            self.status_code = status_code

    class Client:
        def __init__(self, **kwargs):
            init_calls.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, url: str):
            requested.append(url)
            return Response(503 if "first" in url else 204)

    tunnel = XrayTunnel(
        XrayProcess(fake_xray.executable, startup_timeout=1),
        canaries=(
            Canary("https://first.example/check", 204),
            Canary("https://second.example/check", 204),
        ),
        timeout=0.5,
        client_factory=Client,
    )

    result = await tunnel.check(target)

    assert result.canary_ok is True
    assert requested == ["https://first.example/check", "https://second.example/check"]
    assert len(init_calls) == 1
    assert urlsplit(init_calls[0]["proxy"]).hostname == "127.0.0.1"
    assert urlsplit(init_calls[0]["proxy"]).username
    assert init_calls[0]["trust_env"] is False
    assert init_calls[0]["timeout"] == 0.5


@pytest.mark.asyncio
async def test_xray_tunnel_bounds_both_canary_attempts_as_one_probe(target):
    """Applying the timeout per request would let two failed canaries exceed the probe budget."""
    requested: list[str] = []

    class ReadySession(str):
        async def ensure_healthy(self):
            pass

    class ReadyProcess:
        @asynccontextmanager
        async def open(self, target):
            # Startup, ownership checks and cleanup have separate process tests;
            # this test's clock measures only the shared canary budget.
            yield ReadySession("socks5://fixture:fixture@127.0.0.1:1080")

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, url: str):
            requested.append(url)
            if "first" in url:
                await asyncio.sleep(0.04)
                raise httpx.ReadTimeout("first canary stalled")
            # Each request fits a fresh 0.1 s allowance, but their combined
            # 0.12 s duration must not produce a successful second response.
            await asyncio.sleep(0.08)
            return SimpleNamespace(status_code=204)

    tunnel = XrayTunnel(
        ReadyProcess(),
        canaries=(
            Canary("https://first.example/check"),
            Canary("https://second.example/check"),
        ),
        timeout=0.1,
        client_factory=Client,
    )

    result = await asyncio.wait_for(tunnel.check(target), timeout=0.5)

    assert result.canary_ok is False
    assert result.error_code == "canary-timeout"
    assert requested == ["https://first.example/check", "https://second.example/check"]


@pytest.mark.asyncio
async def test_child_exit_after_listener_is_unknown_not_target_down(
    target,
    fake_xray,
    monkeypatch,
):
    """Losing Xray during a canary must never become target-specific DOWN evidence."""
    child = None
    spawn = asyncio.create_subprocess_exec

    async def capture_child(*args, **kwargs):
        nonlocal child
        child = await spawn(*args, **kwargs)
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_child)

    class Resolver:
        async def resolve(self, target):
            return ["1.1.1.1"]

    class Tcp:
        async def check(self, target, addresses):
            return DiagnosticResult(ok=True)

    class Response:
        status_code = 204

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, url):
            # A canary starts only after the listener is owned and healthy.
            # Observe the real child exit before returning the canary response;
            # independent parent/child sleeps cannot establish this ordering.
            assert child is not None
            assert child.returncode is None
            child.terminate()
            await child.wait()
            return Response()

    tunnel = XrayTunnel(
        XrayProcess(fake_xray.executable, startup_timeout=1),
        canaries=(Canary("https://canary.invalid/check"),),
        timeout=0.4,
        client_factory=Client,
    )

    result = await probe_target(
        target,
        control=ControlResult(ok=True),
        resolver=Resolver(),
        tcp=Tcp(),
        tunnel=tunnel,
    )

    assert result.status is ResultStatus.UNKNOWN
    assert result.stage is ProbeStage.XRAY
    assert result.error_code == "xray-exit"


@pytest.mark.asyncio
async def test_foreign_listener_cannot_win_port_race(target, fake_xray, monkeypatch):
    """A TCP listener not proving unique SOCKS credentials must never be trusted as Xray."""

    async def foreign_listener(reader, writer):
        try:
            _, method_count = await reader.readexactly(2)
            await reader.readexactly(method_count)
            writer.write(b"\x05\x00")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(foreign_listener, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(probe_module, "_unused_loopback_port", lambda: port)
    try:
        with pytest.raises(XrayUnavailable) as raised:
            async with XrayProcess(fake_xray.executable, startup_timeout=1).open(target):
                pytest.fail("a foreign listener cannot establish Xray ownership")
    finally:
        server.close()
        await server.wait_closed()

    assert raised.value.error_code in {"xray-exit", "xray-ownership"}


@pytest.mark.asyncio
async def test_permissive_foreign_listener_cannot_fake_unique_credentials(
    target,
    fake_xray,
    monkeypatch,
):
    """A foreign listener accepting every password has not proved the unique credential."""

    async def permissive_listener(reader, writer):
        try:
            _, method_count = await reader.readexactly(2)
            await reader.readexactly(method_count)
            writer.write(b"\x05\x02")
            await writer.drain()
            _, user_length = await reader.readexactly(2)
            await reader.readexactly(user_length)
            password_length = (await reader.readexactly(1))[0]
            await reader.readexactly(password_length)
            writer.write(b"\x01\x00")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(permissive_listener, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(probe_module, "_unused_loopback_port", lambda: port)
    monkeypatch.setenv("FAKE_XRAY_MODE", "no-listen")
    try:
        with pytest.raises(XrayUnavailable) as raised:
            async with XrayProcess(
                fake_xray.executable,
                startup_timeout=0.2,
            ).open(target):
                pytest.fail("accepting arbitrary credentials is not an ownership proof")
    finally:
        server.close()
        await server.wait_closed()

    assert raised.value.error_code == "xray-ownership"


@pytest.mark.asyncio
async def test_adaptive_foreign_listener_is_rejected_by_kernel_owner(
    target,
    fake_xray,
    monkeypatch,
):
    """Protocol behavior cannot prove ownership when another process can learn credentials."""
    learned_credentials: list[tuple[bytes, bytes]] = []

    async def adaptive_listener(reader, writer):
        try:
            _, method_count = await reader.readexactly(2)
            await reader.readexactly(method_count)
            writer.write(b"\x05\x02")
            await writer.drain()
            _, user_length = await reader.readexactly(2)
            user = await reader.readexactly(user_length)
            password_length = (await reader.readexactly(1))[0]
            password = await reader.readexactly(password_length)
            credentials = (user, password)
            if not learned_credentials:
                learned_credentials.append(credentials)
            accepted = credentials == learned_credentials[0]
            writer.write(b"\x01\x00" if accepted else b"\x01\xff")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(adaptive_listener, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(probe_module, "_unused_loopback_port", lambda: port)
    monkeypatch.setenv("FAKE_XRAY_MODE", "no-listen")
    try:
        with pytest.raises(XrayUnavailable) as raised:
            async with XrayProcess(
                fake_xray.executable,
                startup_timeout=0.2,
            ).open(target):
                pytest.fail("a listener owned by another PID cannot become Xray")
    finally:
        server.close()
        await server.wait_closed()

    assert learned_credentials
    assert raised.value.error_code == "xray-ownership"


@pytest.mark.asyncio
async def test_default_owner_lookup_failure_fails_closed(
    target,
    fake_xray,
    monkeypatch,
):
    """Denied kernel ownership data must become UNKNOWN/XRAY, never a tunnel verdict."""

    def denied_process(pid):
        raise probe_module.psutil.AccessDenied(pid)

    monkeypatch.setattr(probe_module.psutil, "Process", denied_process)

    with pytest.raises(XrayUnavailable) as raised:
        async with XrayProcess(
            fake_xray.executable,
            startup_timeout=0.2,
        ).open(target):
            pytest.fail("unavailable ownership evidence cannot open a tunnel")

    assert raised.value.error_code == "xray-ownership"


@pytest.mark.asyncio
async def test_default_owner_rejects_stale_process_identity(
    target,
    fake_xray,
    monkeypatch,
):
    """A reused or stale PID identity must invalidate an otherwise responsive listener."""

    class StaleProcess:
        def __init__(self, pid):
            self.pid = pid
            self.create_time_calls = 0

        def is_running(self):
            return True

        def create_time(self):
            self.create_time_calls += 1
            return 1.0 if self.create_time_calls <= 3 else 2.0

        def net_connections(self, *, kind):
            assert kind == "tcp"
            config = json.loads(fake_xray.captured_config.read_text())
            return [
                SimpleNamespace(
                    status=probe_module.psutil.CONN_LISTEN,
                    laddr=("127.0.0.1", config["inbounds"][0]["port"]),
                )
            ]

    process_identity = None

    def stale_process_factory(pid):
        nonlocal process_identity
        process_identity = StaleProcess(pid)
        return process_identity

    monkeypatch.setattr(probe_module.psutil, "Process", stale_process_factory)
    with pytest.raises(XrayUnavailable) as raised:
        async with XrayProcess(
            fake_xray.executable,
            # Cold execution of the temporary fixture may exceed one second
            # on macOS. This test asserts PID reuse, not startup latency.
            startup_timeout=5,
        ).open(target):
            pass

    assert process_identity is not None
    assert process_identity.create_time_calls >= 4
    assert raised.value.error_code == "xray-ownership"


@pytest.mark.asyncio
async def test_shared_tunnel_keeps_overlapping_process_state_isolated(target, fake_xray):
    """Per-open mutable state must not cross-check or clear another concurrent Xray child."""

    class Response:
        status_code = 204

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, url):
            await asyncio.sleep(0.05)
            return Response()

    tunnel = XrayTunnel(
        XrayProcess(fake_xray.executable, startup_timeout=1),
        canaries=(Canary("https://canary.invalid/check"),),
        timeout=1,
        client_factory=Client,
    )
    results = await asyncio.gather(
        tunnel.check(target),
        tunnel.check(target.model_copy(update={"target_id": "target-2"})),
        return_exceptions=True,
    )

    assert all(not isinstance(result, BaseException) for result in results)
    assert all(result.canary_ok for result in results)


@pytest.mark.asyncio
async def test_real_httpx_uses_authenticated_socks_for_https(target, fake_xray):
    """Only a real TLS request after an authenticated SOCKS CONNECT can prove E2E success."""
    certificate_authority = trustme.CA()
    certificate = certificate_authority.issue_cert("127.0.0.1")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    certificate_authority.configure_trust(client_context)
    origin_requests: list[bytes] = []

    async def tls_origin(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            origin_requests.append(request.split(b"\r\n", 1)[0])
            writer.write(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    origin = await asyncio.start_server(
        tls_origin,
        "127.0.0.1",
        0,
        ssl=server_context,
    )
    origin_port = origin.sockets[0].getsockname()[1]
    canary = Canary(f"https://127.0.0.1:{origin_port}/check", 204)
    try:
        tunnel = XrayTunnel(
            XrayProcess(fake_xray.executable, startup_timeout=1),
            canaries=(canary,),
            timeout=1,
            verify=client_context,
        )
        result = await tunnel.check(target)

        assert result.canary_ok is True
        assert origin_requests == [b"GET /check HTTP/1.1"]
        assert fake_xray.connects_file.read_bytes() == b"1"

        async with XrayProcess(fake_xray.executable, startup_timeout=1).open(target) as proxy:
            parsed = urlsplit(proxy)
            wrong_proxy = f"socks5://wrong:wrong@{parsed.hostname}:{parsed.port}"
            with pytest.raises(httpx.HTTPError):
                async with httpx.AsyncClient(
                    proxy=wrong_proxy,
                    verify=client_context,
                    trust_env=False,
                    timeout=0.5,
                ) as client:
                    await client.get(canary.url)
        assert origin_requests == [b"GET /check HTTP/1.1"]
    finally:
        origin.close()
        await origin.wait_closed()

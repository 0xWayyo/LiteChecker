"""Safe subscription smoke output contracts."""

import asyncio
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from litechecker.config import AgentSettings
from litechecker.agent import XrayVersionResult
from litechecker.models import ProbeResult, ProbeStage, ResultStatus
from litechecker.probe import ControlResult, probe_all


FIXTURE = Path(__file__).parent / "fixtures" / "xray-subscription.json"
AGENT_TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


async def _compatible_xray():
    return XrayVersionResult("26.3.27", True, None)


class BytesFetcher:
    def __init__(self, payload: bytes):
        self.payload = payload

    async def fetch(self) -> bytes:
        return self.payload


def _settings(**updates) -> AgentSettings:
    values = {
        "agent_id": "smoke-agent",
        "agent_token": AGENT_TOKEN,
        "collector_url": "https://collector.example.invalid",
        "subscription_url": "https://subscription.example.invalid/private",
        "state_key": "state-key-with-at-least-32-characters",
        "run_deadline_seconds": 30,
    }
    values.update(updates)
    return AgentSettings(**values)


def test_subscription_smoke_summary_contains_aggregates_only():
    """A smoke helper must not echo addresses, labels, UUIDs, or raw outbound data."""
    from litechecker.smoke import summarize_subscription

    output = summarize_subscription(FIXTURE.read_bytes(), b"k" * 32, 20)

    assert "validation=ok" in output
    assert "target_count=3" in output
    assert "sni_count=1" in output
    assert "address_kind_domain=1" in output
    assert "address_kind_ip=1" in output
    assert "revision_prefix=" in output
    fixture_text = FIXTURE.read_text(encoding="utf-8")
    for sensitive in (
        "198.51.100.10",
        "edge.example",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "fake-reality-public-key",
        "fake-short-id",
    ):
        assert sensitive in fixture_text
        assert sensitive not in output


@pytest.mark.asyncio
async def test_probe_smoke_runs_direct_control_and_core_prober_with_safe_summary(
    monkeypatch,
):
    """Dropping probe_all would let a parser-only check masquerade as an E2E smoke."""
    from litechecker.smoke import run_smoke

    observed: dict[str, object] = {}

    async def control_checker(*, timeout):
        observed["control_timeout"] = timeout
        return ControlResult(ok=True, latency_ms=1)

    async def prober(targets, **kwargs):
        observed["target_count"] = len(targets)
        observed.update(kwargs)
        return [
            ProbeResult(
                target_id=target.target_id,
                label=target.label,
                address=target.address,
                port=target.port,
                status=ResultStatus.UP,
                stage=ProbeStage.TLS if target.check_kind == "sni" else ProbeStage.E2E,
                check_kind=target.check_kind,
            )
            for target in targets
        ]

    output = await run_smoke(
        _settings(xray_binary="/usr/local/bin/xray"),
        probe=True,
        fetcher=BytesFetcher(FIXTURE.read_bytes()),
        control_checker=control_checker,
        prober=prober,
        version_checker=_compatible_xray,
    )

    assert observed["control_timeout"] == 5.0
    assert observed["target_count"] == 3
    assert observed["max_concurrency"] == 4
    assert observed["xray_binary"] == "/usr/local/bin/xray"
    assert len(observed["canaries"]) == 2
    assert "refresh_state=FRESH" in output
    assert "status_counts=UP:3,DOWN:0,UNKNOWN:0" in output
    assert "stage_counts=E2E:2,TLS:1" in output
    assert "198.51.100.10" not in output
    assert "edge.example" not in output


@pytest.mark.asyncio
async def test_probe_smoke_control_failure_is_unknown_not_down():
    """A failed direct control must not be summarized as a target outage."""
    from litechecker.smoke import run_smoke

    async def failed_control(*, timeout):
        return ControlResult(ok=False, error_code="control-failed")

    output = await run_smoke(
        _settings(),
        probe=True,
        fetcher=BytesFetcher(FIXTURE.read_bytes()),
        control_checker=failed_control,
        prober=probe_all,
        version_checker=_compatible_xray,
    )

    assert "status_counts=UP:0,DOWN:0,UNKNOWN:3" in output
    assert "stage_counts=AGENT_NETWORK:3" in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_stage"),
    (
        (TimeoutError(), "DEADLINE"),
        (RuntimeError("https://private.invalid/raw-xray-stderr"), "XRAY"),
    ),
)
async def test_probe_smoke_global_probe_failure_is_honest_and_sanitized(
    failure,
    expected_stage,
):
    """Boundary failures must become UNKNOWN aggregates without exception text."""
    from litechecker.smoke import run_smoke

    async def control_checker(*, timeout):
        return ControlResult(ok=True)

    async def failed_prober(targets, **kwargs):
        raise failure

    output = await run_smoke(
        _settings(),
        probe=True,
        fetcher=BytesFetcher(FIXTURE.read_bytes()),
        control_checker=control_checker,
        prober=failed_prober,
        version_checker=_compatible_xray,
    )

    assert "status_counts=UP:0,DOWN:0,UNKNOWN:3" in output
    if expected_stage == "XRAY":
        assert "stage_counts=XRAY:2,POLICY:1" in output
    else:
        assert f"stage_counts={expected_stage}:3" in output
    assert "private.invalid" not in output
    assert "raw-xray-stderr" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version_result",
    (
        XrayVersionResult(None, False, "xray-version-unavailable"),
        XrayVersionResult("99.0.0", False, "xray-version-mismatch"),
    ),
)
async def test_probe_smoke_requires_exact_xray_version_before_probing(version_result):
    """Smoke must never turn an unverified Xray runtime into endpoint DOWN evidence."""
    async def control_checker(*, timeout):
        return ControlResult(ok=True)

    async def must_not_probe(targets, **kwargs):
        assert all(target.check_kind == "sni" for target in targets)
        return [ProbeResult(
            target_id=target.target_id, label=target.label,
            address=target.address, port=443, check_kind="sni",
            status=ResultStatus.UP, stage=ProbeStage.TLS,
        ) for target in targets]

    async def version_checker():
        return version_result

    from litechecker.smoke import run_smoke

    output = await run_smoke(
        _settings(),
        probe=True,
        fetcher=BytesFetcher(FIXTURE.read_bytes()),
        control_checker=control_checker,
        prober=must_not_probe,
        version_checker=version_checker,
    )

    assert "status_counts=UP:1,DOWN:0,UNKNOWN:2" in output
    assert "stage_counts=TLS:1,XRAY:2" in output


def test_smoke_cli_rejects_secret_arguments_without_echoing_them(capsys):
    """A mistaken URL argument must not become a process-list or stderr secret leak."""
    from litechecker.smoke import main

    secret = "https://subscription.example/private?token=do-not-print"
    with pytest.raises(SystemExit) as exit_info:
        main(["--subscription-url", secret])

    assert exit_info.value.code == 2
    assert secret not in capsys.readouterr().err


@pytest.mark.asyncio
async def test_signal_runner_direct_cancellation_awaits_finalizer_and_restores_handlers():
    """Cancelling the wrapper must not abandon the active coroutine or its cleanup."""
    from litechecker.runtime import run_with_signals

    ready = asyncio.Event()
    finalized = asyncio.Event()
    before_tasks = asyncio.all_tasks()
    previous_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }

    async def operation():
        ready.set()
        try:
            await asyncio.Event().wait()
        finally:
            finalized.set()

    wrapper = asyncio.create_task(run_with_signals(operation()))
    await asyncio.wait_for(ready.wait(), timeout=1)
    wrapper.cancel()
    with pytest.raises(asyncio.CancelledError):
        await wrapper

    assert finalized.is_set()
    assert {
        task
        for task in asyncio.all_tasks()
        if task not in before_tasks and not task.done()
    } == set()
    assert {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    } == previous_handlers


@pytest.mark.asyncio
async def test_signal_runner_falls_back_when_loop_handlers_are_unsupported(monkeypatch):
    """Windows-style loops without add_signal_handler must still await the command."""
    from litechecker.runtime import run_with_signals

    loop = asyncio.get_running_loop()

    def unsupported(*args, **kwargs):
        raise NotImplementedError

    monkeypatch.setattr(loop, "add_signal_handler", unsupported)

    assert await run_with_signals(asyncio.sleep(0, result="completed")) == "completed"


def test_smoke_help_and_config_parse_happen_before_signal_install(monkeypatch, capsys):
    """Help and invalid configuration must finish without touching runtime handlers."""
    import litechecker.smoke as smoke

    calls: list[str] = []

    async def unexpected_runner(command):
        calls.append("signal-runner")
        return await command

    monkeypatch.setattr(smoke, "run_with_signals", unexpected_runner)
    with pytest.raises(SystemExit) as help_exit:
        smoke.main(["--help"])
    assert help_exit.value.code == 0
    assert calls == []

    monkeypatch.setattr(
        smoke.AgentSettings,
        "from_env",
        lambda: (_ for _ in ()).throw(ValueError("private-config")),
    )
    assert smoke.main(["--probe"]) == 2
    assert calls == []
    assert "private-config" not in capsys.readouterr().err


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.skipif(not hasattr(signal, "SIGTERM"), reason="POSIX signal required")
def test_smoke_sigterm_awaits_active_probe_child_cleanup(tmp_path):
    """SIGTERM must not orphan the Xray-shaped child owned by an active prober."""
    pid_file = tmp_path / "listener.pid"
    script = r'''
import asyncio
import signal
import socket
import sys
from pathlib import Path

import litechecker.smoke as smoke
from litechecker.config import AgentSettings
from litechecker.probe import ControlResult

fixture_path = Path(sys.argv[1])
pid_path = Path(sys.argv[2])
settings = AgentSettings(
    agent_id="smoke-signal-test",
    agent_token="lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
    collector_url="https://collector.example.invalid",
    subscription_url="https://subscription.example.invalid/private",
    state_key="state-key-with-at-least-32-characters",
)
smoke.AgentSettings.from_env = staticmethod(lambda: settings)

class Fetcher:
    async def fetch(self):
        return fixture_path.read_bytes()

async def control_checker(*, timeout):
    return ControlResult(ok=True)

async def fake_probe_all(targets, **kwargs):
    child_code = """
import os
import signal
import socket

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
print(os.getpid(), flush=True)
signal.pause()
"""
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        child_code,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        assert child.stdout is not None
        child_pid = await asyncio.wait_for(child.stdout.readline(), timeout=2)
        pid_path.write_bytes(child_pid)
        print("probe-active", flush=True)
        await asyncio.Event().wait()
    finally:
        if child.returncode is None:
            child.terminate()
        try:
            await asyncio.wait_for(child.wait(), timeout=2)
        except TimeoutError:
            child.kill()
            await child.wait()
        print("probe-cleaned", flush=True)
    return []

real_run_smoke = smoke.run_smoke

async def run_smoke_with_fake_probe(actual_settings, *, probe=False):
    async def version_checker():
        return smoke.XrayVersionResult("26.3.27", True, None)
    return await real_run_smoke(
        actual_settings,
        probe=probe,
        fetcher=Fetcher(),
        control_checker=control_checker,
        prober=fake_probe_all,
        version_checker=version_checker,
    )

smoke.run_smoke = run_smoke_with_fake_probe
raise SystemExit(smoke.main(["--probe"]))
'''
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(FIXTURE), str(pid_file)],
        cwd=Path(__file__).parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child_pid: int | None = None
    try:
        assert process.stdout is not None
        readable, _, _ = select.select([process.stdout], [], [], 5)
        assert readable, "smoke probe did not become active"
        assert process.stdout.readline().strip() == "probe-active"
        child_pid = int(pid_file.read_text(encoding="utf-8"))

        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)

        assert time.monotonic() - started < 5
        assert process.returncode == 0
        assert stdout.strip() == "probe-cleaned"
        assert stderr == ""
        assert "https://" not in stdout
        assert "outbound" not in stdout
        deadline = time.monotonic() + 2
        while _pid_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_exists(child_pid)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2)
        if child_pid is not None and _pid_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)

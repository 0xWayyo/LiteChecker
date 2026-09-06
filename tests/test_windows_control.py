"""The native controller must not trust stale files or stop foreign processes."""

import importlib
import importlib.util
import asyncio
import json
import os
from pathlib import Path
import sys
import time

import psutil
import pytest


def module(name):
    assert importlib.util.find_spec("litechecker." + name) is not None, "native lifecycle is not implemented"
    return importlib.import_module("litechecker." + name)


def root_at(tmp_path):
    from windows_test_support import secure_test_directory
    root = tmp_path / "_app"
    root.mkdir(mode=0o700)
    secure_test_directory(root)
    (root / "pyproject.toml").write_text('[project]\nversion="0.5.0"\n')
    return root


def record(root, *, pid=None, instance="a" * 32, phase="ready"):
    current = psutil.Process()
    return {"schema": 1, "role": "supervisor", "pid": pid or current.pid,
            "created": current.create_time(), "instance": instance,
            "release": str(root), "phase": phase, "version": "0.5.0"}


def write_record(root, name, value):
    control = root / "windows-state" / "control"
    control.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = control / name
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_status_without_installation_state_is_read_only(tmp_path):
    control = module("windows_control")
    root = root_at(tmp_path)
    assert control.status(root) == {"state": "stopped", "version": "0.5.0"}
    assert not (root / "windows-state").exists()


@pytest.mark.asyncio
async def test_live_foreign_pid_is_never_reported_running_or_stopped_by_command(tmp_path):
    control = module("windows_control")
    root = root_at(tmp_path)
    write_record(root, "supervisor.json", record(root))
    assert control.status(root)["state"] == "unknown"
    result = await control.stop(root)
    assert result["status"] == "failed"
    assert psutil.Process(os.getpid()).is_running()


def test_dead_pid_is_historical_state_not_a_running_service(tmp_path):
    control = module("windows_control")
    root = root_at(tmp_path)
    write_record(root, "supervisor.json", record(root, pid=2_000_000_000))
    assert control.status(root)["state"] == "stopped"


@pytest.mark.asyncio
async def test_duplicate_start_does_not_spawn_another_supervisor(tmp_path, monkeypatch):
    control = module("windows_control")
    root = root_at(tmp_path)
    write_record(root, "supervisor.json", record(root))
    monkeypatch.setattr(control, "_process_matches", lambda *args, **kwargs: True)

    async def forbidden(*args, **kwargs):
        pytest.fail("duplicate Start launched another supervisor")

    monkeypatch.setattr(control, "_spawn_supervisor", forbidden)
    result = await control.start(root)
    assert result["status"] == "already-running"


@pytest.mark.asyncio
async def test_stop_intent_suppresses_activation_and_does_not_fail_release_health(tmp_path):
    control = module("windows_control")
    root = root_at(tmp_path)
    host = control.Supervisor(root, "a" * 32)
    host.stop_requested = True
    await host.activate_release(root, True)
    assert not host.is_running()
    assert await host.healthy_release(root, True)


@pytest.mark.asyncio
async def test_gate_with_another_instance_never_admits_worker(tmp_path, monkeypatch):
    worker = module("windows_worker")
    root = root_at(tmp_path)
    write_record(root, "worker-go.json", {"instance": "b" * 32})
    with pytest.raises(RuntimeError, match="worker-gate-timeout"):
        await worker.wait_for_gate(root, "a" * 32, timeout=0.03)
    assert not (root / "windows-state/control/worker.json").exists()


@pytest.mark.asyncio
async def test_windows_cycle_explicitly_uses_production_d2_not_mac_default(tmp_path, monkeypatch):
    worker = module("windows_worker")
    from litechecker.direct_check import TrialResult
    from litechecker.windows_network import WindowsDirectNetwork
    from types import SimpleNamespace

    settings = SimpleNamespace(state_dir=tmp_path)

    async def measured(value, **kwargs):
        assert value is settings
        assert kwargs == {"production": True, "network_factory": WindowsDirectNetwork.discover,
                          "platform_label": "Windows", "validate_after": True}
        return TrialResult("offline is not a worker failure", False)

    monkeypatch.setattr(worker, "run_trial", measured)
    result = await worker.windows_cycle(settings)
    assert result.text == "offline is not a worker failure"


def test_production_failure_report_has_explicit_windows_platform():
    from datetime import UTC, datetime
    from litechecker.collector.auth import AgentIdentity
    from litechecker.direct_reporting import format_unavailable

    text = format_unavailable(AgentIdentity("node", "city", "device", 600), "cycle-failed",
                              datetime.now(UTC), platform_label="Windows")
    assert "DIRECT (Windows)" in text
    assert "macOS" not in text


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows fail-closed boundary")
def test_job_cannot_silently_run_without_native_ownership():
    job = module("windows_job")
    with pytest.raises(RuntimeError, match="windows-job-unavailable"):
        job.WindowsJob()


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows Job Objects")
def test_native_job_close_kills_assigned_process(tmp_path):
    import ctypes
    from ctypes import wintypes
    import subprocess
    job = module("windows_job").WindowsJob()
    ready = tmp_path / "owned-child-ready.txt"
    child = subprocess.Popen(
        [sys._base_executable, "-I", "-B", "-c",
         "import os,sys,time;from pathlib import Path;"
         "Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(120)", str(ready)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        job.assign(child.pid)
        deadline = time.monotonic() + 10
        while child.poll() is None and time.monotonic() < deadline:
            if ready.exists() and ready.read_text() == str(child.pid):
                break
            time.sleep(0.02)
        assert ready.exists(), "controlled child never reached its sleeping state"
        assert int(ready.read_text()) == child.pid, "must assign the actual interpreter, not a redirector"
        assert child.poll() is None, "a previously exited process does not prove kill-on-close"
        # Windows may add another owned runtime/console process. Query the real
        # job membership instead of assuming one Python executable means one PID.
        class ProcessIds(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD),
                        ("pids", ctypes.c_size_t * 128)]

        membership = ProcessIds()
        assert job._api.QueryInformationJobObject(
            job._handle, 3, ctypes.byref(membership), ctypes.sizeof(membership), None,
        ), "could not inspect this test-owned Job Object"
        assert 1 <= membership.count == membership.assigned <= 128
        members = set(membership.pids[:membership.count])
        assert child.pid in members
        assert os.getpid() not in members, "the test runner must not belong to its child job"
        assert job.active_processes() >= 1
        job.close()
        child.wait(timeout=5)
        deadline = time.monotonic() + 5
        while any(psutil.pid_exists(pid) for pid in members) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not any(psutil.pid_exists(pid) for pid in members), "an owned job member survived close"
    finally:
        job.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


@pytest.mark.asyncio
async def test_gate_does_not_accept_a_matching_nonce_without_verified_supervisor(tmp_path):
    worker = module("windows_worker")
    root = root_at(tmp_path)
    write_record(root, "supervisor.json", record(root))
    write_record(root, "worker-go.json", {"instance": "a" * 32, "supervisor_instance": "a" * 32})
    with pytest.raises(RuntimeError, match="worker-gate-timeout"):
        await worker.wait_for_gate(root, "a" * 32, timeout=0.03)


@pytest.mark.asyncio
async def test_service_readiness_and_latest_failure_are_local_not_network_health(tmp_path):
    from types import SimpleNamespace
    from litechecker.collector.auth import AgentIdentity
    from litechecker.direct_service import run_service
    calls = []
    settings = SimpleNamespace(state_dir=tmp_path, identity=AgentIdentity("node", "city", "device", 600),
                               agent=SimpleNamespace(run_deadline_seconds=10))

    async def unavailable(_):
        calls.append("measured")
        raise OSError("SECRET upstream failure")

    def observed(result):
        calls.append(result.text)

    result = await run_service(settings, once=True, send=False, cycle=unavailable,
                               platform_label="Windows", on_ready=lambda: calls.append("ready"),
                               result_observer=observed)
    assert calls[:2] == ["ready", "measured"]
    assert not result.available
    assert "DIRECT (Windows)" in calls[2] and "SECRET" not in calls[2]


@pytest.mark.asyncio
async def test_worker_gate_precedes_config_and_stop_nonce_awaits_cycle_cleanup(tmp_path, monkeypatch):
    worker = module("windows_worker")
    from filelock import FileLock
    from litechecker.windows_trial import save_configuration
    root = root_at(tmp_path)
    save_configuration(root, {"subscription_url": "https://example.invalid/controlled"})
    xray = root / ".windows-native/tools/xray/xray.exe"
    xray.parent.mkdir(parents=True)
    xray.write_bytes(b"controlled boundary, never executed")
    write_record(root, "supervisor.json", record(root, instance="b" * 32))
    monkeypatch.setattr(worker, "process_matches", lambda *args: True)  # parent OS identity boundary
    entered, cleaned = asyncio.Event(), asyncio.Event()

    async def measured(*args, **kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    monkeypatch.setattr(worker, "run_trial", measured)
    task = asyncio.create_task(worker.run_worker(root, root, "a" * 32))
    try:
        await asyncio.sleep(0.04)
        assert not (root / "windows-state/device.json").exists()
        assert not (root / "windows-state/control/worker.json").exists()
        write_record(root, "worker-go.json", {"instance": "a" * 32, "supervisor_instance": "b" * 32})
        await asyncio.wait_for(entered.wait(), 2)
        assert json.loads((root / "windows-state/control/worker.json").read_text())["phase"] == "ready"
        write_record(root, "worker-stop.json", {"instance": "c" * 32})
        await asyncio.sleep(0.25)
        assert not task.done()
        write_record(root, "worker-stop.json", {"instance": "a" * 32})
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert cleaned.is_set()
        assert json.loads((root / "windows-state/control/worker.json").read_text())["phase"] == "stopped"
        with FileLock(root / "windows-state/service.lock", timeout=0, preserve_lock_file=True):
            pass
        with FileLock(root / "windows-state/trial.lock", timeout=0, preserve_lock_file=True):
            pass
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_stop_arriving_during_activation_cleanup_cannot_resurrect_worker(tmp_path, monkeypatch):
    control = module("windows_control")
    from types import SimpleNamespace
    root = root_at(tmp_path)
    host = control.Supervisor(root, "a" * 32)
    process = SimpleNamespace(code=None)
    process.poll = lambda: process.code
    host.worker, host.worker_instance = process, "b" * 32
    host.job = SimpleNamespace(close=lambda: None, active_processes=lambda: 0)

    async def observed_exit(timeout):
        host.stop_requested = True  # arrives while the old child is exiting
        process.code = 0
        return True

    monkeypatch.setattr(host, "_wait_exit", observed_exit)
    await host.activate_release(root, True)
    assert host.stop_requested and not host.is_running()
    assert await host.healthy_release(root, True)


@pytest.mark.asyncio
async def test_stopped_manual_update_excludes_concurrent_start(tmp_path, monkeypatch):
    control = module("windows_control")
    from litechecker import updater, windows_update
    root = root_at(tmp_path)
    entered, finish = asyncio.Event(), asyncio.Event()

    async def update(*args, **kwargs):
        entered.set()
        await finish.wait()
        return {"status": "current"}

    monkeypatch.setattr(updater, "check_for_update", update)  # external signed transaction boundary
    monkeypatch.setattr(windows_update, "WindowsUpdateAdapter", lambda root: object())
    task = asyncio.create_task(control.request_update(root))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        started = await control.start(root)
        assert started["status"] == "busy", "Start must not claim a worker was queued during an update"
        assert started["state"] == "stopped"
    finally:
        finish.set()
        await task


def test_candidate_validation_does_not_initialize_device_identity(tmp_path):
    worker = module("windows_worker")
    from litechecker.windows_trial import save_configuration
    root = root_at(tmp_path)
    save_configuration(root, {"subscription_url": "https://example.invalid/controlled"})
    xray = root / ".windows-native/tools/xray/xray.exe"
    xray.parent.mkdir(parents=True)
    xray.write_bytes(b"not executed during validation")
    before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    worker.validate(root, root)
    after = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert after == before, "candidate validation must not generate device.json or locks"


@pytest.mark.asyncio
async def test_stop_awaits_all_job_descendants_not_only_worker(tmp_path):
    control = module("windows_control")
    from types import SimpleNamespace
    root = root_at(tmp_path)
    host = control.Supervisor(root, "a" * 32)
    host.worker = SimpleNamespace(poll=lambda: 0)
    seen = []

    class KernelJob:
        def __init__(self):
            self.active = 1

        def active_processes(self):
            seen.append("query")
            return self.active

        def terminate(self):
            seen.append("terminate")
            asyncio.get_running_loop().call_later(0.03, setattr, self, "active", 0)

        def close(self):
            assert self.active == 0, "reported stop before the owned descendants exited"
            seen.append("close")

    host.job = KernelJob()
    await host._stop_worker()
    assert "terminate" in seen and seen[-1] == "close"


def test_process_identity_accepts_only_managed_base_python_with_exact_venv_argv(tmp_path, monkeypatch):
    state = module("windows_process_state")
    from types import SimpleNamespace
    root = root_at(tmp_path)
    venv = root / ".windows-native/venv/Scripts/python.exe"
    base = root / ".windows-native/python/managed/python.exe"
    entry = root / "scripts/windows-app-entry.py"
    for path in (venv, base, entry):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"controlled, not executed")
        path.chmod(0o700)
    cfg = root / ".windows-native/venv/pyvenv.cfg"
    cfg.write_text(f"home = {base.parent}\n")
    cfg.chmod(0o600)
    expected = [str(venv), "-I", "-B", str(entry), "supervisor", "--root", str(root), "--instance", "a" * 32]
    process = SimpleNamespace(is_running=lambda: True, status=lambda: "running", create_time=lambda: 1000.0,
                              exe=lambda: str(base), cmdline=lambda: expected)
    monkeypatch.setattr(state.psutil, "Process", lambda pid: process)
    monkeypatch.setattr(state.psutil, "pid_exists", lambda pid: True)
    saved = {"schema": 1, "role": "supervisor", "pid": 1234, "created": 1000.0,
             "instance": "a" * 32, "release": str(root)}
    assert state.process_matches(root, saved, "supervisor")
    process.cmdline = lambda: expected[:-1] + ["b" * 32]
    assert not state.process_matches(root, saved, "supervisor")
    process.cmdline = lambda: expected
    cfg.write_text(f"home = {tmp_path}\n")
    assert not state.process_matches(root, saved, "supervisor")


@pytest.mark.parametrize("system_root_key", ["SystemRoot", "SYSTEMROOT"])
def test_python_launch_does_not_inherit_launcher_or_python_overrides(tmp_path, monkeypatch, system_root_key):
    state = module("windows_process_state")
    root = root_at(tmp_path)
    venv = root / ".windows-native/venv/Scripts/python.exe"
    base = root / ".windows-native/python/managed/python.exe"
    for path in (venv, base):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"controlled, not executed")
        path.chmod(0o700)
    cfg = root / ".windows-native/venv/pyvenv.cfg"
    cfg.write_text(f"home = {base.parent}\n")
    cfg.chmod(0o600)
    monkeypatch.setenv("__PYVENV_LAUNCHER__", "untrusted.exe")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    monkeypatch.setenv("LC_SUBSCRIPTION_URL", "SECRET")
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    monkeypatch.setenv(system_root_key, "controlled-system-root")
    assert callable(getattr(state, "python_launch", None)), "direct managed interpreter launch is missing"
    executable, environment = state.python_launch(root)
    assert executable == base
    assert environment["__PYVENV_LAUNCHER__"] == str(venv)
    # os.environ normalizes names to uppercase on Windows. Preserve the value,
    # not POSIX-only mixed-case dictionary spelling.
    normalized = {name.upper(): value for name, value in environment.items()}
    assert normalized["SYSTEMROOT"] == "controlled-system-root"
    assert "PYTHONPATH" not in normalized and "LC_SUBSCRIPTION_URL" not in normalized


def native_fault_diagnostic(error):
    """Test-only diagnostic: no exception text, arguments, locals or full paths."""
    from pathlib import Path

    result = []
    known_files = {"windows_control.py", "windows_worker.py", "windows_process_state.py",
                   "windows_security.py", "windows_job.py", "windows_trial.py", "config.py",
                   "direct_service.py", "state.py", "update_launcher.py", "update_store.py"}
    for _ in range(4):
        if error is None:
            break
        item = {"type": type(error).__name__[:64], "frames": []}
        for name in ("errno", "winerror"):
            value = getattr(error, name, None)
            if type(value) is int:
                item[name] = value
        trace = error.__traceback__
        while trace is not None and len(item["frames"]) < 12:
            code = trace.tb_frame.f_code
            filename = Path(code.co_filename).name
            if filename in known_files:
                item["frames"].append(f"{filename}:{code.co_name[:64]}")
            trace = trace.tb_next
        result.append(item)
        error = error.__cause__ or error.__context__
    return result


def test_native_fault_diagnostic_preserves_winerror_without_exception_text():
    function = globals().get("native_fault_diagnostic")
    assert callable(function), "native startup failures need a bounded secret-free diagnostic"
    cause = PermissionError(13, "SECRET token and URL")
    cause.winerror = 32
    try:
        raise RuntimeError("SECRET second message") from cause
    except RuntimeError as error:
        observed = function(error)
    assert observed[0]["type"] == "RuntimeError"
    assert observed[1]["type"] == "PermissionError"
    assert observed[1]["winerror"] == 32 and observed[1]["errno"] == 13
    assert "SECRET" not in json.dumps(observed)
    assert len(observed) <= 4


def native_application(tmp_path):
    """A real isolated Python host; only the external measurement is controlled."""
    import shutil
    import subprocess
    import inspect

    root = root_at(tmp_path)
    runtime = root / ".windows-native"
    # Mirror the production uv-managed layout without downloads. The real base
    # interpreter must live inside this release, not in a machine-wide install.
    managed = runtime / "python" / "managed"
    managed.mkdir(parents=True)
    installed = Path(sys.base_prefix)
    for item in installed.iterdir():
        if item.is_file() and item.suffix.lower() in {".exe", ".dll", ".zip", "._pth"}:
            shutil.copyfile(item, managed / item.name)
    for name in ("Lib", "DLLs"):
        if (installed / name).is_dir():
            shutil.copytree(installed / name, managed / name,
                            ignore=shutil.ignore_patterns("site-packages", "test", "tests", "__pycache__", "idlelib"))
    subprocess.run([str(managed / "python.exe"), "-I", "-m", "venv", "--without-pip", str(runtime / "venv")],
                   check=True, timeout=90, capture_output=True)
    xray = runtime / "tools" / "xray" / "xray.exe"
    xray.parent.mkdir(parents=True)
    shutil.copy2(sys.executable, xray)
    from litechecker.windows_trial import save_configuration
    save_configuration(root, {"subscription_url": "https://example.invalid/authorized-fixture"})
    entry = root / "scripts" / "windows-app-entry.py"
    entry.parent.mkdir()
    source = str(Path(__file__).resolve().parents[1] / "src")
    packages = [path for path in sys.path if "site-packages" in path]
    entry.write_text(
        "import asyncio, json, sys\nfrom pathlib import Path\n"
        f"sys.path[:0] = {[source, *packages]!r}\n"
        "from litechecker import windows_control, windows_worker\n"
        "from litechecker.direct_check import TrialResult\n"
        + inspect.getsource(native_fault_diagnostic) + "\n"
        + f"fault_root = Path({str(root / 'windows-state')!r})\n"
        "supervisor_run = windows_control.Supervisor.run\n"
        "worker_run = windows_worker.run_worker\n"
        "async def observed_supervisor(self):\n"
        "    try: return await supervisor_run(self)\n"
        "    except BaseException as error:\n"
        "        (fault_root / 'fixture-supervisor-fault.json').write_text(json.dumps(native_fault_diagnostic(error)), encoding='utf-8')\n"
        "        raise\n"
        "async def observed_worker(*args):\n"
        "    try: return await worker_run(*args)\n"
        "    except BaseException as error:\n"
        "        (fault_root / 'fixture-worker-fault.json').write_text(json.dumps(native_fault_diagnostic(error)), encoding='utf-8')\n"
        "        raise\n"
        "windows_control.Supervisor.run = observed_supervisor\n"
        "windows_worker.run_worker = observed_worker\n"
        "async def controlled_measurement(settings, **kwargs):\n"
        "    child = await asyncio.create_subprocess_exec(sys.executable, '-I', '-c', 'import time; time.sleep(120)')\n"
        "    (settings.state_dir / 'controlled-child.txt').write_text(str(child.pid))\n"
        "    try:\n"
        "        await asyncio.sleep(120)\n"
        "    finally:\n"
        "        if child.returncode is None: child.terminate()\n"
        "        await child.wait()\n"
        "    return TrialResult('controlled unavailable network', False)\n"
        "windows_worker.run_trial = controlled_measurement\n"
        "module = windows_control if sys.argv[1] == 'supervisor' else windows_worker\n"
        "raise SystemExit(module.main(sys.argv[2:]))\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows process and Job Object semantics")
@pytest.mark.parametrize("crash", [False, True], ids=["cooperative-stop", "supervisor-crash"])
@pytest.mark.parametrize("attempt", [1, 2, 3], ids=["attempt-1", "attempt-2", "attempt-3"])
async def test_native_supervisor_worker_and_child_lifecycle(tmp_path, monkeypatch, crash, attempt):
    import asyncio
    control = module("windows_control")
    root = native_application(tmp_path)
    launches = []
    original_spawn = control._spawn_supervisor

    async def observed_spawn(*args):
        process = await original_spawn(*args)
        launches.append(process)
        return process

    monkeypatch.setattr(control, "_spawn_supervisor", observed_spawn)

    async def failed_start_details(result, *, point):
        # The failing result remains authoritative. Briefly observe its aftermath
        # so an asynchronously exiting supervisor can finish the safe fault file.
        deadline = time.monotonic() + 1
        while any(process.poll() is None for process in launches) and time.monotonic() < deadline:
            if any((root / "windows-state" / f"fixture-{role}-fault.json").exists()
                   for role in ("supervisor", "worker")):
                break
            await asyncio.sleep(0.05)
        details = {"result": result, "point": point, "attempt": attempt,
                   "created": [{"pid": process.pid, "returncode": process.poll()} for process in launches]}
        details["observed_now"] = control.status(root)
        details["records"] = {}
        for role in ("supervisor", "worker"):
            path = root / "windows-state" / f"fixture-{role}-fault.json"
            try:
                details[role] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
            except (OSError, ValueError):
                details[role] = "fixture-diagnostic-unavailable"
            try:
                record = control.read_record(root, f"{role}.json")
                item = {"present": record is not None}
                if record is not None:
                    item["pid"] = record.get("pid") if type(record.get("pid")) is int else None
                    item["phase"] = (record.get("phase") if record.get("phase") in
                                     {"starting", "ready", "stopping", "stopped"} else "unrecognized")
                    item["exists"] = control.process_exists(record)
                    item["identity_matches"] = control._process_matches(root, record, role)
                details["records"][role] = item
            except Exception as error:
                details["records"][role] = {"error": native_fault_diagnostic(error)}
        return details

    supervisor_pid = worker_pid = child_pid = None
    try:
        first = await control.start(root)
        assert first["status"] == "started", await failed_start_details(first, point="initial-start")
        supervisor_pid = first["pid"]
        second = await control.start(root)
        assert second["status"] == "already-running" and second["pid"] == supervisor_pid, await failed_start_details(second, point="duplicate-start")
        saved = json.loads((root / "windows-state/control/worker.json").read_text())
        worker_pid = saved["pid"]
        deadline = time.monotonic() + 5
        child_file = root / "windows-state/controlled-child.txt"
        while not child_file.exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        child_pid = int(child_file.read_text())
        assert psutil.pid_exists(child_pid)
        if crash:
            psutil.Process(supervisor_pid).kill()
        else:
            stopped = await control.stop(root)
            assert stopped["status"] == "stopped", stopped
        deadline = time.monotonic() + 10
        while any(psutil.pid_exists(pid) for pid in (supervisor_pid, worker_pid, child_pid)) and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        assert not any(psutil.pid_exists(pid) for pid in (supervisor_pid, worker_pid, child_pid))
        assert control.status(root)["state"] == "stopped"
    finally:
        # A failed Start assertion still owns the exact process it launched.
        # Do not leave that process running merely because no ready PID record
        # was observed, and never substitute an unverified PID from a file.
        for created in launches:
            if created.poll() is None:
                await control.stop(root)
                if created.poll() is None:
                    created.kill()
                await asyncio.to_thread(created.wait, 5)
        if supervisor_pid and psutil.pid_exists(supervisor_pid):
            await control.stop(root)
            if psutil.pid_exists(supervisor_pid):
                psutil.Process(supervisor_pid).kill()
        for pid in (worker_pid, child_pid):
            if pid and psutil.pid_exists(pid):
                psutil.Process(pid).kill()

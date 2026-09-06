"""Remember user intent, not stale PIDs; never touch the host's real startup folder."""
import base64
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from test_windows_control import root_at, write_record


def autostart():
    assert importlib.util.find_spec("litechecker.windows_autostart"), "persistent startup is missing"
    return importlib.import_module("litechecker.windows_autostart")


def setup_startup(tmp_path, monkeypatch):
    module = autostart()
    root = root_at(tmp_path)
    installed = {}
    monkeypatch.setattr(module, "set_autostart", lambda root, enabled: installed.update(enabled=enabled))
    return module, root, installed


def test_no_intent_means_stopped_even_with_historical_worker_file(tmp_path, monkeypatch):
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    write_record(root, "supervisor.json", {"phase": "ready", "pid": 2_000_000_000})
    assert module.requested(root) is False


def test_start_and_explicit_stop_survive_reloading_state(tmp_path, monkeypatch):
    module, root, installed = setup_startup(tmp_path, monkeypatch)
    assert module.remember(root, True) is True
    assert installed == {"enabled": True}
    assert module.requested(root) is True
    assert module.remember(root, False) is True
    assert installed == {"enabled": False}
    assert module.requested(root) is False


@pytest.mark.parametrize("value", [{"running": "true"}, {"running": 1}, {}, {"running": True, "extra": 1}])
def test_corrupt_intent_never_enables_background_work(tmp_path, monkeypatch, value):
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    write_record(root, "desired-running.json", value)
    with pytest.raises(ValueError):
        module.requested(root)


def test_shortcut_failure_does_not_lose_explicit_stop(tmp_path, monkeypatch):
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    module.remember(root, True)
    def denied(*args):
        raise OSError("SECRET")
    monkeypatch.setattr(module, "set_autostart", denied)
    assert module.remember(root, False) is False
    assert module.requested(root) is False


def test_concurrent_stop_start_cannot_leave_enabled_intent_without_shortcut(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    module, root, installed = setup_startup(tmp_path, monkeypatch)
    removing, release_remove = threading.Event(), threading.Event()
    starting, finished_start = threading.Event(), threading.Event()
    def apply(root, enabled):
        if not enabled:
            removing.set()
            assert release_remove.wait(2)
        installed["enabled"] = enabled
    monkeypatch.setattr(module, "set_autostart", apply)
    def start():
        starting.set()
        module.remember(root, True)
        finished_start.set()
    with ThreadPoolExecutor(2) as pool:
        stopped = pool.submit(module.remember, root, False)
        assert removing.wait(2)
        started = pool.submit(start)
        assert starting.wait(2)
        try:
            assert not finished_start.wait(.1), "Start passed an unfinished Stop registration"
        finally:
            release_remove.set()
        stopped.result(timeout=3)
        started.result(timeout=3)
    assert module.requested(root) is True and installed["enabled"] is True


@pytest.mark.asyncio
async def test_reboot_resumes_then_manual_stop_survives_another_reboot(tmp_path, monkeypatch):
    from litechecker import windows_control as control
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    spawned = []
    async def spawn(root, instance):
        spawned.append(instance)
        write_record(root, "supervisor.json", {"instance": instance})
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(control, "_spawn_supervisor", spawn)
    monkeypatch.setattr(control, "status", lambda _: {"state": "running" if spawned else "stopped"})
    module.remember(root, True)
    result = await control.start(root, resume=True)
    assert result["status"] == "started"
    assert len(spawned) == 1
    # Another logon shortcut/menu must not duplicate the already running process.
    assert (await control.start(root, resume=True))["status"] == "already-running"
    assert len(spawned) == 1
    spawned.clear()  # simulated shutdown, no controller Stop
    assert (await control.start(root, resume=True))["status"] == "started"
    spawned.clear()
    assert (await control.stop(root))["status"] == "stopped"
    assert (await control.start(root, resume=True))["status"] == "stopped"
    assert spawned == []


@pytest.mark.asyncio
async def test_stop_during_supervisor_start_does_not_restore_running_intent(tmp_path, monkeypatch):
    from litechecker import windows_control as control
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    async def spawn(root, instance):
        # Stop can happen after process creation but before its identity is published.
        assert (await control.stop(root))["status"] == "stopped"
        write_record(root, "supervisor.json", {"instance": instance})
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(control, "_spawn_supervisor", spawn)
    monkeypatch.setattr(control, "status", lambda _: {"state": "stopped"})
    result = await control.start(root)
    assert result["status"] == "stopping"
    assert module.requested(root) is False
    state = root / "windows-state/control"
    assert json.loads((state / "supervisor-stop.json").read_text())["instance"] == json.loads((state / "supervisor.json").read_text())["instance"]


@pytest.mark.asyncio
async def test_stop_after_start_deadline_still_cancels_unpublished_baseline_supervisor(tmp_path, monkeypatch):
    from litechecker import windows_control as control
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    instances = []
    async def spawn(root, instance):
        instances.append(instance)
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(control, "_spawn_supervisor", spawn)
    monkeypatch.setattr(control, "status", lambda _: {"state": "stopped"})
    monkeypatch.setattr(control, "_START_TIMEOUT", 0)
    assert (await control.start(root))["status"] == "starting"
    assert (await control.stop(root))["status"] == "stopped"
    path = root / "windows-state/control/supervisor-stop.json"
    assert path.is_file(), "Stop lost the nonce of a launched but unpublished process"
    assert json.loads(path.read_text()) == {"instance": instances[0]}
    assert module.requested(root) is False


@pytest.mark.asyncio
async def test_two_late_supervisors_both_respect_persisted_stop(tmp_path, monkeypatch):
    from litechecker import windows_control as control, windows_worker as worker
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    instances = []
    async def spawn(root, instance):
        instances.append(instance)
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(control, "_spawn_supervisor", spawn)
    monkeypatch.setattr(control, "status", lambda _: {"state": "stopped"})
    monkeypatch.setattr(control, "_START_TIMEOUT", 0)
    await control.start(root)
    await control.start(root)
    await control.stop(root)
    assert len(instances) == 2 and module.requested(root) is False
    async def gate(*args):
        return {"instance": "a" * 32, "supervisor_instance": instances[0]}
    monkeypatch.setattr(worker, "wait_for_gate", gate)
    def forbidden(*args):
        pytest.fail("an older pending worker measured after explicit Stop")
    monkeypatch.setattr(worker, "validate", forbidden)
    await worker.run_worker(root, root, "a" * 32)


@pytest.mark.asyncio
async def test_legacy_adoption_cannot_overwrite_intervening_manual_stop(tmp_path, monkeypatch):
    from litechecker import windows_control as control
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    def observed(_):
        module.remember(root, False)
        return {"state": "running"}
    monkeypatch.setattr(control, "status", observed)
    await control.start(root, resume=True, adopt=True)
    assert module.requested(root) is False


def test_shortcut_targets_stable_entry_not_a_cleanable_update(tmp_path, monkeypatch):
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    python = root / ".windows-native/venv/Scripts/python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fixture")
    entry = root / "scripts/windows-app-entry.py"
    entry.parent.mkdir()
    entry.write_text("# fixture")
    monkeypatch.setattr(module, "runtime_python", lambda root, **kwargs: python)
    spec = module.shortcut_spec(root)
    assert spec["target"] == str(python)
    assert spec["arguments"] == subprocess.list2cmdline(["-I", "-B", str(entry), "menu", "--root", str(root)])
    assert ".updates" not in spec["arguments"]
    assert spec["working_directory"] == str(root)
    assert spec["name"].startswith("LiteChecker-") and spec["name"].endswith(".lnk")


def test_menu_restores_monitoring_before_waiting_for_input(tmp_path, monkeypatch):
    from litechecker import windows_app as app, windows_control as control
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    module.remember(root, True)
    calls = []
    async def resume(value, *, resume=False):
        calls.append(("resume", value, resume))
        return {"status": "started", "state": "running"}
    monkeypatch.setattr(control, "start", resume)
    monkeypatch.setattr(app, "ensure_update_channel", lambda _: True)
    monkeypatch.setattr(app, "ensure_initial_settings", lambda _: True)
    monkeypatch.setattr(app, "run_menu", lambda value: calls.append(("menu", value)) or 0)
    assert app.main(["--root", str(root)]) == 0
    assert calls == [("resume", root, True), ("menu", root)]


def test_corrupt_intent_does_not_hide_menu_or_stop_action(tmp_path, monkeypatch):
    from litechecker import windows_app as app
    _, root, _ = setup_startup(tmp_path, monkeypatch)
    write_record(root, "desired-running.json", {"running": "corrupt"})
    opened = []
    monkeypatch.setattr(app, "ensure_update_channel", lambda _: True)
    monkeypatch.setattr(app, "ensure_initial_settings", lambda _: True)
    monkeypatch.setattr(app, "run_menu", lambda value: opened.append(value) or 0)
    assert app.main(["--root", str(root)]) == 0
    assert opened == [root]


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows shortcut COM")
def test_native_shortcut_is_idempotent_and_removes_only_owned_entry(tmp_path, monkeypatch):
    module, root, _ = setup_startup(tmp_path, monkeypatch)
    from litechecker.windows_update import powershell_path
    # Redirect only the OS folder lookup. Creating/reading .lnk files uses the
    # actual Windows COM implementation, never the user's real Startup folder.
    folder = tmp_path / "Startup test"
    folder.mkdir()
    prefix = r"""
$global:realShell = [Activator]::CreateInstance([type]::GetTypeFromProgID('WScript.Shell'))
$folders = [pscustomobject]@{}
$folders | Add-Member ScriptMethod Item { param($name) if ($name -cne 'Startup') { throw 'Wrong folder' }; return $env:LC_TEST_STARTUP_FOLDER }
$global:fakeShell = [pscustomobject]@{ SpecialFolders = $folders }
$global:fakeShell | Add-Member ScriptMethod CreateShortcut { param($path) return $global:realShell.CreateShortcut($path) }
function New-Object { param($ComObject) if ($ComObject -cne 'WScript.Shell') { throw 'Wrong COM type' }; return $global:fakeShell }
"""
    spec = {"name": "LiteChecker-controlled.lnk", "target": sys.executable,
            "arguments": '-I -c "print(123)"', "working_directory": str(root)}
    def run(enabled, **changes):
        return subprocess.run(
            [str(powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode((prefix + module._SHORTCUT_SCRIPT).encode("utf-16le")).decode("ascii")],
            env={**os.environ, "LC_TEST_STARTUP_FOLDER": str(folder),
                 "LITECHECKER_STARTUP_SPEC": json.dumps({**spec, "enabled": enabled, **changes})},
            capture_output=True, timeout=30,
        ).returncode
    assert run(True) == 0
    shortcut = folder / spec["name"]
    original = shortcut.read_bytes()
    assert run(True) == 0 and shortcut.read_bytes() == original
    assert run(False, arguments="foreign command") != 0
    assert shortcut.read_bytes() == original
    other = folder / "unrelated.lnk"
    other.write_bytes(b"do not delete")
    assert run(False) == 0 and not shortcut.exists()
    assert other.read_bytes() == b"do not delete"

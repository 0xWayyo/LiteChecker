"""Signed profiled updates must change the next menu without moving user data."""
import asyncio
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
import time

import pytest

from litechecker import distribution, updater
from litechecker.update_store import UpdateStore
from platform_package_support import extracted_profile, local_runtime
from test_platform_distribution import script
from test_platform_updates import run_release, signed
from test_updater import Adapter


def candidate_archive(root, version, extra_files=None):
    files = {}
    manifest = json.loads((root / "CONTENTS.sha256.json").read_bytes())
    for name in manifest:
        files[name] = (root / name).read_bytes()
    files["pyproject.toml"] = files["pyproject.toml"].replace(b'"0.6.3"', json.dumps(version).encode())
    files["uv.lock"] = files["uv.lock"].replace(b'version = "0.6.3"', ('version = "' + version + '"').encode())
    # Only this visible UI label changes; all dispatch and storage code is real.
    name = "src/litechecker/windows_app.py" if os.name == "nt" else "scripts/control.sh"
    files[name] = files[name].replace(b"header LITECHECKER", ("header MENU-" + version).encode())
    files[name] = files[name].replace(b'frame("LITECHECKER",', ('frame("MENU-' + version + '",').encode())
    files.update(extra_files or {})
    return script("package_platforms")._archive(files)


class PreparedAdapter(Adapter):
    async def prepare(self, release):
        await super().prepare(release)
        local_runtime(release)


def command(root):
    if os.name == "nt":
        return [sys.executable, "-I", "-B", str(root / "scripts/windows-app-entry.py"), "menu", "--root", str(root)]
    return ["bash", str(root / "scripts/control.sh")]


@pytest.mark.skipif(os.name == "nt", reason="Windows pinned runtime scenario runs in native CI")
@pytest.mark.asyncio
async def test_signed_update_next_menu_uses_candidate_and_keeps_baseline_settings(tmp_path):
    root, key = extracted_profile(tmp_path, distribution.host_platform())
    local_runtime(root)
    from test_platform_updates import channel
    updater.initialize_channel(root, channel(key.public_key().public_bytes_raw(), distribution.host_platform()))
    adapter = PreparedAdapter(root, running=False)
    data = candidate_archive(root, "0.7.0")
    result = await run_release(root, adapter, signed(key, data, platform=distribution.host_platform()), data)
    assert result["status"] == "updated", result
    env = {**os.environ, "LITECHECKER_NATIVE_ROOT": str(root)}
    from filelock import FileLock
    with FileLock(root / ".updates/update.lock", preserve_lock_file=True):
        run = subprocess.run(command(root), input="0\n", text=True, capture_output=True, env=env, timeout=10)
    assert run.returncode == 0, run.stderr
    assert "MENU-0.7.0" in run.stdout
    assert "MENU-0.7.0 · v0.7.0" in run.stdout
    assert " · v0.6.3" not in run.stdout
    folder = subprocess.run(command(root) + ["folder"], text=True, capture_output=True, env=env, timeout=10)
    assert str(root) in folder.stdout
    assert str(root / ".updates/releases/0.7.0") not in folder.stdout
    assert adapter.running is False
    assert all(running is False for _, running in adapter.activations)


def test_cleanup_keeps_pending_release_until_transaction_resolves(tmp_path):
    from litechecker.update_store import validate_source_zip
    from test_platform_updates import archive
    from windows_test_support import secure_test_directory
    secure_test_directory(tmp_path)
    store = UpdateStore(tmp_path.resolve())
    candidate = store.stage("0.7.0", validate_source_zip(archive()))
    state = store.read_install()
    state["pending"] = dict(from_version=None, to_version="0.7.0", sequence=9,
                            digest="a" * 64, was_running=False)
    store.write_install(state)
    store.cleanup(active=None, previous=None, now=datetime.now(timezone.utc))
    assert candidate.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="Windows pinned runtime scenario runs in native CI")
@pytest.mark.parametrize("prepared", [False, True])
def test_wrong_target_menu_does_not_execute_even_before_configuration(tmp_path, prepared):
    wrong = "linux" if sys.platform == "darwin" else "macos"
    root, _ = extracted_profile(tmp_path, wrong)
    if prepared:
        local_runtime(root)
    run = subprocess.run(command(root), input="0\n", text=True, capture_output=True,
                         env={**os.environ, "LITECHECKER_NATIVE_ROOT": str(root)}, timeout=10)
    assert run.returncode != 0
    assert "Выберите цифру" not in run.stdout
    assert not (root / ".updates").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX recovery shell")
def test_corrupt_selector_keeps_baseline_recovery_menu(tmp_path):
    root, _ = extracted_profile(tmp_path, distribution.host_platform())
    local_runtime(root)
    (root / ".updates").mkdir(mode=0o700)
    (root / ".updates/install.json").write_text('{"active":"../escape"}')
    run = subprocess.run(command(root), input="0\n", text=True, capture_output=True,
                         env={**os.environ, "LITECHECKER_NATIVE_ROOT": str(root)}, timeout=10)
    assert run.returncode == 0, run.stderr
    assert "LITECHECKER" in run.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe inheritance; Windows uses real pinned CI runtime")
def test_child_gate_eof_exits_without_importing_ui_and_stale_identity_never_pins(tmp_path):
    import psutil
    from litechecker.runtime_lease import _command, dispatch_lock, live_versions
    from litechecker.update_store import validate_source_zip
    root, _ = extracted_profile(tmp_path, distribution.host_platform())
    data = candidate_archive(root, "0.7.0")
    store = UpdateStore(root)
    candidate = store.stage("0.7.0", validate_source_zip(data))
    local_runtime(candidate)
    read_gate, write_gate = os.pipe()
    nonce = "c" * 32
    command_line = _command(root, candidate, read_gate, nonce, "menu")
    process = subprocess.Popen(command_line, pass_fds=(read_gate,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    record = dict(owner="litechecker-menu-v1", pid=process.pid,
                  created=psutil.Process(process.pid).create_time(), version="0.7.0",
                  gate=read_gate, nonce=nonce, action="menu")
    lease = store.updates / f"menu-{nonce}.json"
    try:
        store._atomic_json(lease, record)
        with dispatch_lock(root):
            assert live_versions(root) == {"0.7.0"}
        # A PID reused with a different creation time never pins this release.
        store._atomic_json(lease, {**record, "created": record["created"] - 20})
        with dispatch_lock(root):
            assert live_versions(root) == set()
        store._atomic_json(lease, record)
        os.close(write_gate)
        write_gate = None
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 1 and stdout == b"", stderr
        with dispatch_lock(root):
            assert live_versions(root) == set()
        assert not lease.exists()
    finally:
        os.close(read_gate)
        if write_gate is not None:
            os.close(write_gate)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


@pytest.mark.skipif(os.name == "nt", reason="POSIX wizard child lifetime")
@pytest.mark.asyncio
async def test_settings_child_retains_runtime_after_actual_menu_sigkill(tmp_path):
    import psutil
    from test_platform_updates import channel
    root, key = extracted_profile(tmp_path, distribution.host_platform())
    local_runtime(root)
    # Replace only the OS service boundary: this fixture must never run a host
    # service. The signed candidate, actual Bash and actual Python are real.
    (root / "run.sh").write_text('#!/bin/bash\nexit 0\n')
    updater.initialize_channel(root, channel(key.public_key().public_bytes_raw(), distribution.host_platform()))
    adapter = PreparedAdapter(root, running=False)
    wizard = ("import os,sys\nfrom pathlib import Path\n"
              "root=Path(sys.argv[sys.argv.index('--root')+1])\n"
              "(root/'child.ready').write_text(str(os.getpid()))\n"
              "sys.stdin.readline()\n")
    data = candidate_archive(root, "0.7.0", {"src/litechecker/device_setup.py": wizard.encode()})
    result = await run_release(root, adapter, signed(key, data, platform=distribution.host_platform()), data)
    assert result["status"] == "updated"
    output = (tmp_path / "wizard.log").open("w")
    menu = subprocess.Popen(command(root) + ["settings"], stdin=subprocess.PIPE, stdout=output, stderr=output,
                            env={**os.environ, "LITECHECKER_NATIVE_ROOT": str(root)})
    child_pid = None
    try:
        menu.stdin.write(b"y\n"); menu.stdin.flush()
        deadline = time.monotonic() + 10
        while not (root / "child.ready").exists():
            assert menu.poll() is None and time.monotonic() < deadline
            await asyncio.sleep(.02)
        child_pid = int((root / "child.ready").read_text())
        record = json.loads(next((root / ".updates").glob("menu-*.json")).read_bytes())
        psutil.Process(record["pid"]).kill()  # The real bash menu, not its launcher.
        menu.wait(timeout=5)
        assert psutil.Process(child_pid).is_running()
        for version, sequence in (("0.8.0", 10), ("0.9.0", 11)):
            data = candidate_archive(root, version)
            result = await run_release(root, adapter, signed(key, data, version=version,
                sequence=sequence, platform=distribution.host_platform()), data)
            assert result["status"] == "updated", result
        old = root / ".updates/releases/0.7.0"
        assert (old / "src/litechecker/device_setup.py").is_file()
        menu.stdin.write(b"\n"); menu.stdin.flush()
        deadline = time.monotonic() + 5
        while old.exists() and time.monotonic() < deadline:
            updater.cleanup_updates(root)
            await asyncio.sleep(.02)
        assert not old.exists()
        assert not list((root / ".updates").glob("menu-*.lock"))
    finally:
        menu.stdin.close()
        if menu.poll() is None:
            menu.kill()
        menu.wait(timeout=5)
        if child_pid:
            try:
                psutil.Process(child_pid).kill()
            except psutil.NoSuchProcess:
                pass
        output.close()


@pytest.mark.skipif(os.name == "nt", reason="Windows pinned runtime scenario runs in native CI")
@pytest.mark.parametrize("kill_launcher", [False, True])
@pytest.mark.asyncio
async def test_menu_survives_two_more_updates_and_releases_after_exit(tmp_path, kill_launcher):
    from test_platform_updates import channel
    root, key = extracted_profile(tmp_path, distribution.host_platform())
    local_runtime(root)
    updater.initialize_channel(root, channel(key.public_key().public_bytes_raw(), distribution.host_platform()))
    adapter = PreparedAdapter(root, running=False)

    async def update(version, sequence):
        data = candidate_archive(root, version)
        result = await run_release(root, adapter, signed(key, data, version=version,
            sequence=sequence, platform=distribution.host_platform()), data)
        assert result["status"] == "updated", result

    await update("0.7.0", 9)
    transcript = tmp_path / "menu.log"
    with transcript.open("w") as output:
        menu = subprocess.Popen(command(root), stdin=subprocess.PIPE, stdout=output, stderr=output,
                                env={**os.environ, "LITECHECKER_NATIVE_ROOT": str(root)})
        try:
            deadline = time.monotonic() + 10
            while "MENU-0.7.0" not in transcript.read_text():
                assert menu.poll() is None and time.monotonic() < deadline, transcript.read_text()
                await asyncio.sleep(.02)
            if kill_launcher:
                menu.kill()
                menu.wait(timeout=5)
            await update("0.8.0", 10)
            await update("0.9.0", 11)
            old = root / ".updates/releases/0.7.0"
            assert (old / "scripts/control.sh").is_file()
            menu.stdin.write(b"0\n")
            menu.stdin.flush()
            if not kill_launcher:
                assert menu.wait(timeout=5) == 0
            deadline = time.monotonic() + 5
            while old.exists() and time.monotonic() < deadline:
                updater.cleanup_updates(root)
                await asyncio.sleep(.02)
            assert not old.exists()
            assert (root / "scripts/control.sh").is_file()
        finally:
            menu.stdin.close()
            if menu.poll() is None:
                menu.kill()
            menu.wait(timeout=5)

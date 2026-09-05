"""Native adapter controls only the owned worker and preserves signed transactions."""
import base64
import asyncio
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import stat
import sys
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


def put(path, payload=b"fixture"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o700)


def installation(tmp_path):
    from windows_test_support import secure_test_directory
    secure_test_directory(tmp_path)
    root = (tmp_path / "LiteChecker с пробелами" / "_app").resolve()
    files = {
        "pyproject.toml": b'[project]\nname="litechecker"\nversion="0.5.0"\n',
        "scripts/windows-native.ps1": b"# fixture bootstrap",
        "scripts/windows-app-entry.py": b"# fixture isolated entry",
        "src/litechecker/windows_worker.py": b"# fixture worker",
    }
    for name, payload in files.items():
        put(root / name, payload)
    put(root / "windows-state/settings.json", b"preserve-private-settings")
    put(root / "windows-state/device.json", b"preserve-device")
    runtime(root)
    return root, files


def runtime(release):
    put(release / ".windows-native/venv/Scripts/python.exe")
    put(release / ".windows-native/tools/xray/xray.exe")


class Runner:
    def __init__(self):
        self.calls = []
        self.failure = False

    async def __call__(self, args, *, cwd, timeout, python_release=None):
        if "--validate" in args:
            assert python_release == cwd
        self.calls.append((list(map(str, args)), cwd, timeout))
        if self.failure:
            raise RuntimeError("SECRET must never reach error text")
        if "Prepare" in args:
            script = Path(args[args.index("-File") + 1])
            runtime(script.parent.parent)


@pytest.fixture
def windows_runtime(monkeypatch):
    # OS boundary only: real source guards/adapter/transaction still execute.
    assert importlib.util.find_spec("litechecker.windows_update") is not None, "Windows update adapter is not implemented"
    from litechecker import windows_update
    monkeypatch.setattr(windows_update, "runtime_python", lambda release, **kw: release / ".windows-native/venv/Scripts/python.exe")
    return windows_update


@pytest.mark.asyncio
async def test_prepare_uses_candidate_runtime_and_baseline_data_without_start(tmp_path, windows_runtime):
    root, files = installation(tmp_path)
    candidate = root / ".updates/releases/0.6.0"
    for name, payload in files.items():
        put(candidate / name, payload)
    put(candidate / ".litechecker-update-owned", b"litechecker-updater-v1\n")
    put(candidate / ".artifact.sha256", b"a" * 64 + b"\n")
    runner = Runner()
    adapter = windows_runtime.WindowsUpdateAdapter(root, runner=runner, powershell=Path("powershell.exe"))
    await adapter.prepare(candidate)
    assert adapter.maintenance_lock == root / "windows-state/maintenance.lock"
    assert runner.calls[0][0] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(candidate / "scripts/windows-native.ps1"), "-Root", str(root), "-Action", "Prepare"]
    validate = runner.calls[1][0]
    assert validate == [str(candidate / ".windows-native/venv/Scripts/python.exe"), "-I", "-B", str(candidate / "scripts/windows-app-entry.py"), "worker", "--validate", "--root", str(root), "--release", str(candidate)]
    assert (root / "windows-state/settings.json").read_bytes() == b"preserve-private-settings"
    assert not (candidate / "windows-state").exists()


@pytest.mark.asyncio
async def test_stopped_activation_never_creates_worker_and_errors_are_closed(tmp_path, windows_runtime):
    root, _ = installation(tmp_path)
    runner = Runner()
    adapter = windows_runtime.WindowsUpdateAdapter(root, runner=runner, powershell=Path("powershell.exe"))
    assert await adapter.is_running() is False
    await adapter.activate(root, False)
    assert await adapter.healthy(root, False) is True
    with pytest.raises(windows_runtime.WindowsUpdateError):
        await adapter.activate(root, True)
    runner.failure = True
    assert await adapter.healthy(root, False) is False
    with pytest.raises(windows_runtime.WindowsUpdateError) as failure:
        await adapter.prepare(root)
    assert "SECRET" not in str(failure.value)


@pytest.mark.asyncio
async def test_adapter_delegates_worker_health_not_remote_network(tmp_path, windows_runtime):
    root, _ = installation(tmp_path)
    class Host:
        active = None
        def is_running(self):
            return True
        async def activate_release(self, release, running):
            self.active = (release, running)
        async def healthy_release(self, release, running):
            return self.active == (release, running)
    host = Host()
    adapter = windows_runtime.WindowsUpdateAdapter(root, host=host, runner=Runner(), powershell=Path("powershell.exe"))
    assert await adapter.is_running() is True
    await adapter.activate(root, True)
    assert await adapter.healthy(root, True) is True
    assert host.active == (root, True)


@pytest.mark.asyncio
async def test_foreign_release_refused_before_any_command(tmp_path, windows_runtime):
    root, _ = installation(tmp_path)
    outsider = tmp_path / "foreign"
    outsider.mkdir()
    runner = Runner()
    adapter = windows_runtime.WindowsUpdateAdapter(root, runner=runner, powershell=Path("powershell.exe"))
    with pytest.raises(windows_runtime.WindowsUpdateError):
        await adapter.prepare(outsider)
    unowned = root / ".updates/releases/0.6.0"
    unowned.mkdir(parents=True)
    with pytest.raises(windows_runtime.WindowsUpdateError):
        await adapter.prepare(unowned)
    assert runner.calls == []


def signed_payload(files, key, version, sequence):
    from litechecker.update_manifest import canonical_payload
    files = {**files, "pyproject.toml": f'[project]\nname="litechecker"\nversion="{version}"\n'.encode()}
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    files["CONTENTS.sha256.json"] = json.dumps(manifest).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    data = buffer.getvalue()
    payload = {"version": version, "sequence": sequence, "published_at": "2026-09-06T00:00:00Z", "artifact": {"urls": ["https://example.com/source.zip"], "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}}
    envelope = {"schema": 1, "payload": payload, "signature": base64.b64encode(key.sign(canonical_payload(payload))).decode()}
    return {"https://example.com/release.json": json.dumps(envelope).encode(), "https://example.com/source.zip": data}


@pytest.mark.asyncio
async def test_real_signed_stopped_update_and_tamper_preserve_private_state(tmp_path, windows_runtime):
    from litechecker.updater import check_for_update, initialize_channel
    root, files = installation(tmp_path)
    key = Ed25519PrivateKey.generate()
    channel = {"schema": 1, "enabled": True, "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(), "manifest_urls": ["https://example.com/release.json"]}
    initialize_channel(root, json.dumps(channel).encode())
    responses = signed_payload(files, key, "0.6.0", 6)
    async def fetch(url, limit):
        assert len(responses[url]) <= limit
        return responses[url]
    runner = Runner()
    adapter = windows_runtime.WindowsUpdateAdapter(root, runner=runner, powershell=Path("powershell.exe"))
    result = await check_for_update(root, adapter, force=True, fetcher=fetch)
    assert result["status"] == "updated", result
    assert result["version"] == "0.6.0"
    assert await adapter.is_running() is False
    assert all("--validate" in args or "Prepare" in args for args, *_ in runner.calls)
    responses = signed_payload(files, Ed25519PrivateKey.generate(), "0.7.0", 7)
    result = await check_for_update(root, adapter, force=True, fetcher=fetch)
    assert result["status"] == "failed"
    assert result["version"] == "0.6.0"
    assert (root / "windows-state/settings.json").read_bytes() == b"preserve-private-settings"
    assert (root / "windows-state/device.json").read_bytes() == b"preserve-device"


@pytest.mark.asyncio
async def test_real_signed_transaction_rolls_back_failed_worker_activation(tmp_path, windows_runtime):
    from litechecker.updater import check_for_update, initialize_channel
    from litechecker.update_launcher import select_release
    root, files = installation(tmp_path)
    key = Ed25519PrivateKey.generate()
    initialize_channel(root, json.dumps({"schema": 1, "enabled": True,
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "manifest_urls": ["https://example.com/release.json"]}).encode())
    responses = signed_payload(files, key, "0.6.0", 6)
    async def fetch(url, limit):
        return responses[url]
    class Host:
        activations = []
        def is_running(self):
            return True
        async def activate_release(self, release, running):
            self.activations.append((release, running))
        async def healthy_release(self, release, running):
            return release == root
    host = Host()
    adapter = windows_runtime.WindowsUpdateAdapter(root, host=host, runner=Runner(), powershell=Path("powershell.exe"))
    result = await check_for_update(root, adapter, force=True, fetcher=fetch)
    assert result["status"] == "rolled-back", result
    assert host.activations == [(root / ".updates/releases/0.6.0", True), (root, True)]
    assert select_release(root) == root
    assert (root / "windows-state/settings.json").read_bytes() == b"preserve-private-settings"


@pytest.mark.skipif(sys.platform != "win32", reason="actual Windows Job Object process cleanup")
@pytest.mark.parametrize("failure", ["timeout", "output", "cancel"])
@pytest.mark.asyncio
async def test_native_prepare_runner_cleans_owned_descendants_and_gate(tmp_path, failure):
    import psutil
    from litechecker.windows_update import run_command, WindowsUpdateError
    from windows_test_support import secure_test_directory
    secure_test_directory(tmp_path)
    root = tmp_path / "_app"
    root.mkdir()
    script = root / "prepare-fixture.py"
    # Real child/grandchild processes, no network, no uv or production settings.
    script.write_text('''import pathlib, subprocess, sys, time
args = sys.argv
root = pathlib.Path(args[args.index('-Root') + 1])
nonce = args[args.index('-PrepareGate') + 1]
gate = root / 'windows-state' / ('prepare-' + nonce + '.gate')
deadline = time.monotonic() + 10
while not gate.exists() and time.monotonic() < deadline: time.sleep(.02)
assert gate.read_text() == nonce
child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(120)'])
(root / 'child.pid').write_text(str(child.pid))
if args[args.index('-Mode') + 1] == 'output':
    print('X' * 70000, flush=True)
time.sleep(120)
''', encoding="utf-8")
    task = asyncio.create_task(run_command(
        [sys.executable, "-I", str(script), "-Action", "Prepare", "-Root", str(root), "-Mode", failure],
        cwd=root, timeout=5 if failure == "timeout" else 30))
    async with asyncio.timeout(15):
        while not (root / "child.pid").exists():
            if task.done():
                await task
                pytest.fail("prepare process exited before gated child startup")
            await asyncio.sleep(.05)
    pid = int((root / "child.pid").read_text())
    if failure == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(WindowsUpdateError):
            await task
    async with asyncio.timeout(5):
        while psutil.pid_exists(pid):
            await asyncio.sleep(.05)
    assert not list((root / "windows-state").glob("prepare-*.gate"))

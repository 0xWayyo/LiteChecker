"""Actual NTFS cleanup boundaries; no network, Windows API mocks or global state."""

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from litechecker import update_launcher, update_store
from litechecker.update_manifest import canonical_payload, verify_release_metadata
from windows_test_support import secure_test_directory


pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows ACL/NTFS boundary")
NOW = datetime(2026, 9, 6, tzinfo=timezone.utc)


def _signed_archive(version, key):
    """Bind each minimal source ZIP to locally authenticated release metadata."""
    files = {
        "pyproject.toml": f'[project]\nname="litechecker"\nversion="{version}"\n'.encode(),
        "src/litechecker/payload.py": b"# controlled source; never executed\n",
    }
    files["CONTENTS.sha256.json"] = json.dumps({
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()
    }).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for name, data in files.items():
            item = zipfile.ZipInfo("LiteChecker/" + name)
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | 0o644) << 16
            output.writestr(item, data)
    data = stream.getvalue()
    payload = {
        "version": version, "sequence": int(version.split(".")[1]),
        "published_at": "2026-09-06T00:00:00Z",
        "artifact": {"urls": ["https://example.com/never-fetched.zip"],
                     "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
    }
    envelope = {"schema": 1, "payload": payload,
                "signature": base64.b64encode(key.sign(canonical_payload(payload))).decode()}
    metadata = verify_release_metadata(json.dumps(envelope).encode(), key.public_key().public_bytes_raw())
    assert metadata.version == version
    return update_store.validate_source_zip(
        data, expected_sha256=metadata.artifact.sha256, expected_size=metadata.artifact.size,
    )


@pytest.fixture
def private_store(tmp_path):
    root = tmp_path / "LiteChecker с пробелами" / "_app"
    root.mkdir(parents=True)
    secure_test_directory(root)
    store = update_store.UpdateStore(root)
    store.ensure_layout()
    state = root / "windows-state"
    state.mkdir()
    (state / "settings.json").write_bytes(b"private settings must survive cleanup")
    (state / "device.json").write_bytes(b"stable device identity")
    foreign = store.releases / "0.0.9"
    foreign.mkdir()
    (foreign / "keep.txt").write_bytes(b"not updater-owned")
    return root, store, Ed25519PrivateKey.generate()


@contextmanager
def _deny_delete(path):
    """Hold one known test file without FILE_SHARE_DELETE, not an executable."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 0x1 | 0x2, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _assert_preserved(root, store):
    assert (root / "windows-state/settings.json").read_bytes() == b"private settings must survive cleanup"
    assert (root / "windows-state/device.json").read_bytes() == b"stable device identity"
    assert (store.releases / "0.0.9/keep.txt").read_bytes() == b"not updater-owned"
    for version in ("0.2.0", "0.3.0"):
        release = store.releases / version
        assert (release / "pyproject.toml").read_bytes() == (
            f'[project]\nname="litechecker"\nversion="{version}"\n'.encode()
        )
        assert (release / "src/litechecker/payload.py").read_bytes() == b"# controlled source; never executed\n"
        assert (release / update_store.OWNED_MARKER).read_bytes() == b"litechecker-updater-v1\n"
    assert update_launcher.select_release(root) == store.releases / "0.3.0"


def _stage_retained_releases(store, key):
    for version in ("0.2.0", "0.3.0"):
        archive = _signed_archive(version, key)
        release = store.stage(version, archive)
        digest = (release / update_store.ARTIFACT_DIGEST).read_bytes()
        assert len(digest) == 65
        assert digest == archive.sha256.encode("ascii") + b"\n"
    state = update_store.default_install_state()
    state.update(active="0.3.0", previous="0.2.0")
    store.write_install(state)


def test_native_cleanup_keeps_locked_marker_then_retries_only_owned_obsolete_release(private_store):
    # Removing the marker before children, treating sharing failure as success,
    # or sweeping retained/unowned releases must make this test fail.
    root, store, key = private_store
    obsolete = store.stage("0.1.0", _signed_archive("0.1.0", key))
    _stage_retained_releases(store, key)
    locked = obsolete / "src/litechecker/payload.py"
    install_before = store.install_path.read_bytes()
    with _deny_delete(locked):
        with pytest.raises(PermissionError) as blocked:
            locked.unlink()
        assert blocked.value.winerror == 32, "fixture must cause a real sharing violation"
        result = store.cleanup(active="0.3.0", previous="0.2.0", now=NOW)
        assert result == {"releases": 0, "temporary": 0, "deferred": 1}
        assert locked.read_bytes() == b"# controlled source; never executed\n"
        assert (obsolete / update_store.OWNED_MARKER).read_bytes() == b"litechecker-updater-v1\n"
        assert store.install_path.read_bytes() == install_before
        _assert_preserved(root, store)

    result = store.cleanup(active="0.3.0", previous="0.2.0", now=NOW)
    assert result == {"releases": 1, "temporary": 0}
    assert not obsolete.exists()
    assert sorted(path.name for path in store.releases.iterdir()) == ["0.0.9", "0.2.0", "0.3.0"]
    assert store.install_path.read_bytes() == install_before
    _assert_preserved(root, store)


@pytest.mark.parametrize("placement", ["nested", "release"])
def test_native_cleanup_and_launcher_reject_junction_without_touching_target(private_store, tmp_path, placement):
    # Dropping ancestor reparse checks or following junctions while cleaning an
    # owned release must fail without relying on a simulated symlink flag.
    root, store, key = private_store
    _stage_retained_releases(store, key)
    outside = tmp_path / "outside updater storage"
    outside.mkdir()
    secure_test_directory(outside)
    sentinel = outside / "keep.txt"
    sentinel.write_bytes(b"outside user data")
    # Even a target with an apparently valid ownership marker is not in scope.
    (outside / update_store.OWNED_MARKER).write_bytes(b"litechecker-updater-v1\n")
    if placement == "nested":
        obsolete = store.stage("0.1.0", _signed_archive("0.1.0", key))
        junction = obsolete / "linked-data"
    else:
        junction = store.releases / "0.1.0"
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 0, repr(result.stdout + result.stderr)
    try:
        assert junction.is_junction(), "fixture must be an actual NTFS directory junction"
        with pytest.raises(update_launcher.LauncherError):
            update_launcher.checked_path(root, junction / "keep.txt", regular=True)
        assert store.remove_release("0.1.0") is False
        result = store.cleanup(active="0.3.0", previous="0.2.0", now=NOW)
        assert result["releases"] == 0
        assert sentinel.read_bytes() == b"outside user data"
        assert (outside / update_store.OWNED_MARKER).read_bytes() == b"litechecker-updater-v1\n"
        assert junction.is_junction()
        if placement == "nested":
            assert result["deferred"] == 1
            assert (obsolete / "src/litechecker/payload.py").read_bytes() == b"# controlled source; never executed\n"
            assert (obsolete / update_store.OWNED_MARKER).read_bytes() == b"litechecker-updater-v1\n"
        _assert_preserved(root, store)
    finally:
        # Remove this exact test-owned link, never recursively remove its target.
        if junction.is_junction():
            junction.rmdir()

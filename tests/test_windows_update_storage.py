"""Windows updater contracts; only native ACL/reparse boundaries are simulated."""
from datetime import datetime, timezone
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest

from litechecker import update_launcher, update_store, updater


def source_zip(files=None):
    files = files or {"pyproject.toml": b'[project]\nversion="0.5.0"\n', "scripts/run.sh": b"run"}
    contents = {**files, "CONTENTS.sha256.json": json.dumps({name: hashlib.sha256(data).hexdigest() for name, data in files.items()}).encode()}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in contents.items():
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16
            archive.writestr(info, data)
    return stream.getvalue()


@pytest.fixture
def windows(monkeypatch):
    from litechecker import windows_security
    monkeypatch.setattr(windows_security, "is_windows", lambda: True)
    # GetNamedSecurityInfo/GetTokenInformation are the native OS boundary.
    monkeypatch.setattr(windows_security, "_read_directory_acl", lambda path: (
        "S-1-5-21-123", "S-1-5-21-123", True,
        ((0, 0x1F01FF, "S-1-5-21-123"), (0, 0x1F01FF, "S-1-5-18"), (0, 0x1F01FF, "S-1-5-32-544")),
    ))
    return windows_security


@pytest.mark.parametrize("owner", ["S-1-5-18", "S-1-5-32-544"])
def test_trusted_privileged_child_owner_with_private_acl_is_usable(tmp_path, monkeypatch, windows, owner):
    # Elevated Windows tokens can create Admin-owned children under a parent
    # whose owner was explicitly set to the current user by the bootstrap.
    from litechecker.windows_process_state import safe_root

    candidate = tmp_path / ".updates/releases/0.5.0"
    candidate.mkdir(parents=True)
    file = candidate / "fixture.txt"
    file.write_bytes(b"controlled source")
    _, current, present, entries = windows._read_directory_acl(tmp_path)
    monkeypatch.setattr(windows, "_read_directory_acl", lambda path: (
        current if Path(path) == tmp_path else owner, current, present, entries,
    ))
    assert windows.assert_private_directory(tmp_path) == tmp_path
    assert windows.assert_private_directory(candidate) == candidate
    assert windows.assert_private_file(file) == file
    assert safe_root(candidate) == candidate


@pytest.mark.parametrize("bad", ["foreign-owner", "broad-read", "null-dacl", "unsupported-ace"])
def test_privileged_owner_does_not_bypass_acl_or_owner_guards(tmp_path, monkeypatch, windows, bad):
    _, current, present, entries = windows._read_directory_acl(tmp_path)
    owner = "S-1-5-32-544"
    if bad == "foreign-owner":
        owner = "S-1-5-21-999"
    elif bad == "broad-read":
        entries += ((0, 0x120089, "S-1-1-0"),)
    elif bad == "null-dacl":
        present = False
    else:
        entries += ((5, 0x1F01FF, current),)
    monkeypatch.setattr(windows, "_read_directory_acl", lambda path: (owner, current, present, entries))
    with pytest.raises(ValueError):
        windows.assert_private_directory(tmp_path)
    with pytest.raises((ValueError, OSError)):
        update_store.UpdateStore(tmp_path).ensure_layout()
    assert not (tmp_path / ".updates").exists()


@pytest.mark.parametrize("owner", ["S-1-5-21-123", "S-1-5-18", "S-1-5-32-544"])
def test_owner_rights_ace_resolves_only_to_validated_trusted_owner(tmp_path, monkeypatch, windows, owner):
    # Python 3.12.11 mkdir(0700) emits SY + BA + OW, not an explicit user SID.
    current = "S-1-5-21-123"
    entries = ((0, 0x1F01FF, "S-1-5-18"), (0, 0x1F01FF, "S-1-5-32-544"),
               (0, 0x1F01FF, "S-1-3-4"))
    monkeypatch.setattr(windows, "_read_directory_acl", lambda path: (owner, current, True, entries))
    file = tmp_path / "fixture.txt"
    file.write_bytes(b"private")
    assert windows.assert_private_directory(tmp_path) == tmp_path
    assert windows.assert_private_file(file) == file
    store = update_store.UpdateStore(tmp_path)
    store.write_install(update_store.default_install_state())
    assert store.read_install()["active"] is None


@pytest.mark.parametrize("bad", ["foreign-owner", "S-1-1-0", "S-1-5-32-545", "S-1-3-0"])
def test_owner_rights_does_not_authorize_foreign_owner_or_broad_trustees(tmp_path, monkeypatch, windows, bad):
    current = "S-1-5-21-123"
    owner = "S-1-5-21-999" if bad == "foreign-owner" else "S-1-5-32-544"
    entries = ((0, 0x1F01FF, "S-1-3-4"),)
    if bad != "foreign-owner":
        entries += ((0, 0x120089, bad),)
    monkeypatch.setattr(windows, "_read_directory_acl", lambda path: (owner, current, True, entries))
    file = tmp_path / "fixture.txt"
    file.write_bytes(b"private")
    with pytest.raises(ValueError):
        windows.assert_private_directory(tmp_path)
    with pytest.raises(ValueError):
        windows.assert_private_file(file)
    with pytest.raises((ValueError, OSError)):
        update_store.UpdateStore(tmp_path).ensure_layout()
    assert not (tmp_path / ".updates").exists()


def test_runtime_uses_windows_exe_without_posix_execution_bits(tmp_path):
    from windows_test_support import secure_test_directory
    secure_test_directory(tmp_path)
    executable = tmp_path / ".windows-native/venv/Scripts/python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"controlled runtime")
    executable.chmod(0o600)
    assert update_launcher.runtime_python(tmp_path, system="Windows") == executable


def test_windows_channel_and_state_do_not_require_fchmod_or_geteuid(tmp_path, monkeypatch, windows):
    monkeypatch.delattr(os, "fchmod", raising=False)
    monkeypatch.delattr(os, "geteuid", raising=False)
    channel = json.dumps({"schema": 1, "enabled": True, "public_key": base64.b64encode(b"x" * 32).decode(), "manifest_urls": ["https://example.com/release.json"]}).encode()
    assert updater.initialize_channel(tmp_path, channel)
    store = update_store.UpdateStore(tmp_path)
    state = update_store.default_install_state()
    store.write_install(state)
    assert store.read_install() == state
    assert update_launcher.select_release(tmp_path) == tmp_path
    assert not updater.initialize_channel(tmp_path, channel.replace(b"example.com", b"other.example"))
    assert json.loads(store.channel_path.read_bytes())["manifest_urls"] == ["https://example.com/release.json"]


def test_windows_staged_source_reuse_does_not_compare_posix_executable_bits(tmp_path, windows):
    store = update_store.UpdateStore(tmp_path)
    archive = update_store.validate_source_zip(source_zip())
    release = store.stage("0.5.0", archive)
    (release / "scripts/run.sh").chmod(0o600)
    assert store.stage("0.5.0", archive) == release
    (release / "scripts/run.sh").write_bytes(b"tampered")
    with pytest.raises(update_store.StoreError):
        store.stage("0.5.0", archive)


@pytest.mark.parametrize("member", ["windows-state/settings.json", ".windows-native/tools/xray.exe", "Scripts/A.py", "scripts/a.py"])
def test_windows_private_paths_and_case_collisions_cannot_be_release_members(member):
    files = {member: b"private-or-colliding", "scripts/a.py": b"source"}
    if member == "scripts/a.py":
        files["Scripts/A.py"] = b"different"
    with pytest.raises(update_store.StoreError):
        update_store.validate_source_zip(source_zip(files))


@pytest.mark.parametrize("bad", ["foreign-owner", "everyone", "null-dacl", "unsupported-ace"])
def test_unsafe_windows_acl_refuses_storage_before_writes(tmp_path, windows, monkeypatch, bad):
    owner, current, present, aces = windows._read_directory_acl(tmp_path)
    if bad == "foreign-owner":
        owner = "S-1-5-21-999"
    elif bad == "everyone":
        aces += ((0, 0x120089, "S-1-1-0"),)
    elif bad == "null-dacl":
        present = False
    else:
        aces += ((5, 0x1F01FF, current),)
    monkeypatch.setattr(windows, "_read_directory_acl", lambda path: (owner, current, present, aces))
    with pytest.raises((ValueError, OSError)):
        update_store.UpdateStore(tmp_path).write_install(update_store.default_install_state())
    assert not (tmp_path / ".updates").exists()


def test_junction_ancestor_rejected_by_launcher_and_store(tmp_path, monkeypatch, windows):
    parent = tmp_path / "linked"
    parent.mkdir()
    root = parent / "app"
    root.mkdir()
    original = windows._is_reparse_point
    monkeypatch.setattr(windows, "_is_reparse_point", lambda path: path == parent or original(path))
    with pytest.raises((ValueError, OSError)):
        update_launcher.checked_path(root, root / "state.json")
    with pytest.raises((ValueError, OSError)):
        update_store.UpdateStore(root).ensure_layout()
    assert not (root / ".updates").exists()


def test_cleanup_defers_locked_owned_release_and_continues(tmp_path, monkeypatch, windows):
    store = update_store.UpdateStore(tmp_path)
    archive = update_store.validate_source_zip(source_zip())
    for version in ("0.1.0", "0.2.0", "0.3.0", "0.4.0"):
        store.stage(version, archive)
    foreign = store.releases / "0.0.9"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("foreign")
    state = tmp_path / "windows-state"
    state.mkdir()
    (state / "settings.json").write_text("private settings")
    original = update_store.shutil.rmtree
    def locked(path, *args, **kwargs):
        if "0.1.0" in Path(path).parts:
            raise PermissionError(13, "controlled locked image")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(update_store.shutil, "rmtree", locked)
    result = store.cleanup(active="0.4.0", previous="0.3.0", now=datetime.now(timezone.utc))
    assert result["releases"] == 1
    assert (store.releases / "0.1.0").is_dir()
    assert (store.releases / "0.1.0" / update_store.OWNED_MARKER).read_bytes() == b"litechecker-updater-v1\n"
    assert result["deferred"] == 1
    assert not (store.releases / "0.2.0").exists()
    assert (store.releases / "0.3.0").is_dir() and (store.releases / "0.4.0").is_dir()
    assert (foreign / "keep.txt").read_text() == "foreign"
    assert (state / "settings.json").read_text() == "private settings"


def test_cleanup_does_not_enter_reparse_directory(tmp_path, monkeypatch, windows):
    store = update_store.UpdateStore(tmp_path)
    release = store.stage("0.1.0", update_store.validate_source_zip(source_zip()))
    original = windows._is_reparse_point
    monkeypatch.setattr(windows, "_is_reparse_point", lambda path: path == release or original(path))
    assert not store.remove_release("0.1.0")
    assert (release / "scripts/run.sh").exists()


def test_launcher_rejects_writable_runtime_ancestor_acl(tmp_path, monkeypatch, windows):
    executable = tmp_path / ".windows-native/venv/Scripts/python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"runtime")
    private_acl = windows._read_directory_acl(tmp_path)
    def descriptor(path):
        if Path(path) == executable.parent:
            owner, user, present, entries = private_acl
            return owner, user, present, entries + ((0, 0x1F01FF, "S-1-1-0"),)
        return private_acl
    monkeypatch.setattr(windows, "_read_directory_acl", descriptor)
    with pytest.raises(update_launcher.LauncherError):
        update_launcher.runtime_python(tmp_path, system="Windows")


def test_select_baseline_does_not_require_private_acl_on_drive_root(tmp_path, monkeypatch, windows):
    private_acl = windows._read_directory_acl(tmp_path)
    def descriptor(path):
        if Path(path) == tmp_path or tmp_path in Path(path).parents:
            return private_acl
        return "S-1-5-18", private_acl[1], True, ((0, 0x120089, "S-1-1-0"),)
    monkeypatch.setattr(windows, "_read_directory_acl", descriptor)
    assert update_launcher.select_release(tmp_path) == tmp_path
    assert not (tmp_path / ".updates").exists()


@pytest.mark.asyncio
async def test_unsafe_existing_update_acl_returns_closed_failure(tmp_path, monkeypatch, windows):
    channel = json.dumps({"schema": 1, "enabled": True, "public_key": base64.b64encode(b"x" * 32).decode(), "manifest_urls": ["https://example.com/release.json"]}).encode()
    updater.initialize_channel(tmp_path, channel)
    private_acl = windows._read_directory_acl(tmp_path)
    def descriptor(path):
        if Path(path) == tmp_path / ".updates/releases":
            owner, user, present, entries = private_acl
            return owner, user, present, entries + ((0, 0x1F01FF, "S-1-1-0"),)
        return private_acl
    monkeypatch.setattr(windows, "_read_directory_acl", descriptor)
    result = await updater.check_for_update(tmp_path, object())
    assert result["status"] == "failed"
    assert not (tmp_path / ".updates/install.json").exists()


def test_locked_cleanup_marker_allows_later_retry(tmp_path, monkeypatch, windows):
    store = update_store.UpdateStore(tmp_path)
    release = store.stage("0.1.0", update_store.validate_source_zip(source_zip()))
    unlink = Path.unlink
    with monkeypatch.context() as patch:
        def locked(path, *args, **kwargs):
            if path.name == "run.sh":
                raise PermissionError(13, "sharing violation")
            return unlink(path, *args, **kwargs)
        patch.setattr(Path, "unlink", locked)
        # rmtree uses its own descriptor-relative unlink: deny its directory
        # operation instead, exercising the same native sharing-error boundary.
        patch.setattr(update_store.shutil, "rmtree", lambda path: (_ for _ in ()).throw(PermissionError(13, "sharing violation")))
        assert not store.remove_release("0.1.0")
        assert (release / update_store.OWNED_MARKER).exists()
    assert store.remove_release("0.1.0")
    assert not release.exists()


@pytest.mark.skipif(os.name != "nt", reason="actual Windows ACL/NTFS boundary")
def test_native_windows_acl_state_runtime_and_locked_cleanup(tmp_path):
    from litechecker import windows_security
    from windows_test_support import secure_test_directory
    root = tmp_path / "Приватный LiteChecker"
    root.mkdir()
    secure_test_directory(root)
    assert windows_security.assert_private_directory(root) == root
    store = update_store.UpdateStore(root)
    store.write_install(update_store.default_install_state())
    assert store.read_install()["active"] is None
    release = store.stage("0.1.0", update_store.validate_source_zip(source_zip()))
    owner, current, present, entries = windows_security._read_directory_acl(release)
    assert owner in {current, "S-1-5-18", "S-1-5-32-544"}
    assert present and entries
    assert windows_security.assert_private_directory(release) == release
    from litechecker.windows_process_state import safe_root
    assert safe_root(release) == release
    executable = release / ".windows-native/venv/Scripts/python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"controlled runtime, not executed")
    assert windows_security.assert_private_file(executable) == executable
    assert update_launcher.runtime_python(release, system="Windows") == executable
    with executable.open("rb"):
        assert not store.remove_release("0.1.0")
        assert (release / update_store.OWNED_MARKER).exists()
    assert store.remove_release("0.1.0")
    assert not release.exists()


@pytest.mark.skipif(os.name != "nt", reason="actual Windows mkdir(0700) ACL boundary")
def test_native_windows_mode700_owner_rights_acl_is_validated_without_rewrite(tmp_path):
    from litechecker import windows_security
    from windows_test_support import secure_test_directory

    parent = tmp_path / "private-parent"
    parent.mkdir()
    secure_test_directory(parent)
    child = parent / "mode700"
    child.mkdir(mode=0o700)
    file = child / "fixture.txt"
    file.write_bytes(b"private contents")
    before = {path: windows_security._read_directory_acl(path) for path in (child, file)}
    for owner, current, present, entries in before.values():
        assert owner in {current, "S-1-5-18", "S-1-5-32-544"}
        assert present
        assert any(trustee == "S-1-3-4" for _, _, trustee in entries)
    assert windows_security.assert_private_directory(child) == child
    assert windows_security.assert_private_file(file) == file
    assert {path: windows_security._read_directory_acl(path) for path in (child, file)} == before

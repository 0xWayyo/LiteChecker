from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
from pathlib import Path
import stat
import warnings
import zipfile

import pytest


def _module():
    return importlib.import_module("litechecker.update_store")


def _zip(files=None, *, extra_entries=()):
    files = files or {"pyproject.toml": b"project", "scripts/run.sh": b"#!/bin/sh\n"}
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        all_entries = [("CONTENTS.sha256.json", json.dumps(manifest).encode(), 0o644)]
        all_entries += [(name, data, 0o755 if name.endswith(".sh") else 0o644) for name, data in files.items()]
        all_entries += list(extra_entries)
        for name, data, mode in all_entries:
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def test_validates_manifest_exactly_and_stages_private_immutable_release(tmp_path):
    module = _module()
    data = _zip()
    validated = module.validate_source_zip(
        data, expected_sha256=hashlib.sha256(data).hexdigest(), expected_size=len(data)
    )
    assert {entry.path.as_posix() for entry in validated.files} == {
        "pyproject.toml",
        "scripts/run.sh",
    }

    store = module.UpdateStore(tmp_path)
    release = store.stage("0.2.0", validated)

    assert release == tmp_path / ".updates/releases/0.2.0"
    assert (release / "pyproject.toml").read_bytes() == b"project"
    assert (release / "scripts/run.sh").stat().st_mode & 0o777 == 0o755
    assert (tmp_path / ".updates").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "files,extra",
    [
        ({"../outside": b"x"}, ()),
        ({"/absolute": b"x"}, ()),
        ({"secrets/token": b"x"}, ()),
        ({"state/device.json": b"x"}, ()),
        ({".updates/install.json": b"x"}, ()),
        ({".updater-runtime/python": b"x"}, ()),
        ({".env": b"TOKEN=x"}, ()),
        ({".env.standalone": b"TOKEN=x"}, ()),
        ({"native-settings.json": b"device"}, ()),
        ({"bin": b"file", "bin/run": b"child"}, ()),
        ({"CON.txt": b"windows-device"}, ()),
        ({"app.py": b"x"}, (("APP.py", b"x", 0o644),)),
        ({"app.py": b"x"}, (("app.py", b"x", 0o644),)),
        ({"app.py": b"x"}, (("unlisted.py", b"x", 0o644),)),
    ],
)
def test_rejects_paths_collisions_duplicates_and_unlisted_members(files, extra):
    module = _module()
    with pytest.raises(module.StoreError):
        module.validate_source_zip(_zip(files, extra_entries=extra))


def test_rejects_symlinks_and_special_files():
    module = _module()
    output = io.BytesIO()
    manifest = {"run": hashlib.sha256(b"target").hexdigest()}
    with zipfile.ZipFile(output, "w") as archive:
        for name, data, kind in (
            ("CONTENTS.sha256.json", json.dumps(manifest).encode(), stat.S_IFREG),
            ("run", b"target", stat.S_IFLNK),
        ):
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (kind | 0o644) << 16
            archive.writestr(info, data)
    with pytest.raises(module.StoreError):
        module.validate_source_zip(output.getvalue())


def test_allows_secret_free_environment_examples_and_public_channel_bootstrap():
    module = _module()
    archive = module.validate_source_zip(_zip({
        ".env.standalone.example": b"LC_AGENT_NAME=change-me\n",
        "update-channel.json": b'{"schema":1}\n',
    }))
    assert {item.path.as_posix() for item in archive.files} == {
        ".env.standalone.example", "update-channel.json"
    }


def test_rejects_bad_hash_size_and_archive_limits(monkeypatch):
    module = _module()
    data = _zip()
    with pytest.raises(module.StoreError):
        module.validate_source_zip(data, expected_sha256="0" * 64)
    with pytest.raises(module.StoreError):
        module.validate_source_zip(data, expected_size=len(data) + 1)
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", len(data) - 1)
    with pytest.raises(module.StoreError):
        module.validate_source_zip(data)


def test_cleanup_deletes_only_owned_old_releases_and_stale_temporary_dirs(tmp_path):
    module = _module()
    store = module.UpdateStore(tmp_path)
    for version in ("0.2.0", "0.3.0", "0.4.0"):
        store.stage(version, module.validate_source_zip(_zip({"version.txt": version.encode()})))
    unknown = tmp_path / ".updates/releases/keep-me"
    unknown.mkdir()
    (unknown / module.OWNED_MARKER).write_bytes(module.OWNED_MARKER_BYTES)
    stale = tmp_path / ".updates/tmp" / ("stage-0.1.0-" + "a" * 32)
    stale.mkdir(parents=True)
    (stale / module.OWNED_MARKER).write_bytes(module.OWNED_MARKER_BYTES)
    fresh = tmp_path / ".updates/tmp/fresh"
    fresh.mkdir()
    (fresh / module.OWNED_MARKER).write_bytes(module.OWNED_MARKER_BYTES)
    outside = tmp_path / "outside"
    outside.mkdir()
    escape = tmp_path / ".updates/releases/escape"
    escape.symlink_to(outside, target_is_directory=True)
    old = datetime(2026, 9, 3, tzinfo=timezone.utc).timestamp()
    for path in (stale, stale / module.OWNED_MARKER):
        path.touch()
        import os
        os.utime(path, (old, old), follow_symlinks=False)

    counts = store.cleanup(
        active="0.4.0",
        previous="0.3.0",
        now=datetime(2026, 9, 5, tzinfo=timezone.utc),
    )

    assert counts == {"releases": 1, "temporary": 1}
    assert {path.name for path in (tmp_path / ".updates/releases").iterdir()} == {
        "0.3.0", "0.4.0", "keep-me", "escape"
    }
    assert fresh.exists()
    assert outside.exists()
    assert escape.is_symlink()


def test_state_writes_are_atomic_private_and_reads_do_not_create_store(tmp_path):
    module = _module()
    store = module.UpdateStore(tmp_path)
    assert store.read_install() == module.default_install_state()
    assert not (tmp_path / ".updates").exists()

    state = module.default_install_state()
    state["status"] = "current"
    store.write_install(state)

    path = tmp_path / ".updates/install.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert store.read_install()["status"] == "current"


def test_staging_never_reuses_a_corrupted_owned_release(tmp_path):
    module = _module()
    validated = module.validate_source_zip(_zip())
    store = module.UpdateStore(tmp_path)
    release = store.stage("0.2.0", validated)
    (release / "pyproject.toml").write_bytes(b"corrupted")

    with pytest.raises(module.StoreError):
        store.stage("0.2.0", validated)


def test_unhashable_status_is_rejected_as_invalid_state_not_type_error():
    module = _module()
    state = module.default_install_state()
    state["status"] = []
    with pytest.raises(module.StoreError):
        module.validate_install_state(state)

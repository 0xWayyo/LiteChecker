import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest
from filelock import FileLock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _module():
    return importlib.import_module("litechecker.updater")


def _archive(version):
    files = {
        "pyproject.toml": f'version = "{version}"\n'.encode(),
        "src/litechecker/__init__.py": b'"release"\n',
    }
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in [("CONTENTS.sha256.json", json.dumps(manifest).encode()), *files.items()]:
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def _release(private, version="0.2.0", sequence=2, archive=None, urls=None):
    archive = archive or _archive(version)
    urls = urls or [f"https://downloads.example/LiteChecker-{version}.zip"]
    payload = {
        "version": version,
        "sequence": sequence,
        "published_at": "2026-09-05T00:00:00Z",
        "artifact": {
            "urls": urls,
            "sha256": hashlib.sha256(archive).hexdigest(),
            "size": len(archive),
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    metadata = json.dumps({
        "schema": 1,
        "payload": payload,
        "signature": base64.b64encode(private.sign(canonical)).decode(),
    }).encode()
    return metadata, archive


def _configure(root, public, enabled=True, urls=None):
    directory = root / ".updates"
    directory.mkdir(mode=0o700)
    (directory / "channel.json").write_text(json.dumps({
        "schema": 1,
        "enabled": enabled,
        "public_key": base64.b64encode(public).decode(),
        "manifest_urls": urls or ["https://updates.example/release.json"],
    }))


class Adapter:
    def __init__(self, root, *, running=True):
        self.maintenance_lock = root / "state/maintenance.lock"
        self.maintenance_lock.parent.mkdir(parents=True, exist_ok=True)
        self.baseline = root
        baseline_project = root / "pyproject.toml"
        if not baseline_project.exists():
            baseline_project.write_text('[project]\nversion = "0.1.0"\n')
        self.running = running
        self.activated = root
        self.prepared = []
        self.activations = []
        self.fail_health_for = set()
        self.fail_activation_for = set()

    async def prepare(self, release):
        probe = FileLock(self.maintenance_lock)
        probe.acquire(timeout=0)
        probe.release()
        self.prepared.append(release)

    async def is_running(self):
        return self.running

    async def activate(self, release, running):
        self.activations.append((release, running))
        if release.name in self.fail_activation_for:
            raise RuntimeError("fixture URL https://secret.invalid must be redacted")
        self.activated = release
        self.running = running

    async def healthy(self, release, running):
        return release.name not in self.fail_health_for and self.activated == release and self.running == running


def _fetcher(mapping, calls=None, gate=None):
    async def fetch(url, limit):
        if calls is not None:
            calls.append((url, limit))
        if gate is not None and url.endswith("release.json"):
            await gate.wait()
        value = mapping[url]
        if isinstance(value, Exception):
            raise value
        return value
    return fetch


@pytest.mark.asyncio
async def test_good_update_preserves_existing_device_bytes_and_commits_private_state(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    existing_device = tmp_path / "state/device.json"
    existing_device.parent.mkdir(exist_ok=True)
    existing_device.write_bytes(b"unchanged")
    adapter = Adapter(tmp_path)

    result = await updater.check_for_update(
        tmp_path,
        adapter,
        force=True,
        fetcher=_fetcher({
            "https://updates.example/release.json": metadata,
            "https://downloads.example/LiteChecker-0.2.0.zip": archive,
        }),
    )

    assert result == {
        "status": "updated",
        "version": "0.2.0",
        "previous": None,
        "error": None,
        "cleanup": {"releases": 0, "temporary": 0},
    }
    assert existing_device.read_bytes() == b"unchanged"
    assert adapter.activated == tmp_path / ".updates/releases/0.2.0"
    assert adapter.running is True
    assert (tmp_path / ".updates/install.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_wrong_key_is_rejected_before_artifact_download_or_execution(tmp_path):
    updater = _module()
    signing = Ed25519PrivateKey.generate()
    trusted = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(signing)
    _configure(tmp_path, trusted)
    calls = []
    adapter = Adapter(tmp_path)

    result = await updater.check_for_update(
        tmp_path,
        adapter,
        force=True,
        fetcher=_fetcher({
            "https://updates.example/release.json": metadata,
            "https://downloads.example/LiteChecker-0.2.0.zip": archive,
        }, calls),
    )

    assert result["status"] == "failed"
    assert [url for url, _ in calls] == ["https://updates.example/release.json"]
    assert adapter.prepared == []
    assert adapter.activations == []
    assert "https://" not in result["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["tampered", "duplicate", "unknown-schema"])
async def test_malformed_or_tampered_metadata_never_reaches_platform(tmp_path, kind):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    if kind == "tampered":
        envelope = json.loads(metadata)
        envelope["payload"]["sequence"] = 99
        metadata = json.dumps(envelope).encode()
    elif kind == "duplicate":
        metadata = metadata[:-1] + b',"schema":1}'
    else:
        envelope = json.loads(metadata)
        envelope["schema"] = 2
        metadata = json.dumps(envelope).encode()
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)

    result = await updater.check_for_update(
        tmp_path,
        adapter,
        force=True,
        fetcher=_fetcher({"https://updates.example/release.json": metadata}),
    )

    assert result["status"] == "failed"
    assert adapter.prepared == []
    assert adapter.activations == []


@pytest.mark.asyncio
async def test_metadata_mirror_failure_falls_through_to_valid_signed_mirror(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    urls = ["https://bad.example/release.json", "https://updates.example/release.json"]
    _configure(tmp_path, public, urls=urls)

    result = await updater.check_for_update(
        tmp_path,
        Adapter(tmp_path),
        force=True,
        fetcher=_fetcher({
            urls[0]: OSError("unavailable https://secret.invalid"),
            urls[1]: metadata,
            "https://downloads.example/LiteChecker-0.2.0.zip": archive,
        }),
    )
    assert result["status"] == "updated"


@pytest.mark.asyncio
async def test_downgrade_and_same_sequence_conflict_are_rejected_without_execution(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)

    async def install(version, sequence):
        metadata, archive = _release(private, version, sequence)
        return await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
            "https://updates.example/release.json": metadata,
            f"https://downloads.example/LiteChecker-{version}.zip": archive,
        }))

    assert (await install("0.3.0", 3))["status"] == "updated"
    prepared = len(adapter.prepared)
    assert (await install("0.2.0", 2))["status"] == "failed"
    assert (await install("0.4.0", 3))["status"] == "failed"
    assert len(adapter.prepared) == prepared


@pytest.mark.asyncio
async def test_fresh_managed_store_rejects_release_older_than_baseline(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.3.0"\n')
    metadata, archive = _release(private, "0.2.0", 2)

    result = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
        "https://updates.example/release.json": metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": archive,
    }))

    assert result["status"] == "failed"
    assert adapter.prepared == []
    assert adapter.activations == []


@pytest.mark.asyncio
async def test_failed_health_rolls_back_to_previous_and_preserves_paused_state(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path, running=False)

    first_metadata, first_archive = _release(private, "0.2.0", 2)
    first = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
        "https://updates.example/release.json": first_metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": first_archive,
    }))
    assert first["status"] == "updated"
    adapter.fail_health_for.add("0.3.0")
    second_metadata, second_archive = _release(private, "0.3.0", 3)

    result = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
        "https://updates.example/release.json": second_metadata,
        "https://downloads.example/LiteChecker-0.3.0.zip": second_archive,
    }))

    assert result["status"] == "rolled-back"
    assert result["version"] == "0.2.0"
    assert adapter.activated == tmp_path / ".updates/releases/0.2.0"
    assert adapter.running is False
    assert not (tmp_path / ".updates/releases/0.3.0").exists()


@pytest.mark.asyncio
async def test_transient_archive_and_prepare_failures_allow_same_signed_release_retry(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    good_mapping = {
        "https://updates.example/release.json": metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": archive,
    }
    unavailable = dict(good_mapping)
    unavailable["https://downloads.example/LiteChecker-0.2.0.zip"] = OSError("offline")
    assert (await updater.check_for_update(
        tmp_path, adapter, force=True, fetcher=_fetcher(unavailable)
    ))["status"] == "failed"

    original_prepare = adapter.prepare
    attempts = 0

    async def transient_prepare(release):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("runtime dependency temporarily unavailable")
        await original_prepare(release)

    adapter.prepare = transient_prepare
    assert (await updater.check_for_update(
        tmp_path, adapter, force=True, fetcher=_fetcher(good_mapping)
    ))["status"] == "failed"
    assert (await updater.check_for_update(
        tmp_path, adapter, force=True, fetcher=_fetcher(good_mapping)
    ))["status"] == "updated"


@pytest.mark.asyncio
async def test_commit_disk_failure_restores_old_release_and_keeps_recovery_state_consistent(tmp_path, monkeypatch):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    original = updater.UpdateStore.write_install

    def fail_commit(self, state):
        if state["active"] == "0.2.0" and state["pending"] is None:
            raise OSError("disk full")
        return original(self, state)

    monkeypatch.setattr(updater.UpdateStore, "write_install", fail_commit)
    result = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
        "https://updates.example/release.json": metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": archive,
    }))

    assert result["status"] == "rolled-back"
    assert result["version"] is None
    assert adapter.activated == tmp_path
    assert json.loads((tmp_path / ".updates/install.json").read_text())["active"] is None


@pytest.mark.asyncio
async def test_interrupted_pending_transaction_rolls_back_before_any_download(tmp_path):
    updater = _module()
    store_module = importlib.import_module("litechecker.update_store")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path, running=False)
    candidate_archive = _archive("0.2.0")
    store = store_module.UpdateStore(tmp_path)
    candidate = store.stage("0.2.0", store_module.validate_source_zip(candidate_archive))
    state = store_module.default_install_state()
    state["pending"] = {
        "from_version": None,
        "to_version": "0.2.0",
        "sequence": 2,
        "digest": hashlib.sha256(candidate_archive).hexdigest(),
        "was_running": False,
    }
    state["status"] = "failed"
    store.write_install(state)
    adapter.activated = candidate
    calls = []

    result = await updater.check_for_update(
        tmp_path, adapter, force=True, fetcher=_fetcher({}, calls)
    )

    assert result["status"] == "rolled-back"
    assert adapter.activated == tmp_path
    assert adapter.running is False
    assert calls == []
    assert not candidate.exists()


@pytest.mark.asyncio
async def test_disabled_channel_still_recovers_pending_transaction_without_download(tmp_path):
    updater = _module()
    store_module = importlib.import_module("litechecker.update_store")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public, enabled=False)
    adapter = Adapter(tmp_path, running=False)
    candidate_archive = _archive("0.2.0")
    store = store_module.UpdateStore(tmp_path)
    candidate = store.stage("0.2.0", store_module.validate_source_zip(candidate_archive))
    state = store_module.default_install_state()
    state["pending"] = {
        "from_version": None,
        "to_version": "0.2.0",
        "sequence": 2,
        "digest": hashlib.sha256(candidate_archive).hexdigest(),
        "was_running": False,
    }
    state["status"] = "failed"
    store.write_install(state)
    adapter.activated = candidate
    calls = []

    result = await updater.check_for_update(
        tmp_path, adapter, force=False, fetcher=_fetcher({}, calls)
    )

    assert result["status"] == "rolled-back"
    assert adapter.activated == tmp_path
    assert calls == []


@pytest.mark.asyncio
async def test_successive_updates_keep_only_active_and_previous(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    last = None
    for sequence, version in enumerate(("0.2.0", "0.3.0", "0.4.0"), start=2):
        metadata, archive = _release(private, version, sequence)
        last = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=_fetcher({
            "https://updates.example/release.json": metadata,
            f"https://downloads.example/LiteChecker-{version}.zip": archive,
        }))

    assert last["cleanup"] == {"releases": 1, "temporary": 0}
    assert {path.name for path in (tmp_path / ".updates/releases").iterdir()} == {"0.3.0", "0.4.0"}


@pytest.mark.asyncio
async def test_current_check_cleans_abandoned_owned_temp_but_preserves_unknown(tmp_path):
    updater = _module()
    store_module = importlib.import_module("litechecker.update_store")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    mapping = {
        "https://updates.example/release.json": metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": archive,
    }
    assert (await updater.check_for_update(
        tmp_path, adapter, force=True, fetcher=_fetcher(mapping)
    ))["status"] == "updated"
    temporary = tmp_path / ".updates/tmp"
    stale = temporary / ("stage-0.1.0-" + "b" * 32)
    stale.mkdir()
    (stale / store_module.OWNED_MARKER).write_bytes(store_module.OWNED_MARKER_BYTES)
    unknown = temporary / "keep-unknown"
    unknown.mkdir()
    old = datetime(2026, 9, 3, tzinfo=timezone.utc).timestamp()
    os.utime(stale, (old, old), follow_symlinks=False)

    result = await updater.check_for_update(
        tmp_path,
        adapter,
        force=True,
        fetcher=_fetcher(mapping),
        now=datetime(2026, 9, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "current"
    assert result["cleanup"] == {"releases": 0, "temporary": 1}
    assert not stale.exists()
    assert unknown.exists()


@pytest.mark.asyncio
async def test_cancellation_during_prepare_removes_unjournaled_candidate(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    adapter = Adapter(tmp_path)
    entered = asyncio.Event()
    hold = asyncio.Event()

    async def blocked_prepare(_release):
        entered.set()
        await hold.wait()

    adapter.prepare = blocked_prepare
    task = asyncio.create_task(updater.check_for_update(
        tmp_path,
        adapter,
        force=True,
        fetcher=_fetcher({
            "https://updates.example/release.json": metadata,
            "https://downloads.example/LiteChecker-0.2.0.zip": archive,
        }),
    ))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not (tmp_path / ".updates/releases/0.2.0").exists()
    assert json.loads((tmp_path / ".updates/install.json").read_text())["pending"] is None


@pytest.mark.asyncio
async def test_unconfigured_disabled_not_due_and_status_reads_are_non_mutating(tmp_path):
    updater = _module()
    adapter = Adapter(tmp_path)
    untouched = tmp_path / "empty"
    untouched.mkdir()
    assert updater.update_status(untouched)["status"] == "unconfigured"
    assert list(untouched.iterdir()) == []
    assert (await updater.check_for_update(untouched, adapter, force=True))["status"] == "unconfigured"
    assert list(untouched.iterdir()) == []

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public, enabled=False)
    before = (tmp_path / ".updates/channel.json").read_bytes()
    assert (await updater.check_for_update(tmp_path, adapter, force=True))["status"] == "disabled"
    assert (tmp_path / ".updates/channel.json").read_bytes() == before


@pytest.mark.asyncio
async def test_concurrent_check_returns_busy_without_second_execution(tmp_path):
    updater = _module()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    metadata, archive = _release(private)
    _configure(tmp_path, public)
    gate = asyncio.Event()
    adapter = Adapter(tmp_path)
    fetch = _fetcher({
        "https://updates.example/release.json": metadata,
        "https://downloads.example/LiteChecker-0.2.0.zip": archive,
    }, gate=gate)
    first = asyncio.create_task(updater.check_for_update(tmp_path, adapter, force=True, fetcher=fetch))
    await asyncio.sleep(0)
    second = await updater.check_for_update(tmp_path, adapter, force=True, fetcher=fetch)
    gate.set()
    assert second["status"] == "busy"
    assert (await first)["status"] == "updated"


def test_enable_disable_only_changes_existing_trusted_channel(tmp_path):
    updater = _module()
    with pytest.raises(FileNotFoundError):
        updater.set_updates_enabled(tmp_path, True)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _configure(tmp_path, public, enabled=False)

    updater.set_updates_enabled(tmp_path, True)

    channel = json.loads((tmp_path / ".updates/channel.json").read_text())
    assert channel["enabled"] is True
    assert base64.b64decode(channel["public_key"]) == public
    assert (tmp_path / ".updates/channel.json").stat().st_mode & 0o777 == 0o600

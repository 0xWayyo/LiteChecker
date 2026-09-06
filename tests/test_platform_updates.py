"""Independent signed fixtures exercise platform identity through real storage."""

import base64
import hashlib
import io
import json
import stat
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from litechecker import update_launcher, update_manifest, updater
from litechecker.update_store import UpdateStore, validate_source_zip
from test_updater import Adapter


def marker(platform):
    return json.dumps({"schema": 1, "platform": platform}).encode()


def channel(public, platform="macos", schema=2):
    document = {"schema": schema, "enabled": True,
                "public_key": base64.b64encode(public).decode(),
                "manifest_urls": ["https://fixture.example/release.json"]}
    if schema == 2:
        document["platform"] = platform
    return json.dumps(document).encode()


def archive(version="0.7.0", platform="macos", marker_bytes=None, project=None):
    files = {"pyproject.toml": project if project is not None else
             f'[project]\nversion="{version}"\n'.encode(),
             "src/litechecker/__init__.py": b"# fixture\n"}
    if platform is not None:
        files["distribution.json"] = marker_bytes if marker_bytes is not None else marker(platform)
    contents = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    files["CONTENTS.sha256.json"] = json.dumps(contents).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipped:
        for name, data in files.items():
            info = zipfile.ZipInfo("LiteChecker/" + name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            zipped.writestr(info, data)
    return output.getvalue()


def signed(private, data, *, version="0.7.0", sequence=9, platform="macos", schema=2):
    payload = {"version": version, "sequence": sequence,
               "published_at": "2026-09-06T00:00:00Z",
               "artifact": {"urls": ["https://fixture.example/source.zip"],
                            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}}
    if platform is not None:
        payload["platform"] = platform
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return json.dumps({"schema": schema, "payload": payload,
                       "signature": base64.b64encode(private.sign(canonical)).decode()}).encode()


@pytest.fixture
def keys():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_schema2_signed_platform_roundtrip(keys, platform):
    private, public = keys
    result = update_manifest.verify_release_metadata(signed(private, archive(), platform=platform), public)
    assert result.platform == platform
    assert result.payload["platform"] == platform
    config = update_manifest.parse_channel_config(channel(public, platform))
    assert config.platform == platform
    assert updater._channel_document(config)["schema"] == 2
    assert updater._channel_document(config)["platform"] == platform


@pytest.mark.parametrize("platform", [None, "freebsd", True, ["macos"]])
def test_schema2_rejects_missing_unknown_or_invalid_signed_platform(keys, platform):
    private, public = keys
    with pytest.raises(update_manifest.ManifestError):
        update_manifest.verify_release_metadata(signed(private, archive(), platform=platform), public)


def test_platform_is_signature_covered_and_duplicate_keys_are_rejected(keys):
    private, public = keys
    good = signed(private, archive())
    tampered = good.replace(b'"platform": "macos"', b'"platform": "linux"')
    duplicate = good.replace(b'"platform": "macos"', b'"platform": "macos", "platform": "macos"')
    for data in (tampered, duplicate):
        with pytest.raises(update_manifest.ManifestError):
            update_manifest.verify_release_metadata(data, public)


@pytest.fixture
def install(tmp_path, keys, monkeypatch):
    from litechecker import distribution
    monkeypatch.setattr(distribution, "host_platform", lambda: "macos")
    (tmp_path / "distribution.json").write_bytes(marker("macos"))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="0.6.1"\n')
    updater.initialize_channel(tmp_path, channel(keys[1]))
    return tmp_path, UpdateStore(tmp_path), Adapter(tmp_path, running=False)


async def run_release(root, adapter, metadata, data):
    async def fetch(url, limit):
        value = metadata if url.endswith("release.json") else data
        if isinstance(value, Exception):
            raise value
        return value
    return await updater.check_for_update(root, adapter, force=True, fetcher=fetch)


@pytest.mark.asyncio
@pytest.mark.parametrize("platform,schema", [("linux", 2), (None, 2), ("freebsd", 2), (None, 1)])
async def test_wrong_signed_metadata_cannot_poison_highwater_or_prepare(install, keys, platform, schema):
    root, store, adapter = install
    before = store.read_install()
    data = archive()
    result = await run_release(root, adapter, signed(keys[0], data, sequence=999, platform=platform, schema=schema), data)
    assert result["status"] == "failed"
    assert not adapter.prepared
    assert store.read_install()["highest_sequence"] == before["highest_sequence"]
    assert not list(store.releases.glob("*"))
    # A normal authenticated release remains usable after the wrong-OS announcement.
    result = await run_release(root, adapter, signed(keys[0], data), data)
    assert result["status"] == "updated"


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [archive(platform="linux"), archive(platform=None),
                                  archive(marker_bytes=b'{"schema":1,"platform":"macos","platform":"macos"}'),
                                  archive(version="0.8.0"), archive(project=b'version="0.7.0"\n')],
                         ids=["wrong-os", "missing-marker", "duplicate-marker", "wrong-version", "invalid-project"])
async def test_authenticated_archive_must_match_platform_and_version_before_staging(install, keys, data):
    root, store, adapter = install
    result = await run_release(root, adapter, signed(keys[0], data), data)
    assert result["status"] == "failed"
    assert not adapter.prepared
    assert not list(store.releases.iterdir())
    assert store.read_install()["highest_sequence"] == 9


@pytest.mark.asyncio
async def test_authenticated_same_target_download_failure_retains_highwater(install, keys):
    root, store, adapter = install
    data = archive()
    metadata = signed(keys[0], data)
    result = await run_release(root, adapter, metadata, OSError("offline"))
    assert result["status"] == "failed"
    assert store.read_install()["highest_sequence"] == 9
    assert store.read_install()["highest_digest"] == hashlib.sha256(data).hexdigest()
    assert not adapter.prepared
    assert (await run_release(root, adapter, metadata, data))["status"] == "updated"


@pytest.mark.parametrize("old_platform,old_schema", [(None, 1), ("linux", 2)])
def test_incompatible_installed_channel_fails_without_replacing_trust_or_state(install, keys, old_platform, old_schema):
    root, store, _ = install
    old = channel(keys[1], old_platform, old_schema)
    store.channel_path.write_bytes(old)
    state = store.read_install()
    state.update(highest_sequence=8, highest_digest="a" * 64)
    store.write_install(state)
    before = store.install_path.read_bytes()
    with pytest.raises(ValueError, match="platform|distribution"):
        updater.initialize_channel(root, channel(keys[1]))
    with pytest.raises(ValueError, match="platform|distribution"):
        updater._load_channel(store)
    assert updater.update_status(root)["status"] == "failed"
    assert store.channel_path.read_bytes() == old
    assert store.install_path.read_bytes() == before


@pytest.mark.parametrize("baseline", [None, "linux"])
def test_platform_channel_requires_matching_host_and_baseline(tmp_path, keys, monkeypatch, baseline):
    from litechecker import distribution
    monkeypatch.setattr(distribution, "host_platform", lambda: "macos")
    if baseline:
        (tmp_path / "distribution.json").write_bytes(marker(baseline))
    with pytest.raises(ValueError):
        updater.initialize_channel(tmp_path, channel(keys[1], baseline or "macos"))
    assert not (tmp_path / ".updates").exists()


@pytest.mark.asyncio
async def test_sequential_updates_rollback_recovery_and_cleanup_preserve_user_bytes(install, keys):
    root, store, adapter = install
    preserved = {"state/device.json": b"device", "state/settings.json": b"settings", "reports/result.json": b"report"}
    for name, value in preserved.items():
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(value)
    for sequence, version in enumerate(("0.7.0", "0.8.0", "0.9.0"), 9):
        data = archive(version)
        result = await run_release(root, adapter, signed(keys[0], data, version=version, sequence=sequence), data)
        assert result["status"] == "updated"
        assert adapter.running is False
        assert update_launcher.select_release(root) == store.releases / version
    assert {p.name for p in store.releases.iterdir()} == {"0.8.0", "0.9.0"}
    adapter.fail_activation_for.add("0.10.0")
    data = archive("0.10.0")
    result = await run_release(root, adapter, signed(keys[0], data, version="0.10.0", sequence=12), data)
    assert result["status"] == "rolled-back"
    assert adapter.activated == store.releases / "0.9.0"
    candidate = store.stage("0.11.0", validate_source_zip(archive("0.11.0"), expected_platform="macos"))
    state = store.read_install()
    state["pending"] = {"from_version": "0.9.0", "to_version": "0.11.0", "sequence": 13,
                        "digest": "b" * 64, "was_running": False}
    store.write_install(state)
    restarted = Adapter(root, running=False)
    restarted.activated = candidate
    result = await run_release(root, restarted, AssertionError("must recover before fetch"), b"")
    assert result["status"] == "rolled-back"
    assert restarted.activated == store.releases / "0.9.0"
    assert restarted.running is False
    assert {p.name for p in store.releases.iterdir()} == {"0.8.0", "0.9.0"}
    assert not list(store.temporary.iterdir())
    for name, value in preserved.items():
        assert (root / name).read_bytes() == value


@pytest.mark.parametrize("platform", [None, "linux"])
def test_launcher_rejects_wrong_or_missing_active_distribution(install, platform):
    root, store, _ = install
    store.stage("0.7.0", validate_source_zip(archive(platform=platform)))
    state = store.read_install()
    state["active"] = "0.7.0"
    store.write_install(state)
    with pytest.raises(update_launcher.LauncherError):
        update_launcher.select_release(root)


def test_launcher_rejects_wrong_host_before_opening_fresh_package(tmp_path, monkeypatch):
    from litechecker import distribution
    monkeypatch.setattr(distribution, "host_platform", lambda: "macos")
    (tmp_path / "distribution.json").write_bytes(marker("linux"))
    with pytest.raises(update_launcher.LauncherError):
        update_launcher.select_release(tmp_path)


@pytest.mark.parametrize("data", [b'{"schema":1,"platform":"macos","platform":"macos"}',
    b'{"schema":true,"platform":"macos"}', b'{"schema":1,"platform":"freebsd"}',
    b'{"schema":1,"platform":null}', b'{"schema":1,"platform":[]}',
    b'{"schema":1,"platform":"macos","extra":0}', b'{"schema":1}', b" " * 4097])
def test_distribution_marker_is_strict(data):
    from litechecker import distribution
    with pytest.raises(ValueError):
        distribution.parse_distribution(data)


def test_distribution_reads_only_bounded_regular_files(tmp_path):
    from litechecker import distribution
    assert distribution.read_distribution(tmp_path) is None
    path = tmp_path / "distribution.json"
    path.write_bytes(marker("macos"))
    assert distribution.read_distribution(tmp_path) == "macos"
    path.write_bytes(b" " * 4097)
    with pytest.raises(ValueError):
        distribution.read_distribution(tmp_path)
    path.unlink()
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError):
        distribution.read_distribution(tmp_path)
    path.unlink()
    path.mkdir()
    with pytest.raises(ValueError):
        distribution.read_distribution(tmp_path)


@pytest.mark.parametrize("change", [{"platform": None}, {"platform": "freebsd"}, {"platform": []},
                                   {"platform": True}, {"extra": 1}, {"schema": True}])
def test_channel_rejects_invalid_platform_identity(keys, change):
    document = json.loads(channel(keys[1]))
    document.update(change)
    with pytest.raises(update_manifest.ManifestError):
        update_manifest.parse_channel_config(json.dumps(document).encode())


def test_channel_rejects_missing_and_duplicate_platform(keys):
    data = channel(keys[1])
    duplicate = data.replace(b'"platform": "macos"', b'"platform": "macos", "platform": "macos"')
    document = json.loads(data)
    del document["platform"]
    for invalid in (duplicate, json.dumps(document).encode()):
        with pytest.raises(update_manifest.ManifestError):
            update_manifest.parse_channel_config(invalid)


def test_toggle_preserves_platform_trust_and_highwater(install, keys):
    root, store, _ = install
    state = store.read_install()
    state.update(highest_sequence=8, highest_digest="a" * 64)
    store.write_install(state)
    before = store.install_path.read_bytes()
    updater.set_updates_enabled(root, False)
    value = json.loads(store.channel_path.read_bytes())
    assert value == {"schema": 2, "platform": "macos", "enabled": False,
                     "public_key": base64.b64encode(keys[1]).decode(),
                     "manifest_urls": ["https://fixture.example/release.json"]}
    assert store.install_path.read_bytes() == before


def test_launcher_rejects_missing_marker_in_fresh_profiled_package(tmp_path, keys):
    (tmp_path / "update-channel.json").write_bytes(channel(keys[1]))
    with pytest.raises(update_launcher.LauncherError):
        update_launcher.select_release(tmp_path)


@pytest.mark.parametrize("schema,platform", [(1, None), (2, "linux")])
def test_launcher_rejects_incompatible_installed_channel(install, keys, schema, platform):
    root, store, _ = install
    store.channel_path.write_bytes(channel(keys[1], platform, schema))
    with pytest.raises(update_launcher.LauncherError):
        update_launcher.select_release(root)


@pytest.mark.asyncio
async def test_recovery_never_executes_previous_release_with_wrong_marker(install):
    root, store, adapter = install
    store.stage("0.7.0", validate_source_zip(archive(platform="linux")))
    store.stage("0.8.0", validate_source_zip(archive("0.8.0")))
    state = store.read_install()
    state.update(active="0.7.0", highest_sequence=10, highest_digest="b" * 64)
    state["pending"] = {"from_version": "0.7.0", "to_version": "0.8.0", "sequence": 10,
                        "digest": "b" * 64, "was_running": False}
    store.write_install(state)
    result = await run_release(root, adapter, AssertionError("no download"), b"")
    assert result["status"] == "failed"
    assert not adapter.activations
    assert store.read_install()["pending"] == state["pending"]
    assert {p.name for p in store.releases.iterdir()} == {"0.7.0", "0.8.0"}


@pytest.mark.asyncio
async def test_running_profiled_update_restores_desired_running_state(install, keys):
    root, store, adapter = install
    adapter.running = True
    data = archive()
    assert (await run_release(root, adapter, signed(keys[0], data), data))["status"] == "updated"
    assert adapter.running is True
    adapter.fail_health_for.add("0.8.0")
    data = archive("0.8.0")
    result = await run_release(root, adapter, signed(keys[0], data, version="0.8.0", sequence=10), data)
    assert result["status"] == "rolled-back"
    assert adapter.running is True
    assert adapter.activated == store.releases / "0.7.0"

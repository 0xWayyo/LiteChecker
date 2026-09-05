"""Exercise the offline release CLI with synthetic keys and real source ZIPs."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release.py"


@pytest.fixture
def release():
    assert SCRIPT.is_file(), "offline release author CLI is missing"
    spec = importlib.util.spec_from_file_location("release_author", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_archive(path, *, version="0.2.0", extra=None, tampered=False):
    files = {
        "pyproject.toml": f'[project]\nname = "litechecker"\nversion = "{version}"\n'.encode(),
        "src/litechecker/__init__.py": b"# source fixture\n",
        "scripts/update.sh": b"#!/bin/sh\nexit 0\n",
    }
    files.update(extra or {})
    manifest = {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}
    if tampered:
        files["src/litechecker/__init__.py"] = b"modified after hashing\n"
    files["CONTENTS.sha256.json"] = json.dumps(manifest).encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            entry = zipfile.ZipInfo("LiteChecker/" + name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, payload)
    return path


def keys(release, directory):
    private = directory / "signing-private.key"
    public = directory / "signing-public.key"
    assert release.main(["keygen", "--private-key", str(private), "--public-key", str(public)]) == 0
    return private, public


def build_args(archive, private, output, *, version="0.2.0", sequence="2", repository="example-owner/LiteChecker"):
    return [
        "build", "--archive", str(archive), "--private-key", str(private),
        "--version", version, "--sequence", sequence,
        f"--repository={repository}", "--output", str(output),
    ]


def test_keygen_writes_raw_base64_pair_and_keeps_private_key_out_of_output(release, tmp_path, capsys):
    private, public = keys(release, tmp_path)
    assert private.stat().st_mode & 0o777 == 0o600
    assert public.stat().st_mode & 0o777 == 0o644
    private_raw = base64.b64decode(private.read_bytes().strip(), validate=True)
    public_raw = base64.b64decode(public.read_bytes().strip(), validate=True)
    assert len(private_raw) == len(public_raw) == 32
    output = capsys.readouterr()
    assert private.read_text().strip() not in output.out + output.err


@pytest.mark.parametrize("which", ["private", "public"])
@pytest.mark.parametrize("kind", ["existing", "directory", "symlink", "dangling"])
def test_keygen_refuses_existing_or_linked_destination_without_partial_key(release, tmp_path, which, kind):
    private, public = tmp_path / "private.key", tmp_path / "public.key"
    destination = private if which == "private" else public
    elsewhere = tmp_path / "unrelated"
    if kind == "existing":
        destination.write_bytes(b"retain original\n")
    elif kind == "directory":
        destination.mkdir()
    else:
        if kind == "symlink":
            elsewhere.write_bytes(b"retain original\n")
        destination.symlink_to(elsewhere)
    assert release.main(["keygen", "--private-key", str(private), "--public-key", str(public)]) != 0
    assert not (public if which == "private" else private).exists()
    if kind == "existing":
        assert destination.read_bytes() == b"retain original\n"
    if kind == "symlink":
        assert elsewhere.read_bytes() == b"retain original\n"


def test_keygen_refuses_same_destination_and_linked_parent(release, tmp_path):
    same = tmp_path / "same.key"
    assert release.main(["keygen", "--private-key", str(same), "--public-key", str(same)]) != 0
    assert not same.exists()
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    assert release.main(["keygen", "--private-key", str(linked / "private"), "--public-key", str(tmp_path / "public")]) != 0
    assert not list(outside.iterdir())


def test_keygen_failed_second_write_removes_only_its_partial_outputs(release, tmp_path, monkeypatch):
    original_link = release.os.link
    calls = 0

    def second_link_fails(source, destination, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic storage failure")
        return original_link(source, destination, **kwargs)

    monkeypatch.setattr(release.os, "link", second_link_fails)
    preserved = tmp_path / "unrelated"
    preserved.write_bytes(b"retain original")
    assert release.main([
        "keygen", "--private-key", str(tmp_path / "private.key"),
        "--public-key", str(tmp_path / "public.key"),
    ]) != 0
    assert sorted(path.name for path in tmp_path.iterdir()) == ["unrelated"]
    assert preserved.read_bytes() == b"retain original"


def test_channel_command_produces_valid_public_first_install_configuration(release, tmp_path, capsys):
    private, public = keys(release, tmp_path)
    channel_path = tmp_path / "update-channel.json"
    assert release.main([
        "channel", "--public-key", str(public), "--repository", "example-owner/LiteChecker",
        "--output", str(channel_path),
    ]) == 0
    from litechecker.update_manifest import parse_channel_config
    channel = parse_channel_config(channel_path.read_bytes())
    assert channel.enabled is True
    assert channel.public_key == base64.b64decode(public.read_bytes())
    assert channel.manifest_urls == ("https://github.com/example-owner/LiteChecker/releases/latest/download/release.json",)
    assert channel_path.stat().st_mode & 0o777 == 0o644
    captured = capsys.readouterr()
    assert private.read_text().strip() not in captured.out + captured.err + channel_path.read_text()


@pytest.mark.parametrize("case", ["bad-key", "linked-key", "bad-repository", "existing-output", "linked-output"])
def test_channel_command_rejects_invalid_or_existing_output(release, tmp_path, case):
    _, public = keys(release, tmp_path)
    channel = tmp_path / "update-channel.json"
    repository = "example-owner/LiteChecker"
    if case == "bad-key":
        public.write_bytes(b"not a key")
    elif case == "linked-key":
        source = public.rename(tmp_path / "original-public.key")
        public.symlink_to(source)
    elif case == "bad-repository":
        repository = "owner/repo?private-token"
    elif case == "existing-output":
        channel.write_bytes(b"preserve existing trust")
    else:
        channel.symlink_to(tmp_path / "unrelated")
    assert release.main([
        "channel", "--public-key", str(public), "--repository", repository,
        "--output", str(channel),
    ]) != 0
    if case == "existing-output":
        assert channel.read_bytes() == b"preserve existing trust"
    elif case == "linked-output":
        assert channel.is_symlink()
        assert not (tmp_path / "unrelated").exists()
    else:
        assert not channel.exists()


def test_signed_build_matches_protocol_archive_and_pinned_channel(release, tmp_path, capsys):
    private, public = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip")
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) == 0
    assert sorted(path.name for path in output.iterdir()) == ["LiteChecker-0.2.0.zip", "release.json", "update-channel.json"]
    artifact = output / "LiteChecker-0.2.0.zip"
    assert artifact.read_bytes() == archive.read_bytes()
    manifest_bytes = (output / "release.json").read_bytes()
    envelope = json.loads(manifest_bytes)
    assert set(envelope) == {"schema", "payload", "signature"}
    assert envelope["schema"] == 1
    payload = envelope["payload"]
    assert payload["version"] == "0.2.0"
    assert payload["sequence"] == 2
    assert payload["published_at"].endswith("Z")
    assert payload["artifact"] == {
        "urls": ["https://github.com/example-owner/LiteChecker/releases/download/v0.2.0/LiteChecker-0.2.0.zip"],
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "size": archive.stat().st_size,
    }
    raw_public = base64.b64decode(public.read_bytes().strip(), validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    Ed25519PublicKey.from_public_bytes(raw_public).verify(signature, canonical)
    from litechecker.update_manifest import verify_release_metadata
    assert verify_release_metadata(manifest_bytes, raw_public).version == "0.2.0"
    assert json.loads((output / "update-channel.json").read_bytes()) == {
        "schema": 1, "enabled": True,
        "public_key": public.read_text().strip(),
        "manifest_urls": ["https://github.com/example-owner/LiteChecker/releases/latest/download/release.json"],
    }
    captured = capsys.readouterr()
    private_base64 = private.read_bytes().strip()
    assert private_base64.decode() not in captured.out + captured.err
    assert all(private_base64 not in path.read_bytes() for path in output.iterdir())


def test_published_payload_tampering_invalidates_real_signature(release, tmp_path):
    private, public = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip")
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) == 0
    manifest = json.loads((output / "release.json").read_bytes())
    manifest["payload"]["sequence"] += 1
    canonical = json.dumps(manifest["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public.read_bytes())).verify(
            base64.b64decode(manifest["signature"]), canonical,
        )
    from litechecker.update_manifest import verify_release_metadata
    with pytest.raises(ValueError):
        verify_release_metadata(json.dumps(manifest).encode(), base64.b64decode(public.read_bytes()))


def test_public_bootstrap_channel_can_be_part_of_source_archive(release, tmp_path):
    private, public = keys(release, tmp_path)
    channel = {
        "schema": 1, "enabled": True, "public_key": public.read_text().strip(),
        "manifest_urls": ["https://github.com/example-owner/LiteChecker/releases/latest/download/release.json"],
    }
    archive = source_archive(tmp_path / "public.zip", extra={"update-channel.json": json.dumps(channel).encode()})
    assert release.main(build_args(archive, private, tmp_path / "release")) == 0


@pytest.mark.parametrize("case", ["wrong-key", "invalid-channel"])
def test_build_rejects_unusable_embedded_bootstrap_channel(release, tmp_path, case):
    private, public = keys(release, tmp_path)
    if case == "wrong-key":
        other = tmp_path / "other-keys"
        other.mkdir()
        _, public = keys(release, other)
    channel = {
        "schema": 1, "enabled": True, "public_key": public.read_text().strip(),
        "manifest_urls": ["https://github.com/example-owner/LiteChecker/releases/latest/download/release.json"],
    }
    if case == "invalid-channel":
        channel["unexpected"] = "value"
    archive = source_archive(tmp_path / "public.zip", extra={"update-channel.json": json.dumps(channel).encode()})
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) != 0
    assert not output.exists()


def test_release_cli_works_as_a_process_outside_project_directory(tmp_path):
    private, public = tmp_path / "private.key", tmp_path / "public.key"
    generated = subprocess.run(
        [sys.executable, str(SCRIPT), "keygen", "--private-key", str(private), "--public-key", str(public)],
        cwd=tmp_path, text=True, capture_output=True, timeout=10,
    )
    assert generated.returncode == 0, generated.stderr
    built = subprocess.run(
        [sys.executable, str(SCRIPT), *build_args(source_archive(tmp_path / "public.zip"), private, tmp_path / "release")],
        cwd=tmp_path, text=True, capture_output=True, timeout=10,
    )
    assert built.returncode == 0, built.stderr
    assert private.read_text().strip() not in generated.stdout + generated.stderr + built.stdout + built.stderr


@pytest.mark.parametrize("name", [
    "secrets/telegram_bot_token", "secrets/telegram_proxy_url", "state/device.json",
    ".env", ".env.standalone", ".updates/channel.json", ".native-direct/bin/python",
    ".env.backup", "native-settings.json", ".updater-runtime/venv/bin/python",
])
def test_private_archive_is_refused_even_when_renamed_public(release, tmp_path, capsys, name):
    private, _ = keys(release, tmp_path)
    archive = source_archive(tmp_path / "innocent-public.zip", extra={name: b"private-fixture-value"})
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) != 0
    assert not output.exists()
    captured = capsys.readouterr()
    assert "private-fixture-value" not in captured.out + captured.err


@pytest.mark.parametrize("kwargs", [
    {"repository": "owner/repo/extra"}, {"repository": "owner/repo?token=secret"},
    {"repository": "../repo"}, {"repository": "owner/.."}, {"repository": "owner//repo"},
    {"repository": "-owner/repo"}, {"repository": "owner/repo name"},
    {"version": "0.2.0/../bad"}, {"version": "v0.2.0"}, {"version": "0.2"},
    {"version": "0.2.0\n"}, {"sequence": "0"}, {"sequence": "-1"},
    {"sequence": "true"}, {"sequence": "2.0"},
])
def test_invalid_release_identifiers_fail_before_output(release, tmp_path, kwargs):
    private, _ = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip")
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output, **kwargs)) != 0
    assert not output.exists()


@pytest.mark.parametrize("case", ["version-mismatch", "hash-mismatch", "bad-zip", "linked-archive", "private-name"])
def test_unverified_archive_cannot_become_signed_release(release, tmp_path, case):
    private, _ = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip", version="0.1.0" if case == "version-mismatch" else "0.2.0", tampered=case == "hash-mismatch")
    if case == "bad-zip":
        archive.write_bytes(b"not a ZIP")
    if case == "linked-archive":
        linked = tmp_path / "linked.zip"
        linked.symlink_to(archive)
        archive = linked
    if case == "private-name":
        archive = archive.rename(tmp_path / "LiteChecker-READY-PRIVATE.zip")
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) != 0
    assert not output.exists()


@pytest.mark.parametrize("kind", ["bad-base64", "short", "wide-permissions", "symlink", "directory"])
def test_invalid_signing_key_never_creates_release(release, tmp_path, kind):
    private, _ = keys(release, tmp_path)
    if kind == "bad-base64":
        private.write_text("not!base64\n")
    if kind == "short":
        private.write_bytes(base64.b64encode(b"not 32 bytes"))
    if kind == "wide-permissions":
        private.chmod(0o644)
    if kind == "symlink":
        original = private.rename(tmp_path / "original.key")
        private.symlink_to(original)
    if kind == "directory":
        private.unlink()
        private.mkdir()
    output = tmp_path / "release"
    assert release.main(build_args(source_archive(tmp_path / "public.zip"), private, output)) != 0
    assert not output.exists()


def test_signing_key_hidden_in_an_allowed_source_file_is_not_published(release, tmp_path):
    private, _ = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip", extra={"README.md": private.read_bytes()})
    output = tmp_path / "release"
    assert release.main(build_args(archive, private, output)) != 0
    assert not output.exists()


@pytest.mark.parametrize("kind", ["existing-artifact", "existing-manifest", "linked-output", "linked-artifact"])
def test_release_outputs_are_immutable_and_do_not_follow_links(release, tmp_path, kind):
    private, _ = keys(release, tmp_path)
    archive = source_archive(tmp_path / "public.zip")
    output = tmp_path / "release"
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "linked-output":
        output.symlink_to(outside, target_is_directory=True)
    else:
        output.mkdir()
        path = output / ("release.json" if kind == "existing-manifest" else "LiteChecker-0.2.0.zip")
        if kind == "linked-artifact":
            path.symlink_to(outside / "untouched")
        else:
            path.write_bytes(b"retain original")
    before = {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}
    assert release.main(build_args(archive, private, output)) != 0
    assert {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()} == before
    assert not list(outside.iterdir())

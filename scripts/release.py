#!/usr/bin/env python3
"""Offline author tooling for signed, secret-free LiteChecker releases."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import tomllib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
_REPOSITORY = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/([A-Za-z0-9._-]{1,100})", re.ASCII)


class ReleaseError(ValueError):
    """Closed release-author error; messages never include input contents."""


def _path(path: str | Path) -> Path:
    normalized = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (normalized, *normalized.parents)):
        raise ReleaseError("symlink-path")
    return normalized


def _read_file(path: str | Path, *, limit: int, private: bool = False) -> bytes:
    selected = _path(path)
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= limit:
            raise ReleaseError("unsafe-input-file")
        if private and stat.S_IMODE(info.st_mode) & 0o077:
            raise ReleaseError("signing-key-permissions-must-be-0600")
        payload = stream.read(limit + 1)
    if not 1 <= len(payload) <= limit:
        raise ReleaseError("input-file-size")
    return payload


def _write_new_files(outputs: dict[Path, tuple[bytes, int]]) -> None:
    """Publish fully written local files exclusively; roll back only our new links."""
    selected = {_path(path): value for path, value in outputs.items()}
    if len(selected) != len(outputs):
        raise ReleaseError("duplicate-output-path")
    for path in selected:
        if path.exists() or not path.parent.is_dir():
            raise ReleaseError("output-exists-or-parent-missing")
    staged: list[tuple[Path, Path]] = []
    published: list[tuple[Path, int, int]] = []
    try:
        for destination, (payload, mode) in selected.items():
            descriptor, temporary_name = tempfile.mkstemp(prefix=".release-", dir=destination.parent)
            temporary = Path(temporary_name)
            staged.append((temporary, destination))
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        for temporary, destination in staged:
            _path(destination)
            os.link(temporary, destination, follow_symlinks=False)
            info = temporary.stat()
            published.append((destination, info.st_dev, info.st_ino))
    except BaseException:
        for destination, device, inode in reversed(published):
            info = destination.lstat()
            if (info.st_dev, info.st_ino) == (device, inode):
                destination.unlink()
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def keygen(private_key: Path, public_key: Path) -> None:
    private_path, public_path = _path(private_key), _path(public_key)
    if private_path == public_path:
        raise ReleaseError("duplicate-output-path")
    # Preflight both destinations before generating any private material.
    for path in (private_path, public_path):
        if path.exists() or not path.parent.is_dir():
            raise ReleaseError("output-exists-or-parent-missing")
    private = Ed25519PrivateKey.generate()
    _write_new_files({
        private_path: (base64.b64encode(private.private_bytes_raw()) + b"\n", 0o600),
        public_path: (base64.b64encode(private.public_key().public_bytes_raw()) + b"\n", 0o644),
    })


def _validate_repository(repository: str) -> None:
    match = _REPOSITORY.fullmatch(repository)
    if match is None or "--" in match[1] or match[2] in {".", ".."}:
        raise ReleaseError("invalid-repository")


def _channel_bytes(public_key: str, repository: str) -> bytes:
    from litechecker.update_manifest import parse_channel_config

    _validate_repository(repository)
    configuration = {
        "schema": 1, "enabled": True, "public_key": public_key,
        "manifest_urls": [f"https://github.com/{repository}/releases/latest/download/release.json"],
    }
    payload = (json.dumps(configuration, indent=2) + "\n").encode("utf-8")
    parse_channel_config(payload)
    return payload


def channel(*, public_key: Path, repository: str, output: Path) -> None:
    encoded_public = _read_file(public_key, limit=128).strip().decode("ascii")
    payload = _channel_bytes(encoded_public, repository)
    _write_new_files({output: (payload, 0o644)})


def build_release(*, archive: Path, private_key: Path, output: Path,
                  version: str, sequence: str, repository: str) -> None:
    if not _VERSION.fullmatch(version):
        raise ReleaseError("invalid-version")
    if not re.fullmatch(r"[1-9][0-9]*", sequence, flags=re.ASCII):
        raise ReleaseError("invalid-sequence")
    _validate_repository(repository)
    if "PRIVATE" in archive.name.upper():
        raise ReleaseError("private-archive-forbidden")
    archive_bytes = _read_file(archive, limit=MAX_ARCHIVE_BYTES)

    # Use the installer's exact archive and metadata rules before producing a
    # publishable file. Keep imports here so keygen is usable independently.
    from litechecker.update_manifest import canonical_payload, parse_channel_config, verify_release_metadata
    from litechecker.update_store import validate_source_zip

    verified = validate_source_zip(archive_bytes)
    files = {item.path.as_posix(): item.data for item in verified.files}
    try:
        embedded = tomllib.loads(files["pyproject.toml"].decode("utf-8"))["project"]["version"]
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError, TypeError):
        raise ReleaseError("archive-project-version-missing") from None
    if embedded != version:
        raise ReleaseError("archive-project-version-mismatch")

    encoded_private = _read_file(private_key, limit=128, private=True).strip()
    try:
        raw_private = base64.b64decode(encoded_private, validate=True)
        if len(raw_private) != 32:
            raise ValueError
        private = Ed25519PrivateKey.from_private_bytes(raw_private)
    except (ValueError, binascii.Error):
        raise ReleaseError("invalid-signing-key") from None
    if any(raw_private in data or encoded_private in data for data in files.values()):
        raise ReleaseError("archive-contains-signing-key")

    public_key = private.public_key().public_bytes_raw()
    if "update-channel.json" in files:
        embedded_channel = parse_channel_config(files["update-channel.json"])
        if embedded_channel.public_key != public_key:
            raise ReleaseError("archive-channel-signing-key-mismatch")
    artifact_name = f"LiteChecker-{version}.zip"
    payload = {
        "version": version,
        "sequence": int(sequence),
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifact": {
            "urls": [f"https://github.com/{repository}/releases/download/v{version}/{artifact_name}"],
            "sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "size": len(archive_bytes),
        },
    }
    envelope = {
        "schema": 1, "payload": payload,
        "signature": base64.b64encode(private.sign(canonical_payload(payload))).decode("ascii"),
    }
    manifest_bytes = (json.dumps(envelope, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    verify_release_metadata(manifest_bytes, public_key)
    channel_payload = _channel_bytes(base64.b64encode(public_key).decode("ascii"), repository)
    output = _path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_new_files({
        output / artifact_name: (archive_bytes, 0o644),
        output / "release.json": (manifest_bytes, 0o644),
        output / "update-channel.json": (channel_payload, 0o644),
    })


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen", help="create an offline Ed25519 signing key pair")
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--public-key", type=Path, required=True)
    provision = commands.add_parser("channel", help="create public first-install update channel configuration")
    provision.add_argument("--public-key", type=Path, required=True)
    provision.add_argument("--repository", required=True)
    provision.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("build", help="verify and sign an existing secret-free source archive")
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--sequence", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--private-key", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "keygen":
            keygen(arguments.private_key, arguments.public_key)
            print("Signing key pair created. Keep the private key offline.")
        elif arguments.command == "channel":
            channel(public_key=arguments.public_key, repository=arguments.repository, output=arguments.output)
            print("Public update channel created. Existing installed trust is unchanged.")
        else:
            build_release(
                archive=arguments.archive, version=arguments.version,
                sequence=arguments.sequence, repository=arguments.repository,
                private_key=arguments.private_key, output=arguments.output,
            )
            print(f"Created LiteChecker-{arguments.version}.zip, release.json and update-channel.json. Nothing uploaded.")
    except ReleaseError as error:
        print(f"release: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ImportError):
        print("release: input-validation-or-output-failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

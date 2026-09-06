#!/usr/bin/env python3
"""Legacy author/test bundle; production releases use package_platforms.py."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "Dockerfile", ".dockerignore", "pyproject.toml", "uv.lock",
    "run.sh", "compose.standalone.yml", "compose.telegram-proxy.yml",
    "INSTALL.command", "INSTALL.sh", "INSTALL.bat", "INSTALL.ps1",
    "scripts/install.sh", "scripts/install-wsl.sh", "scripts/control.sh", "НАЧНИТЕ-ЗДЕСЬ.txt",
    "scripts/install-macos.sh", "scripts/native-direct.sh",
    "TRY-DIRECT.command", "scripts/try-direct.sh",
    "scripts/update.sh", "scripts/prepare-updater.sh",
    "docs/operations/updates.md",
    "LiteChecker.bat", "WINDOWS.md",
    "scripts/windows-native.ps1", "scripts/windows-app-entry.py",
    "scripts/windows-entry.py",
)


def _read_release_input(path: Path, *, root: Path | None = None) -> bytes:
    root = ROOT if root is None else root
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("release input must be inside the project") from exc
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink() or not current.is_dir():
            raise ValueError("release input must be a regular file")
    if path.is_symlink():
        raise ValueError("release input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("release input must be a regular file")
        return stream.read()


def _tree_files(relative: str, *, suffixes: frozenset[str]) -> list[Path]:
    root = ROOT / relative
    if root.is_symlink() or not root.is_dir():
        if relative == "src/litechecker":
            raise ValueError("release input directory must be a real directory")
        return []
    selected: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in dirnames:
            if (directory_path / name).is_symlink():
                raise ValueError("release input must be a regular file")
        for name in filenames:
            path = directory_path / name
            if path.is_symlink():
                raise ValueError("release input must be a regular file")
            if path.suffix in suffixes:
                selected.append(path)
    return sorted(selected)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-secrets", action="store_true", help="explicitly include common bot/subscription and optional Telegram proxy for trusted testers")
    parser.add_argument(
        "--direct-trial",
        action="store_true",
        help="compatibility alias; the standard archive already contains TRY-DIRECT.command",
    )
    arguments = parser.parse_args(argv)
    selected = [ROOT / name for name in FILES]
    selected += _tree_files("src/litechecker", suffixes=frozenset({".py"}))
    contents = {}
    for path in selected:
        contents[path.relative_to(ROOT).as_posix()] = _read_release_input(path)
    channel_path = ROOT / "update-channel.json"
    if channel_path.exists() or channel_path.is_symlink():
        from litechecker.native_runtime import read_bounded_regular
        from litechecker.update_manifest import parse_channel_config

        channel = read_bounded_regular(channel_path)
        parse_channel_config(channel)
        contents["update-channel.json"] = channel
    proxy_path = ROOT / "secrets/telegram_proxy_url"
    proxy_payload = None
    if proxy_path.exists() or proxy_path.is_symlink():
        if proxy_path.parent.is_symlink() or proxy_path.is_symlink() or not proxy_path.is_file() or not 1 <= proxy_path.stat().st_size <= 65_536:
            raise ValueError("shared Telegram proxy secret file is unsafe")
        proxy_payload = proxy_path.read_bytes()
        if not proxy_payload.strip():
            raise ValueError("shared Telegram proxy secret file is empty")
    # A content check also prevents an accidentally hardcoded local secret from
    # being shipped, without printing or including its value in an exception.
    for name in ("telegram_bot_token", "agent_token", "state_key", "subscription_url", "telegram_proxy_url", "update_signing_key"):
        secret_path = ROOT / "secrets" / name
        if secret_path.is_file():
            secret = secret_path.read_bytes().strip()
            if secret and any(secret in payload for payload in contents.values()):
                raise ValueError("local secret detected in release input")
    if arguments.with_secrets:
        for name in ("telegram_bot_token", "subscription_url"):
            path = ROOT / "secrets" / name
            if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 65_536:
                raise ValueError("shared secret file is missing or unsafe")
            payload = path.read_bytes()
            if not payload.strip():
                raise ValueError("shared secret file is empty")
            contents["secrets/" + name] = payload
        if proxy_payload is not None:
            contents["secrets/telegram_proxy_url"] = proxy_payload
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    contents["CONTENTS.sha256.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    filename = "LiteChecker-READY-PRIVATE.zip" if arguments.with_secrets else "LiteChecker-agent.zip"
    destination = ROOT / "dist" / filename
    if destination.parent.is_symlink():
        raise ValueError("release output directory must not be a symbolic link")
    destination.parent.mkdir(exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600 if arguments.with_secrets else 0o644)
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), 0o600 if arguments.with_secrets else 0o644)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(contents.items()):
                info = zipfile.ZipInfo(f"LiteChecker/{name}", date_time=(2026, 9, 5, 0, 0, 0))
                info.create_system = 3
                mode = 0o755 if name.startswith("scripts/") or name.endswith((".sh", ".command")) else 0o644
                if name.startswith("secrets/"):
                    mode = 0o600
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError("archive verification failed")
        assert len(archive.namelist()) == len(contents)
        for name, expected in manifest.items():
            assert hashlib.sha256(archive.read(f"LiteChecker/{name}")).hexdigest() == expected
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    checksum_path = destination.with_suffix(".zip.sha256")
    checksum_descriptor = os.open(checksum_path, flags, 0o600 if arguments.with_secrets else 0o644)
    with os.fdopen(checksum_descriptor, "w", encoding="utf-8") as checksum:
        os.fchmod(checksum.fileno(), 0o600 if arguments.with_secrets else 0o644)
        checksum.write(f"{digest}  {destination.name}\n")
    print(f"archive={destination.name} files={len(contents)} bytes={destination.stat().st_size}")
    print(f"sha256={digest}")


if __name__ == "__main__":
    main()

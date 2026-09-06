#!/usr/bin/env python3
"""Wrap validated desktop profiles unchanged in the compact launcher/_app layout."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import zipfile

from litechecker.update_store import MAX_ARCHIVE_BYTES, validate_source_zip


def safe_path(path: Path) -> Path:
    path = path.absolute()
    if any(item.is_symlink() or item.is_junction() for item in (path, *path.parents)):
        raise ValueError("distribution path must not contain links")
    return path


def build_package(source: Path, output: Path, *, platform: str = "windows") -> str:
    if platform not in {"windows", "macos"}:
        raise ValueError("unsupported desktop distribution")
    if platform == "windows":
        entry, launcher, guide = "LiteChecker.bat", "LiteChecker.bat", "WINDOWS.md"
        required = (entry, guide, "scripts/windows-app-entry.py", "scripts/windows-native.ps1")
    else:
        entry, launcher, guide = "scripts/macos-launcher.command", "INSTALL.command", "MACOS.md"
        required = (entry, guide, "INSTALL.command", "scripts/install-macos.sh", "scripts/control.sh", "distribution.json")
    source, output = safe_path(Path(source)), safe_path(Path(output))
    if not source.is_file() or not 1 <= source.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("source archive is unavailable or too large")
    validated = validate_source_zip(source.read_bytes())
    payloads = {item.path.as_posix(): item.data for item in validated.files}
    if "distribution.json" in payloads:
        from litechecker.distribution import parse_distribution

        if parse_distribution(payloads["distribution.json"]) != platform:
            raise ValueError("desktop wrapper requires a matching distribution")
    if any(name not in payloads for name in required):
        raise ValueError("source archive does not contain native desktop controls")
    checksum = safe_path(output.with_suffix(".zip.sha256"))
    if output.suffix.lower() != ".zip" or output.exists() or checksum.exists():
        raise ValueError("distribution output must be a new ZIP")
    if not output.parent.is_dir():
        raise ValueError("distribution output directory is missing")
    # ValidatedArchive deliberately excludes the hash manifest from files.
    # Preserve the original manifest bytes as well as every signed source file.
    with zipfile.ZipFile(source) as archive:
        manifest = archive.read("LiteChecker/CONTENTS.sha256.json")
    contents = {"LiteChecker/_app/" + name: data for name, data in payloads.items()}
    contents["LiteChecker/_app/CONTENTS.sha256.json"] = manifest
    contents["LiteChecker/" + launcher] = payloads[entry]
    contents["LiteChecker/НАЧНИТЕ-ЗДЕСЬ.txt"] = payloads[guide]
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    checksum_created = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(contents.items()):
                    item = zipfile.ZipInfo(name, date_time=(2026, 9, 6, 0, 0, 0))
                    item.create_system = 3
                    mode = 0o755 if platform == "macos" and name.endswith((".sh", ".command")) else 0o644
                    item.external_attr = (stat.S_IFREG | mode) << 16
                    archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(output) as archive:
            if archive.testzip() is not None:
                raise ValueError("distribution archive verification failed")
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        with checksum.open("x", encoding="ascii") as stream:
            checksum_created = True
            stream.write(f"{digest}  {output.name}\n")
        return digest
    except BaseException:
        output.unlink(missing_ok=True)
        if checksum_created:
            checksum.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=("windows", "macos"), default="windows")
    args = parser.parse_args(argv)
    print("sha256=" + build_package(args.source, args.output, platform=args.platform))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

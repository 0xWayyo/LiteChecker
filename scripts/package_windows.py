#!/usr/bin/env python3
"""Wrap validated universal source bytes in a compact Windows-facing layout."""
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


def build_package(source: Path, output: Path) -> str:
    source, output = safe_path(Path(source)), safe_path(Path(output))
    if not source.is_file() or not 1 <= source.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("source archive is unavailable or too large")
    validated = validate_source_zip(source.read_bytes())
    payloads = {item.path.as_posix(): item.data for item in validated.files}
    if any(name not in payloads for name in ("LiteChecker.bat", "WINDOWS.md", "scripts/windows-app-entry.py", "scripts/windows-native.ps1")):
        raise ValueError("source archive does not contain native Windows controls")
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
    contents["LiteChecker/LiteChecker.bat"] = payloads["LiteChecker.bat"]
    contents["LiteChecker/НАЧНИТЕ-ЗДЕСЬ.txt"] = payloads["WINDOWS.md"]
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    checksum_created = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(contents.items()):
                    item = zipfile.ZipInfo(name, date_time=(2026, 9, 6, 0, 0, 0))
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | 0o644) << 16
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
    args = parser.parse_args(argv)
    print("sha256=" + build_package(args.source, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

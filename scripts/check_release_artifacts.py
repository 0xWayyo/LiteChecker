#!/usr/bin/env python3
"""Reject release archives containing anything outside the package allowlist."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


_FORBIDDEN = frozenset(
    {".superpowers", ".worktrees", "secrets", "tests", "deploy", "scripts"}
)


def _safe_member(name: str, *, wheel: bool) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or _FORBIDDEN.intersection(path.parts):
        return False
    lowered = name.lower()
    if lowered.endswith((".diff", ".report")) or ".env" in path.parts:
        return False
    if wheel:
        return path.parts[0] == "litechecker" or (
            len(path.parts) > 1 and path.parts[0].endswith(".dist-info")
        )
    if len(path.parts) < 2:
        return path.parts[0].startswith("litechecker-")
    relative = PurePosixPath(*path.parts[1:])
    return relative in {
        PurePosixPath("PKG-INFO"),
        PurePosixPath("README.md"),
        PurePosixPath("pyproject.toml"),
        PurePosixPath(".gitignore"),
    } or relative.parts[:2] == ("src", "litechecker")


def check_directory(directory: Path) -> bool:
    archives = sorted(directory.glob("litechecker-*"))
    if not archives or not any(path.suffix == ".whl" for path in archives):
        return False
    if not any(path.name.endswith(".tar.gz") for path in archives):
        return False
    for archive in archives:
        wheel = archive.suffix == ".whl"
        if wheel:
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
        elif archive.name.endswith(".tar.gz"):
            with tarfile.open(archive) as bundle:
                members = bundle.getmembers()
                if any(not (member.isfile() or member.isdir()) for member in members):
                    return False
                names = [member.name for member in members]
        else:
            return False
        if not names or any(not _safe_member(name, wheel=wheel) for name in names):
            return False
    return True


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        return 64
    directory = Path(argv[0] if argv else "dist")
    return 0 if directory.is_dir() and check_directory(directory) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

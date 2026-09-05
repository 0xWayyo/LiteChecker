#!/usr/bin/env python3
"""Restore SQLite after collector shutdown with filesystem rollback on failure."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path


def _integrity_ok(path: Path) -> bool:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30) as database:
            return database.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    except sqlite3.Error:
        return False


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _restore_old_files(
    destination: Path,
    moved: list[tuple[Path, Path]],
    *,
    installed: bool,
) -> None:
    original_paths = {original for original, _ in moved}
    if installed and destination not in original_paths:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
    for original, rollback in moved:
        if rollback.exists():
            os.replace(rollback, original)
    _fsync_directory(destination.parent)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 64
    source = Path(argv[0]).resolve()
    destination = Path(argv[1]).resolve()
    if source == destination or not source.is_file() or not destination.parent.is_dir():
        return 2
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.restore.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    moved: list[tuple[Path, Path]] = []
    installed = False
    committed = False
    try:
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = -1
        if not _integrity_ok(source):
            raise sqlite3.DatabaseError("backup-integrity-failed")
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=30) as backup:
            with sqlite3.connect(temporary, timeout=30) as restored:
                backup.backup(restored)
        if not _integrity_ok(temporary):
            raise sqlite3.DatabaseError("staged-integrity-failed")
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())

        nonce = uuid.uuid4().hex
        for original in (
            destination,
            Path(f"{destination}-wal"),
            Path(f"{destination}-shm"),
        ):
            if original.exists():
                rollback = original.with_name(f".{original.name}.rollback.{nonce}")
                os.replace(original, rollback)
                moved.append((original, rollback))
        os.replace(temporary, destination)
        installed = True
        os.chmod(destination, 0o600)
        _fsync_directory(destination.parent)
        if not _integrity_ok(destination):
            raise sqlite3.DatabaseError("installed-integrity-failed")
        committed = True
    except (OSError, sqlite3.Error):
        try:
            _restore_old_files(destination, moved, installed=installed)
        except OSError:
            pass
        return 3
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not committed:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    for _, rollback in moved:
        with contextlib.suppress(FileNotFoundError):
            rollback.unlink()
    with contextlib.suppress(OSError):
        _fsync_directory(destination.parent)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Create an atomic, WAL-aware SQLite backup without printing database content."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 64
    source = Path(argv[0]).resolve()
    destination = Path(argv[1]).resolve()
    if source == destination or not source.is_file() or not destination.parent.is_dir():
        return 2
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = -1
        with sqlite3.connect(source, timeout=30) as source_db:
            with sqlite3.connect(temporary, timeout=30) as backup_db:
                source_db.backup(backup_db)
                if backup_db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    return 3
        os.replace(temporary, destination)
        return 0
    except (OSError, sqlite3.Error):
        return 3
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

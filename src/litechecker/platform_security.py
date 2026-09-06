"""Small filesystem-security boundary; NTFS implementation loads only on Windows."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


def is_windows() -> bool:
    return sys.platform == "win32"


def _windows():
    if __package__:
        from . import windows_security
    else:  # update_launcher.py can execute directly from the stable source.
        import windows_security
    return windows_security


def reject_reparse_points(path: Path) -> Path:
    if is_windows():
        return _windows().reject_reparse_points(path)
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith("\\\\"):
        raise ValueError("windows-path-unsafe")
    for current in (*reversed(path.parents), path):
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError("windows-reparse-path-unsafe")
    return path


def _assert_posix_private(path: Path, *, directory: bool) -> Path:
    path = reject_reparse_points(path)
    metadata = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode):
        raise ValueError("windows-private-path-type-invalid")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("private-path-permissions-unsafe")
    return path


def assert_private_directory(path: Path) -> Path:
    if is_windows():
        return _windows().assert_private_directory(path)
    return _assert_posix_private(path, directory=True)


def assert_private_file(path: Path) -> Path:
    if is_windows():
        return _windows().assert_private_file(path)
    return _assert_posix_private(path, directory=False)

"""Read explicitly selected public build inputs without following file links."""
from __future__ import annotations

import os
from pathlib import Path
import stat


def read_release_input(path: Path, *, root: Path) -> bytes:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("release input must be inside the project") from exc
    if ".." in relative.parts:
        raise ValueError("release input must be inside the project")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("release input must be a regular file")
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink() or not current.is_dir():
            raise ValueError("release input must be a regular file")
    if path.is_symlink():
        raise ValueError("release input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("release input must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)

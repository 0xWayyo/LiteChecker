"""Bounded reads and private atomic files for POSIX setup and installation."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile


MAX_NATIVE_FILE_BYTES = 65_536


def read_bounded_regular(path: Path, *, private: bool = False) -> bytes:
    """Read one bounded regular file without following links or blocking on a FIFO."""

    if path.is_symlink():
        raise ValueError("symbolic link input is not allowed")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= MAX_NATIVE_FILE_BYTES
        ):
            raise ValueError("input must be a bounded regular file")
        if private and os.name == "posix" and (
            metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            raise ValueError("private input permissions are unsafe")
        data = bytearray()
        while len(data) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(data))
            if not chunk:
                raise ValueError("input changed while reading")
            data.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("input changed while reading")
        return bytes(data)
    finally:
        os.close(descriptor)


def ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("installation path must not be a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("installation path must be a directory")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise ValueError("installation path owner is unsafe")
    path.chmod(0o700)


def atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    *,
    private_parent: bool = True,
) -> None:
    """Atomically replace one file after fsyncing its content, not its parent."""

    if private_parent:
        ensure_private_directory(path.parent)
    else:
        if path.parent.is_symlink():
            raise ValueError("destination directory must not be a symbolic link")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.is_dir():
            raise ValueError("destination directory is invalid")
    if path.is_symlink():
        raise ValueError("destination must not be a symbolic link")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        path.chmod(mode)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise

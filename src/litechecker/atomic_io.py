"""Small, bounded replacement boundary for already-written local state files."""

from __future__ import annotations

import os
from pathlib import Path
from time import monotonic as _monotonic, sleep as _sleep

from . import platform_security


def _check_retry_paths(source: Path, destination: Path) -> None:
    if source.parent != destination.parent:
        raise ValueError("atomic-replace-parent-mismatch")
    platform_security.reject_reparse_points(source)
    platform_security.reject_reparse_points(destination)
    platform_security.assert_private_directory(destination.parent)
    platform_security.assert_private_file(source)
    if destination.exists():
        platform_security.assert_private_file(destination)


def atomic_replace(source: str | Path, destination: str | Path) -> None:
    """Replace a closed, fsynced sibling temp without changing permissions.

    Windows deny-delete readers can cause ERROR_ACCESS_DENIED as well as
    sharing/lock violations. Retry only this final operation, for at most half
    a second; serialization, creation and fsync are never repeated. Callers
    retain ownership of temporary-file cleanup on failure.
    """
    if not platform_security.is_windows():
        os.replace(source, destination)
        return
    # mkstemp returns an absolute path even when callers pass a relative dir.
    # Do not resolve links here: retry validation must still see reparses.
    source, destination = Path(source).absolute(), Path(destination).absolute()
    deadline = _monotonic() + 0.5
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as error:
            if getattr(error, "winerror", None) not in (5, 32, 33):
                raise
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise
            _sleep(min(0.01, remaining))
            if _monotonic() >= deadline:
                raise
            try:
                _check_retry_paths(source, destination)
            except (OSError, ValueError):
                # Preserve the original OSError contract so callers' existing
                # fail-closed cleanup also runs when retry validation fails.
                raise error from None
            if _monotonic() >= deadline:
                raise

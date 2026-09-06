"""Strict distribution identity shared with the stdlib bootstrap launcher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

if __package__:
    from . import platform_security
else:
    import platform_security


PLATFORMS = frozenset({"windows", "macos", "linux"})
MAX_DISTRIBUTION_BYTES = 4096


class DistributionError(ValueError):
    """The package identity is missing, malformed or unsafe to read."""


def parse_distribution(data: bytes) -> str:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DistributionError("duplicate distribution field")
            result[key] = value
        return result

    if type(data) is not bytes or not 1 <= len(data) <= MAX_DISTRIBUTION_BYTES:
        raise DistributionError("distribution size is invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise DistributionError("distribution JSON is invalid") from error
    if (
        type(value) is not dict or set(value) != {"schema", "platform"}
        or type(value["schema"]) is not int or value["schema"] != 1
        or type(value["platform"]) is not str or value["platform"] not in PLATFORMS
    ):
        raise DistributionError("distribution fields or platform are invalid")
    return value["platform"]


def host_platform() -> str:
    try:
        return {"win32": "windows", "darwin": "macos", "linux": "linux"}[sys.platform]
    except KeyError:
        raise DistributionError("host platform is unsupported") from None


def read_distribution(root: Path) -> str | None:
    """Read a bounded regular marker; only an absent path returns None."""

    path = Path(root) / "distribution.json"
    try:
        platform_security.reject_reparse_points(path)
        try:
            details = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(details.st_mode):
            raise DistributionError("distribution path is unsafe")
        if platform_security.is_windows():
            platform_security.assert_private_file(path)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if (not stat.S_ISREG(details.st_mode) or not 1 <= details.st_size <= MAX_DISTRIBUTION_BYTES
                or not platform_security.is_windows() and
                (details.st_uid != os.geteuid() or details.st_mode & 0o022)):
                raise DistributionError("distribution file is unsafe")
            return parse_distribution(source.read(MAX_DISTRIBUTION_BYTES + 1))
    except (OSError, ValueError) as error:
        raise DistributionError("distribution cannot be read safely") from error

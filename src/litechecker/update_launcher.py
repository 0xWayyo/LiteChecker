"""Small stable stdlib launcher; installation state never supplies executable paths."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

if __package__:
    from . import distribution, platform_security
else:  # The stable POSIX entry also executes this file directly.
    sys.path.insert(0, str(Path(__file__).absolute().parent))
    import distribution
    import platform_security


VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class LauncherError(ValueError):
    def __init__(self):
        super().__init__("unsafe-update-launcher-state")


def checked_path(root: Path, path: Path, *, regular: bool = False) -> Path:
    root, path = Path(root).absolute(), Path(path).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise LauncherError() from None
    if ".." in relative.parts or root.is_symlink() or not root.is_dir():
        raise LauncherError()
    if platform_security.is_windows():
        try:
            platform_security.reject_reparse_points(path)
            platform_security.assert_private_directory(root)
            directory = root
            for component in relative.parts:
                directory /= component
                if directory.is_dir():
                    platform_security.assert_private_directory(directory)
        except (OSError, ValueError):
            raise LauncherError() from None
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise LauncherError()
    if regular and (not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise LauncherError()
    return path


def read_json(root: Path, path: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LauncherError()
            result[key] = value
        return result
    try:
        value = json.loads(read_bytes(root, path).decode("utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, ValueError):
        raise LauncherError() from None
    if not isinstance(value, dict):
        raise LauncherError()
    return value


def read_bytes(root: Path, path: Path, maximum=65536) -> bytes:
    checked_path(root, path, regular=True)
    windows = platform_security.is_windows()
    if windows:
        platform_security.assert_private_directory(root)
        platform_security.assert_private_file(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum or (not windows and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022)):
            raise LauncherError()
        data = bytearray()
        while chunk := os.read(fd, min(8192, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise LauncherError()
        return bytes(data)
    finally:
        os.close(fd)


def validate_baseline(root: Path) -> Path:
    root = checked_path(Path(root), Path(root))
    try:
        platform = distribution.read_distribution(root)
        if platform is not None and platform != distribution.host_platform():
            raise LauncherError()
        channel_path = checked_path(root, root / ".updates/channel.json")
        if not channel_path.exists():
            channel_path = checked_path(root, root / "update-channel.json")
        if channel_path.exists():
            channel = read_json(root, channel_path)
            if platform is not None:
                if type(channel.get("schema")) is not int or channel["schema"] != 2 or channel.get("platform") != platform:
                    raise LauncherError()
            elif channel.get("schema") == 2 or "platform" in channel:
                raise LauncherError()
    except (OSError, ValueError):
        raise LauncherError() from None
    return root


def select_release(root: Path) -> Path:
    root = validate_baseline(root)
    platform = distribution.read_distribution(root)
    state = checked_path(root, root / ".updates/install.json")
    if not state.exists():
        return root
    active = read_json(root, state).get("active")
    if active is None:
        return root
    if not isinstance(active, str) or VERSION.fullmatch(active) is None:
        raise LauncherError()
    release = checked_path(root, root / ".updates/releases" / active)
    # The bootstrap installation remains available for interrupted-state recovery.
    if not release.is_dir():
        return root
    marker = checked_path(root, release / ".litechecker-update-owned")
    digest = checked_path(root, release / ".artifact.sha256")
    if not marker.exists() or not digest.exists():
        return root
    if read_bytes(root, marker, 64) != b"litechecker-updater-v1\n" or re.fullmatch(rb"[a-f0-9]{64}\n?", read_bytes(root, digest, 65)) is None:
        raise LauncherError()
    try:
        if distribution.read_distribution(release) != platform:
            raise LauncherError()
    except (OSError, ValueError):
        raise LauncherError() from None
    return release


def runtime_python(release: Path, *, system: str | None = None) -> Path:
    selected_system = system or sys.platform
    if selected_system in {"Windows", "win32"}:
        executable = release / ".windows-native/venv/Scripts/python.exe"
        try:
            checked_path(release, executable, regular=True)
            platform_security.reject_reparse_points(executable)
            platform_security.assert_private_directory(release)
            platform_security.assert_private_file(executable)
        except (OSError, ValueError):
            raise LauncherError() from None
        return executable
    native = selected_system in {"darwin", "Darwin"}
    runtime = release / (".native-direct" if native else ".updater-runtime")
    executable = runtime / "venv/bin/python"
    checked_path(release, executable.parent)
    try:
        resolved = executable.resolve(strict=True)
        resolved.relative_to(runtime)
        metadata = resolved.stat()
    except (OSError, ValueError):
        raise LauncherError() from None
    if (
        not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o100
        or metadata.st_mode & 0o022 or metadata.st_uid != os.geteuid()
    ):
        raise LauncherError()
    return executable


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args, remaining = parser.parse_known_args(argv)
    try:
        root = args.root.absolute()
        if remaining and remaining[0] in {"menu", "folder", "settings"}:
            # Keep stop/status's stable launcher stdlib-only. UI dispatch needs
            # the prepared runtime's process identity and short lock support.
            sys.path.insert(0, str(root / "src"))
            from litechecker.runtime_lease import launch_menu
            return launch_menu(root, remaining[0])
        # Stopping must remain available even when an active release or its
        # selector is damaged. Bootstrap code has the stable control contract.
        release = checked_path(root, root) if remaining and remaining[0] == "stop" else select_release(root)
        checked_path(release, release / "src/litechecker/update_service.py", regular=True)
        python = runtime_python(release)
        env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        env.update(PYTHONPATH=str(release / "src"), PYTHONDONTWRITEBYTECODE="1")
        os.execve(str(python), [str(python), "-m", "litechecker.update_service", *remaining, "--root", str(root)], env)
    except Exception:
        print("updater-launcher-unavailable", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""macOS native runtime paths, validation and launchd serialization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from litechecker.update_launcher import checked_path, runtime_python
from litechecker.file_safety import atomic_write, ensure_private_directory, read_bounded_regular


DIRECT_SERVICE_LABEL = "com.litechecker.direct"
UPDATER_SERVICE_LABEL = "com.litechecker.updater"


@dataclass(frozen=True)
class NativeRuntimePaths:
    root: Path
    runtime: Path
    python: Path
    xray: Path
    state: Path


def launch_agents_directory(
    environment: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
) -> Path:
    """Return the shell-launcher-compatible per-user LaunchAgents directory."""

    values = os.environ if environment is None else environment
    override = values.get("LITECHECKER_LAUNCH_AGENTS_DIR")
    if override:
        return Path(override)
    return (Path.home() if home is None else Path(home)) / "Library/LaunchAgents"


def direct_service_plist_path(launch_agents: Path | None = None) -> Path:
    directory = launch_agents_directory() if launch_agents is None else Path(launch_agents)
    return directory / f"{DIRECT_SERVICE_LABEL}.plist"


def updater_plist_path(launch_agents: Path | None = None) -> Path:
    directory = launch_agents_directory() if launch_agents is None else Path(launch_agents)
    return directory / f"{UPDATER_SERVICE_LABEL}.plist"


def ensure_launch_agents_directory(path: Path) -> Path:
    """Create a user-owned LaunchAgents directory without traversing path links."""

    directory = Path(path).absolute()
    for candidate in (directory, *directory.parents):
        if candidate.is_symlink():
            raise ValueError("launch agents path must not contain a symbolic link")
    directory.mkdir(parents=True, exist_ok=True)
    metadata = directory.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("launch agents path must be a directory")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise ValueError("launch agents path owner is unsafe")
    return directory


def native_runtime_paths(root: Path) -> NativeRuntimePaths:
    root = Path(root).absolute()
    runtime = root / ".native-direct"
    return NativeRuntimePaths(
        root=root,
        runtime=runtime,
        python=runtime / "venv/bin/python",
        xray=runtime / "xray",
        state=root / "state/native-direct",
    )


def validate_native_runtime(root: Path) -> NativeRuntimePaths:
    """Validate the owned executable paths while allowing uv's internal Python link."""

    paths = native_runtime_paths(root)
    python = runtime_python(paths.root, system="Darwin")
    xray = checked_path(paths.root, paths.xray, regular=True)
    metadata = xray.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & 0o100
        or metadata.st_mode & 0o022
        or metadata.st_uid != os.geteuid()
    ):
        raise ValueError("native Xray is incomplete or unsafe")
    return NativeRuntimePaths(
        root=paths.root,
        runtime=paths.runtime,
        python=python,
        xray=xray,
        state=paths.state,
    )


def build_direct_service_plist(data_root: Path, release_root: Path) -> dict:
    """Build the one launchd schema used by initial install and signed updates."""

    data_root = Path(data_root).absolute()
    release = validate_native_runtime(Path(release_root).absolute())
    return {
        "Label": DIRECT_SERVICE_LABEL,
        "ProgramArguments": [
            str(release.python),
            "-m",
            "litechecker.macos_service",
            "--root",
            str(data_root),
            "--xray",
            str(release.xray),
        ],
        "WorkingDirectory": str(release.root),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "Umask": 0o077,
        "ProcessType": "Background",
        "StandardOutPath": str(data_root / "state/native-direct/service.log"),
        "StandardErrorPath": str(data_root / "state/native-direct/service.log"),
        "EnvironmentVariables": {
            "PYTHONPATH": str(release.root / "src"),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    }

"""Bounded lifecycle records. Executable paths are derived, never trusted from state."""
from __future__ import annotations

import math
import os
from pathlib import Path
import re
import sys
import tomllib

import psutil

from litechecker.state import _atomic_write_json
from litechecker.update_launcher import checked_path, read_bytes, read_json, runtime_python


NONCE = re.compile(r"[a-f0-9]{32}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def safe_root(root: Path) -> Path:
    root = Path(root).absolute()
    if ".." in root.parts:
        raise ValueError("unsafe-windows-root")
    checked_path(root, root)
    if sys.platform == "win32":
        from litechecker.windows_security import assert_private_directory
        assert_private_directory(root)
    return root


def release_path(root: Path, release: Path) -> Path:
    root, release = safe_root(root), Path(release).absolute()
    if release != root:
        if release.parent != root / ".updates" / "releases" or VERSION.fullmatch(release.name) is None:
            raise ValueError("unsafe-worker-release")
    checked_path(root, release)
    if not release.is_dir():
        raise ValueError("missing-worker-release")
    return release


def version(release: Path) -> str | None:
    try:
        data = tomllib.loads(read_bytes(release, release / "pyproject.toml", 65536).decode("utf-8"))
        value = data["project"]["version"]
        return value if isinstance(value, str) and VERSION.fullmatch(value) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def control_path(root: Path, name: str) -> Path:
    if not re.fullmatch(r"[a-z-]+\.(?:json|lock)", name):
        raise ValueError("invalid-control-file")
    return checked_path(root, root / "windows-state" / "control" / name)


def read_record(root: Path, name: str) -> dict | None:
    path = control_path(root, name)
    if not path.exists():
        return None
    return read_json(root, path)


def write_record(root: Path, name: str, value: dict) -> None:
    root = safe_root(root)
    path = control_path(root, name)
    (root / "windows-state").mkdir(mode=0o700, exist_ok=True)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    checked_path(root, path)
    _atomic_write_json(path, value)


def command(root: Path, release: Path, role: str, instance: str) -> list[str]:
    if role not in {"worker", "supervisor"} or NONCE.fullmatch(instance) is None:
        raise ValueError("invalid-process-command")
    release = release_path(root, release)
    executable = runtime_python(release, system="Windows")
    entry = checked_path(release, release / "scripts" / "windows-app-entry.py", regular=True)
    result = [str(executable), "-I", "-B", str(entry), role, "--root", str(root)]
    if role == "worker":
        result += ["--release", str(release)]
    return result + ["--instance", instance]


def process_record(root: Path, release: Path, role: str, instance: str, *, phase="starting", **extra) -> dict:
    process = psutil.Process()
    return {"schema": 1, "role": role, "pid": process.pid, "created": process.create_time(),
            "instance": instance, "release": str(release), "phase": phase,
            "version": version(release), **extra}


def process_exists(record: dict) -> bool:
    """A PID reused after exit/reboot is not the recorded process.

    AccessDenied deliberately propagates: inability to inspect identity is not
    proof that the process exited, and must not enable a duplicate worker.
    """
    pid = record.get("pid")
    created = record.get("created")
    if (type(pid) is not int or not 0 < pid <= 0xFFFFFFFF
            or type(created) not in (int, float) or not math.isfinite(created) or created <= 0):
        raise ValueError("invalid-process-record")
    try:
        process = psutil.Process(pid)
        return abs(process.create_time() - created) <= 0.001 and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def process_matches(root: Path, record: dict, role: str) -> bool:
    try:
        if record.get("schema") != 1 or record.get("role") != role:
            return False
        created, instance = record.get("created"), record.get("instance")
        if (type(created) not in (int, float) or not math.isfinite(created)
                or not isinstance(instance, str) or NONCE.fullmatch(instance) is None
                or not process_exists(record)):
            return False
        release = root if role == "supervisor" else release_path(root, Path(record["release"]))
        expected = command(root, release, role, instance)
        executable, _ = python_launch(release)
        process = psutil.Process(record["pid"])
        if (not process.is_running() or process.status() == psutil.STATUS_ZOMBIE
                or abs(process.create_time() - created) > 0.001):
            return False
        if os.path.normcase(process.exe()) != os.path.normcase(str(executable)):
            return False
        actual = process.cmdline()
        return (len(actual) == len(expected)
                and os.path.normcase(actual[0]) == os.path.normcase(expected[0])
                and actual[1:] == expected[1:])
    except (OSError, ValueError, TypeError, KeyError, psutil.Error):
        return False


def clean_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(("PYTHON", "PYLAUNCHER", "LC_"))
            and key.upper() != "__PYVENV_LAUNCHER__"}


def python_launch(release: Path) -> tuple[Path, dict[str, str]]:
    """Launch the protected base directly, retaining the venv's Python identity.

    CPython's Windows venv executable is a redirector that creates another
    process. Bypassing it lets the supervisor assign the actual gated worker to
    its Job Object before the worker is allowed to create any children.
    """
    from litechecker.windows_security import assert_private_file

    release = safe_root(release)
    venv = runtime_python(release, system="Windows")
    cfg = checked_path(release, release / ".windows-native/venv/pyvenv.cfg", regular=True)
    assert_private_file(cfg)
    homes = [line.partition("=")[2].strip() for line in read_bytes(release, cfg, 8192).decode("utf-8").splitlines()
             if line.partition("=")[0].strip().lower() == "home"]
    if len(homes) != 1 or not homes[0]:
        raise ValueError("unsafe-managed-python")
    home = Path(homes[0])
    if not home.is_absolute() or ".." in home.parts:
        raise ValueError("unsafe-managed-python")
    native = release / ".windows-native"
    try:
        home.relative_to(native)
    except ValueError:
        raise ValueError("unsafe-managed-python") from None
    executable = checked_path(release, home / "python.exe", regular=True)
    if executable == venv:
        raise ValueError("unsafe-managed-python")
    assert_private_file(executable)
    environment = clean_environment()
    environment["__PYVENV_LAUNCHER__"] = str(venv)
    return executable, environment

"""Shared POSIX host command, desired-state and adapter controls."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import signal

from filelock import AsyncFileLock

from litechecker.state import _atomic_write_json
from litechecker.update_launcher import VERSION, checked_path, read_json


class UpdatePlatformError(RuntimeError):
    def __init__(
        self,
        code="update-platform-unavailable",
        *,
        operation: str | None = None,
        reason: str | None = None,
        exit_code: int | None = None,
    ):
        super().__init__(code)
        self.operation = operation
        self.reason = reason
        self.exit_code = exit_code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""


def _command_operation(args) -> str:
    try:
        executable = Path(str(args[0])).name
    except (IndexError, TypeError):
        return "owned-command"
    if executable in {"bash", "docker", "launchctl", "systemctl"}:
        return executable
    if re.fullmatch(r"python(?:3(?:\.[0-9]+)?)?", executable):
        return "python"
    return "owned-command"


async def run_command(args, *, cwd=None, env=None, timeout=30) -> CommandResult:
    """Run an owned subprocess with bounded output/deadline and child cleanup."""
    process = None
    operation = _command_operation(args)
    try:
        async with asyncio.timeout(timeout):
            process = await asyncio.create_subprocess_exec(
                *map(str, args), cwd=cwd, env=env, start_new_session=True,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            output = bytearray()
            while chunk := await process.stdout.read(8192):
                output.extend(chunk)
                if len(output) > 65536:
                    raise UpdatePlatformError(
                        "update-command-output-limit",
                        operation=operation,
                        reason="output-limit",
                    )
            await process.wait()
            return CommandResult(process.returncode, output.decode("utf-8", errors="replace"))
    except asyncio.CancelledError:
        raise
    except UpdatePlatformError:
        raise
    except TimeoutError:
        raise UpdatePlatformError(
            "update-command-failed", operation=operation, reason="timeout"
        ) from None
    except Exception:
        raise UpdatePlatformError(
            "update-command-failed", operation=operation, reason="execution-failed"
        ) from None
    finally:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()


def _system(system=None):
    result = system or platform.system()
    if result not in {"Darwin", "Linux"}:
        raise UpdatePlatformError("update-platform-unsupported")
    return result


def _state_dir(root, system):
    return root / "state" / ("native-direct" if system == "Darwin" else "standalone")


def record_desired_running(root: Path, running: bool, *, system=None) -> None:
    if type(running) is not bool:
        raise UpdatePlatformError("desired-running-invalid")
    root = Path(root).absolute()
    path = checked_path(root, _state_dir(root, _system(system)) / "desired-running.json")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _atomic_write_json(path, {"running": running})


class _Adapter:
    def __init__(self, root, *, runner=None, system):
        self.baseline = checked_path(Path(root), Path(root))
        self._runner = runner or run_command
        self.system = system
        self.state_dir = _state_dir(self.baseline, system)
        self.maintenance_lock = self.state_dir / "maintenance.lock"

    def _release(self, release):
        release = checked_path(self.baseline, Path(release))
        if release != self.baseline:
            if release.parent != self.baseline / ".updates/releases" or not VERSION.fullmatch(release.name):
                raise UpdatePlatformError("update-release-path-invalid")
        if not release.is_dir():
            raise UpdatePlatformError("update-release-unavailable")
        return release

    def _desired(self, fallback):
        path = checked_path(self.baseline, self.state_dir / "desired-running.json")
        if not path.exists():
            return fallback
        state = read_json(self.baseline, path)
        if set(state) != {"running"} or type(state["running"]) is not bool:
            raise UpdatePlatformError("desired-running-invalid")
        return state["running"]

    async def is_running(self):
        desired = self._desired(None)
        return desired if desired is not None else await self._actual_running()

    def _control_lock(self):
        checked_path(self.baseline, self.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = checked_path(self.baseline, self.state_dir / "service-control.lock")
        return AsyncFileLock(path, timeout=30, mode=0o600, preserve_lock_file=True)

    async def _run(self, args, *, cwd=None, env=None, timeout=30, allow_failure=False):
        result = await self._runner(args, cwd=cwd, env=env, timeout=timeout)
        if result.returncode and not allow_failure:
            exit_code = result.returncode if type(result.returncode) is int else None
            raise UpdatePlatformError(
                "update-command-failed",
                operation=_command_operation(args),
                reason="nonzero-exit",
                exit_code=exit_code,
            )
        return result

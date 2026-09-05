"""Native Windows adapter for the shared authenticated update transaction."""
from __future__ import annotations

import asyncio
import ctypes
import os
from pathlib import Path
import subprocess
import uuid

from litechecker.update_launcher import VERSION, checked_path, read_bytes, runtime_python


class WindowsUpdateError(RuntimeError):
    def __init__(self, code="windows-update-unavailable"):
        super().__init__(code)


def powershell_path() -> Path:
    """Resolve Windows' own executable without PATH or user environment lookup."""
    if os.name != "nt":
        raise WindowsUpdateError("windows-host-required")
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    function.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise WindowsUpdateError("windows-system-directory-unavailable")
    executable = Path(buffer.value) / "WindowsPowerShell/v1.0/powershell.exe"
    if not executable.is_file():
        raise WindowsUpdateError("windows-powershell-unavailable")
    return executable


async def run_command(args, *, cwd: Path, timeout: float, python_release: Path | None = None) -> None:
    """Bound output and lifetime; preparation waits for job assignment first."""
    from litechecker.windows_job import WindowsJob
    from litechecker.windows_security import assert_private_directory

    if os.name != "nt":
        raise WindowsUpdateError("windows-host-required")
    command = list(map(str, args))
    gate = None
    instance = uuid.uuid4().hex
    if "-Action" in command and command[command.index("-Action") + 1] == "Prepare":
        root = assert_private_directory(Path(command[command.index("-Root") + 1]))
        state = checked_path(root, root / "windows-state")
        state.mkdir(mode=0o700, exist_ok=True)
        gate = checked_path(root, state / f"prepare-{instance}.gate")
        command.extend(["-PrepareGate", instance])
    from litechecker.windows_process_state import clean_environment
    environment = clean_environment()
    launch_options = {}
    if python_release is not None:
        from litechecker.windows_process_state import python_launch
        executable, environment = python_launch(python_release)
        if Path(command[0]) != runtime_python(python_release, system="Windows"):
            raise WindowsUpdateError("windows-python-launch-invalid")
        launch_options["executable"] = str(executable)
    process = None
    job = WindowsJob()
    try:
        async with asyncio.timeout(timeout):
            process = await asyncio.create_subprocess_exec(
                *command, cwd=cwd, env=environment, **launch_options,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            job.assign(process.pid)
            if gate is not None:
                with gate.open("xb") as stream:
                    stream.write(instance.encode("ascii"))
            count = 0
            while chunk := await process.stdout.read(8192):
                count += len(chunk)
                if count > 65536:
                    raise WindowsUpdateError("windows-update-output-limit")
            if await process.wait():
                raise WindowsUpdateError("windows-update-command-failed")
    except asyncio.CancelledError:
        raise
    except WindowsUpdateError:
        raise
    except Exception:
        raise WindowsUpdateError("windows-update-command-failed") from None
    finally:
        # The validation child never starts descendants; the Prepare child is
        # gated until job assignment, so all uv/Python descendants belong here.
        job.close()
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
        if gate is not None:
            gate.unlink(missing_ok=True)


class WindowsUpdateAdapter:
    def __init__(self, root: Path, *, host=None, runner=None, powershell=None):
        self.baseline = checked_path(Path(root), Path(root))
        self.maintenance_lock = self.baseline / "windows-state/maintenance.lock"
        self._host = host
        self._runner = runner or run_command
        self._powershell = powershell

    def _release(self, release: Path) -> Path:
        try:
            release = checked_path(self.baseline, release)
            if not release.is_dir():
                raise ValueError
            if release != self.baseline:
                if release.parent != self.baseline / ".updates/releases" or not VERSION.fullmatch(release.name):
                    raise ValueError
                if read_bytes(self.baseline, release / ".litechecker-update-owned", 64) != b"litechecker-updater-v1\n":
                    raise ValueError
                digest = read_bytes(self.baseline, release / ".artifact.sha256", 65).strip()
                if len(digest) != 64 or any(char not in b"0123456789abcdef" for char in digest):
                    raise ValueError
            return release
        except Exception:
            raise WindowsUpdateError("windows-release-path-invalid") from None

    async def _validate(self, release: Path) -> None:
        executable = runtime_python(release, system="Windows")
        entry = checked_path(release, release / "scripts/windows-app-entry.py", regular=True)
        checked_path(release, release / ".windows-native/tools/xray/xray.exe", regular=True)
        await self._runner(
            [str(executable), "-I", "-B", str(entry), "worker", "--validate",
             "--root", str(self.baseline), "--release", str(release)],
            cwd=release, timeout=30, python_release=release,
        )

    async def prepare(self, release: Path) -> None:
        try:
            release = self._release(release)
            script = checked_path(release, release / "scripts/windows-native.ps1", regular=True)
            await self._runner(
                [str(self._powershell or powershell_path()), "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", str(script), "-Root", str(self.baseline), "-Action", "Prepare"],
                cwd=release, timeout=600,
            )
            await self._validate(release)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise WindowsUpdateError("windows-release-prepare-failed") from None

    async def is_running(self) -> bool:
        return bool(self._host is not None and self._host.is_running())

    async def activate(self, release: Path, running: bool) -> None:
        release = self._release(release)
        if type(running) is not bool:
            raise WindowsUpdateError("windows-running-state-invalid")
        if self._host is not None:
            await self._host.activate_release(release, running)
        elif running:
            raise WindowsUpdateError("windows-supervisor-required")
        else:
            await self._validate(release)

    async def healthy(self, release: Path, running: bool) -> bool:
        try:
            release = self._release(release)
            if type(running) is not bool:
                return False
            if self._host is not None:
                return bool(await self._host.healthy_release(release, running))
            if running:
                return False
            await self._validate(release)
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

"""macOS launchd update adapter and explicit service operations."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import plistlib
import re
import subprocess

from litechecker.native_runtime import (
    DIRECT_SERVICE_LABEL,
    UPDATER_SERVICE_LABEL,
    atomic_write,
    build_direct_service_plist,
    direct_service_plist_path,
    ensure_launch_agents_directory,
    launch_agents_directory,
    updater_plist_path,
)
from litechecker.update_host import _Adapter, UpdatePlatformError
from litechecker.update_launcher import checked_path, runtime_python


class NativeUpdateAdapter(_Adapter):
    def __init__(self, root, *, runner=None, launch_agents=None):
        super().__init__(root, runner=runner, system="Darwin")
        self.launch_agents = Path(launch_agents) if launch_agents is not None else launch_agents_directory()
        self.plist = direct_service_plist_path(self.launch_agents)
        self.target = f"gui/{os.getuid()}/{DIRECT_SERVICE_LABEL}"

    async def _actual_running(self):
        result = await self._run(["launchctl", "print", self.target], allow_failure=True)
        return result.returncode == 0 and re.search(r"(?m)^\s*state = running\s*$", result.stdout) is not None

    async def prepare(self, release):
        try:
            release = self._release(release)
            script = checked_path(release, release / "scripts/native-direct.sh", regular=True)
            await self._run(["/bin/bash", str(script), "prepare", "--root", str(release)], timeout=600)
            python = runtime_python(release, system="Darwin")
            checked_path(self.baseline, self.state_dir / "device.json", regular=True)
            code = "import sys, litechecker.updater, litechecker.update_service, litechecker.update_platform; from pathlib import Path; from litechecker.macos_service import service_settings; service_settings(Path(sys.argv[1]), Path(sys.argv[2]))"
            env = {**os.environ, "PYTHONPATH": str(release / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
            env.pop("PYTHONHOME", None)
            await self._run([str(python), "-c", code, str(self.baseline), str(release / ".native-direct/xray")], cwd=release, env=env)
        except Exception:
            raise UpdatePlatformError("native-prepare-failed") from None

    def _write_plist(self, release, python):
        if self.plist.is_symlink():
            raise UpdatePlatformError("native-plist-unsafe")
        ensure_launch_agents_directory(self.launch_agents)
        payload = build_direct_service_plist(self.baseline, release)
        if payload["ProgramArguments"][0] != str(python):
            raise UpdatePlatformError("native-runtime-invalid")
        atomic_write(self.plist, plistlib.dumps(payload), 0o600, private_parent=False)

    async def activate(self, release, running):
        try:
            release = self._release(release)
            python = runtime_python(release, system="Darwin")
            checked_path(release, release / ".native-direct/xray", regular=True)
            ensure_launch_agents_directory(self.launch_agents)
            async with self._control_lock():
                await self._run(["launchctl", "bootout", self.target], allow_failure=True)
                self._write_plist(release, python)
                if self._desired(running):
                    await self._run(["launchctl", "enable", self.target])
                    for attempt in range(10):
                        if not self._desired(running):
                            break
                        result = await self._run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(self.plist)], allow_failure=True)
                        if result.returncode == 0:
                            break
                        if result.returncode != 5 or attempt == 9:
                            raise UpdatePlatformError("native-activation-failed")
                        await asyncio.sleep(1)
                    if not self._desired(running):
                        await self._run(["launchctl", "disable", self.target])
                        await self._run(["launchctl", "bootout", self.target], allow_failure=True)
                else:
                    await self._run(["launchctl", "disable", self.target])
        except Exception:
            raise UpdatePlatformError("native-activation-failed") from None

    async def healthy(self, release, running):
        try:
            release = self._release(release)
            runtime_python(release, system="Darwin")
            if self.plist.is_symlink():
                return False
            payload = plistlib.loads(self.plist.read_bytes())
            if payload.get("WorkingDirectory") != str(release):
                return False
            previous_pid = None
            for attempt in range(12):
                observation = await self._run(["launchctl", "print", self.target], allow_failure=True)
                active = observation.returncode == 0 and re.search(r"(?m)^\s*state = running\s*$", observation.stdout) is not None
                if not self._desired(running):
                    return not active
                pid = re.search(r"(?m)^\s*pid = ([1-9][0-9]*)\s*$", observation.stdout)
                program = re.search(r"(?m)^\s*program = (.+)$", observation.stdout)
                selected = program and program[1].strip() == str(runtime_python(release, system="Darwin"))
                if active and selected and pid:
                    if previous_pid == pid[1]:
                        return True
                    previous_pid = pid[1]
                else:
                    previous_pid = None
                if attempt < 11:
                    await asyncio.sleep(0.5)
            return False
        except Exception:
            return False

    async def stop_live(self):
        async with self._control_lock():
            await self._run(["launchctl", "disable", self.target])
            result = await self._run(["launchctl", "bootout", self.target], allow_failure=True)
            if result.returncode and await self._actual_running():
                raise UpdatePlatformError("native-stop-failed")


async def run_probe(adapter, release):
    python = runtime_python(release, system="Darwin")
    env = {**os.environ, "PYTHONPATH": str(release / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("PYTHONHOME", None)
    await adapter._run([str(python), "-m", "litechecker.macos_service", "--root", str(adapter.baseline), "--xray", str(release / ".native-direct/xray"), "--once"], cwd=release, env=env, timeout=600)


def install_update_schedule(root, python, launcher):
    launch_agents = ensure_launch_agents_directory(launch_agents_directory())
    destination = updater_plist_path(launch_agents)
    payload = {"Label": UPDATER_SERVICE_LABEL, "ProgramArguments": [str(python), str(launcher), "--root", str(root), "check"], "EnvironmentVariables": {"LITECHECKER_LAUNCH_AGENTS_DIR": str(launch_agents)}, "StartInterval": 3600, "RunAtLoad": True, "Umask": 0o077, "ProcessType": "Background"}
    atomic_write(destination, plistlib.dumps(payload), 0o600, private_parent=False)
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/com.litechecker.updater"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    result = subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(destination)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode:
        raise UpdatePlatformError("update-schedule-unavailable")

"""Host-only update adapters. Preparation never invokes a checker measurement."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import signal
import subprocess

from filelock import AsyncFileLock

from litechecker.state import _atomic_write_json
from litechecker.update_launcher import VERSION, checked_path, read_bytes, read_json, runtime_python, select_release


class UpdatePlatformError(RuntimeError):
    def __init__(self, code="update-platform-unavailable"):
        super().__init__(code)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""


async def run_command(args, *, cwd=None, env=None, timeout=30) -> CommandResult:
    """Run an owned subprocess with bounded output/deadline and child cleanup."""
    process = None
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
                    raise UpdatePlatformError("update-command-output-limit")
            await process.wait()
            return CommandResult(process.returncode, output.decode("utf-8", errors="replace"))
    except asyncio.CancelledError:
        raise
    except Exception:
        raise UpdatePlatformError("update-command-failed") from None
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
            raise UpdatePlatformError("update-command-failed")
        return result


class NativeUpdateAdapter(_Adapter):
    def __init__(self, root, *, runner=None, launch_agents=None):
        super().__init__(root, runner=runner, system="Darwin")
        self.launch_agents = Path(launch_agents) if launch_agents is not None else Path.home() / "Library/LaunchAgents"
        self.plist = self.launch_agents / "com.litechecker.direct.plist"
        self.target = f"gui/{os.getuid()}/com.litechecker.direct"

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
            code = "import sys, litechecker.updater, litechecker.update_service, litechecker.update_platform; from pathlib import Path; from litechecker.direct_service import service_settings; service_settings(Path(sys.argv[1]), Path(sys.argv[2]))"
            env = {**os.environ, "PYTHONPATH": str(release / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
            env.pop("PYTHONHOME", None)
            await self._run([str(python), "-c", code, str(self.baseline), str(release / ".native-direct/xray")], cwd=release, env=env)
        except Exception:
            raise UpdatePlatformError("native-prepare-failed") from None

    def _write_plist(self, release, python):
        if self.launch_agents.is_symlink() or self.plist.is_symlink():
            raise UpdatePlatformError("native-plist-unsafe")
        self.launch_agents.mkdir(parents=True, exist_ok=True)
        payload = {
            "Label": "com.litechecker.direct",
            "ProgramArguments": [str(python), "-m", "litechecker.direct_service", "--root", str(self.baseline), "--xray", str(release / ".native-direct/xray")],
            "WorkingDirectory": str(release), "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 30, "Umask": 0o077, "ProcessType": "Background",
            "EnvironmentVariables": {"PYTHONPATH": str(release / "src"), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
            "StandardOutPath": str(self.state_dir / "service.log"),
            "StandardErrorPath": str(self.state_dir / "service.log"),
        }
        # Existing helper gives an atomic fsync/replace without chmodding LaunchAgents.
        from litechecker.native_install import _atomic_write
        _atomic_write(self.plist, plistlib.dumps(payload), 0o600, private_parent=False)

    async def activate(self, release, running):
        try:
            release = self._release(release)
            python = runtime_python(release, system="Darwin")
            checked_path(release, release / ".native-direct/xray", regular=True)
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


class DockerUpdateAdapter(_Adapter):
    def __init__(self, root, *, runner=None):
        super().__init__(root, runner=runner, system="Linux")
        self.owner = hashlib.sha256(str(self.baseline).encode()).hexdigest()[:16]
        self.image_state = self.baseline / ".updates/docker-images.json"
        self.override = self.baseline / ".updates/compose-image.json"

    def _images(self):
        checked_path(self.baseline, self.image_state)
        state = read_json(self.baseline, self.image_state) if self.image_state.exists() else {"images": {}}
        images = state.get("images")
        baseline = state.get("baseline_image")
        if set(state) - {"images", "baseline_image"} or not isinstance(images, dict) or len(images) > 128:
            raise UpdatePlatformError("docker-image-record-invalid")
        if baseline is not None and (not isinstance(baseline, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", baseline)):
            raise UpdatePlatformError("docker-image-record-invalid")
        for version, image in images.items():
            if not isinstance(version, str) or not VERSION.fullmatch(version) or image != f"litechecker-update-{self.owner}:{version}":
                raise UpdatePlatformError("docker-image-record-invalid")
        return state

    def _compose(self, *, override=True):
        root = self.baseline
        for name in (".env.standalone", "compose.standalone.yml"):
            checked_path(root, root / name, regular=True)
        args = ["docker", "compose", "--project-directory", str(root), "--project-name", "litechecker-standalone", "--env-file", str(root / ".env.standalone"), "-f", str(root / "compose.standalone.yml")]
        proxy = checked_path(root, root / "secrets/telegram_proxy_url")
        if proxy.exists():
            checked_path(root, proxy, regular=True)
            checked_path(root, root / "compose.telegram-proxy.yml", regular=True)
            args.extend(["-f", str(root / "compose.telegram-proxy.yml")])
        if override and self.override.exists():
            checked_path(root, self.override, regular=True)
            args.extend(["-f", str(self.override)])
        return args

    def _env(self):
        return {**os.environ, "LITECHECKER_UID": str(os.getuid()), "LITECHECKER_GID": str(os.getgid())}

    async def _container(self):
        # Query labels directly: stop/status must work even when optional proxy
        # settings or a compose input are broken.
        found = await self._run(["docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=litechecker-standalone", "--filter", "label=com.docker.compose.service=checker"])
        identifiers = found.stdout.split()
        if not identifiers:
            return None
        if len(identifiers) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", identifiers[0]):
            raise UpdatePlatformError("docker-checker-scope-invalid")
        result = await self._run(["docker", "inspect", identifiers[0]])
        try:
            data = json.loads(result.stdout)
            container = data[0]
            labels = container["Config"]["Labels"]
            if len(data) != 1 or labels.get("com.docker.compose.project") != "litechecker-standalone" or labels.get("com.docker.compose.service") != "checker" or labels.get("com.docker.compose.project.working_dir") != str(self.baseline):
                raise ValueError
            return container
        except Exception:
            raise UpdatePlatformError("docker-checker-scope-invalid") from None

    async def _actual_running(self):
        container = await self._container()
        return bool(container and container["State"]["Running"])

    async def prepare(self, release):
        release = self._release(release)
        checked_path(release, release / "Dockerfile", regular=True)
        script = checked_path(release, release / "scripts/prepare-updater.sh", regular=True)
        await self._run(["/bin/bash", str(script), "--root", str(release)], cwd=release, timeout=600)
        runtime_python(release, system="Linux")
        image = f"litechecker-update-{self.owner}:{release.name}"
        state = self._images()
        if "baseline_image" not in state:
            old = await self._container()
            if old:
                baseline_image = old.get("Image")
            else:
                result = await self._run(["docker", "image", "inspect", "litechecker:local"])
                baseline_image = json.loads(result.stdout)[0]["Id"]
            if not isinstance(baseline_image, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", baseline_image):
                raise UpdatePlatformError("docker-baseline-image-invalid")
            state["baseline_image"] = baseline_image
        state["images"][release.name] = image
        _atomic_write_json(self.image_state, state)
        try:
            await self._run(["docker", "build", "--quiet", "--label", f"io.litechecker.update-owner={self.owner}", "--label", f"io.litechecker.update-version={release.name}", "--tag", image, str(release)], timeout=600)
            await self._run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", "import litechecker.cli, litechecker.update_service"], timeout=60)
            checked_path(self.baseline, self.state_dir / "device.json", regular=True)
            preflight = checked_path(release, release / ".update-preflight.json")
            _atomic_write_json(preflight, {"services": {"checker": {"image": image, "network_mode": "none", "healthcheck": {"disable": True}}}})
            compose = self._compose(override=False)
            compose[compose.index("--project-name") + 1] = f"litechecker-update-{self.owner}-preflight"
            await self._run([
                *compose, "-f", str(preflight), "run", "--rm", "--no-deps", "--pull", "never", "--entrypoint", "python", "checker", "-c",
                "from litechecker.config import StandaloneSettings; StandaloneSettings.from_env()",
            ], cwd=self.baseline, env=self._env(), timeout=60)
        except BaseException:
            await self._remove_image(release.name, image)
            raise

    async def _remove_image(self, version, image):
        if not VERSION.fullmatch(version) or image != f"litechecker-update-{self.owner}:{version}":
            raise UpdatePlatformError("docker-image-record-invalid")
        result = await self._run(["docker", "image", "inspect", image], allow_failure=True)
        if result.returncode:
            return
        try:
            metadata = json.loads(result.stdout)
            labels = metadata[0]["Config"]["Labels"]
            if len(metadata) != 1 or labels.get("io.litechecker.update-owner") != self.owner or labels.get("io.litechecker.update-version") != version:
                raise ValueError
        except Exception:
            raise UpdatePlatformError("docker-image-ownership-invalid") from None
        await self._run(["docker", "image", "rm", image])
        state = self._images()
        state["images"].pop(version, None)
        _atomic_write_json(self.image_state, state)

    async def activate(self, release, running):
        release = self._release(release)
        state = self._images()
        image = state.get("baseline_image", "litechecker:local") if release == self.baseline else state.get("images", {}).get(release.name)
        expected = f"litechecker-update-{self.owner}:{release.name}"
        if not isinstance(image, str) or (release != self.baseline and image != expected):
            raise UpdatePlatformError("docker-release-not-prepared")
        async with self._control_lock():
            await self._container()  # Reject same-name deployments belonging to other roots.
            _atomic_write_json(self.override, {"services": {"checker": {"image": image}}})
            if self._desired(running):
                await self._run([*self._compose(), "up", "--detach", "--force-recreate", "--no-build", "--pull", "never", "checker"], cwd=self.baseline, env=self._env(), timeout=120)
            if not self._desired(running):
                await self._stop_container()

    async def _stop_container(self):
        container = await self._container()
        if container and container["State"]["Running"]:
            identifier = container.get("Id")
            if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{12,64}", identifier):
                raise UpdatePlatformError("docker-checker-scope-invalid")
            await self._run(["docker", "stop", identifier], timeout=60)

    async def stop_live(self):
        async with self._control_lock():
            await self._stop_container()

    async def healthy(self, release, running):
        try:
            self._release(release)
            image = json.loads(self.override.read_text())["services"]["checker"]["image"]
            previous = None
            stable = 0
            for attempt in range(12):
                container = await self._container()
                state = container.get("State", {}) if container else {}
                if not self._desired(running):
                    return not state.get("Running") and not state.get("Restarting")
                pid = state.get("Pid")
                restarts = container.get("RestartCount") if container else None
                valid = (
                    container is not None and container["Config"]["Image"] == image
                    and state.get("Running") is True and state.get("Status") == "running"
                    and state.get("Restarting") is False and type(pid) is int and pid > 0
                    and type(restarts) is int and restarts >= 0
                )
                observation = (pid, restarts) if valid else None
                stable = stable + 1 if observation is not None and observation == previous else (1 if valid else 0)
                if stable >= 3:
                    return True
                previous = observation
                if attempt < 11:
                    await asyncio.sleep(0.5)
            return False
        except Exception:
            return False


def platform_adapter(root: Path):
    return NativeUpdateAdapter(root) if _system() == "Darwin" else DockerUpdateAdapter(root)


async def set_checker_running(root: Path, running: bool):
    record_desired_running(root, running)
    adapter = platform_adapter(root)
    if running:
        root = Path(root).absolute()
        update_lock = checked_path(root, root / ".updates/update.lock")
        update_lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Selection happens after a concurrent transaction commits. The same
        # lock order as core avoids starting an old version after publication.
        async with AsyncFileLock(update_lock, timeout=30, mode=0o600, preserve_lock_file=True):
            checked_path(root, adapter.maintenance_lock)
            async with AsyncFileLock(adapter.maintenance_lock, timeout=30, mode=0o600, preserve_lock_file=True):
                await adapter.activate(select_release(root), True)
    else:
        await adapter.stop_live()


async def run_probe(root: Path):
    """Manual user check, invoked only by the explicit probe CLI action."""
    adapter = platform_adapter(root)
    release = select_release(Path(root).absolute())
    if isinstance(adapter, NativeUpdateAdapter):
        python = runtime_python(release, system="Darwin")
        env = {**os.environ, "PYTHONPATH": str(release / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("PYTHONHOME", None)
        await adapter._run([str(python), "-m", "litechecker.direct_service", "--root", str(adapter.baseline), "--xray", str(release / ".native-direct/xray"), "--once"], cwd=release, env=env, timeout=600)
    else:
        await adapter._run([*adapter._compose(), "run", "--rm", "--no-deps", "--pull", "never", "checker", "standalone", "--once"], cwd=adapter.baseline, env=adapter._env(), timeout=600)


async def cleanup_platform_images(root: Path, *, runner=None) -> int:
    """After core cleanup only: remove recorded tags whose managed source is gone."""
    if _system() != "Linux":
        return 0
    root = Path(root).absolute()
    if not (root / ".updates/docker-images.json").exists():
        return 0
    lock_path = checked_path(root, root / ".updates/update.lock")
    async with AsyncFileLock(lock_path, timeout=0, mode=0o600, preserve_lock_file=True):
        state = read_json(root, root / ".updates/install.json")
        if state.get("pending") is not None:
            return 0
        keep = {state.get("active"), state.get("previous")}
        adapter = DockerUpdateAdapter(root, runner=runner)
        removed = 0
        for version, image in list(adapter._images().get("images", {}).items())[:128]:
            path = checked_path(root, root / ".updates/releases" / version)
            if version in keep or path.exists():
                continue
            await adapter._remove_image(version, image)
            removed += 1
        return removed


def install_update_schedule(root: Path) -> None:
    """Explicit setup only: no channel means no filesystem/service effects."""
    root = Path(root).absolute()
    channel = root / ".updates/channel.json"
    if not channel.exists() and not channel.is_symlink():
        return
    from litechecker.update_manifest import parse_channel_config
    parse_channel_config(read_bytes(root, channel))
    system = _system()
    python = runtime_python(root, system=system)
    launcher = checked_path(root, root / "src/litechecker/update_launcher.py", regular=True)
    if system == "Darwin":
        destination = Path.home() / "Library/LaunchAgents/com.litechecker.updater.plist"
        from litechecker.native_install import _atomic_write
        payload = {"Label": "com.litechecker.updater", "ProgramArguments": [str(python), str(launcher), "--root", str(root), "check"], "StartInterval": 3600, "RunAtLoad": True, "Umask": 0o077, "ProcessType": "Background"}
        _atomic_write(destination, plistlib.dumps(payload), 0o600, private_parent=False)
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/com.litechecker.updater"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        result = subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(destination)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    else:
        directory = Path.home() / ".config/systemd/user"
        if directory.is_symlink():
            raise UpdatePlatformError("update-schedule-path-invalid")
        directory.mkdir(parents=True, exist_ok=True)
        from litechecker.native_install import _atomic_write
        def quoted(value):
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
        command = " ".join(map(quoted, [python, launcher, "--root", root, "check"]))
        service = f"[Unit]\nDescription=LiteChecker signed update check\n[Service]\nType=oneshot\nUMask=0077\nExecStart={command}\nTimeoutStartSec=1800\n"
        timer = "[Unit]\nDescription=Hourly LiteChecker update check\n[Timer]\nOnStartupSec=5m\nOnCalendar=hourly\nPersistent=false\n[Install]\nWantedBy=timers.target\n"
        _atomic_write(directory / "litechecker-updater.service", service.encode(), 0o600, private_parent=False)
        _atomic_write(directory / "litechecker-updater.timer", timer.encode(), 0o600, private_parent=False)
        subprocess.run(["systemctl", "--user", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
        result = subprocess.run(["systemctl", "--user", "enable", "--now", "litechecker-updater.timer"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode:
        raise UpdatePlatformError("update-schedule-unavailable")

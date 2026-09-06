"""Linux Docker update adapter and explicit user-systemd scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from filelock import AsyncFileLock

from litechecker.file_safety import atomic_write
from litechecker.state import _atomic_write_json
from litechecker.update_host import _Adapter, UpdatePlatformError
from litechecker.update_launcher import VERSION, checked_path, read_json, runtime_python


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


async def run_probe(adapter, release):
    await adapter._run([*adapter._compose(), "run", "--rm", "--no-deps", "--pull", "never", "checker", "standalone", "--once"], cwd=adapter.baseline, env=adapter._env(), timeout=600)
async def cleanup_platform_images(root: Path, *, runner=None) -> int:
    """After core cleanup only: remove recorded tags whose managed source is gone."""
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


def install_update_schedule(root, python, launcher):
    directory = Path.home() / ".config/systemd/user"
    if directory.is_symlink():
        raise UpdatePlatformError("update-schedule-path-invalid")
    directory.mkdir(parents=True, exist_ok=True)
    def quoted(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    command = " ".join(map(quoted, [python, launcher, "--root", root, "check"]))
    service = f"[Unit]\nDescription=LiteChecker signed update check\n[Service]\nType=oneshot\nUMask=0077\nExecStart={command}\nTimeoutStartSec=1800\n"
    timer = "[Unit]\nDescription=Hourly LiteChecker update check\n[Timer]\nOnStartupSec=5m\nOnCalendar=hourly\nPersistent=false\n[Install]\nWantedBy=timers.target\n"
    atomic_write(directory / "litechecker-updater.service", service.encode(), 0o600, private_parent=False)
    atomic_write(directory / "litechecker-updater.timer", timer.encode(), 0o600, private_parent=False)
    subprocess.run(["systemctl", "--user", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
    result = subprocess.run(["systemctl", "--user", "enable", "--now", "litechecker-updater.timer"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode:
        raise UpdatePlatformError("update-schedule-unavailable")

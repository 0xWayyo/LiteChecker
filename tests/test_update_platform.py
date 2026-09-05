"""Platform changes use real local state and only synthetic OS command boundaries."""

import json
import os
from pathlib import Path
import plistlib

import pytest


def file(path, text="fixture", mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def installation(tmp_path):
    root = tmp_path / "Data root с пробелами"
    release = root / ".updates/releases/1.2.3"
    for target in (root, release):
        file(target / "scripts/native-direct.sh", "#!/bin/bash\nexit 0\n", 0o700)
        file(target / "src/litechecker/direct_service.py")
        file(target / "src/litechecker/update_service.py")
        file(target / ".native-direct/venv/bin/python", "python", 0o700)
        file(target / ".native-direct/xray", "xray", 0o700)
        file(target / ".updater-runtime/venv/bin/python", "python", 0o700)
        file(target / "scripts/prepare-updater.sh", "#!/bin/bash\nexit 0\n", 0o700)
        file(target / "Dockerfile")
    file(release / ".litechecker-update-owned", "litechecker-updater-v1\n")
    file(release / ".artifact.sha256", "a" * 64 + "\n")
    file(root / ".updater-runtime/uv", "uv", 0o700)
    file(root / "state/native-direct/device.json", '{"agent_id":"same","state_key":"unchanged"}')
    file(root / "state/standalone/device.json", '{"agent_id":"same","state_key":"unchanged"}')
    file(root / "native-settings.json", "{}")
    file(root / "compose.standalone.yml")
    file(root / "compose.telegram-proxy.yml")
    file(root / ".env.standalone", "LC_AGENT_NAME='Same device'\n")
    file(root / "secrets/telegram_proxy_url", "socks5://fixture:password@127.0.0.1:1080")
    return root, release


class Runner:
    def __init__(self):
        self.calls = []
        self.running = False
        self.callback = None
        self.program = "/baseline/python"

    async def __call__(self, args, *, cwd=None, env=None, timeout=30):
        from litechecker.update_platform import CommandResult
        args = list(map(str, args))
        self.calls.append((args, cwd, env, timeout))
        if self.callback:
            self.callback(args)
        if args[:2] == ["launchctl", "print"]:
            return CommandResult(0, f"state = running\npid = 123\nprogram = {self.program}\n") if self.running else CommandResult(113, "")
        if args[:2] == ["launchctl", "bootout"]:
            self.running = False
        if args[:2] == ["launchctl", "bootstrap"]:
            self.running = True
            self.program = plistlib.loads(Path(args[-1]).read_bytes())["ProgramArguments"][0]
        if args[:3] == ["docker", "image", "inspect"]:
            return CommandResult(0, '[{"Id":"sha256:' + 'a' * 64 + '","Config":{"Labels":{}}}]')
        if "ps" in args:
            return CommandResult(0, "")
        return CommandResult(0, "")


@pytest.mark.asyncio
async def test_native_prepare_keeps_canonical_data_and_service_untouched(tmp_path):
    from litechecker.update_platform import NativeUpdateAdapter
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    before = (root / "state/native-direct/device.json").read_bytes()
    await adapter.prepare(release)
    assert not any(args[0] == "launchctl" for args, *_ in runner.calls)
    assert runner.calls[0][0] == ["/bin/bash", str(release / "scripts/native-direct.sh"), "prepare", "--root", str(release)]
    assert (root / "state/native-direct/device.json").read_bytes() == before
    assert not (release / "state").exists()
    assert adapter.maintenance_lock == root / "state/native-direct/maintenance.lock"


@pytest.mark.asyncio
async def test_native_activation_selects_release_code_but_original_data(tmp_path):
    from litechecker.update_platform import NativeUpdateAdapter, record_desired_running
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    record_desired_running(root, True, system="Darwin")
    await adapter.activate(release, True)
    plist = plistlib.loads((tmp_path / "LaunchAgents/com.litechecker.direct.plist").read_bytes())
    assert plist["ProgramArguments"] == [str(release / ".native-direct/venv/bin/python"), "-m", "litechecker.direct_service", "--root", str(root), "--xray", str(release / ".native-direct/xray")]
    assert plist["WorkingDirectory"] == str(release)
    assert plist["EnvironmentVariables"]["PYTHONPATH"] == str(release / "src")
    assert plist["Umask"] == 0o077
    assert ["launchctl", "enable", f"gui/{os.getuid()}/com.litechecker.direct"] in [args for args, *_ in runner.calls]
    assert await adapter.healthy(release, True)


@pytest.mark.asyncio
async def test_native_install_and_update_activation_share_direct_plist_schema(tmp_path):
    from litechecker.native_install import install_configuration
    from litechecker.update_platform import NativeUpdateAdapter, record_desired_running

    root, _ = installation(tmp_path)
    file(
        root / "state/native-direct/device.json",
        json.dumps({"agent_id": "device-" + "a" * 32, "state_key": "k" * 32}),
    )
    source = tmp_path / "source"
    source.mkdir()
    installed_plist = tmp_path / "InstalledAgents/com.litechecker.direct.plist"
    install_configuration(source, root, installed_plist)
    installed = plistlib.loads(installed_plist.read_bytes())

    runner = Runner()
    updated_agents = tmp_path / "UpdatedAgents"
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=updated_agents)
    record_desired_running(root, False, system="Darwin")
    await adapter.activate(root, False)
    updated = plistlib.loads((updated_agents / "com.litechecker.direct.plist").read_bytes())

    assert updated == installed
    assert updated["ProgramArguments"] == [
        str(root / ".native-direct/venv/bin/python"),
        "-m",
        "litechecker.direct_service",
        "--root",
        str(root),
        "--xray",
        str(root / ".native-direct/xray"),
    ]
    assert updated["EnvironmentVariables"] == {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(root / "src"),
        "PYTHONUNBUFFERED": "1",
    }


def test_native_paths_honor_launch_agents_override_for_service_and_schedule(
    tmp_path, monkeypatch
):
    import base64
    from litechecker import update_platform
    from litechecker.native_runtime import (
        direct_service_plist_path,
        launch_agents_directory,
        updater_plist_path,
    )

    root, _ = installation(tmp_path)
    file(root / "src/litechecker/update_launcher.py")
    file(
        root / ".updates/channel.json",
        json.dumps({
            "schema": 1,
            "enabled": True,
            "public_key": base64.b64encode(b"k" * 32).decode(),
            "manifest_urls": ["https://updates.example/manifest.json"],
        }),
    )
    launch_agents = tmp_path / "Custom LaunchAgents"
    monkeypatch.setenv("LITECHECKER_LAUNCH_AGENTS_DIR", str(launch_agents))
    monkeypatch.setattr(update_platform.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        update_platform.subprocess,
        "run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )

    adapter = update_platform.NativeUpdateAdapter(root)
    update_platform.install_update_schedule(root)

    assert launch_agents_directory() == launch_agents
    assert adapter.plist == direct_service_plist_path()
    assert updater_plist_path().is_file()
    assert updater_plist_path().parent == launch_agents


def test_native_schedule_persists_absolute_launch_agents_for_later_adapter(
    tmp_path, monkeypatch
):
    import base64
    from litechecker import update_platform

    root, _ = installation(tmp_path)
    file(root / "src/litechecker/update_launcher.py")
    file(
        root / ".updates/channel.json",
        json.dumps({
            "schema": 1,
            "enabled": True,
            "public_key": base64.b64encode(b"k" * 32).decode(),
            "manifest_urls": ["https://updates.example/manifest.json"],
        }),
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LITECHECKER_LAUNCH_AGENTS_DIR", "Custom LaunchAgents")
    monkeypatch.setattr(update_platform.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        update_platform.subprocess,
        "run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )

    update_platform.install_update_schedule(root)

    launch_agents = tmp_path / "Custom LaunchAgents"
    scheduled = plistlib.loads(
        (launch_agents / "com.litechecker.updater.plist").read_bytes()
    )
    scheduled_environment = scheduled["EnvironmentVariables"]
    persisted = scheduled_environment["LITECHECKER_LAUNCH_AGENTS_DIR"]
    assert Path(persisted).is_absolute()
    assert Path(persisted) == launch_agents

    monkeypatch.delenv("LITECHECKER_LAUNCH_AGENTS_DIR")
    for key, value in scheduled_environment.items():
        monkeypatch.setenv(key, value)
    restarted = update_platform.NativeUpdateAdapter(root)
    assert restarted.plist == launch_agents / "com.litechecker.direct.plist"


@pytest.mark.asyncio
async def test_native_activation_rejects_symlinked_launch_agents_ancestor_before_commands(
    tmp_path,
):
    from litechecker.update_platform import NativeUpdateAdapter, UpdatePlatformError

    root, _ = installation(tmp_path)
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)
    runner = Runner()
    adapter = NativeUpdateAdapter(
        root,
        runner=runner,
        launch_agents=linked_parent / "LaunchAgents",
    )

    with pytest.raises(UpdatePlatformError, match="native-activation-failed"):
        await adapter.activate(root, False)

    assert runner.calls == []
    assert not (actual_parent / "LaunchAgents/com.litechecker.direct.plist").exists()


@pytest.mark.asyncio
async def test_user_stop_during_activation_is_not_overridden(tmp_path):
    from litechecker.update_platform import NativeUpdateAdapter, record_desired_running
    root, release = installation(tmp_path)
    runner = Runner()
    runner.running = True
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    record_desired_running(root, True, system="Darwin")
    def stop_when_unloaded(args):
        if args[:2] == ["launchctl", "bootout"]:
            record_desired_running(root, False, system="Darwin")
    runner.callback = stop_when_unloaded
    await adapter.activate(release, True)
    assert not any(args[:2] == ["launchctl", "bootstrap"] for args, *_ in runner.calls)
    assert await adapter.healthy(release, True)


@pytest.mark.asyncio
async def test_explicit_pause_wins_over_running_argument_and_actual_service(tmp_path):
    from litechecker.update_platform import NativeUpdateAdapter, record_desired_running
    root, release = installation(tmp_path)
    runner = Runner()
    runner.running = True
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    record_desired_running(root, False, system="Darwin")
    assert await adapter.is_running() is False
    await adapter.activate(release, True)
    assert not runner.running
    assert not any(args[:2] == ["launchctl", "bootstrap"] for args, *_ in runner.calls)
    assert ["launchctl", "disable", f"gui/{os.getuid()}/com.litechecker.direct"] in [args for args, *_ in runner.calls]


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", ["outside", "symlink", "runtime"])
async def test_unsafe_release_is_rejected_before_commands(tmp_path, unsafe):
    from litechecker.update_platform import NativeUpdateAdapter, UpdatePlatformError
    root, release = installation(tmp_path)
    runner = Runner()
    if unsafe == "outside":
        release = tmp_path / "outside"
        release.mkdir()
    elif unsafe == "symlink":
        link = root / ".updates/releases/2.0.0"
        link.symlink_to(release, target_is_directory=True)
        release = link
    else:
        python = release / ".native-direct/venv/bin/python"
        python.unlink()
        python.symlink_to(file(tmp_path / "outside-python", "python", 0o700))
    adapter = NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    with pytest.raises(UpdatePlatformError):
        await adapter.activate(release, True)
    assert not runner.calls


@pytest.mark.asyncio
async def test_docker_build_and_switch_use_stable_compose_data_and_owned_image(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, record_desired_running
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = DockerUpdateAdapter(root, runner=runner)
    await adapter.prepare(release)
    assert not any("up" in args or "stop" in args for args, *_ in runner.calls)
    record_desired_running(root, True, system="Linux")
    await adapter.activate(release, True)
    calls = [args for args, *_ in runner.calls]
    build = next(args for args in calls if args[:2] == ["docker", "build"])
    assert str(release) == build[-1]
    assert "--label" in build
    up = next(args for args in calls if "up" in args)
    assert str(root / "compose.standalone.yml") in up
    assert str(root / "compose.telegram-proxy.yml") in up
    assert "--no-build" in up and "--pull" in up and "never" in up
    override = json.loads((root / ".updates/compose-image.json").read_text())
    assert override["services"]["checker"]["image"].startswith("litechecker-update-")
    assert adapter.maintenance_lock == root / "state/standalone/maintenance.lock"


@pytest.mark.asyncio
async def test_docker_paused_update_never_starts_checker(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, record_desired_running
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = DockerUpdateAdapter(root, runner=runner)
    await adapter.prepare(release)
    record_desired_running(root, False, system="Linux")
    await adapter.activate(release, False)
    assert not any("up" in args for args, *_ in runner.calls)


def test_missing_channel_schedule_has_no_filesystem_or_command_side_effects(tmp_path):
    from litechecker.update_platform import install_update_schedule
    root = tmp_path / "unconfigured"
    install_update_schedule(root)
    assert not root.exists()


@pytest.mark.asyncio
async def test_command_timeout_reaps_owned_process_and_returns_closed_failure(tmp_path):
    import sys
    from litechecker.update_platform import run_command, UpdatePlatformError
    with pytest.raises(UpdatePlatformError, match="update-command-failed") as raised:
        await run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
    assert raised.value.operation == "python"
    assert raised.value.reason == "timeout"
    assert raised.value.exit_code is None


@pytest.mark.asyncio
async def test_nonzero_command_error_has_only_closed_diagnostics(tmp_path):
    from litechecker.update_platform import CommandResult, NativeUpdateAdapter, UpdatePlatformError

    root, _ = installation(tmp_path)

    async def fail(args, **kwargs):
        return CommandResult(7, "https://secret.invalid/token")

    adapter = NativeUpdateAdapter(root, runner=fail, launch_agents=tmp_path / "LaunchAgents")
    with pytest.raises(UpdatePlatformError, match="update-command-failed") as raised:
        await adapter._run(["/private/secret-tool", "--token=secret"])

    assert str(raised.value) == "update-command-failed"
    assert raised.value.operation == "owned-command"
    assert raised.value.reason == "nonzero-exit"
    assert raised.value.exit_code == 7
    assert "secret" not in repr(raised.value.__dict__)


@pytest.mark.asyncio
async def test_docker_scope_mismatch_cannot_stop_other_installation(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, CommandResult, UpdatePlatformError
    root, release = installation(tmp_path)
    calls = []
    async def runner(args, **kwargs):
        calls.append(list(args))
        if "ps" in args:
            return CommandResult(0, "a" * 64)
        if list(args[:2]) == ["docker", "inspect"]:
            return CommandResult(0, json.dumps([{"Config": {"Labels": {"com.docker.compose.project": "litechecker-standalone", "com.docker.compose.service": "checker", "com.docker.compose.project.working_dir": "/unrelated"}}}]))
        return CommandResult(0)
    adapter = DockerUpdateAdapter(root, runner=runner)
    with pytest.raises(UpdatePlatformError):
        await adapter.activate(root, False)
    assert not any("stop" in args or "up" in args for args in calls)


def test_native_hourly_schedule_executes_stable_updater_only(tmp_path, monkeypatch):
    import base64
    from litechecker import update_platform
    root, _ = installation(tmp_path)
    file(root / "src/litechecker/update_launcher.py")
    file(root / ".updates/channel.json", json.dumps({"schema": 1, "enabled": True, "public_key": base64.b64encode(b"k" * 32).decode(), "manifest_urls": ["https://updates.example/manifest.json"]}))
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return type("Result", (), {"returncode": 0})()
    monkeypatch.setattr(update_platform.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(update_platform.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(update_platform.subprocess, "run", run)
    update_platform.install_update_schedule(root)
    plist = plistlib.loads((tmp_path / "Library/LaunchAgents/com.litechecker.updater.plist").read_bytes())
    assert plist["StartInterval"] == 3600 and plist["RunAtLoad"]
    assert plist["ProgramArguments"][-1] == "check"
    assert str(root / "src/litechecker/update_launcher.py") in plist["ProgramArguments"]
    assert all("com.litechecker.direct" not in " ".join(args) for args in calls)


@pytest.mark.asyncio
async def test_failed_docker_local_import_drops_only_owned_built_image(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, CommandResult, UpdatePlatformError
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = DockerUpdateAdapter(root, runner=runner)
    original = runner.__call__
    async def fail_import(args, **kwargs):
        if list(args[:2]) == ["docker", "run"]:
            runner.calls.append((list(args), None, None, 30))
            return CommandResult(1)
        if list(args[:3]) == ["docker", "image", "inspect"] and str(args[-1]).startswith("litechecker-update-"):
            return CommandResult(0, json.dumps([{"Config": {"Labels": {"io.litechecker.update-owner": adapter.owner, "io.litechecker.update-version": "1.2.3"}}}]))
        return await original(args, **kwargs)
    adapter._runner = fail_import
    with pytest.raises(UpdatePlatformError):
        await adapter.prepare(release)
    removed = [args for args, *_ in runner.calls if args[:3] == ["docker", "image", "rm"]]
    assert removed == [["docker", "image", "rm", f"litechecker-update-{adapter.owner}:1.2.3"]]


def test_linux_bootstrap_rejects_external_python_before_any_uv_execution(tmp_path):
    import subprocess
    root = tmp_path / "root"
    runtime = root / ".updater-runtime"
    marker = tmp_path / "executed"
    file(runtime / "uv", f"#!/bin/bash\ntouch '{marker}'\n", 0o700)
    outside = file(tmp_path / "outside", f"#!/bin/bash\ntouch '{marker}'\n", 0o700)
    python = runtime / "venv/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(outside)
    binary = tmp_path / "bin"
    file(binary / "uname", "#!/bin/bash\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\n", 0o700)
    script = Path(__file__).resolve().parents[1] / "scripts/prepare-updater.sh"
    result = subprocess.run(["/bin/bash", str(script), "--root", str(root)], env={**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"]}, capture_output=True, timeout=5)
    assert result.returncode != 0
    assert not marker.exists()
    assert b"unsafe" in result.stderr


@pytest.mark.asyncio
async def test_docker_image_state_cannot_select_unrecorded_arbitrary_baseline_image(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, UpdatePlatformError
    root, _ = installation(tmp_path)
    file(root / ".updates/docker-images.json", json.dumps({"images": {}, "baseline_image": "unrelated:latest"}))
    runner = Runner()
    with pytest.raises(UpdatePlatformError):
        await DockerUpdateAdapter(root, runner=runner).activate(root, True)
    assert not runner.calls


@pytest.mark.asyncio
async def test_native_health_waits_for_selected_process_and_never_uses_endpoint_status(tmp_path, monkeypatch):
    from litechecker import update_platform
    root, release = installation(tmp_path)
    runner = Runner()
    adapter = update_platform.NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    await adapter.activate(release, True)
    original = runner.__call__
    attempts = 0
    async def delayed(args, **kwargs):
        nonlocal attempts
        if list(args[:2]) == ["launchctl", "print"]:
            attempts += 1
            if attempts == 1:
                return update_platform.CommandResult(0, "state = waiting\n")
        return await original(args, **kwargs)
    async def no_wait(seconds):
        return None
    adapter._runner = delayed
    monkeypatch.setattr(update_platform.asyncio, "sleep", no_wait)
    assert await adapter.healthy(release, True)
    assert attempts >= 2


@pytest.mark.asyncio
async def test_docker_stop_is_possible_with_broken_optional_proxy(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter, CommandResult
    root, _ = installation(tmp_path)
    proxy = root / "secrets/telegram_proxy_url"
    proxy.unlink()
    proxy.symlink_to(tmp_path / "missing-proxy")
    identifier = "b" * 64
    calls = []
    async def runner(args, **kwargs):
        calls.append(list(args))
        if "ps" in args:
            return CommandResult(0, identifier)
        if list(args[:2]) == ["docker", "inspect"]:
            return CommandResult(0, json.dumps([{"Id": identifier, "Config": {"Labels": {"com.docker.compose.project": "litechecker-standalone", "com.docker.compose.service": "checker", "com.docker.compose.project.working_dir": str(root)}}, "State": {"Running": True}}]))
        return CommandResult(0)
    await DockerUpdateAdapter(root, runner=runner).activate(root, False)
    assert ["docker", "stop", identifier] in calls
    assert not any("compose" in args for args in calls)


def test_linux_schedule_uses_user_timer_and_quotes_space_unicode_paths(tmp_path, monkeypatch):
    import base64
    from litechecker import update_platform
    root, _ = installation(tmp_path)
    file(root / "src/litechecker/update_launcher.py")
    file(root / ".updates/channel.json", json.dumps({"schema": 1, "enabled": True, "public_key": base64.b64encode(b"k" * 32).decode(), "manifest_urls": ["https://updates.example/manifest.json"]}))
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return type("Result", (), {"returncode": 0})()
    monkeypatch.setattr(update_platform.platform, "system", lambda: "Linux")
    monkeypatch.setattr(update_platform.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(update_platform.subprocess, "run", run)
    update_platform.install_update_schedule(root)
    service = (tmp_path / ".config/systemd/user/litechecker-updater.service").read_text()
    timer = (tmp_path / ".config/systemd/user/litechecker-updater.timer").read_text()
    assert '"' + str(root / ".updater-runtime/venv/bin/python") + '"' in service
    assert "OnStartupSec=5m" in timer and "OnCalendar=hourly" in timer
    assert calls == [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "litechecker-updater.timer"]]


@pytest.mark.asyncio
async def test_manual_start_selects_release_only_after_pending_update_commits(tmp_path, monkeypatch):
    import asyncio
    from filelock import AsyncFileLock
    from litechecker import update_platform
    root, release = installation(tmp_path)
    file(root / ".updates/install.json", json.dumps({"active": None}))
    runner = Runner()
    adapter = update_platform.NativeUpdateAdapter(root, runner=runner, launch_agents=tmp_path / "LaunchAgents")
    monkeypatch.setattr(update_platform.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(update_platform, "platform_adapter", lambda _: adapter)
    async with AsyncFileLock(root / ".updates/update.lock", mode=0o600, preserve_lock_file=True):
        task = asyncio.create_task(update_platform.set_checker_running(root, True))
        await asyncio.sleep(0.05)
        file(root / ".updates/install.json", json.dumps({"active": "1.2.3"}))
    await task
    plist = plistlib.loads((tmp_path / "LaunchAgents/com.litechecker.direct.plist").read_bytes())
    assert plist["WorkingDirectory"] == str(release)


@pytest.mark.asyncio
async def test_docker_prepare_validates_real_configuration_in_isolated_candidate(tmp_path):
    from litechecker.update_platform import DockerUpdateAdapter
    root, release = installation(tmp_path)
    runner = Runner()
    await DockerUpdateAdapter(root, runner=runner).prepare(release)
    calls = [args for args, *_ in runner.calls]
    validation = next(args for args in calls if "compose" in args and "run" in args)
    assert "StandaloneSettings.from_env()" in validation[-1]
    assert str(root / "compose.standalone.yml") in validation
    assert str(root / ".env.standalone") in validation
    candidate = json.loads((release / ".update-preflight.json").read_text())
    assert candidate["services"]["checker"]["network_mode"] == "none"
    assert candidate["services"]["checker"]["image"].startswith("litechecker-update-")
    assert not (root / ".updates/compose-image.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("crash", [False, True])
async def test_docker_health_requires_stable_selected_startup_process(tmp_path, monkeypatch, crash):
    from litechecker import update_platform
    root, release = installation(tmp_path)
    adapter = update_platform.DockerUpdateAdapter(root, runner=Runner())
    image = f"litechecker-update-{adapter.owner}:1.2.3"
    file(root / ".updates/compose-image.json", json.dumps({"services": {"checker": {"image": image}}}))
    calls = 0
    async def observe():
        nonlocal calls
        calls += 1
        state = {"Running": True, "Status": "running", "Restarting": False, "Pid": 101}
        if crash and calls > 1:
            state.update(Running=False, Status="restarting", Restarting=True, Pid=0)
        return {"Config": {"Image": image}, "State": state, "RestartCount": 1 if crash and calls > 1 else 0}
    async def no_wait(_):
        return None
    adapter._container = observe
    monkeypatch.setattr(update_platform.asyncio, "sleep", no_wait)
    assert await adapter.healthy(release, True) is (not crash)
    assert calls >= 3

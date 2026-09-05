"""Exercise the actual shell setup with piped operator input, never real secrets."""

from pathlib import Path
import shutil
import subprocess
import os

import pytest


ROOT = Path(__file__).resolve().parents[1]


def run_setup(tmp_path, text, *, env=None):
    script = ROOT / "run.sh"
    assert script.exists(), "portable launcher is missing"
    shutil.copy2(script, tmp_path / "run.sh")
    return subprocess.run(
        ["bash", "run.sh", "setup"], cwd=tmp_path, input=text,
        text=True, capture_output=True, timeout=5, env=env,
    )


def test_setup_writes_private_secrets_and_does_not_print_them(tmp_path):
    result = run_setup(tmp_path, "Москва\nИван / ПК\n\n123456:abcdefghijklmnopqrstuvwxyz\nhttps://subscription.example/private\n")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "secrets/telegram_bot_token").read_text().strip() == "123456:abcdefghijklmnopqrstuvwxyz"
    assert (tmp_path / "secrets/subscription_url").read_text().strip() == "https://subscription.example/private"
    env = (tmp_path / ".env.standalone").read_text()
    assert "-5361201677" in env
    assert "Москва" in env and "Иван / ПК" in env
    assert "abcdefghijklmnopqrstuvwxyz" not in env + result.stdout + result.stderr
    assert "https://subscription.example/private" not in env + result.stdout + result.stderr
    assert (tmp_path / "secrets/telegram_bot_token").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "state/standalone").stat().st_mode & 0o777 == 0o700
    assert not (tmp_path / "state/standalone/device.json").exists()


def test_setup_does_not_overwrite_existing_device_settings(tmp_path):
    saved = tmp_path / ".env.standalone"
    saved.write_text("existing configuration")
    result = run_setup(tmp_path, "")
    assert result.returncode != 0
    assert saved.read_text() == "existing configuration"


def test_setup_can_reuse_shared_bot_and_subscription_files(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    for name in ("telegram_bot_token", "subscription_url"):
        (secrets / name).write_text("keep-this-existing-value")
        (secrets / name).chmod(0o600)
    result = run_setup(tmp_path, "Москва\nАлексей / VPS\n-12345\n")
    assert result.returncode == 0, result.stderr
    assert (secrets / "telegram_bot_token").read_text() == "keep-this-existing-value"
    assert (secrets / "subscription_url").read_text() == "keep-this-existing-value"


def test_setup_interrupted_input_does_not_leave_finished_configuration(tmp_path):
    result = run_setup(tmp_path, "Москва\n")
    assert result.returncode != 0
    assert not (tmp_path / ".env.standalone").exists()


def test_start_recreates_container_so_replaced_secret_files_take_effect(tmp_path):
    shutil.copy2(ROOT / "run.sh", tmp_path / "run.sh")
    (tmp_path / ".env.standalone").write_text("LC_AGENT_CITY='Москва'\n")
    commands = tmp_path / "commands"
    fake_docker = tmp_path / "docker"
    fake_docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\n')
    fake_docker.chmod(0o700)
    fake_uname = tmp_path / "uname"
    fake_uname.write_text('#!/bin/sh\necho Linux\n')
    fake_uname.chmod(0o700)
    result = subprocess.run(
        ["bash", "run.sh", "start"], cwd=tmp_path, capture_output=True,
        text=True, timeout=5,
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "COMMAND_LOG": str(commands)},
    )
    assert result.returncode == 0, result.stderr
    startup = next(line for line in commands.read_text().splitlines() if " up " in line)
    assert "--force-recreate" in startup


@pytest.mark.parametrize("action,expected", [("start", "start"), ("stop", "stop"), ("check", "probe")])
def test_managed_linux_controls_use_selected_release(tmp_path, action, expected):
    shutil.copy2(ROOT / "run.sh", tmp_path / "run.sh")
    (tmp_path / ".env.standalone").write_text("LC_AGENT_CITY='Москва'\n")
    commands = tmp_path / "commands"
    for name, body in {
        "docker": 'printf "docker:%s\\n" "$*" >> "$COMMAND_LOG"\n',
        "uname": 'echo Linux\n',
        "scripts/update.sh": 'printf "update:%s\\n" "$*" >> "$COMMAND_LOG"\n',
        ".updater-runtime/venv/bin/python": 'exit 0\n',
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o700)
    result = subprocess.run(
        ["bash", "run.sh", action], cwd=tmp_path, capture_output=True,
        text=True, timeout=5,
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "COMMAND_LOG": str(commands)},
    )
    assert result.returncode == 0, result.stderr
    lines = commands.read_text().splitlines()
    assert f"update:{expected}" in lines
    assert not any(" build " in line or " up " in line or " stop " in line for line in lines)


def test_empty_name_enables_auto_naming_with_actual_host_metadata(tmp_path):
    for command, value in (("hostname", "Work-Laptop"), ("uname", "Linux")):
        executable = tmp_path / command
        executable.write_text("#!/bin/sh\nprintf '%s\\n' '" + value + "'\n")
        executable.chmod(0o700)
    result = run_setup(
        tmp_path, "Москва\n\n\n123456:abcdefghijklmnopqrstuvwxyz\nhttps://subscription.example/private\n",
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
    )
    assert result.returncode == 0, result.stderr
    env = (tmp_path / ".env.standalone").read_text()
    assert "LC_AGENT_NAME=''" in env
    assert "LC_HOST_NAME='Work-Laptop'" in env
    assert "LC_HOST_OS='Linux'" in env


def test_quick_setup_with_shared_secrets_needs_no_input(tmp_path):
    shutil.copy2(ROOT / "run.sh", tmp_path / "run.sh")
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    for name in ("telegram_bot_token", "subscription_url"):
        (secrets / name).write_text("existing-shared-secret")
    result = subprocess.run(
        ["bash", "run.sh", "setup", "--quick"], cwd=tmp_path, input="",
        text=True, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    env = (tmp_path / ".env.standalone").read_text()
    assert "LC_AGENT_NAME=''" in env
    assert "LC_AGENT_CITY=''" in env
    assert "LC_TELEGRAM_CHAT_ID='-5361201677'" in env


def launch_with_optional_proxy(tmp_path, action):
    shutil.copy2(ROOT / "run.sh", tmp_path / "run.sh")
    (tmp_path / ".env.standalone").write_text("LC_AGENT_CITY='Москва'\n")
    commands = tmp_path / "commands"
    fake_docker = tmp_path / "docker"
    fake_docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\n')
    fake_docker.chmod(0o700)
    fake_uname = tmp_path / "uname"
    fake_uname.write_text('#!/bin/sh\necho Linux\n')
    fake_uname.chmod(0o700)
    result = subprocess.run(
        ["bash", "run.sh", action], cwd=tmp_path, capture_output=True,
        text=True, timeout=5,
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "COMMAND_LOG": str(commands)},
    )
    calls = commands.read_text().splitlines() if commands.exists() else []
    return result, [call for call in calls if call != "compose version"]


@pytest.mark.parametrize("action", ["start", "check", "build"])
def test_launcher_uses_optional_proxy_overlay_without_changing_env(tmp_path, action):
    (tmp_path / "secrets").mkdir(mode=0o755)
    proxy = tmp_path / "secrets/telegram_proxy_url"
    proxy.write_text("socks5://fixture-user:fixture-password@proxy.invalid:1080\n")
    proxy.chmod(0o644)
    shutil.copy2(ROOT / "compose.telegram-proxy.yml", tmp_path / "compose.telegram-proxy.yml")
    result, calls = launch_with_optional_proxy(tmp_path, action)
    assert result.returncode == 0, result.stderr
    assert calls
    assert all("-f compose.standalone.yml -f compose.telegram-proxy.yml " in call for call in calls)
    assert (tmp_path / ".env.standalone").read_text() == "LC_AGENT_CITY='Москва'\n"
    assert proxy.stat().st_mode & 0o777 == 0o600
    assert proxy.parent.stat().st_mode & 0o777 == 0o700
    assert "fixture-password" not in result.stdout + result.stderr + "\n".join(calls)


@pytest.mark.parametrize("action", ["start", "check", "build", "stop", "logs", "status"])
def test_launcher_keeps_existing_compose_flow_without_optional_proxy(tmp_path, action):
    result, calls = launch_with_optional_proxy(tmp_path, action)
    assert result.returncode == 0, result.stderr
    assert calls
    assert all("compose.telegram-proxy.yml" not in call for call in calls)


@pytest.mark.parametrize("kind", ["empty", "whitespace", "directory", "symlink", "dangling", "fifo", "linked-parent"])
@pytest.mark.parametrize("action", ["start", "check", "build"])
def test_launcher_refuses_unsafe_proxy_before_container_commands(tmp_path, kind, action):
    directory = tmp_path / "secrets"
    if kind == "linked-parent":
        outside = tmp_path / "outside-secrets"
        outside.mkdir(mode=0o755)
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.mkdir()
    proxy = directory / "telegram_proxy_url"
    if kind == "directory":
        proxy.mkdir()
    elif kind == "fifo":
        os.mkfifo(proxy)
    elif kind in ("symlink", "dangling"):
        outside = tmp_path / "outside-secret"
        if kind == "symlink":
            outside.write_text("never-show-this-value")
            outside.chmod(0o644)
        proxy.symlink_to(outside)
    else:
        proxy.write_text("socks5://proxy.invalid:1080" if kind == "linked-parent" else " \n\t" if kind == "whitespace" else "")
    result, calls = launch_with_optional_proxy(tmp_path, action)
    assert result.returncode != 0
    assert calls == []
    assert "never-show-this-value" not in result.stdout + result.stderr
    if kind == "symlink":
        assert outside.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("action", ["stop", "logs", "status"])
def test_launcher_can_manage_container_even_after_proxy_file_becomes_invalid(tmp_path, action):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets/telegram_proxy_url").mkdir()
    result, calls = launch_with_optional_proxy(tmp_path, action)
    assert result.returncode == 0, result.stderr
    assert len(calls) == 1

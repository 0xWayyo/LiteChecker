"""Execute native macOS installer/control scripts using local command fixtures."""

from __future__ import annotations

import os
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


def make_script(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\nset -eu\n" + body)
    path.chmod(0o700)


def write_manifest(tree: Path) -> None:
    payload = {}
    for path in sorted(tree.rglob("*")):
        if path.is_file() and path.name != "CONTENTS.sha256.json" and ".native-direct" not in path.parts:
            payload[path.relative_to(tree).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tree / "CONTENTS.sha256.json").write_text(json.dumps(payload, indent=2) + "\n")


@pytest.fixture
def native_tree(tmp_path):
    tree = tmp_path / "Пакет LiteChecker"
    (tree / "scripts").mkdir(parents=True)
    for name in ("run.sh", "scripts/install.sh", "scripts/install-macos.sh", "scripts/native-direct.sh", "scripts/try-direct.sh"):
        shutil.copy2(SOURCE / name, tree / name)
    return tree


def native_env(tmp_path, root):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    make_script(bin_dir / "uname", 'case "${1:-}" in -s) echo Darwin;; -m) echo arm64;; esac\n')
    log = tmp_path / "commands.log"
    make_script(bin_dir / "launchctl", 'printf "launchctl:%s\\n" "$*" >> "$COMMAND_LOG"\n')
    make_script(bin_dir / "tail", 'printf "tail:%s\\n" "$*" >> "$COMMAND_LOG"\n')
    return {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "HOME": str(tmp_path / "home"),
        "LITECHECKER_NATIVE_ROOT": str(root),
        "LITECHECKER_LAUNCH_AGENTS_DIR": str(tmp_path / "LaunchAgents"),
        "COMMAND_LOG": str(log),
    }, log


def test_shared_installer_routes_darwin_before_docker_checks(native_tree, tmp_path):
    root = tmp_path / "canonical"
    env, log = native_env(tmp_path, root)
    marker = tmp_path / "mac-installer-called"
    make_script(native_tree / "scripts/install-macos.sh", 'printf called > "$MAC_MARKER"\n')
    env["MAC_MARKER"] = str(marker)

    result = subprocess.run([BASH, "scripts/install.sh"], cwd=native_tree, env=env,
                            capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "called"
    assert not log.exists()
    assert "native-settings.json" in result.stdout
    assert ".env.standalone" not in result.stdout


@pytest.mark.parametrize("action", ["start", "stop", "status", "logs", "check"])
def test_run_sh_routes_macos_controls_without_docker(native_tree, tmp_path, action):
    root = tmp_path / "canonical"
    env, log = native_env(tmp_path, root)
    make_script(native_tree / "scripts/native-direct.sh", 'printf "native:%s\\n" "$*" >> "$COMMAND_LOG"\n')

    result = subprocess.run([BASH, "run.sh", action], cwd=native_tree, env=env,
                            capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, result.stderr
    assert log.read_text().splitlines() == [f"native:{action}"]


def prepared_control(tmp_path):
    root = tmp_path / "Library/Application Support/LiteChecker"
    python = root / ".native-direct/venv/bin/python"
    python.parent.mkdir(parents=True)
    xray = root / ".native-direct/xray"
    xray.write_text("xray")
    xray.chmod(0o700)
    calls = tmp_path / "python.log"
    make_script(python, 'printf "%s\\n" "$@" > "$PYTHON_LOG"\n')
    plist_dir = tmp_path / "LaunchAgents"
    plist_dir.mkdir()
    (plist_dir / "com.litechecker.direct.plist").write_text("plist")
    env, command_log = native_env(tmp_path, root)
    env["PYTHON_LOG"] = str(calls)
    script = tmp_path / "native-direct.sh"
    shutil.copy2(SOURCE / "scripts/native-direct.sh", script)
    return script, root, env, command_log, calls


@pytest.mark.parametrize("action", ["start", "stop"])
def test_native_controls_delegate_to_transactional_updater_when_installed(tmp_path, action):
    script, root, env, command_log, python_log = prepared_control(tmp_path)
    (root / "scripts").mkdir()
    make_script(root / "scripts/update.sh", 'printf "update:%s\\n" "$*" >> "$COMMAND_LOG"\n')
    result = subprocess.run([BASH, str(script), action], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert command_log.read_text().splitlines() == [f"update:{action}"]


def test_native_explicit_root_is_forwarded_to_updater(tmp_path):
    script, root, env, command_log, python_log = prepared_control(tmp_path)
    (root / "scripts").mkdir()
    make_script(root / "scripts/update.sh", 'printf "%s\\n" "$LITECHECKER_NATIVE_ROOT" >> "$COMMAND_LOG"\n')
    env["LITECHECKER_NATIVE_ROOT"] = str(tmp_path / "wrong-root")
    result = subprocess.run([BASH, str(script), "stop", "--root", str(root)], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert command_log.read_text().strip() == str(root)


def install_fixture(tmp_path):
    source = tmp_path / "Исходный LiteChecker"
    (source / "scripts").mkdir(parents=True)
    for name in ("run.sh", "pyproject.toml", "uv.lock", "compose.standalone.yml", "compose.telegram-proxy.yml",
                 "scripts/install-macos.sh", "scripts/native-direct.sh"):
        shutil.copy2(SOURCE / name, source / name)
    shutil.copytree(SOURCE / "src", source / "src")
    nested = source / "src/litechecker/diagnostics/platform/macos.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("NESTED_RUNTIME = True\n")
    (source / ".env.standalone").write_text(
        "LC_AGENT_NAME='Source Mac'\nLC_TELEGRAM_CHAT_ID='-77'\nLC_INTERVAL_SECONDS='12'\n"
    )
    (source / "secrets").mkdir()
    for name, value in {
        "telegram_bot_token": "source-bot",
        "subscription_url": "https://subscription.invalid/native",
    }.items():
        path = source / "secrets" / name
        path.write_text(value)
        path.chmod(0o600)
    (source / "state/standalone").mkdir(parents=True)
    (source / "state/standalone/device.json").write_text(
        json.dumps({"agent_id": "device-" + "4" * 32, "state_key": "k" * 32})
    )
    write_manifest(source)

    root = tmp_path / "home/Library/Application Support/LiteChecker"
    runtime = root / ".native-direct"
    (runtime / "venv/bin").mkdir(parents=True)
    make_script(runtime / "uv", 'printf "uv:%s\\n" "$*" >> "$COMMAND_LOG"\n')
    make_script(runtime / "xray", 'printf "Xray 26.3.27\\n"\n')
    make_script(
        runtime / "venv/bin/python",
        'printf "python:%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$*" in *"litechecker.native_install"*|*"service_settings"*) exec "$PYTHON_BIN" "$@";; esac\n',
    )
    env, command_log = native_env(tmp_path, root)
    # The test runner's environment need not live inside this source checkout.
    env["PYTHON_BIN"] = sys.executable
    docker = Path(env["PATH"].split(os.pathsep)[0]) / "docker"
    make_script(
        docker,
        'printf "docker:%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$1" in\n'
        '  ps) printf "legacy-id\\nunrelated-id\\n";;\n'
        '  inspect) id="${@: -1}"; '
        'if test "$id" = legacy-id; then printf "litechecker-standalone|checker|%s|%s/compose.standalone.yml,%s/compose.telegram-proxy.yml|[\\"standalone\\"]\\n" "$SOURCE_ROOT" "$SOURCE_ROOT" "$SOURCE_ROOT"; '
        'else printf "litechecker-standalone|checker|/different/source|/different/source/compose.standalone.yml|[\\"standalone\\"]\\n"; fi;;\n'
        '  stop|start) :;;\n'
        'esac\n',
    )
    env["SOURCE_ROOT"] = str(source)
    return source, root, env, command_log


def test_native_controls_use_absolute_launchd_target_and_one_shot_check(tmp_path):
    script, root, env, command_log, python_log = prepared_control(tmp_path)
    for action in ("start", "status", "stop", "check"):
        result = subprocess.run([BASH, script, action], env=env, capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == 0, result.stderr
    commands = command_log.read_text().splitlines()
    uid = os.getuid()
    assert any(f"bootstrap gui/{uid} " in command for command in commands)
    assert any(f"print gui/{uid}/com.litechecker.direct" in command for command in commands)
    assert any(f"bootout gui/{uid}/com.litechecker.direct" in command for command in commands)
    assert python_log.read_text().splitlines() == [
        "-m", "litechecker.direct_service", "--root", str(root),
        "--xray", str(root / ".native-direct/xray"), "--once",
    ]


def test_failed_launchctl_start_is_not_reported_as_started(tmp_path):
    script, _, env, command_log, _ = prepared_control(tmp_path)
    launchctl = Path(env["PATH"].split(os.pathsep)[0]) / "launchctl"
    make_script(launchctl, 'printf "launchctl:%s\\n" "$*" >> "$COMMAND_LOG"\ncase "$1" in bootstrap) exit 23;; esac\n')

    result = subprocess.run([BASH, script, "start"], env=env, capture_output=True,
                            text=True, timeout=10)

    assert result.returncode == 23
    assert "запущ" not in result.stdout.lower()
    assert "bootstrap" in command_log.read_text()


def test_start_retries_transient_launchd_unload_race(tmp_path):
    script, _, env, command_log, _ = prepared_control(tmp_path)
    env["LITECHECKER_LAUNCHCTL_RETRY_DELAY_SECONDS"] = "0"
    launchctl = Path(env["PATH"].split(os.pathsep)[0]) / "launchctl"
    attempts = tmp_path / "bootstrap-attempts"
    env["BOOTSTRAP_ATTEMPTS"] = str(attempts)
    make_script(
        launchctl,
        'printf "launchctl:%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'if test "$1" = bootstrap; then\n'
        '  count=0; test ! -f "$BOOTSTRAP_ATTEMPTS" || count=$(cat "$BOOTSTRAP_ATTEMPTS")\n'
        '  count=$((count + 1)); printf "%s" "$count" > "$BOOTSTRAP_ATTEMPTS"\n'
        '  test "$count" -gt 1 || exit 5\n'
        'fi\n',
    )

    result = subprocess.run([BASH, script, "start"], env=env, capture_output=True,
                            text=True, timeout=10)

    assert result.returncode == 0, result.stderr
    commands = command_log.read_text().splitlines()
    assert sum("launchctl:bootstrap" in command for command in commands) == 2
    assert "запущен" in result.stdout.lower()


def test_native_installer_prepares_before_launch_and_stops_only_exact_legacy(tmp_path):
    source, root, env, command_log = install_fixture(tmp_path)

    result = subprocess.run([BASH, source / "scripts/install-macos.sh", source], env=env,
                            capture_output=True, text=True, timeout=20)

    assert result.returncode == 0, result.stderr
    calls = command_log.read_text().splitlines()
    uv_index = next(i for i, call in enumerate(calls) if call.startswith("uv:"))
    configure_index = next(i for i, call in enumerate(calls) if "litechecker.native_install" in call)
    preflight_index = next(i for i, call in enumerate(calls) if "service_settings" in call)
    stop_index = calls.index("docker:stop legacy-id")
    launch_index = next(i for i, call in enumerate(calls) if "launchctl:bootstrap" in call)
    assert uv_index < configure_index < preflight_index < stop_index < launch_index
    assert "docker:stop unrelated-id" not in calls
    assert json.loads((root / "native-settings.json").read_text())["LC_INTERVAL_SECONDS"] == "600"
    assert json.loads((root / "state/native-direct/device.json").read_text())["agent_id"] == "device-" + "4" * 32
    assert not (root / ".env.standalone").exists()
    assert not (root / "state/standalone").exists()
    assert (
        root / "src/litechecker/diagnostics/platform/macos.py"
    ).read_text() == "NESTED_RUNTIME = True\n"


def test_native_installer_rejects_payload_not_matching_manifest_before_bootstrap(tmp_path):
    source, root, env, command_log = install_fixture(tmp_path)
    (source / "src/litechecker/native_install.py").write_text("# tampered after packaging\n")

    result = subprocess.run([BASH, source / "scripts/install-macos.sh", source], env=env,
                            capture_output=True, text=True, timeout=20)

    assert result.returncode != 0
    calls = command_log.read_text().splitlines() if command_log.exists() else []
    assert not any(call.startswith("uv:") for call in calls)
    assert not any(call.startswith("docker:stop") for call in calls)
    assert not any("launchctl:bootstrap" in call for call in calls)


def test_native_installer_missing_manifest_points_to_attached_client_archive(tmp_path):
    source, _, env, command_log = install_fixture(tmp_path)
    (source / "CONTENTS.sha256.json").unlink()

    result = subprocess.run(
        [BASH, source / "scripts/install-macos.sh", source],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode != 0
    assert re.findall(r"https://[^\s]+", result.stderr) == [
        "https://github.com/0xWayyo/LiteChecker/releases/latest"
    ]
    assert "клиентский ZIP" in result.stderr
    assert "Source code" in result.stderr
    assert "package_agent.py" not in result.stderr
    assert "PYTHONPATH" not in result.stderr
    assert "uv run" not in result.stderr
    assert not command_log.exists()


def test_native_installer_rolls_back_exact_legacy_if_launchd_start_fails(tmp_path):
    source, _, env, command_log = install_fixture(tmp_path)
    launchctl = Path(env["PATH"].split(os.pathsep)[0]) / "launchctl"
    make_script(
        launchctl,
        'printf "launchctl:%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$1" in bootstrap) exit 31;; esac\n',
    )

    result = subprocess.run([BASH, source / "scripts/install-macos.sh", source], env=env,
                            capture_output=True, text=True, timeout=20)

    assert result.returncode == 31
    calls = command_log.read_text().splitlines()
    assert "docker:stop legacy-id" in calls
    assert "docker:start legacy-id" in calls
    assert "docker:start unrelated-id" not in calls
    assert "установлен и запущен" not in result.stdout.lower()


@pytest.mark.parametrize(
    "linked",
    ["scripts", "src", "src/litechecker/collector", "src/litechecker/diagnostics"],
)
def test_native_installer_rejects_linked_payload_directory_before_mutation(tmp_path, linked):
    source, root, env, command_log = install_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)

    result = subprocess.run([BASH, source / "scripts/install-macos.sh", source], env=env,
                            capture_output=True, text=True, timeout=20)

    assert result.returncode != 0
    assert list(outside.iterdir()) == []
    calls = command_log.read_text().splitlines() if command_log.exists() else []
    assert not any(call.startswith("uv:") for call in calls)
    assert not any(call.startswith("docker:stop") for call in calls)
    assert not any("launchctl:bootstrap" in call for call in calls)

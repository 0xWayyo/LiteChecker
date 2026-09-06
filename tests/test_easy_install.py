"""Run the click installers with local command doubles; no Docker or network."""

import os
from pathlib import Path
import shutil
import subprocess
import pty

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


@pytest.fixture
def bundle(tmp_path):
    source = tmp_path / "Папка Ивана's LiteChecker"
    (source / "scripts").mkdir(parents=True)
    for name in ("scripts/install.sh", "INSTALL.sh", "INSTALL.command"):
        original = ROOT / name
        if original.is_file():
            shutil.copy2(original, source / name)
    (source / "run.sh").write_text(
        '#!/bin/bash\nset -eu\n'
        'printf "%s\\n" "$*" >> "$RUN_LOG"\n'
        'case "$*" in\n'
        '  "setup --quick") test "${FAIL_SETUP:-0}" = 0 || exit 19; '
        'printf "configured here\\n" > .env.standalone ;;\n'
        '  start) test -f .env.standalone; exit "${FAIL_START:-0}" ;;\n'
        '  status) printf "checker running\\n" ;;\n'
        '  *) exit 99 ;;\nesac\n'
    )
    for name in ("Dockerfile", ".dockerignore", "pyproject.toml", "uv.lock", "compose.standalone.yml", "compose.telegram-proxy.yml"):
        (source / name).write_text("build input\n")
    (source / "src/litechecker/collector").mkdir(parents=True)
    (source / "src/litechecker/__init__.py").write_text("# runtime source\n")
    (source / "src/litechecker/collector/__init__.py").write_text("# collector source\n")
    (source / "secrets").mkdir()
    (source / "secrets/telegram_bot_token").write_text("shared-test-bot-token\n")
    (source / "secrets/subscription_url").write_text("https://example.invalid/test-preset\n")
    return source


@pytest.fixture
def local_env(tmp_path):
    executable_dir = tmp_path / "bin"
    executable_dir.mkdir()
    for name in ("bash", "dirname", "mkdir", "chmod", "cp", "mv", "find", "sort", "id", "tail"):
        executable = shutil.which(name)
        assert executable
        (executable_dir / name).symlink_to(executable)
    uname = executable_dir / "uname"
    uname.write_text('#!/bin/bash\necho Linux\n')
    uname.chmod(0o700)
    docker = executable_dir / "docker"
    docker.write_text(
        '#!/bin/bash\ncase "$*" in\n'
        '  "compose version") exit "${COMPOSE_EXIT:-0}" ;;\n'
        '  info) exit "${DOCKER_EXIT:-0}" ;;\n'
        '  *) exit 99 ;;\nesac\n'
    )
    docker.chmod(0o700)
    home = tmp_path / "linux-home"
    home.mkdir()
    return {
        **os.environ,
        "PATH": str(executable_dir),
        "HOME": str(home),
        "RUN_LOG": str(tmp_path / "run-log"),
    }


def launch(source, env, script="scripts/install.sh", *args):
    assert (source / script).is_file(), f"installer is missing: {script}"
    return subprocess.run(
        [BASH, str(source / script), *args], cwd=source.parent,
        env=env, input="", text=True, capture_output=True, timeout=10,
    )


def calls(env):
    log = Path(env["RUN_LOG"])
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("entry", ["scripts/install.sh", "INSTALL.sh", "INSTALL.command"])
def test_installer_locates_its_project_and_sets_up_then_starts(bundle, local_env, entry):
    result = launch(bundle, local_env, entry)
    assert result.returncode == 0, result.stderr
    assert calls(local_env) == ["setup --quick", "start", "status"]
    assert "checker running" in result.stdout
    assert "shared-test-bot-token" not in result.stdout + result.stderr
    assert (bundle / "secrets/telegram_bot_token").read_text() == "shared-test-bot-token\n"


def test_repeat_installer_preserves_existing_device_configuration(bundle, local_env):
    (bundle / ".env.standalone").write_text("my existing device settings\n")
    result = launch(bundle, local_env)
    assert result.returncode == 0, result.stderr
    assert calls(local_env) == ["start", "status"]
    assert (bundle / ".env.standalone").read_text() == "my existing device settings\n"


def test_interactive_linux_install_uses_credential_wizard_before_start(bundle, local_env):
    (bundle / 'scripts/prepare-updater.sh').write_text('#!/bin/bash\nprintf "prepare\\n" >> "$RUN_LOG"\n')
    python = bundle / '.updater-runtime/venv/bin/python'
    python.parent.mkdir(parents=True)
    python.write_text('#!/bin/bash\nprintf "wizard\\n" >> "$RUN_LOG"\nprintf "configured here\\n" > .env.standalone\n')
    python.chmod(0o700)
    master, slave = pty.openpty()
    try:
        result = subprocess.run([BASH, str(bundle / 'scripts/install.sh')], stdin=slave,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=local_env, timeout=10)
    finally:
        os.close(master)
        os.close(slave)
    assert result.returncode == 0, result.stderr
    assert calls(local_env) == ['prepare', 'wizard', 'start', 'status']


@pytest.mark.parametrize("old_image,build_exit", [(False, 0), (True, 0), (False, 17)])
def test_linux_wizard_builds_current_image_before_managed_start(bundle, local_env, old_image, build_exit):
    # Real run.sh must build before its early updater-runtime handoff. The
    # external Docker/runtime doubles reject missing or stale baseline images.
    shutil.copy2(ROOT / "run.sh", bundle / "run.sh")
    (bundle / "scripts/prepare-updater.sh").write_text(
        '#!/bin/bash\nprintf "prepare\\n" >> "$RUN_LOG"\n'
    )
    python = bundle / ".updater-runtime/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text(
        '#!/bin/bash\nprintf "wizard\\n" >> "$RUN_LOG"\n'
        'printf "configured\\n" > .env.standalone\n'
    )
    python.chmod(0o700)
    (bundle / "scripts/update.sh").write_text(
        '#!/bin/bash\nset -eu\ntest "$*" = start\n'
        'printf "managed:start\\n" >> "$RUN_LOG"\n'
        'docker compose --env-file .env.standalone -f compose.standalone.yml '
        'up --detach --force-recreate --no-build --pull never checker\n'
    )
    local_env["IMAGE_FILE"] = str(bundle / "test-image")
    local_env["BUILD_EXIT"] = str(build_exit)
    if old_image:
        Path(local_env["IMAGE_FILE"]).write_text("old-source\n")
    (Path(local_env["PATH"]) / "docker").write_text(
        '#!/bin/bash\nset -eu\ncase "$*" in\n'
        '  "info"|"compose version") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml build checker")\n'
        '    printf "build\\n" >> "$RUN_LOG"\n'
        '    test "$BUILD_EXIT" = 0 || exit "$BUILD_EXIT"\n'
        '    printf "current-source\\n" > "$IMAGE_FILE" ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml up --detach --force-recreate --no-build --pull never checker")\n'
        '    test -f "$IMAGE_FILE" && test "$(< "$IMAGE_FILE")" = current-source || exit 23\n'
        '    printf "up\\n" >> "$RUN_LOG" ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml ps")\n'
        '    printf "ps\\n" >> "$RUN_LOG" ;;\n'
        '  *) exit 99 ;;\nesac\n'
    )
    master, slave = pty.openpty()
    try:
        result = subprocess.run([BASH, str(bundle / "scripts/install.sh")],
                                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=local_env, timeout=10)
    finally:
        os.close(master)
        os.close(slave)
    assert calls(local_env) == (["prepare", "wizard", "build", "managed:start", "up", "ps"]
                               if build_exit == 0 else ["prepare", "wizard", "build"])
    assert result.returncode == build_exit, result.stdout + result.stderr


def test_private_bundle_real_setup_needs_no_input(bundle, local_env):
    shutil.copy2(ROOT / "run.sh", bundle / "run.sh")
    (Path(local_env["PATH"]) / "docker").write_text(
        '#!/bin/bash\ncase "$*" in\n'
        '  "info"|"compose version") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml build checker") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml up -d --force-recreate checker") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml ps") exit 0 ;;\n'
        '  *) exit 99 ;;\nesac\n'
    )
    result = subprocess.run(
        [BASH, str(bundle / "INSTALL.sh")], cwd=bundle.parent,
        env=local_env, input="", text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    config = (bundle / ".env.standalone").read_text()
    assert "LC_AGENT_CITY=''" in config
    assert "LC_AGENT_NAME=''" in config
    assert "LC_TELEGRAM_CHAT_ID='-5361201677'" in config
    assert not (bundle / "state/standalone/device.json").exists()
    assert (bundle / "secrets/telegram_bot_token").read_text() == "shared-test-bot-token\n"
    assert (bundle / "secrets/subscription_url").read_text() == "https://example.invalid/test-preset\n"


def test_missing_docker_explains_installation_before_creating_settings(bundle, local_env):
    (Path(local_env["PATH"]) / "docker").unlink()
    result = launch(bundle, local_env)
    assert result.returncode != 0
    assert "Docker" in result.stdout + result.stderr
    assert "https://" in result.stdout + result.stderr
    assert calls(local_env) == []
    assert not (bundle / ".env.standalone").exists()


@pytest.mark.parametrize("variable, expected", [("COMPOSE_EXIT", "Compose"), ("DOCKER_EXIT", "Docker")])
def test_unavailable_docker_dependency_stops_before_setup(bundle, local_env, variable, expected):
    local_env[variable] = "1"
    result = launch(bundle, local_env)
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr
    assert calls(local_env) == []


@pytest.mark.parametrize("variable, expected", [("FAIL_SETUP", ["setup --quick"]), ("FAIL_START", ["setup --quick", "start"])])
def test_failure_never_reports_success_or_continues(bundle, local_env, variable, expected):
    local_env[variable] = "1"
    result = launch(bundle, local_env)
    assert result.returncode != 0
    assert calls(local_env) == expected
    assert "Контейнер запущен" not in result.stdout


def noisy_docker_for_real_launcher(bundle, local_env):
    shutil.copy2(ROOT / "run.sh", bundle / "run.sh")
    (bundle / ".env.standalone").write_text("LC_AGENT_CITY='Москва'\n")
    (Path(local_env["PATH"]) / "docker").write_text(
        '#!/bin/bash\ncase "$*" in\n'
        '  "info"|"compose version") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml build checker")\n'
        '    for ((i = 1; i <= 30; i++)); do printf "build-step-%02d\\n" "$i"; done\n'
        '    printf "build detail on stderr\\n" >&2\n'
        '    exit "${BUILD_EXIT:-0}" ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml up -d --force-recreate checker") exit 0 ;;\n'
        '  "compose --env-file .env.standalone -f compose.standalone.yml ps") printf "checker container status\\n" ;;\n'
        '  *) exit 99 ;;\nesac\n'
    )


def test_build_noise_goes_into_private_log_with_only_one_visible_status(bundle, local_env):
    noisy_docker_for_real_launcher(bundle, local_env)
    result = launch(bundle, local_env)
    assert result.returncode == 0, result.stderr
    assert "build-step-" not in result.stdout + result.stderr
    assert "build detail on stderr" not in result.stdout + result.stderr
    assert result.stdout.count("checker container status") == 1
    log = bundle / "state/install.log"
    assert "build-step-01" in log.read_text()
    assert "build-step-30" in log.read_text()
    assert "build detail on stderr" in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.parent.stat().st_mode & 0o777 == 0o700


def test_failed_build_shows_last_twenty_lines_and_retains_failure_code(bundle, local_env):
    noisy_docker_for_real_launcher(bundle, local_env)
    local_env["BUILD_EXIT"] = "17"
    result = launch(bundle, local_env)
    assert result.returncode == 17
    assert "Не удалось" in result.stderr
    assert "state/install.log" in result.stderr
    assert "build-step-11" not in result.stdout + result.stderr
    assert "build-step-12" in result.stderr
    assert "build-step-30" in result.stderr
    assert "build detail on stderr" in result.stderr
    assert "checker container status" not in result.stdout + result.stderr
    assert "Контейнер запущен" not in result.stdout
    assert "build-step-01" in (bundle / "state/install.log").read_text()


@pytest.mark.parametrize("target", ["state", "state/install.log"])
def test_install_logging_refuses_symlinks_without_touching_target(bundle, local_env, tmp_path, target):
    (bundle / ".env.standalone").write_text("my config\n")
    elsewhere = tmp_path / "elsewhere"
    if target == "state":
        elsewhere.mkdir(mode=0o755)
    else:
        elsewhere.write_text("keep this unrelated content\n")
        elsewhere.chmod(0o644)
        (bundle / "state").mkdir()
    (bundle / target).symlink_to(elsewhere)
    original_mode = elsewhere.stat().st_mode
    result = launch(bundle, local_env)
    assert result.returncode != 0
    assert calls(local_env) == []
    assert elsewhere.stat().st_mode == original_mode
    if target == "state":
        assert not list(elsewhere.iterdir())
    else:
        assert elsewhere.read_text() == "keep this unrelated content\n"

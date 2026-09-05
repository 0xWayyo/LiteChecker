"""Exercise Docker status output through the real launcher without Docker."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


@pytest.fixture
def launcher(tmp_path):
    root = tmp_path / "Lite Checker"
    root.mkdir()
    shutil.copy2(ROOT / "run.sh", root / "run.sh")
    (root / ".env.standalone").write_text("")
    (root / "compose.standalone.yml").write_text("services: {}\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    commands = {
        "uname": '#!/bin/sh\nprintf "Linux\\n"\n',
        "hostname": '#!/bin/sh\nprintf "test-device\\n"\n',
        "id": '#!/bin/sh\ncase "$1" in -u) echo 1234;; -g) echo 5678;; *) exit 97;; esac\n',
        "docker": '''#!/bin/sh
if [ "$*" = 'compose version' ]; then exit 0; fi
printf '%s\\n' "$@" > "$DOCKER_ARGS"
printf '%s\\n' "${LITECHECKER_UID-unset}" "${LITECHECKER_GID-unset}" > "$DOCKER_IDS"
case "$*" in
  'compose --env-file .env.standalone -f compose.standalone.yml ps')
    printf 'NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS\\n'
    ;;
  'compose --env-file .env.standalone -f compose.standalone.yml ps --all --format {{.State}} checker')
    printf '%s' "$STATE_OUTPUT"
    if [ "$STATUS_EXIT" != 0 ]; then printf 'Docker daemon unavailable\\n' >&2; fi
    exit "$STATUS_EXIT"
    ;;
  *) printf 'Unexpected Docker operation\\n' >&2; exit 97;;
esac
''',
    }
    for name, content in commands.items():
        command = bindir / name
        command.write_text(content)
        command.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        "DOCKER_ARGS": str(tmp_path / "docker-args"),
        "DOCKER_IDS": str(tmp_path / "docker-ids"),
        "STATE_OUTPUT": "running\n",
        "STATUS_EXIT": "0",
    }
    return root, env


def run_status(launcher, *arguments):
    root, env = launcher
    return subprocess.run(
        [BASH, str(root / "run.sh"), "status", *arguments],
        cwd=root.parent,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )


@pytest.mark.parametrize("output", ["running\n", "exited\n", "restarting\n", ""])
def test_machine_status_returns_checker_state_including_stopped_containers(launcher, output):
    _, env = launcher
    env["STATE_OUTPUT"] = output

    result = run_status(launcher, "--state")

    assert result.returncode == 0, result.stderr
    assert result.stdout == output
    assert Path(env["DOCKER_ARGS"]).read_text().splitlines() == [
        "compose", "--env-file", ".env.standalone", "-f", "compose.standalone.yml",
        "ps", "--all", "--format", "{{.State}}", "checker",
    ]
    assert Path(env["DOCKER_IDS"]).read_text().splitlines() == ["1234", "5678"]


def test_machine_status_preserves_docker_failure_instead_of_reporting_empty_success(launcher):
    launcher[1].update(STATE_OUTPUT="", STATUS_EXIT="19")

    result = run_status(launcher, "--state")

    assert result.returncode == 19
    assert result.stdout == ""
    assert "Docker daemon unavailable" in result.stderr


def test_plain_status_keeps_existing_human_readable_compose_output(launcher):
    result = run_status(launcher)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS\n"
    assert Path(launcher[1]["DOCKER_ARGS"]).read_text().splitlines() == [
        "compose", "--env-file", ".env.standalone", "-f", "compose.standalone.yml", "ps",
    ]

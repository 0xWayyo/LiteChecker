"""Executable contracts for container and host deployment artifacts."""

from __future__ import annotations

import json
import importlib.util
import os
import posixpath
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tomllib
import zipfile
import xml.etree.ElementTree as ET
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlsplit

import yaml
import pytest

from litechecker.collector.auth import AgentRegistry, RegistryError
from litechecker.security import is_valid_agent_id
from litechecker.update_store import validate_source_zip


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS_GUIDE = ROOT / "docs/operations/full-reference.md"
_RESTORE_SPEC = importlib.util.spec_from_file_location(
    "restore_sqlite", ROOT / "scripts/restore_sqlite.py"
)
assert _RESTORE_SPEC is not None and _RESTORE_SPEC.loader is not None
restore_sqlite = importlib.util.module_from_spec(_RESTORE_SPEC)
_RESTORE_SPEC.loader.exec_module(restore_sqlite)


def _readme_bash_block(marker: str) -> str:
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    return next(
        block
        for block in re.findall(r"```bash\n(.*?)\n```", readme, flags=re.DOTALL)
        if marker in block
    )


def _checkout_packaging_block() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Сборка из checkout", 1)[1].split("\n## ", 1)[0]
    return next(
        block
        for block in re.findall(r"```bash\n(.*?)\n```", section, flags=re.DOTALL)
        if "scripts/package_platforms.py" in block
    )


def _write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _docker_context_included(path: str) -> bool:
    ignored = False
    for raw_rule in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        rule = raw_rule.strip()
        if not rule or rule.startswith("#"):
            continue
        negated = rule.startswith("!")
        pattern = rule[1:] if negated else rule
        matched = (
            pattern == "**"
            or fnmatch(path, pattern)
            or (pattern.endswith("/") and path.rstrip("/") == pattern.rstrip("/"))
        )
        if matched:
            ignored = not negated
    return not ignored


def test_container_venv_keeps_launcher_interpreter_at_the_same_absolute_path(tmp_path):
    """Copying a venv from /build to /opt leaves console-script shebangs dangling."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_stages = re.findall(
        r"^FROM (python:[^ ]+) AS (?:builder|runtime)$",
        dockerfile,
        re.MULTILINE,
    )
    assert python_stages == [
        "python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
    ] * 2
    environment = re.search(r"UV_PROJECT_ENVIRONMENT=(/[^\\\s]+)", dockerfile)
    assert environment is not None
    venv_path = environment.group(1)

    copied = re.search(
        r"COPY --from=builder(?: --chown=[^ ]+)? (/[^ ]*\.venv) (/[^\n ]*\.venv)",
        dockerfile,
    )
    assert copied is not None
    assert copied.group(1) == venv_path
    assert copied.group(2) == venv_path
    assert "/build/.venv" not in dockerfile

    entrypoint_match = re.search(r"^ENTRYPOINT (\[[^\n]+\])$", dockerfile, re.MULTILINE)
    assert entrypoint_match is not None
    entrypoint = json.loads(entrypoint_match.group(1))
    assert entrypoint[:3] == [f"{venv_path}/bin/python", "-m", "litechecker.cli"]

    staged_root = tmp_path / "runtime-root"
    staged_interpreter = staged_root / f"{venv_path.lstrip('/')}/bin/python"
    staged_interpreter.parent.mkdir(parents=True)
    staged_interpreter.write_bytes(b"simulated-python")
    staged_launcher = staged_interpreter.with_name("litechecker")
    staged_launcher.write_text(f"#!{venv_path}/bin/python\n", encoding="utf-8")
    shebang = staged_launcher.read_text(encoding="utf-8").splitlines()[0][2:]

    assert (staged_root / shebang.lstrip("/")).is_file()


def test_container_explicitly_installs_the_collector_dependency_extra():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    sync = next(line for line in dockerfile.splitlines() if line.startswith("RUN uv sync"))

    assert "--extra collector" in sync


def test_web_stack_is_an_explicit_collector_extra_and_lock_version_agrees():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    installed = next(package for package in lock["package"] if package["name"] == "litechecker")
    assert installed["version"] == project["version"]
    assert not {"fastapi", "uvicorn"} & {
        requirement.split("[", 1)[0].split("=", 1)[0].split("<", 1)[0]
        for requirement in project["dependencies"]
    }
    collector = "\n".join(project["optional-dependencies"]["collector"])
    assert "fastapi" in collector
    assert "uvicorn[standard]" in collector


def test_docker_context_is_fail_closed_for_secrets_and_build_artifacts():
    """A newly created local secret must not silently enter the Docker context."""
    excluded = (
        ".git/config",
        ".worktrees/agent/private.txt",
        ".superpowers/sdd/report.md",
        ".venv/bin/python",
        ".pytest_cache/v/cache/nodeids",
        "__pycache__/module.pyc",
        "dist/litechecker.whl",
        ".env",
        ".env.production",
        "agents.json",
        "secrets/agent_token",
        "state/snapshot.json",
        "collector.sqlite3",
        "collector.sqlite3-wal",
        "private-subscription.json",
        "captured-xray-config.json",
        ".DS_Store",
        "src/litechecker/.DS_Store",
    )
    required = (
        "Dockerfile",
        ".dockerignore",
        "pyproject.toml",
        "uv.lock",
        "src/litechecker/cli.py",
        "src/litechecker/collector/app.py",
        "compose.example.yml",
        "deploy/litechecker-agent.service",
        "README.md",
    )

    assert all(not _docker_context_included(path) for path in excluded)
    assert all(_docker_context_included(path) for path in required)


def test_host_services_use_documented_installed_python_xray_and_state_paths():
    """A host unit must invoke the venv that the bootstrap guide actually creates."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    systemd = (ROOT / "deploy/litechecker-agent.service").read_text(encoding="utf-8")
    assert (
        "ExecStart=/opt/litechecker/.venv/bin/python -m litechecker.cli agent"
        in systemd
    )
    assert "EnvironmentFile=/etc/litechecker/agent.env" in systemd
    assert "Environment=LC_STATE_DIR=/var/lib/litechecker" in systemd
    assert "Environment=LC_XRAY_BINARY=/usr/local/bin/xray" in systemd
    assert "-o root -g litechecker -m 750 /etc/litechecker" in readme
    for path in (
        "/opt/litechecker/.venv/bin/python",
        "/etc/litechecker/agent.env",
        "/etc/litechecker/secrets/agent_token",
        "/etc/litechecker/secrets/subscription_url",
        "/etc/litechecker/secrets/state_key",
        "/var/lib/litechecker",
        "/usr/local/bin/xray",
    ):
        assert path in readme

    plist = ET.parse(ROOT / "deploy/com.litechecker.agent.plist").getroot()
    root_dict = plist.find("dict")
    assert root_dict is not None
    children = list(root_dict)
    arguments_index = next(
        index
        for index, element in enumerate(children)
        if element.tag == "key" and element.text == "ProgramArguments"
    )
    arguments = [
        value.text for value in children[arguments_index + 1].findall("string")
    ]
    assert arguments == [
        "/Users/REPLACE_ME/Library/Application Support/LiteChecker/.venv/bin/python",
        "-m",
        "litechecker.cli",
        "agent",
    ]
    assert arguments[0] in readme


def test_host_bootstrap_pins_downloads_and_has_no_abstract_install_paths():
    """A fresh-host guide must name verifiable artifacts, not imaginary local paths."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    assert "/path/to/xray" not in readme
    assert "/absolute/path/to/dist" not in readme
    assert "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/" in readme
    assert "sha256sum --check" in readme
    assert "shasum -a 256 -c" in readme


def test_host_bootstraps_use_frozen_source_sync_at_the_service_venv():
    """Host installs must not resolve wheel dependencies outside the committed lock."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    linux = _readme_bash_block("Xray-linux-64.zip")
    macos = _readme_bash_block("Xray-macos-64.zip")

    assert "pip install" not in linux
    assert "pip install" not in macos
    assert (
        'test "$(/usr/local/bin/uv --version | awk \'{print $1, $2}\')" = "uv 0.8.22"'
        in linux
    )
    assert "UV_PROJECT_ENVIRONMENT=/opt/litechecker/.venv" in linux
    assert "uv sync --frozen --no-dev --no-editable" in linux
    assert "--project /opt/litechecker/app" in linux
    assert (
        'test "$("$UV_BIN" --version | awk \'{print $1, $2}\')" = "uv 0.8.22"'
        in macos
    )
    assert 'UV_PROJECT_ENVIRONMENT="$LITECHECKER_DIR/.venv"' in macos
    assert "sync --frozen --no-dev --no-editable" in macos
    assert '--project "$LITECHECKER_DIR/app"' in macos
    for block in (linux, macos):
        assert "pyproject.toml" in block
        assert "uv.lock" in block
        assert "src" in block


def test_docker_bootstrap_uses_mount_owner_identity_on_both_platforms():
    """Explicit host identity keeps strict owner checks portable without a global relaxation."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    docker = readme.split("## Первый запуск в Docker", 1)[1].split(
        "## Добавление второго города", 1
    )[0]
    macos_host = readme.split("## macOS: launchd", 1)[1]

    assert "LITECHECKER_UID=$(id -u)" in docker
    assert "LITECHECKER_GID=$(id -g)" in docker
    assert "Docker Desktop" in docker
    assert "native Linux" in docker
    assert "10001:10001" not in docker
    assert "10001:10001" not in macos_host
    assert "chmod 600 .env .env.collector .env.agent agents.json secrets/*" in docker


def test_second_city_registry_replacement_is_atomic_and_owner_preserving():
    """Editing the live registry in place could expose a partial configuration."""
    block = _readme_bash_block("agents.json.next")
    assert "mktemp ./agents.json.next." in block
    assert block.index("${EDITOR") < block.index("chmod 600")
    assert block.index("chmod 600") < block.index("mv -f")
    assert "chown" not in block


def test_macos_creates_xray_destination_before_root_install():
    """A fresh macOS host does not guarantee that /usr/local/bin already exists."""
    block = _readme_bash_block("Xray-macos-64.zip")
    directory = "sudo install -d -o root -g wheel -m 755 /usr/local/bin"
    binary = 'sudo install -o root -g wheel -m 755 "$XRAY_TMP/unpacked/xray" /usr/local/bin/xray'
    assert block.index(directory) < block.index(binary)


def test_host_checksum_mismatch_stops_before_extraction_or_install(tmp_path):
    """A failed digest must make both host bootstraps unable to install bytes."""
    stubs = tmp_path / "bin"
    stubs.mkdir()
    trace = tmp_path / "trace"
    home = tmp_path / "home"
    home.mkdir()
    _write_stub(stubs, "uname", 'printf "%s\\n" "$FAKE_ARCH"')
    _write_stub(
        stubs,
        "curl",
        'eval "output=\\${$#}"; printf corrupt > "$output"',
    )
    _write_stub(stubs, "sha256sum", 'printf "checksum-failed\\n" >> "$TRACE"; exit 1')
    _write_stub(stubs, "shasum", 'printf "checksum-failed\\n" >> "$TRACE"; exit 1')
    _write_stub(
        stubs,
        "uv",
        'if [ "$1" = "--version" ]; then printf "uv 0.8.22\\n"; '
        'else printf "uv %s\\n" "$*" >> "$TRACE"; fi',
    )
    for name in (
        "brew",
        "python3.12",
        "sudo",
        "install",
        "chmod",
        "sed",
        "open",
        "launchctl",
    ):
        _write_stub(stubs, name, f'printf "{name} %s\\n" "$*" >> "$TRACE"')

    base_env = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{stubs}:/usr/bin:/bin",
        "TMPDIR": str(tmp_path),
        "TRACE": str(trace),
    }
    for marker, architecture in (
        ("Xray-linux-64.zip", "x86_64"),
        ("Xray-macos-64.zip", "x86_64"),
    ):
        trace.write_text("", encoding="utf-8")
        block = _readme_bash_block(marker).replace(
            "/usr/local/bin/uv", str(stubs / "uv")
        )
        result = subprocess.run(
            ["bash", "-c", block],
            cwd=ROOT,
            env={**base_env, "FAKE_ARCH": architecture},
            text=True,
            capture_output=True,
            check=False,
        )
        calls = trace.read_text(encoding="utf-8")
        assert result.returncode != 0
        assert "checksum-failed" in calls
        assert "zipfile" not in calls
        assert "/usr/local/bin/xray" not in calls


def test_all_container_bases_use_verified_tag_plus_manifest_digest():
    """The official distroless image exposes the executable at /usr/local/bin/xray."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (
        "FROM ghcr.io/xtls/xray-core:26.3.27@sha256:"
        "592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7 AS xray"
    ) in dockerfile
    assert (
        "FROM ghcr.io/astral-sh/uv:0.8.22@sha256:"
        "9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv"
    ) in dockerfile
    assert len(re.findall(r"^FROM [^\n]+@sha256:[0-9a-f]{64}", dockerfile, re.MULTILINE)) == 4
    assert (
        "COPY --from=xray --chown=10001:10001 "
        "/usr/local/bin/xray /usr/local/bin/xray"
    ) in dockerfile


def test_dockerfile_frontend_is_pinned_by_verified_manifest_digest():
    """The BuildKit frontend is executable build input and must not float by tag."""
    first_line = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()[0]
    assert re.fullmatch(
        r"# syntax=docker/dockerfile:1\.7@sha256:[0-9a-f]{64}", first_line
    )


def test_tracked_examples_are_intentionally_invalid_until_replaced(tmp_path):
    """Copying an example unchanged must fail closed rather than enroll a public token."""
    registry = tmp_path / "agents.json"
    registry.write_bytes((ROOT / "examples/agents.example.json").read_bytes())
    registry.chmod(0o600)
    with pytest.raises(RegistryError):
        AgentRegistry.load(registry)

    agent_env = (ROOT / "examples/.env.agent.example").read_text(encoding="utf-8")
    collector_env = (ROOT / "examples/.env.collector.example").read_text(encoding="utf-8")
    compose_env = (ROOT / "examples/.env.compose.example").read_text(encoding="utf-8")
    agent_placeholder = re.search(r"^LC_AGENT_ID=(.+)$", agent_env, re.MULTILINE)
    assert agent_placeholder is not None
    assert is_valid_agent_id(agent_placeholder.group(1)) is False
    registry_placeholder = next(iter(json.loads(registry.read_text())))
    assert is_valid_agent_id(registry_placeholder) is False
    assert "LC_TELEGRAM_CHAT_ID=REPLACE_WITH_CHAT_ID" in collector_env
    assert "CADDY_DOMAIN=collector.example.invalid" in compose_env
    assert "CADDY_EMAIL=admin@example.invalid" in compose_env


def test_compose_has_automatic_https_private_collector_and_ack_healthcheck():
    """The example deployment must be public only through Caddy automatic HTTPS."""
    compose = yaml.safe_load((ROOT / "compose.example.yml").read_text(encoding="utf-8"))
    caddy = compose["services"]["caddy"]
    collector = compose["services"]["collector"]
    agent = compose["services"]["tbilisi-agent"]
    assert caddy["image"] == (
        "caddy:2.10.2-alpine@sha256:"
        "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
    )
    assert set(caddy["ports"]) == {"80:80", "443:443", "443:443/udp"}
    assert "ports" not in collector
    assert "collector-private" in caddy["networks"]
    assert "collector-private" in collector["networks"]
    assert compose["networks"]["collector-private"]["internal"] is True
    assert agent["healthcheck"]["test"] == ["CMD", "litechecker", "agent-health"]
    assert "/readyz" in " ".join(collector["healthcheck"]["test"])
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "{$CADDY_DOMAIN}" in caddyfile
    assert "email {$CADDY_EMAIL}" in caddyfile
    assert "reverse_proxy collector:8000" in caddyfile


def test_compose_runs_app_as_explicit_host_identity_with_bind_state():
    """The process UID must own mounted secrets and state on Linux and Docker Desktop."""
    compose = yaml.safe_load((ROOT / "compose.example.yml").read_text(encoding="utf-8"))
    for name in ("collector", "tbilisi-agent"):
        service = compose["services"][name]
        assert service["user"] == "${LITECHECKER_UID:?set LITECHECKER_UID}:${LITECHECKER_GID:?set LITECHECKER_GID}"
        assert not any(volume.startswith("collector-state:") or volume.startswith("tbilisi-agent-state:") for volume in service["volumes"])


def test_online_backup_script_copies_uncheckpointed_wal_safely(tmp_path):
    """SQLite online backup must include committed WAL pages without raw file copying."""
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    import sqlite3

    connection = sqlite3.connect(source)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
    connection.execute("INSERT INTO evidence VALUES ('committed-in-wal')")
    connection.commit()
    result = subprocess.run(
        ["python3", str(ROOT / "scripts/backup_sqlite.py"), str(source), str(backup)],
        text=True,
        capture_output=True,
        check=False,
    )
    connection.close()
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    with sqlite3.connect(backup) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert restored.execute("SELECT value FROM evidence").fetchall() == [("committed-in-wal",)]
    assert backup.stat().st_mode & 0o077 == 0


def test_restore_script_quarantines_wal_sidecars_and_atomically_replaces_main(tmp_path):
    """A stopped restore must not replay stale WAL bytes into a validated backup."""
    source = tmp_path / "backup.sqlite3"
    destination = tmp_path / "collector.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence VALUES ('backup')")
    with sqlite3.connect(destination) as connection:
        connection.execute("CREATE TABLE stale(value TEXT NOT NULL)")
    for suffix in ("-wal", "-shm"):
        (tmp_path / f"collector.sqlite3{suffix}").write_bytes(b"stale-sidecar")

    result = subprocess.run(
        ["python3", str(ROOT / "scripts/restore_sqlite.py"), str(source), str(destination)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "collector.sqlite3-wal").exists()
    assert not (tmp_path / "collector.sqlite3-shm").exists()
    assert list(tmp_path.glob("*.rollback.*")) == []
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT value FROM evidence").fetchall() == [("backup",)]
    assert destination.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    ("fault_kind", "fault_index"),
    [
        *(("replace", index) for index in range(1, 5)),
        *(("fsync", index) for index in range(1, 3)),
        *(("integrity", index) for index in range(1, 4)),
    ],
)
def test_restore_rolls_back_old_main_and_sidecars_after_every_filesystem_fault(
    tmp_path, monkeypatch, fault_kind, fault_index
):
    """Every failure through installed validation must restore all old bytes."""
    source = tmp_path / "backup.sqlite3"
    destination = tmp_path / "collector.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence VALUES ('backup')")
    expected = {
        destination: b"old-main",
        Path(f"{destination}-wal"): b"old-wal",
        Path(f"{destination}-shm"): b"old-shm",
    }
    for path, body in expected.items():
        path.write_bytes(body)

    if fault_kind == "replace":
        original = restore_sqlite.os.replace
        calls = 0

        def fail_once(source_path, destination_path):
            nonlocal calls
            calls += 1
            if calls == fault_index:
                raise OSError("synthetic-replace")
            return original(source_path, destination_path)

        monkeypatch.setattr(restore_sqlite.os, "replace", fail_once)
    elif fault_kind == "fsync":
        original = restore_sqlite.os.fsync
        calls = 0

        def fail_once(descriptor):
            nonlocal calls
            calls += 1
            if calls == fault_index:
                raise OSError("synthetic-fsync")
            return original(descriptor)

        monkeypatch.setattr(restore_sqlite.os, "fsync", fail_once)
    else:
        original = restore_sqlite._integrity_ok
        calls = 0

        def fail_once(path):
            nonlocal calls
            calls += 1
            return False if calls == fault_index else original(path)

        monkeypatch.setattr(restore_sqlite, "_integrity_ok", fail_once)

    assert restore_sqlite.main([str(source), str(destination)]) == 3
    assert {path: path.read_bytes() for path in expected} == expected


def test_built_archives_contain_only_explicit_release_members(tmp_path):
    """Source and wheel artifacts must exclude reviews, worktrees, tests, and secrets."""
    output = tmp_path / "dist"
    result = subprocess.run(
        ["uv", "build", "--out-dir", str(output)],
        cwd=ROOT,
        env={**os.environ},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    archives = list(output.glob("litechecker-*"))
    assert {path.suffix for path in archives} == {".gz", ".whl"}
    members: list[str] = []
    for archive in archives:
        if archive.suffix == ".whl":
            with zipfile.ZipFile(archive) as bundle:
                members.extend(bundle.namelist())
        else:
            with tarfile.open(archive) as bundle:
                members.extend(bundle.getnames())
    forbidden = (".superpowers", ".worktrees", "secrets", "tests/", ".diff", ".report")
    assert all(not any(token in member for token in forbidden) for member in members)
    assert any(member.endswith("src/litechecker/agent.py") for member in members)
    assert any(member == "litechecker/agent.py" for member in members)
    assert any(
        member.endswith("src/litechecker/collector/reporting.py") for member in members
    )
    assert any(member == "litechecker/collector/reporting.py" for member in members)


def test_documented_checkout_packaging_workflow_builds_valid_platform_archives(tmp_path):
    checkout = tmp_path / "checkout"
    shutil.copytree(
        ROOT,
        checkout,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", ".pytest_cache", "__pycache__", "dist", "secrets", "state", ".superpowers"
        ),
    )
    tools = tmp_path / "bin"
    tools.mkdir()
    _write_stub(
        tools,
        "uv",
        """case "$1" in
sync)
  shift
  test "$*" = "--frozen --no-dev" || exit 31
  : > .locked-environment-ready
  ;;
run)
  shift
  test "$1" = "--frozen" || exit 32
  shift
  test "$1" = "--no-dev" || exit 36
  shift
  test -f .locked-environment-ready || exit 33
  test "$1" = python || exit 34
  shift
  PYTHONPATH="$PWD/src" exec "$TEST_PYTHON" "$@"
  ;;
*) exit 35;;
esac""",
    )

    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    (checkout / "test-signing-public.key").write_bytes(base64.b64encode(public_key) + b"\n")
    command = _checkout_packaging_block().replace("/absolute/path/signing-public.key", "test-signing-public.key")
    result = subprocess.run(
        ["bash", "-eu", "-c", command],
        cwd=checkout,
        env={
            **os.environ,
            "PATH": f"{tools}:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEST_PYTHON": sys.executable,
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    output = checkout / "dist/platform-sources-0.6.3"
    assert len(list(output.iterdir())) == 3
    for platform, suffix, guide in (
        ("windows", "windows-update-source", "WINDOWS.md"),
        ("macos", "macos-update-source", "MACOS.md"),
        ("linux", "Linux", "LINUX.md"),
    ):
        archive = output / f"LiteChecker-0.6.3-{suffix}.zip"
        validated = validate_source_zip(archive.read_bytes(), expected_platform=platform, expected_version="0.6.3")
        assert validated.sha256
        assert any(file.path.as_posix() == guide for file in validated.files)


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_client_markdown_links_resolve_inside_archive_or_use_https(tmp_path, platform):
    from platform_package_support import extracted_profile

    root, _ = extracted_profile(tmp_path, platform)
    inventory = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    for source_name in sorted(name for name in inventory if name.endswith(".md")):
        source = root / source_name
        body = source.read_text(encoding="utf-8")
        for raw_target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", body):
            target = urlsplit(raw_target)
            if target.scheme:
                assert target.scheme == "https", f"unsafe link in {source_name}: {raw_target}"
                continue
            if not target.path:
                continue
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(source_name), target.path)
            )
            resolves_to_directory = any(
                member.startswith(resolved.rstrip("/") + "/") for member in inventory
            )
            assert resolved in inventory or resolves_to_directory, (
                f"client link escapes the archive inventory: {source_name} -> {raw_target}"
            )


def test_release_verifier_is_tracked_closed_and_covers_release_boundary():
    """A durable verifier must not accept/echo secrets and must retain all release checks."""
    verifier = ROOT / "scripts/verify-release.sh"
    body = verifier.read_text(encoding="utf-8")
    assert verifier.stat().st_mode & 0o111
    assert "usage: verify-release.sh [offline|live]" in body
    for command in (
        "git status --porcelain",
        "git grep",
        "uv sync --all-groups --all-extras --frozen",
        "uv run --no-sync pytest",
        "uv run --no-sync python -m compileall",
        "uv build --offline",
        "check_release_artifacts.py",
        "docker compose -f compose.example.yml config",
        "caddy validate",
        "xray version",
        "litechecker-smoke-subscription --probe",
    ):
        assert command in body
    marker = "do-not-print-this-secret"
    rejected = subprocess.run(
        [str(verifier), marker], text=True, capture_output=True, check=False
    )
    assert rejected.returncode != 0
    assert marker not in rejected.stdout + rejected.stderr


def test_release_verifier_live_mode_requires_docker(tmp_path):
    """Live mode is an explicit gate and cannot silently degrade to offline checks."""
    verifier = ROOT / "scripts/verify-release.sh"
    stub = tmp_path / "bin"
    stub.mkdir()
    _write_stub(stub, "docker", "exit 1")
    no_docker = subprocess.run(
        [str(verifier), "live"],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{stub}:{os.environ['PATH']}",
        },
        text=True,
        capture_output=True,
    )
    assert no_docker.returncode != 0
    assert "release-docker-required" in no_docker.stderr


def test_release_verifier_offline_mode_never_invokes_docker_or_live_smoke(tmp_path):
    verifier = ROOT / "scripts/verify-release.sh"
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "external-calls"
    _write_stub(
        tools,
        "git",
        'if [ "$1" = status ]; then printf " M local-change\\n"; exit 0; fi; exit 99',
    )
    _write_stub(tools, "docker", 'printf "docker\\n" >> "$MARKER"; exit 99')
    _write_stub(
        tools,
        "uv",
        'printf "uv:%s\\n" "$*" >> "$MARKER"; exit 99',
    )

    result = subprocess.run(
        [str(verifier), "offline"],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{tools}:/usr/bin:/bin",
            "MARKER": str(marker),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "release-worktree-not-clean" in result.stderr
    assert not marker.exists()


def test_ci_is_hermetic_pinned_and_validates_public_package_on_linux_and_macos():
    workflow = ROOT / ".github/workflows/ci.yml"
    body = workflow.read_text(encoding="utf-8")

    assert "push:" in body and "pull_request:" in body
    assert "ubuntu-latest" in body and "macos-latest" in body
    uses = re.findall(r"uses:\s+([^\s#]+)", body)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
    assert "scripts/check_release_artifacts.py --platform-smoke" in body
    assert "--network none" in body
    assert "prepare --root \"$candidate\"" in body
    assert "test_windows_bootstrap_runtime.py" in body
    assert not re.search(r"\b(secrets|sign|publish)\b", body, re.IGNORECASE)


def test_ci_and_release_verifier_reuse_the_explicitly_synced_environment():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    ci_steps = workflow["jobs"]["test-and-package"]["steps"]
    sync_index = next(
        index
        for index, step in enumerate(ci_steps)
        if str(step.get("run", "")).startswith("uv sync ")
    )
    run_steps = [
        (index, str(step["run"]))
        for index, step in enumerate(ci_steps)
        if str(step.get("run", "")).lstrip().startswith("uv run ")
    ]
    assert run_steps
    assert all(index > sync_index for index, _ in run_steps)
    assert all(command.lstrip().startswith("uv run --no-sync ") for _, command in run_steps)

    verifier_lines = (ROOT / "scripts/verify-release.sh").read_text(
        encoding="utf-8"
    ).splitlines()
    verifier_sync_index = verifier_lines.index(
        "uv sync --all-groups --all-extras --frozen"
    )
    verifier_runs = [
        (index, line.strip())
        for index, line in enumerate(verifier_lines)
        if line.strip().startswith("uv run ")
    ]
    assert verifier_runs
    assert all(index > verifier_sync_index for index, _ in verifier_runs)
    assert all(command.startswith("uv run --no-sync ") for _, command in verifier_runs)
    assert "uv build --offline" in verifier_lines


def test_readme_documents_verified_image_transfer_and_online_backup_restore():
    """A clean second host and rollback need complete immutable, WAL-safe workflows."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    for text in (
        "docker image save",
        "docker image load",
        "docker image inspect --format '{{.Id}}'",
        "scripts/backup_sqlite.py",
        "PRAGMA integrity_check",
        "LITECHECKER_UID=$(id -u)",
        "LITECHECKER_GID=$(id -g)",
        "scripts/restore_sqlite.py",
        "collector.sqlite3-wal",
        "collector.sqlite3-shm",
        "compose.agent.example.yml",
        "docker run",
        "Architecture",
    ):
        assert text in readme


def test_second_host_receiver_image_verification_runs_with_set_u_on_clean_host(
    tmp_path,
):
    """The receiver block must define every image/architecture value after docker load."""
    block = _readme_bash_block("LOADED_IMAGE_ID=")
    tools = tmp_path / "bin"
    tools.mkdir()
    _write_stub(
        tools,
        "docker",
        "case \"$*\" in *Architecture*) echo arm64;; *.Id*) echo sha256:expected;; *'run --rm'*) echo 'Xray 26.3.27';; *) exit 0;; esac",
    )
    _write_stub(tools, "shasum", "exit 0")
    _write_stub(tools, "uname", "echo arm64")
    (tmp_path / "litechecker-image.id").write_text("sha256:expected\n")
    (tmp_path / "litechecker-image.tar").write_bytes(b"image")
    (tmp_path / "litechecker-image.tar.sha256").write_text("placeholder\n")

    result = subprocess.run(
        ["bash", "-u", "-c", block],
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"},
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert block.index("docker image load") < block.index("LOADED_IMAGE_ID=")


def test_second_host_agent_bundle_is_runnable_and_mount_complete():
    """A clean second host must be able to run only the agent from source or an image."""
    compose = yaml.safe_load(
        (ROOT / "compose.agent.example.yml").read_text(encoding="utf-8")
    )
    assert set(compose["services"]) == {"agent"}
    agent = compose["services"]["agent"]
    assert agent["image"] == "litechecker:local"
    assert agent["build"]["context"] == "."
    assert agent["env_file"] == [".env.agent"]
    mounts = {entry.split(":", 1)[0] for entry in agent["volumes"]}
    assert mounts == {
        "./state/agent",
        "./secrets/agent_token",
        "./secrets/subscription_url",
        "./secrets/state_key",
    }
    assert agent["healthcheck"]["test"] == ["CMD", "litechecker", "agent-health"]


def test_compose_secret_mounts_match_example_file_configuration():
    """A secret path mismatch would make an otherwise correct Compose profile fail at startup."""
    compose = yaml.safe_load((ROOT / "compose.example.yml").read_text(encoding="utf-8"))

    def dotenv(name: str) -> dict[str, str]:
        return dict(
            line.split("=", 1)
            for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )

    agent = dotenv("examples/.env.agent.example")
    collector = dotenv("examples/.env.collector.example")
    agent_mounts = {volume.rsplit(":", 2)[-2] for volume in compose["services"]["tbilisi-agent"]["volumes"]}
    collector_mounts = {volume.rsplit(":", 2)[-2] for volume in compose["services"]["collector"]["volumes"]}

    assert {
        agent["LC_AGENT_TOKEN_FILE"],
        agent["LC_SUBSCRIPTION_URL_FILE"],
        agent["LC_STATE_KEY_FILE"],
    } <= agent_mounts
    assert {
        collector["LC_AGENTS_REGISTRY_PATH"],
        collector["LC_TELEGRAM_BOT_TOKEN_FILE"],
    } <= collector_mounts
    for service in compose["services"].values():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["tmpfs"]


def test_readme_bash_bootstrap_blocks_are_syntactically_valid():
    """Copy-paste setup blocks must at least parse as complete Bash programs."""
    readme = OPERATIONS_GUIDE.read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)\n```", readme, flags=re.DOTALL)
    assert len(blocks) >= 8
    for position, block in enumerate(blocks):
        result = subprocess.run(
            ["bash", "-n"],
            input=block,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, f"bash block {position}: {result.stderr}"

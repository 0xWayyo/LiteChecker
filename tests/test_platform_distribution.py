"""Production archives are complete, target-specific, reproducible public inputs."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def script(name):
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    path = ROOT / "scripts" / (name + ".py")
    assert path.is_file(), "production platform builder is missing"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sources(tmp_path):
    key = Ed25519PrivateKey.generate()
    paths = script("package_platforms").build_sources(
        tmp_path / "sources", version="0.6.0", public_key=key.public_key().public_bytes_raw(),
        repository="example/LiteChecker",
    )
    return key, paths


COMMON = {
    "pyproject.toml", "uv.lock", "distribution.json", "update-channel.json",
    "src/litechecker/__init__.py", "src/litechecker/distribution.py",
    "src/litechecker/platform_security.py", "src/litechecker/update_launcher.py",
    "src/litechecker/update_manifest.py", "src/litechecker/update_store.py",
    "src/litechecker/updater.py", "src/litechecker/probe.py",
    "src/litechecker/collector/auth.py", "src/litechecker/collector/reporting.py",
    "src/litechecker/collector/telegram.py", "src/litechecker/subscription.py",
}
REQUIRED = {
    "windows": {"LiteChecker.bat", "WINDOWS.md", "scripts/windows-native.ps1", "scripts/windows-app-entry.py", "scripts/windows-entry.py", "src/litechecker/windows_worker.py", "src/litechecker/windows_update.py"},
    "macos": {"INSTALL.command", "MACOS.md", "scripts/install.sh", "scripts/install-macos.sh", "scripts/native-direct.sh", "scripts/control.sh", "src/litechecker/install_handoff.py", "src/litechecker/macos_service.py", "src/litechecker/macos_update.py", "src/litechecker/device_setup.py", "src/litechecker/native_config.py"},
    "linux": {"INSTALL.sh", "LINUX.md", "Dockerfile", ".dockerignore", "compose.standalone.yml", "compose.telegram-proxy.yml", "scripts/install.sh", "scripts/control.sh", "src/litechecker/linux_update.py", "src/litechecker/device_setup.py", "src/litechecker/native_config.py"},
}
FORBIDDEN = {
    "windows": {"INSTALL.command", "INSTALL.sh", "Dockerfile", "scripts/install-wsl.sh", "scripts/control.sh", "src/litechecker/device_setup.py", "src/litechecker/native_config.py", "src/litechecker/macos_update.py", "src/litechecker/linux_update.py"},
    "macos": {"LiteChecker.bat", "WINDOWS.md", "INSTALL.sh", "Dockerfile", "compose.standalone.yml", "scripts/install-wsl.sh", "scripts/prepare-updater.sh", "scripts/windows-native.ps1", "src/litechecker/windows_worker.py", "src/litechecker/linux_update.py"},
    "linux": {"LiteChecker.bat", "WINDOWS.md", "INSTALL.command", "scripts/install-macos.sh", "scripts/native-direct.sh", "scripts/install-wsl.sh", "scripts/windows-native.ps1", "src/litechecker/windows_worker.py", "src/litechecker/macos_service.py", "src/litechecker/native_runtime.py", "src/litechecker/native_install.py", "src/litechecker/install_handoff.py"},
}


def contents(path):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        return {name.removeprefix("LiteChecker/"): archive.read(name) for name in archive.namelist()}


def test_platform_inventory_channels_dependencies_and_shared_bytes(sources):
    key, paths = sources
    assert set(paths) == {"windows", "macos", "linux"}
    trees = {platform: contents(path) for platform, path in paths.items()}
    for platform, files in trees.items():
        assert COMMON | REQUIRED[platform] <= files.keys()
        assert not FORBIDDEN[platform] & files.keys()
        assert json.loads(files["distribution.json"]) == {"schema": 1, "platform": platform}
        assert json.loads(files["update-channel.json"]) == {
            "schema": 2, "platform": platform, "enabled": True,
            "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            "manifest_urls": [f"https://github.com/example/LiteChecker/releases/latest/download/release-{platform}.json"],
        }
        project = tomllib.loads(files["pyproject.toml"].decode())
        assert project["project"]["version"] == "0.6.0"
        assert "dependency-groups" not in project
        assert "optional-dependencies" not in project["project"]
        packages = {p["name"] for p in tomllib.loads(files["uv.lock"].decode())["package"]}
        assert {"cryptography", "dnspython", "filelock", "httpx", "psutil", "pydantic", "socksio"} <= packages
        assert not {"pytest", "trustme", "fastapi", "uvicorn"} & packages
        for name in files:
            assert not set(name.split("/")) & {"tests", "secrets", "state", ".git", ".superpowers", "__pycache__"}
            assert name not in {"scripts/release.py", "scripts/package_agent.py", "src/litechecker/smoke.py", "src/litechecker/collector/app.py"}
        if platform != "windows":
            assert not any(name.endswith((".ps1", ".bat")) or "/windows_" in name for name in files)
    for left, right in (("windows", "macos"), ("macos", "linux"), ("linux", "windows")):
        shared = trees[left].keys() & trees[right].keys()
        for name in shared:
            if name.startswith("src/"):
                assert trees[left][name] == trees[right][name], name


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_extracted_profile_runs_entry_imports_and_lock_is_current(sources, tmp_path, platform):
    _, paths = sources
    destination = tmp_path / platform
    with zipfile.ZipFile(paths[platform]) as archive:
        archive.extractall(destination)
    root = destination / "LiteChecker"
    imports = {
        "windows": "from litechecker import windows_app, windows_worker, windows_update; assert callable(windows_app.main)",
        "macos": "from litechecker import macos_service, macos_update, native_install, install_handoff, device_setup; assert device_setup.main(['--help']) == 0",
        "linux": "from litechecker import cli, linux_update, device_setup, update_service; assert cli._parser().parse_args(['standalone', '--once']).once",
    }
    # argparse --help intentionally exits zero; imports come entirely from the extracted tree.
    result = subprocess.run([sys.executable, "-c", imports[platform]], cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    uv = os.environ.get("LITECHECKER_TEST_UV") or __import__("shutil").which("uv")
    if uv:
        result = subprocess.run([uv, "lock", "--check", "--offline", "--no-config", "--cache-dir", str(tmp_path / "uv-cache"), "--project", str(root)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_sign_all_targets_and_windows_wrapper_preserves_payload(sources, tmp_path):
    key, paths = sources
    private = tmp_path / "test-signing.key"
    private.write_bytes(base64.b64encode(key.private_bytes_raw()))
    private.chmod(0o600)
    release = script("release")
    for platform, path in paths.items():
        output = tmp_path / "signed" / platform
        release.build_release(archive=path, private_key=private, output=output,
            version="0.6.0", sequence="8", repository="example/LiteChecker", platform=platform)
        manifest = json.loads((output / f"release-{platform}.json").read_bytes())
        assert manifest["schema"] == 2
        payload = manifest["payload"]
        assert (payload["platform"], payload["version"], payload["sequence"]) == (platform, "0.6.0", 8)
        key.public_key().verify(base64.b64decode(manifest["signature"]), json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        artifact = output / payload["artifact"]["urls"][0].rsplit("/", 1)[1]
        assert artifact.read_bytes() == path.read_bytes()
        assert payload["artifact"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    wrapper = tmp_path / "LiteChecker-0.6.0-Windows.zip"
    script("package_windows").build_package(paths["windows"], wrapper)
    with zipfile.ZipFile(wrapper) as archive:
        for name, data in contents(paths["windows"]).items():
            assert archive.read("LiteChecker/_app/" + name) == data


def test_profile_builder_never_reads_local_secrets_and_outputs_are_immutable(tmp_path, monkeypatch):
    builder = script("package_platforms")
    original = Path.open
    def guarded(path, *args, **kwargs):
        assert "secrets" not in path.parts, "public build read local secrets"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    original_os_open = os.open
    def guarded_descriptor(path, *args, **kwargs):
        assert "secrets" not in Path(path).parts, "public build read local secrets"
        return original_os_open(path, *args, **kwargs)
    monkeypatch.setattr(os, "open", guarded_descriptor)
    options = dict(version="0.6.0", public_key=b"k" * 32, repository="example/LiteChecker")
    paths = builder.build_sources(tmp_path / "out", **options)
    before = {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}
    with pytest.raises(ValueError):
        builder.build_sources(tmp_path / "out", **options)
    assert before == {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}
    assert len(paths) == 3


def test_one_command_builds_all_public_artifacts_without_overwriting(tmp_path):
    release = script("release")
    private, public = tmp_path / "generated-test.key", tmp_path / "generated-test.pub"
    release.keygen(private, public)
    output = tmp_path / "release"
    args = ["build-platforms", "--version", "0.6.0", "--sequence", "8", "--repository", "example/LiteChecker", "--private-key", str(private), "--output", str(output)]
    assert release.main(args) == 0
    assert {p.name for p in output.glob("*.zip")} == {
        "LiteChecker-0.6.0-Windows.zip", "LiteChecker-0.6.0-macOS.zip", "LiteChecker-0.6.0-Linux.zip", "LiteChecker-0.6.0-windows-update-source.zip",
    }
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    assert len(before) == 11
    assert release.main(args) == 2
    assert before == {p.name: p.read_bytes() for p in output.iterdir()}
    assert all(private.read_bytes().strip() not in data for data in before.values())


@pytest.mark.parametrize("case", ["platform", "key", "repository", "version"])
def test_signing_rejects_profile_mismatch_before_outputs(sources, tmp_path, case):
    key, paths = sources
    private = tmp_path / "fixture.key"
    if case == "key":
        key = Ed25519PrivateKey.generate()
    private.write_bytes(base64.b64encode(key.private_bytes_raw()))
    private.chmod(0o600)
    output = tmp_path / "signed"
    with pytest.raises(ValueError):
        script("release").build_release(archive=paths["macos"], private_key=private, output=output,
            version="0.6.1" if case == "version" else "0.6.0", sequence="8",
            repository="other/LiteChecker" if case == "repository" else "example/LiteChecker",
            platform="linux" if case == "platform" else "macos")
    assert not output.exists()


def mac_source(tmp_path):
    key = Ed25519PrivateKey.generate()
    paths = script("package_platforms").build_sources(tmp_path / "sources", version="0.6.0",
        public_key=key.public_key().public_bytes_raw(), repository="example/LiteChecker")
    with zipfile.ZipFile(paths["macos"]) as archive:
        archive.extractall(tmp_path / "extracted")
    return tmp_path / "extracted/LiteChecker"


def install_attempt(source, root, tmp_path):
    # Fail runtime preparation deliberately after safe payload/anchor copying.
    # No dependency downloads, launchd, Docker or other host actions can run.
    bindir = tmp_path / "fixture-bin"
    bindir.mkdir(exist_ok=True)
    for name, body in {
        "uname": '#!/bin/sh\nprintf "Darwin\\n"\n',
        "bash": '#!/bin/sh\nexit 73\n',
    }.items():
        path = bindir / name
        path.write_text(body)
        path.chmod(0o700)
    return subprocess.run(["/bin/bash", str(source / "scripts/install-macos.sh"), str(source)],
        env={**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
             "LITECHECKER_NATIVE_ROOT": str(root), "LITECHECKER_LAUNCH_AGENTS_DIR": str(tmp_path / "launch-agents")},
        capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("enabled", [True, False])
def test_mac_interrupted_fresh_install_keeps_verified_anchors_and_can_retry(tmp_path, enabled):
    source = mac_source(tmp_path)
    root = tmp_path / "installed"
    first = install_attempt(source, root, tmp_path)
    assert first.returncode == 73, first.stderr
    assert (root / "distribution.json").read_bytes() == (source / "distribution.json").read_bytes()
    assert (root / "update-channel.json").read_bytes() == (source / "update-channel.json").read_bytes()
    assert (root / "scripts/install-profile.sh").read_bytes() == (source / "scripts/install-profile.sh").read_bytes()
    assert not (root / "scripts/prepare-updater.sh").exists()
    installed = root / ".updates"
    installed.mkdir(mode=0o700)
    channel = json.loads((source / "update-channel.json").read_bytes())
    channel["enabled"] = enabled
    channel_path = installed / "channel.json"
    channel_path.write_text(json.dumps(channel, sort_keys=True, separators=(",", ":")) + "\n")
    channel_path.chmod(0o600)
    settings = root / "native-settings.json"
    settings.write_bytes(b'{"LC_TELEGRAM_TOPIC_ID":42}\n')
    settings.chmod(0o600)
    trust = channel_path.read_bytes()
    retry = install_attempt(source, root, tmp_path)
    assert retry.returncode == 73, retry.stderr
    assert channel_path.read_bytes() == trust
    assert settings.read_bytes() == b'{"LC_TELEGRAM_TOPIC_ID":42}\n'


@pytest.mark.parametrize("case", ["legacy", "wrong-marker", "duplicate-marker", "duplicate-channel", "wrong-platform-channel", "extra-channel", "wrong-key", "oversized", "linked-marker", "linked-channel", "noncanonical"])
def test_mac_incompatible_root_is_unchanged_before_any_copy(tmp_path, case):
    source = mac_source(tmp_path)
    root = tmp_path / "installed"
    root.mkdir(mode=0o700)
    (root / "run.sh").write_bytes(b"old program retained")
    (root / "native-settings.json").write_bytes(b"old settings retained")
    if case != "legacy":
        for name in ("distribution.json", "update-channel.json"):
            (root / name).write_bytes((source / name).read_bytes())
            (root / name).chmod(0o600)
        if case == "wrong-marker":
            (root / "distribution.json").write_bytes(b'{"platform":"linux","schema":1}\n')
        elif case == "duplicate-marker":
            (root / "distribution.json").write_bytes(b'{"platform":"macos","platform":"macos","schema":1}\n')
        elif case == "duplicate-channel":
            path = root / "update-channel.json"
            path.write_bytes(path.read_bytes().replace(b'"schema":2', b'"schema":2,"schema":2'))
        elif case in {"extra-channel", "wrong-key", "noncanonical", "wrong-platform-channel"}:
            channel = json.loads((root / "update-channel.json").read_bytes())
            if case == "extra-channel":
                channel["extra"] = True
            elif case == "wrong-key":
                channel["public_key"] = base64.b64encode(b"z" * 32).decode()
            elif case == "wrong-platform-channel":
                channel["platform"] = "linux"
            (root / "update-channel.json").write_text(json.dumps(channel, sort_keys=True, separators=(",", ":") if case != "noncanonical" else None) + "\n")
        elif case == "oversized":
            (root / "update-channel.json").write_bytes(b"x" * 65537)
        else:
            name = "distribution.json" if case == "linked-marker" else "update-channel.json"
            (root / name).unlink()
            (root / name).symlink_to(source / name)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    result = install_attempt(source, root, tmp_path)
    assert result.returncode == 2, result.stderr
    assert "LITECHECKER_NATIVE_ROOT" in result.stderr
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}
    assert not (tmp_path / "launch-agents").exists()


def test_native_configuration_installs_marker_before_schema2_channel(tmp_path, monkeypatch):
    from litechecker import distribution, native_install
    source = mac_source(tmp_path)
    root = tmp_path / "installed"
    monkeypatch.setattr(distribution, "host_platform", lambda: "macos")
    # LaunchAgent/runtime preparation belongs to shell integration tests. Keep
    # actual marker, configuration, private-file and channel writes here.
    monkeypatch.setattr(native_install, "_write_plist", lambda *args: None)
    native_install.install_configuration(source, root, tmp_path / "launch-agents/test.plist")
    assert (root / "distribution.json").read_bytes() == (source / "distribution.json").read_bytes()
    assert json.loads((root / ".updates/channel.json").read_bytes())["platform"] == "macos"


def test_mac_partial_marker_anchor_is_retryable(tmp_path):
    source = mac_source(tmp_path)
    root = tmp_path / "installed"
    root.mkdir(mode=0o700)
    (root / "distribution.json").write_bytes((source / "distribution.json").read_bytes())
    result = install_attempt(source, root, tmp_path)
    assert result.returncode == 73, result.stderr
    assert (root / "update-channel.json").read_bytes() == (source / "update-channel.json").read_bytes()


@pytest.mark.parametrize("case", ["missing-marker", "duplicate-marker", "wrong-platform", "duplicate-channel", "extra-channel", "oversized-channel", "linked-channel"])
def test_mac_bad_source_profile_is_rejected_before_destination_creation(tmp_path, case):
    source = mac_source(tmp_path)
    marker, channel = source / "distribution.json", source / "update-channel.json"
    if case == "missing-marker":
        marker.unlink()
    elif case == "duplicate-marker":
        marker.write_bytes(b'{"platform":"macos","platform":"macos","schema":1}\n')
    elif case == "wrong-platform":
        marker.write_bytes(b'{"platform":"linux","schema":1}\n')
    elif case == "duplicate-channel":
        channel.write_bytes(channel.read_bytes().replace(b'"schema":2', b'"schema":2,"schema":2'))
    elif case == "extra-channel":
        channel.write_bytes(channel.read_bytes().replace(b'"schema":2', b'"schema":2,"extra":true'))
    elif case == "oversized-channel":
        channel.write_bytes(b"x" * 65537)
    else:
        other = tmp_path / "elsewhere-channel"
        other.write_bytes(channel.read_bytes())
        channel.unlink()
        channel.symlink_to(other)
    manifest_path = source / "CONTENTS.sha256.json"
    manifest = json.loads(manifest_path.read_bytes())
    for path in (marker, channel):
        if path.exists():
            manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            manifest.pop(path.name, None)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    root = tmp_path / "installed"
    result = install_attempt(source, root, tmp_path)
    assert result.returncode == 2, result.stderr
    assert not root.exists()
    assert not (tmp_path / "launch-agents").exists()


def test_linux_prerequisite_does_not_route_to_obsolete_windows_installer(sources, tmp_path):
    _, paths = sources
    with zipfile.ZipFile(paths["linux"]) as archive:
        archive.extractall(tmp_path / "linux")
    bindir = tmp_path / "fixture-bin"
    bindir.mkdir()
    uname = bindir / "uname"
    uname.write_text('#!/bin/sh\nprintf "Linux\\n"\n')
    uname.chmod(0o700)
    result = subprocess.run(["/bin/bash", str(tmp_path / "linux/LiteChecker/INSTALL.sh")],
        env={**os.environ, "PATH": str(bindir) + ":/usr/bin:/bin", "WSL_DISTRO_NAME": "Ubuntu"},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "Docker Engine" in result.stderr
    assert "Windows" not in result.stderr and "Docker Desktop" not in result.stderr


def test_real_mac_profile_retains_flat_layout_handoff(tmp_path, monkeypatch):
    from litechecker import install_handoff
    from types import SimpleNamespace

    source = mac_source(tmp_path)
    root = tmp_path / "installed"
    result = install_attempt(source, root, tmp_path)
    assert result.returncode == 73, result.stderr
    for name, data, mode in (
        ("native-settings.json", b'{"LC_INTERVAL_SECONDS":"600"}\n', 0o600),
        (".native-direct/venv/bin/python", b"#!/bin/sh\nexit 0\n", 0o700),
        (".native-direct/xray", b"#!/bin/sh\nexit 0\n", 0o700),
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    monkeypatch.setattr(install_handoff, "sys", SimpleNamespace(platform="darwin"))
    retained = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = install_handoff.finish_handoff(source, root)
    assert result["ok"] and result["cleaned"], result
    assert [p.name for p in source.iterdir()] == ["LiteChecker.command"]
    assert retained == {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("case", ["missing-marker", "duplicate-marker", "wrong-marker", "wrong-channel", "duplicate-channel", "old-installed-channel", "hash-mismatch"])
def test_linux_bad_profile_fails_before_docker_or_settings(sources, tmp_path, case):
    _, paths = sources
    with zipfile.ZipFile(paths["linux"]) as archive:
        archive.extractall(tmp_path / "linux")
    root = tmp_path / "linux/LiteChecker"
    marker, channel = root / "distribution.json", root / "update-channel.json"
    if case == "missing-marker":
        marker.unlink()
    elif case == "duplicate-marker":
        marker.write_bytes(b'{"platform":"linux","platform":"linux","schema":1}\n')
    elif case == "wrong-marker":
        marker.write_bytes(b'{"platform":"macos","schema":1}\n')
    elif case == "wrong-channel":
        channel.write_bytes(channel.read_bytes().replace(b'"platform":"linux"', b'"platform":"macos"'))
    elif case == "duplicate-channel":
        channel.write_bytes(channel.read_bytes().replace(b'"schema":2', b'"schema":2,"schema":2'))
    elif case == "old-installed-channel":
        (root / ".updates").mkdir(mode=0o700)
        (root / ".updates/channel.json").write_bytes(b'{"schema":1}\n')
    else:
        channel.write_bytes(channel.read_bytes().replace(b"example/LiteChecker", b"another/LiteChecker"))
    if case != "hash-mismatch":
        manifest = json.loads((root / "CONTENTS.sha256.json").read_bytes())
        for path in (marker, channel):
            if path.exists():
                manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                manifest.pop(path.name, None)
        (root / "CONTENTS.sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (root / ".env.standalone").write_bytes(b"preserve old device settings\n")
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    bindir = tmp_path / "fixture-bin"
    bindir.mkdir()
    docker_log = tmp_path / "docker-called"
    for name, body in {
        "uname": '#!/bin/sh\nprintf "Linux\\n"\n',
        "docker": '#!/bin/sh\nprintf "called\\n" >> "$DOCKER_LOG"\nexit 0\n',
    }.items():
        path = bindir / name
        path.write_text(body)
        path.chmod(0o700)
    result = subprocess.run(["/bin/bash", str(root / "INSTALL.sh")],
        env={**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"], "DOCKER_LOG": str(docker_log)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2, result.stderr
    assert not docker_log.exists()
    assert before == {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_posix_packages_share_guard_and_only_linux_ships_linux_bootstrap(sources):
    _, paths = sources
    macos, linux, windows = (contents(paths[target]) for target in ("macos", "linux", "windows"))
    assert "scripts/install-profile.sh" in macos
    assert macos["scripts/install-profile.sh"] == linux["scripts/install-profile.sh"]
    assert "scripts/install-profile.sh" not in windows
    assert "scripts/prepare-updater.sh" in linux
    assert "scripts/prepare-updater.sh" not in macos


@pytest.mark.parametrize("platform", ["macos", "linux"])
@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_posix_installers_reject_bad_shared_guard_before_execution(sources, tmp_path, platform, damage):
    _, paths = sources
    with zipfile.ZipFile(paths[platform]) as archive:
        archive.extractall(tmp_path / platform)
    source = tmp_path / platform / "LiteChecker"
    helper = source / "scripts/install-profile.sh"
    assert helper.is_file(), "shared pre-bootstrap guard must be packaged"
    marker = tmp_path / "helper-executed"
    if damage == "missing":
        helper.unlink()
    else:
        helper.write_text('printf executed > "$HELPER_EXECUTED"\nexit 71\n')
    if platform == "macos":
        result = install_attempt(source, tmp_path / "installed", tmp_path)
        assert not (tmp_path / "installed").exists()
    else:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for name, body in {
            "uname": '#!/bin/sh\nprintf "Linux\\n"\n',
            "docker": '#!/bin/sh\nprintf called > "$DOCKER_CALLED"\nexit 73\n',
        }.items():
            path = bindir / name
            path.write_text(body)
            path.chmod(0o700)
        result = subprocess.run(["/bin/bash", str(source / "INSTALL.sh")], stdin=subprocess.DEVNULL,
            env={**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
                 "HELPER_EXECUTED": str(marker), "DOCKER_CALLED": str(tmp_path / "docker-called")},
            text=True, capture_output=True, timeout=10)
        assert not (tmp_path / "docker-called").exists()
        assert not (source / "state").exists()
    assert result.returncode == 2, result.stderr
    assert not marker.exists()

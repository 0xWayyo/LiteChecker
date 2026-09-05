"""Public builds omit secrets; explicitly private handoff includes only shared secrets."""

import importlib.util
from pathlib import Path
import zipfile

import pytest


def packager(tmp_path):
    file = Path(__file__).resolve().parents[1] / "scripts/package_agent.py"
    spec = importlib.util.spec_from_file_location("test_packager", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    for name in (*module.FILES, "src/litechecker/__init__.py"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("distribution source " + name)
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for name in ("telegram_bot_token", "subscription_url", "state_key", "agent_token"):
        (secrets / name).write_text("private-fixture-value-for-" + name)
    (tmp_path / ".env.standalone").write_text("another-tester-name")
    return module


def test_public_package_does_not_include_deployment_secrets(tmp_path):
    module = packager(tmp_path)
    module.main([])
    with zipfile.ZipFile(tmp_path / "dist/LiteChecker-agent.zip") as archive:
        assert not any("secrets/" in name or "state/" in name for name in archive.namelist())
        assert "LiteChecker/.env.standalone" not in archive.namelist()
        assert not any(b"private-fixture-value" in archive.read(name) for name in archive.namelist())


def test_optional_public_update_channel_is_packaged_and_manifested(tmp_path):
    import base64
    import json
    import hashlib

    module = packager(tmp_path)
    channel = json.dumps({
        "schema": 1, "enabled": True,
        "public_key": base64.b64encode(b"k" * 32).decode(),
        "manifest_urls": ["https://github.com/example/LiteChecker/releases/latest/download/release.json"],
    }).encode()
    (tmp_path / "update-channel.json").write_bytes(channel)
    module.main([])
    with zipfile.ZipFile(tmp_path / "dist/LiteChecker-agent.zip") as archive:
        assert archive.read("LiteChecker/update-channel.json") == channel
        manifest = json.loads(archive.read("LiteChecker/CONTENTS.sha256.json"))
        assert manifest["update-channel.json"] == hashlib.sha256(channel).hexdigest()


@pytest.mark.parametrize("data", [b"{}", b'{"schema":true}', b"not-json"])
def test_unsafe_update_channel_is_not_packaged(tmp_path, data):
    module = packager(tmp_path)
    (tmp_path / "update-channel.json").write_bytes(data)
    with pytest.raises(ValueError):
        module.main([])
    assert not (tmp_path / "dist").exists()


def test_private_package_contains_common_secrets_but_never_device_identity(tmp_path):
    module = packager(tmp_path)
    module.main(["--with-secrets"])
    archive_path = tmp_path / "dist/LiteChecker-READY-PRIVATE.zip"
    assert archive_path.stat().st_mode & 0o777 == 0o600
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.read("LiteChecker/secrets/telegram_bot_token") == b"private-fixture-value-for-telegram_bot_token"
        assert archive.read("LiteChecker/secrets/subscription_url") == b"private-fixture-value-for-subscription_url"
        assert "LiteChecker/secrets/state_key" not in archive.namelist()
        assert "LiteChecker/secrets/agent_token" not in archive.namelist()
        assert "LiteChecker/.env.standalone" not in archive.namelist()


@pytest.mark.parametrize("private", [False, True])
def test_native_installer_is_shipped_but_native_device_data_is_not(tmp_path, private):
    module = packager(tmp_path)
    for name in ("scripts/install-macos.sh", "scripts/native-direct.sh"):
        (tmp_path / name).write_text("#!/bin/bash\nexit 0\n")
    for name in ("direct_service.py", "direct_outbox.py", "direct_reporting.py", "native_install.py"):
        (tmp_path / "src/litechecker" / name).write_text('"""Native module fixture."""\n')
    (tmp_path / "native-settings.json").write_text('{"LC_AGENT_NAME":"private-device-name"}')
    (tmp_path / "state/native-direct").mkdir(parents=True)
    (tmp_path / "state/native-direct/outbox.json").write_text("private-pending-report")
    (tmp_path / ".native-direct").mkdir()
    (tmp_path / ".native-direct/python").write_text("host-runtime")
    module.main(["--with-secrets"] if private else [])
    filename = "LiteChecker-READY-PRIVATE.zip" if private else "LiteChecker-agent.zip"
    with zipfile.ZipFile(tmp_path / "dist" / filename) as archive:
        for name in ("scripts/install-macos.sh", "scripts/native-direct.sh"):
            assert f"LiteChecker/{name}" in archive.namelist()
            assert archive.getinfo(f"LiteChecker/{name}").external_attr >> 16 & 0o111
        for name in ("direct_service.py", "direct_outbox.py", "direct_reporting.py", "native_install.py"):
            assert f"LiteChecker/src/litechecker/{name}" in archive.namelist()
        assert "LiteChecker/native-settings.json" not in archive.namelist()
        assert not any("/state/" in name or "/.native-direct/" in name for name in archive.namelist())
        assert not any(b"private-device-name" in archive.read(name) for name in archive.namelist())


def test_trial_package_does_not_replace_regular_private_distribution(tmp_path):
    module = packager(tmp_path)
    module.main(["--with-secrets"])
    regular = tmp_path / "dist/LiteChecker-READY-PRIVATE.zip"
    original = regular.read_bytes()
    module.main(["--with-secrets", "--direct-trial"])
    assert regular.read_bytes() == original
    trial = tmp_path / "dist/LiteChecker-DIRECT-TRIAL-PRIVATE.zip"
    with zipfile.ZipFile(trial) as archive:
        assert "LiteChecker/TRY-DIRECT.command" in archive.namelist()
        assert not any(".native-direct" in name or "/state/" in name for name in archive.namelist())


@pytest.mark.parametrize("trial", [False, True])
def test_private_package_includes_optional_proxy_with_private_permissions(tmp_path, trial):
    module = packager(tmp_path)
    (tmp_path / "secrets/telegram_proxy_url").write_text("socks5://fixture-user:fixture-password@proxy.invalid:1080\n")
    module.main(["--with-secrets", *(["--direct-trial"] if trial else [])])
    filename = "LiteChecker-DIRECT-TRIAL-PRIVATE.zip" if trial else "LiteChecker-READY-PRIVATE.zip"
    with zipfile.ZipFile(tmp_path / "dist" / filename) as archive:
        name = "LiteChecker/secrets/telegram_proxy_url"
        assert archive.read(name) == b"socks5://fixture-user:fixture-password@proxy.invalid:1080\n"
        assert archive.getinfo(name).external_attr >> 16 & 0o777 == 0o600
        assert "LiteChecker/compose.telegram-proxy.yml" in archive.namelist()
        assert "LiteChecker/secrets/agent_token" not in archive.namelist()
        assert "LiteChecker/secrets/state_key" not in archive.namelist()


def test_public_package_omits_optional_proxy_and_detects_its_content_in_source(tmp_path):
    module = packager(tmp_path)
    value = "socks5://fixture-user:fixture-password@proxy.invalid:1080"
    (tmp_path / "secrets/telegram_proxy_url").write_text(value + "\n")
    module.main([])
    with zipfile.ZipFile(tmp_path / "dist/LiteChecker-agent.zip") as archive:
        assert "LiteChecker/secrets/telegram_proxy_url" not in archive.namelist()
        assert not any(value.encode() in archive.read(name) for name in archive.namelist())
    (tmp_path / "src/litechecker/__init__.py").write_text(value)
    with pytest.raises(ValueError, match="local secret detected"):
        module.main([])


@pytest.mark.parametrize("kind", ["empty", "whitespace", "directory", "symlink", "dangling", "fifo"])
@pytest.mark.parametrize("private", [False, True])
def test_package_rejects_unsafe_optional_proxy_without_disclosing_it(tmp_path, kind, private):
    module = packager(tmp_path)
    path = tmp_path / "secrets/telegram_proxy_url"
    if kind == "empty":
        path.write_text("")
    elif kind == "whitespace":
        path.write_text(" \n\t")
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        import os
        os.mkfifo(path)
    else:
        target = tmp_path / "outside-secret"
        if kind == "symlink":
            target.write_text("never-show-this-value")
        path.symlink_to(target)
    with pytest.raises(ValueError) as failure:
        module.main(["--with-secrets"] if private else [])
    assert "never-show-this-value" not in str(failure.value)
    assert not (tmp_path / "dist").exists()

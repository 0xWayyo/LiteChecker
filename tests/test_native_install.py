"""Native installation migration is data-only and preserves local ownership."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest


def identity(agent_id: str) -> str:
    return json.dumps({"agent_id": agent_id, "state_key": "s" * 32})


def test_native_config_allowlist_is_public_and_drives_installer_parsing(tmp_path):
    from litechecker.native_config import NATIVE_CONFIG_KEYS
    from litechecker.native_install import _parse_env

    source = tmp_path / ".env.standalone"
    source.write_text(
        "\n".join(f"{key}='value'" for key in sorted(NATIVE_CONFIG_KEYS))
        + "\nLC_ALLOW_PRIVATE_TARGETS='true'\n"
    )

    parsed = _parse_env(source)

    assert set(parsed) == NATIVE_CONFIG_KEYS
    assert parsed["LC_INTERVAL_SECONDS"] == "600"
    assert "LC_ALLOW_PRIVATE_TARGETS" not in parsed


def test_public_bounded_reader_preserves_private_and_symlink_guarantees(tmp_path):
    from litechecker.native_runtime import read_bounded_regular

    source = tmp_path / "private-input"
    source.write_bytes(b"payload")
    source.chmod(0o600)
    assert read_bounded_regular(source, private=True) == b"payload"

    source.chmod(0o644)
    with pytest.raises(ValueError, match="private input permissions are unsafe"):
        read_bounded_regular(source, private=True)

    link = tmp_path / "linked-input"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="symbolic link input is not allowed"):
        read_bounded_regular(link)


def test_first_install_channel_is_pinned_and_reinstall_preserves_it(tmp_path):
    import base64
    from litechecker.native_install import _install_update_channel

    source, root = tmp_path / "source", tmp_path / "root"
    source.mkdir()
    root.mkdir()
    channel = {"schema": 1, "enabled": True,
               "public_key": base64.b64encode(b"a" * 32).decode(),
               "manifest_urls": ["https://example.com/release.json"]}
    incoming = source / "update-channel.json"
    incoming.write_text(json.dumps(channel))
    _install_update_channel(source, root)
    pinned = root / ".updates/channel.json"
    original = pinned.read_bytes()
    channel["public_key"] = base64.b64encode(b"b" * 32).decode()
    incoming.write_text(json.dumps(channel))
    _install_update_channel(source, root)
    assert pinned.read_bytes() == original
    assert pinned.stat().st_mode & 0o777 == 0o600


def test_optional_channel_absence_does_not_create_update_state(tmp_path):
    from litechecker.native_install import _install_update_channel

    source, root = tmp_path / "source", tmp_path / "root"
    source.mkdir()
    root.mkdir()
    _install_update_channel(source, root)
    assert not (root / ".updates").exists()


def test_configuration_parses_env_as_data_and_forces_production_interval(tmp_path):
    from litechecker.native_install import install_configuration

    source = tmp_path / "Пакет $(не команда)"
    root = tmp_path / "Library" / "Application Support" / "LiteChecker"
    plist = tmp_path / "Library" / "LaunchAgents" / "com.litechecker.direct.plist"
    source.mkdir()
    marker = tmp_path / "must-not-exist"
    (source / ".env.standalone").write_text(
        "LC_AGENT_NAME='$(touch " + str(marker) + ")'\n"
        "LC_AGENT_CITY='Тбилиси'\n"
        "LC_TELEGRAM_CHAT_ID='-12345'\n"
        "LC_INTERVAL_SECONDS='17'\n"
        "LC_MAX_CONCURRENCY='7'\n"
        "LC_ALLOW_PRIVATE_TARGETS='true'\n",
        encoding="utf-8",
    )
    runtime_python = root / ".native-direct/venv/bin/python"
    xray = root / ".native-direct/xray"
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("python")
    runtime_python.chmod(0o700)
    xray.write_text("xray")
    xray.chmod(0o700)

    install_configuration(source, root, plist)

    settings = json.loads((root / "native-settings.json").read_text())
    assert settings == {
        "LC_AGENT_CITY": "Тбилиси",
        "LC_AGENT_NAME": "$(touch " + str(marker) + ")",
        "LC_INTERVAL_SECONDS": "600",
        "LC_MAX_CONCURRENCY": "7",
        "LC_TELEGRAM_CHAT_ID": "-12345",
    }
    assert not marker.exists()
    assert (root / "native-settings.json").stat().st_mode & 0o777 == 0o600

    payload = plistlib.loads(plist.read_bytes())
    assert payload["Label"] == "com.litechecker.direct"
    assert payload["ProgramArguments"] == [
        str(runtime_python), "-m", "litechecker.macos_service",
        "--root", str(root), "--xray", str(xray),
    ]
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["ThrottleInterval"] >= 10
    assert payload["Umask"] == 0o077
    assert not any("telegram" in str(item).lower() for item in payload.get("EnvironmentVariables", {}).values())


def test_configuration_round_trips_quick_setup_empty_nbsp_and_apostrophe(tmp_path):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    source.mkdir()
    (source / ".env.standalone").write_text(
        "LC_AGENT_CITY=''\n"
        "LC_AGENT_NAME='Alice\\'s MacBook Pro'\n"
        "LC_HOST_NAME='MacBook Pro\N{NO-BREAK SPACE}— Tester'\n"
        "LC_AUTO_CITY='true'\n",
        encoding="utf-8",
    )
    root = tmp_path / "root"
    python = root / ".native-direct/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    python.chmod(0o700)
    xray = root / ".native-direct/xray"
    xray.write_text("xray")
    xray.chmod(0o700)

    install_configuration(source, root, tmp_path / "agent.plist")

    settings = json.loads((root / "native-settings.json").read_text())
    assert settings["LC_AGENT_CITY"] == ""
    assert settings["LC_AGENT_NAME"] == "Alice's MacBook Pro"
    assert settings["LC_HOST_NAME"] == "MacBook Pro\N{NO-BREAK SPACE}— Tester"
    assert settings["LC_AUTO_CITY"] == "true"


def test_plist_accepts_uv_python_symlink_only_when_target_stays_in_runtime(tmp_path):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    source.mkdir()
    root = tmp_path / "canonical"
    target = root / ".native-direct/python/cpython/bin/python3.12"
    target.parent.mkdir(parents=True)
    target.write_text("python")
    target.chmod(0o700)
    link = root / ".native-direct/venv/bin/python"
    link.parent.mkdir(parents=True)
    link.symlink_to(Path("../../python/cpython/bin/python3.12"))
    xray = root / ".native-direct/xray"
    xray.write_text("xray")
    xray.chmod(0o700)

    plist = tmp_path / "agent.plist"
    install_configuration(source, root, plist)
    assert plistlib.loads(plist.read_bytes())["ProgramArguments"][0] == str(link)

    plist.unlink()
    link.unlink()
    outside = tmp_path / "outside-python"
    outside.write_text("python")
    outside.chmod(0o700)
    link.symlink_to(outside)
    with pytest.raises(ValueError):
        install_configuration(source, root, plist)


def test_native_installer_rejects_symlinked_launch_agents_ancestor(tmp_path):
    from litechecker.native_install import _write_plist

    root = tmp_path / "root"
    python = root / ".native-direct/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    python.chmod(0o700)
    xray = root / ".native-direct/xray"
    xray.write_text("xray")
    xray.chmod(0o700)
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        _write_plist(
            root,
            linked_parent / "LaunchAgents/com.litechecker.direct.plist",
        )

    assert not (actual_parent / "LaunchAgents/com.litechecker.direct.plist").exists()


def test_migration_prefers_standalone_identity_and_preserves_canonical_files(tmp_path):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    root = tmp_path / "canonical"
    plist = tmp_path / "agent.plist"
    (source / "state/standalone").mkdir(parents=True)
    (source / "state/direct-trial").mkdir(parents=True)
    (source / "state/standalone/device.json").write_text(identity("device-" + "1" * 32))
    (source / "state/direct-trial/device.json").write_text(identity("device-" + "2" * 32))
    (source / "secrets").mkdir()
    for name, value in {
        "telegram_bot_token": "source-bot", "subscription_url": "https://source.invalid/sub",
        "telegram_proxy_url": "socks5://source.invalid:1080",
    }.items():
        path = source / "secrets" / name
        path.write_text(value)
        path.chmod(0o600)
    (source / ".env.standalone").write_text("LC_TELEGRAM_CHAT_ID='-7'\n")
    (root / "state/native-direct").mkdir(parents=True)
    canonical_identity = root / "state/native-direct/device.json"
    canonical_identity.write_text(identity("device-" + "9" * 32))
    canonical_identity.chmod(0o600)
    (root / "secrets").mkdir()
    canonical_bot = root / "secrets/telegram_bot_token"
    canonical_bot.write_text("canonical-bot")
    canonical_bot.chmod(0o600)
    (root / "native-settings.json").write_text('{"LC_AGENT_NAME":"canonical","LC_MAX_CONCURRENCY":9}\n')
    (root / "native-settings.json").chmod(0o600)
    runtime_python = root / ".native-direct/venv/bin/python"
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("python")
    runtime_python.chmod(0o700)
    (root / ".native-direct/xray").write_text("xray")
    (root / ".native-direct/xray").chmod(0o700)

    install_configuration(source, root, plist)
    install_configuration(source, root, plist)

    assert json.loads(canonical_identity.read_text())["agent_id"] == "device-" + "9" * 32
    assert canonical_bot.read_text() == "canonical-bot"
    assert (root / "secrets/subscription_url").read_text().strip() == "https://source.invalid/sub"
    assert (root / "secrets/telegram_proxy_url").read_text().strip() == "socks5://source.invalid:1080"
    assert json.loads((root / "native-settings.json").read_text()) == {
        "LC_AGENT_NAME": "canonical", "LC_MAX_CONCURRENCY": 9,
    }


def test_first_migration_uses_trial_identity_only_when_standalone_is_absent(tmp_path):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    root = tmp_path / "root"
    (source / "state/direct-trial").mkdir(parents=True)
    (source / "state/direct-trial/device.json").write_text(identity("device-" + "3" * 32))
    (source / "secrets").mkdir()
    for name in ("telegram_bot_token", "subscription_url"):
        path = source / "secrets" / name
        path.write_text("https://example.invalid" if name == "subscription_url" else "bot")
        path.chmod(0o600)
    (root / ".native-direct/venv/bin").mkdir(parents=True)
    (root / ".native-direct/venv/bin/python").write_text("python")
    (root / ".native-direct/venv/bin/python").chmod(0o700)
    (root / ".native-direct/xray").write_text("xray")
    (root / ".native-direct/xray").chmod(0o700)

    install_configuration(source, root, tmp_path / "agent.plist")

    migrated = json.loads((root / "state/native-direct/device.json").read_text())
    assert migrated["agent_id"] == "device-" + "3" * 32


@pytest.mark.parametrize("kind", ["identity", "secret", "settings", "root"])
def test_migration_rejects_symlink_inputs_and_destinations(tmp_path, kind):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    root = tmp_path / "root"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("do not touch")
    if kind == "identity":
        (source / "state/standalone").mkdir(parents=True)
        (source / "state/standalone/device.json").symlink_to(outside)
    elif kind == "secret":
        (source / "secrets").mkdir()
        (source / "secrets/telegram_bot_token").symlink_to(outside)
    elif kind == "settings":
        (source / ".env.standalone").symlink_to(outside)
    else:
        target = tmp_path / "actual-root"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)
    if kind != "root":
        (root / ".native-direct/venv/bin").mkdir(parents=True)
        (root / ".native-direct/venv/bin/python").write_text("python")
        (root / ".native-direct/venv/bin/python").chmod(0o700)
        (root / ".native-direct/xray").write_text("xray")
        (root / ".native-direct/xray").chmod(0o700)

    with pytest.raises(ValueError):
        install_configuration(source, root, tmp_path / "agent.plist")
    assert outside.read_text() == "do not touch"


@pytest.mark.parametrize("kind", ["identity", "secret", "settings"])
def test_repeat_install_still_rejects_linked_source_inputs(tmp_path, kind):
    from litechecker.native_install import install_configuration

    source = tmp_path / "source"
    source.mkdir()
    root = tmp_path / "root"
    (root / "state/native-direct").mkdir(parents=True)
    saved_identity = root / "state/native-direct/device.json"
    saved_identity.write_text(identity("device-" + "8" * 32))
    saved_identity.chmod(0o600)
    (root / "secrets").mkdir()
    for name, value in {
        "telegram_bot_token": "saved-bot",
        "subscription_url": "https://saved.invalid/sub",
    }.items():
        path = root / "secrets" / name
        path.write_text(value)
        path.chmod(0o600)
    settings = root / "native-settings.json"
    settings.write_text('{"LC_INTERVAL_SECONDS":600}\n')
    settings.chmod(0o600)
    python = root / ".native-direct/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("python")
    python.chmod(0o700)
    xray = root / ".native-direct/xray"
    xray.write_text("xray")
    xray.chmod(0o700)
    outside = tmp_path / "outside"
    outside.write_text("unrelated")
    if kind == "identity":
        (source / "state/standalone").mkdir(parents=True)
        (source / "state/standalone/device.json").symlink_to(outside)
    elif kind == "secret":
        (source / "secrets").mkdir()
        (source / "secrets/telegram_bot_token").symlink_to(outside)
    else:
        (source / ".env.standalone").symlink_to(outside)

    with pytest.raises(ValueError):
        install_configuration(source, root, tmp_path / "agent.plist")
    assert saved_identity.read_text() == identity("device-" + "8" * 32)
    assert (root / "secrets/telegram_bot_token").read_text() == "saved-bot"
    assert settings.read_text() == '{"LC_INTERVAL_SECONDS":600}\n'

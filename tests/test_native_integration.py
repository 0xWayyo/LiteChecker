"""The real installer output must be usable by the real production settings loader."""

import json
import plistlib


def test_migrated_installation_loads_same_identity_and_proxy_with_real_venv_layout(tmp_path):
    from litechecker.macos_service import service_settings
    from litechecker.native_install import install_configuration

    source = tmp_path / "Архив с пробелами"
    root = tmp_path / "Library/Application Support/LiteChecker"
    plist = tmp_path / "Library/LaunchAgents/com.litechecker.direct.plist"
    (source / "secrets").mkdir(parents=True, mode=0o700)
    for name, value in {
        "telegram_bot_token": "123456789:abcdefghijklmnopqrstuvwxyz12345",
        "subscription_url": "https://subscription.example/private",
        "telegram_proxy_url": "socks5://fixture:password@192.0.2.10:1080",
    }.items():
        path = source / "secrets" / name
        path.write_text(value)
        path.chmod(0o600)
    (source / "state/standalone").mkdir(parents=True, mode=0o700)
    saved_id = "device-" + "a" * 32
    device = source / "state/standalone/device.json"
    device.write_text(json.dumps({"agent_id": saved_id, "state_key": "k" * 32}))
    device.chmod(0o600)
    (source / ".env.standalone").write_text(
        "LC_TELEGRAM_CHAT_ID='-5361201677'\nLC_TELEGRAM_TOPIC_ID='42'\n"
        "LC_INTERVAL_SECONDS='120'\nLC_HOST_NAME='Test Mac'\nLC_HOST_OS='macOS'\n"
        "LC_ALLOW_PRIVATE_TARGETS='true'\nLC_STATE_DIR='/var/lib/litechecker'\n"
        "LC_TELEGRAM_BOT_TOKEN_FILE='/run/secrets/telegram_bot_token'\n"
    )
    actual_python = root / ".native-direct/python/cpython/bin/python3.12"
    actual_python.parent.mkdir(parents=True)
    actual_python.write_text("#!/bin/sh\nexit 0\n")
    actual_python.chmod(0o700)
    venv_python = root / ".native-direct/venv/bin/python"
    venv_python.parent.mkdir(parents=True)
    venv_python.symlink_to(actual_python)
    xray = root / ".native-direct/xray"
    xray.write_text("#!/bin/sh\nexit 0\n")
    xray.chmod(0o700)

    install_configuration(source, root, plist)
    settings = service_settings(root, xray)
    assert settings.identity.agent_id == saved_id
    assert settings.identity.name == "Test Mac (macOS)"
    assert settings.agent.state_key.get_secret_value() == "k" * 32
    assert settings.agent.interval_seconds == 600
    assert settings.agent.allow_private_targets is False
    assert settings.telegram_topic_id == 42
    assert settings.telegram_proxy_url.get_secret_value() == "socks5://fixture:password@192.0.2.10:1080"
    assert settings.state_dir == root / "state/native-direct"
    args = plistlib.loads(plist.read_bytes())["ProgramArguments"]
    assert args[:3] == [str(venv_python), "-m", "litechecker.macos_service"]
    assert "password" not in " ".join(args)

    # A normal user edit can use a JSON number; reinstallation must preserve it.
    config_path = root / "native-settings.json"
    payload = json.loads(config_path.read_text())
    payload["LC_TELEGRAM_TOPIC_ID"] = 43
    config_path.write_text(json.dumps(payload))
    install_configuration(source, root, plist)
    restarted = service_settings(root, xray)
    assert restarted.telegram_topic_id == 43
    assert restarted.identity.agent_id == saved_id

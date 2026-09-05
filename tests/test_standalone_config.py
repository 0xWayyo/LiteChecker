"""Device identity must survive restarts and not be shared by new installs."""

import json
import os

import pytest

from litechecker import config


def environment(path):
    return {
        "LC_STATE_DIR": str(path),
        "LC_AGENT_CITY": "Москва",
        "LC_AGENT_NAME": "Иван / домашний ПК",
        "LC_SUBSCRIPTION_URL": "https://subscription.example/private",
        "LC_TELEGRAM_BOT_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz",
        "LC_TELEGRAM_CHAT_ID": "-5361201677",
    }


def test_restart_keeps_id_and_key_but_another_install_gets_its_own(tmp_path):
    assert hasattr(config, "StandaloneSettings"), "standalone configuration is missing"
    first = config.StandaloneSettings.from_env(environment(tmp_path / "first"))
    restart = config.StandaloneSettings.from_env(environment(tmp_path / "first"))
    second = config.StandaloneSettings.from_env(environment(tmp_path / "second"))
    assert first.identity.agent_id == restart.identity.agent_id
    assert first.agent.state_key == restart.agent.state_key
    assert first.identity.agent_id != second.identity.agent_id
    assert first.agent.state_key != second.agent.state_key
    assert first.identity.city == second.identity.city == "Москва"
    assert first.identity.name == "Иван / домашний ПК"
    assert first.telegram_bot_token == second.telegram_bot_token
    assert first.telegram_chat_id == "-5361201677"
    assert first.agent.interval_seconds == 600
    assert first.agent.agent_id == first.identity.agent_id
    assert (tmp_path / "first/device.json").stat().st_mode & 0o777 == 0o600


def test_configuration_uses_explicit_environment_without_mutating_process(tmp_path):
    assert hasattr(config, "StandaloneSettings")
    before = dict(os.environ)
    env = environment(tmp_path)
    env["LC_MAX_CONCURRENCY"] = "7"
    env["LC_AGENT_TOKEN_FILE"] = "/old/collector-only-token"
    env["LC_STATE_KEY_FILE"] = "/old/collector-only-key"
    settings = config.StandaloneSettings.from_env(env)
    assert settings.agent.max_concurrency == 7
    assert dict(os.environ) == before


def test_secret_files_work_without_collector_credentials(tmp_path):
    assert hasattr(config, "StandaloneSettings")
    env = environment(tmp_path / "state")
    for name in ("LC_SUBSCRIPTION_URL", "LC_TELEGRAM_BOT_TOKEN"):
        file = tmp_path / name
        file.write_text(env.pop(name))
        file.chmod(0o600)
        env[name + "_FILE"] = str(file)
    result = config.StandaloneSettings.from_env(env)
    assert result.telegram_bot_token.get_secret_value() == "123456:abcdefghijklmnopqrstuvwxyz"
    assert result.agent.subscription_url.get_secret_value() == "https://subscription.example/private"


@pytest.mark.parametrize("field", ["LC_TELEGRAM_CHAT_ID"])
def test_missing_device_label_or_chat_is_not_silently_invented(tmp_path, field):
    assert hasattr(config, "StandaloneSettings")
    env = environment(tmp_path)
    env.pop(field)
    with pytest.raises(ValueError):
        config.StandaloneSettings.from_env(env)


def test_corrupt_saved_identity_is_not_silently_replaced(tmp_path):
    assert hasattr(config, "StandaloneSettings")
    device = tmp_path / "device.json"
    device.write_text('{"agent_id":"saved-device","state_key":"too-short"}')
    device.chmod(0o600)
    before = device.read_bytes()
    with pytest.raises(ValueError):
        config.StandaloneSettings.from_env(environment(tmp_path))
    assert device.read_bytes() == before


def test_explicit_id_can_be_selected_once_but_not_reassigned_in_place(tmp_path):
    assert hasattr(config, "StandaloneSettings")
    env = environment(tmp_path)
    env["LC_AGENT_ID"] = "moscow-ivan-home"
    assert config.StandaloneSettings.from_env(env).identity.agent_id == "moscow-ivan-home"
    env["LC_AGENT_ID"] = "another-device"
    with pytest.raises(ValueError):
        config.StandaloneSettings.from_env(env)


def test_device_symlink_is_rejected_without_changing_target(tmp_path):
    assert hasattr(config, "StandaloneSettings")
    target = tmp_path / "outside"
    target.write_text(json.dumps({"agent_id": "original", "state_key": "x" * 40}))
    target.chmod(0o600)
    (tmp_path / "device.json").symlink_to(target)
    with pytest.raises(ValueError):
        config.StandaloneSettings.from_env(environment(tmp_path))
    assert json.loads(target.read_text())["agent_id"] == "original"


def test_auto_name_uses_host_metadata_not_container_hostname(tmp_path):
    env = environment(tmp_path)
    env["LC_AGENT_NAME"] = ""
    env.update(LC_HOST_NAME="Ivan-MacBook", LC_HOST_OS="macOS", LC_CONTAINER_MODE="true")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "Ivan-MacBook (macOS)"
    assert settings.auto_network is True


def test_renaming_device_does_not_change_persistent_id_or_key(tmp_path):
    env = environment(tmp_path)
    env.update(LC_AGENT_NAME="", LC_HOST_NAME="Laptop-A", LC_HOST_OS="Linux")
    first = config.StandaloneSettings.from_env(env)
    env["LC_HOST_NAME"] = "Laptop-B"
    renamed = config.StandaloneSettings.from_env(env)
    assert renamed.identity.name == "Laptop-B (Linux)"
    assert first.identity.agent_id == renamed.identity.agent_id
    assert first.agent.state_key == renamed.agent.state_key


def test_manual_name_wins_and_disables_external_network_lookup_by_default(tmp_path):
    env = environment(tmp_path)
    env.update(LC_HOST_NAME="auto-host", LC_HOST_OS="Linux")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "Иван / домашний ПК"
    assert settings.auto_network is False


def test_container_without_host_metadata_uses_stable_id_fallback(tmp_path):
    env = environment(tmp_path)
    env.pop("LC_AGENT_NAME")
    env["LC_CONTAINER_MODE"] = "true"
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "Устройство " + settings.identity.agent_id[-8:]


def test_auto_network_can_be_disabled_without_losing_auto_device_name(tmp_path):
    env = environment(tmp_path)
    env.update(LC_AGENT_NAME="", LC_HOST_NAME="WorkPC", LC_HOST_OS="Windows / WSL", LC_AUTO_NETWORK="false")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "WorkPC (Windows / WSL)"
    assert settings.auto_network is False


def test_external_network_lookup_can_be_explicitly_enabled(tmp_path):
    env = environment(tmp_path)
    env.update(LC_AGENT_NAME="", LC_HOST_NAME="WorkPC", LC_HOST_OS="Linux", LC_AUTO_NETWORK="true")
    assert config.StandaloneSettings.from_env(env).auto_network is True


def test_auto_host_labels_cannot_inject_multiline_report_fields(tmp_path):
    env = environment(tmp_path)
    env.update(LC_AGENT_NAME="", LC_HOST_NAME="bad\nUP everything", LC_HOST_OS="bad\x00", LC_CONTAINER_MODE="true")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "Устройство " + settings.identity.agent_id[-8:]


def test_macos_nonbreaking_space_in_computer_name_is_not_discarded(tmp_path):
    env = environment(tmp_path)
    env.update(LC_AGENT_NAME="", LC_HOST_NAME="MacBook Pro\u00a0— Ivan", LC_HOST_OS="macOS", LC_CONTAINER_MODE="true")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.identity.name == "MacBook Pro — Ivan (macOS)"


def test_missing_city_enables_ipinfo_without_inventing_location(tmp_path):
    env = environment(tmp_path)
    env.pop("LC_AGENT_CITY")
    settings = config.StandaloneSettings.from_env(env)
    assert settings.auto_city is True
    assert settings.identity.city == "Город не определён"


def test_manual_city_overrides_ipinfo_without_changing_device_id(tmp_path):
    env = environment(tmp_path)
    env["LC_AGENT_CITY"] = ""
    automatic = config.StandaloneSettings.from_env(env)
    env["LC_AGENT_CITY"] = "Москва"
    manual = config.StandaloneSettings.from_env(env)
    assert manual.auto_city is False
    assert manual.identity.city == "Москва"
    assert automatic.identity.agent_id == manual.identity.agent_id

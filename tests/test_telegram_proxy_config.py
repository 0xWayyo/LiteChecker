"""Telegram's private proxy setting must not alter probe networking."""

import os
from pathlib import Path

import pytest

from litechecker.config import CollectorSettings, StandaloneSettings


PROXY = "socks5://tester:private-proxy-password@192.0.2.10:1080"


def env_for(tmp_path):
    return {
        "LC_STATE_DIR": str(tmp_path / "state"),
        "LC_SUBSCRIPTION_URL": "https://example.com/subscription",
        "LC_TELEGRAM_BOT_TOKEN": "123456789:abcdefghijklmnopqrstuvwxyz12345",
        "LC_TELEGRAM_CHAT_ID": "-1234",
    }


def secret_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(0o600)
    return path


def test_absent_telegram_proxy_does_not_adopt_global_proxy_environment(tmp_path):
    env = dict(env_for(tmp_path), HTTPS_PROXY=PROXY, ALL_PROXY=PROXY)
    assert StandaloneSettings.from_env(env).telegram_proxy_url is None


def test_proxy_file_wins_without_leaking_into_agent_settings_or_process_env(tmp_path):
    path = secret_file(tmp_path / "proxy", PROXY)
    env = dict(env_for(tmp_path), LC_TELEGRAM_PROXY_URL="http://old.invalid:1080",
               LC_TELEGRAM_PROXY_URL_FILE=str(path))
    before = dict(os.environ)
    settings = StandaloneSettings.from_env(env)
    assert settings.telegram_proxy_url.get_secret_value() == PROXY
    assert "private-proxy-password" not in repr(settings)
    assert "proxy" not in settings.agent.model_dump()
    assert "telegram_proxy_url" not in settings.agent.model_dump()
    assert dict(os.environ) == before


@pytest.mark.parametrize("kind", ["missing", "empty", "public", "symlink"])
def test_configured_unusable_proxy_secret_fails_closed(tmp_path, kind):
    path = tmp_path / "proxy"
    if kind != "missing":
        secret_file(path, "" if kind == "empty" else PROXY)
    if kind == "public":
        path.chmod(0o644)
    if kind == "symlink":
        path.rename(tmp_path / "real-proxy")
        path.symlink_to(tmp_path / "real-proxy")
    with pytest.raises(ValueError) as caught:
        StandaloneSettings.from_env(dict(env_for(tmp_path), LC_TELEGRAM_PROXY_URL_FILE=str(path)))
    assert "private-proxy-password" not in str(caught.value)


def test_invalid_proxy_url_error_does_not_expose_credentials(tmp_path):
    with pytest.raises(ValueError) as caught:
        StandaloneSettings.from_env(dict(env_for(tmp_path), LC_TELEGRAM_PROXY_URL=PROXY + "/wrong"))
    assert "private-proxy-password" not in str(caught.value)


def test_collector_reads_the_same_optional_private_proxy_setting(tmp_path, monkeypatch):
    for name, value in {
        "LC_AGENTS_REGISTRY_PATH": str(tmp_path / "agents.json"),
        "LC_DATABASE_PATH": str(tmp_path / "collector.sqlite3"),
        "LC_TELEGRAM_BOT_TOKEN": "123456789:abcdefghijklmnopqrstuvwxyz12345",
        "LC_TELEGRAM_CHAT_ID": "-1234",
        "LC_TELEGRAM_PROXY_URL_FILE": str(secret_file(tmp_path / "proxy", PROXY)),
    }.items():
        monkeypatch.setenv(name, value)
    settings = CollectorSettings.from_env()
    assert settings.telegram_proxy_url.get_secret_value() == PROXY
    assert "private-proxy-password" not in repr(settings)


def native_root(tmp_path):
    from litechecker.direct_check import trial_settings
    env = env_for(tmp_path)
    secret_file(tmp_path / "secrets/telegram_bot_token", env["LC_TELEGRAM_BOT_TOKEN"])
    secret_file(tmp_path / "secrets/subscription_url", env["LC_SUBSCRIPTION_URL"])
    secret_file(tmp_path / "secrets/telegram_proxy_url", PROXY)
    return trial_settings


def test_native_trial_picks_up_bundled_proxy_without_other_configuration(tmp_path):
    load_settings = native_root(tmp_path)
    settings = load_settings(tmp_path, "/path/to/xray", environment={})
    assert settings.telegram_proxy_url.get_secret_value() == PROXY


def test_native_trial_respects_explicit_proxy_override(tmp_path):
    load_settings = native_root(tmp_path)
    settings = load_settings(tmp_path, "/path/to/xray", environment={"LC_TELEGRAM_PROXY_URL": "http://127.0.0.1:8888"})
    assert settings.telegram_proxy_url.get_secret_value() == "http://127.0.0.1:8888"


@pytest.mark.asyncio
async def test_direct_unavailable_notification_still_uses_telegram_proxy(tmp_path, monkeypatch):
    from litechecker import direct_check
    from litechecker.direct_network import DirectNetworkUnavailable

    settings = native_root(tmp_path)(tmp_path, "/path/to/xray", environment={})
    calls = []

    class Sender:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        async def send_chunks(self, chunks):
            assert "не выполнена" in "".join(chunks)

    async def unavailable():
        raise DirectNetworkUnavailable("interface_changed")

    monkeypatch.setattr(direct_check, "TelegramClient", Sender)
    monkeypatch.setattr(direct_check.MacDirectNetwork, "discover", unavailable)
    result = await direct_check.run_trial(settings, send=True)
    assert result.available is False
    assert len(calls) == 1
    assert calls[0].get("proxy_url") == PROXY

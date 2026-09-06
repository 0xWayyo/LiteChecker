"""Shared Telegram options preserve private settings and optional delivery fields."""

import pytest

from litechecker.collector import telegram
from litechecker.config import CollectorSettings


@pytest.mark.parametrize("topic_id, proxy_url", [
    (None, None),
    (17, None),
    (None, "socks5://tester:p%40ss@192.0.2.10:1080"),
    (17, "socks5://tester:p%40ss@192.0.2.10:1080"),
])
def test_client_options_unwrap_secrets_and_preserve_optional_delivery_fields(tmp_path, topic_id, proxy_url):
    # Dropping topic/proxy routing or forwarding masked SecretStr values would
    # send to the wrong destination or break authentication at the client boundary.
    settings = CollectorSettings(
        agents_registry_path=tmp_path / "agents.json",
        database_path=tmp_path / "collector.sqlite3",
        telegram_bot_token="123456789:abcdefghijklmnopqrstuvwxyz12345",
        telegram_chat_id="-1001234567890",
        telegram_topic_id=topic_id,
        telegram_proxy_url=proxy_url,
    )
    before = settings.model_dump()

    options = telegram.telegram_client_options(settings)

    assert options == {
        "token": "123456789:abcdefghijklmnopqrstuvwxyz12345",
        "chat_id": "-1001234567890",
        "topic_id": topic_id,
        "proxy_url": proxy_url,
    }
    assert settings.model_dump() == before

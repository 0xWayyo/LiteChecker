"""Public native configuration schema shared by installation and runtime."""

from __future__ import annotations


NATIVE_CONFIG_KEYS = frozenset(
    {
        "LC_AGENT_CITY",
        "LC_AGENT_NAME",
        "LC_HOST_NAME",
        "LC_HOST_OS",
        "LC_TELEGRAM_CHAT_ID",
        "LC_TELEGRAM_TOPIC_ID",
        "LC_INTERVAL_SECONDS",
        "LC_RUN_DEADLINE_SECONDS",
        "LC_PROBE_TIMEOUT_SECONDS",
        "LC_TCP_TIMEOUT_SECONDS",
        "LC_MAX_CONCURRENCY",
        "LC_MAX_SUBSCRIPTION_BYTES",
        "LC_MAX_ENDPOINTS",
        "LC_AUTO_NETWORK",
        "LC_AUTO_CITY",
        "LC_EXPECTED_XRAY_VERSION",
    }
)

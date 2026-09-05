from pathlib import Path
import multiprocessing
import os

import pytest
from pydantic import ValidationError

from litechecker.config import AgentSettings, CollectorSettings


AGENT_TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


def test_agent_settings_reads_secret_from_file_and_defaults_to_600(tmp_path, monkeypatch):
    """Removing _FILE support would expose Docker deployments to broken auth."""
    secret = tmp_path / "token"
    secret.write_text(AGENT_TOKEN + "\n")
    secret.chmod(0o600)
    monkeypatch.setenv("LC_AGENT_ID", "tbilisi-home")
    monkeypatch.setenv("LC_AGENT_TOKEN_FILE", str(secret))
    monkeypatch.setenv("LC_COLLECTOR_URL", "https://collector.example")
    monkeypatch.setenv("LC_SUBSCRIPTION_URL", "https://subscription.example/private")
    monkeypatch.setenv("LC_STATE_KEY", "state-key-with-at-least-32-characters")

    settings = AgentSettings.from_env()

    assert settings.agent_token.get_secret_value() == AGENT_TOKEN
    assert settings.interval_seconds == 600


def test_collector_pending_backpressure_defaults_cover_operational_report_bursts():
    """Collector defaults must bound outages without rejecting normal ten-minute reports."""
    fields = CollectorSettings.model_fields
    assert fields["max_pending_notifications_per_agent"].default == 100
    assert fields["max_pending_notifications_global"].default == 10_000
    assert fields["max_pending_chunks_per_agent"].default == 1_000
    assert fields["max_pending_chunks_global"].default == 100_000


def test_agent_settings_rejects_weak_collector_token():
    """Configuration must reject a token the collector would never authenticate."""
    with pytest.raises(ValidationError, match="agent_token"):
        AgentSettings(
            agent_id="agent-1",
            agent_token="agent-secret",
            collector_url="https://collector.example",
            subscription_url="https://subscription.example/private",
            state_key="state-key-with-at-least-32-characters",
        )


def test_agent_settings_rejects_missing_required_values(monkeypatch):
    """Removing required-environment validation must not start an anonymous agent."""
    for name in (
        "LC_AGENT_ID",
        "LC_AGENT_TOKEN",
        "LC_AGENT_TOKEN_FILE",
        "LC_COLLECTOR_URL",
        "LC_SUBSCRIPTION_URL",
        "LC_STATE_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValidationError):
        AgentSettings.from_env()


def test_agent_settings_prefers_file_secret_over_direct_environment(tmp_path, monkeypatch):
    """Changing precedence must not accidentally use a stale local development token."""
    token_file = tmp_path / "token"
    token_file.write_text(AGENT_TOKEN + "\n")
    token_file.chmod(0o600)
    monkeypatch.setenv("LC_AGENT_ID", "tbilisi-home")
    monkeypatch.setenv("LC_AGENT_TOKEN", "lc_BQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQ")
    monkeypatch.setenv("LC_AGENT_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("LC_COLLECTOR_URL", "https://collector.example")
    monkeypatch.setenv("LC_SUBSCRIPTION_URL", "https://subscription.example/private")
    monkeypatch.setenv("LC_STATE_KEY", "state-key-with-at-least-32-characters")

    assert AgentSettings.from_env().agent_token.get_secret_value() == AGENT_TOKEN


def test_collector_settings_read_bot_token_from_file_and_use_safe_defaults(tmp_path, monkeypatch):
    """Removing collector secret-file support would break containerized collector startup."""
    token_file = tmp_path / "telegram-token"
    token_file.write_text("123456:telegram-token\n")
    token_file.chmod(0o600)
    monkeypatch.setenv("LC_AGENTS_REGISTRY_PATH", str(tmp_path / "agents.json"))
    monkeypatch.setenv("LC_DATABASE_PATH", str(tmp_path / "litechecker.sqlite3"))
    monkeypatch.setenv("LC_TELEGRAM_BOT_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("LC_TELEGRAM_CHAT_ID", "-1001234567890")

    settings = CollectorSettings.from_env()

    assert settings.telegram_bot_token.get_secret_value() == "123456:telegram-token"
    assert settings.offline_threshold_seconds == 1500
    assert settings.bind_host == "127.0.0.1"
    assert settings.bind_port == 8000
    assert settings.agents_registry_path == Path(tmp_path / "agents.json")


@pytest.mark.parametrize(
    "url",
    (
        "http://localhost:8000",
        "http://127.0.0.2:8000",
        "http://[::1]:8000",
    ),
)
def test_agent_settings_accepts_explicit_http_only_for_loopback(url):
    """The local override should cover actual loopback IPs, not only one spelling."""
    settings = AgentSettings(
        agent_id="agent-1",
        agent_token=AGENT_TOKEN,
        collector_url=url,
        subscription_url="https://subscription.example/private",
        state_key="state-key-with-at-least-32-characters",
        allow_insecure_collector=True,
    )

    assert settings.collector_url == url


@pytest.mark.parametrize(
    "url",
    (
        "http://collector.example:8000",
        "http://localhost.evil:8000",
        "http://127.0.0.1.evil:8000",
        "http://2130706433:8000",
        "http://user@localhost:8000",
    ),
)
def test_agent_settings_rejects_nonloopback_http_and_hostname_tricks(url):
    """Explicit development mode must not turn arbitrary HTTP into a valid collector."""
    with pytest.raises(ValidationError, match="collector_url"):
        AgentSettings(
            agent_id="agent-1",
            agent_token=AGENT_TOKEN,
            collector_url=url,
            subscription_url="https://subscription.example/private",
            state_key="state-key-with-at-least-32-characters",
            allow_insecure_collector=True,
        )


@pytest.mark.parametrize(
    "agent_id",
    (" leading", "trailing ", "two words", "slash/name", "", "x" * 129),
)
def test_agent_id_uses_the_exact_collector_registry_grammar(agent_id):
    """An ID accepted only by the agent can never authenticate at the collector."""
    with pytest.raises(ValidationError, match="agent_id"):
        AgentSettings(
            agent_id=agent_id,
            agent_token=AGENT_TOKEN,
            collector_url="https://collector.example",
            subscription_url="https://subscription.example/private",
            state_key="state-key-with-at-least-32-characters",
        )


def _base_file_environment(monkeypatch, secret_path: Path) -> None:
    monkeypatch.setenv("LC_AGENT_ID", "agent-1")
    monkeypatch.setenv("LC_AGENT_TOKEN_FILE", str(secret_path))
    monkeypatch.setenv("LC_COLLECTOR_URL", "https://collector.example")
    monkeypatch.setenv("LC_SUBSCRIPTION_URL", "https://subscription.example/private")
    monkeypatch.setenv("LC_STATE_KEY", "state-key-with-at-least-32-characters")


def test_secret_file_rejects_symlink_and_world_readable_mode(tmp_path, monkeypatch):
    """Path-following or permissive secret files let another local user replace/read them."""
    target = tmp_path / "real-token"
    target.write_text(AGENT_TOKEN)
    target.chmod(0o600)
    link = tmp_path / "token-link"
    link.symlink_to(target)
    _base_file_environment(monkeypatch, link)
    with pytest.raises(ValueError, match="cannot read LC_AGENT_TOKEN_FILE"):
        AgentSettings.from_env()

    _base_file_environment(monkeypatch, target)
    target.chmod(0o644)
    with pytest.raises(ValueError, match="cannot read LC_AGENT_TOKEN_FILE"):
        AgentSettings.from_env()


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFOs only")
def test_secret_file_fifo_is_rejected_without_blocking_startup(tmp_path, monkeypatch):
    """Opening a hostile FIFO must not hang service startup before type validation."""
    fifo = tmp_path / "token-fifo"
    os.mkfifo(fifo, 0o600)
    _base_file_environment(monkeypatch, fifo)

    context = multiprocessing.get_context("fork")
    outcome = context.Queue()

    def load_settings():
        try:
            AgentSettings.from_env()
        except ValueError as exc:
            outcome.put(str(exc))

    process = context.Process(target=load_settings)
    process.start()
    process.join(timeout=1)
    if process.is_alive():
        process.terminate()
        process.join(timeout=1)
        pytest.fail("secure file open blocked on a FIFO")
    assert "cannot read LC_AGENT_TOKEN_FILE" in outcome.get(timeout=1)

def test_secret_file_rejects_wrong_owner_and_oversize(tmp_path, monkeypatch):
    """Owner and byte bounds must be checked on the same opened descriptor."""
    token = tmp_path / "token"
    token.write_text(AGENT_TOKEN)
    token.chmod(0o600)
    _base_file_environment(monkeypatch, token)
    real_fstat = os.fstat

    def wrong_owner(descriptor):
        values = list(real_fstat(descriptor))
        values[4] = values[4] + 1
        return os.stat_result(values)

    import litechecker.config as config_module

    monkeypatch.setattr(config_module.os, "fstat", wrong_owner)
    with pytest.raises(ValueError, match="cannot read LC_AGENT_TOKEN_FILE"):
        AgentSettings.from_env()

    monkeypatch.setattr(config_module.os, "fstat", real_fstat)
    token.write_bytes(b"x" * 65_537)
    token.chmod(0o600)
    with pytest.raises(ValueError, match="cannot read LC_AGENT_TOKEN_FILE"):
        AgentSettings.from_env()


def test_secret_file_rename_after_open_reads_only_original_descriptor(tmp_path, monkeypatch):
    """A pathname swap after open must not switch the bytes being validated and read."""
    token = tmp_path / "token"
    token.write_text(AGENT_TOKEN)
    token.chmod(0o600)
    replacement = tmp_path / "replacement"
    replacement.write_text("attacker-controlled")
    replacement.chmod(0o600)
    _base_file_environment(monkeypatch, token)
    import litechecker.config as config_module

    real_open = config_module.os.open
    swapped = False

    def open_then_swap(path, flags):
        nonlocal swapped
        descriptor = real_open(path, flags)
        if not swapped:
            swapped = True
            os.replace(replacement, token)
        return descriptor

    monkeypatch.setattr(config_module.os, "open", open_then_swap)
    settings = AgentSettings.from_env()

    assert settings.agent_token.get_secret_value() == AGENT_TOKEN
    assert token.read_text() == "attacker-controlled"

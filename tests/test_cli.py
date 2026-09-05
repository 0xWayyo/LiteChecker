"""Command-line behavior at LiteChecker's process boundary."""

from __future__ import annotations

import asyncio
import signal
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from litechecker.config import AgentSettings, CollectorSettings


VALID_AGENT_TOKEN = "lc_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"


def _agent_settings() -> AgentSettings:
    return AgentSettings(
        agent_id="tbilisi-home",
        agent_token=SecretStr(VALID_AGENT_TOKEN),
        collector_url="https://collector.example",
        subscription_url=SecretStr("https://subscription.example/private"),
        state_key=SecretStr("state-key-with-at-least-32-characters"),
    )


def _collector_settings(tmp_path) -> CollectorSettings:
    return CollectorSettings(
        agents_registry_path=tmp_path / "agents.json",
        database_path=tmp_path / "collector.sqlite3",
        telegram_bot_token=SecretStr("123456:fake-telegram-token"),
        telegram_chat_id="-1000000000000",
        bind_host="0.0.0.0",
        bind_port=8765,
    )


def test_help_exits_zero_and_names_both_commands(capsys):
    from litechecker import cli

    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])

    assert raised.value.code == 0
    output = capsys.readouterr().out
    assert "agent" in output
    assert "collector" in output


def test_help_exposes_direct_telegram_standalone_command(capsys):
    from litechecker import cli

    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])

    assert raised.value.code == 0
    assert "standalone" in capsys.readouterr().out


def test_standalone_once_waits_for_direct_delivery(monkeypatch):
    from litechecker import cli

    settings = object()
    received = []
    monkeypatch.setattr(cli.StandaloneSettings, "from_env", lambda: settings)

    async def run(settings, *, once=False):
        received.append((settings, once))

    monkeypatch.setattr(cli, "run_standalone", run)

    assert cli.main(["standalone", "--once"]) == 0
    assert received == [(settings, True)]


def test_standalone_delivery_failure_is_specific_nonzero_without_secrets(monkeypatch, capsys):
    from litechecker import cli
    from litechecker.standalone import StandaloneDeliveryError

    monkeypatch.setattr(cli.StandaloneSettings, "from_env", lambda: object())

    async def unavailable(*args, **kwargs):
        raise StandaloneDeliveryError()

    monkeypatch.setattr(cli, "run_standalone", unavailable)

    assert cli.main(["standalone", "--once"]) == 1
    assert "telegram-report-not-delivered" in capsys.readouterr().err


def test_standalone_duplicate_process_reports_clear_error(monkeypatch, capsys):
    from litechecker import cli
    from litechecker.standalone import StandaloneAlreadyRunning

    monkeypatch.setattr(cli.StandaloneSettings, "from_env", lambda: object())

    async def locked(*args, **kwargs):
        raise StandaloneAlreadyRunning()

    monkeypatch.setattr(cli, "run_standalone", locked)

    assert cli.main(["standalone"]) == 1
    assert "standalone-already-running" in capsys.readouterr().err


@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt])
def test_standalone_once_interruption_does_not_report_success(monkeypatch, interruption):
    from litechecker import cli

    monkeypatch.setattr(cli.StandaloneSettings, "from_env", lambda: object())

    async def interrupted(*args, **kwargs):
        raise interruption()

    monkeypatch.setattr(cli, "run_standalone", interrupted)

    assert cli.main(["standalone", "--once"]) == 130
    assert cli.main(["standalone"]) == 0


def test_standalone_health_requires_telegram_ack_and_ignores_collector_ack(
    tmp_path, monkeypatch, capsys
):
    from litechecker import cli
    from litechecker.state import CollectorAckStore

    monkeypatch.setenv("LC_STATE_DIR", str(tmp_path))
    CollectorAckStore(tmp_path / "collector-ack.json").record(
        "device:boot:0", datetime.now(UTC)
    )
    assert cli.main(["standalone-health"]) == 1
    assert "telegram-ack-stale" in capsys.readouterr().err

    CollectorAckStore(tmp_path / "telegram-ack.json").record(
        "device:boot:0", datetime.now(UTC)
    )
    assert cli.main(["standalone-health"]) == 0


def test_standalone_health_respects_ack_maximum_age(tmp_path, monkeypatch, capsys):
    from litechecker import cli
    from litechecker.state import CollectorAckStore

    monkeypatch.setenv("LC_STATE_DIR", str(tmp_path))
    CollectorAckStore(tmp_path / "telegram-ack.json").record(
        "device:boot:0", datetime.now(UTC) - timedelta(seconds=1501)
    )
    assert cli.main(["standalone-health"]) == 1
    monkeypatch.setenv("LC_AGENT_HEALTH_MAX_AGE_SECONDS", "1800")
    assert cli.main(["standalone-health"]) == 0
    monkeypatch.setenv("LC_AGENT_HEALTH_MAX_AGE_SECONDS", "0")
    assert cli.main(["standalone-health"]) == 2


def test_invalid_environment_returns_configuration_exit_code(monkeypatch, capsys):
    from litechecker import cli

    monkeypatch.delenv("LC_AGENT_ID", raising=False)
    monkeypatch.delenv("LC_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("LC_AGENT_TOKEN_FILE", raising=False)
    monkeypatch.delenv("LC_COLLECTOR_URL", raising=False)
    monkeypatch.delenv("LC_SUBSCRIPTION_URL", raising=False)
    monkeypatch.delenv("LC_SUBSCRIPTION_URL_FILE", raising=False)
    monkeypatch.delenv("LC_STATE_KEY", raising=False)
    monkeypatch.delenv("LC_STATE_KEY_FILE", raising=False)

    assert cli.main(["agent", "--once"]) == 2
    assert "configuration-error" in capsys.readouterr().err


def test_agent_once_passes_literal_once_to_runner(monkeypatch):
    from litechecker import cli

    settings = _agent_settings()
    received: list[tuple[AgentSettings, bool]] = []

    monkeypatch.setattr(cli.AgentSettings, "from_env", lambda: settings)

    async def fake_run_agent(actual_settings, once=False):
        received.append((actual_settings, once))

    monkeypatch.setattr(cli, "run_agent", fake_run_agent)

    assert cli.main(["agent", "--once"]) == 0
    assert received == [(settings, True)]


def test_collector_uses_configured_bind_address(monkeypatch, tmp_path):
    from litechecker import cli

    settings = _collector_settings(tmp_path)
    app = object()
    observed: dict[str, object] = {}

    monkeypatch.setattr(cli.CollectorSettings, "from_env", lambda: settings)
    monkeypatch.setattr(cli, "create_app", lambda actual: app if actual is settings else None)

    class FakeConfig:
        def __init__(self, actual_app, **kwargs):
            observed["app"] = actual_app
            observed.update(kwargs)

    class FakeServer:
        started = True

        def __init__(self, config):
            observed["config"] = config

        async def serve(self):
            observed["served"] = True

    monkeypatch.setattr(cli.uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(cli.uvicorn, "Server", FakeServer)

    assert cli.main(["collector"]) == 0
    assert observed["app"] is app
    assert observed["host"] == "0.0.0.0"
    assert observed["port"] == 8765
    assert observed["access_log"] is False
    assert observed["served"] is True


def test_cancellation_is_a_clean_shutdown(monkeypatch):
    from litechecker import cli

    monkeypatch.setattr(cli.AgentSettings, "from_env", _agent_settings)

    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(cli, "run_agent", cancelled)

    assert cli.main(["agent"]) == 0


def test_fatal_error_returns_one_without_rendering_sensitive_exception(monkeypatch, capsys):
    from litechecker import cli

    secret = VALID_AGENT_TOKEN
    monkeypatch.setattr(cli.AgentSettings, "from_env", _agent_settings)

    async def failed(*args, **kwargs):
        raise RuntimeError(
            f"https://user:pass@example/private?token=bad {secret} "
            "outbound={'address': '198.51.100.25', 'password': 'private'}"
        )

    monkeypatch.setattr(cli, "run_agent", failed)

    assert cli.main(["agent", "--once"]) == 1
    stderr = capsys.readouterr().err
    assert "fatal-runtime-error" in stderr
    assert "https://" not in stderr
    assert secret not in stderr
    assert "198.51.100.25" not in stderr
    assert "private" not in stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal required")
def test_sigterm_cancels_the_running_command_cleanly():
    script = """
import asyncio
from litechecker.cli import _run_with_signals

async def command():
    print("ready", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        print("stopped", flush=True)

try:
    asyncio.run(_run_with_signals(command()))
except asyncio.CancelledError:
    pass
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "ready"
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0
    assert stdout.strip() == "stopped"
    assert stderr == ""


def test_agent_health_checks_recent_collector_ack_without_loading_secrets(
    tmp_path, monkeypatch
):
    """Container health must fail when delivery ACKs are stale even if a snapshot exists."""
    from litechecker import cli
    from litechecker.state import CollectorAckStore

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    CollectorAckStore(state_dir / "collector-ack.json").record(
        "agent-1:boot-1:1", datetime.now(UTC)
    )
    monkeypatch.setenv("LC_STATE_DIR", str(state_dir))
    for name in ("LC_AGENT_TOKEN", "LC_AGENT_TOKEN_FILE", "LC_SUBSCRIPTION_URL"):
        monkeypatch.delenv(name, raising=False)

    assert cli.main(["agent-health"]) == 0


def test_collector_nonzero_system_exit_becomes_sanitized_fatal_exit(
    monkeypatch, tmp_path, capsys
):
    """Uvicorn uses SystemExit for bind failures, which must not escape the CLI."""
    from litechecker import cli

    monkeypatch.setattr(
        cli.CollectorSettings, "from_env", lambda: _collector_settings(tmp_path)
    )
    monkeypatch.setattr(cli, "create_app", lambda settings: object())
    monkeypatch.setattr(cli.uvicorn, "Config", lambda *args, **kwargs: object())

    class FailedServer:
        started = False

        def __init__(self, config):
            pass

        async def serve(self):
            raise SystemExit(3)

    monkeypatch.setattr(cli.uvicorn, "Server", FailedServer)

    assert cli.main(["collector"]) == 1
    stderr = capsys.readouterr().err
    assert "fatal-runtime-error" in stderr
    assert "SystemExit" not in stderr


def test_collector_lifespan_failure_without_system_exit_is_fatal(
    monkeypatch, tmp_path, capsys
):
    """Uvicorn can return normally with started false after lifespan startup fails."""
    from litechecker import cli

    monkeypatch.setattr(
        cli.CollectorSettings, "from_env", lambda: _collector_settings(tmp_path)
    )
    monkeypatch.setattr(cli, "create_app", lambda settings: object())
    monkeypatch.setattr(cli.uvicorn, "Config", lambda *args, **kwargs: object())

    class FailedLifespanServer:
        started = False

        def __init__(self, config):
            pass

        async def serve(self):
            return None

    monkeypatch.setattr(cli.uvicorn, "Server", FailedLifespanServer)

    assert cli.main(["collector"]) == 1
    assert "fatal-runtime-error" in capsys.readouterr().err


def test_collector_zero_system_exit_is_clean(monkeypatch, tmp_path):
    """A zero-valued server exit remains an intentional clean shutdown."""
    from litechecker import cli

    monkeypatch.setattr(
        cli.CollectorSettings, "from_env", lambda: _collector_settings(tmp_path)
    )
    monkeypatch.setattr(cli, "create_app", lambda settings: object())
    monkeypatch.setattr(cli.uvicorn, "Config", lambda *args, **kwargs: object())

    class CleanServer:
        started = False

        def __init__(self, config):
            pass

        async def serve(self):
            raise SystemExit(0)

    monkeypatch.setattr(cli.uvicorn, "Server", CleanServer)

    assert cli.main(["collector"]) == 0

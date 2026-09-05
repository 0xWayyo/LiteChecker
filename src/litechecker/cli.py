"""Process entry point for LiteChecker agents and collectors."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from pydantic import ValidationError

from litechecker.agent import run_agent
from litechecker.collector.app import create_app
from litechecker.config import AgentSettings, CollectorSettings, StandaloneSettings
from litechecker.runtime import run_with_signals as _run_with_signals
from litechecker.security import redact
from litechecker.state import CollectorAckStore
from litechecker.standalone import (
    StandaloneAlreadyRunning,
    StandaloneDeliveryError,
    run_standalone,
)


_LOGGER = logging.getLogger("litechecker.cli")


class AgentUnhealthy(RuntimeError):
    pass


class StandaloneUnhealthy(RuntimeError):
    pass


class _SanitizedJsonFormatter(logging.Formatter):
    """Render a closed, single-line event without exception payloads."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname.lower(),
                "event": redact(record.getMessage()),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_SanitizedJsonFormatter())
    _LOGGER.handlers.clear()
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(logging.INFO)
    _LOGGER.propagate = False
    standalone_logger = logging.getLogger("litechecker.standalone")
    standalone_logger.handlers.clear()
    standalone_logger.addHandler(handler)
    standalone_logger.setLevel(logging.INFO)
    standalone_logger.propagate = False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="litechecker",
        description="Multi-city VLESS/REALITY availability monitor",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    standalone = commands.add_parser(
        "standalone", help="probe locally and send reports directly to Telegram"
    )
    standalone.add_argument(
        "--once", action="store_true", help="run once and require Telegram delivery"
    )
    commands.add_parser(
        "standalone-health", help="check for a recent successful Telegram delivery"
    )
    agent = commands.add_parser("agent", help="run a city probe agent")
    agent.add_argument(
        "--once",
        action="store_true",
        help="run one probe cycle and exit",
    )
    commands.add_parser("collector", help="run the central collector")
    commands.add_parser(
        "agent-health",
        help="check for a recent successful collector acceptance",
    )
    return parser


async def _run_command(arguments: argparse.Namespace) -> None:
    if arguments.command == "standalone":
        settings = StandaloneSettings.from_env()
        await run_standalone(settings, once=arguments.once)
        return

    if arguments.command == "agent":
        settings = AgentSettings.from_env()
        await run_agent(settings, once=arguments.once)
        return

    if arguments.command in {"agent-health", "standalone-health"}:
        state_dir = Path(os.environ.get("LC_STATE_DIR", "/var/lib/litechecker"))
        max_age = int(os.environ.get("LC_AGENT_HEALTH_MAX_AGE_SECONDS", "1500"))
        if max_age < 1:
            raise ValueError("agent health age is invalid")
        direct = arguments.command == "standalone-health"
        ack_file = "telegram-ack.json" if direct else "collector-ack.json"
        if not CollectorAckStore(state_dir / ack_file).is_recent(
            datetime.now(UTC), max_age_seconds=max_age
        ):
            if direct:
                raise StandaloneUnhealthy("telegram-ack-stale")
            raise AgentUnhealthy("collector-ack-stale")
        return

    settings = CollectorSettings.from_env()
    app = create_app(settings)
    config = uvicorn.Config(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        log_config=None,
        access_log=False,
    )
    server = uvicorn.Server(config)
    try:
        await server.serve()
    except SystemExit as exc:
        if exc.code in (None, 0):
            return
        raise RuntimeError("collector-startup-failed") from None
    if not server.started:
        raise RuntimeError("collector-startup-failed")


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI command and return its literal process exit code."""
    arguments = _parser().parse_args(argv)
    _configure_logging()
    try:
        asyncio.run(_run_with_signals(_run_command(arguments)))
    except (ValidationError, ValueError):
        _LOGGER.error("configuration-error")
        return 2
    except (asyncio.CancelledError, KeyboardInterrupt):
        _LOGGER.info("shutdown")
        if arguments.command == "standalone" and arguments.once:
            return 130
        return 0
    except AgentUnhealthy:
        _LOGGER.error("agent-unhealthy")
        return 1
    except StandaloneUnhealthy:
        _LOGGER.error("telegram-ack-stale")
        return 1
    except StandaloneAlreadyRunning:
        _LOGGER.error("standalone-already-running")
        return 1
    except StandaloneDeliveryError:
        _LOGGER.error("telegram-report-not-delivered")
        return 1
    except Exception:
        _LOGGER.error("fatal-runtime-error")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Native macOS DIRECT daemon with durable, route-independent Telegram delivery."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from filelock import AsyncFileLock, Timeout as FileLockTimeout

from litechecker.collector.reporting import chunk_message
from litechecker.collector.telegram import TelegramClient
from litechecker.config import StandaloneSettings, _read_secure_text
from litechecker.direct_check import TrialResult, run_trial
from litechecker.direct_outbox import DirectOutbox, DirectOutboxError
from litechecker.direct_reporting import format_unavailable
from litechecker.maintenance import cycle_maintenance
from litechecker.runtime import run_with_signals
from litechecker.state import _atomic_write_json


_INTERVAL_SECONDS = 600
_NATIVE_CONFIG_KEYS = frozenset(
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


class ServiceAlreadyRunning(RuntimeError):
    def __init__(self) -> None:
        super().__init__("service-lock-unavailable")


def service_settings(
    root: Path,
    xray: str | os.PathLike[str],
    *,
    environment: Mapping[str, str] | None = None,
) -> StandaloneSettings:
    """Load strict canonical data and force all private/runtime paths locally."""
    del environment  # Ambient LC_* variables are not canonical native configuration.
    root = Path(root)
    xray_path = Path(xray)
    _validate_root(root)
    _validate_xray(xray_path)
    try:
        raw = json.loads(_read_secure_text(root / "native-settings.json"))
        if not isinstance(raw, dict) or not set(raw).issubset(_NATIVE_CONFIG_KEYS):
            raise ValueError
        env = {key: _config_value(value) for key, value in raw.items()}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("native configuration is invalid") from None

    state_dir = root / "state" / "native-direct"
    env.update(
        LC_STATE_DIR=str(state_dir),
        LC_XRAY_BINARY=str(xray_path),
        LC_INTERVAL_SECONDS=str(_INTERVAL_SECONDS),
        LC_ALLOW_PRIVATE_TARGETS="false",
        LC_TELEGRAM_BOT_TOKEN_FILE=str(root / "secrets" / "telegram_bot_token"),
        LC_SUBSCRIPTION_URL_FILE=str(root / "secrets" / "subscription_url"),
    )
    proxy_file = root / "secrets" / "telegram_proxy_url"
    if proxy_file.exists() or proxy_file.is_symlink():
        env["LC_TELEGRAM_PROXY_URL_FILE"] = str(proxy_file)
    try:
        return StandaloneSettings.from_env(env)
    except Exception:
        raise ValueError("native configuration is invalid") from None


def telegram_client(settings: StandaloneSettings) -> TelegramClient:
    """Build the reporting client; its optional proxy never enters measurement deps."""
    return TelegramClient(
        token=settings.telegram_bot_token.get_secret_value(),
        chat_id=settings.telegram_chat_id,
        topic_id=settings.telegram_topic_id,
        proxy_url=(
            settings.telegram_proxy_url.get_secret_value()
            if settings.telegram_proxy_url is not None
            else None
        ),
    )


async def run_service(
    settings: StandaloneSettings,
    *,
    once: bool = False,
    send: bool = True,
    cycle: Callable[[StandaloneSettings], Awaitable[TrialResult]] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], datetime] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    telegram_factory: Callable[[StandaloneSettings], Any] = telegram_client,
    max_cycles: int | None = None,
) -> TrialResult:
    """Run immediately and then at non-overlapping 600-second start cadence."""
    if max_cycles is not None and (
        isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or max_cycles < 1
    ):
        raise ValueError("max_cycles must be positive")
    wall_clock = wall_clock or (lambda: datetime.now(UTC))
    cycle = cycle or _production_cycle
    state_dir = settings.state_dir
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = AsyncFileLock(
        state_dir / "service.lock",
        timeout=0,
        mode=0o600,
        preserve_lock_file=True,
        run_in_executor=True,
    )
    try:
        async with lock:
            return await _run_locked(
                settings,
                once=once,
                send=send,
                cycle=cycle,
                monotonic=monotonic,
                wall_clock=wall_clock,
                sleep=sleep,
                telegram_factory=telegram_factory,
                max_cycles=max_cycles,
            )
    except FileLockTimeout:
        raise ServiceAlreadyRunning() from None


async def _production_cycle(settings: StandaloneSettings) -> TrialResult:
    return await run_trial(settings, production=True)


async def _run_locked(
    settings: StandaloneSettings,
    *,
    once: bool,
    send: bool,
    cycle: Callable[[StandaloneSettings], Awaitable[TrialResult]],
    monotonic: Callable[[], float],
    wall_clock: Callable[[], datetime],
    sleep: Callable[[float], Awaitable[None]],
    telegram_factory: Callable[[StandaloneSettings], Any],
    max_cycles: int | None,
) -> TrialResult:
    outbox = DirectOutbox(settings.state_dir / "direct-outbox.json")
    status = _initial_status(settings, wall_clock(), outbox)
    _write_status(settings.state_dir, status)
    delivery_failed = False
    if send and outbox.next_chunk() is not None:
        delivery_failed = not await _drain(outbox, settings, telegram_factory, wall_clock)
        _update_telegram_status(status, outbox, delivery_failed)
        _write_status(settings.state_dir, status)

    completed = 0
    result = TrialResult(
        format_unavailable(settings.identity, "cycle-failed", _utc(wall_clock())),
        False,
        reason="cycle-failed",
        observed_at=_utc(wall_clock()),
    )
    while True:
        async with cycle_maintenance(settings.state_dir):
            result, started_mono, delivery_failed = await _measured_cycle(
                settings, status, outbox, send, cycle, monotonic, wall_clock,
                telegram_factory, delivery_failed,
            )

        completed += 1
        if once or (max_cycles is not None and completed >= max_cycles):
            return result
        next_start = started_mono + _INTERVAL_SECONDS
        while True:
            remaining = next_start - monotonic()
            if remaining <= 0:
                break
            has_backlog = send and outbox.status()["pending_chunks"] > 0
            before_wait = monotonic()
            await sleep(min(30.0, remaining) if has_backlog else remaining)
            if monotonic() <= before_wait:
                # Deterministic test clocks must advance with their injected sleep.
                # Never spin if a custom boundary returns without doing so.
                break
            remaining = next_start - monotonic()
            if has_backlog and remaining > 0:
                delivery_failed = not await _drain(
                    outbox,
                    settings,
                    telegram_factory,
                    wall_clock,
                    timeout_seconds=min(30.0, remaining),
                )
                _update_telegram_status(status, outbox, delivery_failed)
                _write_status(settings.state_dir, status)


async def _measured_cycle(
    settings, status, outbox, send, cycle, monotonic, wall_clock,
    telegram_factory, delivery_failed,
):
    started_mono = monotonic()
    started_at = _utc(wall_clock())
    status.update(
        cycle_started_at=started_at.isoformat(),
        cycle_finished_at=None,
        next_cycle_at=(started_at + timedelta(seconds=_INTERVAL_SECONDS)).isoformat(),
        last_observation_fresh=False,
    )
    _write_status(settings.state_dir, status)
    try:
        async with asyncio.timeout(settings.agent.run_deadline_seconds + 60):
            result = await cycle(settings)
        if not isinstance(result, TrialResult):
            raise TypeError
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        observed_at = _utc(wall_clock())
        result = TrialResult(
            format_unavailable(settings.identity, "cycle-timeout", observed_at),
            False,
            reason="cycle-timeout",
            observed_at=observed_at,
        )
    except Exception:
        observed_at = _utc(wall_clock())
        result = TrialResult(
            format_unavailable(settings.identity, "cycle-failed", observed_at),
            False,
            reason="cycle-failed",
            observed_at=observed_at,
        )

    cycle_state = _cycle_state(result)
    status.update(
        cycle_finished_at=_utc(wall_clock()).isoformat(),
        last_cycle_status=cycle_state,
        last_cycle_error=result.reason if cycle_state in {"failed", "unavailable"} else None,
        last_observation_fresh=cycle_state == "complete",
    )
    if send:
        current_accepted = False
        try:
            before_dropped = outbox.status()["dropped_messages"]
            current_message_id = outbox.enqueue(
                chunk_message(result.text),
                created_at=result.observed_at or _utc(wall_clock()),
            )
            overflowed = outbox.status()["dropped_messages"] > before_dropped
        except DirectOutboxError:
            delivery_failed = True
            overflowed = False
            status["telegram"]["last_error"] = "state-write-failed"
        else:
            if not delivery_failed:
                delivery_failed = not await _drain(
                    outbox, settings, telegram_factory, wall_clock,
                    current_message_id=current_message_id,
                )
            _update_telegram_status(status, outbox, delivery_failed)
            if overflowed:
                status["telegram"]["last_error"] = "outbox-overflow"
            current_accepted = (
                not overflowed and outbox.status()["pending_chunks"] == 0
            )
        result = replace(result, delivery_accepted=current_accepted)
    else:
        _update_telegram_status(status, outbox, False)
        result = replace(result, delivery_accepted=None)
    _write_status(settings.state_dir, status)

    return result, started_mono, delivery_failed


async def _drain(
    outbox: DirectOutbox,
    settings: StandaloneSettings,
    telegram_factory: Callable[[StandaloneSettings], Any],
    wall_clock: Callable[[], datetime],
    *,
    timeout_seconds: float = 30.0,
    current_message_id: str | None = None,
) -> bool:
    try:
        client = telegram_factory(settings)
        sent = 0
        async with asyncio.timeout(timeout_seconds):
            while sent < 8 and (pending := outbox.next_chunk()) is not None:
                if pending.message_id == current_message_id:
                    chunks = [pending.text]
                else:
                    prefix = "🕓 Отложенная доставка — отчёт сформирован ранее.\n\n"
                    chunks = [
                        prefix + part
                        for part in chunk_message(pending.text, limit=3500 - len(prefix))
                    ]
                await client.send_chunks(chunks)
                outbox.acknowledge(pending, accepted_at=_utc(wall_clock()))
                sent += 1
        return True
    except asyncio.CancelledError:
        raise
    except Exception:
        return False


def _cycle_state(result: TrialResult) -> str:
    if result.available:
        return "complete"
    if result.report is not None:
        return "incomplete"
    if result.reason in {"cycle-failed", "cycle-timeout"}:
        return "failed"
    return "unavailable"


def _initial_status(
    settings: StandaloneSettings,
    started_at: datetime,
    outbox: DirectOutbox,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "agent_id": settings.identity.agent_id,
        "service_started_at": _utc(started_at).isoformat(),
        "cycle_started_at": None,
        "cycle_finished_at": None,
        "next_cycle_at": None,
        "last_cycle_status": None,
        "last_cycle_error": None,
        "last_observation_fresh": False,
        "telegram": {**outbox.status(), "last_error": None},
    }


def _update_telegram_status(
    status: dict[str, Any], outbox: DirectOutbox, failed: bool,
) -> None:
    prior_error = status["telegram"].get("last_error")
    status["telegram"] = {
        **outbox.status(),
        "last_error": "telegram-delivery-failed" if failed else (
            "outbox-overflow" if prior_error == "outbox-overflow" else None
        ),
    }


def _write_status(state_dir: Path, status: dict[str, Any]) -> None:
    try:
        _atomic_write_json(state_dir / "status.json", status)
    except Exception:
        raise RuntimeError("state-write-failed") from None


def _validate_root(root: Path) -> None:
    try:
        metadata = root.lstat()
    except OSError:
        raise ValueError("native root is invalid") from None
    if not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("native root is invalid")


def _validate_xray(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError("native Xray is invalid") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o100
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        raise ValueError("native Xray is invalid")


def _config_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str) and "\x00" not in value:
        return value
    raise ValueError


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("service clock is invalid")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Native macOS DIRECT LiteChecker service")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args(argv)

    async def execute() -> int:
        settings = service_settings(args.root, args.xray)
        result = await run_service(settings, once=args.once, send=not args.no_send)
        if args.once and (
            not result.available
            or (not args.no_send and result.delivery_accepted is not True)
        ):
            return 1
        return 0

    try:
        return asyncio.run(run_with_signals(execute()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("DIRECT service stopped.")
        return 130
    except ServiceAlreadyRunning:
        print("DIRECT service is already running.")
        return 1
    except Exception:
        print("DIRECT service could not start; inspect state/native-direct/status.json.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

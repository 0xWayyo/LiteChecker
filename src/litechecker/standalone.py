"""Run the existing probe pipeline with a durable, direct Telegram outbox."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import replace

from filelock import AsyncFileLock, Timeout as FileLockTimeout

from litechecker.agent import (
    AgentDependencies,
    CurrentReportNotAccepted,
    _default_dependencies,
    run_agent,
)
from litechecker.collector.db import CollectorDB
from litechecker.collector.telegram import NotificationDispatcher, TelegramClient
from litechecker.config import StandaloneSettings
from litechecker.models import AgentReport
from litechecker.maintenance import cycle_maintenance
from litechecker.network_identity import (
    NetworkIdentity,
    lookup_network_identity,
    network_display_city,
    network_display_name,
)
from litechecker.state import CollectorAckStore


_LOGGER = logging.getLogger(__name__)
_RETRY_SECONDS = 60.0


class StandaloneAlreadyRunning(RuntimeError):
    def __init__(self) -> None:
        super().__init__("standalone-already-running")


class StandaloneDeliveryError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("telegram-report-not-delivered")


class _DirectReportSender:
    """Queue atomically; one-shot success additionally requires Telegram acceptance."""

    def __init__(self, settings, dependencies, db, dispatcher, *, once):
        self._base_identity = settings.identity
        self._identity = settings.identity
        self._clock = dependencies.wall_clock
        self._db = db
        self._dispatcher = dispatcher
        self._once = once
        self._ack = CollectorAckStore(settings.state_dir / "telegram-ack.json")
        self._latest_event_id: str | None = None
        self._last_acked_event_id: str | None = None

    def set_network_identity(
        self, identity: NetworkIdentity | None, *, auto_network: bool, auto_city: bool,
    ) -> None:
        provider = identity.provider if identity else None
        self._identity = replace(
            self._base_identity,
            name=(
                network_display_name(self._base_identity.name, provider)
                if auto_network else self._base_identity.name
            ),
            city=(
                network_display_city(self._base_identity.city, identity)
                if auto_city else self._base_identity.city
            ),
        )

    async def send(self, report: AgentReport) -> None:
        try:
            await asyncio.to_thread(
                self._db.accept_report,
                report,
                self._identity,
                received_at=self._clock(),
            )
        except Exception:
            _LOGGER.error("standalone-outbox-store-failed")
            raise
        self._latest_event_id = report.event_id
        await self.flush()
        if self._once and not await asyncio.to_thread(
            self._db.notification_delivered, report.event_id
        ):
            raise StandaloneDeliveryError()

    async def flush(self) -> None:
        try:
            await self._dispatcher.drain()
            if (
                self._latest_event_id is not None
                and self._latest_event_id != self._last_acked_event_id
                and await asyncio.to_thread(
                    self._db.notification_delivered, self._latest_event_id
                )
            ):
                self._ack.record(self._latest_event_id, self._clock())
                self._last_acked_event_id = self._latest_event_id
                _LOGGER.info("telegram-report-delivered")
            if await asyncio.to_thread(self._db.dead_letter_count):
                _LOGGER.error("telegram-delivery-blocked-check-bot-chat-and-restart")
            elif await asyncio.to_thread(self._db.pending_notification_count):
                _LOGGER.warning("telegram-report-queued-for-retry")
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.error("standalone-outbox-drain-failed")


async def run_standalone(
    settings: StandaloneSettings,
    once: bool = False,
    *,
    dependencies: AgentDependencies | None = None,
    telegram: TelegramClient | None = None,
    network_lookup: Callable[[], Awaitable[NetworkIdentity | None]] | None = None,
    max_cycles: int | None = None,
) -> AgentReport:
    """Probe immediately, then every full interval, retrying Telegram in between.

    SQLite owns queued reports across restarts. No HTTP server or offline watchdog
    is started, and completed report objects are not accumulated in memory.
    """
    if max_cycles is not None and (
        isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or max_cycles < 1
    ):
        raise ValueError("max_cycles must be positive")
    settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = AsyncFileLock(
        settings.state_dir / "standalone.lock",
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
                dependencies=dependencies,
                telegram=telegram,
                network_lookup=network_lookup,
                max_cycles=max_cycles,
            )
    except FileLockTimeout:
        raise StandaloneAlreadyRunning() from None


async def _run_locked(settings, *, once, dependencies, telegram, network_lookup, max_cycles):
    dependencies = dependencies or _default_dependencies(
        settings.agent, state_dir=settings.state_dir
    )
    db = CollectorDB(
        settings.state_dir / "standalone.sqlite3",
        [settings.identity],
        registry_activated_at=dependencies.wall_clock(),
    )
    telegram = telegram or TelegramClient(
        token=settings.telegram_bot_token.get_secret_value(),
        chat_id=settings.telegram_chat_id,
        topic_id=settings.telegram_topic_id,
        proxy_url=settings.telegram_proxy_url.get_secret_value() if settings.telegram_proxy_url else None,
    )
    dispatcher = NotificationDispatcher(
        db,
        telegram,
        clock=dependencies.wall_clock,
        max_delivery_attempts=100,
        retry_delay_seconds=_RETRY_SECONDS,
    )
    sender = _DirectReportSender(settings, dependencies, db, dispatcher, once=once)
    # Agent acceptance here means durable local storage. Only the Telegram sender
    # may write the health acknowledgement after all chunks are accepted.
    dependencies = replace(dependencies, sender=sender, ack_store=None)
    await asyncio.to_thread(db.retry_dead_letters, dependencies.wall_clock())
    await sender.flush()
    completed = 0
    auto_network = getattr(settings, "auto_network", False)
    auto_city = getattr(settings, "auto_city", False)
    while True:
        async with cycle_maintenance(settings.state_dir):
            if auto_network or auto_city:
                try:
                    identity = await (network_lookup or lookup_network_identity)()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    identity = None
                sender.set_network_identity(
                    identity, auto_network=auto_network, auto_city=auto_city,
                )
            try:
                result = await run_agent(
                    settings.agent, once=once, dependencies=dependencies, max_cycles=1
                )
            except CurrentReportNotAccepted:
                raise StandaloneDeliveryError() from None
        report = result if isinstance(result, AgentReport) else result[0]
        completed += 1
        if dependencies.last_accepted_event_id != report.event_id:
            _LOGGER.error("standalone-report-retained-for-retry")
        if once or (max_cycles is not None and completed >= max_cycles):
            return report

        next_start = dependencies.monotonic() + settings.agent.interval_seconds
        while True:
            remaining = next_start - dependencies.monotonic()
            if remaining <= 0:
                break
            await dependencies.sleep(min(_RETRY_SECONDS, remaining))
            await sender.flush()

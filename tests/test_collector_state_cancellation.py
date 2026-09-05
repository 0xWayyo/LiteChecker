"""Dispatcher cancellation cannot outlive the guards protecting SQLite writes."""

import asyncio
import sqlite3
import threading
from datetime import UTC, datetime

import pytest
from filelock import FileLock, Timeout

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.db import CollectorDB
from litechecker.collector.telegram import NotificationDispatcher, TelegramTransientError
from litechecker.maintenance import cycle_maintenance
from litechecker.models import AgentReport, ResultStatus


NOW = datetime(2026, 9, 4, 12, tzinfo=UTC)


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", [
    "reset_notification_leases", "claim_notification",
    "acknowledge_chunk", "record_notification_failure",
])
async def test_cancelled_dispatch_joins_sqlite_transition_before_guards_release(
    tmp_path, monkeypatch, transition,
):
    identity = AgentIdentity("agent-1", "Tbilisi", "Test device", 600)
    db = CollectorDB(tmp_path / "collector.sqlite3", [identity])
    report = AgentReport(
        event_id="agent-1:boot-1:0", agent_id="agent-1", boot_id="boot-1",
        sequence=0, observed_at=NOW, control_status=ResultStatus.UP, duration_ms=1,
    )
    db.accept_report(report, identity, received_at=NOW)
    if transition == "reset_notification_leases":
        assert db.claim_notification("old-owner", NOW, lease_seconds=180) is not None

    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original = getattr(db, transition)

    def slow_transition(*args, **kwargs):
        entered.set()
        try:
            assert release.wait(5), "test did not release the SQLite transition"
            return original(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(db, transition, slow_transition)
    sent = []

    class Sender:
        async def send_chunks(self, chunks):
            sent.extend(chunks)
            if transition == "record_notification_failure":
                raise TelegramTransientError("telegram-network")

    dispatcher = NotificationDispatcher(db, Sender(), clock=lambda: NOW, owner="worker")

    async def cycle():
        async with cycle_maintenance(tmp_path):
            await dispatcher.drain()

    task = asyncio.create_task(cycle())
    try:
        async with asyncio.timeout(3):
            while not entered.is_set():
                await asyncio.sleep(0.001)
        task.cancel()
        await asyncio.sleep(0.02)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not finished.is_set()
        assert not task.done(), "cancellation detached a still-running SQLite transition"
        assert dispatcher._lock.locked()
        for path in (tmp_path / "maintenance.lock", db.dispatch_lock_path):
            with pytest.raises(Timeout):
                with FileLock(path, timeout=0, preserve_lock_file=True):
                    pass

        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
        assert not dispatcher._lock.locked()
        for path in (tmp_path / "maintenance.lock", db.dispatch_lock_path):
            with FileLock(path, timeout=0, preserve_lock_file=True):
                pass
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        assert await asyncio.to_thread(finished.wait, 5)

    # Inspect committed state independently: joining must preserve the complete
    # lease, acknowledgement or retry transition, not just delay cancellation.
    with sqlite3.connect(db.path) as connection:
        state = connection.execute(
            "SELECT lease_owner, completed, next_chunk, attempt_count, "
            "last_error_code, next_attempt_us FROM notifications"
        ).fetchone()
    expected = {
        "reset_notification_leases": (None, 0, 0, 0, None, None),
        "claim_notification": ("worker", 0, 0, 0, None, None),
        "acknowledge_chunk": (None, 1, 1, 0, None, None),
        "record_notification_failure": (
            None, 0, 0, 1, "telegram-network", 1788523260000000,
        ),
    }
    assert state == expected[transition]
    assert len(sent) == (1 if transition in {"acknowledge_chunk", "record_notification_failure"} else 0)

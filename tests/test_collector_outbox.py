from __future__ import annotations

import asyncio
import multiprocessing
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.db import CollectorDB
from litechecker.collector.reporting import chunk_message, format_report
from litechecker.collector.telegram import (
    NotificationDispatchError,
    NotificationDispatcher,
    TelegramClient,
    TelegramError,
    TelegramPermanentError,
    TelegramTransientError,
)
from filelock import FileLock
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
AGENT = AgentIdentity("agent-1", "Tbilisi", "Home ISP", 600)


def _report(sequence: int, *, rows: int = 0) -> AgentReport:
    boot_id = "boot-1"
    results = [
        ProbeResult(
            target_id=f"target-{index:03d}",
            label="Длинная метка " + "я" * 240,
            address=f"node-{index}.example",
            port=443,
            status=ResultStatus.DOWN,
            stage=ProbeStage.TCP,
            error_code="connect-timeout",
        )
        for index in range(rows)
    ]
    return AgentReport(
        event_id=f"agent-1:{boot_id}:{sequence}",
        agent_id="agent-1",
        boot_id=boot_id,
        sequence=sequence,
        observed_at=NOW,
        subscription_revision="a" * 64,
        results=results,
        control_status=ResultStatus.UP,
        duration_ms=1,
    )


class RecordingSender:
    def __init__(self, *, fail_calls=()):
        self.fail_calls = set(fail_calls)
        self.calls: list[str] = []

    async def send_chunks(self, chunks):
        [chunk] = list(chunks)
        self.calls.append(chunk)
        if len(self.calls) in self.fail_calls:
            raise TelegramError("telegram-network")


@pytest.mark.asyncio
async def test_partial_multichunk_delivery_resumes_from_persisted_chunk_after_reopen(tmp_path):
    """A later chunk failure must not resend already acknowledged chunks after restart."""
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [AGENT])
    db.accept_report(_report(1, rows=40), AGENT, received_at=NOW)
    first_sender = RecordingSender(fail_calls={2})

    await NotificationDispatcher(db, first_sender, clock=lambda: NOW).drain()

    notification_id, next_chunk, total_chunks = db.oldest_pending_progress()
    assert next_chunk == 1
    assert total_chunks > 2
    reopened = CollectorDB(path, [AGENT])
    second_sender = RecordingSender()
    await NotificationDispatcher(
        reopened, second_sender, clock=lambda: NOW + timedelta(seconds=60)
    ).drain()

    assert second_sender.calls[0] == first_sender.calls[1]
    assert first_sender.calls[0] not in second_sender.calls
    assert reopened.pending_notification_count() == 0
    assert notification_id > 0


@pytest.mark.asyncio
async def test_crash_after_send_before_ack_is_at_least_once_after_lease_expiry(tmp_path):
    """Crash ambiguity may duplicate one chunk, but it must never lose that chunk."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    crashing = RecordingSender()
    claim = db.claim_notification("crashed-worker", NOW, lease_seconds=5)
    assert claim is not None
    await crashing.send_chunks([claim.body])
    # Process exits here: no ACK and no explicit lease release.

    replay = RecordingSender()
    await NotificationDispatcher(
        CollectorDB(db.path, [AGENT]),
        replay,
        clock=lambda: NOW + timedelta(seconds=6),
        lease_seconds=5,
        send_timeout_seconds=2,
        lease_margin_seconds=1,
    ).drain()

    assert replay.calls == crashing.calls
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_concurrent_dispatchers_normally_send_each_chunk_once_in_order(tmp_path):
    """Database leasing must serialize dispatchers without process-local coordination."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1, rows=40), AGENT, received_at=NOW)
    expected = chunk_message(format_report(_report(1, rows=40), AGENT, received_at=NOW))
    sender = RecordingSender()
    first = NotificationDispatcher(db, sender, clock=lambda: NOW, owner="worker-1")
    second = NotificationDispatcher(
        CollectorDB(db.path, [AGENT]), sender, clock=lambda: NOW, owner="worker-2"
    )

    await asyncio.gather(first.drain(), second.drain())

    assert sender.calls == expected
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_default_dispatch_lease_outlives_bounded_telegram_retry_window(tmp_path):
    """A normal rate-limit wait must not let another process claim the in-flight chunk."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    started = asyncio.Event()
    release = asyncio.Event()

    class BlockingSender:
        async def send_chunks(self, chunks):
            started.set()
            await release.wait()

    task = asyncio.create_task(
        NotificationDispatcher(
            db, BlockingSender(), clock=lambda: NOW, owner="primary-worker"
        ).drain()
    )
    await started.wait()

    competing = db.claim_notification(
        "competing-worker", NOW + timedelta(seconds=31), lease_seconds=30
    )
    release.set()
    await task

    assert competing is None


def test_offline_recovery_and_report_are_enqueued_in_commit_order(tmp_path):
    """A concurrent recovery path must not overtake its durable OFFLINE transition."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    while claim := db.claim_notification("setup", NOW, lease_seconds=30):
        db.acknowledge_chunk(claim, "setup")

    db.offline_transitions(NOW + timedelta(minutes=25))
    recovered = db.accept_report(
        _report(2), AGENT, received_at=NOW + timedelta(minutes=25, seconds=1)
    )

    assert recovered.recovered is True
    assert db.pending_notification_kinds() == ["OFFLINE", "RECOVERY", "REPORT"]


def test_concurrent_offline_and_report_transactions_never_invert_recovery_order(tmp_path):
    """Whichever transaction wins, RECOVERY can never commit before OFFLINE."""
    from concurrent.futures import ThreadPoolExecutor
    import threading

    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    while claim := db.claim_notification("setup", NOW, lease_seconds=30):
        db.acknowledge_chunk(claim, "setup")
    barrier = threading.Barrier(2)

    def mark_offline():
        barrier.wait()
        return db.offline_transitions(NOW + timedelta(minutes=25))

    def accept_report():
        barrier.wait()
        return db.accept_report(
            _report(2), AGENT, received_at=NOW + timedelta(minutes=25, seconds=1)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        offline_future = pool.submit(mark_offline)
        report_future = pool.submit(accept_report)
        offline_future.result()
        report_future.result()

    kinds = db.pending_notification_kinds()
    if "RECOVERY" in kinds:
        assert kinds.index("OFFLINE") < kinds.index("RECOVERY") < kinds.index("REPORT")
    else:
        assert kinds == ["REPORT"]


def _multiprocess_claim(arguments):
    path, owner = arguments
    db = CollectorDB(path, [AGENT])
    claim = db.claim_notification(owner, NOW, lease_seconds=30)
    return owner, claim


def test_multiprocess_claim_allows_only_one_owner_for_oldest_notification(tmp_path):
    """Independent processes must not normally double-send the same oldest chunk."""
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    context = multiprocessing.get_context("spawn")
    arguments = [(str(path), f"worker-{index}") for index in range(4)]

    with context.Pool(4) as pool:
        outcomes = pool.map(_multiprocess_claim, arguments)

    claimed = [(owner, claim) for owner, claim in outcomes if claim is not None]
    assert len(claimed) == 1
    assert db.claim_notification("late-worker", NOW, lease_seconds=30) is None
    owner, claim = claimed[0]
    db.acknowledge_chunk(claim, owner)
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_transient_failure_stays_queued_and_closed_error_is_logged(tmp_path, caplog):
    """Notification failure must retain evidence without logging arbitrary exception text."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)

    class UnsafeFailure:
        async def send_chunks(self, chunks):
            raise RuntimeError("Bearer private https://secret.invalid")

    await NotificationDispatcher(db, UnsafeFailure(), clock=lambda: NOW).drain()

    assert db.pending_notification_count() == 1
    rendered = "\n".join(
        record.getMessage() + repr(record.args) + repr(record.exc_info)
        for record in caplog.records
    )
    assert "private" not in rendered
    assert "secret.invalid" not in rendered


@pytest.mark.asyncio
async def test_permanent_failure_dead_letters_poison_and_later_report_drains(tmp_path):
    """One invalid destination must not block every later durable notification forever."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    db.accept_report(_report(2), AGENT, received_at=NOW + timedelta(seconds=1))

    class PermanentOnceSender(RecordingSender):
        async def send_chunks(self, chunks):
            await super().send_chunks(chunks)
            if len(self.calls) == 1:
                raise TelegramPermanentError("telegram-http-400")

    sender = PermanentOnceSender()
    await NotificationDispatcher(db, sender, clock=lambda: NOW).drain()

    assert len(sender.calls) == 2
    assert db.pending_notification_count() == 0
    assert db.dead_letter_count() == 1
    reopened = CollectorDB(db.path, [AGENT])
    [dead] = reopened.dead_letters()
    assert dead.error_code == "telegram-http-400"
    assert dead.attempt_count == 1
    assert dead.next_chunk == 0
    assert dead.failed_at == NOW


@pytest.mark.asyncio
async def test_transient_failure_is_scheduled_and_survives_restart(tmp_path):
    """A retryable outage remains ordered, durable, and unavailable before its due time."""
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)

    class TransientSender:
        def __init__(self):
            self.calls = 0

        async def send_chunks(self, chunks):
            self.calls += 1
            raise TelegramTransientError("telegram-network")

    failed = TransientSender()
    await NotificationDispatcher(
        db, failed, clock=lambda: NOW, retry_delay_seconds=10
    ).drain()
    assert failed.calls == 1
    assert db.pending_notification_count() == 1
    assert db.dead_letter_count() == 0

    early = RecordingSender()
    await NotificationDispatcher(
        CollectorDB(path, [AGENT]),
        early,
        clock=lambda: NOW + timedelta(seconds=9),
    ).drain()
    assert early.calls == []

    due = RecordingSender()
    reopened = CollectorDB(path, [AGENT])
    await NotificationDispatcher(
        reopened, due, clock=lambda: NOW + timedelta(seconds=10)
    ).drain()
    assert len(due.calls) == 1
    assert reopened.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_retry_budget_exhaustion_dead_letters_and_allows_later_progress(tmp_path):
    """Bounded transient retries prevent a permanently unavailable row from poisoning order."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    db.accept_report(_report(2), AGENT, received_at=NOW + timedelta(seconds=1))

    class FailsTwice(RecordingSender):
        async def send_chunks(self, chunks):
            await super().send_chunks(chunks)
            if len(self.calls) <= 2:
                raise TelegramTransientError("telegram-server-error")

    sender = FailsTwice()
    first = NotificationDispatcher(
        db,
        sender,
        clock=lambda: NOW,
        max_delivery_attempts=2,
        retry_delay_seconds=1,
    )
    await first.drain()
    await NotificationDispatcher(
        db,
        sender,
        clock=lambda: NOW + timedelta(seconds=1),
        max_delivery_attempts=2,
        retry_delay_seconds=1,
    ).drain()

    assert len(sender.calls) == 3
    assert db.dead_letter_count() == 1
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_partial_permanent_failure_retains_acks_and_requeue_resumes_remaining(tmp_path):
    """Dead-lettering a later chunk must preserve prior ACK progress for explicit requeue."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1, rows=40), AGENT, received_at=NOW)

    class SecondChunkPermanent(RecordingSender):
        async def send_chunks(self, chunks):
            await super().send_chunks(chunks)
            if len(self.calls) == 2:
                raise TelegramPermanentError("telegram-response-invalid")

    failed = SecondChunkPermanent()
    await NotificationDispatcher(db, failed, clock=lambda: NOW).drain()
    [dead] = db.dead_letters()
    assert dead.next_chunk == 1
    assert dead.chunk_count > 2
    assert dead.error_code == "telegram-response-invalid"

    clone_id = db.requeue_dead_letter(
        dead.notification_id, NOW + timedelta(seconds=1)
    )
    assert clone_id > dead.notification_id
    assert db.requeue_dead_letter(
        dead.notification_id, NOW + timedelta(seconds=2)
    ) == clone_id
    with sqlite3.connect(db.path) as connection:
        original = connection.execute(
            "SELECT dead_letter, requeued_notification_id FROM notifications WHERE notification_id = ?",
            (dead.notification_id,),
        ).fetchone()
        clone = connection.execute(
            "SELECT notification_id, next_chunk, chunk_count FROM notifications WHERE notification_id = ?",
            (clone_id,),
        ).fetchone()
        cloned_bodies = [
            row[0]
            for row in connection.execute(
                "SELECT body FROM notification_chunks WHERE notification_id = ? ORDER BY chunk_index",
                (clone_id,),
            )
        ]
    assert original == (1, clone_id)
    assert clone == (clone_id, 0, dead.chunk_count - dead.next_chunk)
    assert cloned_bodies[0] == failed.calls[1]
    resumed = RecordingSender()
    await NotificationDispatcher(
        CollectorDB(db.path, [AGENT]),
        resumed,
        clock=lambda: NOW + timedelta(seconds=2),
    ).drain()

    assert resumed.calls[0] == failed.calls[1]
    assert failed.calls[0] not in resumed.calls
    assert db.dead_letter_count() == 0
    assert db.pending_notification_count() == 0


def test_concurrent_requeue_creates_exactly_one_tail_clone(tmp_path):
    """Repeated operators/processes must idempotently resolve one dead letter once."""
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "collector.db"
    db = CollectorDB(path, [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    claim = db.claim_notification("setup", NOW, lease_seconds=30)
    assert claim is not None
    db.record_notification_failure(
        claim,
        "setup",
        "telegram-http-400",
        NOW,
        permanent=True,
        max_attempts=5,
        retry_delay_seconds=60,
    )
    [dead] = db.dead_letters()

    def requeue(_):
        return CollectorDB(path, [AGENT]).requeue_dead_letter(
            dead.notification_id, NOW + timedelta(seconds=1)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        clone_ids = list(pool.map(requeue, range(16)))

    assert len(set(clone_ids)) == 1
    assert clone_ids[0] > dead.notification_id
    assert db.dead_letter_count() == 0
    assert db.pending_notification_count() == 1


@pytest.mark.asyncio
async def test_tail_requeue_waits_for_already_leased_later_notification(tmp_path):
    """A requeued old remainder cannot overtake a newer notification already in flight."""
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [AGENT])
    first_report = _report(1)
    second_report = _report(2).model_copy(
        update={"observed_at": NOW + timedelta(seconds=1)}
    )
    db.accept_report(first_report, AGENT, received_at=NOW)
    db.accept_report(second_report, AGENT, received_at=NOW + timedelta(seconds=1))
    poison = db.claim_notification("poison", NOW, lease_seconds=30)
    assert poison is not None
    db.record_notification_failure(
        poison,
        "poison",
        "telegram-http-400",
        NOW,
        permanent=True,
        max_attempts=5,
        retry_delay_seconds=60,
    )
    later = db.claim_notification("later-worker", NOW, lease_seconds=30)
    assert later is not None
    [dead] = db.dead_letters()

    clone_id = db.requeue_dead_letter(dead.notification_id, NOW)
    assert clone_id > later.notification_id
    assert db.claim_notification("competitor", NOW, lease_seconds=30) is None

    actual_order: list[str] = []
    actual_order.append(later.body)
    db.acknowledge_chunk(later, "later-worker", NOW)
    sender = RecordingSender()
    await NotificationDispatcher(
        CollectorDB(path, [AGENT]), sender, clock=lambda: NOW
    ).drain()
    actual_order.extend(sender.calls)

    assert actual_order == [later.body, poison.body]
    assert "12:00:01 UTC" in actual_order[0]
    assert "12:00:00 UTC" in actual_order[1]


@pytest.mark.asyncio
async def test_send_deadline_cancels_live_owner_before_lease_can_expire(tmp_path):
    """A hung Telegram call must stop before another worker can reclaim its lease."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class HungSender:
        async def send_chunks(self, chunks):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    dispatcher = NotificationDispatcher(
        db,
        HungSender(),
        clock=lambda: NOW,
        lease_seconds=2,
        send_timeout_seconds=0.2,
        lease_margin_seconds=0.1,
        retry_delay_seconds=1,
    )
    task = asyncio.create_task(dispatcher.drain())
    await started.wait()
    await task

    assert cancelled.is_set()
    competing = db.claim_notification(
        "competitor", NOW + timedelta(seconds=2, milliseconds=1), lease_seconds=2
    )
    assert competing is not None


def test_dispatcher_rejects_timeout_that_can_reach_lease_boundary(tmp_path):
    """Deployment settings must make the send deadline provably shorter than its DB lease."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])

    with pytest.raises(ValueError, match="lease"):
        NotificationDispatcher(
            db,
            RecordingSender(),
            clock=lambda: NOW,
            lease_seconds=10,
            send_timeout_seconds=9,
            lease_margin_seconds=1,
        )


@pytest.mark.asyncio
async def test_expired_lease_refuses_ack_and_stops_before_any_later_chunk(tmp_path):
    """Wall-clock lease loss after a send is ambiguous and must stop ordered progress."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1, rows=40), AGENT, received_at=NOW)

    class Clock:
        value = NOW

        def __call__(self):
            return self.value

    clock = Clock()

    class LeaseExpiringSender(RecordingSender):
        async def send_chunks(self, chunks):
            await super().send_chunks(chunks)
            clock.value = NOW + timedelta(seconds=3)

    sender = LeaseExpiringSender()
    with pytest.raises(NotificationDispatchError, match="notification-dispatch-failed"):
        await NotificationDispatcher(
            db,
            sender,
            clock=clock,
            lease_seconds=2,
            send_timeout_seconds=0.5,
            lease_margin_seconds=0.1,
        ).drain()

    assert len(sender.calls) == 1
    claim = db.claim_notification("replacement", clock.value, lease_seconds=2)
    assert claim is not None
    assert claim.chunk_index == 0


@pytest.mark.asyncio
async def test_worst_retry_path_is_cancelled_before_lease_and_competitor_sends_alone(tmp_path):
    """Two long retry-after waits remain under the dispatcher-wide monotonic deadline."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    entered_sleeps: list[float] = []

    class RateLimited(httpx.AsyncBaseTransport):
        calls = 0

        async def handle_async_request(self, request):
            self.calls += 1
            return httpx.Response(
                429,
                json={"ok": False, "parameters": {"retry_after": 60}},
                request=request,
            )

    async def slow_retry_after(delay: float) -> None:
        entered_sleeps.append(delay)
        await asyncio.sleep(0.1)

    transport = RateLimited()
    client = TelegramClient(
        token="123456:example-token-for-tests-only",
        chat_id="-1001234567890",
        transport=transport,
        sleep=slow_retry_after,
        max_attempts=3,
    )
    task = asyncio.create_task(
        NotificationDispatcher(
            db,
            client,
            clock=lambda: NOW,
            lease_seconds=1,
            send_timeout_seconds=0.15,
            lease_margin_seconds=0.1,
        ).drain()
    )
    await task

    assert entered_sleeps == [60.0, 60.0]
    assert transport.calls == 2
    assert task.done()
    replacement = db.claim_notification(
        "replacement", NOW + timedelta(seconds=61), lease_seconds=1
    )
    assert replacement is not None


@pytest.mark.asyncio
async def test_concurrent_dispatchers_dead_letter_one_poison_then_preserve_later_progress(tmp_path):
    """A permanent oldest row remains terminal under competing dispatcher processes."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    db.accept_report(_report(2), AGENT, received_at=NOW + timedelta(seconds=1))

    class OnePoison(RecordingSender):
        async def send_chunks(self, chunks):
            await super().send_chunks(chunks)
            if len(self.calls) == 1:
                raise TelegramPermanentError("telegram-http-400")

    sender = OnePoison()
    await asyncio.gather(
        NotificationDispatcher(db, sender, clock=lambda: NOW, owner="worker-a").drain(),
        NotificationDispatcher(
            CollectorDB(db.path, [AGENT]), sender, clock=lambda: NOW, owner="worker-b"
        ).drain(),
    )

    assert len(sender.calls) == 2
    assert db.dead_letter_count() == 1
    assert db.pending_notification_count() == 0


def _hold_dispatch_file_lock(path, acquired, release):
    lock = FileLock(path, timeout=1, mode=0o600, preserve_lock_file=True)
    with lock:
        acquired.set()
        release.wait(10)


@pytest.mark.asyncio
async def test_dispatcher_network_work_is_guarded_by_cross_process_file_lock(tmp_path):
    """Wall-clock lease jumps cannot defeat the crash-released OS dispatcher lock."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_dispatch_file_lock,
        args=(str(db.dispatch_lock_path), acquired, release),
    )
    holder.start()
    assert await asyncio.to_thread(acquired.wait, 5)
    sender = RecordingSender()
    try:
        await NotificationDispatcher(
            db,
            sender,
            clock=lambda: NOW + timedelta(days=365),
            dispatch_lock_timeout_seconds=0.05,
        ).drain()
        assert sender.calls == []
        assert db.pending_notification_count() == 1
    finally:
        release.set()
        await asyncio.to_thread(holder.join, 5)

    assert holder.exitcode == 0
    await NotificationDispatcher(
        db,
        sender,
        clock=lambda: NOW + timedelta(days=365),
    ).drain()
    assert len(sender.calls) == 1
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_os_lock_owner_steals_crash_left_future_sqlite_lease(tmp_path):
    """A backward clock cannot stall recovery after the exclusive OS owner starts."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    db.accept_report(_report(1), AGENT, received_at=NOW)
    abandoned = db.claim_notification(
        "crashed-worker", NOW + timedelta(days=365), lease_seconds=300
    )
    assert abandoned is not None
    sender = RecordingSender()

    await NotificationDispatcher(
        CollectorDB(db.path, [AGENT]),
        sender,
        clock=lambda: NOW - timedelta(days=1),
        owner="replacement",
    ).drain()

    assert sender.calls == [abandoned.body]
    assert db.pending_notification_count() == 0

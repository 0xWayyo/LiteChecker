from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tracemalloc
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from litechecker.collector.app import _bounded_body, create_app
from litechecker.collector.auth import AgentRegistry
from litechecker.collector.db import CollectorDB, CollectorDBError
from litechecker.collector.telegram import TelegramPermanentError, TelegramTransientError
from litechecker.config import CollectorSettings
from litechecker.models import AgentReport, ResultStatus


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
FAKE_BOT_TOKEN = "123456:example-token-for-tests-only"


class RecordingTelegram:
    def __init__(self, db=None, *, failure: Exception | None = None):
        self.db = db
        self.failure = failure
        self.calls: list[list[str]] = []

    async def send_chunks(self, chunks):
        if self.db is not None:
            assert self.db.event_count() >= 1
        self.calls.append(list(chunks))
        if self.failure is not None:
            raise self.failure


class MustNotRead(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError("unauthenticated or declared-oversized body was read")
        yield b""  # pragma: no cover


class ChunkedBody(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


class MutableClock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


def _registry(tmp_path):
    path = tmp_path / "agents.json"
    path.write_text(
        json.dumps(
            {
                "agent-1": {
                    "token": TOKEN,
                    "city": "Tbilisi",
                    "name": "Home ISP",
                    "expected_interval_seconds": 600,
                }
            }
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return AgentRegistry.load(path), path


def _report(**updates):
    values = {
        "event_id": "agent-1:boot-1:1",
        "agent_id": "agent-1",
        "boot_id": "boot-1",
        "sequence": 1,
        "observed_at": NOW,
        "subscription_revision": "a" * 64,
        "control_status": ResultStatus.UP,
        "duration_ms": 10,
    }
    values.update(updates)
    if "event_id" not in updates and any(
        key in updates for key in ("agent_id", "boot_id", "sequence")
    ):
        values["event_id"] = (
            f"{values['agent_id']}:{values['boot_id']}:{values['sequence']}"
        )
    return AgentReport(**values)


def _settings(registry_path, database_path):
    return CollectorSettings(
        agents_registry_path=registry_path,
        database_path=database_path,
        telegram_bot_token=FAKE_BOT_TOKEN,
        telegram_chat_id="-1001234567890",
        offline_threshold_seconds=1500,
    )


def test_collector_passes_proxy_to_its_default_notification_client(tmp_path, monkeypatch):
    from pydantic import SecretStr
    from litechecker.collector import app as module

    registry, registry_path = _registry(tmp_path)
    db = CollectorDB(tmp_path / "collector.db", registry.identities)
    settings = _settings(registry_path, db.path)
    settings.telegram_proxy_url = SecretStr("socks5://test:private-password@192.0.2.10:1080")
    configured = []

    def make_sender(**kwargs):
        configured.append(kwargs)
        return RecordingTelegram(db)

    monkeypatch.setattr(module, "TelegramClient", make_sender)
    module.create_app(settings, registry=registry, db=db)
    assert len(configured) == 1
    assert configured[0].get("proxy_url") == settings.telegram_proxy_url.get_secret_value()


def _app(tmp_path, *, telegram=None, clock=None, max_body_bytes=4096):
    registry, registry_path = _registry(tmp_path)
    db = CollectorDB(tmp_path / "collector.db", registry.identities)
    telegram = telegram or RecordingTelegram(db)
    app = create_app(
        _settings(registry_path, db.path),
        registry=registry,
        db=db,
        telegram=telegram,
        clock=clock or MutableClock(),
        max_body_bytes=max_body_bytes,
    )
    return app, db, telegram


@pytest.mark.asyncio
async def test_wrong_bearer_is_generic_401_before_body_is_read(tmp_path):
    """Authentication must precede body parsing and reveal no registry detail."""
    app, _, _ = _app(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
    ) as client:
        response = await client.post(
            "/v1/reports",
            headers={"Authorization": "Bearer " + "x" * len(TOKEN)},
            content=MustNotRead(),
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}
    assert TOKEN not in response.text


@pytest.mark.asyncio
async def test_declared_and_streamed_oversized_bodies_return_413(tmp_path):
    """Both known and chunked bodies must be capped without schema allocation."""
    app, _, _ = _app(tmp_path, max_body_bytes=64)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
    ) as client:
        declared = await client.post(
            "/v1/reports",
            headers={**headers, "Content-Length": "65"},
            content=MustNotRead(),
        )
        streamed = await client.post(
            "/v1/reports",
            headers=headers,
            content=ChunkedBody(b"{" + b"x" * 40, b"x" * 40 + b"}"),
        )

    assert declared.status_code == 413
    assert streamed.status_code == 413


@pytest.mark.asyncio
async def test_asgi_cap_checks_chunk_length_before_copying_it():
    """A hostile ASGI chunk must be rejected before a second large in-memory copy."""
    oversized = b"x" * 10_000_000

    class Request:
        async def stream(self):
            yield oversized

    tracemalloc.start()
    try:
        with pytest.raises(Exception) as raised:
            await _bounded_body(Request(), 64)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert getattr(raised.value, "status_code", None) == 413
    assert peak < 1_000_000


@pytest.mark.asyncio
async def test_malformed_schema_is_422_and_agent_mismatch_is_generic_401(tmp_path):
    """Authenticated malformed input and identity mismatch need distinct safe semantics."""
    app, _, _ = _app(tmp_path)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
    ) as client:
        malformed = await client.post(
            "/v1/reports", headers=headers, json={"agent_id": "agent-1"}
        )
        mismatch = await client.post(
            "/v1/reports",
            headers=headers,
            content=_report(agent_id="agent-2").model_dump_json(),
        )
        unbound_event = await client.post(
            "/v1/reports",
            headers=headers,
            content=_report(event_id="unbound").model_dump_json(),
        )

    assert malformed.status_code == 422
    assert malformed.json() == {"detail": "invalid-report"}
    assert mismatch.status_code == 401
    assert mismatch.json() == {"detail": "unauthorized"}
    assert unbound_event.status_code == 422
    assert unbound_event.json() == {"detail": "invalid-report"}


@pytest.mark.asyncio
async def test_new_report_commits_before_one_notification_and_duplicate_does_not_send(tmp_path):
    """Telegram failures or retries must never control evidence durability or duplicate output."""
    registry, registry_path = _registry(tmp_path)
    db = CollectorDB(tmp_path / "collector.db", registry.identities)
    telegram = RecordingTelegram(db)
    app = create_app(
        _settings(registry_path, db.path), registry=registry, db=db, telegram=telegram
    )
    headers = {"Authorization": f"Bearer {TOKEN}"}
    body = _report().model_dump_json()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            accepted = await client.post("/v1/reports", headers=headers, content=body)
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
            duplicate = await client.post("/v1/reports", headers=headers, content=body)
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)

    assert accepted.status_code == 202
    assert accepted.json() == {"accepted": True, "duplicate": False}
    assert duplicate.status_code == 200
    assert duplicate.json() == {"accepted": True, "duplicate": True}
    assert db.event_count() == 1
    assert len(telegram.calls) == 1
    assert db.pending_notification_count() == 0
    assert "Tbilisi" in "".join(telegram.calls[0])


@pytest.mark.asyncio
async def test_notification_failure_never_rolls_back_accepted_report(tmp_path, caplog):
    """The collector is an evidence sink even when Telegram is unavailable."""
    telegram = RecordingTelegram(failure=RuntimeError(f"Bearer {TOKEN}"))
    app, db, _ = _app(tmp_path, telegram=telegram)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            response = await client.post(
                "/v1/reports",
                headers={"Authorization": f"Bearer {TOKEN}"},
                content=_report().model_dump_json(),
            )
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)

    assert response.status_code == 202
    assert db.event_count() == 1
    assert db.pending_notification_count() == 1
    assert TOKEN not in response.text
    for record in caplog.records:
        assert TOKEN not in " | ".join(
            (record.getMessage(), repr(record.args), repr(record.exc_info), repr(record))
        )


@pytest.mark.asyncio
async def test_duplicate_request_retries_already_pending_notification(tmp_path):
    """Duplicate requests wake only retry rows whose bounded delay is already due."""
    clock = MutableClock(NOW)
    telegram = RecordingTelegram(failure=RuntimeError("temporary"))
    app, db, _ = _app(tmp_path, telegram=telegram, clock=clock)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    body = _report().model_dump_json()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            first = await client.post("/v1/reports", headers=headers, content=body)
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
            telegram.failure = None
            early_duplicate = await client.post("/v1/reports", headers=headers, content=body)
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
            assert len(telegram.calls) == 1
            assert db.pending_notification_count() == 1
            clock.value = NOW + timedelta(seconds=60)
            due_duplicate = await client.post("/v1/reports", headers=headers, content=body)
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)

    assert first.status_code == 202
    assert early_duplicate.status_code == 200
    assert due_duplicate.status_code == 200
    assert db.event_count() == 1
    assert db.pending_notification_count() == 0
    assert len(telegram.calls) == 2


@pytest.mark.asyncio
async def test_lifespan_watchdog_health_and_shutdown_have_no_task_leak(tmp_path):
    """Health must cover DB/watchdog readiness and lifespan exit must cancel its task."""
    clock = MutableClock(NOW)
    app, db, telegram = _app(tmp_path, clock=clock)
    db.accept_report(_report(), app.state.registry.get("agent-1"), received_at=NOW)
    await app.state.dispatcher.drain()
    telegram.calls.clear()

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            healthy = await client.get("/healthz")
            clock.value = NOW + timedelta(seconds=181)
            stale = await client.get("/healthz")

    assert healthy.status_code == 200
    assert healthy.json()["status"] == "ok"
    assert healthy.json()["storage"] == {
        "events": 1,
        "results": 0,
        "pending_notifications": 0,
        "pending_chunks": 0,
        "completed_notifications": 1,
        "dead_letters": 0,
    }
    assert stale.status_code == 503
    assert len(telegram.calls) == 0
    assert app.state.watchdog_task.done()
    assert app.state.outbox_task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize("lock_failure_phase", ("create", "acquire", "release"))
async def test_outbox_worker_reports_lock_oserror_and_recovers_without_task_death(
    tmp_path, lock_failure_phase
):
    """OS lock failures at every boundary must degrade health, retry, and recover."""
    retrying = asyncio.Event()
    allow_retry = asyncio.Event()

    async def controlled_retry_sleep(delay):
        assert 0 < delay <= 60
        retrying.set()
        await allow_retry.wait()

    app, _, _ = _app(tmp_path)
    calls = 0

    async def flaky_drain():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(f"synthetic-{lock_failure_phase}")

    app.state.dispatcher.drain = flaky_drain
    app.state.outbox_retry_sleep = controlled_retry_sleep
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(retrying.wait(), timeout=1)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            health = await client.get("/healthz")
            ready = await client.get("/readyz")
        assert health.status_code == 503
        assert health.json()["worker"]["status"] == "retrying"
        assert "synthetic" not in health.text
        assert ready.status_code == 200
        allow_retry.set()
        await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
        assert app.state.outbox_task.done() is False

    assert calls >= 2
    assert app.state.outbox_task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ("claim_notification", "acknowledge_chunk"))
async def test_outbox_worker_surfaces_database_dispatch_failure_then_recovers(
    tmp_path, failure_point
):
    """Claim/ACK database faults must make the supervisor unhealthy and retry."""
    retrying = asyncio.Event()
    allow_retry = asyncio.Event()

    async def controlled_retry_sleep(delay):
        retrying.set()
        await allow_retry.wait()

    app, db, telegram = _app(tmp_path)
    db.accept_report(_report(), app.state.registry.get("agent-1"), received_at=NOW)
    original = getattr(db, failure_point)
    calls = 0

    def flaky(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CollectorDBError("synthetic-private-database-detail")
        return original(*args, **kwargs)

    setattr(db, failure_point, flaky)
    app.state.outbox_retry_sleep = controlled_retry_sleep
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(retrying.wait(), timeout=1)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            health = await client.get("/healthz")
        assert health.status_code == 503
        assert health.json()["worker"]["status"] == "retrying"
        assert "synthetic" not in health.text
        allow_retry.set()
        await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)

    assert db.pending_notification_count() == 0
    assert telegram.calls


@pytest.mark.asyncio
async def test_watchdog_sends_one_offline_transition(tmp_path):
    """Repeated lifespan ticks must not repeat an already persisted offline transition."""
    clock = MutableClock(NOW)
    app, db, telegram = _app(tmp_path, clock=clock)
    db.accept_report(_report(), app.state.registry.get("agent-1"), received_at=NOW)
    await app.state.dispatcher.drain()
    telegram.calls.clear()
    clock.value = NOW + timedelta(minutes=25)

    sent = asyncio.Event()
    original_send = telegram.send_chunks

    async def send_and_signal(chunks):
        await original_send(chunks)
        sent.set()

    telegram.send_chunks = send_and_signal

    async with app.router.lifespan_context(app):
        # Sending and committing the acknowledgement are separate awaits.
        # Do not cancel the worker after an arbitrary 10 ms while it is saving.
        await asyncio.wait_for(sent.wait(), timeout=1)
        await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)

    assert len(telegram.calls) == 1
    assert "OFFLINE" in "".join(telegram.calls[0])
    assert db.pending_notification_count() == 0


@pytest.mark.asyncio
async def test_watchdog_is_not_fresh_until_database_scan_succeeds(tmp_path):
    """Startup and failed ticks must not make health report a working watchdog."""
    clock = MutableClock(NOW)
    app, db, _ = _app(tmp_path, clock=clock)

    def fail_scan(now):
        raise RuntimeError("database unavailable")

    db.offline_transitions = fail_scan
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.01)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert response.json()["storage"]["events"] == 0
    assert "private-collector" not in response.text
    assert "locked" not in response.text
    assert app.state.last_watchdog_at is None


@pytest.mark.asyncio
async def test_health_is_operator_visible_and_unhealthy_while_dead_letter_exists(tmp_path):
    """A terminal Telegram notification must be visible without exposing its payload."""
    telegram = RecordingTelegram(
        failure=TelegramPermanentError("telegram-http-400")
    )
    app, db, _ = _app(tmp_path, telegram=telegram)
    headers = {"Authorization": f"Bearer {TOKEN}"}

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            accepted = await client.post(
                "/v1/reports", headers=headers, content=_report().model_dump_json()
            )
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
            health = await client.get("/healthz")
            dead_count_before_requeue = db.dead_letter_count()
            [dead] = db.dead_letters()
            clone_id = db.requeue_dead_letter(
                dead.notification_id, NOW + timedelta(seconds=1)
            )
            resolved_health = await client.get("/healthz")

    assert accepted.status_code == 202
    assert dead_count_before_requeue == 1
    assert health.status_code == 503
    assert health.json()["status"] == "unavailable"
    assert health.json()["dead_letters"] == 1
    assert health.json()["storage"]["dead_letters"] == 1
    assert TOKEN not in health.text
    assert clone_id > dead.notification_id
    assert db.dead_letter_count() == 0
    assert db.pending_notification_count() == 1
    assert resolved_health.status_code == 200
    assert resolved_health.json()["status"] == "ok"
    assert resolved_health.json()["storage"]["pending_notifications"] == 1


@pytest.mark.asyncio
async def test_watchdog_retries_due_transient_outbox_without_new_request(tmp_path):
    """A quiet collector must recover queued delivery through autonomous watchdog ticks."""
    clock = MutableClock(NOW)
    telegram = RecordingTelegram(
        failure=TelegramTransientError("telegram-network")
    )
    registry, registry_path = _registry(tmp_path)
    db = CollectorDB(tmp_path / "collector.db", registry.identities)
    db.accept_report(_report(), registry.get("agent-1"), received_at=NOW)
    sleeping = asyncio.Event()
    resume = asyncio.Event()

    async def controlled_sleep(delay: float) -> None:
        sleeping.set()
        await resume.wait()
        resume.clear()

    app = create_app(
        _settings(registry_path, db.path),
        registry=registry,
        db=db,
        telegram=telegram,
        clock=clock,
        sleep=controlled_sleep,
    )

    async with app.router.lifespan_context(app):
        await asyncio.wait_for(sleeping.wait(), timeout=1)
        await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
        assert db.pending_notification_count() == 1
        assert len(telegram.calls) == 1
        telegram.failure = None
        clock.value = NOW + timedelta(seconds=60)
        sleeping.clear()
        resume.set()
        for _ in range(100):
            if db.pending_notification_count() == 0:
                break
            await asyncio.sleep(0.001)

    assert db.pending_notification_count() == 0
    assert len(telegram.calls) == 2


@pytest.mark.asyncio
async def test_sqlite_runtime_failure_maps_to_closed_503(tmp_path):
    """SQL text, database paths, and SQLite diagnostics must not cross the API boundary."""
    registry, registry_path = _registry(tmp_path)
    db = CollectorDB(
        tmp_path / "private-collector.db", registry.identities, timeout_seconds=0.01
    )
    app = create_app(
        _settings(registry_path, db.path),
        registry=registry,
        db=db,
        telegram=RecordingTelegram(db),
    )
    blocker = sqlite3.connect(db.path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://collector.test"
        ) as client:
            response = await client.post(
                "/v1/reports",
                headers={"Authorization": f"Bearer {TOKEN}"},
                content=_report().model_dump_json(),
            )
    finally:
        blocker.rollback()
        blocker.close()

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_report_returns_after_transactional_enqueue_while_outbox_send_is_slow(
    tmp_path,
):
    """Collector acceptance latency must not inherit Telegram's retry/send window."""
    started = asyncio.Event()
    release = asyncio.Event()

    class SlowTelegram:
        async def send_chunks(self, chunks):
            started.set()
            await release.wait()

    app, db, _ = _app(tmp_path, telegram=SlowTelegram())
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://collector.test",
            ) as client:
                response = await asyncio.wait_for(
                    client.post(
                        "/v1/reports",
                        headers={"Authorization": f"Bearer {TOKEN}"},
                        content=_report().model_dump_json(),
                    ),
                    timeout=0.2,
                )
            await asyncio.wait_for(started.wait(), timeout=1)
            assert response.status_code == 202
            assert db.pending_notification_count() == 1
            release.set()
            await asyncio.wait_for(app.state.outbox_idle.wait(), timeout=1)
    finally:
        release.set()


@pytest.mark.asyncio
async def test_lifespan_cancels_blocked_outbox_worker_without_task_leak(tmp_path):
    """Shutdown must own, cancel, and await an autonomous blocked dispatcher task."""
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class BlockingTelegram:
        async def send_chunks(self, chunks):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    app, _, _ = _app(tmp_path, telegram=BlockingTelegram())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://collector.test",
        ) as client:
            response = await client.post(
                "/v1/reports",
                headers={"Authorization": f"Bearer {TOKEN}"},
                content=_report().model_dump_json(),
            )
        assert response.status_code == 202
        await asyncio.wait_for(started.wait(), timeout=1)

    assert cancelled.is_set()
    assert app.state.outbox_task.done()

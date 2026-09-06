"""FastAPI collector routes and lifecycle-owned offline watchdog."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from litechecker.collector.auth import AgentIdentity, AgentRegistry
from litechecker.collector.db import (
    CollectorBackpressure,
    CollectorDB,
    CollectorDBError,
    ReportRateLimited,
    SequenceConflict,
)
from litechecker.collector.telegram import (
    NotificationDispatcher, TelegramClient, telegram_client_options,
)
from litechecker.config import CollectorSettings
from litechecker.models import AgentReport


_LOGGER = logging.getLogger(__name__)
_UNAUTHORIZED = "unauthorized"
_INVALID_REPORT = "invalid-report"


def create_app(
    settings: CollectorSettings,
    *,
    registry: AgentRegistry | None = None,
    db: CollectorDB | None = None,
    telegram: TelegramClient | None = None,
    clock: Callable[[], datetime] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_body_bytes: int = 1_048_576,
    watchdog_interval_seconds: float = 60.0,
    watchdog_stale_after_seconds: float = 180.0,
) -> FastAPI:
    if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 1:
        raise ValueError("collector body limit is invalid")
    if watchdog_interval_seconds <= 0 or watchdog_stale_after_seconds <= watchdog_interval_seconds:
        raise ValueError("watchdog timing is invalid")
    wall_clock = clock or (lambda: datetime.now(UTC))
    registry = registry or AgentRegistry.load(settings.agents_registry_path)
    db = db or CollectorDB(
        settings.database_path,
        registry.identities,
        offline_threshold_seconds=settings.offline_threshold_seconds,
        registry_activated_at=_utc_now(wall_clock),
        report_burst=settings.report_burst,
        report_window_seconds=settings.report_window_seconds,
        event_retention_seconds=settings.event_retention_seconds,
        max_events_per_agent=settings.max_events_per_agent,
        completed_notification_retention_seconds=(
            settings.completed_notification_retention_seconds
        ),
        max_completed_notifications=settings.max_completed_notifications,
        max_dead_letters_per_agent=settings.max_dead_letters_per_agent,
        max_pending_notifications_per_agent=(
            settings.max_pending_notifications_per_agent
        ),
        max_pending_notifications_global=settings.max_pending_notifications_global,
        max_pending_chunks_per_agent=settings.max_pending_chunks_per_agent,
        max_pending_chunks_global=settings.max_pending_chunks_global,
    )
    telegram = telegram or TelegramClient(**telegram_client_options(settings))
    dispatcher = NotificationDispatcher(db, telegram, clock=wall_clock)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not await asyncio.to_thread(db.is_ready):
            raise RuntimeError("collector-database-not-ready")
        watchdog_task = asyncio.create_task(
            _watchdog_loop(app), name="litechecker-watchdog"
        )
        outbox_task = asyncio.create_task(
            _outbox_loop(app), name="litechecker-outbox"
        )
        app.state.watchdog_task = watchdog_task
        app.state.outbox_task = outbox_task
        _signal_outbox(app)
        try:
            yield
        finally:
            watchdog_task.cancel()
            outbox_task.cancel()
            with suppress(asyncio.CancelledError):
                await watchdog_task
            with suppress(asyncio.CancelledError):
                await outbox_task

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.registry = registry
    app.state.db = db
    app.state.telegram = telegram
    app.state.dispatcher = dispatcher
    app.state.last_watchdog_at = None
    app.state.watchdog_task = None
    app.state.outbox_task = None
    app.state.outbox_event = asyncio.Event()
    app.state.outbox_idle = asyncio.Event()
    app.state.outbox_idle.set()
    app.state.outbox_retry_sleep = asyncio.sleep
    app.state.outbox_error = None
    app.state.outbox_failure_count = 0
    app.state.outbox_consecutive_failures = 0
    app.state.last_outbox_success_at = None

    def _signal_outbox(app: FastAPI) -> None:
        app.state.outbox_idle.clear()
        app.state.outbox_event.set()

    async def _outbox_loop(app: FastAPI) -> None:
        while True:
            await app.state.outbox_event.wait()
            app.state.outbox_event.clear()
            try:
                await dispatcher.drain()
            except asyncio.CancelledError:
                raise
            except Exception:
                app.state.outbox_error = "outbox-drain-failed"
                app.state.outbox_failure_count += 1
                app.state.outbox_consecutive_failures += 1
                _LOGGER.error("collector-outbox-drain-failed")
                delay = min(
                    60.0,
                    float(2 ** min(app.state.outbox_consecutive_failures - 1, 6)),
                )
                await app.state.outbox_retry_sleep(delay)
                app.state.outbox_event.set()
            else:
                app.state.outbox_error = None
                app.state.outbox_consecutive_failures = 0
                app.state.last_outbox_success_at = _utc_now(wall_clock)
            finally:
                if not app.state.outbox_event.is_set():
                    app.state.outbox_idle.set()

    async def _watchdog_once(app: FastAPI) -> None:
        now = _utc_now(wall_clock)
        try:
            await asyncio.to_thread(db.offline_transitions, now)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.error("collector-watchdog-database-failed")
        else:
            app.state.last_watchdog_at = now
            _signal_outbox(app)

    async def _watchdog_loop(app: FastAPI) -> None:
        while True:
            await _watchdog_once(app)
            await sleep(watchdog_interval_seconds)

    @app.post("/v1/reports")
    async def receive_report(request: Request) -> JSONResponse:
        agent = _authenticate_request(request, registry)
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                raise HTTPException(status_code=413, detail="payload-too-large") from None
            if declared_length < 0 or declared_length > max_body_bytes:
                raise HTTPException(status_code=413, detail="payload-too-large")
        body = await _bounded_body(request, max_body_bytes)
        try:
            payload = json.loads(body.decode("utf-8"))
            report = AgentReport.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError):
            raise HTTPException(status_code=422, detail=_INVALID_REPORT) from None
        if report.agent_id != agent.agent_id:
            raise HTTPException(status_code=401, detail=_UNAUTHORIZED)
        received_at = _utc_now(wall_clock)
        try:
            accepted = await asyncio.to_thread(
                db.accept_report, report, agent, received_at=received_at
            )
        except (SequenceConflict, ValueError):
            raise HTTPException(status_code=422, detail=_INVALID_REPORT) from None
        except ReportRateLimited:
            raise HTTPException(status_code=429, detail="report-rate-limited") from None
        except CollectorBackpressure:
            raise HTTPException(status_code=503, detail="collector-backpressure") from None
        except CollectorDBError:
            raise HTTPException(status_code=503, detail="collector-unavailable") from None

        _signal_outbox(app)
        if accepted.is_new:
            return JSONResponse(
                status_code=202,
                content={"accepted": True, "duplicate": False},
            )
        return JSONResponse(
            status_code=200,
            content={"accepted": True, "duplicate": True},
        )

    @app.get("/healthz")
    async def health() -> JSONResponse:
        ready = await asyncio.to_thread(db.is_ready)
        dead_letters: int | None = None
        storage: dict[str, int] | None = None
        if ready:
            try:
                storage = await asyncio.to_thread(db.storage_stats)
                dead_letters = storage["dead_letters"]
            except CollectorDBError:
                ready = False
        last_watchdog = app.state.last_watchdog_at
        healthy_watchdog = False
        if isinstance(last_watchdog, datetime):
            age = (_utc_now(wall_clock) - last_watchdog).total_seconds()
            healthy_watchdog = 0 <= age <= watchdog_stale_after_seconds
        worker = _worker_status(app)
        healthy_worker = worker["alive"] and worker["status"] == "ok"
        if not ready or not healthy_watchdog or not healthy_worker or dead_letters:
            content: dict[str, object] = {"status": "unavailable"}
            if storage is not None:
                content["storage"] = storage
            if dead_letters:
                content["dead_letters"] = dead_letters
            content["worker"] = worker
            return JSONResponse(status_code=503, content=content)
        return JSONResponse(
            status_code=200,
            content={"status": "ok", "storage": storage, "worker": worker},
        )

    @app.get("/readyz")
    async def readiness() -> JSONResponse:
        ready = await asyncio.to_thread(db.is_ready)
        worker = _worker_status(app)
        watchdog = app.state.watchdog_task
        tasks_alive = (
            bool(worker["alive"])
            and watchdog is not None
            and not watchdog.done()
        )
        status = 200 if ready and tasks_alive else 503
        return JSONResponse(
            status_code=status,
            content={
                "status": "ready" if status == 200 else "unavailable",
                "worker": worker,
            },
        )

    return app


def _authenticate_request(request: Request, registry: AgentRegistry) -> AgentIdentity:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    candidate = token if separator and scheme.lower() == "bearer" and token and " " not in token else ""
    agent = registry.authenticate(candidate)
    if agent is None:
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED)
    return agent


async def _bounded_body(request: Request, maximum: int) -> bytes:
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > maximum:
                raise HTTPException(status_code=413, detail="payload-too-large")
            body.extend(chunk)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=422, detail=_INVALID_REPORT) from None
    return bytes(body)


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeError("collector-clock-not-utc")
    return value.astimezone(UTC)


def _worker_status(app: FastAPI) -> dict[str, object]:
    task = app.state.outbox_task
    alive = task is not None and not task.done()
    last_success = app.state.last_outbox_success_at
    return {
        "alive": alive,
        "status": (
            "stopped"
            if not alive
            else "retrying"
            if app.state.outbox_error is not None
            else "ok"
        ),
        "failures": app.state.outbox_failure_count,
        "last_success_at": (
            last_success.isoformat() if isinstance(last_success, datetime) else None
        ),
    }

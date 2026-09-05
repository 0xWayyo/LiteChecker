"""Collector delivery around fresh measurements and a bounded-memory daemon."""

from __future__ import annotations

import asyncio
import os
import secrets  # Compatibility for subscription freshness callers.
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from litechecker.async_state import state_call
from litechecker.config import AgentSettings
from litechecker.measurement import (
    ControlChecker, Parser, SubscriptionFetchError, SubscriptionFetcher,
    SubscriptionSource, TargetProber, XrayVersionChecker, XrayVersionResult,
    _SecretRoutingTransport, _bounded_version_output, _reconcile_run_status,
    _remaining, _run_control, _run_probes, _snapshot_age, _unknown_results, _utc,
    make_measurement_dependencies, measure_cycle, query_xray_version,
)
from litechecker.models import AgentReport
from litechecker.protocol import CollectorClient
from litechecker.state import (
    CollectorAckStore, DeliveryLockUnavailable, PendingReportStore,
    SequenceStore, SnapshotStore,
)
from litechecker.subscription import parse_xray_subscription


class CurrentReportNotAccepted(RuntimeError):
    """One-shot mode did not receive collector acceptance for its current event."""

    def __init__(self) -> None:
        super().__init__("current-report-not-accepted")


class ReportSender(Protocol):
    async def send(self, report: AgentReport) -> Any: ...


@dataclass
class AgentDependencies:
    """Injectable cycle boundaries for deterministic tests and local operation."""

    fetcher: SubscriptionSource
    snapshot_store: SnapshotStore
    sequence_store: SequenceStore
    pending_store: PendingReportStore
    control_checker: ControlChecker
    prober: TargetProber | None
    sender: ReportSender
    wall_clock: Callable[[], datetime]
    monotonic: Callable[[], float]
    sleep: Callable[[float], Awaitable[None]]
    boot_id: str
    parser: Parser = parse_xray_subscription
    version_checker: XrayVersionChecker | None = None
    ack_store: CollectorAckStore | None = None
    last_accepted_event_id: str | None = None


Dependencies = AgentDependencies


async def run_cycle(
    settings: AgentSettings,
    dependencies: AgentDependencies,
) -> AgentReport:
    """Measure once and retain durable collector delivery ownership."""
    report = await measure_cycle(settings, dependencies)
    delivered, accepted = await deliver_report(
        report, dependencies.pending_store, dependencies.sender,
    )
    if accepted:
        dependencies.last_accepted_event_id = delivered.event_id
        if dependencies.ack_store is not None:
            await state_call(
                dependencies.ack_store.record,
                delivered.event_id, _utc(dependencies.wall_clock()),
            )
    return delivered


async def deliver_report(
    report: AgentReport,
    pending_store: PendingReportStore,
    sender: ReportSender,
) -> tuple[AgentReport, bool]:
    """Persist before sending, preserving retry and exact-event ownership."""
    previous_pending = await state_call(pending_store.load)
    owns_outbox = await state_call(pending_store.save, report.model_dump(mode="json"))
    if not owns_outbox:
        return report, False
    try:
        return await _deliver_current(report, previous_pending, pending_store, sender)
    except DeliveryLockUnavailable:
        return report, False


async def run_agent(
    settings: AgentSettings,
    once: bool = False,
    *,
    dependencies: AgentDependencies | None = None,
    max_cycles: int | None = None,
) -> AgentReport | list[AgentReport]:
    """Run immediately, then wait one full monotonic interval after each completion."""
    if max_cycles is not None and max_cycles < 1:
        raise ValueError("max_cycles must be positive")
    dependencies = dependencies or _default_dependencies(settings)
    completed: list[AgentReport] = []
    while True:
        report = await run_cycle(settings, dependencies)
        if max_cycles is not None:
            completed.append(report)
        if once:
            if dependencies.last_accepted_event_id != report.event_id:
                raise CurrentReportNotAccepted()
            return report
        if max_cycles is not None and len(completed) >= max_cycles:
            return completed

        next_start = dependencies.monotonic() + settings.interval_seconds
        while True:
            delay = next_start - dependencies.monotonic()
            if delay <= 0:
                break
            await dependencies.sleep(delay)


def _default_dependencies(
    settings: AgentSettings, *, state_dir: Path | None = None
) -> AgentDependencies:
    state_dir = state_dir if state_dir is not None else Path(
        os.environ.get("LC_STATE_DIR", "/var/lib/litechecker")
    )
    measurement = make_measurement_dependencies(settings, state_dir=state_dir)
    return AgentDependencies(
        **vars(measurement),
        pending_store=PendingReportStore(state_dir / "pending-report.json"),
        ack_store=CollectorAckStore(state_dir / "collector-ack.json"),
        sender=CollectorClient(
            settings.collector_url,
            settings.agent_token.get_secret_value(),
            allow_insecure_loopback=settings.allow_insecure_collector,
        ),
    )


async def _retry_pending(
    raw: dict[str, Any] | None,
    sender: ReportSender,
) -> int:
    if raw is None:
        return 0
    try:
        pending = AgentReport.model_validate(raw)
    except ValidationError:
        return 1
    try:
        await sender.send(pending)
    except Exception:
        return 1
    return 0


async def _deliver_current(
    report: AgentReport,
    previous_pending: dict[str, Any] | None,
    pending_store: PendingReportStore,
    sender: ReportSender,
) -> tuple[AgentReport, bool]:
    """Deliver only while this report remains the exact durable owner."""
    async with pending_store.delivery_lock():
        if not await state_call(pending_store.is_pending, report.event_id, report.sequence):
            return report, False

        dropped_count = await _retry_pending(previous_pending, sender)
        if not await state_call(pending_store.is_pending, report.event_id, report.sequence):
            return report, False
        if dropped_count:
            report = report.model_copy(update={"dropped_report_count": dropped_count})
            if not await state_call(
                pending_store.replace_if_event, report.event_id,
                report.model_dump(mode="json"),
            ):
                return report, False

        if not await state_call(pending_store.is_pending, report.event_id, report.sequence):
            return report, False
        try:
            await sender.send(report)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        else:
            await state_call(pending_store.clear, report.event_id)
            return report, True
        return report, False

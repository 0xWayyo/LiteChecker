from __future__ import annotations

import asyncio
import gzip
import json
import logging
import multiprocessing
import re
import ssl
import threading
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import trustme

import litechecker.agent as agent_module

from litechecker.agent import (
    AgentDependencies,
    CurrentReportNotAccepted,
    SubscriptionFetchError,
    SubscriptionFetcher,
    XrayVersionResult,
    query_xray_version,
    run_agent,
    run_cycle,
)
from litechecker.config import AgentSettings
from litechecker.models import (
    AgentReport,
    ProbeResult,
    ProbeStage,
    ResultStatus,
    TargetConfig,
)
from litechecker.probe import ControlResult
from litechecker.probe import probe_all
from litechecker.protocol import DeliveryError
from litechecker.state import (
    CollectorAckStore,
    PendingReportStore,
    SequenceStore,
    SnapshotStore,
    StateError,
)
from litechecker.subscription import parse_xray_subscription


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
AGENT_TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


def _hold_delivery_lock_for_agent_test(path, acquired, release):
    async def hold() -> None:
        store = PendingReportStore(path)
        async with store.delivery_lock():
            acquired.set()
            while not release.is_set():
                await asyncio.sleep(0.01)

    asyncio.run(hold())


def _target(number: int, *, fingerprint: str | None = None) -> TargetConfig:
    return TargetConfig(
        target_id=f"target-{number}",
        config_fingerprint=fingerprint or f"fingerprint-{number}",
        label=f"Target {number}",
        address=f"node-{number}.example",
        port=443,
        address_kind="domain",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": f"node-{number}.example",
                        "port": 443,
                        "users": [
                            {"id": "11111111-1111-4111-8111-111111111111"}
                        ],
                    }
                ]
            },
        },
    )


def _subscription(*numbers: int) -> bytes:
    profiles = []
    for number in numbers:
        target = _target(number)
        outbound = {
            **target.outbound,
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.example.com",
                    "publicKey": "fake-public-key",
                    "shortId": "fake-short-id",
                },
            },
        }
        profiles.append(
            {
                "remarks": target.label,
                "outbounds": [outbound],
            }
        )
    return json.dumps(profiles).encode()


def _settings(**updates) -> AgentSettings:
    values = {
        "agent_id": "agent-1",
        "agent_token": AGENT_TOKEN,
        "collector_url": "https://collector.example",
        "subscription_url": "https://subscription.example/private?key=redacted",
        "state_key": "state-key-with-at-least-32-characters",
        "interval_seconds": 10,
        "run_deadline_seconds": 100,
        "probe_timeout_seconds": 4,
        "tcp_timeout_seconds": 2,
        "max_concurrency": 2,
        "max_subscription_bytes": 1024,
        "max_endpoints": 20,
    }
    values.update(updates)
    return AgentSettings(**values)


def test_default_dependencies_forward_explicit_loopback_http_override(
    tmp_path, monkeypatch
):
    """Valid config is unusable if the delivery client silently drops its dev override."""
    observed: dict[str, object] = {}

    class RecordingClient:
        def __init__(self, url, token, *, allow_insecure_loopback=False):
            observed.update(
                url=url,
                token=token,
                allow_insecure_loopback=allow_insecure_loopback,
            )

    monkeypatch.setenv("LC_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(agent_module, "CollectorClient", RecordingClient)
    settings = _settings(
        collector_url="http://127.0.0.1:8000",
        allow_insecure_collector=True,
    )

    dependencies = agent_module._default_dependencies(settings)

    assert isinstance(dependencies.sender, RecordingClient)
    assert observed["url"] == "http://127.0.0.1:8000"
    assert observed["token"] == AGENT_TOKEN
    assert observed["allow_insecure_loopback"] is True


class FakeFetcher:
    def __init__(self, *outcomes: bytes | Exception):
        self._outcomes = iter(outcomes)
        self.calls = 0

    async def fetch(self) -> bytes:
        self.calls += 1
        outcome = next(self._outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class RecordingSender:
    def __init__(self, *outcomes: Exception | None):
        self._outcomes = iter(outcomes)
        self.reports: list[AgentReport] = []

    async def send(self, report: AgentReport) -> None:
        self.reports.append(report)
        outcome = next(self._outcomes, None)
        if outcome is not None:
            raise outcome


class StaticClock:
    def __init__(self, now: datetime = NOW, monotonic: float = 10.0):
        self.now = now
        self.monotonic_value = monotonic

    def wall(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.monotonic_value


def _dependencies(
    tmp_path: Path,
    *,
    fetcher: FakeFetcher,
    sender: RecordingSender,
    prober,
    control_checker=None,
    clock: StaticClock | None = None,
) -> AgentDependencies:
    clock = clock or StaticClock()
    return AgentDependencies(
        fetcher=fetcher,
        snapshot_store=SnapshotStore(tmp_path, state_key=b"s" * 32),
        sequence_store=SequenceStore(tmp_path / "sequence.json"),
        pending_store=PendingReportStore(tmp_path / "pending-report.json"),
        control_checker=control_checker or (lambda: _async_value(ControlResult(ok=True))),
        prober=prober,
        sender=sender,
        wall_clock=clock.wall,
        monotonic=clock.monotonic,
        sleep=_no_sleep,
        boot_id="boot-1",
    )


async def _async_value(value):
    return value


async def _no_sleep(delay: float) -> None:
    del delay


def _up_result(target: TargetConfig) -> ProbeResult:
    return ProbeResult(
        target_id=target.target_id,
        label=target.label,
        address=target.address,
        port=target.port,
        status=ResultStatus.UP,
        stage=ProbeStage.TLS if target.check_kind == "sni" else ProbeStage.E2E,
        check_kind=target.check_kind,
        latency_ms=7,
    )


@pytest.mark.asyncio
async def test_failed_fetch_with_cached_snapshot_probes_no_old_targets_or_xray(tmp_path):
    settings = _settings()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("https://private.invalid/?token=secret")),
        sender=RecordingSender(None),
        prober=None,
    )
    dependencies.snapshot_store.consider([_target(1)], NOW - timedelta(minutes=10))
    probed: list[list[str]] = []

    async def prober(
        targets: Sequence[TargetConfig], control: ControlResult, deadline: float
    ) -> list[ProbeResult]:
        assert control.ok is True
        assert deadline > 0
        probed.append([target.target_id for target in targets])
        return [_up_result(target) for target in targets]

    dependencies.prober = prober
    version_calls = 0

    async def version_checker():
        nonlocal version_calls
        version_calls += 1
        return XrayVersionResult("26.3.27", True, None)

    dependencies.version_checker = version_checker

    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "UNAVAILABLE"
    assert report.snapshot_age_seconds is None
    assert report.subscription_revision is None
    assert report.run_reason == "no-valid-snapshot"
    assert probed == []
    assert version_calls == 0
    assert report.results == []
    assert "private.invalid" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_invalid_refresh_with_cache_probes_nothing_and_reports_unavailable(tmp_path):
    settings = _settings()
    invalid = _subscription(2).replace(b"node-2.example", b"bad_host.example")
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(invalid),
        sender=RecordingSender(None),
        prober=None,
    )
    dependencies.snapshot_store.consider([_target(1)], NOW - timedelta(minutes=10))

    async def prober(targets, control, deadline):
        del targets, control, deadline
        pytest.fail("invalid current subscription must not probe cached targets")

    dependencies.prober = prober
    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "UNAVAILABLE"
    assert report.run_reason == "no-valid-snapshot"
    assert report.results == []


@pytest.mark.asyncio
async def test_fresh_snapshot_diff_is_attached_and_control_runs_before_probe(tmp_path):
    """Losing the accepted diff or probing before control would misstate fresh evidence."""
    settings = _settings()
    calls: list[str] = []

    async def control_checker() -> ControlResult:
        calls.append("control")
        return ControlResult(ok=True)

    async def prober(targets, control, deadline):
        del control, deadline
        calls.append("probe")
        return [_up_result(target) for target in targets]

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1, 2)),
        sender=RecordingSender(None),
        prober=prober,
        control_checker=control_checker,
    )

    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "FRESH"
    assert len(report.diff.added) == 3
    assert {result.check_kind for result in report.results} == {"vpn", "sni"}
    assert report.diff.removed == []
    assert calls == ["control", "probe"]
    assert report.control_status is ResultStatus.UP


@pytest.mark.asyncio
async def test_refresh_failure_after_success_never_derives_or_probes_old_sni(tmp_path):
    settings = _settings()

    probed: list[list[str]] = []

    async def prober(targets, control, deadline):
        del control, deadline
        probed.append([target.target_id for target in targets])
        return [_up_result(target) for target in targets]

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(
            _subscription(1), SubscriptionFetchError("subscription-network")
        ),
        sender=RecordingSender(None), prober=prober,
    )

    fresh_report = await run_cycle(settings, dependencies)
    assert fresh_report.refresh_state == "FRESH"
    assert {result.check_kind for result in fresh_report.results} == {"vpn", "sni"}
    accepted_revision = fresh_report.subscription_revision
    assert probed and len(probed[0]) == 2

    probed.clear()
    failed_report = await run_cycle(settings, dependencies)

    assert failed_report.refresh_state == "UNAVAILABLE"
    assert failed_report.snapshot_age_seconds is None
    assert failed_report.subscription_revision is None
    assert failed_report.run_reason == "no-valid-snapshot"
    assert failed_report.results == []
    assert probed == []
    assert dependencies.snapshot_store.load().subscription_revision == accepted_revision


@pytest.mark.asyncio
async def test_snapshot_acceptance_failure_skips_version_and_all_probes(tmp_path):
    settings = _settings()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1)),
        sender=RecordingSender(None),
        prober=None,
    )

    def reject_candidate(targets, now):
        del targets, now
        raise StateError("snapshot acceptance failed")

    dependencies.snapshot_store.consider = reject_candidate  # type: ignore[method-assign]

    async def prober(targets, control, deadline):
        del targets, control, deadline
        pytest.fail("unaccepted current subscription must not be probed")

    async def version_checker():
        pytest.fail("unaccepted current subscription must not run Xray")

    dependencies.prober = prober
    dependencies.version_checker = version_checker

    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "UNAVAILABLE"
    assert report.run_reason == "no-valid-snapshot"
    assert report.results == []


@pytest.mark.asyncio
async def test_mass_removal_refresh_activates_and_probes_new_targets_immediately(tmp_path):
    settings = _settings()
    probed: list[str] = []

    async def prober(targets, control, deadline):
        del control, deadline
        probed.extend(target.target_id for target in targets)
        return [_up_result(target) for target in targets]

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1)),
        sender=RecordingSender(None),
        prober=prober,
    )
    initial_targets = parse_xray_subscription(
        _subscription(1, 2, 3, 4),
        settings.state_key.get_secret_value(),
        settings.max_endpoints,
    )
    dependencies.snapshot_store.consider(initial_targets, NOW - timedelta(minutes=10))

    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "FRESH"
    assert report.run_status is ResultStatus.UP
    assert report.run_reason is None
    expected = parse_xray_subscription(
        _subscription(1), settings.state_key.get_secret_value(), settings.max_endpoints,
    )
    assert probed == sorted(target.target_id for target in expected)
    assert len(report.diff.removed) == 3


@pytest.mark.asyncio
async def test_probe_deadline_reconciles_agent_run_status_and_complete_down_does_not(
    tmp_path,
):
    """Agent-local incomplete evidence must close the run without hiding complete DOWNs."""
    settings = _settings(max_endpoints=30)
    payload = _subscription(*range(1, 23))

    async def deadline_prober(targets, control, deadline):
        del control, deadline
        return [
            ProbeResult(
                target_id=target.target_id,
                label=target.label,
                address=target.address,
                port=target.port,
                status=ResultStatus.UNKNOWN,
                stage=ProbeStage.DEADLINE,
                error_code="deadline",
                check_kind=target.check_kind,
            )
            for target in targets
        ]

    deadline = await run_cycle(
        settings,
        _dependencies(
            tmp_path / "deadline",
            fetcher=FakeFetcher(payload),
            sender=RecordingSender(None),
            prober=deadline_prober,
        ),
    )
    assert len(deadline.results) == 23
    assert deadline.run_status is ResultStatus.UNKNOWN
    assert deadline.run_reason == "deadline"

    async def down_prober(targets, control, deadline):
        del control, deadline
        return [
            ProbeResult(
                target_id=target.target_id,
                label=target.label,
                address=target.address,
                port=target.port,
                status=ResultStatus.DOWN,
                stage=ProbeStage.TCP,
                error_code="tcp-connect",
                check_kind=target.check_kind,
            )
            for target in targets
        ]

    complete = await run_cycle(
        settings,
        _dependencies(
            tmp_path / "complete",
            fetcher=FakeFetcher(payload),
            sender=RecordingSender(None),
            prober=down_prober,
        ),
    )
    assert complete.run_status is ResultStatus.UP
    assert complete.run_reason is None


@pytest.mark.asyncio
async def test_missing_snapshot_reports_agent_unknown_with_zero_targets(tmp_path):
    """Inventing target rows without a valid snapshot would fabricate observations."""
    settings = _settings()

    async def must_not_probe(*args):
        pytest.fail("no snapshot must not invoke target probes")

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(SubscriptionFetchError("subscription-network")),
        sender=RecordingSender(None),
        prober=must_not_probe,
    )

    report = await run_cycle(settings, dependencies)

    assert report.refresh_state == "UNAVAILABLE"
    assert report.control_status is ResultStatus.UP
    assert report.run_status is ResultStatus.UNKNOWN
    assert report.run_reason == "no-valid-snapshot"
    assert report.subscription_revision is None
    assert report.results == []


@pytest.mark.asyncio
async def test_failed_current_delivery_is_saved_without_losing_report(tmp_path):
    """Discarding a failed current send would create an unobservable monitoring gap."""
    settings = _settings()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=RecordingSender(DeliveryError("collector-network")),
        prober=None,
    )

    report = await run_cycle(settings, dependencies)

    pending = dependencies.pending_store.load()
    assert pending is not None
    assert pending["event_id"] == report.event_id
    assert pending["sequence"] == 0


@pytest.mark.asyncio
async def test_cancelled_current_delivery_is_saved_before_cancellation_propagates(tmp_path):
    """Shutdown during delivery must not lose the report that was already observed."""
    settings = _settings()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=RecordingSender(asyncio.CancelledError()),
        prober=None,
    )

    with pytest.raises(asyncio.CancelledError):
        await run_cycle(settings, dependencies)

    pending = dependencies.pending_store.load()
    assert pending is not None
    assert pending["event_id"] == "agent-1:boot-1:0"
    contender = PendingReportStore(
        tmp_path / "pending-report.json",
        lock_timeout=0,
    )
    async with contender.delivery_lock():
        pass


@pytest.mark.asyncio
async def test_control_failure_remains_unknown_agent_network_in_cycle(tmp_path):
    """Cycle orchestration must not reclassify Task 3 control uncertainty as target DOWN."""
    settings = _settings()

    async def failed_control() -> ControlResult:
        return ControlResult(ok=False, error_code="control-failed")

    async def real_prober(targets, control, deadline):
        return await probe_all(
            targets,
            control=control,
            max_concurrency=1,
            deadline_seconds=deadline,
        )

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1)),
        sender=RecordingSender(None),
        prober=real_prober,
        control_checker=failed_control,
    )

    report = await run_cycle(settings, dependencies)

    assert report.control_status is ResultStatus.UNKNOWN
    assert [result.status for result in report.results] == [ResultStatus.UNKNOWN] * 2
    assert [result.stage for result in report.results] == [ProbeStage.AGENT_NETWORK] * 2
    assert {result.check_kind for result in report.results} == {"vpn", "sni"}


@pytest.mark.asyncio
async def test_previous_pending_is_retried_before_current_and_latest_failure_replaces_it(
    tmp_path,
):
    """Queueing history or keeping an older failure would violate the bounded latest-only outbox."""
    settings = _settings()
    sender = RecordingSender(
        DeliveryError("collector-network"),
        DeliveryError("collector-network"),
    )
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=sender,
        prober=None,
    )
    previous = AgentReport(
        event_id="agent-1:old-boot:0",
        agent_id="agent-1",
        boot_id="old-boot",
        sequence=0,
        observed_at=NOW - timedelta(minutes=10),
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UNKNOWN,
        duration_ms=1,
    )
    dependencies.sequence_store.next()
    dependencies.pending_store.save(previous.model_dump(mode="json"))

    current = await run_cycle(settings, dependencies)

    assert [report.event_id for report in sender.reports] == [
        previous.event_id,
        current.event_id,
    ]
    assert current.dropped_report_count == 1
    assert dependencies.pending_store.load()["event_id"] == current.event_id


@pytest.mark.asyncio
async def test_cancellation_during_old_pending_retry_leaves_current_on_disk(tmp_path):
    """A cancelled older retry must not prevent write-ahead persistence of this cycle."""
    settings = _settings()
    sender = RecordingSender(asyncio.CancelledError())
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=sender,
        prober=None,
    )
    previous = AgentReport(
        event_id="agent-1:old-boot:0",
        agent_id="agent-1",
        boot_id="old-boot",
        sequence=0,
        observed_at=NOW - timedelta(minutes=10),
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UNKNOWN,
        duration_ms=1,
    )
    dependencies.sequence_store.next()
    dependencies.pending_store.save(previous.model_dump(mode="json"))

    with pytest.raises(asyncio.CancelledError):
        await run_cycle(settings, dependencies)

    pending = AgentReport.model_validate(dependencies.pending_store.load())
    assert pending.event_id == "agent-1:boot-1:1"
    assert [report.event_id for report in sender.reports] == [previous.event_id]


@pytest.mark.asyncio
async def test_current_is_persisted_before_entering_current_network_send(tmp_path):
    """A crash at the current send boundary must leave the already-built report durable."""
    settings = _settings()

    class SimulatedCrash(BaseException):
        pass

    class CrashPointSender:
        async def send(self, report: AgentReport) -> None:
            pending = AgentReport.model_validate(dependencies.pending_store.load())
            assert pending.event_id == report.event_id
            raise SimulatedCrash

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=CrashPointSender(),
        prober=None,
    )

    with pytest.raises(SimulatedCrash):
        await run_cycle(settings, dependencies)

    pending = AgentReport.model_validate(dependencies.pending_store.load())
    assert pending.event_id == "agent-1:boot-1:0"


@pytest.mark.asyncio
async def test_successful_old_retry_and_current_send_clear_only_prepared_current(tmp_path):
    """Retry success must not clear the write-ahead current report before its own send."""
    settings = _settings()

    class InspectingSender:
        def __init__(self):
            self.calls: list[str] = []

        async def send(self, report: AgentReport) -> None:
            pending = AgentReport.model_validate(dependencies.pending_store.load())
            assert pending.event_id == "agent-1:boot-1:1"
            self.calls.append(report.event_id)

    sender = InspectingSender()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=sender,
        prober=None,
    )
    previous = AgentReport(
        event_id="agent-1:old-boot:0",
        agent_id="agent-1",
        boot_id="old-boot",
        sequence=0,
        observed_at=NOW - timedelta(minutes=10),
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UNKNOWN,
        duration_ms=1,
    )
    dependencies.sequence_store.next()
    dependencies.pending_store.save(previous.model_dump(mode="json"))

    current = await run_cycle(settings, dependencies)

    assert sender.calls == [previous.event_id, current.event_id]
    assert dependencies.pending_store.load() is None


@pytest.mark.asyncio
async def test_stale_concurrent_cycle_skips_delivery_and_cannot_clear_newer_outbox(tmp_path):
    """A delayed lower-sequence cycle must not arrive after or own a newer event."""
    settings = _settings()
    sender = RecordingSender()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=sender,
        prober=None,
    )
    newer = AgentReport(
        event_id="agent-1:newer-boot:1",
        agent_id="agent-1",
        boot_id="newer-boot",
        sequence=1,
        observed_at=NOW,
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UNKNOWN,
        duration_ms=1,
    )
    dependencies.pending_store.save(newer.model_dump(mode="json"))

    stale = await run_cycle(settings, dependencies)

    assert stale.sequence == 0
    assert sender.reports == []
    pending = AgentReport.model_validate(dependencies.pending_store.load())
    assert pending.event_id == newer.event_id


@pytest.mark.asyncio
async def test_delayed_old_cycle_cannot_send_after_newer_successful_clear(tmp_path):
    """The delivered high-water tombstone must reject a resumed older cycle."""
    path = tmp_path / "pending-report.json"
    newer_store = PendingReportStore(path)
    newer = AgentReport(
        event_id="agent-1:newer-boot:1",
        agent_id="agent-1",
        boot_id="newer-boot",
        sequence=1,
        observed_at=NOW,
        refresh_state="UNAVAILABLE",
        control_status=ResultStatus.UNKNOWN,
        duration_ms=1,
    )
    assert newer_store.save(newer.model_dump(mode="json")) is True
    assert newer_store.clear(newer.event_id) is True
    assert newer_store.load() is None

    sender = RecordingSender()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=sender,
        prober=None,
    )
    dependencies.pending_store = PendingReportStore(path)

    older = await run_cycle(_settings(), dependencies)

    assert older.sequence == 0
    assert sender.reports == []
    restarted = PendingReportStore(path)
    assert restarted.load() is None
    assert restarted.save(older.model_dump(mode="json")) is False


@pytest.mark.asyncio
async def test_newer_cycle_sends_and_clears_before_paused_old_cycle_resumes(tmp_path):
    """Ownership from save must be revalidated after a newer delivered tombstone."""
    old_loaded = threading.Event()
    newer_loaded = threading.Event()
    release_old_load = threading.Event()
    release_newer_load = threading.Event()
    old_saved = threading.Event()
    release_old_save = threading.Event()

    class OrchestratedStore(PendingReportStore):
        def __init__(self, path, *, loaded, release_load, pause_after_save=False):
            super().__init__(path)
            self._loaded = loaded
            self._release_load = release_load
            self._pause_after_save = pause_after_save
            self._first_load = True

        def load(self):
            value = super().load()
            if self._first_load:
                self._first_load = False
                assert value is None
                self._loaded.set()
                assert self._release_load.wait(timeout=5)
            return value

        def save(self, report):
            outcome = super().save(report)
            if self._pause_after_save:
                old_saved.set()
                assert release_old_save.wait(timeout=5)
            return outcome

    path = tmp_path / "pending-report.json"
    old_sender = RecordingSender()
    newer_sender = RecordingSender()
    old_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=old_sender,
        prober=None,
    )
    old_dependencies.pending_store = OrchestratedStore(
        path,
        loaded=old_loaded,
        release_load=release_old_load,
        pause_after_save=True,
    )
    newer_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=newer_sender,
        prober=None,
    )
    newer_dependencies.pending_store = OrchestratedStore(
        path,
        loaded=newer_loaded,
        release_load=release_newer_load,
    )

    old_task = asyncio.create_task(
        asyncio.to_thread(lambda: asyncio.run(run_cycle(_settings(), old_dependencies)))
    )
    newer_task = None
    try:
        assert await asyncio.to_thread(old_loaded.wait, 5)
        newer_task = asyncio.create_task(
            asyncio.to_thread(
                lambda: asyncio.run(run_cycle(_settings(), newer_dependencies))
            )
        )
        assert await asyncio.to_thread(newer_loaded.wait, 5)
        release_old_load.set()
        assert await asyncio.to_thread(old_saved.wait, 5)
        release_newer_load.set()
        newer = await newer_task
        assert [report.sequence for report in newer_sender.reports] == [newer.sequence]
        release_old_save.set()
        older = await old_task
    finally:
        release_old_load.set()
        release_newer_load.set()
        release_old_save.set()
        tasks = [task for task in (old_task, newer_task) if task is not None]
        for task in tasks:
            with suppress(BaseException):
                await task

    assert [older.sequence, newer.sequence] == [0, 1]
    assert old_sender.reports == []
    assert PendingReportStore(path).load() is None


@pytest.mark.asyncio
async def test_newer_sender_waits_while_older_holds_delivery_lock(tmp_path):
    """A newer writer may save during I/O but cannot reach the collector first."""
    first_send_started = asyncio.Event()
    release_first_send = asyncio.Event()
    newer_saved = asyncio.Event()
    order: list[tuple[str, int]] = []

    class BlockingSender:
        async def send(self, report):
            order.append(("old-sender", report.sequence))
            first_send_started.set()
            await release_first_send.wait()

    class OrderedSender:
        async def send(self, report):
            order.append(("new-sender", report.sequence))

    class SignalingStore(PendingReportStore):
        def save(self, report):
            outcome = super().save(report)
            if report["sequence"] == 1:
                newer_saved.set()
            return outcome

    old_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=BlockingSender(),
        prober=None,
    )
    newer_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=OrderedSender(),
        prober=None,
    )
    newer_dependencies.pending_store = SignalingStore(
        tmp_path / "pending-report.json"
    )

    old_task = asyncio.create_task(run_cycle(_settings(), old_dependencies))
    newer_task = None
    try:
        await asyncio.wait_for(first_send_started.wait(), timeout=5)
        newer_task = asyncio.create_task(run_cycle(_settings(), newer_dependencies))
        await asyncio.wait_for(newer_saved.wait(), timeout=5)
        await asyncio.sleep(0.05)
        assert order == [("old-sender", 0)]
        release_first_send.set()
        await asyncio.gather(old_task, newer_task)
    finally:
        release_first_send.set()
        tasks = [task for task in (old_task, newer_task) if task is not None]
        for task in tasks:
            with suppress(BaseException):
                await task

    assert order == [
        ("old-sender", 0),
        ("new-sender", 0),
        ("new-sender", 1),
    ]
    assert PendingReportStore(tmp_path / "pending-report.json").load() is None


@pytest.mark.asyncio
async def test_sequence_and_event_id_increase_across_cycles_and_restart(tmp_path):
    """Resetting sequence on a new store instance would break collector idempotency."""
    settings = _settings()
    first_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=RecordingSender(None),
        prober=None,
    )
    first = await run_cycle(settings, first_dependencies)
    restarted_dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fetch failed")),
        sender=RecordingSender(None),
        prober=None,
    )
    second = await run_cycle(settings, restarted_dependencies)

    assert [first.sequence, second.sequence] == [0, 1]
    assert first.event_id == "agent-1:boot-1:0"
    assert second.event_id == "agent-1:boot-1:1"


class AdvancingClock(StaticClock):
    def __init__(self):
        super().__init__(monotonic=0.0)
        self.control_starts: list[float] = []
        self.sleeps: list[float] = []

    async def control(self) -> ControlResult:
        self.control_starts.append(self.monotonic_value)
        self.monotonic_value += 7.0
        return ControlResult(ok=True)

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.monotonic_value += delay


@pytest.mark.asyncio
async def test_agent_starts_immediately_and_schedules_from_slow_cycle_completion(tmp_path):
    """Anchoring to old deadlines would overlap or catch up after a slow cycle."""
    settings = _settings(interval_seconds=10)
    clock = AdvancingClock()
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fail"), RuntimeError("fail")),
        sender=RecordingSender(None, None),
        prober=None,
        control_checker=clock.control,
        clock=clock,
    )
    dependencies.sleep = clock.sleep

    reports = await run_agent(
        settings,
        dependencies=dependencies,
        max_cycles=2,
    )

    assert [report.sequence for report in reports] == [0, 1]
    assert clock.control_starts == [0.0, 17.0]
    assert clock.sleeps == [10.0]


@pytest.mark.asyncio
async def test_agent_continues_after_delivery_lock_timeout_and_retries_next_cycle(
    tmp_path,
):
    """Expected delivery contention must finish the cycle without killing the daemon."""
    path = tmp_path / "pending-report.json"
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_delivery_lock_for_agent_test,
        args=(str(path), acquired, release),
    )
    holder.start()
    assert await asyncio.to_thread(acquired.wait, 5)

    settings = _settings(interval_seconds=3)
    clock = StaticClock(monotonic=0.0)
    sender = RecordingSender()
    pending = PendingReportStore(path, lock_timeout=0.05)
    sleeps: list[float] = []
    durable_at_sleep: list[int] = []
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(RuntimeError("fail"), RuntimeError("fail")),
        sender=sender,
        prober=None,
        clock=clock,
    )
    dependencies.pending_store = pending

    async def release_during_scheduled_sleep(delay: float) -> None:
        sleeps.append(delay)
        durable = pending.load()
        assert durable is not None
        durable_at_sleep.append(durable["sequence"])
        assert sender.reports == []
        release.set()
        await asyncio.to_thread(holder.join, 5)
        clock.monotonic_value += delay

    dependencies.sleep = release_during_scheduled_sleep

    try:
        reports = await run_agent(
            settings,
            dependencies=dependencies,
            max_cycles=2,
        )
    finally:
        release.set()
        await asyncio.to_thread(holder.join, 5)

    assert holder.exitcode == 0
    assert [report.sequence for report in reports] == [0, 1]
    assert durable_at_sleep == [0]
    assert sleeps == [3.0]
    assert [report.sequence for report in sender.reports] == [0, 1]
    assert pending.load() is None
    serialized = "".join(report.model_dump_json() for report in reports)
    assert settings.agent_token.get_secret_value() not in serialized


@pytest.mark.asyncio
async def test_cycle_does_not_mask_write_ahead_or_state_corruption_failures(tmp_path):
    class FailingSaveStore(PendingReportStore):
        def save(self, report):
            del report
            raise StateError("local state cannot be written")

    class CorruptingStore(PendingReportStore):
        def is_pending(self, event_id, sequence):
            del event_id, sequence
            raise StateError("pending report state is malformed")

    for store, message in (
        (
            FailingSaveStore(tmp_path / "write-failure.json"),
            "local state cannot be written",
        ),
        (
            CorruptingStore(tmp_path / "corrupt.json"),
            "pending report state is malformed",
        ),
    ):
        dependencies = _dependencies(
            tmp_path,
            fetcher=FakeFetcher(RuntimeError("fail")),
            sender=RecordingSender(),
            prober=None,
        )
        dependencies.pending_store = store
        with pytest.raises(StateError, match=rf"^{message}$"):
            await run_cycle(_settings(), dependencies)


@pytest.mark.asyncio
async def test_agent_keeps_prober_deadline_evidence_and_never_overlaps_next_cycle(tmp_path):
    """A duplicate outer deadline would cancel cleanup and erase completed target evidence."""
    settings = _settings(interval_seconds=1, run_deadline_seconds=1)
    clock = AdvancingClock()
    clock.control = lambda: _async_value(ControlResult(ok=True))

    class DeadlineFetcher(FakeFetcher):
        async def fetch(self) -> bytes:
            payload = await super().fetch()
            clock.monotonic_value += 0.99
            return payload

    active = 0
    maximum = 0

    async def authoritative_prober(targets, control, deadline):
        nonlocal active, maximum
        del control
        assert deadline == pytest.approx(0.01)
        active += 1
        maximum = max(maximum, active)
        try:
            await asyncio.sleep(0.02)
            return [
                _up_result(targets[0]),
                ProbeResult(
                    target_id=targets[1].target_id,
                    label=targets[1].label,
                    address=targets[1].address,
                    port=targets[1].port,
                    status=ResultStatus.UNKNOWN,
                    stage=ProbeStage.DEADLINE,
                    error_code="deadline",
                ),
            ]
        finally:
            active -= 1

    dependencies = _dependencies(
        tmp_path,
        fetcher=DeadlineFetcher(_subscription(1, 2), _subscription(1, 2)),
        sender=RecordingSender(None, None),
        prober=authoritative_prober,
        control_checker=clock.control,
        clock=clock,
    )
    dependencies.sleep = clock.sleep

    reports = await run_agent(settings, dependencies=dependencies, max_cycles=2)

    assert maximum == 1
    assert active == 0
    assert [report.results[0].status for report in reports] == [
        ResultStatus.UP,
        ResultStatus.UP,
    ]
    assert [report.results[1].stage for report in reports] == [
        ProbeStage.DEADLINE,
        ProbeStage.DEADLINE,
    ]


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


@pytest.mark.asyncio
async def test_subscription_fetcher_streams_with_cap_and_does_not_follow_redirects():
    """Buffering or following redirects could exceed memory bounds or disclose the private URL."""
    requests: list[httpx.Request] = []

    async def oversized(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, stream=ChunkStream([b"1234", b"5678"]))

    with pytest.raises(SubscriptionFetchError) as raised:
        await SubscriptionFetcher(
            "https://subscription.example/private?token=hidden",
            max_bytes=6,
            transport=httpx.MockTransport(oversized),
        ).fetch()

    redirect_requests: list[httpx.Request] = []

    async def redirect(request: httpx.Request) -> httpx.Response:
        redirect_requests.append(request)
        return httpx.Response(
            302,
            headers={"location": "https://attacker.invalid/steal"},
        )

    with pytest.raises(SubscriptionFetchError) as redirect_error:
        await SubscriptionFetcher(
            "https://subscription.example/private?token=hidden",
            max_bytes=64,
            transport=httpx.MockTransport(redirect),
        ).fetch()

    assert raised.value.error_code == "subscription-too-large"
    assert redirect_error.value.error_code == "subscription-http-302"
    assert len(requests) == 1
    assert len(redirect_requests) == 1
    assert "hidden" not in str(raised.value)
    assert "hidden" not in str(redirect_error.value)


@pytest.mark.asyncio
async def test_subscription_fetcher_sanitizes_unexpected_transport_errors():
    """An unusual HTTP boundary failure must not expose its URL or message upstream."""

    async def broken(request: httpx.Request) -> httpx.Response:
        del request
        raise RuntimeError("https://secret.invalid/?token=private")

    with pytest.raises(SubscriptionFetchError) as raised:
        await SubscriptionFetcher(
            "https://subscription.example/private?token=hidden",
            max_bytes=64,
            transport=httpx.MockTransport(broken),
        ).fetch()

    assert raised.value.error_code == "subscription-network"
    assert str(raised.value) == "subscription-network"


@pytest.mark.asyncio
async def test_subscription_fetcher_hides_secret_url_and_rejects_real_gzip_expansion(
    caplog,
):
    """The private path must stay below HTTPX logs and compressed bodies must fail closed."""
    authority = trustme.CA()
    certificate = authority.issue_cert("127.0.0.1")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    authority.configure_trust(client_context)
    request_lines: list[bytes] = []
    compressed = gzip.compress(b"x" * 100_000)

    async def serve(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            request_lines.append(request.split(b"\r\n", 1)[0])
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(compressed)}\r\n".encode()
                + b"Content-Encoding: gzip\r\nConnection: close\r\n\r\n"
                + compressed
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    secret_path = "private-path-token"
    caplog.set_level(logging.DEBUG)
    try:
        with pytest.raises(SubscriptionFetchError) as raised:
            await SubscriptionFetcher(
                f"https://127.0.0.1:{port}/{secret_path}?access=hidden-query",
                max_bytes=256,
                transport=httpx.AsyncHTTPTransport(verify=client_context),
            ).fetch()
    finally:
        server.close()
        await server.wait_closed()

    assert raised.value.error_code == "subscription-content-encoding-invalid"
    assert len(request_lines) == 1
    assert re.fullmatch(
        rb"GET /private-path-token\?access=hidden-query&_lc_nonce="
        rb"[A-Za-z0-9_-]{16,64} HTTP/1\.1",
        request_lines[0],
    )
    rendered_logs = "\n".join(
        record.getMessage() + repr(record.args) + repr(record.exc_info)
        for record in caplog.records
    )
    assert secret_path not in rendered_logs
    assert "hidden-query" not in rendered_logs


@pytest.mark.asyncio
async def test_subscription_fetcher_caps_raw_identity_bytes_and_sets_identity_header():
    """Decoded streaming can allocate beyond the application cap before it is checked."""
    requests: list[httpx.Request] = []

    async def oversized(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Encoding": "identity"},
            stream=ChunkStream([b"1234", b"5678"]),
        )

    with pytest.raises(SubscriptionFetchError) as raised:
        await SubscriptionFetcher(
            "https://subscription.example/secret",
            max_bytes=6,
            transport=httpx.MockTransport(oversized),
        ).fetch()

    assert raised.value.error_code == "subscription-too-large"
    assert requests[0].headers["accept-encoding"] == "identity"


@pytest.mark.asyncio
@pytest.mark.parametrize("http_status", [200, 503])
async def test_subscription_fetch_closes_injected_transport_after_each_request(http_status):
    closed = []

    class ClosingTransport(httpx.MockTransport):
        async def aclose(self):
            closed.append(True)
            await super().aclose()

    fetcher = SubscriptionFetcher(
        "https://subscription.example/private", max_bytes=64,
        transport=ClosingTransport(lambda request: httpx.Response(
            http_status, stream=ChunkStream([b"fresh"]),
        )),
    )
    for _ in range(2):
        if http_status == 200:
            assert await fetcher.fetch() == b"fresh"
        else:
            with pytest.raises(SubscriptionFetchError):
                await fetcher.fetch()
    assert closed == [True, True]


@pytest.mark.asyncio
async def test_subscription_fetcher_adds_fresh_nonce_and_preserves_raw_secret_query(
    caplog, monkeypatch,
):
    requests: list[httpx.Request] = []
    nonces = iter(("fresh_nonce_00000001", "fresh_nonce_00000002"))
    monkeypatch.setattr(agent_module.secrets, "token_urlsafe", lambda size: next(nonces))

    async def fresh(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"Age": "0"}, stream=ChunkStream([b"fresh"]))

    caplog.set_level(logging.DEBUG)
    fetcher = SubscriptionFetcher(
        "https://user:password@subscription.example/private?token=a%2Fb&token=second&_lc_nonce=existing",
        max_bytes=64,
        transport=httpx.MockTransport(fresh),
    )

    assert await fetcher.fetch() == b"fresh"
    assert await fetcher.fetch() == b"fresh"

    queries = [request.url.query for request in requests]
    prefix = b"token=a%2Fb&token=second&_lc_nonce=existing&"
    assert all(query.startswith(prefix) for query in queries)
    assert all(query.count(b"_lc_nonce=") == 2 for query in queries)
    assert queries == [
        prefix + b"_lc_nonce=fresh_nonce_00000001",
        prefix + b"_lc_nonce=fresh_nonce_00000002",
    ]
    assert all(request.url.username == "user" and request.url.password == "password" for request in requests)
    assert all(request.headers["cache-control"] == "no-cache,no-store,max-age=0" for request in requests)
    assert all(request.headers["pragma"] == "no-cache" for request in requests)
    rendered_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert "password" not in rendered_logs
    assert "a%2Fb" not in rendered_logs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("age_headers", "error_code"),
    [
        (["1"], "subscription-response-stale"),
        (["999"], "subscription-response-stale"),
        (["-1"], "subscription-response-invalid"),
        (["unknown"], "subscription-response-invalid"),
        (["0, 1"], "subscription-response-invalid"),
        (["0", "0"], "subscription-response-invalid"),
    ],
)
async def test_subscription_fetcher_rejects_positive_malformed_or_duplicate_age(
    age_headers, error_code,
):
    async def response(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers=[("Age", value) for value in age_headers],
            stream=ChunkStream([b"must-not-be-accepted"]),
        )

    with pytest.raises(SubscriptionFetchError) as raised:
        await SubscriptionFetcher(
            "https://subscription.example/private",
            max_bytes=64,
            transport=httpx.MockTransport(response),
        ).fetch()

    assert raised.value.error_code == error_code


@pytest.mark.asyncio
async def test_subscription_fetcher_never_accepts_http_not_modified():
    async def not_modified(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(304, headers={"Age": "0"})

    with pytest.raises(SubscriptionFetchError) as raised:
        await SubscriptionFetcher(
            "https://subscription.example/private",
            max_bytes=64,
            transport=httpx.MockTransport(not_modified),
        ).fetch()

    assert raised.value.error_code == "subscription-http-304"


@pytest.mark.asyncio
async def test_xray_version_mismatch_is_visible_and_skips_target_probe(tmp_path):
    """Running an unexpected Xray build cannot create a false target DOWN verdict."""
    async def sni_only(targets, control, deadline):
        assert targets and all(target.check_kind == "sni" for target in targets)
        return [_up_result(target) for target in targets]

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1)),
        sender=RecordingSender(None),
        prober=sni_only,
    )
    dependencies.version_checker = lambda: _async_value(
        XrayVersionResult(
            version="99.0.0",
            compatible=False,
            error_code="xray-version-mismatch",
        )
    )

    report = await run_cycle(_settings(), dependencies)

    assert report.xray_version == "99.0.0"
    assert report.run_status is ResultStatus.UNKNOWN
    assert report.run_reason == "xray-version-mismatch"
    assert [(item.status, item.stage, item.error_code) for item in report.results] == [
        (ResultStatus.UNKNOWN, ProbeStage.XRAY, "xray-version-mismatch"),
        (ResultStatus.UP, ProbeStage.TLS, None),
    ]


@pytest.mark.asyncio
async def test_xray_version_unavailable_is_unknown_and_skips_target_probe(tmp_path):
    """A missing version proof is an agent/Xray uncertainty, not endpoint downtime."""
    async def sni_only(targets, control, deadline):
        assert targets and all(target.check_kind == "sni" for target in targets)
        return [_up_result(target) for target in targets]

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(_subscription(1)),
        sender=RecordingSender(None),
        prober=sni_only,
    )
    dependencies.version_checker = lambda: _async_value(
        XrayVersionResult(
            version=None,
            compatible=False,
            error_code="xray-version-unavailable",
        )
    )

    report = await run_cycle(_settings(), dependencies)

    assert report.xray_version is None
    assert report.run_reason == "xray-version-unavailable"
    assert report.results[0].status is ResultStatus.UNKNOWN
    assert report.results[0].stage is ProbeStage.XRAY
    assert report.results[1].check_kind == "sni"
    assert report.results[1].stage is ProbeStage.TLS


@pytest.mark.asyncio
async def test_query_xray_version_is_bounded_and_accepts_exact_expected_build(tmp_path):
    """Version discovery must use argv safely and return only the parsed version token."""
    executable = tmp_path / "xray"
    executable.write_text(
        "#!/bin/sh\nprintf 'Xray 26.3.27 (synthetic)\\nprivate trailing output\\n'\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    result = await query_xray_version(
        executable, expected_version="26.3.27", timeout=1, output_limit=128
    )

    assert result == XrayVersionResult("26.3.27", True, None)
    assert "private" not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rendered",
    ("26.3.27.1", "26.3.27-custom", "26.3.27junk"),
)
async def test_query_xray_version_rejects_non_exact_semver_token(tmp_path, rendered):
    """A prefix match must not bless a customized or otherwise different Xray build."""
    executable = tmp_path / "xray"
    executable.write_text(
        f"#!/bin/sh\nprintf 'Xray {rendered}\\n'\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    result = await query_xray_version(executable, expected_version="26.3.27")

    assert result == XrayVersionResult(None, False, "xray-version-unavailable")


@pytest.mark.asyncio
async def test_query_xray_version_cancellation_reaps_child_process(monkeypatch):
    """Daemon shutdown must not leave a hung version subprocess behind."""
    released = asyncio.Event()

    class HangingProcess:
        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.returncode = None
            self.killed = False

        async def wait(self):
            await released.wait()
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9
            released.set()

    process = HangingProcess()

    async def create_process(*args, **kwargs):
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    task = asyncio.create_task(
        query_xray_version("xray", expected_version="26.3.27", timeout=60)
    )
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed


@pytest.mark.asyncio
async def test_agent_once_fails_closed_until_current_event_is_accepted(tmp_path):
    """A durable pending report is not collector acceptance for one-shot enrollment."""
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(SubscriptionFetchError("subscription-network")),
        sender=RecordingSender(DeliveryError("collector-network")),
        prober=None,
    )

    with pytest.raises(CurrentReportNotAccepted):
        await run_agent(_settings(), once=True, dependencies=dependencies)

    assert dependencies.pending_store.load()["event_id"] == "agent-1:boot-1:0"


@pytest.mark.asyncio
async def test_agent_once_succeeds_only_after_current_event_ack(tmp_path):
    """A successful current collector response is the enrollment success boundary."""
    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(SubscriptionFetchError("subscription-network")),
        sender=RecordingSender(None),
        prober=None,
    )

    report = await run_agent(_settings(), once=True, dependencies=dependencies)

    assert dependencies.last_accepted_event_id == report.event_id
    assert dependencies.pending_store.load() is None


@pytest.mark.asyncio
async def test_collector_ack_health_uses_wall_time_after_acceptance(tmp_path):
    """The live ACK path must exist and timestamp the completed collector response."""
    clock = StaticClock()

    class AdvancingSender:
        async def send(self, report: AgentReport) -> None:
            del report
            clock.now += timedelta(seconds=30)

    dependencies = _dependencies(
        tmp_path,
        fetcher=FakeFetcher(SubscriptionFetchError("subscription-network")),
        sender=AdvancingSender(),
        prober=None,
        clock=clock,
    )
    dependencies.ack_store = CollectorAckStore(tmp_path / "collector-ack.json")

    report = await run_agent(_settings(), once=True, dependencies=dependencies)

    assert dependencies.last_accepted_event_id == report.event_id
    assert dependencies.ack_store.is_recent(clock.now, max_age_seconds=1)

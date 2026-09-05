"""One complete probe cycle and a monotonic, non-overlapping agent daemon."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from litechecker.config import AgentSettings
from litechecker.models import (
    AgentReport,
    ProbeResult,
    ProbeStage,
    ResultStatus,
    Snapshot,
    SnapshotDiff,
    TargetConfig,
)
from litechecker.probe import ControlResult, check_control, probe_all
from litechecker.protocol import CollectorClient
from litechecker.state import (
    CollectorAckStore,
    DeliveryLockUnavailable,
    PendingReportStore,
    SequenceStore,
    SnapshotStore,
)
from litechecker.subscription import parse_xray_subscription


class SubscriptionFetchError(RuntimeError):
    """A subscription transport failure represented only by a closed error code."""

    def __init__(self, error_code: str):
        super().__init__(error_code)
        self.error_code = error_code


class CurrentReportNotAccepted(RuntimeError):
    """One-shot mode did not receive collector acceptance for its current event."""

    def __init__(self) -> None:
        super().__init__("current-report-not-accepted")


@dataclass(frozen=True)
class XrayVersionResult:
    version: str | None
    compatible: bool
    error_code: str | None


class SubscriptionSource(Protocol):
    async def fetch(self) -> bytes: ...


class ReportSender(Protocol):
    async def send(self, report: AgentReport) -> Any: ...


ControlChecker = Callable[[], Awaitable[ControlResult]]
TargetProber = Callable[
    [Sequence[TargetConfig], ControlResult, float], Awaitable[list[ProbeResult]]
]
XrayVersionChecker = Callable[[], Awaitable[XrayVersionResult]]
Parser = Callable[[bytes, str | bytes, int], list[TargetConfig]]


class SubscriptionFetcher:
    """Fetch exactly one configured HTTPS URL with redirects and buffering disabled."""

    def __init__(
        self,
        url: str,
        *,
        max_bytes: int,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except (TypeError, ValueError):
            raise ValueError("subscription URL is invalid") from None
        del port
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("subscription URL must be HTTPS")
        if max_bytes < 1:
            raise ValueError("subscription size limit must be positive")
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("subscription timeouts must be positive")
        self._url = "https://subscription.invalid/fetch"
        self._max_bytes = max_bytes
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._target_url = url
        self._transport = transport

    async def fetch(self) -> bytes:
        try:
            nonce = secrets.token_urlsafe(18)
            base_transport = self._transport or httpx.AsyncHTTPTransport()
            routing_transport = _SecretRoutingTransport(
                self._target_url,
                base_transport,
            )
            async with httpx.AsyncClient(
                timeout=self._timeout,
                transport=routing_transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "GET",
                    f"{self._url}?_lc_nonce={nonce}",
                    headers={
                        "Accept-Encoding": "identity",
                        "Cache-Control": "no-cache,no-store,max-age=0",
                        "Pragma": "no-cache",
                    },
                ) as response:
                    if response.status_code != 200:
                        raise SubscriptionFetchError(
                            f"subscription-http-{response.status_code}"
                        )
                    encodings = [
                        value.strip().lower()
                        for value in response.headers.get_list(
                            "content-encoding", split_commas=True
                        )
                    ]
                    if encodings and encodings != ["identity"]:
                        raise SubscriptionFetchError(
                            "subscription-content-encoding-invalid"
                        )
                    ages = response.headers.get_list("age")
                    if ages:
                        if len(ages) != 1 or re.fullmatch(r"[0-9]+", ages[0]) is None:
                            raise SubscriptionFetchError("subscription-response-invalid")
                        if int(ages[0]) > 0:
                            raise SubscriptionFetchError("subscription-response-stale")
                    content_lengths = response.headers.get_list("content-length")
                    if content_lengths:
                        if (
                            len(content_lengths) != 1
                            or re.fullmatch(r"[0-9]+", content_lengths[0]) is None
                        ):
                            raise SubscriptionFetchError("subscription-response-invalid")
                        if int(content_lengths[0]) > self._max_bytes:
                            raise SubscriptionFetchError("subscription-too-large")

                    payload = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(payload) + len(chunk) > self._max_bytes:
                            raise SubscriptionFetchError("subscription-too-large")
                        payload.extend(chunk)
                    return bytes(payload)
        except SubscriptionFetchError:
            raise
        except httpx.TimeoutException:
            raise SubscriptionFetchError("subscription-timeout") from None
        except httpx.HTTPError:
            raise SubscriptionFetchError("subscription-network") from None
        except Exception:
            raise SubscriptionFetchError("subscription-network") from None


class _SecretRoutingTransport(httpx.AsyncBaseTransport):
    """Route below HTTPX logging so the configured private URL is never rendered."""

    def __init__(
        self,
        target_url: str,
        transport: httpx.AsyncBaseTransport | None,
    ):
        self._target_url = target_url
        self._transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        headers = [
            (name, value)
            for name, value in request.headers.raw
            if name.lower() != b"host"
        ]
        nonce_values = request.url.params.get_list("_lc_nonce")
        if (
            len(nonce_values) != 1
            or re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce_values[0]) is None
        ):
            raise httpx.RequestError("invalid private freshness nonce", request=request)
        target = self._target_url.partition("#")[0]
        separator = "?" if "?" not in target else "" if target.endswith(("?", "&")) else "&"
        target = f"{target}{separator}_lc_nonce={nonce_values[0]}"
        routed = httpx.Request(
            request.method,
            target,
            headers=headers,
            content=request.content,
            extensions=request.extensions,
        )
        return await self._transport.handle_async_request(routed)

    async def aclose(self) -> None:
        await self._transport.aclose()


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
    """Refresh, probe, report, and retain the newest failed delivery."""
    started = dependencies.monotonic()
    observed_at = _utc(dependencies.wall_clock())
    control = await _run_control(
        dependencies.control_checker,
        _remaining(settings.run_deadline_seconds, started, dependencies.monotonic),
    )

    snapshot: Snapshot | None = None
    diff = SnapshotDiff()
    refresh_state = "UNAVAILABLE"
    try:
        remaining = _remaining(
            settings.run_deadline_seconds, started, dependencies.monotonic
        )
        if remaining <= 0:
            raise SubscriptionFetchError("subscription-deadline")
        payload = await asyncio.wait_for(dependencies.fetcher.fetch(), timeout=remaining)
        targets = dependencies.parser(
            payload,
            settings.state_key.get_secret_value(),
            settings.max_endpoints,
        )
        decision = dependencies.snapshot_store.consider(targets, observed_at)
        if not decision.activated:
            raise RuntimeError("subscription-candidate-not-activated")
        snapshot = decision.snapshot
        diff = decision.diff
        refresh_state = "FRESH"
    except Exception:
        snapshot = None
        refresh_state = "UNAVAILABLE"

    xray_info = XrayVersionResult(version=None, compatible=True, error_code=None)
    if snapshot is None:
        results: list[ProbeResult] = []
        report_control_status = ResultStatus.UP if control.ok else ResultStatus.UNKNOWN
        run_status = ResultStatus.UNKNOWN
        run_reason = "no-valid-snapshot"
        revision = None
        snapshot_age = None
    else:
        report_control_status = (
            ResultStatus.UP if control.ok else ResultStatus.UNKNOWN
        )
        run_status = ResultStatus.UP if control.ok else ResultStatus.UNKNOWN
        run_reason = None if control.ok else "agent-network"
        if control.ok and dependencies.version_checker is not None:
            remaining = _remaining(
                settings.run_deadline_seconds, started, dependencies.monotonic
            )
            try:
                xray_info = await asyncio.wait_for(
                    dependencies.version_checker(), timeout=remaining
                )
            except Exception:
                xray_info = XrayVersionResult(
                    version=None,
                    compatible=False,
                    error_code="xray-version-unavailable",
                )
        if not xray_info.compatible:
            error_code = xray_info.error_code or "xray-version-unavailable"
            vpn_targets = [target for target in snapshot.targets if target.check_kind == "vpn"]
            sni_targets = [target for target in snapshot.targets if target.check_kind == "sni"]
            results = _unknown_results(vpn_targets, ProbeStage.XRAY, error_code)
            if sni_targets:
                remaining = _remaining(
                    settings.run_deadline_seconds, started, dependencies.monotonic
                )
                results.extend(await _run_probes(
                    sni_targets, control, remaining, dependencies.prober,
                ))
            run_status = ResultStatus.UNKNOWN
            run_reason = error_code
        else:
            remaining = _remaining(
                settings.run_deadline_seconds, started, dependencies.monotonic
            )
            results = await _run_probes(
                snapshot.targets,
                control,
                remaining,
                dependencies.prober,
            )
            run_status, run_reason = _reconcile_run_status(
                results, run_status, run_reason
            )
        revision = snapshot.subscription_revision
        snapshot_age = _snapshot_age(observed_at, snapshot)

    sequence = dependencies.sequence_store.next()
    previous_pending = dependencies.pending_store.load()
    duration_ms = max(
        0,
        int((dependencies.monotonic() - started) * 1000),
    )
    report = AgentReport(
        event_id=f"{settings.agent_id}:{dependencies.boot_id}:{sequence}",
        agent_id=settings.agent_id,
        boot_id=dependencies.boot_id,
        sequence=sequence,
        observed_at=observed_at,
        subscription_revision=revision,
        refresh_state=refresh_state,
        snapshot_age_seconds=snapshot_age,
        diff=diff,
        results=results,
        control_status=report_control_status,
        run_status=run_status,
        run_reason=run_reason,
        duration_ms=duration_ms,
        xray_version=xray_info.version,
    )
    owns_outbox = dependencies.pending_store.save(report.model_dump(mode="json"))
    if not owns_outbox:
        return report

    try:
        delivered_report, accepted = await _deliver_current(
            report,
            previous_pending,
            dependencies.pending_store,
            dependencies.sender,
        )
        if accepted:
            dependencies.last_accepted_event_id = delivered_report.event_id
            if dependencies.ack_store is not None:
                dependencies.ack_store.record(
                    delivered_report.event_id, _utc(dependencies.wall_clock())
                )
        return delivered_report
    except DeliveryLockUnavailable:
        return report


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
    state_dir = state_dir if state_dir is not None else Path(os.environ.get("LC_STATE_DIR", "/var/lib/litechecker"))
    state_key = settings.state_key.get_secret_value()

    async def control_checker() -> ControlResult:
        return await check_control(timeout=min(5.0, settings.probe_timeout_seconds))

    async def prober(
        targets: Sequence[TargetConfig],
        control: ControlResult,
        deadline: float,
    ) -> list[ProbeResult]:
        return await probe_all(
            targets,
            control=control,
            max_concurrency=settings.max_concurrency,
            deadline_seconds=deadline,
            allow_private_targets=settings.allow_private_targets,
            tcp_timeout=settings.tcp_timeout_seconds,
            probe_timeout=settings.probe_timeout_seconds,
            xray_binary=settings.xray_binary,
        )

    async def version_checker() -> XrayVersionResult:
        return await query_xray_version(
            settings.xray_binary,
            expected_version=settings.expected_xray_version,
        )

    return AgentDependencies(
        fetcher=SubscriptionFetcher(
            settings.subscription_url.get_secret_value(),
            max_bytes=settings.max_subscription_bytes,
        ),
        snapshot_store=SnapshotStore(state_dir, state_key=state_key),
        sequence_store=SequenceStore(state_dir / "sequence.json"),
        pending_store=PendingReportStore(state_dir / "pending-report.json"),
        ack_store=CollectorAckStore(state_dir / "collector-ack.json"),
        control_checker=control_checker,
        prober=prober,
        sender=CollectorClient(
            settings.collector_url,
            settings.agent_token.get_secret_value(),
            allow_insecure_loopback=settings.allow_insecure_collector,
        ),
        wall_clock=lambda: datetime.now(UTC),
        monotonic=time.monotonic,
        sleep=asyncio.sleep,
        boot_id=str(uuid.uuid4()),
        version_checker=version_checker,
    )


async def _run_control(
    checker: ControlChecker,
    deadline: float,
) -> ControlResult:
    if deadline <= 0:
        return ControlResult(ok=False, error_code="control-failed")
    try:
        return await asyncio.wait_for(checker(), timeout=deadline)
    except Exception:
        return ControlResult(ok=False, error_code="control-failed")


async def _run_probes(
    targets: Sequence[TargetConfig],
    control: ControlResult,
    deadline: float,
    prober: TargetProber | None,
) -> list[ProbeResult]:
    if deadline <= 0:
        return _unknown_results(targets, ProbeStage.DEADLINE, "deadline")
    if prober is None:
        return _unknown_results(targets, ProbeStage.XRAY, "probe-error")
    try:
        return await prober(targets, control, deadline)
    except TimeoutError:
        return _unknown_results(targets, ProbeStage.DEADLINE, "deadline")
    except Exception:
        return _unknown_results(targets, ProbeStage.XRAY, "probe-error")


def _reconcile_run_status(
    results: Sequence[ProbeResult],
    run_status: ResultStatus,
    run_reason: str | None,
) -> tuple[ResultStatus, str | None]:
    """Close only agent-local incomplete evidence; complete target failures remain valid."""
    if run_status is ResultStatus.UNKNOWN:
        return run_status, run_reason
    unknown_stages = {
        result.stage for result in results if result.status is ResultStatus.UNKNOWN
    }
    if ProbeStage.DEADLINE in unknown_stages:
        return ResultStatus.UNKNOWN, "deadline"
    if ProbeStage.XRAY in unknown_stages:
        return ResultStatus.UNKNOWN, "probe-incomplete"
    if ProbeStage.AGENT_NETWORK in unknown_stages:
        return ResultStatus.UNKNOWN, "agent-network"
    return run_status, run_reason


def _unknown_results(
    targets: Sequence[TargetConfig],
    stage: ProbeStage,
    error_code: str,
) -> list[ProbeResult]:
    return [
        ProbeResult(
            target_id=target.target_id,
            label=target.label,
            address=target.address,
            port=target.port,
            status=ResultStatus.UNKNOWN,
            stage=ProbeStage.POLICY if target.check_kind == "sni" and stage is ProbeStage.XRAY else stage,
            error_code=error_code,
            check_kind=target.check_kind,
        )
        for target in targets
    ]


def _remaining(
    deadline_seconds: float,
    started: float,
    monotonic: Callable[[], float],
) -> float:
    return max(0.0, float(deadline_seconds) - (monotonic() - started))


def _snapshot_age(observed_at: datetime, snapshot: Snapshot) -> int:
    try:
        return max(0, int((observed_at - _utc(snapshot.observed_at)).total_seconds()))
    except (TypeError, ValueError):
        return 0


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
        if not pending_store.is_pending(report.event_id, report.sequence):
            return report, False

        dropped_count = await _retry_pending(previous_pending, sender)
        if not pending_store.is_pending(report.event_id, report.sequence):
            return report, False
        if dropped_count:
            report = report.model_copy(update={"dropped_report_count": dropped_count})
            if not pending_store.replace_if_event(
                report.event_id,
                report.model_dump(mode="json"),
            ):
                return report, False

        if not pending_store.is_pending(report.event_id, report.sequence):
            return report, False
        try:
            await sender.send(report)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        else:
            pending_store.clear(report.event_id)
            return report, True
        return report, False


async def query_xray_version(
    binary: str | os.PathLike[str],
    *,
    expected_version: str,
    timeout: float = 2.0,
    output_limit: int = 4096,
) -> XrayVersionResult:
    """Return only a bounded parsed version; all failures are closed uncertainty."""
    if timeout <= 0 or output_limit < 1:
        raise ValueError("Xray version probe bounds are invalid")
    try:
        process = await asyncio.create_subprocess_exec(
            str(binary),
            "version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return XrayVersionResult(None, False, "xray-version-unavailable")
    reader = asyncio.create_task(_bounded_version_output(process.stdout, output_limit))
    try:
        async with asyncio.timeout(timeout):
            return_code, (body, overflow) = await asyncio.gather(
                process.wait(), reader
            )
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        raise
    except TimeoutError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        return XrayVersionResult(None, False, "xray-version-unavailable")
    if return_code != 0 or overflow:
        return XrayVersionResult(None, False, "xray-version-unavailable")
    match = re.search(
        rb"(?m)^Xray[ \t]+([0-9]+(?:\.[0-9]+){2})(?=[ \t\r\n]|$)",
        body,
    )
    if match is None:
        return XrayVersionResult(None, False, "xray-version-unavailable")
    version = match.group(1).decode("ascii")
    if version != expected_version:
        return XrayVersionResult(version, False, "xray-version-mismatch")
    return XrayVersionResult(version, True, None)


async def _bounded_version_output(
    stream: asyncio.StreamReader | None, limit: int
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    captured = bytearray()
    overflow = False
    while chunk := await stream.read(4096):
        remaining = max(0, limit - len(captured))
        if remaining:
            captured.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow = True
    return bytes(captured), overflow


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)

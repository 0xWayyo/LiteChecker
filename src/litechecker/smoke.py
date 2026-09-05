"""Cleanup-free subscription and Xray smoke checks with aggregate-only output."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence

from pydantic import ValidationError

from litechecker.agent import (
    SubscriptionFetcher,
    SubscriptionSource,
    XrayVersionChecker,
    XrayVersionResult,
    query_xray_version,
)
from litechecker.config import AgentSettings
from litechecker.models import ProbeResult, ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import DEFAULT_CANARIES, ControlResult, check_control, probe_all
from litechecker.runtime import run_with_signals
from litechecker.subscription import parse_xray_subscription


ControlChecker = Callable[..., Awaitable[ControlResult]]
TargetProber = Callable[..., Awaitable[list[ProbeResult]]]


class _SafeArgumentParser(argparse.ArgumentParser):
    """Reject unknown arguments without reflecting possible secrets to stderr."""

    def error(self, message: str) -> None:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="litechecker-smoke-subscription",
        description="Sanitized in-memory LiteChecker smoke check",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="run direct control and exact Xray outbound probes",
    )
    return parser


def _subscription_facts(
    targets: Sequence[TargetConfig],
) -> tuple[str, Counter[str]]:
    revision = hashlib.sha256(
        json.dumps(
            sorted(target.target_id for target in targets),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return revision, Counter(target.address_kind for target in targets if target.check_kind == "vpn")


def summarize_subscription(payload: bytes, state_key: str | bytes, max_endpoints: int) -> str:
    """Return only safe aggregate facts about one in-memory subscription payload."""
    targets = parse_xray_subscription(payload, state_key, max_endpoints)
    revision, kinds = _subscription_facts(targets)
    return "\n".join(
        (
            "validation=ok",
            f"target_count={len(targets)}",
            f"sni_count={sum(target.check_kind == 'sni' for target in targets)}",
            f"revision_prefix={revision[:12]}",
            f"address_kind_domain={kinds.get('domain', 0)}",
            f"address_kind_ip={kinds.get('ip', 0)}",
        )
    )


def _probe_summary(targets: Sequence[TargetConfig], results: Sequence[ProbeResult]) -> str:
    revision, kinds = _subscription_facts(targets)
    statuses = Counter(result.status.value for result in results)
    stages = Counter(result.stage.value for result in results)
    status_counts = ",".join(
        f"{status.value}:{statuses.get(status.value, 0)}" for status in ResultStatus
    )
    stage_counts = ",".join(
        f"{stage.value}:{stages[stage.value]}"
        for stage in ProbeStage
        if stages[stage.value]
    )
    return "\n".join(
        (
            "validation=ok",
            f"target_count={len(targets)}",
            f"sni_count={sum(target.check_kind == 'sni' for target in targets)}",
            f"revision_prefix={revision[:12]}",
            f"address_kind_domain={kinds.get('domain', 0)}",
            f"address_kind_ip={kinds.get('ip', 0)}",
            "refresh_state=FRESH",
            f"status_counts={status_counts}",
            f"stage_counts={stage_counts}",
        )
    )


def _unknown_results(
    targets: Sequence[TargetConfig], stage: ProbeStage, error_code: str
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


def _remaining(deadline: float, started: float, monotonic: Callable[[], float]) -> float:
    return max(0.0, deadline - (monotonic() - started))


async def run_smoke(
    settings: AgentSettings,
    *,
    probe: bool = False,
    fetcher: SubscriptionSource | None = None,
    control_checker: ControlChecker = check_control,
    prober: TargetProber = probe_all,
    version_checker: XrayVersionChecker | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Fetch in memory and optionally exercise the exact control/Xray prober core."""
    source = fetcher or SubscriptionFetcher(
        settings.subscription_url.get_secret_value(),
        max_bytes=settings.max_subscription_bytes,
    )
    if not probe:
        payload = await source.fetch()
        return summarize_subscription(
            payload,
            settings.state_key.get_secret_value(),
            settings.max_endpoints,
        )

    started = monotonic()
    remaining = _remaining(settings.run_deadline_seconds, started, monotonic)
    try:
        control = await asyncio.wait_for(
            control_checker(timeout=min(5.0, settings.probe_timeout_seconds)),
            timeout=remaining,
        )
    except Exception:
        control = ControlResult(ok=False, error_code="control-failed")

    remaining = _remaining(settings.run_deadline_seconds, started, monotonic)
    if remaining <= 0:
        raise TimeoutError("smoke-deadline")
    payload = await asyncio.wait_for(source.fetch(), timeout=remaining)
    targets = parse_xray_subscription(
        payload,
        settings.state_key.get_secret_value(),
        settings.max_endpoints,
    )
    vpn_targets = [target for target in targets if target.check_kind == "vpn"]
    xray_failures: list[ProbeResult] = []
    probe_targets = targets
    if control.ok and vpn_targets:
        remaining = _remaining(settings.run_deadline_seconds, started, monotonic)
        try:
            version_info = await asyncio.wait_for(
                version_checker()
                if version_checker is not None
                else query_xray_version(
                    settings.xray_binary,
                    expected_version=settings.expected_xray_version,
                ),
                timeout=remaining,
            )
        except Exception:
            version_info = XrayVersionResult(
                None, False, "xray-version-unavailable"
            )
        if not version_info.compatible:
            xray_failures = _unknown_results(
                vpn_targets,
                ProbeStage.XRAY,
                version_info.error_code or "xray-version-unavailable",
            )
            probe_targets = [target for target in targets if target.check_kind == "sni"]
    remaining = _remaining(settings.run_deadline_seconds, started, monotonic)
    try:
        results = await prober(
            probe_targets,
            control=control,
            max_concurrency=settings.max_concurrency,
            deadline_seconds=remaining,
            allow_private_targets=settings.allow_private_targets,
            tcp_timeout=settings.tcp_timeout_seconds,
            probe_timeout=settings.probe_timeout_seconds,
            xray_binary=settings.xray_binary,
            canaries=DEFAULT_CANARIES,
        )
    except TimeoutError:
        results = _unknown_results(probe_targets, ProbeStage.DEADLINE, "deadline")
    except Exception:
        results = _unknown_results(probe_targets, ProbeStage.XRAY, "probe-error")
    return _probe_summary(targets, xray_failures + results)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a parser-only or full probe smoke without persistence or delivery."""
    arguments = _parser().parse_args(argv)
    try:
        settings = AgentSettings.from_env()
    except (ValidationError, ValueError):
        print("validation=failed", file=sys.stderr)
        return 2
    try:
        output = asyncio.run(
            run_with_signals(run_smoke(settings, probe=arguments.probe))
        )
    except (asyncio.CancelledError, KeyboardInterrupt):
        return 0
    except Exception:
        print("validation=failed", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())

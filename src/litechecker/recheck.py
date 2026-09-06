"""One bounded confirmation pass; only final evidence enters public reports."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from litechecker.models import ProbeResult, ProbeStage, ResultStatus, TargetConfig
from litechecker.probe import ControlResult
from litechecker.probe_policy import RECHECK_DELAY_SECONDS


async def confirm_failures(
    targets: Sequence[TargetConfig],
    results: list[ProbeResult],
    control: ControlResult,
    *,
    probe: Callable[[Sequence[TargetConfig], ControlResult, float], Awaitable[list[ProbeResult]]],
    check_control: Callable[[float], Awaitable[ControlResult]],
    remaining: Callable[[], float],
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[list[ProbeResult], ControlResult, list[dict]]:
    """Retry DOWN once, after the first pass, using the same scoped dependencies.

    UNKNOWN is never retried as if it were remote evidence. Exhausted budgets
    and failed controls cannot leave an unconfirmed first failure marked DOWN.
    The first result is retained only in local diagnostics, not AgentReport.
    """
    first = [r for r in results if r.status is ResultStatus.DOWN]
    if not first:
        return results, control, []
    target_map = {t.target_id: t for t in targets}
    retry_targets = [target_map[r.target_id] for r in first if r.target_id in target_map]

    def unknown(stage, code):
        return [_uncertain(r, stage, code) for r in first]

    second = unknown(ProbeStage.DEADLINE, "deadline")
    if not control.ok:
        second = unknown(ProbeStage.AGENT_NETWORK, "control-failed")
    elif remaining() > RECHECK_DELAY_SECONDS:
        try:
            await asyncio.wait_for(sleep(RECHECK_DELAY_SECONDS), timeout=remaining())
        except TimeoutError:
            pass
        else:
            if remaining() > 0:
                control = await check_control(remaining())
                if not control.ok:
                    second = unknown(ProbeStage.AGENT_NETWORK, "control-failed")
                elif remaining() > 0:
                    raw = await probe(retry_targets, control, remaining())
                    # Treat incomplete/duplicate/mismatched batches as local
                    # failures, never reuse stale red or invent successful data.
                    valid = (
                        len(raw) == len(first) == len(retry_targets)
                        and len({r.target_id for r in raw}) == len(raw)
                        and {r.target_id for r in raw} == {r.target_id for r in first}
                    )
                    if valid:
                        valid = all(
                            (r.address, r.port, r.check_kind) == (
                                target_map[r.target_id].address, target_map[r.target_id].port,
                                target_map[r.target_id].check_kind,
                            ) for r in raw
                        )
                    second = raw if valid else unknown(ProbeStage.POLICY, "recheck-invalid")
                    if any(r.status is ResultStatus.DOWN for r in second):
                        if remaining() <= 0:
                            second = [_uncertain(r, ProbeStage.DEADLINE, "deadline")
                                      if r.status is ResultStatus.DOWN else r for r in second]
                        else:
                            control = await check_control(remaining())
                            if not control.ok:
                                second = [_uncertain(r, ProbeStage.AGENT_NETWORK, "control-failed")
                                          if r.status is ResultStatus.DOWN else r for r in second]

    replacements = {r.target_id: r for r in second}
    attempts = [{"first": r.model_dump(mode="json"),
                 "second": replacements[r.target_id].model_dump(mode="json")}
                for r in first]
    return [replacements.get(r.target_id, r) for r in results], control, attempts


def _uncertain(result: ProbeResult, stage: ProbeStage, code: str) -> ProbeResult:
    return result.model_copy(update={
        "status": ResultStatus.UNKNOWN, "stage": stage, "error_code": code,
        "latency_ms": None,
    })

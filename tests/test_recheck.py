"""Confirmation must remove transient failures, not manufacture UP evidence."""

import asyncio
import json

import pytest

from litechecker import measurement
from litechecker.agent import AgentDependencies, run_agent
from litechecker.config import ProbeSettings
from litechecker.models import ProbeResult, ProbeStage, ResultStatus
from litechecker.probe import ControlResult
from litechecker.state import PendingReportStore
from test_agent import FakeFetcher, NOW, RecordingSender, _settings, _target, _up_result
from test_direct_production_reporting import render


def down(target):
    return ProbeResult(
        target_id=target.target_id, label=target.label, address=target.address,
        port=target.port, check_kind=target.check_kind, status=ResultStatus.DOWN,
        stage=ProbeStage.TLS_HANDSHAKE if target.check_kind == "sni" else ProbeStage.VLESS_E2E,
        error_code="tls-timeout" if target.check_kind == "sni" else "canary-timeout",
    )


def setup_cycle(tmp_path, *, outcomes=None, controls=(True, True, True), deadline=100):
    targets = [_target(1), _target(2), _target(3).model_copy(update={
        "check_kind": "sni", "outbound": {},
    })]
    settings = _settings(run_deadline_seconds=deadline)
    deps = measurement.make_measurement_dependencies(settings, state_dir=tmp_path)
    deps.fetcher = FakeFetcher(b"fresh-subscription")
    deps.parser = lambda *_: targets
    deps.version_checker = None
    deps.wall_clock = lambda: NOW
    clock = {"now": 0.0}
    events = []
    controls = iter(controls)
    deps.monotonic = lambda: clock["now"]

    async def sleep(delay):
        events.append(("wait", delay))
        clock["now"] += delay
    deps.sleep = sleep

    async def control():
        events.append(("control", clock["now"]))
        return ControlResult(ok=next(controls), error_code="control-failed")
    deps.control_checker = control

    async def probe(batch, control, remaining):
        events.append(("probe", [t.target_id for t in batch], remaining))
        attempt = sum(e[0] == "probe" for e in events)
        if attempt == 1:
            clock["now"] += 4
            return [down(batch[0]), _up_result(batch[1]), down(batch[2])]
        return [(outcomes or {}).get(t.target_id, _up_result)(t) for t in batch]
    deps.prober = probe
    return settings, deps, targets, clock, events


@pytest.mark.asyncio
async def test_recovered_failures_are_silent_in_telegram_but_retained_locally(tmp_path):
    settings, deps, targets, clock, events = setup_cycle(tmp_path)
    report = await measurement.measure_cycle(settings, deps)
    assert [r.status for r in report.results] == [ResultStatus.UP] * 3
    assert [e[1] for e in events if e[0] == "probe"] == [
        [t.target_id for t in targets], ["target-1", "target-3"],
    ]
    assert ("wait", 10.0) in events
    assert report.duration_ms == 14000
    text = render(report)
    assert "Всё доступно" in text and "🟡" not in text
    assert all(t.label not in text and t.address not in text for t in targets)
    assert "попыт" not in text and "повтор" not in text
    history = json.loads((tmp_path / "last-probe-attempts.json").read_text())
    assert history["event_id"] == report.event_id
    assert len(history["attempts"]) == 2
    for entry in history["attempts"]:
        assert entry["first"]["status"] == "DOWN"
        assert entry["second"]["status"] == "UP"
    assert "11111111-1111-4111-8111-111111111111" not in json.dumps(history)
    assert "fresh-subscription" not in json.dumps(history)


@pytest.mark.asyncio
async def test_persistent_failure_remains_red_and_only_it_is_listed(tmp_path):
    settings, deps, targets, _, events = setup_cycle(tmp_path, outcomes={"target-1": down})
    report = await measurement.measure_cycle(settings, deps)
    assert [r.status for r in report.results] == [ResultStatus.DOWN, ResultStatus.UP, ResultStatus.UP]
    assert report.control_status is ResultStatus.UP
    text = render(report)
    assert targets[0].address in text and targets[2].address not in text
    assert "Всё доступно" not in text
    assert sum(e[0] == "probe" for e in events) == 2
    assert sum(e[0] == "control" for e in events) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("controls", [(True, False), (True, True, False)])
async def test_failed_confirmation_control_never_leaves_red_targets(tmp_path, controls):
    settings, deps, _, _, events = setup_cycle(
        tmp_path, controls=controls, outcomes={"target-1": down, "target-3": down},
    )
    report = await measurement.measure_cycle(settings, deps)
    assert [r.status for r in report.results] == [ResultStatus.UNKNOWN, ResultStatus.UP, ResultStatus.UNKNOWN]
    assert report.control_status is ResultStatus.UNKNOWN
    assert report.run_status is ResultStatus.UNKNOWN and report.run_reason == "agent-network"
    assert all(r.stage is ProbeStage.AGENT_NETWORK for r in report.results if r.status is ResultStatus.UNKNOWN)
    assert "Всё доступно" not in render(report)


@pytest.mark.asyncio
async def test_insufficient_retry_budget_is_unknown_not_a_single_failure_verdict(tmp_path):
    settings, deps, _, _, events = setup_cycle(tmp_path, deadline=12)
    report = await measurement.measure_cycle(settings, deps)
    assert [r.status for r in report.results] == [ResultStatus.UNKNOWN, ResultStatus.UP, ResultStatus.UNKNOWN]
    assert all(r.stage is ProbeStage.DEADLINE for r in report.results if r.status is ResultStatus.UNKNOWN)
    assert report.run_reason == "deadline"
    assert sum(e[0] == "probe" for e in events) == 1
    assert not any(e[0] == "wait" for e in events)


@pytest.mark.asyncio
async def test_retry_deadline_keeps_completed_up_and_waits_for_cleanup_before_next_cycle(tmp_path):
    settings, deps, _, clock, events = setup_cycle(
        tmp_path, deadline=15, controls=(True, True, True, True),
    )
    deps.fetcher = FakeFetcher(b"first-subscription", b"second-subscription")
    active = calls = 0

    async def bounded_probe(batch, control, remaining):
        nonlocal active, calls
        assert active == 0
        assert control.ok
        active += 1
        calls += 1
        events.append(("probe-start", calls, clock["now"]))
        try:
            if calls % 2:
                clock["now"] += 4
                return [down(batch[0]), _up_result(batch[1]), down(batch[2])]
            assert remaining == pytest.approx(1)
            assert [t.target_id for t in batch] == ["target-1", "target-3"]
            # The batch owns its deadline and returns completed evidence only
            # after child cleanup, even if that cleanup extends past the budget.
            clock["now"] += remaining
            return [_up_result(batch[0]), down(batch[1])]
        finally:
            await asyncio.sleep(0.01)
            if calls % 2 == 0:
                clock["now"] += 0.5
            active -= 1
            events.append(("cleanup", calls, clock["now"]))

    deps.prober = bounded_probe
    agent_deps = AgentDependencies(
        **vars(deps), pending_store=PendingReportStore(tmp_path / "pending-report.json"),
        sender=RecordingSender(),
    )
    reports = await run_agent(settings, dependencies=agent_deps, max_cycles=2)
    assert calls == 4 and active == 0
    assert sum(e[0] == "control" for e in events) == 4  # No post-control time left.
    for report in reports:
        assert [r.status for r in report.results] == [
            ResultStatus.UP, ResultStatus.UP, ResultStatus.UNKNOWN,
        ]
        assert report.results[2].stage is ProbeStage.DEADLINE
        assert report.run_reason == "deadline"
        assert "Всё доступно" not in render(report)
    cleanup = next(e for e in events if e[:2] == ("cleanup", 2))
    next_start = next(e for e in events if e[:2] == ("probe-start", 3))
    assert events.index(cleanup) < events.index(next_start)
    assert next_start[2] - cleanup[2] == settings.interval_seconds


@pytest.mark.asyncio
async def test_retry_local_error_is_not_promoted_to_a_confirmed_remote_failure(tmp_path):
    def unknown(t):
        return down(t).model_copy(update={
            "status": ResultStatus.UNKNOWN, "stage": ProbeStage.POLICY,
            "error_code": "direct-tcp:interface_binding_failed",
        })
    settings, deps, _, _, _ = setup_cycle(tmp_path, outcomes={"target-1": unknown})
    report = await measurement.measure_cycle(settings, deps)
    assert report.results[0].status is ResultStatus.UNKNOWN
    assert "Всё доступно" not in render(report)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_results", [[], ["duplicate"], ["exception"]])
async def test_missing_duplicate_or_failed_second_pass_cannot_leave_false_up(tmp_path, bad_results):
    settings, deps, _, _, _ = setup_cycle(tmp_path)
    first = deps.prober
    calls = 0
    async def broken(batch, control, remaining):
        nonlocal calls
        calls += 1
        if calls == 1:
            return await first(batch, control, remaining)
        if bad_results == ["exception"]:
            raise RuntimeError("secret-must-not-be-logged")
        if bad_results == ["duplicate"]:
            return [_up_result(batch[0]), _up_result(batch[0])]
        return []
    deps.prober = broken
    report = await measurement.measure_cycle(settings, deps)
    assert [r.status for r in report.results] == [ResultStatus.UNKNOWN, ResultStatus.UP, ResultStatus.UNKNOWN]
    assert "secret-must-not-be-logged" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_new_cycle_clears_old_attempts_and_healthy_targets_are_not_retried(tmp_path):
    settings, deps, _, _, events = setup_cycle(tmp_path)
    await measurement.measure_cycle(settings, deps)
    deps.fetcher = FakeFetcher(b"new-subscription")
    async def healthy(batch, *_):
        return [_up_result(t) for t in batch]
    deps.prober = healthy
    events.clear()
    report = await measurement.measure_cycle(settings, deps)
    history = json.loads((tmp_path / "last-probe-attempts.json").read_text())
    assert history["event_id"] == report.event_id and history["attempts"] == []
    assert not any(e[0] == "wait" for e in events)


@pytest.mark.asyncio
async def test_cancel_during_confirmation_wait_propagates_without_second_probe(tmp_path):
    settings, deps, _, _, events = setup_cycle(tmp_path)
    async def cancelled(delay):
        raise asyncio.CancelledError
    deps.sleep = cancelled
    with pytest.raises(asyncio.CancelledError):
        await measurement.measure_cycle(settings, deps)
    assert sum(e[0] == "probe" for e in events) == 1


@pytest.mark.asyncio
async def test_default_and_explicit_timeouts_reach_the_real_measurement_boundary(tmp_path, monkeypatch):
    received = []
    async def probe_all(targets, **kwargs):
        received.append((kwargs["tcp_timeout"], kwargs["probe_timeout"]))
        return [_up_result(t) for t in targets]
    monkeypatch.setattr(measurement, "probe_all", probe_all)
    base = dict(agent_id="tester", subscription_url="https://example.com/sub", state_key="s" * 32)
    for settings in (ProbeSettings(**base), ProbeSettings.from_env({
        "LC_AGENT_ID": "tester", "LC_SUBSCRIPTION_URL": "https://example.com/sub",
        "LC_STATE_KEY": "s" * 32,
    }), ProbeSettings(**base, tcp_timeout_seconds=11, probe_timeout_seconds=41)):
        deps = measurement.make_measurement_dependencies(settings, state_dir=tmp_path)
        await deps.prober([_target(1)], ControlResult(ok=True), 50)
    assert received == [(8, 30), (8, 30), (11, 41)]

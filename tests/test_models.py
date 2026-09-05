from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from litechecker.models import (
    AgentReport,
    ProbeResult,
    ProbeStage,
    ResultStatus,
    Snapshot,
    SnapshotDiff,
    TargetConfig,
)


def _target() -> TargetConfig:
    return TargetConfig(
        target_id="target-1",
        config_fingerprint="local-only-fingerprint",
        label="Tbilisi edge",
        address="vpn.example",
        port=443,
        address_kind="domain",
        outbound={"protocol": "vless", "settings": {"users": [{"id": "private-uuid"}]}},
    )


def _result() -> ProbeResult:
    return ProbeResult(
        target_id="target-1",
        label="Tbilisi edge",
        address="vpn.example",
        port=443,
        status=ResultStatus.UP,
        stage=ProbeStage.E2E,
        latency_ms=42,
    )


def test_agent_report_rejects_local_target_configuration():
    """Adding raw target data to a report would leak an outbound to the collector."""
    payload = dict(
        event_id="event-1",
        agent_id="tbilisi-home",
        boot_id="boot-1",
        sequence=1,
        observed_at=datetime(2026, 9, 4, tzinfo=UTC),
        subscription_revision="safe-revision",
        snapshot_age_seconds=0,
        diff=SnapshotDiff(),
        results=[_result()],
        control_status=ResultStatus.UP,
        duration_ms=100,
    )

    report = AgentReport(**payload)

    with pytest.raises(ValidationError):
        AgentReport(targets=[_target()], **payload)

    dumped = report.model_dump_json()
    assert '"outbound"' not in dumped
    assert '"config_fingerprint"' not in dumped


def test_snapshot_keeps_local_target_configuration_for_future_probes():
    """Excluding targets from snapshots would prevent stale last-known-good probing."""
    snapshot = Snapshot(
        targets=[_target()],
        subscription_revision="safe-revision",
        observed_at=datetime(2026, 9, 4, tzinfo=UTC),
    )

    assert snapshot.targets[0].outbound["protocol"] == "vless"


def test_probe_result_rejects_more_than_16_resolved_ips():
    """Removing the result bound would permit a hostile DNS response to bloat reports."""
    with pytest.raises(ValidationError):
        ProbeResult(
            target_id="target-1",
            label="Tbilisi edge",
            address="vpn.example",
            port=443,
            status=ResultStatus.DOWN,
            stage=ProbeStage.DNS,
            resolved_ips=[f"192.0.2.{number}" for number in range(17)],
        )


@pytest.mark.parametrize(
    ("status", "stage"),
    [
        (ResultStatus.UP, ProbeStage.DNS),
        (ResultStatus.DOWN, ProbeStage.XRAY),
        (ResultStatus.UNKNOWN, ProbeStage.TCP),
    ],
)
def test_probe_result_rejects_statuses_without_matching_evidence(status, stage):
    """Permitting a mismatched status/stage would fabricate target-outage evidence."""
    with pytest.raises(ValidationError):
        ProbeResult(
            target_id="target-1",
            label="Tbilisi edge",
            address="vpn.example",
            port=443,
            status=status,
            stage=stage,
        )


@pytest.mark.parametrize(("kind", "stage"), [("vpn", ProbeStage.TLS), ("sni", ProbeStage.E2E)])
def test_origin_tls_and_vpn_evidence_cannot_be_interchanged(kind, stage):
    with pytest.raises(ValidationError):
        ProbeResult(target_id="id", label="label", address="example.com", port=443,
                    check_kind=kind, status=ResultStatus.UP, stage=stage)


def test_agent_report_rejects_a_down_direct_control_status():
    """Direct-control failure is agent uncertainty, never a target DOWN result."""
    with pytest.raises(ValidationError):
        AgentReport(
            event_id="event-1",
            agent_id="tbilisi-home",
            boot_id="boot-1",
            sequence=1,
            observed_at=datetime(2026, 9, 4, tzinfo=UTC),
            results=[],
            control_status=ResultStatus.DOWN,
            duration_ms=100,
        )


def test_policy_stage_is_unknown_and_run_reason_is_closed():
    """Policy refusal and run-level uncertainty must serialize without arbitrary text."""
    policy = ProbeResult(
        target_id="target-1",
        label="edge",
        address="node.example",
        port=443,
        status=ResultStatus.UNKNOWN,
        stage=ProbeStage.POLICY,
        error_code="forbidden-address",
    )
    report = AgentReport(
        event_id="agent-1:boot-1:1",
        agent_id="agent-1",
        boot_id="boot-1",
        sequence=1,
        observed_at=datetime(2026, 9, 4, tzinfo=UTC),
        results=[policy],
        control_status=ResultStatus.UP,
        run_status=ResultStatus.UNKNOWN,
        run_reason="no-valid-snapshot",
        duration_ms=1,
    )

    assert report.model_dump(mode="json")["run_reason"] == "no-valid-snapshot"
    with pytest.raises(ValidationError, match="run_reason"):
        report.model_copy(update={"run_reason": "https://secret.invalid"}).model_validate(
            {**report.model_dump(), "run_reason": "https://secret.invalid"}
        )


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (ResultStatus.UP, "no-valid-snapshot"),
        (ResultStatus.UNKNOWN, None),
    ],
)
def test_agent_report_run_status_requires_consistent_reason(status, reason):
    """Run evidence must not claim success with a failure reason or unexplained UNKNOWN."""
    with pytest.raises(ValidationError, match="run status"):
        AgentReport(
            event_id="agent-1:boot-1:1",
            agent_id="agent-1",
            boot_id="boot-1",
            sequence=1,
            observed_at=datetime(2026, 9, 4, tzinfo=UTC),
            control_status=ResultStatus.UP,
            run_status=status,
            run_reason=reason,
            duration_ms=1,
        )

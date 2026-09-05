from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.db import CollectorDB
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
AGENT = AgentIdentity("agent-1", "Tbilisi", "Home ISP", 600)
OWNER = "delivery-test"


def _report(sequence: int = 1, *, rows: int = 0) -> AgentReport:
    return AgentReport(
        event_id=f"agent-1:boot-1:{sequence}",
        agent_id=AGENT.agent_id,
        boot_id="boot-1",
        sequence=sequence,
        observed_at=NOW,
        subscription_revision="a" * 64,
        results=[
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
        ],
        control_status=ResultStatus.UP,
        duration_ms=1,
    )


def test_delivery_requires_every_chunk_acknowledged_and_survives_reopen(tmp_path):
    """Queued, leased, and partially acknowledged reports must not count as delivered."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    report = _report(rows=40)
    db.accept_report(report, AGENT, received_at=NOW)
    assert db.notification_delivered(report.event_id) is False

    claim = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert claim is not None
    assert claim.chunk_count > 2
    assert db.notification_delivered(report.event_id) is False
    db.acknowledge_chunk(claim, OWNER, NOW)
    assert db.notification_delivered(report.event_id) is False

    while (claim := db.claim_notification(OWNER, NOW, lease_seconds=30)) is not None:
        db.acknowledge_chunk(claim, OWNER, NOW)

    assert db.notification_delivered(report.event_id) is True
    assert CollectorDB(db.path, [AGENT]).notification_delivered(report.event_id) is True
    assert db.notification_delivered("agent-1:boot-1:missing") is False


@pytest.mark.parametrize("permanent", [False, True])
def test_failed_notification_is_not_delivered(tmp_path, permanent):
    """Both scheduled retries and terminal errors must prevent a delivery claim."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    report = _report()
    db.accept_report(report, AGENT, received_at=NOW)
    claim = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert claim is not None
    db.record_notification_failure(
        claim,
        OWNER,
        "telegram-network",
        NOW,
        permanent=permanent,
        max_attempts=5,
        retry_delay_seconds=60,
    )

    assert db.notification_delivered(report.event_id) is False


def test_requeued_remainder_counts_only_after_all_remaining_chunks_are_acked(tmp_path):
    """Historical dead letters must not hide success after repeated tail requeues."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    report = _report(rows=40)
    db.accept_report(report, AGENT, received_at=NOW)
    first = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert first is not None
    assert first.chunk_count > 2
    db.acknowledge_chunk(first, OWNER, NOW)

    for _ in range(2):
        failed = db.claim_notification(OWNER, NOW, lease_seconds=30)
        assert failed is not None
        db.record_notification_failure(
            failed,
            OWNER,
            "telegram-http-400",
            NOW,
            permanent=True,
            max_attempts=5,
            retry_delay_seconds=60,
        )
        assert db.notification_delivered(report.event_id) is False
        db.requeue_dead_letter(failed.notification_id, NOW)
        assert db.notification_delivered(report.event_id) is False

    while (claim := db.claim_notification(OWNER, NOW, lease_seconds=30)) is not None:
        assert db.notification_delivered(report.event_id) is False
        db.acknowledge_chunk(claim, OWNER, NOW)

    assert db.notification_delivered(report.event_id) is True


def test_recovery_ack_does_not_count_as_report_delivery(tmp_path):
    """A RECOVERY notification for the same event is not its REPORT notification."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [AGENT],
        registry_activated_at=NOW - timedelta(hours=1),
    )
    db.offline_transitions(NOW)
    offline = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert offline is not None
    assert offline.kind == "OFFLINE"
    db.acknowledge_chunk(offline, OWNER, NOW)
    report = _report()
    db.accept_report(report, AGENT, received_at=NOW)

    recovery = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert recovery is not None
    assert recovery.kind == "RECOVERY"
    db.acknowledge_chunk(recovery, OWNER, NOW)

    assert db.notification_delivered(report.event_id) is False


def test_pruned_requeue_success_is_no_longer_confirmable(tmp_path):
    """A requeued tombstone without retained success evidence must not count as delivery."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT], max_completed_notifications=1)
    report = _report()
    db.accept_report(report, AGENT, received_at=NOW)
    failed = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert failed is not None
    db.record_notification_failure(
        failed,
        OWNER,
        "telegram-http-400",
        NOW,
        permanent=True,
        max_attempts=5,
        retry_delay_seconds=60,
    )
    db.requeue_dead_letter(failed.notification_id, NOW)
    clone = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert clone is not None
    db.acknowledge_chunk(clone, OWNER, NOW)
    assert db.notification_delivered(report.event_id) is True

    db.accept_report(_report(2), AGENT, received_at=NOW)
    later = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert later is not None
    db.acknowledge_chunk(later, OWNER, NOW)

    assert db.notification_delivered(report.event_id) is False


def test_retry_dead_letters_keeps_chunk_progress_and_resets_retry_budget(tmp_path):
    """Restart retries a failed remainder in place, without resending confirmed chunks."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    report = _report(rows=40)
    db.accept_report(report, AGENT, received_at=NOW)
    first = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert first is not None
    db.acknowledge_chunk(first, OWNER, NOW)
    failed = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert failed is not None
    db.record_notification_failure(
        failed, OWNER, "telegram-network", NOW,
        permanent=False, max_attempts=1, retry_delay_seconds=60,
    )

    restarted_at = NOW + timedelta(seconds=1)
    assert db.retry_dead_letters(restarted_at) == 1
    assert db.retry_dead_letters(restarted_at) == 0
    assert db.notification_delivered(report.event_id) is False
    resumed = db.claim_notification(OWNER, restarted_at, lease_seconds=30)
    assert resumed is not None
    assert resumed.notification_id == first.notification_id
    assert resumed.chunk_index == 1
    assert resumed.body == failed.body
    assert resumed.body != first.body
    assert db.record_notification_failure(
        resumed, OWNER, "telegram-network", restarted_at,
        permanent=False, max_attempts=2, retry_delay_seconds=60,
    ) is False
    assert db.retry_dead_letters(restarted_at) == 0
    assert db.claim_notification(OWNER, restarted_at, lease_seconds=30) is None

    retry_at = restarted_at + timedelta(seconds=60)
    while (claim := db.claim_notification(OWNER, retry_at, lease_seconds=30)) is not None:
        db.acknowledge_chunk(claim, OWNER, retry_at)

    assert db.notification_delivered(report.event_id) is True
    assert db.retry_dead_letters(retry_at) == 0


def test_retry_dead_letters_preserves_requeued_history_and_clears_failure_state(tmp_path):
    """Rearming the current remainder must not revive its historical failed ancestors."""
    db = CollectorDB(tmp_path / "collector.db", [AGENT])
    report = _report()
    db.accept_report(report, AGENT, received_at=NOW)
    original = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert original is not None
    db.record_notification_failure(
        original, OWNER, "telegram-http-400", NOW,
        permanent=True, max_attempts=5, retry_delay_seconds=60,
    )
    clone_id = db.requeue_dead_letter(original.notification_id, NOW)
    with sqlite3.connect(db.path) as connection:
        historical = connection.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            (original.notification_id,),
        ).fetchone()
    assert db.retry_dead_letters(NOW) == 0
    clone = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert clone is not None
    db.record_notification_failure(
        clone, OWNER, "telegram-http-400", NOW,
        permanent=True, max_attempts=5, retry_delay_seconds=60,
    )

    assert db.retry_dead_letters(NOW) == 1

    with sqlite3.connect(db.path) as connection:
        assert connection.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            (original.notification_id,),
        ).fetchone() == historical
        assert connection.execute(
            """SELECT attempt_count, dead_letter, dead_letter_at_us,
                      last_error_code, last_error_at_us, lease_owner, lease_until_us
               FROM notifications WHERE notification_id = ?""",
            (clone_id,),
        ).fetchone() == (0, 0, None, None, None, None, None)
    resumed = db.claim_notification(OWNER, NOW, lease_seconds=30)
    assert resumed is not None
    assert resumed.notification_id == clone_id
    db.acknowledge_chunk(resumed, OWNER, NOW)
    assert db.notification_delivered(report.event_id) is True

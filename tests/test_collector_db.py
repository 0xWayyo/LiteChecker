from __future__ import annotations

import hashlib
import json
import sqlite3
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.db import (
    CollectorBackpressure,
    CollectorDB,
    CollectorDBError,
    ReportRateLimited,
    SequenceConflict,
)
from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus, SnapshotDiff


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


@pytest.fixture
def identity() -> AgentIdentity:
    return AgentIdentity(
        agent_id="agent-1",
        city="Tbilisi",
        name="Home ISP",
        expected_interval_seconds=600,
    )


def _report(
    *,
    event_id=None,
    boot_id="boot-1",
    sequence=1,
    observed_at=NOW,
) -> AgentReport:
    if event_id is None:
        event_id = f"agent-1:{boot_id}:{sequence}"
    return AgentReport(
        event_id=event_id,
        agent_id="agent-1",
        boot_id=boot_id,
        sequence=sequence,
        observed_at=observed_at,
        subscription_revision="a" * 64,
        refresh_state="FRESH",
        snapshot_age_seconds=0,
        diff=SnapshotDiff(added=["target-2"], removed=["target-0"]),
        results=[
            ProbeResult(
                target_id="target-1",
                label="Edge\x00\nBearer secret",
                address="node.example",
                port=443,
                status=ResultStatus.DOWN,
                stage=ProbeStage.VLESS_E2E,
                resolved_ips=["203.0.113.1"],
                error_code="proxy-connect\x00",
            )
        ],
        control_status=ResultStatus.UP,
        duration_ms=50,
        xray_version="26.3.27",
    )


def test_first_event_is_committed_with_wal_fk_and_only_sanitized_fields(tmp_path, identity):
    """Persisting an event incompletely or verbatim would lose evidence or unsafe text."""
    db = CollectorDB(tmp_path / "collector.db", [identity], offline_threshold_seconds=1500)

    accepted = db.accept_report(_report(), identity, received_at=NOW)

    assert accepted.is_new is True
    assert accepted.recovered is False
    with sqlite3.connect(db.path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        # Foreign keys are connection-local; CollectorDB exposes a readiness probe
        # that verifies the pragma on the connections it owns.
        assert db.is_ready() is True
        stored = connection.execute(
            "SELECT label, error_code FROM results WHERE event_id = ?",
            ("agent-1:boot-1:1",),
        ).fetchone()
        assert stored == ("Edge Bearer [REDACTED]", "proxy-connect")
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"agents", "events", "results", "agent_boots"} <= tables
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(events)")
        }
        assert "token" not in columns
        assert "outbound" not in columns


def test_current_high_water_duplicate_is_idempotent_without_refreshing_last_seen(tmp_path, identity):
    """A replay is not new monitoring evidence and must never refresh liveness."""
    db = CollectorDB(tmp_path / "collector.db", [identity], offline_threshold_seconds=1500)
    db.accept_report(_report(), identity, received_at=NOW)

    duplicate = db.accept_report(
        _report(), identity, received_at=NOW + timedelta(minutes=5)
    )

    assert duplicate.is_new is False
    assert duplicate.recovered is False
    assert db.event_count() == 1
    assert db.last_seen("agent-1") == NOW


def test_sni_results_retain_their_kind_and_evidence(tmp_path, identity):
    db = CollectorDB(tmp_path / "collector.db", [identity])
    sni = ProbeResult(
        target_id="sni:cover.example", label="cover.example", address="cover.example",
        port=443, check_kind="sni", status=ResultStatus.UP, stage=ProbeStage.TLS,
        latency_ms=32, resolved_ips=["203.0.113.2"],
    )
    report = _report().model_copy(update={"results": [_report().results[0], sni]})

    assert db.accept_report(report, identity, received_at=NOW).is_new
    assert not db.accept_report(report, identity, received_at=NOW).is_new

    with sqlite3.connect(db.path) as connection:
        assert connection.execute(
            "SELECT check_kind, stage FROM results ORDER BY position"
        ).fetchall() == [("vpn", "VLESS_E2E"), ("sni", "TLS")]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE results SET check_kind = 'unrecognized'")
    assert db.is_ready()


def test_check_kind_changes_are_not_silently_accepted_as_duplicate(tmp_path, identity):
    db = CollectorDB(tmp_path / "collector.db", [identity])
    result = ProbeResult(
        target_id="node", label="Node", address="node.example", port=443,
        status=ResultStatus.DOWN, stage=ProbeStage.DNS, error_code="dns-failed",
    )
    report = _report().model_copy(update={"results": [result]})
    db.accept_report(report, identity, received_at=NOW)
    changed = ProbeResult.model_validate({**result.model_dump(), "check_kind": "sni"})

    with pytest.raises(SequenceConflict):
        db.accept_report(report.model_copy(update={"results": [changed]}), identity, received_at=NOW)


def test_v7_upgrade_preserves_history_outbox_and_legacy_duplicate_digest(tmp_path, identity):
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [identity])
    result = ProbeResult(
        target_id="node", label="Node", address="node.example", port=443,
        status=ResultStatus.DOWN, stage=ProbeStage.DNS, error_code="dns-failed",
    )
    report = _report().model_copy(update={"results": [result]})
    db.accept_report(report, identity, received_at=NOW)
    legacy_payload = report.model_dump(mode="json")
    legacy_payload.pop("app_version", None)
    for item in legacy_payload["results"]:
        del item["check_kind"]
    legacy_digest = hashlib.sha256(json.dumps(
        legacy_payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    with sqlite3.connect(path) as connection:
        history = connection.execute("SELECT * FROM events").fetchall()
        chunks = connection.execute("SELECT * FROM notification_chunks").fetchall()
        assert connection.execute("SELECT payload_digest FROM events").fetchone()[0] == legacy_digest
        connection.execute("ALTER TABLE results DROP COLUMN check_kind")
        connection.execute("PRAGMA user_version = 7")

    upgraded = CollectorDB(path, [identity])

    assert upgraded.is_ready()
    assert not upgraded.accept_report(report, identity, received_at=NOW + timedelta(minutes=1)).is_new
    assert upgraded.last_seen(identity.agent_id) == NOW
    assert upgraded.pending_notification_count() == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        assert connection.execute("SELECT * FROM events").fetchall() == history
        assert connection.execute("SELECT * FROM notification_chunks").fetchall() == chunks
        assert connection.execute("SELECT target_id, check_kind FROM results").fetchall() == [("node", "vpn")]


def test_same_boot_sequence_cannot_name_a_different_event(tmp_path, identity):
    """Accepting a reused per-boot sequence would make ordering ambiguous."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    db.accept_report(_report(), identity, received_at=NOW)

    with pytest.raises(ValueError, match="event id"):
        db.accept_report(
            _report(event_id="event-other", sequence=1),
            identity,
            received_at=NOW + timedelta(seconds=1),
        )

    assert db.event_count() == 1


def test_same_event_identity_with_changed_payload_is_not_treated_as_duplicate(tmp_path, identity):
    """An event-id collision must not silently bless different evidence as idempotent."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    db.accept_report(_report(), identity, received_at=NOW)

    changed = _report().model_copy(update={"duration_ms": 999})
    with pytest.raises(SequenceConflict):
        db.accept_report(changed, identity, received_at=NOW + timedelta(seconds=1))

    assert db.event_count() == 1


def test_new_boot_cannot_reset_global_sequence_high_water(tmp_path, identity):
    """Changing boot identity must not bypass the agent's durable global ordering."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    db.accept_report(_report(sequence=9), identity, received_at=NOW)
    with pytest.raises(SequenceConflict):
        db.accept_report(
            _report(boot_id="boot-2", sequence=0),
            identity,
            received_at=NOW + timedelta(seconds=1),
        )


def test_stale_exact_duplicate_does_not_refresh_liveness(tmp_path, identity):
    """Replaying an older event must not keep an otherwise silent agent online."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    old = _report(sequence=1)
    db.accept_report(old, identity, received_at=NOW)
    db.accept_report(
        _report(sequence=2), identity, received_at=NOW + timedelta(minutes=5)
    )

    duplicate = db.accept_report(
        old, identity, received_at=NOW + timedelta(minutes=10)
    )

    assert duplicate.is_new is False
    assert db.last_seen("agent-1") == NOW + timedelta(minutes=5)


def test_event_id_must_match_agent_boot_and_sequence(tmp_path, identity):
    """Free-form event IDs do not bind idempotency to the producer identity triple."""
    db = CollectorDB(tmp_path / "collector.db", [identity])

    with pytest.raises(ValueError, match="event id"):
        db.accept_report(
            _report(event_id="unbound-event"), identity, received_at=NOW
        )


def test_offline_and_recovery_each_transition_once_using_safe_threshold(tmp_path, identity):
    """Repeated watchdog alerts or early alerts would make liveness reporting noisy and false."""
    db = CollectorDB(tmp_path / "collector.db", [identity], offline_threshold_seconds=1200)
    db.accept_report(_report(), identity, received_at=NOW)

    assert db.offline_transitions(NOW + timedelta(seconds=1499)) == []
    transitions = db.offline_transitions(NOW + timedelta(seconds=1500))
    assert [(item.agent.agent_id, item.offline_since) for item in transitions] == [
        ("agent-1", NOW + timedelta(seconds=1500))
    ]
    assert db.offline_transitions(NOW + timedelta(hours=2)) == []

    recovered = db.accept_report(
        _report(sequence=2),
        identity,
        received_at=NOW + timedelta(hours=2),
    )
    assert recovered.is_new is True
    assert recovered.recovered is True
    assert db.accept_report(
        _report(sequence=2),
        identity,
        received_at=NOW + timedelta(hours=2, seconds=1),
    ).recovered is False


def test_naive_times_are_rejected_and_utc_survives_reopen(tmp_path, identity):
    """Local-time interpretation across restarts would move watchdog thresholds."""
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [identity])
    with pytest.raises(ValueError, match="UTC"):
        db.accept_report(_report(), identity, received_at=NOW.replace(tzinfo=None))
    db.accept_report(_report(), identity, received_at=NOW)

    reopened = CollectorDB(path, [identity])

    assert reopened.last_seen("agent-1") == NOW


def test_concurrent_duplicate_acceptance_creates_one_event(tmp_path, identity):
    """Racing retries must not duplicate rows or Telegram-triggering acceptance results."""
    db = CollectorDB(tmp_path / "collector.db", [identity])

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                lambda _: db.accept_report(_report(), identity, received_at=NOW).is_new,
                range(16),
            )
        )

    assert sum(outcomes) == 1
    assert db.event_count() == 1
    assert db.pending_notification_count() == 1


def test_registry_sync_deactivates_missing_agents_and_readd_resets_liveness(tmp_path, identity):
    """Removed registry entries must leave watchdog scope until explicitly re-enrolled."""
    second = AgentIdentity("agent-2", "Batumi", "Office ISP", 600)
    path = tmp_path / "collector.db"
    db = CollectorDB(path, [identity, second])
    db.accept_report(_report(), identity, received_at=NOW)
    db.accept_report(
        AgentReport(
            event_id="agent-2:boot-2:1",
            agent_id="agent-2",
            boot_id="boot-2",
            sequence=1,
            observed_at=NOW,
            control_status=ResultStatus.UP,
            duration_ms=1,
        ),
        second,
        received_at=NOW,
    )

    without_second = CollectorDB(path, [identity])
    transitions = without_second.offline_transitions(NOW + timedelta(minutes=25))
    assert [item.agent.agent_id for item in transitions] == ["agent-1"]

    readded_at = NOW + timedelta(days=1)
    readded = CollectorDB(
        path, [identity, second], registry_activated_at=readded_at
    )
    assert readded.last_seen("agent-2") is None
    assert readded.offline_transitions(readded_at) == []
    accepted = readded.accept_report(
        AgentReport(
            event_id="agent-2:boot-3:2",
            agent_id="agent-2",
            boot_id="boot-3",
            sequence=2,
            observed_at=NOW,
            control_status=ResultStatus.UP,
            duration_ms=1,
        ),
        second,
        received_at=readded_at,
    )
    assert accepted.is_new is True


def test_never_seen_agent_goes_offline_from_registry_activation_and_recovers_once(
    tmp_path, identity
):
    """An enrolled agent that never reports must not stay silently online forever."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        offline_threshold_seconds=1500,
        registry_activated_at=NOW,
    )

    assert db.offline_transitions(NOW + timedelta(seconds=1499)) == []
    [transition] = db.offline_transitions(NOW + timedelta(seconds=1500))
    assert transition.agent.agent_id == "agent-1"
    assert transition.never_seen is True
    assert transition.last_seen == NOW
    assert db.offline_transitions(NOW + timedelta(hours=1)) == []

    accepted = db.accept_report(
        _report(sequence=1), identity, received_at=NOW + timedelta(hours=1)
    )
    assert accepted.recovered is True


def test_db_rate_limit_preserves_duplicates_and_rejects_new_burst(tmp_path, identity):
    """Authenticated tokens need durable abuse bounds without breaking idempotent retries."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        report_burst=3,
        report_window_seconds=60,
    )
    for sequence in range(1, 4):
        db.accept_report(_report(sequence=sequence), identity, received_at=NOW)
        claim = db.claim_notification("rate-test", NOW, lease_seconds=30)
        assert claim is not None
        db.acknowledge_chunk(claim, "rate-test", NOW)

    duplicate = db.accept_report(_report(sequence=3), identity, received_at=NOW)
    with pytest.raises(ReportRateLimited):
        db.accept_report(_report(sequence=4), identity, received_at=NOW)

    assert duplicate.is_new is False
    assert db.event_count() == 3


def test_rate_limit_survives_event_retention_pruning(tmp_path, identity):
    """The abuse window must not disappear when the evidence cap prunes old rows."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        report_burst=3,
        report_window_seconds=60,
        max_events_per_agent=1,
    )
    for sequence in range(1, 4):
        db.accept_report(_report(sequence=sequence), identity, received_at=NOW)
        claim = db.claim_notification("retention-rate-test", NOW, lease_seconds=30)
        assert claim is not None
        db.acknowledge_chunk(claim, "retention-rate-test", NOW)

    assert db.event_count() == 1
    with pytest.raises(ReportRateLimited):
        db.accept_report(_report(sequence=4), identity, received_at=NOW)


def test_retention_caps_completed_history_but_preserves_live_dead_letter(tmp_path, identity):
    """Normal evidence growth must be bounded without deleting unresolved audit state."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        report_burst=20,
        max_events_per_agent=2,
        event_retention_seconds=10_000,
        max_completed_notifications=2,
    )
    for sequence in range(1, 5):
        report_time = NOW + timedelta(seconds=sequence)
        db.accept_report(_report(sequence=sequence), identity, received_at=report_time)
        claim = db.claim_notification("setup", report_time, lease_seconds=30)
        assert claim is not None
        if sequence == 1:
            db.record_notification_failure(
                claim,
                "setup",
                "telegram-http-400",
                report_time,
                permanent=True,
                max_attempts=3,
                retry_delay_seconds=1,
            )
        else:
            db.acknowledge_chunk(claim, "setup", report_time)

    stats = db.storage_stats()
    assert stats["events"] <= 3  # two retained plus protected dead-letter evidence
    assert stats["completed_notifications"] <= 2
    assert stats["dead_letters"] == 1


def test_dead_letter_backpressure_rejects_new_event_but_duplicate_still_works(
    tmp_path, identity
):
    """An unbounded poison backlog must close new ingestion without breaking retries."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        max_dead_letters_per_agent=1,
    )
    first = _report(sequence=1)
    db.accept_report(first, identity, received_at=NOW)
    claim = db.claim_notification("setup", NOW, lease_seconds=30)
    assert claim is not None
    db.record_notification_failure(
        claim,
        "setup",
        "telegram-http-400",
        NOW,
        permanent=True,
        max_attempts=3,
        retry_delay_seconds=1,
    )

    assert db.accept_report(first, identity, received_at=NOW).is_new is False
    with pytest.raises(CollectorBackpressure):
        db.accept_report(
            _report(sequence=2), identity, received_at=NOW + timedelta(seconds=1)
        )


@pytest.mark.parametrize("prune_boundary", ["age-on-accept", "count-on-ack"])
def test_requeued_dead_letter_stays_resolved_after_completed_clone_is_pruned(
    tmp_path, identity, prune_boundary
):
    """Deleting a delivered clone must not violate its source FK or resurrect poison."""
    options = {
        "report_burst": 10,
        "completed_notification_retention_seconds": 60,
        "max_completed_notifications": 1,
    }
    db = CollectorDB(tmp_path / "collector.db", [identity], **options)
    db.accept_report(_report(sequence=1), identity, received_at=NOW)
    poisoned = db.claim_notification("poison", NOW, lease_seconds=30)
    assert poisoned is not None
    db.record_notification_failure(
        poisoned,
        "poison",
        "telegram-http-400",
        NOW,
        permanent=True,
        max_attempts=3,
        retry_delay_seconds=1,
    )
    [dead] = db.dead_letters()
    clone_id = db.requeue_dead_letter(dead.notification_id, NOW + timedelta(seconds=1))
    clone = db.claim_notification("clone", NOW + timedelta(seconds=1), lease_seconds=30)
    assert clone is not None and clone.notification_id == clone_id
    db.acknowledge_chunk(clone, "clone", NOW + timedelta(seconds=1))

    second_time = NOW + timedelta(seconds=62 if prune_boundary == "age-on-accept" else 2)
    accepted = db.accept_report(
        _report(sequence=2), identity, received_at=second_time
    )
    assert accepted.is_new
    if prune_boundary == "count-on-ack":
        second = db.claim_notification("second", second_time, lease_seconds=30)
        assert second is not None
        db.acknowledge_chunk(second, "second", second_time)

    with sqlite3.connect(db.path) as connection:
        audit = connection.execute(
            "SELECT dead_letter, requeued, requeued_notification_id "
            "FROM notifications WHERE notification_id = ?",
            (dead.notification_id,),
        ).fetchone()
        clone_exists = connection.execute(
            "SELECT 1 FROM notifications WHERE notification_id = ?", (clone_id,)
        ).fetchone()
    assert audit == (1, 1, None)
    assert clone_exists is None
    assert db.dead_letter_count() == 0
    reopened = CollectorDB(db.path, [identity], **options)
    assert reopened.is_ready()
    assert reopened.dead_letter_count() == 0


def test_pending_notification_backpressure_is_idempotent_and_recovers_after_ack(
    tmp_path, identity
):
    """A Telegram outage must cap queued reports without rejecting an exact retry."""
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        report_burst=10,
        max_pending_notifications_per_agent=1,
        max_pending_notifications_global=10,
    )
    first = _report(sequence=1)
    assert db.accept_report(first, identity, received_at=NOW).is_new
    assert not db.accept_report(first, identity, received_at=NOW).is_new
    with pytest.raises(CollectorBackpressure):
        db.accept_report(
            _report(sequence=2), identity, received_at=NOW + timedelta(seconds=1)
        )

    claim = db.claim_notification("drain", NOW, lease_seconds=30)
    assert claim is not None
    db.acknowledge_chunk(claim, "drain", NOW)
    assert db.accept_report(
        _report(sequence=2), identity, received_at=NOW + timedelta(seconds=1)
    ).is_new


@pytest.mark.parametrize(
    "setting",
    ["max_pending_chunks_per_agent", "max_pending_chunks_global"],
)
def test_pending_chunk_backpressure_rejects_one_oversized_notification(
    tmp_path, identity, setting
):
    """Chunk limits must bound actual unsent work, not merely notification rows."""
    results = [
        ProbeResult(
            target_id=f"target-{index}",
            label="x" * 200,
            address="node.example",
            port=443,
            status=ResultStatus.DOWN,
            stage=ProbeStage.VLESS_E2E,
            error_code="proxy-connect",
        )
        for index in range(40)
    ]
    report = _report(sequence=1).model_copy(update={"results": results})
    db = CollectorDB(
        tmp_path / "collector.db",
        [identity],
        **{setting: 1},
    )

    with pytest.raises(CollectorBackpressure):
        db.accept_report(report, identity, received_at=NOW)
    assert db.event_count() == 0
    assert db.pending_notification_count() == 0


@pytest.mark.parametrize(
    "cap_name",
    (
        "max_pending_notifications_per_agent",
        "max_pending_notifications_global",
        "max_pending_chunks_per_agent",
        "max_pending_chunks_global",
    ),
)
def test_offline_transition_capacity_failure_rolls_back_state_and_retries(
    tmp_path, identity, cap_name
):
    """Offline state and its alert must commit together under every pending cap."""
    options = {
        "report_burst": 10,
        "max_pending_notifications_per_agent": 10,
        "max_pending_notifications_global": 10,
        "max_pending_chunks_per_agent": 10,
        "max_pending_chunks_global": 10,
        cap_name: 1,
    }
    db = CollectorDB(tmp_path / "collector.db", [identity], **options)
    db.accept_report(_report(sequence=1), identity, received_at=NOW)

    with pytest.raises(CollectorBackpressure):
        db.offline_transitions(NOW + timedelta(minutes=25))
    with pytest.raises(CollectorBackpressure):
        db.offline_transitions(NOW + timedelta(minutes=25))

    claim = db.claim_notification("drain", NOW, lease_seconds=30)
    assert claim is not None
    db.acknowledge_chunk(claim, "drain", NOW)
    [transition] = db.offline_transitions(NOW + timedelta(minutes=25))
    assert transition.agent.agent_id == identity.agent_id


@pytest.mark.parametrize(
    "cap_name",
    (
        "max_pending_notifications_per_agent",
        "max_pending_notifications_global",
        "max_pending_chunks_per_agent",
        "max_pending_chunks_global",
    ),
)
def test_concurrent_dead_letter_requeues_share_all_pending_caps(
    tmp_path, identity, cap_name
):
    """Concurrent requeues must atomically admit at most the configured capacity."""
    options = {
        "report_burst": 10,
        "max_pending_notifications_per_agent": 10,
        "max_pending_notifications_global": 10,
        "max_pending_chunks_per_agent": 10,
        "max_pending_chunks_global": 10,
        cap_name: 1,
    }
    db = CollectorDB(tmp_path / "collector.db", [identity], **options)
    for sequence in (1, 2):
        now = NOW + timedelta(seconds=sequence)
        db.accept_report(_report(sequence=sequence), identity, received_at=now)
        claim = db.claim_notification(f"poison-{sequence}", now, lease_seconds=30)
        assert claim is not None
        db.record_notification_failure(
            claim,
            f"poison-{sequence}",
            "telegram-http-400",
            now,
            permanent=True,
            max_attempts=3,
            retry_delay_seconds=1,
        )
    dead_ids = [item.notification_id for item in db.dead_letters()]

    def requeue(notification_id):
        try:
            return db.requeue_dead_letter(notification_id, NOW + timedelta(minutes=1))
        except CollectorBackpressure:
            return "backpressure"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(requeue, dead_ids))

    assert sum(isinstance(item, int) for item in outcomes) == 1
    assert outcomes.count("backpressure") == 1
    assert db.pending_notification_count() == 1

def test_readiness_rejects_version_only_database_with_missing_index(tmp_path, identity):
    """A matching user_version cannot prove the required schema shape is usable."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    with sqlite3.connect(db.path) as connection:
        connection.execute("DROP INDEX events_agent_received_idx")

    assert db.is_ready() is False


def test_readiness_rejects_required_index_name_with_wrong_shape(tmp_path, identity):
    """An index name alone cannot prove ordering and uniqueness guarantees remain."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    with sqlite3.connect(db.path) as connection:
        connection.execute("DROP INDEX notifications_pending_idx")
        connection.execute(
            "CREATE INDEX notifications_pending_idx ON notifications(kind)"
        )

    assert db.is_ready() is False


def _rewrite_schema_sql(db: CollectorDB, table: str, old: str, new: str) -> None:
    with sqlite3.connect(db.path) as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()[0]
        assert old in sql
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = ?",
            (sql.replace(old, new), table),
        )
        version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {version + 1}")
        connection.execute("PRAGMA writable_schema = OFF")


def _rewrite_index_sql(db: CollectorDB, index: str, old: str, new: str) -> None:
    with sqlite3.connect(db.path) as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", (index,)
        ).fetchone()[0]
        assert old in sql
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'index' AND name = ?",
            (sql.replace(old, new), index),
        )
        version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {version + 1}")
        connection.execute("PRAGMA writable_schema = OFF")


@pytest.mark.parametrize(
    ("table", "old", "new", "guarantee"),
    [
        ("agents", "city TEXT NOT NULL", "city BLOB NOT NULL", "type"),
        ("agents", "city TEXT NOT NULL", "city TEXT", "nullability"),
        ("agents", "active INTEGER NOT NULL DEFAULT 1", "active INTEGER NOT NULL DEFAULT 0", "default"),
        (
            "notification_chunks",
            "PRIMARY KEY(notification_id, chunk_index)",
            "PRIMARY KEY(chunk_index, notification_id)",
            "composite-pk-order",
        ),
        (
            "events",
            ", UNIQUE(agent_id, boot_id, sequence)",
            "",
            "unique-sequence",
        ),
        (
            "results",
            "REFERENCES events(event_id) ON DELETE CASCADE",
            "REFERENCES events(event_id)",
            "foreign-key-action",
        ),
        (
            "results",
            "CHECK(port BETWEEN 1 AND 65535)",
            "",
            "check-constraint",
        ),
        (
            "results",
            "CHECK(check_kind IN ('vpn','sni'))",
            "",
            "check-kind-constraint",
        ),
    ],
)
def test_readiness_rejects_current_version_lookalike_missing_schema_guarantee(
    tmp_path, identity, table, old, new, guarantee
):
    """Version and names cannot substitute for the exact integrity contract."""
    db = CollectorDB(tmp_path / f"{guarantee}.db", [identity])
    _rewrite_schema_sql(db, table, old, new)

    assert db.is_ready() is False


@pytest.mark.parametrize(
    ("table", "old", "new"),
    [
        (
            "results",
            "CHECK(port BETWEEN 1 AND 65535)",
            "/* CHECK(port BETWEEN 1 AND 65535) */ CHECK(port > 0)",
        ),
        (
            "agents",
            "city TEXT NOT NULL",
            "city TEXT NOT NULL CHECK(length(city) > 0)",
        ),
        (
            "notifications",
            "CHECK(dead_letter IN (0, 1))",
            "CHECK(dead_letter IN (0, 1, 2))",
        ),
    ],
)
def test_readiness_rejects_comment_spoofed_extra_or_modified_check(
    tmp_path, identity, table, old, new
):
    """Exact DDL comparison must not mistake comments or extra predicates for guarantees."""
    db = CollectorDB(tmp_path / "spoof.db", [identity])
    _rewrite_schema_sql(db, table, old, new)

    assert db.is_ready() is False


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "ON notifications(completed, dead_letter, next_attempt_us, notification_id)",
            "ON notifications(completed, dead_letter, next_attempt_us, notification_id) WHERE completed = 0",
        ),
        (
            "next_attempt_us, notification_id",
            "next_attempt_us DESC, notification_id",
        ),
        (
            "completed, dead_letter",
            "completed COLLATE NOCASE, dead_letter",
        ),
        (
            "next_attempt_us, notification_id",
            "COALESCE(next_attempt_us, 0), notification_id",
        ),
    ],
)
def test_readiness_rejects_partial_desc_collation_or_expression_index(
    tmp_path, identity, old, new
):
    """Index names and column labels cannot hide weaker or different index semantics."""
    db = CollectorDB(tmp_path / "index-lookalike.db", [identity])
    _rewrite_index_sql(db, "notifications_pending_idx", old, new)

    assert db.is_ready() is False


def test_runtime_lock_error_is_normalized_without_sql_path_or_data(tmp_path, identity):
    """SQLite lock diagnostics must not leak through the collector boundary."""
    db = CollectorDB(tmp_path / "private-name.db", [identity], timeout_seconds=0.01)
    blocker = sqlite3.connect(db.path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(CollectorDBError) as raised:
            db.accept_report(_report(), identity, received_at=NOW)
    finally:
        blocker.rollback()
        blocker.close()

    assert str(raised.value) == "collector-database-error"
    assert "private-name" not in repr(raised.value)
    assert "INSERT" not in repr(raised.value)


def test_connect_error_is_normalized_and_readiness_fails_closed(tmp_path, identity, monkeypatch):
    """Open/disk failures use one closed code while a readiness probe returns false."""
    db = CollectorDB(tmp_path / "collector.db", [identity])

    def fail_connect(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O at /private/collector.db")

    monkeypatch.setattr(sqlite3, "connect", fail_connect)
    with pytest.raises(CollectorDBError, match="^collector-database-error$"):
        db.event_count()
    assert db.is_ready() is False


def test_injected_mid_transaction_sqlite_error_rolls_back_and_is_closed(tmp_path, identity):
    """A runtime schema/disk fault cannot leave half an event or expose SQL diagnostics."""
    db = CollectorDB(tmp_path / "collector.db", [identity])
    with sqlite3.connect(db.path) as connection:
        connection.execute("DROP TABLE results")

    with pytest.raises(CollectorDBError, match="^collector-database-error$") as raised:
        db.accept_report(_report(), identity, received_at=NOW)

    with sqlite3.connect(db.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0
    assert "results" not in repr(raised.value)
    assert "INSERT" not in repr(raised.value)


def _multiprocess_accept(path: str) -> bool:
    identity = AgentIdentity("agent-1", "Tbilisi", "Home ISP", 600)
    db = CollectorDB(path, [identity])
    return db.accept_report(_report(), identity, received_at=NOW).is_new


def test_multiprocess_acceptance_creates_one_event_and_outbox_entry(tmp_path, identity):
    """Separate collector processes must serialize event and notification creation."""
    path = tmp_path / "collector.db"
    CollectorDB(path, [identity])
    context = multiprocessing.get_context("spawn")
    with context.Pool(4) as pool:
        outcomes = pool.map(_multiprocess_accept, [str(path)] * 8)

    reopened = CollectorDB(path, [identity])
    assert sum(outcomes) == 1
    assert reopened.event_count() == 1
    assert reopened.pending_notification_count() == 1


def _create_v1_database(path, *, include_results=True):
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            PRAGMA user_version = 1;
            CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY, city TEXT NOT NULL, name TEXT NOT NULL,
                expected_interval_seconds INTEGER NOT NULL, last_seen_us INTEGER,
                offline INTEGER NOT NULL DEFAULT 0, offline_since_us INTEGER
            );
            CREATE TABLE agent_boots (
                agent_id TEXT NOT NULL REFERENCES agents(agent_id), boot_id TEXT NOT NULL,
                max_sequence INTEGER NOT NULL, PRIMARY KEY(agent_id, boot_id)
            );
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, observed_at_us INTEGER NOT NULL,
                received_at_us INTEGER NOT NULL, subscription_revision TEXT,
                refresh_state TEXT NOT NULL, snapshot_age_seconds INTEGER,
                diff_added_json TEXT NOT NULL, diff_removed_json TEXT NOT NULL,
                diff_changed_json TEXT NOT NULL, control_status TEXT NOT NULL,
                duration_ms INTEGER NOT NULL, xray_version TEXT,
                dropped_report_count INTEGER NOT NULL, payload_digest TEXT NOT NULL,
                UNIQUE(agent_id, boot_id, sequence)
            );
            CREATE INDEX events_agent_received_idx ON events(agent_id, received_at_us DESC);
            """
        )
        if include_results:
            connection.execute(
                """CREATE TABLE results (
                    event_id TEXT NOT NULL REFERENCES events(event_id), position INTEGER NOT NULL,
                    target_id TEXT NOT NULL, label TEXT NOT NULL, address TEXT NOT NULL,
                    port INTEGER NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL,
                    latency_ms INTEGER, resolved_ips_json TEXT NOT NULL, error_code TEXT,
                    PRIMARY KEY(event_id, position)
                )"""
            )


def test_v1_database_migrates_to_outbox_and_global_sequence(tmp_path, identity):
    """A prior Task 5 database must upgrade in place without weakening replay state."""
    path = tmp_path / "collector.db"
    _create_v1_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO agents(agent_id, city, name, expected_interval_seconds) VALUES (?, ?, ?, ?)",
            (identity.agent_id, identity.city, identity.name, 600),
        )
        connection.execute(
            """INSERT INTO events VALUES (
                'agent-1:boot-1:4', 'agent-1', 'boot-1', 4,
                1788523200000000, 1788523200000000, NULL, 'FRESH', NULL,
                '[]', '[]', '[]', 'UP', 1, NULL, 0, 'legacy-digest'
            )"""
        )
        connection.execute(
            """INSERT INTO results VALUES (
                'agent-1:boot-1:4', 0, 'legacy-target', 'Legacy', 'node.example',
                443, 'DOWN', 'TCP', NULL, '[]', 'tcp-timeout'
            )"""
        )

    db = CollectorDB(path, [identity])

    assert db.is_ready() is True
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT target_id, check_kind FROM results").fetchall() == [("legacy-target", "vpn")]
    with pytest.raises(SequenceConflict):
        db.accept_report(_report(sequence=4), identity, received_at=NOW)
    assert db.accept_report(_report(sequence=5), identity, received_at=NOW).is_new is True


def test_corrupt_v1_shape_fails_startup_after_migration_attempt(tmp_path, identity):
    """Migrating by user_version alone must not start with missing required tables."""
    path = tmp_path / "collector.db"
    _create_v1_database(path, include_results=False)

    with pytest.raises(CollectorDBError, match="schema"):
        CollectorDB(path, [identity])


def _downgrade_fresh_database_to_v2(path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE notification_chunks")
        connection.execute("DROP INDEX notifications_pending_idx")
        connection.execute("DROP INDEX notifications_dedupe_key_idx")
        connection.execute("DROP TABLE notifications")
        connection.executescript(
            """
            CREATE TABLE notifications (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK(kind IN ('REPORT','OFFLINE','RECOVERY')),
                agent_id TEXT NOT NULL REFERENCES agents(agent_id), event_id TEXT,
                created_at_us INTEGER NOT NULL, next_chunk INTEGER NOT NULL DEFAULT 0,
                chunk_count INTEGER NOT NULL CHECK(chunk_count > 0),
                completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
                lease_owner TEXT, lease_until_us INTEGER, dedupe_key TEXT NOT NULL UNIQUE,
                CHECK(next_chunk >= 0 AND next_chunk <= chunk_count)
            );
            CREATE TABLE notification_chunks (
                notification_id INTEGER NOT NULL REFERENCES notifications(notification_id) ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
                body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 3500),
                PRIMARY KEY(notification_id, chunk_index)
            );
            CREATE INDEX notifications_pending_idx ON notifications(completed, notification_id);
            CREATE UNIQUE INDEX notifications_dedupe_key_idx ON notifications(dedupe_key);
            PRAGMA user_version = 2;
            """
        )
        notification_id = connection.execute(
            """INSERT INTO notifications(kind, agent_id, created_at_us, chunk_count, dedupe_key)
            VALUES ('REPORT', 'agent-1', 1788523200000000, 1, 'legacy-report')"""
        ).lastrowid
        connection.execute(
            "INSERT INTO notification_chunks VALUES (?, 0, 'legacy chunk')",
            (notification_id,),
        )


def test_v2_outbox_migration_is_atomic_and_concurrent_safe(tmp_path, identity):
    """Independent collector startups must serialize the complete v2-to-v4 upgrade."""
    path = tmp_path / "collector.db"
    CollectorDB(path, [identity])
    _downgrade_fresh_database_to_v2(path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        databases = list(pool.map(lambda _: CollectorDB(path, [identity]), range(16)))

    assert all(database.is_ready() for database in databases)
    assert databases[0].pending_notification_count() == 1
    claim = databases[0].claim_notification("migration-check", NOW, lease_seconds=30)
    assert claim is not None and claim.body == "legacy chunk"
    databases[0].acknowledge_chunk(claim, "migration-check")
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
        columns = {row[1] for row in connection.execute("PRAGMA table_info(notifications)")}
        foreign_keys = {
            (row[3], row[2], row[4], row[6])
            for row in connection.execute("PRAGMA foreign_key_list(notifications)")
        }
    assert {
        "attempt_count", "next_attempt_us", "last_error_code", "dead_letter",
        "requeued", "requeued_notification_id", "requeued_at_us",
    } <= columns
    assert (
        "requeued_notification_id", "notifications", "notification_id", "SET NULL"
    ) in foreign_keys

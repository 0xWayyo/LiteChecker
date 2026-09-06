"""Transactional SQLite evidence storage and durable ordered notification outbox."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import unicodedata
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message, format_offline, format_recovery, format_report
from litechecker.models import AgentReport
from litechecker.security import redact


_SCHEMA_VERSION = 8
_MAX_OFFLINE_THRESHOLD = 604_800
_SAFE_BOOT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_NOTIFICATION_KINDS = frozenset({"REPORT", "OFFLINE", "RECOVERY"})
_REQUIRED_COLUMN_SPECS = {
    "agents": (
        ("agent_id", "TEXT", 0, None, 1), ("city", "TEXT", 1, None, 0),
        ("name", "TEXT", 1, None, 0), ("expected_interval_seconds", "INTEGER", 1, None, 0),
        ("active", "INTEGER", 1, "1", 0), ("last_seen_us", "INTEGER", 0, None, 0),
        ("offline", "INTEGER", 1, "0", 0), ("offline_since_us", "INTEGER", 0, None, 0),
        ("max_sequence", "INTEGER", 0, None, 0),
        ("activated_at_us", "INTEGER", 1, "0", 0),
        ("rate_window_started_us", "INTEGER", 0, None, 0),
        ("rate_count", "INTEGER", 1, "0", 0),
    ),
    "agent_boots": (
        ("agent_id", "TEXT", 1, None, 1), ("boot_id", "TEXT", 1, None, 2),
        ("max_sequence", "INTEGER", 1, None, 0),
    ),
    "events": (
        ("event_id", "TEXT", 0, None, 1), ("agent_id", "TEXT", 1, None, 0),
        ("boot_id", "TEXT", 1, None, 0), ("sequence", "INTEGER", 1, None, 0),
        ("observed_at_us", "INTEGER", 1, None, 0), ("received_at_us", "INTEGER", 1, None, 0),
        ("subscription_revision", "TEXT", 0, None, 0), ("refresh_state", "TEXT", 1, None, 0),
        ("snapshot_age_seconds", "INTEGER", 0, None, 0), ("diff_added_json", "TEXT", 1, None, 0),
        ("diff_removed_json", "TEXT", 1, None, 0), ("diff_changed_json", "TEXT", 1, None, 0),
        ("control_status", "TEXT", 1, None, 0), ("duration_ms", "INTEGER", 1, None, 0),
        ("xray_version", "TEXT", 0, None, 0), ("dropped_report_count", "INTEGER", 1, None, 0),
        ("payload_digest", "TEXT", 1, None, 0),
        ("run_status", "TEXT", 1, "'UP'", 0),
        ("run_reason", "TEXT", 0, None, 0),
    ),
    "results": (
        ("event_id", "TEXT", 1, None, 1), ("position", "INTEGER", 1, None, 2),
        ("target_id", "TEXT", 1, None, 0), ("label", "TEXT", 1, None, 0),
        ("address", "TEXT", 1, None, 0), ("port", "INTEGER", 1, None, 0),
        ("status", "TEXT", 1, None, 0), ("stage", "TEXT", 1, None, 0),
        ("latency_ms", "INTEGER", 0, None, 0), ("resolved_ips_json", "TEXT", 1, None, 0),
        ("error_code", "TEXT", 0, None, 0),
        ("check_kind", "TEXT", 1, "'vpn'", 0),
    ),
    "notifications": (
        ("notification_id", "INTEGER", 0, None, 1), ("kind", "TEXT", 1, None, 0),
        ("agent_id", "TEXT", 1, None, 0), ("event_id", "TEXT", 0, None, 0),
        ("created_at_us", "INTEGER", 1, None, 0), ("next_chunk", "INTEGER", 1, "0", 0),
        ("chunk_count", "INTEGER", 1, None, 0), ("completed", "INTEGER", 1, "0", 0),
        ("lease_owner", "TEXT", 0, None, 0), ("lease_until_us", "INTEGER", 0, None, 0),
        ("dedupe_key", "TEXT", 1, None, 0), ("attempt_count", "INTEGER", 1, "0", 0),
        ("next_attempt_us", "INTEGER", 0, None, 0), ("last_error_code", "TEXT", 0, None, 0),
        ("last_error_at_us", "INTEGER", 0, None, 0), ("dead_letter", "INTEGER", 1, "0", 0),
        ("dead_letter_at_us", "INTEGER", 0, None, 0),
        ("requeued_notification_id", "INTEGER", 0, None, 0),
        ("requeued_at_us", "INTEGER", 0, None, 0),
        ("requeued", "INTEGER", 1, "0", 0),
    ),
    "notification_chunks": (
        ("notification_id", "INTEGER", 1, None, 1), ("chunk_index", "INTEGER", 1, None, 2),
        ("body", "TEXT", 1, None, 0),
    ),
}
_REQUIRED_UNIQUE_COLUMNS = {
    "agents": {("agent_id",)},
    "agent_boots": {("agent_id", "boot_id")},
    "events": {("event_id",), ("agent_id", "boot_id", "sequence")},
    "results": {("event_id", "position")},
    "notifications": {("dedupe_key",)},
    "notification_chunks": {("notification_id", "chunk_index")},
}
_REQUIRED_FOREIGN_KEYS = {
    "agents": set(),
    "agent_boots": {("agent_id", "agents", "agent_id", "NO ACTION", "CASCADE")},
    "events": {("agent_id", "agents", "agent_id", "NO ACTION", "NO ACTION")},
    "results": {("event_id", "events", "event_id", "NO ACTION", "CASCADE")},
    "notifications": {
        ("agent_id", "agents", "agent_id", "NO ACTION", "NO ACTION"),
        ("requeued_notification_id", "notifications", "notification_id", "NO ACTION", "SET NULL"),
    },
    "notification_chunks": {("notification_id", "notifications", "notification_id", "NO ACTION", "CASCADE")},
}
_REQUIRED_INDEXES = {
    "events_agent_received_idx": ("events", ("agent_id", "received_at_us"), False),
    "notifications_pending_idx": ("notifications", ("completed", "dead_letter", "next_attempt_us", "notification_id"), False),
    "notifications_dedupe_key_idx": ("notifications", ("dedupe_key",), True),
}


class CollectorDBError(RuntimeError):
    """A closed database failure safe for logs and HTTP responses."""


class SequenceConflict(CollectorDBError):
    def __init__(self) -> None:
        super().__init__("report-sequence-conflict")


class ReportRateLimited(CollectorDBError):
    def __init__(self) -> None:
        super().__init__("report-rate-limited")


class CollectorBackpressure(CollectorDBError):
    def __init__(self) -> None:
        super().__init__("collector-backpressure")


@dataclass(frozen=True)
class AcceptResult:
    is_new: bool
    recovered: bool


@dataclass(frozen=True)
class OfflineTransition:
    agent: AgentIdentity
    last_seen: datetime
    offline_since: datetime
    never_seen: bool = False


@dataclass(frozen=True)
class ClaimedNotification:
    notification_id: int
    kind: str
    chunk_index: int
    chunk_count: int
    body: str


@dataclass(frozen=True)
class DeadLetter:
    notification_id: int
    kind: str
    next_chunk: int
    chunk_count: int
    attempt_count: int
    error_code: str
    failed_at: datetime


class CollectorDB:
    """Use a short, WAL-backed connection and transaction for every operation."""

    def __init__(
        self,
        path: str | Path,
        agents: Iterable[AgentIdentity] = (),
        *,
        offline_threshold_seconds: int = 1_500,
        timeout_seconds: float = 5.0,
        registry_activated_at: datetime | None = None,
        report_burst: int = 3,
        report_window_seconds: int = 60,
        event_retention_seconds: int = 2_592_000,
        max_events_per_agent: int = 5_000,
        completed_notification_retention_seconds: int = 604_800,
        max_completed_notifications: int = 5_000,
        max_dead_letters_per_agent: int = 100,
        max_pending_notifications_per_agent: int = 100,
        max_pending_notifications_global: int = 10_000,
        max_pending_chunks_per_agent: int = 1_000,
        max_pending_chunks_global: int = 100_000,
    ):
        self.path = Path(path)
        if isinstance(offline_threshold_seconds, bool) or not isinstance(offline_threshold_seconds, int) or not 1 <= offline_threshold_seconds <= _MAX_OFFLINE_THRESHOLD:
            raise ValueError("offline threshold is invalid")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("database timeout is invalid")
        self._offline_threshold = offline_threshold_seconds
        self._timeout = float(timeout_seconds)
        activated_at = registry_activated_at or datetime.now(UTC)
        self._registry_activated_us = _utc_microseconds(activated_at)
        for value, name, lower, upper in (
            (report_burst, "report burst", 1, 100),
            (report_window_seconds, "report window", 1, 86_400),
            (event_retention_seconds, "event retention", 600, 31_536_000),
            (max_events_per_agent, "event cap", 1, 100_000),
            (
                completed_notification_retention_seconds,
                "notification retention",
                60,
                31_536_000,
            ),
            (max_completed_notifications, "notification cap", 1, 100_000),
            (max_dead_letters_per_agent, "dead letter cap", 1, 10_000),
            (
                max_pending_notifications_per_agent,
                "per-agent pending notification cap",
                1,
                100_000,
            ),
            (
                max_pending_notifications_global,
                "global pending notification cap",
                1,
                1_000_000,
            ),
            (max_pending_chunks_per_agent, "per-agent pending chunk cap", 1, 1_000_000),
            (max_pending_chunks_global, "global pending chunk cap", 1, 10_000_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise ValueError(f"{name} is invalid")
        self._report_burst = report_burst
        self._report_window_us = report_window_seconds * 1_000_000
        self._event_retention_us = event_retention_seconds * 1_000_000
        self._max_events_per_agent = max_events_per_agent
        self._completed_retention_us = completed_notification_retention_seconds * 1_000_000
        self._max_completed_notifications = max_completed_notifications
        self._max_dead_letters_per_agent = max_dead_letters_per_agent
        self._max_pending_notifications_per_agent = max_pending_notifications_per_agent
        self._max_pending_notifications_global = max_pending_notifications_global
        self._max_pending_chunks_per_agent = max_pending_chunks_per_agent
        self._max_pending_chunks_global = max_pending_chunks_global
        self._migration_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize(tuple(agents))

    def _initialize(self, agents: tuple[AgentIdentity, ...]) -> None:
        with self._migration_lock, self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                _create_schema(connection)
            elif version == 1:
                _migrate_v1_to_v2(connection)
                _migrate_v2_to_v3(connection)
                _migrate_v3_to_v4(connection)
                _migrate_v4_to_v5(connection)
                _migrate_v5_to_v6(connection)
                _migrate_v6_to_v7(connection)
            elif version == 2:
                _migrate_v2_to_v3(connection)
                _migrate_v3_to_v4(connection)
                _migrate_v4_to_v5(connection)
                _migrate_v5_to_v6(connection)
                _migrate_v6_to_v7(connection)
            elif version == 3:
                _migrate_v3_to_v4(connection)
                _migrate_v4_to_v5(connection)
                _migrate_v5_to_v6(connection)
                _migrate_v6_to_v7(connection)
            elif version == 4:
                _migrate_v4_to_v5(connection)
                _migrate_v5_to_v6(connection)
                _migrate_v6_to_v7(connection)
            elif version == 5:
                _migrate_v5_to_v6(connection)
                _migrate_v6_to_v7(connection)
            elif version == 6:
                _migrate_v6_to_v7(connection)
            elif version not in (7, _SCHEMA_VERSION):
                raise CollectorDBError("database-schema-unsupported")
            if 1 <= version <= 7:
                _migrate_v7_to_v8(connection)
            self._sync_registry(connection, agents, self._registry_activated_us)
            if not _schema_ready(connection):
                raise CollectorDBError("database-schema-invalid")
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def accept_report(self, report: AgentReport, agent: AgentIdentity, *, received_at: datetime) -> AcceptResult:
        received_us = _utc_microseconds(received_at)
        observed_us = _utc_microseconds(report.observed_at)
        if report.agent_id != agent.agent_id:
            raise ValueError("authenticated agent does not match report")
        boot_id = _safe_boot_id(report.boot_id)
        if report.event_id != f"{agent.agent_id}:{boot_id}:{report.sequence}":
            raise ValueError("event id does not match agent boot sequence")
        payload_digest = _safe_report_digest(report)
        with self._transaction() as connection:
            agent_row = connection.execute(
                """SELECT active, max_sequence, offline,
                          rate_window_started_us, rate_count
                   FROM agents WHERE agent_id = ?""",
                (agent.agent_id,),
            ).fetchone()
            if agent_row is None or not agent_row[0]:
                raise CollectorDBError("collector-agent-inactive")
            duplicate = connection.execute("SELECT agent_id, boot_id, sequence, payload_digest FROM events WHERE event_id = ?", (report.event_id,)).fetchone()
            if duplicate is not None:
                if duplicate != (agent.agent_id, boot_id, report.sequence, payload_digest):
                    raise SequenceConflict()
                return AcceptResult(False, False)
            if agent_row[1] is not None and report.sequence <= agent_row[1]:
                raise SequenceConflict()
            dead_letters = connection.execute(
                "SELECT COUNT(*) FROM notifications WHERE agent_id = ? AND dead_letter = 1 AND requeued = 0",
                (agent.agent_id,),
            ).fetchone()[0]
            if dead_letters >= self._max_dead_letters_per_agent:
                raise CollectorBackpressure()
            window_started_us = agent_row[3]
            rate_count = agent_row[4]
            if (
                window_started_us is None
                or received_us < window_started_us
                or received_us - window_started_us >= self._report_window_us
            ):
                window_started_us = received_us
                rate_count = 0
            if rate_count >= self._report_burst:
                raise ReportRateLimited()
            _prune_history(
                connection,
                agent.agent_id,
                received_us,
                event_retention_us=self._event_retention_us,
                max_events=max(1, self._max_events_per_agent - 1),
                completed_retention_us=self._completed_retention_us,
                max_completed=self._max_completed_notifications,
            )
            recovered = bool(agent_row[2])
            received = _from_microseconds(received_us)
            notification_payloads = [
                ("REPORT", format_report(report, agent, received_at=received))
            ]
            if recovered:
                notification_payloads.insert(
                    0,
                    ("RECOVERY", format_recovery(agent, recovered_at=received)),
                )
            _ensure_pending_capacity(
                connection,
                agent.agent_id,
                [body for _, body in notification_payloads],
                max_notifications_per_agent=self._max_pending_notifications_per_agent,
                max_notifications_global=self._max_pending_notifications_global,
                max_chunks_per_agent=self._max_pending_chunks_per_agent,
                max_chunks_global=self._max_pending_chunks_global,
            )
            connection.execute(
                """INSERT INTO events (event_id, agent_id, boot_id, sequence, observed_at_us, received_at_us, subscription_revision, refresh_state, snapshot_age_seconds, diff_added_json, diff_removed_json, diff_changed_json, control_status, duration_ms, xray_version, dropped_report_count, payload_digest, run_status, run_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (report.event_id, agent.agent_id, boot_id, report.sequence, observed_us, received_us, _safe_optional_text(report.subscription_revision, 128), report.refresh_state, report.snapshot_age_seconds, _safe_json_list(report.diff.added, 256), _safe_json_list(report.diff.removed, 256), _safe_json_list(report.diff.changed, 256), report.control_status.value, report.duration_ms, _safe_optional_text(report.xray_version, 64), report.dropped_report_count, payload_digest, report.run_status.value, report.run_reason),
            )
            for position, result in enumerate(report.results):
                connection.execute(
                    """INSERT INTO results (event_id, position, target_id, label, address, port, status, stage, latency_ms, resolved_ips_json, error_code, check_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (report.event_id, position, _safe_text(result.target_id, 256), _safe_text(result.label, 256), _safe_text(result.address, 255), result.port, result.status.value, result.stage.value, result.latency_ms, _safe_json_list(result.resolved_ips, 64), _safe_optional_text(result.error_code, 64), result.check_kind),
                )
            connection.execute("""INSERT INTO agent_boots(agent_id, boot_id, max_sequence) VALUES (?, ?, ?) ON CONFLICT(agent_id, boot_id) DO UPDATE SET max_sequence = MAX(agent_boots.max_sequence, excluded.max_sequence)""", (agent.agent_id, boot_id, report.sequence))
            connection.execute(
                """UPDATE agents SET last_seen_us = MAX(COALESCE(last_seen_us, ?), ?),
                          offline = 0, offline_since_us = NULL, max_sequence = ?,
                          rate_window_started_us = ?, rate_count = ?
                   WHERE agent_id = ?""",
                (
                    received_us,
                    received_us,
                    report.sequence,
                    window_started_us,
                    rate_count + 1,
                    agent.agent_id,
                ),
            )
            for kind, body in notification_payloads:
                _enqueue_notification(
                    connection, kind, agent, report.event_id, received_us, body
                )
            _prune_history(
                connection,
                agent.agent_id,
                received_us,
                event_retention_us=self._event_retention_us,
                max_events=self._max_events_per_agent,
                completed_retention_us=self._completed_retention_us,
                max_completed=self._max_completed_notifications,
            )
            return AcceptResult(True, recovered)

    def offline_transitions(self, now: datetime) -> list[OfflineTransition]:
        now_us = _utc_microseconds(now)
        transitions: list[OfflineTransition] = []
        with self._transaction() as connection:
            rows = connection.execute("SELECT agent_id, city, name, expected_interval_seconds, last_seen_us, activated_at_us FROM agents WHERE active = 1 AND offline = 0 ORDER BY agent_id").fetchall()
            for agent_id, city, name, interval, last_seen_us, activated_at_us in rows:
                evidence_us = last_seen_us if last_seen_us is not None else activated_at_us
                threshold = max(self._offline_threshold, (interval * 5 + 1) // 2)
                if now_us - evidence_us < threshold * 1_000_000:
                    continue
                agent = AgentIdentity(agent_id, city, name, interval)
                transition = OfflineTransition(agent, _from_microseconds(evidence_us), _from_microseconds(now_us), last_seen_us is None)
                body = format_offline(
                    agent,
                    last_seen=transition.last_seen,
                    offline_since=transition.offline_since,
                    never_seen=transition.never_seen,
                )
                _ensure_pending_capacity(
                    connection,
                    agent_id,
                    [body],
                    max_notifications_per_agent=self._max_pending_notifications_per_agent,
                    max_notifications_global=self._max_pending_notifications_global,
                    max_chunks_per_agent=self._max_pending_chunks_per_agent,
                    max_chunks_global=self._max_pending_chunks_global,
                )
                changed = connection.execute("UPDATE agents SET offline = 1, offline_since_us = ? WHERE agent_id = ? AND active = 1 AND offline = 0", (now_us, agent_id)).rowcount
                if not changed:
                    continue
                _enqueue_notification(connection, "OFFLINE", agent, None, now_us, body, dedupe_key=f"OFFLINE:{agent_id}:{now_us}")
                transitions.append(transition)
        return transitions

    def claim_notification(self, owner: str, now: datetime, *, lease_seconds: float) -> ClaimedNotification | None:
        owner = _safe_owner(owner)
        now_us = _utc_microseconds(now)
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not math.isfinite(lease_seconds) or not 1 <= lease_seconds <= 300:
            raise ValueError("notification lease is invalid")
        lease_until = now_us + int(lease_seconds * 1_000_000)
        with self._transaction() as connection:
            row = connection.execute("SELECT notification_id, kind, next_chunk, chunk_count, lease_owner, lease_until_us, next_attempt_us FROM notifications WHERE completed = 0 AND dead_letter = 0 ORDER BY notification_id LIMIT 1").fetchone()
            if row is None:
                return None
            notification_id, kind, next_chunk, chunk_count, current_owner, current_until, next_attempt = row
            if next_attempt is not None and next_attempt > now_us:
                return None
            if current_until is not None and current_until > now_us and current_owner != owner:
                return None
            changed = connection.execute("UPDATE notifications SET lease_owner = ?, lease_until_us = ? WHERE notification_id = ? AND completed = 0 AND dead_letter = 0 AND (next_attempt_us IS NULL OR next_attempt_us <= ?) AND (lease_until_us IS NULL OR lease_until_us <= ? OR lease_owner = ?)", (owner, lease_until, notification_id, now_us, now_us, owner)).rowcount
            if not changed:
                return None
            body_row = connection.execute("SELECT body FROM notification_chunks WHERE notification_id = ? AND chunk_index = ?", (notification_id, next_chunk)).fetchone()
            if body_row is None:
                raise CollectorDBError("notification-outbox-corrupt")
            return ClaimedNotification(notification_id, kind, next_chunk, chunk_count, body_row[0])

    def acknowledge_chunk(self, claim: ClaimedNotification, owner: str, now: datetime | None = None) -> None:
        owner = _safe_owner(owner)
        now_us = None if now is None else _utc_microseconds(now)
        with self._transaction() as connection:
            row = connection.execute("SELECT next_chunk, chunk_count, lease_owner, completed, dead_letter, lease_until_us, agent_id FROM notifications WHERE notification_id = ?", (claim.notification_id,)).fetchone()
            expired = now_us is not None and (row is None or row[5] is None or row[5] <= now_us)
            if row is None or expired or row[3] or row[4] or row[2] != owner or row[0] != claim.chunk_index:
                raise CollectorDBError("notification-claim-lost")
            next_chunk = row[0] + 1
            completed = next_chunk >= row[1]
            connection.execute("UPDATE notifications SET next_chunk = ?, completed = ?, lease_owner = NULL, lease_until_us = NULL, attempt_count = 0, next_attempt_us = NULL, last_error_code = NULL, last_error_at_us = NULL WHERE notification_id = ?", (next_chunk, int(completed), claim.notification_id))
            if completed and now_us is not None:
                _prune_history(
                    connection,
                    row[6],
                    now_us,
                    event_retention_us=self._event_retention_us,
                    max_events=self._max_events_per_agent,
                    completed_retention_us=self._completed_retention_us,
                    max_completed=self._max_completed_notifications,
                )

    def release_notification(self, claim: ClaimedNotification, owner: str) -> None:
        owner = _safe_owner(owner)
        with self._transaction() as connection:
            connection.execute("UPDATE notifications SET lease_owner = NULL, lease_until_us = NULL WHERE notification_id = ? AND lease_owner = ? AND completed = 0 AND dead_letter = 0", (claim.notification_id, owner))

    def reset_notification_leases(self) -> None:
        """Clear crash metadata after the caller proves exclusive OS-lock ownership."""
        with self._transaction() as connection:
            connection.execute(
                """UPDATE notifications SET lease_owner = NULL, lease_until_us = NULL
                   WHERE completed = 0 AND dead_letter = 0
                     AND (lease_owner IS NOT NULL OR lease_until_us IS NOT NULL)"""
            )

    def record_notification_failure(
        self,
        claim: ClaimedNotification,
        owner: str,
        error_code: str,
        now: datetime,
        *,
        permanent: bool,
        max_attempts: int,
        retry_delay_seconds: float,
    ) -> bool:
        owner = _safe_owner(owner)
        error_code = _safe_error_code(error_code)
        now_us = _utc_microseconds(now)
        if not isinstance(permanent, bool):
            raise ValueError("notification failure class is invalid")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 100:
            raise ValueError("notification attempt limit is invalid")
        if isinstance(retry_delay_seconds, bool) or not isinstance(retry_delay_seconds, (int, float)) or not math.isfinite(retry_delay_seconds) or not 0 <= retry_delay_seconds <= 3600:
            raise ValueError("notification retry delay is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT next_chunk, attempt_count, lease_owner, completed, dead_letter FROM notifications WHERE notification_id = ?",
                (claim.notification_id,),
            ).fetchone()
            if row is None or row[2] != owner or row[0] != claim.chunk_index or row[3] or row[4]:
                raise CollectorDBError("notification-claim-lost")
            attempts = row[1] + 1
            terminal = permanent or attempts >= max_attempts
            retry_at = None if terminal else now_us + int(retry_delay_seconds * 1_000_000)
            connection.execute(
                """UPDATE notifications SET attempt_count = ?, next_attempt_us = ?, last_error_code = ?, last_error_at_us = ?, dead_letter = ?, dead_letter_at_us = ?, lease_owner = NULL, lease_until_us = NULL WHERE notification_id = ?""",
                (attempts, retry_at, error_code, now_us, int(terminal), now_us if terminal else None, claim.notification_id),
            )
            return terminal

    def last_seen(self, agent_id: str) -> datetime | None:
        with self._connection() as connection:
            row = connection.execute("SELECT last_seen_us FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        return None if row is None or row[0] is None else _from_microseconds(row[0])

    def event_count(self) -> int:
        return self._scalar("SELECT COUNT(*) FROM events")

    def pending_notification_count(self) -> int:
        return self._scalar("SELECT COUNT(*) FROM notifications WHERE completed = 0 AND dead_letter = 0")

    def notification_delivered(self, event_id: str) -> bool:
        """Confirm retained REPORT delivery, including any requeued remainder."""
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT completed, dead_letter, next_chunk, chunk_count
                   FROM notifications
                   WHERE event_id = ? AND kind = 'REPORT' AND requeued = 0""",
                (event_id,),
            ).fetchall()
        return bool(rows) and all(
            completed == 1 and dead_letter == 0 and next_chunk == chunk_count
            for completed, dead_letter, next_chunk, chunk_count in rows
        )

    def dead_letter_count(self) -> int:
        return self._scalar(
            "SELECT COUNT(*) FROM notifications WHERE dead_letter = 1 AND requeued = 0"
        )

    @property
    def dispatch_lock_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.dispatcher.lock")

    def storage_stats(self) -> dict[str, int]:
        with self._connection() as connection:
            return {
                "events": int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
                "results": int(connection.execute("SELECT COUNT(*) FROM results").fetchone()[0]),
                "pending_notifications": int(connection.execute("SELECT COUNT(*) FROM notifications WHERE completed = 0 AND dead_letter = 0").fetchone()[0]),
                "completed_notifications": int(connection.execute("SELECT COUNT(*) FROM notifications WHERE completed = 1").fetchone()[0]),
                "dead_letters": int(connection.execute("SELECT COUNT(*) FROM notifications WHERE dead_letter = 1 AND requeued = 0").fetchone()[0]),
                "pending_chunks": int(connection.execute("SELECT COALESCE(SUM(chunk_count - next_chunk), 0) FROM notifications WHERE completed = 0 AND dead_letter = 0").fetchone()[0]),
            }

    def dead_letters(self, *, limit: int = 100) -> list[DeadLetter]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("dead letter limit is invalid")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT notification_id, kind, next_chunk, chunk_count, attempt_count, last_error_code, dead_letter_at_us FROM notifications WHERE dead_letter = 1 AND requeued = 0 ORDER BY notification_id LIMIT ?""",
                (limit,),
            ).fetchall()
        return [DeadLetter(row[0], row[1], row[2], row[3], row[4], row[5], _from_microseconds(row[6])) for row in rows]

    def requeue_dead_letter(self, notification_id: int, now: datetime) -> int:
        if isinstance(notification_id, bool) or not isinstance(notification_id, int) or notification_id < 1:
            raise ValueError("notification id is invalid")
        now_us = _utc_microseconds(now)
        with self._transaction() as connection:
            source = connection.execute(
                """SELECT kind, agent_id, event_id, next_chunk, chunk_count,
                          completed, dead_letter, requeued_notification_id, requeued
                   FROM notifications WHERE notification_id = ?""",
                (notification_id,),
            ).fetchone()
            if source is None or source[5] or not source[6]:
                raise CollectorDBError("notification-dead-letter-not-found")
            if source[8]:
                if source[7] is None:
                    raise CollectorDBError("notification-dead-letter-not-found")
                return int(source[7])
            chunks = connection.execute(
                """SELECT body FROM notification_chunks
                   WHERE notification_id = ? AND chunk_index >= ?
                   ORDER BY chunk_index""",
                (notification_id, source[3]),
            ).fetchall()
            expected_remaining = source[4] - source[3]
            if expected_remaining < 1 or len(chunks) != expected_remaining:
                raise CollectorDBError("notification-dead-letter-invalid")
            _ensure_pending_capacity(
                connection,
                source[1],
                [row[0] for row in chunks],
                max_notifications_per_agent=self._max_pending_notifications_per_agent,
                max_notifications_global=self._max_pending_notifications_global,
                max_chunks_per_agent=self._max_pending_chunks_per_agent,
                max_chunks_global=self._max_pending_chunks_global,
                notification_additions=1,
            )
            cursor = connection.execute(
                """INSERT INTO notifications(
                       kind, agent_id, event_id, created_at_us, chunk_count, dedupe_key,
                       next_attempt_us
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    source[0], source[1], source[2], now_us, expected_remaining,
                    f"REQUEUE:{notification_id}", now_us,
                ),
            )
            clone_id = int(cursor.lastrowid)
            connection.executemany(
                """INSERT INTO notification_chunks(notification_id, chunk_index, body)
                   VALUES (?, ?, ?)""",
                [
                    (clone_id, chunk_index, row[0])
                    for chunk_index, row in enumerate(chunks)
                ],
            )
            changed = connection.execute(
                """UPDATE notifications
                   SET requeued_notification_id = ?, requeued_at_us = ?, requeued = 1
                   WHERE notification_id = ? AND requeued = 0""",
                (clone_id, now_us, notification_id),
            ).rowcount
            if changed != 1:
                raise CollectorDBError("notification-requeue-conflict")
            return clone_id

    def retry_dead_letters(self, now: datetime) -> int:
        """Rearm unresolved failures in place when a standalone operator restarts."""
        now_us = _utc_microseconds(now)
        with self._transaction() as connection:
            return connection.execute(
                """UPDATE notifications
                   SET dead_letter = 0, dead_letter_at_us = NULL,
                       attempt_count = 0, next_attempt_us = ?,
                       last_error_code = NULL, last_error_at_us = NULL,
                       lease_owner = NULL, lease_until_us = NULL
                   WHERE completed = 0 AND dead_letter = 1 AND requeued = 0""",
                (now_us,),
            ).rowcount

    def pending_notification_kinds(self) -> list[str]:
        with self._connection() as connection:
            return [row[0] for row in connection.execute("SELECT kind FROM notifications WHERE completed = 0 AND dead_letter = 0 ORDER BY notification_id")]

    def oldest_pending_progress(self) -> tuple[int, int, int]:
        with self._connection() as connection:
            row = connection.execute("SELECT notification_id, next_chunk, chunk_count FROM notifications WHERE completed = 0 AND dead_letter = 0 ORDER BY notification_id LIMIT 1").fetchone()
        if row is None:
            raise CollectorDBError("notification-outbox-empty")
        return row

    def is_ready(self) -> bool:
        try:
            with self._connection() as connection:
                return _schema_ready(connection)
        except CollectorDBError:
            return False

    def _scalar(self, statement: str) -> int:
        with self._connection() as connection:
            return int(connection.execute(statement).fetchone()[0])

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
                raise
            else:
                connection.commit()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None, check_same_thread=False)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout * 1_000)}")
            connection.execute("PRAGMA journal_mode = WAL")
            yield connection
        except CollectorDBError:
            raise
        except sqlite3.Error:
            raise CollectorDBError("collector-database-error") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass

    @staticmethod
    def _sync_registry(connection: sqlite3.Connection, agents: tuple[AgentIdentity, ...], activated_at_us: int) -> None:
        identifiers = [agent.agent_id for agent in agents]
        if identifiers:
            placeholders = ",".join("?" for _ in identifiers)
            connection.execute(f"UPDATE agents SET active = 0 WHERE agent_id NOT IN ({placeholders})", identifiers)
        else:
            connection.execute("UPDATE agents SET active = 0")
        for agent in agents:
            current = connection.execute("SELECT active FROM agents WHERE agent_id = ?", (agent.agent_id,)).fetchone()
            if current is None:
                connection.execute("INSERT INTO agents(agent_id, city, name, expected_interval_seconds, active, activated_at_us) VALUES (?, ?, ?, ?, 1, ?)", (agent.agent_id, agent.city, agent.name, agent.expected_interval_seconds, activated_at_us))
            elif current[0]:
                connection.execute(
                    """UPDATE agents SET city = ?, name = ?, expected_interval_seconds = ?,
                              activated_at_us = CASE WHEN activated_at_us = 0 THEN ? ELSE activated_at_us END
                       WHERE agent_id = ?""",
                    (
                        agent.city,
                        agent.name,
                        agent.expected_interval_seconds,
                        activated_at_us,
                        agent.agent_id,
                    ),
                )
            else:
                connection.execute("UPDATE agents SET city = ?, name = ?, expected_interval_seconds = ?, active = 1, last_seen_us = NULL, offline = 0, offline_since_us = NULL, activated_at_us = ?, rate_window_started_us = NULL, rate_count = 0 WHERE agent_id = ?", (agent.city, agent.name, agent.expected_interval_seconds, activated_at_us, agent.agent_id))


def _create_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)
    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def _migrate_v7_to_v8(connection: sqlite3.Connection) -> None:
    """Retain historical VPN evidence while distinguishing new direct SNI checks."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(results)")}
    if "check_kind" not in columns:
        connection.execute(
            "ALTER TABLE results ADD COLUMN check_kind TEXT NOT NULL DEFAULT 'vpn' "
            "CHECK(check_kind IN ('vpn','sni'))"
        )
    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def _migrate_v5_to_v6(connection: sqlite3.Connection) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(agents)")}
    additions = (
        ("rate_window_started_us", "INTEGER"),
        ("rate_count", "INTEGER NOT NULL DEFAULT 0 CHECK(rate_count >= 0)"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE agents ADD COLUMN {name} {definition}")
    connection.execute("PRAGMA user_version = 6")


def _migrate_v6_to_v7(connection: sqlite3.Connection) -> None:
    """Replace the self-FK with SET NULL while retaining a durable terminal marker."""
    connection.execute("ALTER TABLE notifications RENAME TO notifications_old")
    connection.execute(_OUTBOX_STATEMENTS[0].replace(" IF NOT EXISTS", "", 1))
    connection.execute(
        """INSERT INTO notifications(
               notification_id, kind, agent_id, event_id, created_at_us, next_chunk,
               chunk_count, completed, lease_owner, lease_until_us, dedupe_key,
               attempt_count, next_attempt_us, last_error_code, last_error_at_us,
               dead_letter, dead_letter_at_us, requeued_notification_id,
               requeued_at_us, requeued
           )
           SELECT notification_id, kind, agent_id, event_id, created_at_us, next_chunk,
                  chunk_count, completed, lease_owner, lease_until_us, dedupe_key,
                  attempt_count, next_attempt_us, last_error_code, last_error_at_us,
                  dead_letter, dead_letter_at_us, requeued_notification_id,
                  requeued_at_us,
                  CASE WHEN requeued_notification_id IS NULL THEN 0 ELSE 1 END
           FROM notifications_old"""
    )
    chunks_sql = _OUTBOX_STATEMENTS[1].replace(
        "notification_chunks", "notification_chunks_upgrade", 1
    ).replace(" IF NOT EXISTS", "", 1)
    connection.execute(chunks_sql)
    connection.execute(
        """INSERT INTO notification_chunks_upgrade(notification_id, chunk_index, body)
           SELECT notification_id, chunk_index, body FROM notification_chunks"""
    )
    connection.execute("DROP TABLE notification_chunks")
    connection.execute("DROP TABLE notifications_old")
    connection.execute(
        "ALTER TABLE notification_chunks_upgrade RENAME TO notification_chunks"
    )
    connection.execute(_OUTBOX_STATEMENTS[2])
    connection.execute(_OUTBOX_STATEMENTS[3])
    connection.execute("PRAGMA user_version = 7")


def _schema_ready(connection: sqlite3.Connection) -> bool:
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        return False
    if connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
        return False
    if connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
        return False
    for table, expected in _REQUIRED_COLUMN_SPECS.items():
        columns = tuple(
            (row[1], row[2].upper(), row[3], row[4], row[5], row[6])
            for row in connection.execute(f"PRAGMA table_xinfo({table})")
        )
        if columns != tuple(spec + (0,) for spec in expected):
            return False
        unique_columns = {
            tuple(item[2] for item in connection.execute(f"PRAGMA index_info({row[1]})"))
            for row in connection.execute(f"PRAGMA index_list({table})")
            if row[2]
        }
        if unique_columns != _REQUIRED_UNIQUE_COLUMNS[table]:
            return False
        foreign_keys = {
            (row[3], row[2], row[4], row[5], row[6])
            for row in connection.execute(f"PRAGMA foreign_key_list({table})")
        }
        if foreign_keys != _REQUIRED_FOREIGN_KEYS[table]:
            return False
        sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        if sql_row is None or not isinstance(sql_row[0], str):
            return False
        if _canonical_sql(sql_row[0]) != _CANONICAL_TABLE_SQL[table]:
            return False
        expected_indexes = _REQUIRED_INDEX_MANIFESTS[table]
        actual_index_list = {
            row[1]: (row[2], row[3], row[4])
            for row in connection.execute(f"PRAGMA index_list({table})")
        }
        if actual_index_list != {
            name: manifest[:3] for name, manifest in expected_indexes.items()
        }:
            return False
        for name, manifest in expected_indexes.items():
            actual_xinfo = tuple(
                (row[1], row[2], row[3], row[4], row[5])
                for row in connection.execute(f"PRAGMA index_xinfo({name})")
            )
            if actual_xinfo != manifest[3]:
                return False
    for name, (table, expected_columns, expected_unique) in _REQUIRED_INDEXES.items():
        index_row = connection.execute(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?",
            (name,),
        ).fetchone()
        if index_row is None or index_row[0] != table:
            return False
        columns = tuple(
            row[2] for row in connection.execute(f"PRAGMA index_info({name})")
        )
        listing = {
            row[1]: bool(row[2])
            for row in connection.execute(f"PRAGMA index_list({table})")
        }
        if columns != expected_columns or listing.get(name) is not expected_unique:
            return False
        sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", (name,)
        ).fetchone()
        if sql_row is None or _canonical_sql(sql_row[0]) != _CANONICAL_INDEX_SQL[name]:
            return False
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        return False
    return connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]


def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if not {"agents", "agent_boots", "events", "results"} <= tables:
        raise CollectorDBError("database-schema-invalid")
    connection.execute("""CREATE TABLE agents_upgrade (agent_id TEXT PRIMARY KEY, city TEXT NOT NULL, name TEXT NOT NULL, expected_interval_seconds INTEGER NOT NULL CHECK(expected_interval_seconds > 0), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)), last_seen_us INTEGER, offline INTEGER NOT NULL DEFAULT 0 CHECK(offline IN (0, 1)), offline_since_us INTEGER, max_sequence INTEGER)""")
    connection.execute("""CREATE TABLE events_upgrade (event_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents_upgrade(agent_id), boot_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence >= 0), observed_at_us INTEGER NOT NULL, received_at_us INTEGER NOT NULL, subscription_revision TEXT, refresh_state TEXT NOT NULL CHECK(refresh_state IN ('FRESH','STALE','UNAVAILABLE')), snapshot_age_seconds INTEGER, diff_added_json TEXT NOT NULL, diff_removed_json TEXT NOT NULL, diff_changed_json TEXT NOT NULL, control_status TEXT NOT NULL CHECK(control_status IN ('UP','UNKNOWN')), duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0), xray_version TEXT, dropped_report_count INTEGER NOT NULL CHECK(dropped_report_count >= 0), payload_digest TEXT NOT NULL, UNIQUE(agent_id, boot_id, sequence))""")
    connection.execute("""CREATE TABLE results_upgrade (event_id TEXT NOT NULL REFERENCES events_upgrade(event_id) ON DELETE CASCADE, position INTEGER NOT NULL, target_id TEXT NOT NULL, label TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), status TEXT NOT NULL CHECK(status IN ('UP','DOWN','UNKNOWN')), stage TEXT NOT NULL, latency_ms INTEGER, resolved_ips_json TEXT NOT NULL, error_code TEXT, PRIMARY KEY(event_id, position))""")
    connection.execute("""CREATE TABLE agent_boots_upgrade (agent_id TEXT NOT NULL REFERENCES agents_upgrade(agent_id) ON DELETE CASCADE, boot_id TEXT NOT NULL, max_sequence INTEGER NOT NULL CHECK(max_sequence >= 0), PRIMARY KEY(agent_id, boot_id))""")
    connection.execute("""INSERT INTO agents_upgrade(agent_id, city, name, expected_interval_seconds, last_seen_us, offline, offline_since_us, max_sequence) SELECT agent_id, city, name, expected_interval_seconds, last_seen_us, offline, offline_since_us, (SELECT MAX(events.sequence) FROM events WHERE events.agent_id = agents.agent_id) FROM agents""")
    connection.execute("INSERT INTO events_upgrade SELECT * FROM events")
    connection.execute("INSERT INTO results_upgrade SELECT * FROM results")
    connection.execute("INSERT INTO agent_boots_upgrade SELECT * FROM agent_boots")
    connection.execute("DROP TABLE results")
    connection.execute("DROP TABLE agent_boots")
    connection.execute("DROP TABLE events")
    connection.execute("DROP TABLE agents")
    connection.execute("ALTER TABLE agents_upgrade RENAME TO agents")
    connection.execute("ALTER TABLE events_upgrade RENAME TO events")
    connection.execute("ALTER TABLE results_upgrade RENAME TO results")
    connection.execute("ALTER TABLE agent_boots_upgrade RENAME TO agent_boots")
    connection.execute("CREATE INDEX events_agent_received_idx ON events(agent_id, received_at_us DESC)")
    for statement in _OUTBOX_STATEMENTS:
        connection.execute(statement)
    connection.execute("PRAGMA user_version = 2")


def _migrate_v2_to_v3(connection: sqlite3.Connection) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(notifications)")}
    additions = (
        ("attempt_count", "INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0 AND attempt_count <= 100)"),
        ("next_attempt_us", "INTEGER"),
        ("last_error_code", "TEXT"),
        ("last_error_at_us", "INTEGER"),
        ("dead_letter", "INTEGER NOT NULL DEFAULT 0 CHECK(dead_letter IN (0, 1))"),
        ("dead_letter_at_us", "INTEGER"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE notifications ADD COLUMN {name} {definition}")
    connection.execute("DROP INDEX IF EXISTS notifications_pending_idx")
    connection.execute("CREATE INDEX notifications_pending_idx ON notifications(completed, dead_letter, next_attempt_us, notification_id)")
    connection.execute("PRAGMA user_version = 3")


def _migrate_v3_to_v4(connection: sqlite3.Connection) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(notifications)")}
    additions = (
        (
            "requeued_notification_id",
            "INTEGER REFERENCES notifications(notification_id)",
        ),
        ("requeued_at_us", "INTEGER"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE notifications ADD COLUMN {name} {definition}"
            )
    connection.execute("PRAGMA user_version = 4")


def _migrate_v4_to_v5(connection: sqlite3.Connection) -> None:
    agent_columns = {row[1] for row in connection.execute("PRAGMA table_info(agents)")}
    if "activated_at_us" not in agent_columns:
        connection.execute(
            "ALTER TABLE agents ADD COLUMN activated_at_us INTEGER NOT NULL DEFAULT 0"
        )
    event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    additions = (
        (
            "run_status",
            "TEXT NOT NULL DEFAULT 'UP' CHECK(run_status IN ('UP','UNKNOWN'))",
        ),
        ("run_reason", "TEXT"),
    )
    for name, definition in additions:
        if name not in event_columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")
    connection.execute("PRAGMA user_version = 5")


_BASE_SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY, city TEXT NOT NULL, name TEXT NOT NULL, expected_interval_seconds INTEGER NOT NULL CHECK(expected_interval_seconds > 0), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)), last_seen_us INTEGER, offline INTEGER NOT NULL DEFAULT 0 CHECK(offline IN (0, 1)), offline_since_us INTEGER, max_sequence INTEGER, activated_at_us INTEGER NOT NULL DEFAULT 0, rate_window_started_us INTEGER, rate_count INTEGER NOT NULL DEFAULT 0 CHECK(rate_count >= 0))""",
    """CREATE TABLE IF NOT EXISTS agent_boots (agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE, boot_id TEXT NOT NULL, max_sequence INTEGER NOT NULL CHECK(max_sequence >= 0), PRIMARY KEY(agent_id, boot_id))""",
    """CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(agent_id), boot_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence >= 0), observed_at_us INTEGER NOT NULL, received_at_us INTEGER NOT NULL, subscription_revision TEXT, refresh_state TEXT NOT NULL CHECK(refresh_state IN ('FRESH','STALE','UNAVAILABLE')), snapshot_age_seconds INTEGER, diff_added_json TEXT NOT NULL, diff_removed_json TEXT NOT NULL, diff_changed_json TEXT NOT NULL, control_status TEXT NOT NULL CHECK(control_status IN ('UP','UNKNOWN')), duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0), xray_version TEXT, dropped_report_count INTEGER NOT NULL CHECK(dropped_report_count >= 0), payload_digest TEXT NOT NULL, run_status TEXT NOT NULL DEFAULT 'UP' CHECK(run_status IN ('UP','UNKNOWN')), run_reason TEXT, UNIQUE(agent_id, boot_id, sequence))""",
    """CREATE TABLE IF NOT EXISTS results (event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE, position INTEGER NOT NULL, target_id TEXT NOT NULL, label TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), status TEXT NOT NULL CHECK(status IN ('UP','DOWN','UNKNOWN')), stage TEXT NOT NULL, latency_ms INTEGER, resolved_ips_json TEXT NOT NULL, error_code TEXT, check_kind TEXT NOT NULL DEFAULT 'vpn' CHECK(check_kind IN ('vpn','sni')), PRIMARY KEY(event_id, position))""",
    "CREATE INDEX IF NOT EXISTS events_agent_received_idx ON events(agent_id, received_at_us DESC)",
)

_OUTBOX_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS notifications (notification_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL CHECK(kind IN ('REPORT','OFFLINE','RECOVERY')), agent_id TEXT NOT NULL REFERENCES agents(agent_id), event_id TEXT, created_at_us INTEGER NOT NULL, next_chunk INTEGER NOT NULL DEFAULT 0, chunk_count INTEGER NOT NULL CHECK(chunk_count > 0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)), lease_owner TEXT, lease_until_us INTEGER, dedupe_key TEXT NOT NULL UNIQUE, attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0 AND attempt_count <= 100), next_attempt_us INTEGER, last_error_code TEXT, last_error_at_us INTEGER, dead_letter INTEGER NOT NULL DEFAULT 0 CHECK(dead_letter IN (0, 1)), dead_letter_at_us INTEGER, requeued_notification_id INTEGER REFERENCES notifications(notification_id) ON DELETE SET NULL, requeued_at_us INTEGER, requeued INTEGER NOT NULL DEFAULT 0 CHECK(requeued IN (0, 1)), CHECK(next_chunk >= 0 AND next_chunk <= chunk_count))""",
    """CREATE TABLE IF NOT EXISTS notification_chunks (notification_id INTEGER NOT NULL REFERENCES notifications(notification_id) ON DELETE CASCADE, chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0), body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 3500), PRIMARY KEY(notification_id, chunk_index))""",
    "CREATE INDEX IF NOT EXISTS notifications_pending_idx ON notifications(completed, dead_letter, next_attempt_us, notification_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS notifications_dedupe_key_idx ON notifications(dedupe_key)",
)


def _canonical_sql(statement: str) -> tuple[str, ...]:
    """Tokenize trusted schema SQL, discarding comments but preserving string values."""
    if not isinstance(statement, str):
        raise ValueError("schema SQL is invalid")
    tokens: list[str] = []
    position = 0
    length = len(statement)
    while position < length:
        character = statement[position]
        if character.isspace():
            position += 1
            continue
        if statement.startswith("--", position):
            newline = statement.find("\n", position + 2)
            position = length if newline < 0 else newline + 1
            continue
        if statement.startswith("/*", position):
            end = statement.find("*/", position + 2)
            if end < 0:
                raise ValueError("schema SQL comment is invalid")
            position = end + 2
            continue
        if character == "'":
            end = position + 1
            value = ["'"]
            while end < length:
                value.append(statement[end])
                if statement[end] == "'":
                    if end + 1 < length and statement[end + 1] == "'":
                        value.append("'")
                        end += 2
                        continue
                    end += 1
                    break
                end += 1
            else:
                raise ValueError("schema SQL string is invalid")
            tokens.append("".join(value))
            position = end
            continue
        if character in {'"', '`', '['}:
            closing = ']' if character == '[' else character
            end = statement.find(closing, position + 1)
            if end < 0:
                raise ValueError("schema SQL identifier is invalid")
            tokens.append(statement[position + 1 : end].lower())
            position = end + 1
            continue
        if character.isalpha() or character == "_":
            end = position + 1
            while end < length and (statement[end].isalnum() or statement[end] == "_"):
                end += 1
            tokens.append(statement[position:end].lower())
            position = end
            continue
        if character.isdigit():
            end = position + 1
            while end < length and statement[end].isdigit():
                end += 1
            tokens.append(statement[position:end])
            position = end
            continue
        operator = statement[position : position + 2]
        if operator in {">=", "<=", "!=", "<>", "==", "||"}:
            tokens.append(operator)
            position += 2
            continue
        tokens.append(character)
        position += 1
    return tuple(tokens)


_SCHEMA_STATEMENTS = _BASE_SCHEMA_STATEMENTS + _OUTBOX_STATEMENTS

_TABLE_NAMES = (
    "agents", "agent_boots", "events", "results", "notifications", "notification_chunks"
)
_TABLE_STATEMENTS = (
    _BASE_SCHEMA_STATEMENTS[0],
    _BASE_SCHEMA_STATEMENTS[1],
    _BASE_SCHEMA_STATEMENTS[2],
    _BASE_SCHEMA_STATEMENTS[3],
    _OUTBOX_STATEMENTS[0],
    _OUTBOX_STATEMENTS[1],
)
_CANONICAL_TABLE_SQL = {
    name: _canonical_sql(statement.replace(" IF NOT EXISTS", "", 1))
    for name, statement in zip(_TABLE_NAMES, _TABLE_STATEMENTS, strict=True)
}
_CANONICAL_INDEX_SQL = {
    "events_agent_received_idx": _canonical_sql(
        _BASE_SCHEMA_STATEMENTS[4].replace(" IF NOT EXISTS", "", 1)
    ),
    "notifications_pending_idx": _canonical_sql(
        _OUTBOX_STATEMENTS[2].replace(" IF NOT EXISTS", "", 1)
    ),
    "notifications_dedupe_key_idx": _canonical_sql(
        _OUTBOX_STATEMENTS[3].replace(" IF NOT EXISTS", "", 1)
    ),
}


def _index_manifest(unique: int, origin: str, *columns: tuple[int, str | None, int, str, int]):
    return (unique, origin, 0, columns)


_REQUIRED_INDEX_MANIFESTS = {
    "agents": {
        "sqlite_autoindex_agents_1": _index_manifest(
            1, "pk", (0, "agent_id", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
    "agent_boots": {
        "sqlite_autoindex_agent_boots_1": _index_manifest(
            1, "pk", (0, "agent_id", 0, "BINARY", 1),
            (1, "boot_id", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
    "events": {
        "events_agent_received_idx": _index_manifest(
            0, "c", (1, "agent_id", 0, "BINARY", 1),
            (5, "received_at_us", 1, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
        "sqlite_autoindex_events_2": _index_manifest(
            1, "u", (1, "agent_id", 0, "BINARY", 1),
            (2, "boot_id", 0, "BINARY", 1), (3, "sequence", 0, "BINARY", 1),
            (-1, None, 0, "BINARY", 0)
        ),
        "sqlite_autoindex_events_1": _index_manifest(
            1, "pk", (0, "event_id", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
    "results": {
        "sqlite_autoindex_results_1": _index_manifest(
            1, "pk", (0, "event_id", 0, "BINARY", 1),
            (1, "position", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
    "notifications": {
        "notifications_dedupe_key_idx": _index_manifest(
            1, "c", (10, "dedupe_key", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
        "notifications_pending_idx": _index_manifest(
            0, "c", (7, "completed", 0, "BINARY", 1),
            (15, "dead_letter", 0, "BINARY", 1),
            (12, "next_attempt_us", 0, "BINARY", 1),
            (0, "notification_id", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
        "sqlite_autoindex_notifications_1": _index_manifest(
            1, "u", (10, "dedupe_key", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
    "notification_chunks": {
        "sqlite_autoindex_notification_chunks_1": _index_manifest(
            1, "pk", (0, "notification_id", 0, "BINARY", 1),
            (1, "chunk_index", 0, "BINARY", 1), (-1, None, 0, "BINARY", 0)
        ),
    },
}


def _enqueue_notification(connection: sqlite3.Connection, kind: str, agent: AgentIdentity, event_id: str | None, created_at_us: int, text: str, *, dedupe_key: str | None = None) -> None:
    if kind not in _NOTIFICATION_KINDS:
        raise CollectorDBError("notification-kind-invalid")
    chunks = chunk_message(text)
    key = dedupe_key or f"{kind}:{event_id}"
    cursor = connection.execute("INSERT INTO notifications(kind, agent_id, event_id, created_at_us, chunk_count, dedupe_key) VALUES (?, ?, ?, ?, ?, ?)", (kind, agent.agent_id, event_id, created_at_us, len(chunks), key))
    connection.executemany("INSERT INTO notification_chunks(notification_id, chunk_index, body) VALUES (?, ?, ?)", [(cursor.lastrowid, index, body) for index, body in enumerate(chunks)])


def _ensure_pending_capacity(
    connection: sqlite3.Connection,
    agent_id: str,
    bodies: list[str],
    *,
    max_notifications_per_agent: int,
    max_notifications_global: int,
    max_chunks_per_agent: int,
    max_chunks_global: int,
    notification_additions: int | None = None,
) -> None:
    additions = len(bodies) if notification_additions is None else notification_additions
    added_chunks = sum(len(chunk_message(body)) for body in bodies)
    pending = "completed = 0 AND dead_letter = 0"
    per_agent = connection.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(chunk_count - next_chunk), 0)
              FROM notifications WHERE {pending} AND agent_id = ?""",
        (agent_id,),
    ).fetchone()
    global_totals = connection.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(chunk_count - next_chunk), 0)
              FROM notifications WHERE {pending}"""
    ).fetchone()
    if (
        per_agent[0] + additions > max_notifications_per_agent
        or global_totals[0] + additions > max_notifications_global
        or per_agent[1] + added_chunks > max_chunks_per_agent
        or global_totals[1] + added_chunks > max_chunks_global
    ):
        raise CollectorBackpressure()


def _prune_history(
    connection: sqlite3.Connection,
    agent_id: str,
    now_us: int,
    *,
    event_retention_us: int,
    max_events: int,
    completed_retention_us: int,
    max_completed: int,
) -> None:
    """Bound ordinary history while preserving every unresolved/dead-letter event."""
    connection.execute(
        "DELETE FROM notifications WHERE completed = 1 AND created_at_us < ?",
        (now_us - completed_retention_us,),
    )
    connection.execute(
        """DELETE FROM notifications WHERE notification_id IN (
               SELECT notification_id FROM notifications
               WHERE completed = 1
               ORDER BY notification_id DESC LIMIT -1 OFFSET ?
           )""",
        (max_completed,),
    )
    protected = """SELECT event_id FROM notifications
                   WHERE event_id IS NOT NULL
                     AND (
                       (completed = 0 AND dead_letter = 0)
                       OR (dead_letter = 1 AND requeued = 0)
                     )"""
    connection.execute(
        f"""DELETE FROM events
             WHERE agent_id = ? AND received_at_us < ?
               AND event_id NOT IN ({protected})""",
        (agent_id, now_us - event_retention_us),
    )
    connection.execute(
        f"""DELETE FROM events WHERE event_id IN (
               SELECT event_id FROM events
               WHERE agent_id = ? AND event_id NOT IN ({protected})
               ORDER BY received_at_us DESC, event_id DESC LIMIT -1 OFFSET ?
           )""",
        (agent_id, max_events),
    )


def _utc_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be UTC-aware")
    return int(value.astimezone(UTC).timestamp() * 1_000_000)


def _from_microseconds(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _safe_boot_id(value: str) -> str:
    if _SAFE_BOOT_RE.fullmatch(value) is None:
        raise ValueError("boot id is invalid")
    return value


def _safe_owner(value: str) -> str:
    if not isinstance(value, str) or _SAFE_BOOT_RE.fullmatch(value) is None:
        raise ValueError("notification owner is invalid")
    return value


def _safe_error_code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value, re.ASCII) is None:
        raise ValueError("notification error code is invalid")
    return value


def _safe_text(value: object, maximum: int) -> str:
    cleaned = "".join(" " if character in "\r\n\t" else character for character in str(value) if unicodedata.category(character) not in {"Cc", "Cf", "Cs"} or character in "\r\n\t")
    return " ".join(redact(cleaned).split())[:maximum]


def _safe_optional_text(value: object | None, maximum: int) -> str | None:
    return None if value is None else _safe_text(value, maximum)


def _safe_json_list(values: Iterable[object], maximum: int) -> str:
    return json.dumps(sorted(_safe_text(value, maximum) for value in values), ensure_ascii=True, separators=(",", ":"))


def _safe_report_digest(report: AgentReport) -> str:
    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str):
            return _safe_text(value, 256)
        return value

    document = report.model_dump(mode="json")
    if document.get("app_version") is None:
        document.pop("app_version", None)
    # Old agents omit the kind; upgraded collectors must still recognize their
    # queued retries against the digest accepted before this field existed.
    for result in document["results"]:
        if result.get("check_kind") == "vpn":
            result.pop("check_kind")
    payload = json.dumps(normalize(document), sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

"""Atomic, local-only state for validated subscription targets and reports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from pydantic import ValidationError

from litechecker.models import Snapshot, SnapshotDiff, TargetConfig


class StateError(ValueError):
    """Raised when local state is missing, malformed, or unsafe to use."""


class DeliveryLockUnavailable(StateError):
    """Raised only when the bounded report-delivery lock cannot be acquired."""

    def __init__(self) -> None:
        super().__init__("report delivery lock unavailable")


_DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
_PENDING_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SnapshotDecision:
    """The active snapshot plus the candidate's safe-to-report transition data."""

    snapshot: Snapshot
    diff: SnapshotDiff
    activated: bool
    reason: str


@dataclass(frozen=True)
class _PendingState:
    high_water_sequence: int | None
    high_water_event_id: str | None
    pending: dict[str, Any] | None


class SnapshotStore:
    """Retain the latest accepted snapshot for transition history and diffs."""

    def __init__(
        self,
        path: str | Path,
        *,
        state_key: str | bytes,
        lock_timeout: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        base_path = Path(path)
        self.path = base_path / "snapshot.json" if not base_path.suffix else base_path
        self._state_key = state_key
        self._lock_timeout = _validate_lock_timeout(lock_timeout)

    def load(self) -> Snapshot | None:
        """Return the active snapshot, or ``None`` before the first successful refresh."""
        with _state_lock(self.path, self._lock_timeout):
            return self._load_unlocked()

    def _load_unlocked(self) -> Snapshot | None:
        state = self._read_state()
        if state is None:
            return None
        snapshot_data = state.get("snapshot")
        if not isinstance(snapshot_data, Mapping):
            raise StateError("snapshot state is malformed")
        try:
            return Snapshot.model_validate(snapshot_data)
        except ValidationError as exc:
            raise StateError("snapshot state is malformed") from exc

    def consider(self, targets: Sequence[TargetConfig], now: datetime) -> SnapshotDecision:
        """Activate every valid nonempty candidate immediately."""
        candidate = _sorted_targets(targets)
        if not candidate:
            raise StateError("target set cannot be empty")
        with _state_lock(self.path, self._lock_timeout):
            current = self._load_unlocked()
            diff = _snapshot_diff(current.targets if current else [], candidate)
            candidate_snapshot = Snapshot(
                targets=candidate,
                subscription_revision=_subscription_revision(candidate),
                observed_at=now,
            )

            self._write_state({"snapshot": candidate_snapshot.model_dump(mode="json")})
            return SnapshotDecision(
                snapshot=candidate_snapshot,
                diff=diff,
                activated=True,
                reason="initial" if current is None else "accepted",
            )

    def _read_state(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        return _read_json_object(self.path)

    def _write_state(self, state: Mapping[str, Any]) -> None:
        _atomic_write_json(self.path, state)


class SequenceStore:
    """Persist a report sequence so report idempotency survives an agent restart."""

    def __init__(
        self,
        path: str | Path,
        *,
        lock_timeout: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        self.path = Path(path)
        self._lock_timeout = _validate_lock_timeout(lock_timeout)

    def next(self) -> int:
        with _state_lock(self.path, self._lock_timeout):
            state = _read_json_object(self.path) if self.path.exists() else {"next": 0}
            value = state.get("next")
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise StateError("sequence state is malformed")
            _atomic_write_json(self.path, {"next": value + 1})
            return value


class CollectorAckStore:
    """Persist only the latest collector acceptance needed for agent health."""

    def __init__(
        self,
        path: str | Path,
        *,
        lock_timeout: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        self.path = Path(path)
        self._lock_timeout = _validate_lock_timeout(lock_timeout)

    def record(self, event_id: str, accepted_at: datetime) -> None:
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 512:
            raise StateError("collector acknowledgement is malformed")
        if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
            raise StateError("collector acknowledgement time must be UTC-aware")
        with _state_lock(self.path, self._lock_timeout):
            _atomic_write_json(
                self.path,
                {
                    "event_id": event_id,
                    "accepted_at": accepted_at.astimezone(UTC).isoformat(),
                },
            )

    def is_recent(self, now: datetime, *, max_age_seconds: int) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise StateError("collector acknowledgement time must be UTC-aware")
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds < 1
        ):
            raise ValueError("collector acknowledgement maximum age is invalid")
        try:
            with _state_lock(self.path, self._lock_timeout):
                if not self.path.exists():
                    return False
                raw = _read_json_object(self.path)
            event_id = raw.get("event_id")
            accepted_text = raw.get("accepted_at")
            if not isinstance(event_id, str) or not event_id:
                return False
            if not isinstance(accepted_text, str):
                return False
            accepted_at = datetime.fromisoformat(accepted_text)
            if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
                return False
            age = (now.astimezone(UTC) - accepted_at.astimezone(UTC)).total_seconds()
            return 0 <= age <= max_age_seconds
        except (OSError, ValueError, StateError):
            return False


class PendingReportStore:
    """Keep at most one unsent sanitized report for retry after collector failure."""

    def __init__(
        self,
        path: str | Path,
        *,
        lock_timeout: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ):
        self.path = Path(path)
        self._lock_timeout = _validate_lock_timeout(lock_timeout)

    def load(self) -> dict[str, Any] | None:
        with _state_lock(self.path, self._lock_timeout):
            return self._read_pending_state_unlocked().pending

    def is_pending(self, event_id: str, sequence: int) -> bool:
        """Return whether the exact event still owns the durable pending slot."""
        expected_event_id, expected_sequence = _pending_identity(
            {"event_id": event_id, "sequence": sequence}
        )
        with _state_lock(self.path, self._lock_timeout):
            state = self._read_pending_state_unlocked()
            return (
                state.pending is not None
                and state.high_water_event_id == expected_event_id
                and state.high_water_sequence == expected_sequence
            )

    @asynccontextmanager
    async def delivery_lock(self) -> AsyncIterator[None]:
        """Serialize network sends without holding the short state lock.

        Senders take this long-lived lock first and may briefly take the state
        lock to revalidate ownership. Writers only take the state lock, so newer
        reports remain durable during network I/O without creating lock cycles.
        """
        lock_path = self.path.with_name(f".{self.path.name}.delivery.lock")
        async with _async_file_lock(lock_path, self._lock_timeout):
            yield

    def _read_pending_state_unlocked(self) -> _PendingState:
        if not self.path.exists():
            return _PendingState(None, None, None)
        raw = _read_json_object(self.path)
        if any(
            key in raw
            for key in ("high_water_sequence", "high_water_event_id", "pending")
        ):
            return _pending_state_from_envelope(raw)
        event_id, sequence = _pending_identity(raw)
        return _PendingState(sequence, event_id, raw)

    def save(self, report: Mapping[str, Any]) -> bool:
        """Save only if ``report`` is not older than the durable event."""
        candidate_event_id, candidate_sequence = _pending_identity(report)
        with _state_lock(self.path, self._lock_timeout):
            state = self._read_pending_state_unlocked()
            if state.high_water_sequence is not None:
                if candidate_sequence < state.high_water_sequence:
                    return False
                if (
                    candidate_sequence == state.high_water_sequence
                    and candidate_event_id != state.high_water_event_id
                ):
                    raise StateError("pending report sequence conflict")
                if (
                    candidate_sequence == state.high_water_sequence
                    and state.pending is None
                ):
                    return False
            self._write_pending_state_unlocked(
                _PendingState(
                    high_water_sequence=candidate_sequence,
                    high_water_event_id=candidate_event_id,
                    pending=dict(report),
                )
            )
            return True

    def replace_if_event(self, expected_event_id: str, report: Mapping[str, Any]) -> bool:
        replacement_event_id, replacement_sequence = _pending_identity(report)
        if replacement_event_id != expected_event_id:
            raise StateError("pending report event mismatch")
        with _state_lock(self.path, self._lock_timeout):
            state = self._read_pending_state_unlocked()
            if state.pending is None:
                return False
            if state.high_water_event_id != expected_event_id:
                return False
            if replacement_sequence != state.high_water_sequence:
                raise StateError("pending report sequence conflict")
            self._write_pending_state_unlocked(
                _PendingState(
                    high_water_sequence=state.high_water_sequence,
                    high_water_event_id=state.high_water_event_id,
                    pending=dict(report),
                )
            )
            return True

    def clear(self, expected_event_id: str) -> bool:
        with _state_lock(self.path, self._lock_timeout):
            state = self._read_pending_state_unlocked()
            if state.pending is None:
                return False
            if state.high_water_event_id != expected_event_id:
                return False
            self._write_pending_state_unlocked(
                _PendingState(
                    high_water_sequence=state.high_water_sequence,
                    high_water_event_id=state.high_water_event_id,
                    pending=None,
                )
            )
            return True

    def _write_pending_state_unlocked(self, state: _PendingState) -> None:
        if state.high_water_sequence is None or state.high_water_event_id is None:
            raise StateError("pending report state is malformed")
        _atomic_write_json(
            self.path,
            {
                "schema_version": _PENDING_SCHEMA_VERSION,
                "high_water_sequence": state.high_water_sequence,
                "high_water_event_id": state.high_water_event_id,
                "pending": state.pending,
            },
        )


def _pending_identity(report: Mapping[str, Any]) -> tuple[str, int]:
    event_id = report.get("event_id")
    sequence = report.get("sequence")
    if (
        not isinstance(event_id, str)
        or not event_id
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
    ):
        raise StateError("pending report is malformed")
    return event_id, sequence


def _pending_state_from_envelope(raw: Mapping[str, Any]) -> _PendingState:
    schema_version = raw.get("schema_version")
    high_water_sequence = raw.get("high_water_sequence")
    high_water_event_id = raw.get("high_water_event_id")
    pending = raw.get("pending")
    if (
        "pending" not in raw
        or not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != _PENDING_SCHEMA_VERSION
        or not isinstance(high_water_sequence, int)
        or isinstance(high_water_sequence, bool)
        or high_water_sequence < 0
        or not isinstance(high_water_event_id, str)
        or not high_water_event_id
        or (pending is not None and not isinstance(pending, dict))
    ):
        raise StateError("pending report state is malformed")
    if pending is not None:
        pending_event_id, pending_sequence = _pending_identity(pending)
        if (
            pending_sequence != high_water_sequence
            or pending_event_id != high_water_event_id
        ):
            raise StateError("pending report state is malformed")
    return _PendingState(high_water_sequence, high_water_event_id, pending)


def _validate_lock_timeout(timeout: float) -> float:
    """Accept bounded waits; zero explicitly means a non-blocking acquisition."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout < 0
        or not math.isfinite(timeout)
    ):
        raise ValueError("state lock timeout must be finite and non-negative")
    return float(timeout)


@asynccontextmanager
async def _async_file_lock(lock_path: Path, timeout: float) -> AsyncIterator[None]:
    """Acquire a cross-process lock by non-blocking, cancellation-safe polling."""
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(
            lock_path,
            timeout=0,
            mode=0o600,
            preserve_lock_file=True,
        )
    except (OSError, RuntimeError) as exc:
        raise DeliveryLockUnavailable from exc

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    acquired = False
    try:
        while True:
            try:
                lock.acquire(timeout=0)
            except Timeout:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise DeliveryLockUnavailable from None
                await asyncio.sleep(min(0.05, remaining))
            except (OSError, RuntimeError) as exc:
                raise DeliveryLockUnavailable from exc
            else:
                acquired = True
                break
        yield
    finally:
        if acquired:
            try:
                lock.release()
            except (OSError, RuntimeError) as exc:
                raise StateError("report delivery lock release failed") from exc


@contextmanager
def _state_lock(path: Path, timeout: float) -> Iterator[None]:
    """Serialize one complete state transition across threads and processes."""
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(
            lock_path,
            timeout=timeout,
            mode=0o600,
            preserve_lock_file=True,
        )
        lock.acquire()
    except (OSError, RuntimeError, Timeout) as exc:
        raise StateError("local state lock unavailable") from exc
    try:
        yield
    finally:
        try:
            lock.release()
        except (OSError, RuntimeError) as exc:
            raise StateError("local state lock unavailable") from exc


def _sorted_targets(targets: Sequence[TargetConfig]) -> list[TargetConfig]:
    by_id = {target.target_id: target for target in targets}
    if len(by_id) != len(targets):
        raise StateError("target IDs must be unique")
    return [by_id[target_id] for target_id in sorted(by_id)]


def _snapshot_diff(previous: Sequence[TargetConfig], current: Sequence[TargetConfig]) -> SnapshotDiff:
    old_by_id = {target.target_id: target for target in previous}
    new_by_id = {target.target_id: target for target in current}
    old_ids = set(old_by_id)
    new_ids = set(new_by_id)
    return SnapshotDiff(
        added=sorted(new_ids - old_ids),
        removed=sorted(old_ids - new_ids),
        changed=sorted(
            target_id
            for target_id in old_ids & new_ids
            if old_by_id[target_id].config_fingerprint
            != new_by_id[target_id].config_fingerprint
        ),
    )


def _subscription_revision(targets: Sequence[TargetConfig]) -> str:
    encoded = json.dumps(
        sorted(target.target_id for target in targets), separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateError("local state is unreadable") from exc
    if not isinstance(value, dict):
        raise StateError("local state is malformed")
    return value


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise StateError("local state cannot be written") from exc


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)

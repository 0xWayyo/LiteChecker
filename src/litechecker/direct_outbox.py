"""Small durable per-chunk outbox for the native DIRECT Telegram reporter."""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from filelock import FileLock, Timeout as FileLockTimeout

from litechecker.state import _atomic_write_json


_SCHEMA_VERSION = 1


class DirectOutboxError(RuntimeError):
    """Closed local queue failure which never contains message text."""

    def __init__(self, error_code: str):
        super().__init__(error_code)
        self.error_code = error_code


@dataclass(frozen=True)
class PendingChunk:
    message_id: str
    chunk_index: int
    text: str


class DirectOutbox:
    """Persist a bounded FIFO and advance it only after Telegram acceptance."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_messages: int = 32,
        max_chunks: int = 256,
        lock_timeout: float = 5.0,
    ) -> None:
        if (
            isinstance(max_messages, bool)
            or not isinstance(max_messages, int)
            or max_messages < 1
            or isinstance(max_chunks, bool)
            or not isinstance(max_chunks, int)
            or max_chunks < 1
            or isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout < 0
        ):
            raise ValueError("DIRECT outbox bounds are invalid")
        self.path = Path(path)
        self._max_messages = max_messages
        self._max_chunks = max_chunks
        self._lock_timeout = float(lock_timeout)

    def enqueue(self, chunks: Sequence[str], *, created_at: datetime) -> str:
        checked = list(chunks)
        if (
            not checked
            or len(checked) > self._max_chunks
            or any(not isinstance(chunk, str) or not chunk or len(chunk) > 4_096 for chunk in checked)
        ):
            raise DirectOutboxError("outbox-message-too-large")
        created = _utc_text(created_at)
        message_id = uuid.uuid4().hex
        with self._locked():
            state = self._read_unlocked()
            state["messages"].append(
                {
                    "message_id": message_id,
                    "created_at": created,
                    "chunks": checked,
                    "next_chunk": 0,
                }
            )
            while (
                len(state["messages"]) > self._max_messages
                or _pending_chunks(state) > self._max_chunks
            ):
                state["messages"].pop(0)
                state["dropped_messages"] += 1
            self._write_unlocked(state)
        return message_id

    def next_chunk(self) -> PendingChunk | None:
        with self._locked():
            state = self._read_unlocked()
            if not state["messages"]:
                return None
            message = state["messages"][0]
            index = message["next_chunk"]
            return PendingChunk(message["message_id"], index, message["chunks"][index])

    def acknowledge(self, pending: PendingChunk, *, accepted_at: datetime) -> None:
        accepted = _utc_text(accepted_at)
        with self._locked():
            state = self._read_unlocked()
            if not state["messages"]:
                raise DirectOutboxError("outbox-ack-invalid")
            current = state["messages"][0]
            index = current["next_chunk"]
            if (
                not isinstance(pending, PendingChunk)
                or pending.message_id != current["message_id"]
                or pending.chunk_index != index
                or pending.text != current["chunks"][index]
            ):
                raise DirectOutboxError("outbox-ack-invalid")
            current["next_chunk"] += 1
            if current["next_chunk"] == len(current["chunks"]):
                state["messages"].pop(0)
            state["last_accepted_at"] = accepted
            self._write_unlocked(state)

    def status(self) -> dict[str, int | str | None]:
        with self._locked():
            state = self._read_unlocked()
            return {
                "pending_messages": len(state["messages"]),
                "pending_chunks": _pending_chunks(state),
                "dropped_messages": state["dropped_messages"],
                "last_accepted_at": state["last_accepted_at"],
            }

    def _lock(self) -> FileLock:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            return FileLock(
                self.path.with_name(f".{self.path.name}.lock"),
                timeout=self._lock_timeout,
                mode=0o600,
                preserve_lock_file=True,
            )
        except (OSError, RuntimeError, FileLockTimeout):
            raise DirectOutboxError("outbox-state-unavailable") from None

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock = self._lock()
        acquired = False
        try:
            try:
                lock.acquire()
                acquired = True
            except (OSError, RuntimeError, FileLockTimeout):
                raise DirectOutboxError("outbox-state-unavailable") from None
            yield
        finally:
            if acquired:
                try:
                    lock.release()
                except (OSError, RuntimeError):
                    raise DirectOutboxError("outbox-state-unavailable") from None

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "schema_version": _SCHEMA_VERSION,
                "messages": [],
                "dropped_messages": 0,
                "last_accepted_at": None,
            }
        if self.path.is_symlink():
            raise DirectOutboxError("outbox-state-invalid")
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return _validate_state(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise DirectOutboxError("outbox-state-invalid") from None

    def _write_unlocked(self, state: dict[str, Any]) -> None:
        try:
            _atomic_write_json(self.path, state)
        except Exception:
            raise DirectOutboxError("outbox-state-unavailable") from None


def _validate_state(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "messages",
        "dropped_messages",
        "last_accepted_at",
    }:
        raise ValueError
    if raw["schema_version"] != _SCHEMA_VERSION:
        raise ValueError
    messages = raw["messages"]
    dropped = raw["dropped_messages"]
    accepted = raw["last_accepted_at"]
    if (
        not isinstance(messages, list)
        or not isinstance(dropped, int)
        or isinstance(dropped, bool)
        or dropped < 0
        or (accepted is not None and not isinstance(accepted, str))
    ):
        raise ValueError
    seen: set[str] = set()
    for message in messages:
        if not isinstance(message, dict) or set(message) != {
            "message_id",
            "created_at",
            "chunks",
            "next_chunk",
        }:
            raise ValueError
        message_id = message["message_id"]
        chunks = message["chunks"]
        index = message["next_chunk"]
        if (
            not isinstance(message_id, str)
            or len(message_id) != 32
            or message_id in seen
            or not isinstance(message["created_at"], str)
            or not isinstance(chunks, list)
            or not chunks
            or any(not isinstance(chunk, str) or not chunk or len(chunk) > 4_096 for chunk in chunks)
            or not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(chunks)
        ):
            raise ValueError
        seen.add(message_id)
    if accepted is not None:
        parsed = datetime.fromisoformat(accepted)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
    return raw


def _pending_chunks(state: dict[str, Any]) -> int:
    return sum(len(message["chunks"]) - message["next_chunk"] for message in state["messages"])


def _utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("DIRECT outbox time must be timezone-aware")
    return value.astimezone(UTC).isoformat()

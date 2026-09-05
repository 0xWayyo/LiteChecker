"""Durable DIRECT Telegram delivery keeps bounded per-chunk acknowledgements."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from filelock import FileLock


NOW = datetime(2026, 9, 5, 3, 0, tzinfo=UTC)


def test_reopen_retries_only_unacknowledged_chunks(tmp_path):
    from litechecker.direct_outbox import DirectOutbox

    path = tmp_path / "outbox.json"
    first = DirectOutbox(path)
    message_id = first.enqueue(["part one", "part two"], created_at=NOW)

    pending = DirectOutbox(path).next_chunk()
    assert (pending.message_id, pending.chunk_index, pending.text) == (
        message_id,
        0,
        "part one",
    )
    DirectOutbox(path).acknowledge(pending, accepted_at=NOW + timedelta(seconds=1))

    retried = DirectOutbox(path).next_chunk()
    assert (retried.message_id, retried.chunk_index, retried.text) == (
        message_id,
        1,
        "part two",
    )
    DirectOutbox(path).acknowledge(retried, accepted_at=NOW + timedelta(seconds=2))

    reopened = DirectOutbox(path)
    assert reopened.next_chunk() is None
    assert reopened.status() == {
        "pending_messages": 0,
        "pending_chunks": 0,
        "dropped_messages": 0,
        "last_accepted_at": "2026-09-05T03:00:02+00:00",
    }
    assert path.stat().st_mode & 0o777 == 0o600


def test_queue_discards_oldest_whole_message_to_stay_bounded(tmp_path):
    from litechecker.direct_outbox import DirectOutbox

    queue = DirectOutbox(tmp_path / "outbox.json", max_messages=2, max_chunks=3)
    first = queue.enqueue(["first-a", "first-b"], created_at=NOW)
    second = queue.enqueue(["second"], created_at=NOW + timedelta(seconds=1))
    third = queue.enqueue(["third"], created_at=NOW + timedelta(seconds=2))

    pending = DirectOutbox(
        tmp_path / "outbox.json", max_messages=2, max_chunks=3
    ).next_chunk()
    assert pending.message_id == second
    assert pending.message_id not in {first, third}
    assert queue.status()["dropped_messages"] == 1
    assert queue.status()["pending_chunks"] == 2


def test_acknowledgement_must_match_current_chunk(tmp_path):
    from litechecker.direct_outbox import DirectOutbox, DirectOutboxError, PendingChunk

    queue = DirectOutbox(tmp_path / "outbox.json")
    message_id = queue.enqueue(["only"], created_at=NOW)

    with pytest.raises(DirectOutboxError, match="outbox-ack-invalid"):
        queue.acknowledge(
            PendingChunk(message_id, 1, "only"),
            accepted_at=NOW,
        )
    assert queue.next_chunk().chunk_index == 0


def test_oversized_message_is_rejected_without_displacing_pending_data(tmp_path):
    from litechecker.direct_outbox import DirectOutbox, DirectOutboxError

    queue = DirectOutbox(tmp_path / "outbox.json", max_messages=3, max_chunks=2)
    queue.enqueue(["kept"], created_at=NOW)

    with pytest.raises(DirectOutboxError, match="outbox-message-too-large"):
        queue.enqueue(["a", "b", "c"], created_at=NOW)
    assert queue.next_chunk().text == "kept"


def test_symlinked_queue_is_rejected_without_reading_or_replacing_target(tmp_path):
    from litechecker.direct_outbox import DirectOutbox, DirectOutboxError

    outside = tmp_path / "outside"
    outside.write_text(json.dumps({
        "schema_version": 1,
        "messages": [],
        "dropped_messages": 0,
        "last_accepted_at": None,
    }))
    path = tmp_path / "outbox.json"
    path.symlink_to(outside)

    with pytest.raises(DirectOutboxError, match="outbox-state-invalid"):
        DirectOutbox(path).next_chunk()
    assert json.loads(outside.read_text())["schema_version"] == 1


def test_busy_queue_lock_is_reported_with_closed_error(tmp_path):
    from litechecker.direct_outbox import DirectOutbox, DirectOutboxError

    path = tmp_path / "outbox.json"
    lock = FileLock(path.with_name(".outbox.json.lock"), timeout=0)
    with lock:
        with pytest.raises(DirectOutboxError, match="outbox-state-unavailable"):
            DirectOutbox(path, lock_timeout=0).status()

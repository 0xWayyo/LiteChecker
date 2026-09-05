import asyncio
import json
import multiprocessing
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from filelock import FileLock
import pytest

import litechecker.state as state_module
from litechecker.models import TargetConfig
from litechecker.state import (
    CollectorAckStore,
    PendingReportStore,
    SequenceStore,
    SnapshotStore,
    StateError,
)


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
NOW_LATER = NOW + timedelta(minutes=10)
NOW_LATER_2 = NOW + timedelta(minutes=20)


def test_collector_ack_health_requires_a_recent_successful_current_acceptance(tmp_path):
    """Snapshot freshness alone can hide an agent that has stopped reaching the collector."""
    store = CollectorAckStore(tmp_path / "collector-ack.json")
    assert store.is_recent(NOW, max_age_seconds=1500) is False

    store.record("agent-1:boot-1:1", NOW)

    assert store.is_recent(NOW + timedelta(seconds=1499), max_age_seconds=1500) is True
    assert store.is_recent(NOW + timedelta(seconds=1501), max_age_seconds=1500) is False
    assert (tmp_path / "collector-ack.json").stat().st_mode & 0o777 == 0o600


def _allocate_sequences_worker(path, barrier, output, count):
    try:
        store = SequenceStore(path)
        barrier.wait(timeout=10)
        output.put(("ok", [store.next() for _ in range(count)]))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _save_pending_reports_worker(path, barrier, output, sequences):
    try:
        store = PendingReportStore(path)
        barrier.wait(timeout=10)
        outcomes = []
        for sequence in sequences:
            outcomes.append(
                store.save(
                    {
                        "event_id": f"agent:boot:{sequence}",
                        "sequence": sequence,
                        "results": [],
                    }
                )
            )
        output.put(("ok", outcomes))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _save_and_clear_pending_reports_worker(path, barrier, output, sequences):
    try:
        store = PendingReportStore(path)
        barrier.wait(timeout=10)
        outcomes = []
        for sequence in sequences:
            event_id = f"agent:boot:{sequence}"
            saved = store.save(
                {"event_id": event_id, "sequence": sequence, "results": []}
            )
            outcomes.append((saved, store.clear(event_id) if saved else False))
        output.put(("ok", outcomes))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _hold_delivery_lock_worker(path, acquired, release):
    async def hold() -> None:
        store = PendingReportStore(path)
        async with store.delivery_lock():
            acquired.set()
            while not release.is_set():
                await asyncio.sleep(0.01)

    asyncio.run(hold())


def _target(number: int, *, fingerprint: str | None = None) -> TargetConfig:
    return TargetConfig(
        target_id=f"target-{number}",
        config_fingerprint=fingerprint or f"fingerprint-{number}",
        label=f"Target {number}",
        address=f"node-{number}.example",
        port=443,
        address_kind="domain",
        outbound={
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": f"node-{number}.example", "port": 443}]
            },
        },
    )


def test_failed_refresh_keeps_last_known_good_snapshot(tmp_path):
    target = _target(1)
    store = SnapshotStore(tmp_path, state_key=b"s" * 32)

    accepted = store.consider([target], NOW)
    loaded = store.load()

    assert accepted.activated is True
    assert loaded is not None
    assert loaded.targets[0].target_id == target.target_id


def test_mass_removal_activates_immediately_and_diff_is_correct(tmp_path):
    six_targets = [_target(number) for number in range(6)]
    store = SnapshotStore(tmp_path, state_key=b"s" * 32)
    store.consider(six_targets, NOW)

    decision = store.consider(six_targets[:2], NOW_LATER)

    assert decision.activated is True and decision.reason == "accepted"
    assert decision.diff.removed == ["target-2", "target-3", "target-4", "target-5"]
    assert [target.target_id for target in store.load().targets] == ["target-0", "target-1"]


def test_ordinary_removal_activates_immediately_and_keeps_history_diff(tmp_path):
    targets = [_target(number) for number in range(4)]
    store = SnapshotStore(tmp_path, state_key=b"s" * 32)
    store.consider(targets, NOW)

    decision = store.consider(targets[:1], NOW_LATER)

    assert decision.activated is True
    assert [target.target_id for target in store.load().targets] == ["target-0"]
    assert decision.diff.removed == ["target-1", "target-2", "target-3"]


def test_snapshot_diff_is_sorted_and_marks_rotated_probe_material_changed(tmp_path):
    store = SnapshotStore(tmp_path, state_key=b"s" * 32)
    store.consider([_target(2), _target(1)], NOW)

    decision = store.consider(
        [_target(1, fingerprint="rotated"), _target(3), _target(2)], NOW_LATER
    )

    assert decision.activated is True
    assert decision.diff.added == ["target-3"]
    assert decision.diff.removed == []
    assert decision.diff.changed == ["target-1"]


def test_snapshot_store_writes_private_atomic_state(tmp_path):
    store = SnapshotStore(tmp_path, state_key=b"s" * 32)
    store.consider([_target(1)], NOW)

    state_path = tmp_path / "snapshot.json"

    assert state_path.exists()
    assert state_path.stat().st_mode & 0o777 == 0o600


def test_sequence_store_is_monotonic_across_restarts(tmp_path):
    path = tmp_path / "sequence.json"
    sequence = SequenceStore(path)

    assert sequence.next() == 0
    assert sequence.next() == 1
    assert SequenceStore(path).next() == 2


def test_pending_report_store_replaces_old_report(tmp_path):
    store = PendingReportStore(tmp_path / "pending-report.json")
    old_saved = store.save({"event_id": "old", "sequence": 1, "results": []})
    new_saved = store.save({"event_id": "new", "sequence": 2, "results": []})

    assert old_saved is True
    assert new_saved is True
    assert store.load() == {"event_id": "new", "sequence": 2, "results": []}
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_delayed_older_save_cannot_overwrite_newer_pending_report(tmp_path):
    """An older cycle may allocate first but reach its outbox write last."""
    store = PendingReportStore(tmp_path / "pending-report.json")
    older_allocated = threading.Event()
    release_older = threading.Event()
    outcome: list[bool] = []

    def save_older() -> None:
        older_allocated.set()
        assert release_older.wait(timeout=5)
        outcome.append(
            store.save({"event_id": "agent:boot:4", "sequence": 4, "results": []})
        )

    older = threading.Thread(target=save_older)
    older.start()
    assert older_allocated.wait(timeout=5)
    try:
        newer_outcome = store.save(
            {"event_id": "agent:boot:5", "sequence": 5, "results": []}
        )
    finally:
        release_older.set()
        older.join(timeout=5)

    assert not older.is_alive()
    assert newer_outcome is True
    assert outcome == [False]
    assert store.load()["event_id"] == "agent:boot:5"


def test_equal_pending_sequence_with_different_event_fails_closed(tmp_path):
    store = PendingReportStore(tmp_path / "pending-report.json")
    store.save({"event_id": "agent:a:7", "sequence": 7, "results": []})
    assert store.save(
        {
            "event_id": "agent:a:7",
            "sequence": 7,
            "results": [],
            "dropped_report_count": 1,
        }
    ) is True

    with pytest.raises(StateError, match=r"^pending report sequence conflict$"):
        store.save({"event_id": "agent:b:7", "sequence": 7, "results": []})

    assert store.load()["event_id"] == "agent:a:7"
    assert store.load()["dropped_report_count"] == 1


def test_successful_clear_keeps_high_water_tombstone_across_restart(tmp_path):
    path = tmp_path / "pending-report.json"
    store = PendingReportStore(path)
    assert store.save(
        {"event_id": "agent:boot:11", "sequence": 11, "results": []}
    ) is True

    assert store.clear("agent:boot:11") is True
    assert path.exists()
    assert store.load() is None

    restarted = PendingReportStore(path)
    assert restarted.load() is None
    assert restarted.save(
        {"event_id": "agent:boot:10", "sequence": 10, "results": []}
    ) is False
    assert restarted.save(
        {"event_id": "agent:boot:11", "sequence": 11, "results": []}
    ) is False
    with pytest.raises(StateError, match=r"^pending report sequence conflict$"):
        restarted.save(
            {"event_id": "agent:other:11", "sequence": 11, "results": []}
        )


def test_pending_report_store_reads_legacy_bare_report_and_migrates_on_clear(tmp_path):
    path = tmp_path / "pending-report.json"
    legacy = {"event_id": "agent:legacy:3", "sequence": 3, "results": []}
    path.write_text(json.dumps(legacy), encoding="utf-8")
    store = PendingReportStore(path)

    assert store.load() == legacy
    assert store.clear(legacy["event_id"]) is True
    assert PendingReportStore(path).load() is None
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope == {
        "schema_version": 1,
        "high_water_sequence": 3,
        "high_water_event_id": legacy["event_id"],
        "pending": None,
    }
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "envelope",
    [
        {
            "schema_version": 1,
            "high_water_sequence": 3,
            "high_water_event_id": "agent:boot:3",
        },
        {
            "schema_version": 1.0,
            "high_water_sequence": 3,
            "high_water_event_id": "agent:boot:3",
            "pending": None,
        },
        {
            "schema_version": 1,
            "high_water_sequence": 3,
            "high_water_event_id": "agent:boot:3",
            "pending": {"event_id": "agent:boot:2", "sequence": 2},
        },
    ],
)
def test_corrupt_pending_envelope_fails_closed_with_fixed_error(tmp_path, envelope):
    path = tmp_path / "pending-report.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(StateError, match=r"^pending report state is malformed$"):
        PendingReportStore(path).load()


def test_pending_high_water_survives_multiprocess_save_clear_lifecycle_stress(tmp_path):
    context = multiprocessing.get_context("spawn")
    worker_count = 6
    barrier = context.Barrier(worker_count)
    output = context.Queue()
    path = str(tmp_path / "pending-report.json")
    workers = [
        context.Process(
            target=_save_and_clear_pending_reports_worker,
            args=(
                path,
                barrier,
                output,
                list(range(worker, 60, worker_count))[::-1],
            ),
        )
        for worker in range(worker_count)
    ]

    for worker in workers:
        worker.start()
    outcomes = [output.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)

    assert all(worker.exitcode == 0 for worker in workers)
    assert all(kind == "ok" for kind, _ in outcomes)
    restarted = PendingReportStore(path)
    assert restarted.load() is None
    assert restarted.save(
        {"event_id": "agent:boot:58", "sequence": 58, "results": []}
    ) is False
    assert restarted.save(
        {"event_id": "agent:boot:59", "sequence": 59, "results": []}
    ) is False
    assert restarted.save(
        {"event_id": "agent:boot:60", "sequence": 60, "results": []}
    ) is True
    assert restarted.load()["event_id"] == "agent:boot:60"


def test_pending_report_highest_sequence_survives_multiprocess_save_stress(tmp_path):
    context = multiprocessing.get_context("spawn")
    worker_count = 6
    barrier = context.Barrier(worker_count)
    output = context.Queue()
    path = str(tmp_path / "pending-report.json")
    workers = [
        context.Process(
            target=_save_pending_reports_worker,
            args=(
                path,
                barrier,
                output,
                list(range(worker, 60, worker_count))[::-1],
            ),
        )
        for worker in range(worker_count)
    ]

    for worker in workers:
        worker.start()
    outcomes = [output.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)

    assert all(worker.exitcode == 0 for worker in workers)
    assert all(kind == "ok" for kind, _ in outcomes)
    store_report = PendingReportStore(path).load()
    assert store_report is not None
    assert store_report["sequence"] == 59
    assert store_report["event_id"] == "agent:boot:59"


def test_pending_report_compare_and_swap_never_clears_or_replaces_newer_event(tmp_path):
    """A delayed sender must not mutate an outbox entry written by a newer cycle."""
    store = PendingReportStore(tmp_path / "pending-report.json")
    store.save({"event_id": "current", "sequence": 1, "results": []})
    store.save({"event_id": "newer", "sequence": 2, "results": []})

    replaced = store.replace_if_event(
        "current",
        {"event_id": "current", "sequence": 1, "results": [], "dropped": 1},
    )
    cleared = store.clear("current")

    assert replaced is False
    assert cleared is False
    assert store.load()["event_id"] == "newer"


def test_sequence_store_allocates_unique_strictly_increasing_values_across_processes(
    tmp_path,
):
    """Atomic rename alone cannot protect the sequence read-modify-write across agents."""
    context = multiprocessing.get_context("spawn")
    worker_count = 8
    allocations_per_worker = 8
    barrier = context.Barrier(worker_count)
    output = context.Queue()
    path = str(tmp_path / "sequence.json")
    workers = [
        context.Process(
            target=_allocate_sequences_worker,
            args=(path, barrier, output, allocations_per_worker),
        )
        for _ in range(worker_count)
    ]

    for worker in workers:
        worker.start()
    outcomes = [output.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)

    assert all(worker.exitcode == 0 for worker in workers)
    assert all(kind == "ok" for kind, _ in outcomes)
    values = [value for _, worker_values in outcomes for value in worker_values]
    assert sorted(values) == list(range(worker_count * allocations_per_worker))


def test_stale_clear_racing_newer_save_cannot_delete_newer_pending(
    tmp_path,
    monkeypatch,
):
    """The compare and unlink must share one lock with a concurrent newer save."""
    store = PendingReportStore(tmp_path / "pending-report.json")
    store.save({"event_id": "current", "sequence": 1, "results": []})
    original_read = state_module._read_json_object
    stale_read_complete = threading.Event()
    continue_clear = threading.Event()

    def gated_read(path):
        value = original_read(path)
        if threading.current_thread().name == "old-clear":
            stale_read_complete.set()
            assert continue_clear.wait(timeout=5)
        return value

    monkeypatch.setattr(state_module, "_read_json_object", gated_read)
    clear_result: list[bool] = []

    def clear_old() -> None:
        clear_result.append(store.clear("current"))

    newer_saved = threading.Event()

    def save_newer() -> None:
        store.save({"event_id": "newer", "sequence": 2, "results": []})
        newer_saved.set()

    clear_thread = threading.Thread(target=clear_old, name="old-clear")
    save_thread = threading.Thread(target=save_newer, name="newer-save")
    clear_thread.start()
    assert stale_read_complete.wait(timeout=5)
    save_thread.start()
    newer_saved.wait(timeout=0.5)
    continue_clear.set()
    clear_thread.join(timeout=5)
    save_thread.join(timeout=5)

    assert not clear_thread.is_alive()
    assert not save_thread.is_alive()
    assert newer_saved.is_set()
    assert clear_result == [True]
    assert store.load()["event_id"] == "newer"


def test_lock_timeout_fails_closed_with_sanitized_state_error(tmp_path):
    path = tmp_path / "sequence.json"
    lock_path = path.with_name(f".{path.name}.lock")
    held = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with FileLock(lock_path, timeout=1):
            held.set()
            assert release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert held.wait(timeout=5)

    try:
        store = SequenceStore(path, lock_timeout=0.01)
        with pytest.raises(StateError, match=r"^local state lock unavailable$"):
            store.next()
        assert not path.exists()
    finally:
        release.set()
        holder.join(timeout=5)

    assert not holder.is_alive()


@pytest.mark.parametrize("lock_timeout", [-1, float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize(
    "store_factory",
    [
        lambda path, timeout: SnapshotStore(
            path, state_key=b"s" * 32, lock_timeout=timeout
        ),
        lambda path, timeout: SequenceStore(path, lock_timeout=timeout),
        lambda path, timeout: PendingReportStore(path, lock_timeout=timeout),
    ],
)
def test_state_stores_reject_negative_or_non_finite_lock_timeout(
    tmp_path,
    store_factory,
    lock_timeout,
):
    with pytest.raises(
        ValueError,
        match=r"^state lock timeout must be finite and non-negative$",
    ):
        store_factory(tmp_path / "state.json", lock_timeout)


def test_zero_lock_timeout_is_supported_as_nonblocking_when_uncontended(tmp_path):
    snapshot = SnapshotStore(
        tmp_path / "snapshot.json",
        state_key=b"s" * 32,
        lock_timeout=0,
    )
    sequence = SequenceStore(tmp_path / "sequence.json", lock_timeout=0)
    pending = PendingReportStore(tmp_path / "pending-report.json", lock_timeout=0)

    assert snapshot.load() is None
    assert sequence.next() == 0
    assert pending.save(
        {"event_id": "agent:boot:0", "sequence": 0, "results": []}
    ) is True


@pytest.mark.asyncio
async def test_zero_delivery_lock_timeout_fails_immediately_when_contended(tmp_path):
    path = tmp_path / "pending-report.json"
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_delivery_lock_worker,
        args=(str(path), acquired, release),
    )
    holder.start()
    contender = PendingReportStore(path, lock_timeout=0)

    try:
        assert await asyncio.to_thread(acquired.wait, 5)
        with pytest.raises(StateError, match=r"^report delivery lock unavailable$"):
            async with contender.delivery_lock():
                pytest.fail("contended zero-timeout delivery lock must not be acquired")
    finally:
        release.set()
        await asyncio.to_thread(holder.join, 5)

    assert holder.exitcode == 0

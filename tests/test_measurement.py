"""Measurement owns fresh evidence and state, independently of delivery."""

import asyncio
import gc
import importlib.util
import threading
import weakref
from dataclasses import fields

import pytest

from litechecker import config
from litechecker.agent import run_agent, run_cycle
from test_agent import FakeFetcher, RecordingSender, _dependencies, _settings, _subscription
from test_standalone_config import environment


def measurement_module():
    assert importlib.util.find_spec("litechecker.measurement") is not None, "measurement boundary is missing"
    from litechecker import measurement
    return measurement


def test_standalone_settings_have_no_collector_identity(tmp_path):
    settings = config.StandaloneSettings.from_env(environment(tmp_path))
    assert not hasattr(settings.agent, "collector_url")
    assert not hasattr(settings.agent, "agent_token")
    assert isinstance(settings.agent, config.ProbeSettings)


@pytest.mark.asyncio
async def test_measurement_refreshes_and_sequences_without_delivery_state(tmp_path):
    measurement = measurement_module()
    settings = config.StandaloneSettings.from_env(environment(tmp_path)).agent
    deps = measurement.make_measurement_dependencies(settings, state_dir=tmp_path)
    assert not {"sender", "pending_store", "ack_store"} & {field.name for field in fields(deps)}
    original = _dependencies(tmp_path, fetcher=FakeFetcher(_subscription(1), RuntimeError("secret")), sender=RecordingSender(), prober=None)
    deps.fetcher = original.fetcher
    deps.control_checker = original.control_checker
    deps.version_checker = None
    deps.prober = None
    fresh = await measurement.measure_cycle(settings, deps)
    failed = await measurement.measure_cycle(settings, deps)
    assert fresh.refresh_state == "FRESH"
    assert failed.refresh_state == "UNAVAILABLE"
    assert failed.results == []
    assert [fresh.sequence, failed.sequence] == [0, 1]
    assert (tmp_path / "snapshot.json").exists()
    assert not (tmp_path / "pending-report.json").exists()
    assert not (tmp_path / "collector-ack.json").exists()


@pytest.mark.asyncio
async def test_unlimited_daemon_releases_completed_reports(tmp_path):
    references = []
    class Sender:
        async def send(self, report):
            references.append(weakref.ref(report))

    deps = _dependencies(tmp_path, fetcher=FakeFetcher(b"invalid", b"invalid", b"invalid"), sender=Sender(), prober=None)
    class Finished(Exception):
        pass
    elapsed = 0.0
    deps.monotonic = lambda: elapsed
    async def sleep(delay):
        nonlocal elapsed
        elapsed += delay
        if len(references) == 3:
            gc.collect()
            assert references[0]() is None
            assert references[1]() is None
            raise Finished
    deps.sleep = sleep
    with pytest.raises(Finished):
        await run_agent(_settings(), dependencies=deps)


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["snapshot", "sequence", "pending", "ack"])
async def test_state_transition_keeps_event_loop_responsive(tmp_path, transition):
    from litechecker.state import CollectorAckStore
    deps = _dependencies(tmp_path, fetcher=FakeFetcher(_subscription(1)), sender=RecordingSender(), prober=None)
    deps.ack_store = CollectorAckStore(tmp_path / "collector-ack.json")
    store, method = {
        "snapshot": (deps.snapshot_store, "consider"),
        "sequence": (deps.sequence_store, "next"),
        "pending": (deps.pending_store, "save"),
        "ack": (deps.ack_store, "record"),
    }[transition]
    original = getattr(store, method)
    entered = threading.Event()
    release = threading.Event()
    timed_out = threading.Event()
    def slow(*args, **kwargs):
        entered.set()
        if not release.wait(2):
            timed_out.set()
        return original(*args, **kwargs)
    setattr(store, method, slow)
    task = asyncio.create_task(run_cycle(_settings(), deps))
    try:
        while not entered.is_set():
            await asyncio.sleep(0.001)
        assert not timed_out.is_set(), "blocking state transition starved event loop"
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_cancelled_measurement_joins_write_before_outer_lock_release(tmp_path):
    measurement = measurement_module()
    deps = _dependencies(tmp_path, fetcher=FakeFetcher(_subscription(1)), sender=RecordingSender(), prober=None)
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    original = deps.snapshot_store.consider
    def slow(*args):
        entered.set()
        release.wait(2)
        result = original(*args)
        completed.set()
        return result
    deps.snapshot_store.consider = slow
    lock = asyncio.Lock()
    async def cycle():
        async with lock:
            await measurement.measure_cycle(_settings(), deps)
    task = asyncio.create_task(cycle())
    try:
        while not entered.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert lock.locked() and not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert completed.is_set()
        assert not lock.locked()
        assert (tmp_path / "snapshot.json").exists()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancelled_delivery_joins_clear_before_releasing_delivery_lock(tmp_path):
    deps = _dependencies(tmp_path, fetcher=FakeFetcher(b"invalid"), sender=RecordingSender(), prober=None)
    entered = threading.Event()
    release = threading.Event()
    cleared = threading.Event()
    original = deps.pending_store.clear
    def slow_clear(event_id):
        entered.set()
        release.wait(2)
        original(event_id)
        cleared.set()
    deps.pending_store.clear = slow_clear
    task = asyncio.create_task(run_cycle(_settings(), deps))
    contender_entered = asyncio.Event()
    async def contend():
        async with deps.pending_store.delivery_lock():
            contender_entered.set()
            assert cleared.is_set()
    contender = None
    try:
        while not entered.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        contender = asyncio.create_task(contend())
        await asyncio.sleep(0.02)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done()
        assert not contender_entered.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(contender, 1)
        assert deps.pending_store.load() is None
    finally:
        release.set()
        await asyncio.gather(task, *([contender] if contender else []), return_exceptions=True)

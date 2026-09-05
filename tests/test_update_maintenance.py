"""Updates and measured cycles must never overlap their critical sections."""
import asyncio

import pytest
from filelock import AsyncFileLock


@pytest.mark.asyncio
async def test_maintenance_blocks_probe_cycle_without_blocking_event_loop(tmp_path):
    from litechecker.maintenance import cycle_maintenance

    entered = asyncio.Event()
    lock = AsyncFileLock(tmp_path / "maintenance.lock", run_in_executor=True)

    async def cycle():
        async with cycle_maintenance(tmp_path):
            entered.set()

    async with lock:
        task = asyncio.create_task(cycle())
        await asyncio.sleep(0.05)
        assert not entered.is_set()
    await asyncio.wait_for(task, 2)
    assert entered.is_set()


@pytest.mark.asyncio
async def test_cancelled_probe_releases_maintenance_lock(tmp_path):
    from litechecker.maintenance import cycle_maintenance

    entered = asyncio.Event()

    async def cycle():
        async with cycle_maintenance(tmp_path):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(cycle())
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with AsyncFileLock(tmp_path / "maintenance.lock", timeout=0, run_in_executor=True):
        pass


@pytest.mark.asyncio
async def test_maintenance_rejects_symlink_without_touching_external_file(tmp_path):
    from litechecker.maintenance import cycle_maintenance

    state = tmp_path / "state"
    state.mkdir()
    sentinel = tmp_path / "do-not-touch"
    sentinel.write_bytes(b"user data")
    (state / "maintenance.lock").symlink_to(sentinel)
    with pytest.raises(ValueError, match="maintenance path"):
        async with cycle_maintenance(state):
            pytest.fail("unsafe lock cannot be acquired")
    assert sentinel.read_bytes() == b"user data"

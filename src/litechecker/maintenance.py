"""A cross-process boundary between a measured cycle and program replacement."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from filelock import AsyncFileLock, Timeout


@asynccontextmanager
async def cycle_maintenance(state_dir: Path):
    state_dir = Path(state_dir)
    lock_path = state_dir / "maintenance.lock"
    if any(path.is_symlink() for path in (state_dir, *state_dir.parents)):
        raise ValueError("unsafe maintenance path")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = AsyncFileLock(
        lock_path, timeout=0, mode=0o600, preserve_lock_file=True,
        run_in_executor=False,
    )
    while True:
        if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
            raise ValueError("unsafe maintenance path")
        try:
            await lock.acquire(timeout=0)
            break
        except Timeout:
            await asyncio.sleep(0.1)
    try:
        yield
    finally:
        await lock.release()

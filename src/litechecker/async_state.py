"""Cancellation-safe boundary for complete blocking state transitions."""

import asyncio
from collections.abc import Callable
from typing import TypeVar


T = TypeVar("T")


async def state_call(operation: Callable[..., T], /, *args, **kwargs) -> T:
    """Join an in-flight transition before cancellation can release outer locks."""
    worker = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        # Repeated cancellation must not detach a worker still mutating state.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        # Retrieve any worker exception while keeping cancellation authoritative.
        if not worker.cancelled():
            worker.exception()
        raise

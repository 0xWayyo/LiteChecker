"""Shared cancellation-aware process runtime boundaries."""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable, Iterable
from typing import TypeVar


_T = TypeVar("_T")


async def join_owned_tasks(tasks: Iterable[asyncio.Task], *, cancel: bool = False) -> None:
    """Finish owned cleanup even under repeated parent cancellation.

    Do not cancel an already cancelling child again: it may be closing/reaping
    resources in its finally block. Cancellation remains authoritative only
    after every child is joined. Exceptions are retrieved by the owner separately.
    """
    tasks = tuple(tasks)
    if cancel:
        for task in tasks:
            if not task.done() and not task.cancelling():
                task.cancel()
    joined = asyncio.gather(*tasks, return_exceptions=True)
    cancelled = False
    while not joined.done():
        try:
            await asyncio.shield(joined)
        except asyncio.CancelledError:
            cancelled = True
    if cancelled:
        raise asyncio.CancelledError


async def run_with_signals(command: Awaitable[_T]) -> _T:
    """Cancel and fully await one command on SIGINT/SIGTERM when supported."""
    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(command)
    installed: list[tuple[signal.Signals, signal.Handlers]] = []
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous = signal.getsignal(signum)
        try:
            loop.add_signal_handler(signum, task.cancel)
        except (NotImplementedError, RuntimeError):
            continue
        installed.append((signum, previous))
    try:
        return await task
    finally:
        for signum, previous in reversed(installed):
            loop.remove_signal_handler(signum)
            try:
                signal.signal(signum, previous)
            except (OSError, RuntimeError, ValueError):
                pass

"""Shared cancellation-aware process runtime boundaries."""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable
from typing import TypeVar


_T = TypeVar("_T")


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

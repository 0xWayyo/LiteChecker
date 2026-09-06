"""Cancel and join an observation if its physical network snapshot is invalidated."""

from __future__ import annotations

import asyncio

from litechecker.direct_network import DirectNetworkUnavailable
from litechecker.runtime import join_owned_tasks


_POLL_SECONDS = 2.0
_VALIDATION_SECONDS = 10.0


class NetworkInterrupted(RuntimeError):
    def __init__(self, *, changed: bool):
        self.reason = "direct-network-changed" if changed else "direct-network-unverifiable"
        super().__init__(self.reason)


async def _validate(validator):
    try:
        async with asyncio.timeout(_VALIDATION_SECONDS):
            await validator()
    except DirectNetworkUnavailable as exc:
        raise NetworkInterrupted(changed=exc.code == "interface_changed") from None
    except TimeoutError:
        raise NetworkInterrupted(changed=False) from None


async def guard_network(network, operation):
    """Only opted-in transports are watched; no routing changes or fallback.

    The operation must not publish results. Its resources are joined on every
    exit, including repeated cancellation, before a new connection can start.
    """
    validator = getattr(network, "validate_snapshot", None)
    if validator is None:
        return await operation()
    await _validate(validator)

    async def watch():
        while True:
            await asyncio.sleep(_POLL_SECONDS)
            await _validate(validator)

    measuring = asyncio.create_task(operation())
    watching = asyncio.create_task(watch())
    try:
        done, _ = await asyncio.wait((measuring, watching), return_when=asyncio.FIRST_COMPLETED)
        # A simultaneous completion must not hide the monitor's failure.
        if watching in done:
            await watching
        result = await measuring
    finally:
        await join_owned_tasks((measuring, watching), cancel=True)
    # Cover the final poll interval and changes during measurement cleanup.
    await _validate(validator)
    return result

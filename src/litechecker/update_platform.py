"""Lazy POSIX update facade; only the selected host implementation is loaded."""

from __future__ import annotations

from pathlib import Path

from filelock import AsyncFileLock

from litechecker.update_host import (
    CommandResult, UpdatePlatformError, _system, record_desired_running, run_command,
)
from litechecker.update_launcher import checked_path, read_bytes, runtime_python, select_release


def _implementation():
    if _system() == "Darwin":
        from litechecker import macos_update
        return macos_update
    from litechecker import linux_update
    return linux_update


def platform_adapter(root: Path):
    module = _implementation()
    if _system() == "Darwin":
        return module.NativeUpdateAdapter(root)
    return module.DockerUpdateAdapter(root)


async def set_checker_running(root: Path, running: bool):
    record_desired_running(root, running)
    adapter = platform_adapter(root)
    if running:
        root = Path(root).absolute()
        update_lock = checked_path(root, root / ".updates/update.lock")
        update_lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Selection happens after a concurrent transaction commits. The same
        # lock order as core avoids starting an old version after publication.
        async with AsyncFileLock(update_lock, timeout=30, mode=0o600, preserve_lock_file=True):
            checked_path(root, adapter.maintenance_lock)
            async with AsyncFileLock(adapter.maintenance_lock, timeout=30, mode=0o600, preserve_lock_file=True):
                await adapter.activate(select_release(root), True)
    else:
        await adapter.stop_live()


async def run_probe(root: Path):
    """Manual user check, invoked only by the explicit probe CLI action."""
    adapter = platform_adapter(root)
    release = select_release(Path(root).absolute())
    await _implementation().run_probe(adapter, release)


async def cleanup_platform_images(root: Path, *, runner=None) -> int:
    if _system() != "Linux":
        return 0
    from litechecker.linux_update import cleanup_platform_images as cleanup
    return await cleanup(root, runner=runner)


def install_update_schedule(root: Path) -> None:
    """Explicit setup only: no channel means no filesystem/service effects."""
    root = Path(root).absolute()
    channel = root / ".updates/channel.json"
    if not channel.exists() and not channel.is_symlink():
        return
    from litechecker.update_manifest import parse_channel_config
    parse_channel_config(read_bytes(root, channel))
    python = runtime_python(root, system=_system())
    launcher = checked_path(root, root / "src/litechecker/update_launcher.py", regular=True)
    _implementation().install_update_schedule(root, python, launcher)


def __getattr__(name: str):
    if name == "NativeUpdateAdapter":
        from litechecker.macos_update import NativeUpdateAdapter
        return NativeUpdateAdapter
    if name == "DockerUpdateAdapter":
        from litechecker.linux_update import DockerUpdateAdapter
        return DockerUpdateAdapter
    raise AttributeError(name)

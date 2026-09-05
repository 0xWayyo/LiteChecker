"""A release-local D2 worker; lifecycle and updates belong to the supervisor."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

from filelock import AsyncFileLock

from litechecker.direct_check import run_trial
from litechecker.direct_service import run_service
from litechecker.config import _read_secure_text
from litechecker.security import is_valid_agent_id
from litechecker.runtime import run_with_signals
from litechecker.windows_process_state import (
    NONCE, process_matches, process_record, read_record, release_path, safe_root, write_record,
)
from litechecker.windows_trial import TrialConfiguration, _save_text, load_settings
from litechecker.update_launcher import checked_path


async def wait_for_gate(root: Path, instance: str, *, timeout=10.0) -> dict:
    if not isinstance(instance, str) or NONCE.fullmatch(instance) is None:
        raise ValueError("invalid-worker-instance")
    try:
        async with asyncio.timeout(timeout):
            while True:
                gate = read_record(root, "worker-go.json")
                if gate and gate.get("instance") == instance:
                    parent = read_record(root, "supervisor.json")
                    if (parent and gate.get("supervisor_instance") == parent.get("instance")
                            and process_matches(root, parent, "supervisor")):
                        return gate
                await asyncio.sleep(0.05)
    except TimeoutError:
        raise RuntimeError("worker-gate-timeout") from None


def validate(root: Path, release: Path):
    root, release = safe_root(root), release_path(root, release)
    checked_path(release, release / ".windows-native/tools/xray/xray.exe", regular=True)
    configuration = checked_path(root, root / "windows-state/settings.json", regular=True)
    TrialConfiguration.model_validate_json(_read_secure_text(configuration))
    identity = checked_path(root, root / "windows-state/device.json")
    # Preparation is read-only, including the first install: do not initialize
    # device identity or acquire/create a device lock as load_settings would.
    if identity.exists():
        saved = json.loads(_read_secure_text(identity))
        if (not isinstance(saved, dict) or set(saved) != {"agent_id", "state_key"}
                or not is_valid_agent_id(saved["agent_id"])
                or not isinstance(saved["state_key"], str) or len(saved["state_key"]) < 32):
            raise ValueError("invalid-device-identity")


async def windows_cycle(settings):
    from litechecker.windows_network import WindowsDirectNetwork

    async with AsyncFileLock(settings.state_dir / "trial.lock", timeout=0, mode=0o600,
                             preserve_lock_file=True, run_in_executor=True):
        return await run_trial(settings, production=True, network_factory=WindowsDirectNetwork.discover,
                               platform_label="Windows", validate_after=True)


async def run_worker(root: Path, release: Path, instance: str):
    root, release = safe_root(root), release_path(root, release)
    gate = await wait_for_gate(root, instance)
    validate(root, release)
    settings = load_settings(root, str(release / ".windows-native/tools/xray/xray.exe"))
    record = process_record(root, release, "worker", instance,
                            supervisor_instance=gate["supervisor_instance"])

    def ready():
        record["phase"] = "ready"
        write_record(root, "worker.json", record)

    def observed(result):
        _save_text(settings.state_dir, result.text)

    command = asyncio.create_task(run_service(
        settings, send=bool(settings.telegram_bot_token and settings.telegram_chat_id),
        cycle=windows_cycle, platform_label="Windows", on_ready=ready, result_observer=observed,
    ))

    async def watch_stop():
        while not command.done():
            request = read_record(root, "worker-stop.json")
            if request and request.get("instance") == instance:
                command.cancel()
                return
            await asyncio.sleep(0.2)

    watcher = asyncio.create_task(watch_stop())
    try:
        await command
    finally:
        if not command.done():
            command.cancel()
        watcher.cancel()
        await asyncio.gather(command, watcher, return_exceptions=True)
        record["phase"] = "stopped"
        write_record(root, "worker.json", record)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--instance")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        return 2
    try:
        if args.validate:
            validate(args.root, args.release)
            return 0
        if args.instance is None:
            return 2
        asyncio.run(run_with_signals(run_worker(args.root, args.release, args.instance)))
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

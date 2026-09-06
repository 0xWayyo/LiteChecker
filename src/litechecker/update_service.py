"""Explicit host updater CLI. Unconfigured/status paths never inspect OS services."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

from litechecker.update_platform import cleanup_platform_images, install_update_schedule, platform_adapter, run_probe, set_checker_running
from litechecker.update_launcher import checked_path


async def _cleanup_platform_best_effort(root: Path, result: dict) -> dict:
    try:
        await cleanup_platform_images(root)
    except Exception:
        result = dict(result)
        result.setdefault("warning", "platform-cleanup-failed")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "status", "enable", "disable", "cleanup", "configure", "schedule", "install-schedule", "start", "stop", "probe"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--channel", type=Path)
    args = parser.parse_args(argv)
    root = args.root.absolute()
    try:
        if args.action in {"start", "stop"}:
            asyncio.run(set_checker_running(root, args.action == "start"))
            print(json.dumps({"status": "started" if args.action == "start" else "stopped"}))
            return 0
        if args.action == "probe":
            asyncio.run(run_probe(root))
            print('{"status":"checked"}')
            return 0
        if args.action in {"schedule", "install-schedule"}:
            install_update_schedule(root)
            print(json.dumps({"status": "schedule-configured" if (root / ".updates/channel.json").exists() else "unconfigured"}))
            return 0
        if args.action in {"status", "check"} and not (root / ".updates/channel.json").exists() and not (root / ".updates/channel.json").is_symlink():
            print('{"status":"unconfigured"}')
            return 0
        if args.action == "configure":
            from litechecker.updater import initialize_channel
            from litechecker.file_safety import read_bounded_regular
            if args.channel is None:
                raise ValueError
            path = args.channel.absolute()
            checked_path(path.parent, path, regular=True)
            initialize_channel(root, read_bounded_regular(path))
            print('{"status":"configured"}')
            return 0
        from litechecker.updater import check_for_update, set_updates_enabled, update_status
        status = update_status(root)
        if args.action == "status":
            result = status
        elif args.action in {"enable", "disable"}:
            set_updates_enabled(root, args.action == "enable")
            result = update_status(root)
        elif args.action == "cleanup":
            from litechecker.updater import cleanup_updates
            result = cleanup_updates(root)
            result = asyncio.run(_cleanup_platform_best_effort(root, result))
        elif status.get("status") == "unconfigured":
            result = status
        else:
            result = asyncio.run(check_for_update(root, platform_adapter(root), force=args.force))
            if result.get("status") in {"updated", "rolled-back", "current"}:
                result = asyncio.run(_cleanup_platform_best_effort(root, result))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 1 if result.get("status") in {"failed", "rolled-back"} else 0
    except Exception:
        print('{"status":"failed","error":"updater-command-failed"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

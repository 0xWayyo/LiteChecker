"""Native macOS DIRECT settings and daemon entry."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path

from litechecker.config import StandaloneSettings, _read_secure_text
from litechecker.direct_service import ServiceAlreadyRunning, _INTERVAL_SECONDS, run_service
from litechecker.native_config import NATIVE_CONFIG_KEYS
from litechecker.runtime import run_with_signals


def service_settings(
    root: Path,
    xray: str | os.PathLike[str],
    *,
    environment: Mapping[str, str] | None = None,
) -> StandaloneSettings:
    """Load strict canonical data and force all private/runtime paths locally."""
    del environment  # Ambient LC_* variables are not canonical native configuration.
    root = Path(root)
    xray_path = Path(xray)
    _validate_root(root)
    _validate_xray(xray_path)
    try:
        raw = json.loads(_read_secure_text(root / "native-settings.json"))
        if not isinstance(raw, dict) or not set(raw).issubset(NATIVE_CONFIG_KEYS):
            raise ValueError
        env = {key: _config_value(value) for key, value in raw.items()}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("native configuration is invalid") from None

    state_dir = root / "state" / "native-direct"
    env.update(
        LC_STATE_DIR=str(state_dir),
        LC_XRAY_BINARY=str(xray_path),
        LC_INTERVAL_SECONDS=str(_INTERVAL_SECONDS),
        LC_ALLOW_PRIVATE_TARGETS="false",
        LC_TELEGRAM_BOT_TOKEN_FILE=str(root / "secrets" / "telegram_bot_token"),
        LC_SUBSCRIPTION_URL_FILE=str(root / "secrets" / "subscription_url"),
    )
    proxy_file = root / "secrets" / "telegram_proxy_url"
    if proxy_file.exists() or proxy_file.is_symlink():
        env["LC_TELEGRAM_PROXY_URL_FILE"] = str(proxy_file)
    try:
        return StandaloneSettings.from_env(env)
    except Exception:
        raise ValueError("native configuration is invalid") from None


def _validate_root(root: Path) -> None:
    try:
        metadata = root.lstat()
    except OSError:
        raise ValueError("native root is invalid") from None
    if not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("native root is invalid")


def _validate_xray(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError("native Xray is invalid") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o100
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        raise ValueError("native Xray is invalid")


def _config_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str) and "\x00" not in value:
        return value
    raise ValueError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Native macOS DIRECT LiteChecker service")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args(argv)

    async def execute() -> int:
        settings = service_settings(args.root, args.xray)
        result = await run_service(settings, once=args.once, send=not args.no_send)
        if args.once and (
            not result.available
            or (not args.no_send and result.delivery_accepted is not True)
        ):
            return 1
        return 0

    try:
        return asyncio.run(run_with_signals(execute()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("DIRECT service stopped.")
        return 130
    except ServiceAlreadyRunning:
        print("DIRECT service is already running.")
        return 1
    except Exception:
        print("DIRECT service could not start; inspect state/native-direct/status.json.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

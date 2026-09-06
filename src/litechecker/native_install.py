"""Prepare private native macOS configuration without executing source files."""

from __future__ import annotations

import argparse
import json
import plistlib
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from litechecker.native_config import NATIVE_CONFIG_KEYS
from litechecker.native_runtime import (
    DIRECT_SERVICE_LABEL,
    atomic_write as _atomic_write,
    build_direct_service_plist,
    ensure_launch_agents_directory,
    ensure_private_directory as _ensure_private_directory,
    read_bounded_regular as _read_regular,
)
from litechecker.security import is_valid_agent_id
from litechecker.telegram_proxy import validate_telegram_proxy_url


LABEL = DIRECT_SERVICE_LABEL
SETTINGS_FILE = "native-settings.json"
_MAX_FILE_BYTES = 65_536
_ALLOWED_SETTINGS = NATIVE_CONFIG_KEYS
_SECRET_NAMES = ("telegram_bot_token", "subscription_url", "telegram_proxy_url")


def _parse_env(path: Path) -> dict[str, str]:
    text = _read_regular(path).decode("utf-8")
    values: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, encoded = line.partition("=")
        if not separator or key not in _ALLOWED_SETTINGS:
            # Unknown inputs include Docker paths and possible direct secrets.
            continue
        if not key.isascii() or not key.replace("_", "A").isalnum():
            raise ValueError(f"invalid settings key on line {number}")
        value = _decode_compose_value(encoded, number)
        if (
            len(value) > 4096
            or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value)
        ):
            raise ValueError(f"unsafe settings value on line {number}")
        values[key] = value
    values["LC_INTERVAL_SECONDS"] = "600"
    values.setdefault("LC_TELEGRAM_CHAT_ID", "-5361201677")
    return dict(sorted(values.items()))


def _decode_compose_value(encoded: str, number: int) -> str:
    """Decode only the inert single-quoted format emitted by run.sh dotenv."""
    raw = encoded.strip()
    if not raw:
        return ""
    if not raw.startswith("'"):
        if raw.startswith('"') or any(character.isspace() for character in raw):
            raise ValueError(f"invalid settings value on line {number}")
        return raw
    if len(raw) < 2 or not raw.endswith("'"):
        raise ValueError(f"invalid settings value on line {number}")
    inner = raw[1:-1]
    decoded: list[str] = []
    index = 0
    while index < len(inner):
        character = inner[index]
        if character == "\\" and index + 1 < len(inner) and inner[index + 1] == "'":
            decoded.append("'")
            index += 2
            continue
        if character == "'":
            raise ValueError(f"invalid settings value on line {number}")
        decoded.append(character)
        index += 1
    return "".join(decoded)


def _validate_identity(data: bytes) -> None:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("source identity is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"agent_id", "state_key"}
        or not isinstance(payload.get("agent_id"), str)
        or not is_valid_agent_id(payload["agent_id"])
        or not isinstance(payload.get("state_key"), str)
        or len(payload["state_key"]) < 32
    ):
        raise ValueError("source identity is invalid")


def _validate_secret(name: str, data: bytes) -> None:
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("source secret is invalid") from exc
    if not value or len(value) > _MAX_FILE_BYTES or not value.isprintable():
        raise ValueError("source secret is invalid")
    if name == "subscription_url":
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("source subscription URL is invalid")
    elif name == "telegram_proxy_url":
        validate_telegram_proxy_url(value)


def _copy_initial_private_data(source: Path, root: Path) -> None:
    state_dir = root / "state" / "native-direct"
    secrets_dir = root / "secrets"
    _ensure_private_directory(root / "state")
    _ensure_private_directory(state_dir)
    _ensure_private_directory(secrets_dir)

    destination_identity = state_dir / "device.json"
    source_identities: list[bytes] = []
    for candidate in (
        source / "state" / "standalone" / "device.json",
        source / "state" / "direct-trial" / "device.json",
    ):
        if candidate.exists() or candidate.is_symlink():
            data = _read_regular(candidate)
            _validate_identity(data)
            source_identities.append(data)
    if destination_identity.exists() or destination_identity.is_symlink():
        _validate_identity(_read_regular(destination_identity, private=True))
    elif source_identities:
        _atomic_write(destination_identity, source_identities[0].rstrip() + b"\n", 0o600)

    for name in _SECRET_NAMES:
        incoming = source / "secrets" / name
        destination = secrets_dir / name
        incoming_data = None
        if incoming.exists() or incoming.is_symlink():
            incoming_data = _read_regular(incoming, private=True)
            _validate_secret(name, incoming_data)
        if destination.exists() or destination.is_symlink():
            data = _read_regular(destination, private=True)
            _validate_secret(name, data)
            continue
        if incoming_data is not None:
            _atomic_write(destination, incoming_data.rstrip() + b"\n", 0o600)


def _write_settings(source: Path, root: Path) -> None:
    destination = root / SETTINGS_FILE
    source_env = source / ".env.standalone"
    incoming_values = (
        _parse_env(source_env)
        if source_env.exists() or source_env.is_symlink()
        else {
            "LC_INTERVAL_SECONDS": "600",
            "LC_TELEGRAM_CHAT_ID": "-5361201677",
        }
    )
    if destination.exists() or destination.is_symlink():
        data = _read_regular(destination, private=True)
        try:
            payload = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("canonical native settings are invalid") from exc
        if (
            not isinstance(payload, dict)
            or any(key not in _ALLOWED_SETTINGS for key in payload)
            or any(not isinstance(value, (str, bool, int)) for value in payload.values())
        ):
            raise ValueError("canonical native settings are invalid")
        return
    serialized = (json.dumps(incoming_values, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    _atomic_write(destination, serialized, 0o600)


def _write_plist(root: Path, plist_path: Path) -> None:
    ensure_launch_agents_directory(plist_path.parent)
    _atomic_write(
        plist_path,
        plistlib.dumps(build_direct_service_plist(root, root), sort_keys=True),
        0o600,
        private_parent=False,
    )


def _install_update_channel(source: Path, root: Path) -> None:
    incoming = source / "update-channel.json"
    if incoming.exists() or incoming.is_symlink():
        from litechecker.updater import initialize_channel

        initialize_channel(root, _read_regular(incoming))


def _validate_install_profile(source: Path, root: Path) -> bytes | None:
    """Reject an old installation before touching its settings, secrets or trust."""
    from litechecker import distribution
    from litechecker.update_manifest import parse_channel_config

    platform = distribution.read_distribution(source)
    incoming_path = source / "update-channel.json"
    incoming = parse_channel_config(_read_regular(incoming_path)) if incoming_path.exists() or incoming_path.is_symlink() else None
    if platform is None:
        if incoming is not None and incoming.platform is not None:
            raise ValueError("source distribution marker is missing")
        return None  # Unprofiled author fixtures retain their separate API.
    if platform != "macos" or platform != distribution.host_platform():
        raise ValueError("native installation platform does not match host")
    if incoming is None or incoming.platform != platform:
        raise ValueError("source channel does not match distribution")
    if root.exists() and any(root.iterdir()):
        if distribution.read_distribution(root) != platform:
            raise ValueError("incompatible installation; use an empty LITECHECKER_NATIVE_ROOT")
        installed_path = root / ".updates/channel.json"
        if not installed_path.exists() and not installed_path.is_symlink():
            installed_path = root / "update-channel.json"
        if not installed_path.exists() and not installed_path.is_symlink() and set(p.name for p in root.iterdir()) == {"distribution.json"}:
            return _read_regular(source / "distribution.json")
        installed = parse_channel_config(_read_regular(installed_path))
        if (installed.platform, installed.public_key, installed.manifest_urls) != (platform, incoming.public_key, incoming.manifest_urls):
            raise ValueError("incompatible channel; use an empty LITECHECKER_NATIVE_ROOT")
    return _read_regular(source / "distribution.json")


def install_configuration(source: Path, root: Path, plist_path: Path) -> None:
    source = source.absolute()
    root = root.absolute()
    plist_path = plist_path.absolute()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source must be a regular directory")
    if root.is_symlink():
        raise ValueError("installation root must not be a symbolic link")
    marker = _validate_install_profile(source, root)
    _ensure_private_directory(root)
    if marker is not None and not (root / "distribution.json").exists():
        _atomic_write(root / "distribution.json", marker, 0o600)
    _copy_initial_private_data(source, root)
    _write_settings(source, root)
    _install_update_channel(source, root)
    _write_plist(root, plist_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plist", required=True, type=Path)
    parser.add_argument("--configure", action="store_true", help="ask for missing credentials in a terminal")
    arguments = parser.parse_args(argv)
    install_configuration(arguments.source, arguments.root, arguments.plist)
    if arguments.configure:
        from litechecker.device_setup import configure_device

        return configure_device(arguments.root, "native", initial=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

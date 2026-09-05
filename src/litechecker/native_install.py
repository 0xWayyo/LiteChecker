"""Prepare private native macOS configuration without executing source files."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import stat
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from litechecker.security import is_valid_agent_id
from litechecker.telegram_proxy import validate_telegram_proxy_url


LABEL = "com.litechecker.direct"
SETTINGS_FILE = "native-settings.json"
_MAX_FILE_BYTES = 65_536
_ALLOWED_SETTINGS = frozenset({
    "LC_AGENT_CITY",
    "LC_AGENT_NAME",
    "LC_HOST_NAME",
    "LC_HOST_OS",
    "LC_TELEGRAM_CHAT_ID",
    "LC_TELEGRAM_TOPIC_ID",
    "LC_INTERVAL_SECONDS",
    "LC_RUN_DEADLINE_SECONDS",
    "LC_PROBE_TIMEOUT_SECONDS",
    "LC_TCP_TIMEOUT_SECONDS",
    "LC_MAX_CONCURRENCY",
    "LC_MAX_SUBSCRIPTION_BYTES",
    "LC_MAX_ENDPOINTS",
    "LC_AUTO_NETWORK",
    "LC_AUTO_CITY",
    "LC_EXPECTED_XRAY_VERSION",
})
_SECRET_NAMES = ("telegram_bot_token", "subscription_url", "telegram_proxy_url")


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("installation path must not be a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("installation path must be a directory")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise ValueError("installation path owner is unsafe")
    path.chmod(0o700)


def _read_regular(path: Path, *, private: bool = False) -> bytes:
    if path.is_symlink():
        raise ValueError("symbolic link input is not allowed")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_FILE_BYTES:
            raise ValueError("input must be a bounded regular file")
        if private and os.name == "posix" and (
            metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            raise ValueError("private input permissions are unsafe")
        data = bytearray()
        while len(data) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(data))
            if not chunk:
                raise ValueError("input changed while reading")
            data.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("input changed while reading")
        return bytes(data)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, data: bytes, mode: int, *, private_parent: bool = True) -> None:
    if private_parent:
        _ensure_private_directory(path.parent)
    else:
        if path.parent.is_symlink():
            raise ValueError("destination directory must not be a symbolic link")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.is_dir():
            raise ValueError("destination directory is invalid")
    if path.is_symlink():
        raise ValueError("destination must not be a symbolic link")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        path.chmod(mode)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


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
    runtime_python = root / ".native-direct" / "venv" / "bin" / "python"
    xray = root / ".native-direct" / "xray"
    runtime_root = (root / ".native-direct").resolve(strict=True)
    try:
        resolved_python = runtime_python.resolve(strict=True)
        resolved_python.relative_to(runtime_root)
    except (OSError, ValueError) as exc:
        raise ValueError("native Python escapes its private runtime") from exc
    metadata = resolved_python.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved_python, os.X_OK):
        raise ValueError("native Python is incomplete or unsafe")
    if xray.is_symlink() or not xray.is_file() or not os.access(xray, os.X_OK):
        raise ValueError("native Xray is incomplete or unsafe")
    state_dir = root / "state" / "native-direct"
    payload = {
        "Label": LABEL,
        "ProgramArguments": [
            str(runtime_python),
            "-m",
            "litechecker.direct_service",
            "--root",
            str(root),
            "--xray",
            str(xray),
        ],
        "WorkingDirectory": str(root),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "Umask": 0o077,
        "ProcessType": "Background",
        "StandardOutPath": str(state_dir / "service.log"),
        "StandardErrorPath": str(state_dir / "service.log"),
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
    }
    _atomic_write(
        plist_path,
        plistlib.dumps(payload, sort_keys=True),
        0o600,
        private_parent=False,
    )


def _install_update_channel(source: Path, root: Path) -> None:
    incoming = source / "update-channel.json"
    if incoming.exists() or incoming.is_symlink():
        from litechecker.updater import initialize_channel

        initialize_channel(root, _read_regular(incoming))


def install_configuration(source: Path, root: Path, plist_path: Path) -> None:
    source = source.absolute()
    root = root.absolute()
    plist_path = plist_path.absolute()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source must be a regular directory")
    if root.is_symlink():
        raise ValueError("installation root must not be a symbolic link")
    _ensure_private_directory(root)
    _copy_initial_private_data(source, root)
    _write_settings(source, root)
    _install_update_channel(source, root)
    _write_plist(root, plist_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plist", required=True, type=Path)
    arguments = parser.parse_args(argv)
    install_configuration(arguments.source, arguments.root, arguments.plist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

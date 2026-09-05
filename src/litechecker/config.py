"""Strict environment configuration with Docker-secret file support."""

import ipaddress
import json
import os
import platform
import secrets
import stat
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from filelock import FileLock

from litechecker.collector.auth import AgentIdentity
from litechecker.security import generate_agent_token, is_valid_agent_id, is_valid_agent_token
from litechecker.state import _atomic_write_json


_MAX_FILE_VALUE_BYTES = 65_536


def _value_from_env(name: str, environment: Mapping[str, str] | None = None) -> str | None:
    """Return a file-backed secret in preference to its direct env counterpart."""
    env = os.environ if environment is None else environment
    file_name = env.get(f"{name}_FILE")
    if file_name:
        try:
            value = _read_secure_text(Path(file_name)).strip()
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"cannot read {name}_FILE") from exc
        if not value:
            raise ValueError(f"{name}_FILE is empty")
        return value
    return env.get(name)


def _read_secure_text(path: Path) -> str:
    """Validate and read one bounded regular file through one descriptor."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    nofollow = hasattr(os, "O_NOFOLLOW")
    if nofollow:
        flags |= os.O_NOFOLLOW
    before = None if nofollow else path.lstat()
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("file must be regular")
        if os.name == "posix":
            if metadata.st_mode & 0o077:
                raise ValueError("file permissions are unsafe")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise ValueError("file owner is unsafe")
        if metadata.st_size < 1 or metadata.st_size > _MAX_FILE_VALUE_BYTES:
            raise ValueError("file size is unsafe")
        if not nofollow:
            after = path.lstat()
            if (
                before is None
                or stat.S_ISLNK(before.st_mode)
                or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
                or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise ValueError("file changed while opening")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("file changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("file changed while reading")
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(descriptor)


def _is_loopback_host(host: str | None) -> bool:
    if host is None or "%" in host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AgentSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    agent_token: SecretStr = Field(min_length=1)
    collector_url: str
    subscription_url: SecretStr = Field(min_length=1)
    state_key: SecretStr = Field(min_length=32)
    interval_seconds: int = Field(default=600, ge=1)
    run_deadline_seconds: int = Field(default=480, ge=1)
    probe_timeout_seconds: int = Field(default=12, ge=1)
    tcp_timeout_seconds: int = Field(default=3, ge=1)
    max_concurrency: int = Field(default=4, ge=1)
    max_subscription_bytes: int = Field(default=5_242_880, ge=1)
    max_endpoints: int = Field(default=2_000, ge=1)
    allow_private_targets: bool = False
    allow_insecure_collector: bool = False
    xray_binary: str = Field(default="xray", min_length=1, max_length=4096)
    expected_xray_version: str = Field(
        default="26.3.27", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$"
    )

    @field_validator("agent_id")
    @classmethod
    def _agent_id_matches_registry(cls, value: str) -> str:
        if not is_valid_agent_id(value):
            raise ValueError("agent_id is invalid")
        return value

    @field_validator("agent_token")
    @classmethod
    def _agent_token_is_strong(cls, value: SecretStr) -> SecretStr:
        if not is_valid_agent_token(value.get_secret_value()):
            raise ValueError("agent_token must use the generated lc_ format")
        return value

    @field_validator("collector_url")
    @classmethod
    def _collector_url_has_host(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("collector_url must be an absolute HTTP(S) URL")
        return value.rstrip("/")

    @field_validator("subscription_url")
    @classmethod
    def _subscription_url_is_https(cls, value: SecretStr) -> SecretStr:
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("subscription_url must be an absolute HTTPS URL")
        return value

    @model_validator(mode="after")
    def _collector_transport_is_safe(self) -> "AgentSettings":
        parsed = urlsplit(self.collector_url)
        if parsed.scheme == "http" and not (
            self.allow_insecure_collector and _is_loopback_host(parsed.hostname)
        ):
            raise ValueError("collector_url requires HTTPS outside explicit loopback development")
        return self

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> "AgentSettings":
        env = os.environ if environment is None else environment
        return cls(
            agent_id=env.get("LC_AGENT_ID"),
            agent_token=_value_from_env("LC_AGENT_TOKEN", env),
            collector_url=env.get("LC_COLLECTOR_URL"),
            subscription_url=_value_from_env("LC_SUBSCRIPTION_URL", env),
            state_key=_value_from_env("LC_STATE_KEY", env),
            interval_seconds=env.get("LC_INTERVAL_SECONDS", 600),
            run_deadline_seconds=env.get("LC_RUN_DEADLINE_SECONDS", 480),
            probe_timeout_seconds=env.get("LC_PROBE_TIMEOUT_SECONDS", 12),
            tcp_timeout_seconds=env.get("LC_TCP_TIMEOUT_SECONDS", 3),
            max_concurrency=env.get("LC_MAX_CONCURRENCY", 4),
            max_subscription_bytes=env.get("LC_MAX_SUBSCRIPTION_BYTES", 5_242_880),
            max_endpoints=env.get("LC_MAX_ENDPOINTS", 2_000),
            allow_private_targets=env.get("LC_ALLOW_PRIVATE_TARGETS", False),
            allow_insecure_collector=env.get("LC_ALLOW_INSECURE_COLLECTOR", False),
            xray_binary=env.get("LC_XRAY_BINARY", "xray"),
            expected_xray_version=env.get(
                "LC_EXPECTED_XRAY_VERSION", "26.3.27"
            ),
        )


def _validate_telegram_proxy_secret(value: SecretStr | None) -> SecretStr | None:
    if value is not None:
        from litechecker.telegram_proxy import validate_telegram_proxy_url
        validate_telegram_proxy_url(value.get_secret_value())
    return value


class StandaloneSettings(BaseModel):
    """One self-contained tester; city/name are labels, not device identity."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    agent: AgentSettings
    identity: AgentIdentity
    state_dir: Path
    telegram_bot_token: SecretStr = Field(min_length=1)
    telegram_chat_id: str = Field(min_length=1)
    telegram_topic_id: int | None = Field(default=None, ge=1)
    telegram_proxy_url: SecretStr | None = None
    auto_network: bool = False
    auto_city: bool = False

    _proxy_is_valid = field_validator("telegram_proxy_url")(_validate_telegram_proxy_secret)

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> "StandaloneSettings":
        env = dict(os.environ if environment is None else environment)
        manual_city = env.get("LC_AGENT_CITY", "").strip()
        city = _device_label(manual_city) if manual_city else "Город не определён"
        manual_name = env.get("LC_AGENT_NAME", "").strip()
        chat = env.get("LC_TELEGRAM_CHAT_ID")
        token = _value_from_env("LC_TELEGRAM_BOT_TOKEN", env)
        if not chat or not token:
            raise ValueError("standalone Telegram configuration is required")
        state_dir = Path(env.get("LC_STATE_DIR", "/var/lib/litechecker"))
        device_id, state_key = _device_identity(state_dir, env.get("LC_AGENT_ID"))
        name = _device_label(manual_name) if manual_name else _automatic_device_name(env, device_id)
        # These credentials are only compatibility inputs to the shared probe
        # settings. Standalone injects a local sender and never contacts a collector.
        env.pop("LC_AGENT_TOKEN_FILE", None)
        env.pop("LC_STATE_KEY_FILE", None)
        env.update(
            LC_AGENT_ID=device_id,
            LC_AGENT_TOKEN=generate_agent_token(),
            LC_COLLECTOR_URL="http://127.0.0.1",
            LC_ALLOW_INSECURE_COLLECTOR="true",
            LC_STATE_KEY=state_key,
        )
        agent = AgentSettings.from_env(env)
        return cls(
            agent=agent,
            identity=AgentIdentity(device_id, city, name, agent.interval_seconds),
            state_dir=state_dir,
            telegram_bot_token=token,
            telegram_chat_id=chat,
            telegram_topic_id=env.get("LC_TELEGRAM_TOPIC_ID") or None,
            telegram_proxy_url=_value_from_env("LC_TELEGRAM_PROXY_URL", env),
            auto_network=env.get("LC_AUTO_NETWORK", not bool(manual_name)),
            auto_city=env.get("LC_AUTO_CITY", True) if not manual_city else False,
        )


def _automatic_device_name(env: Mapping[str, str], device_id: str) -> str:
    """Use launcher-provided host metadata; never label a container as the PC."""
    in_container = env.get("LC_CONTAINER_MODE", "").lower() in {"true", "1"} or Path("/.dockerenv").exists()
    host = env.get("LC_HOST_NAME", "")
    system = env.get("LC_HOST_OS", "")
    if not in_container:
        host = host or platform.node().split(".")[0]
        raw_system = platform.system()
        system = system or {"Darwin": "macOS"}.get(raw_system, raw_system)
    # macOS ComputerName commonly contains NBSP. Accept spacing characters,
    # while retaining rejection of newlines, controls and bidi formatting.
    host = "".join(" " if unicodedata.category(char) == "Zs" else char for char in host)
    system = "".join(" " if unicodedata.category(char) == "Zs" else char for char in system)
    host = host.strip() if host.isprintable() else ""
    system = system.strip() if system.isprintable() else ""
    host = host or "Устройство " + device_id[-8:]
    return f"{host[:44]} ({system[:16]})" if system else host[:64]


def _device_label(value: str | None) -> str:
    if not value or not value.strip() or len(value) > 128 or not value.isprintable():
        raise ValueError("device city and name must be non-empty printable labels")
    return value.strip()


def _device_identity(state_dir: Path, requested_id: str | None) -> tuple[str, str]:
    """Generate identity once, atomically, never replace unreadable saved identity."""
    if requested_id and not is_valid_agent_id(requested_id):
        raise ValueError("device id is invalid")
    try:
        if state_dir.is_symlink():
            raise ValueError("state directory must not be a symlink")
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = state_dir.stat()
        if os.name == "posix" and (
            metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("state directory must be owned by this user with mode 0700")
        path = state_dir / "device.json"
        with FileLock(state_dir / ".device.lock", timeout=5, mode=0o600, preserve_lock_file=True):
            if path.exists() or path.is_symlink():
                saved = json.loads(_read_secure_text(path))
                if (
                    not isinstance(saved, dict)
                    or set(saved) != {"agent_id", "state_key"}
                    or not is_valid_agent_id(saved["agent_id"])
                    or not isinstance(saved["state_key"], str)
                    or len(saved["state_key"]) < 32
                    or (requested_id and requested_id != saved["agent_id"])
                ):
                    raise ValueError("saved device identity is invalid or conflicts with configuration")
            else:
                saved = {
                    "agent_id": requested_id or "device-" + secrets.token_hex(16),
                    "state_key": secrets.token_urlsafe(32),
                }
                _atomic_write_json(path, saved)
            return saved["agent_id"], saved["state_key"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read or initialize device identity") from exc


class CollectorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    agents_registry_path: Path
    database_path: Path
    telegram_bot_token: SecretStr = Field(min_length=1)
    telegram_chat_id: str = Field(min_length=1)
    telegram_topic_id: int | None = Field(default=None, ge=1)
    telegram_proxy_url: SecretStr | None = None
    _proxy_is_valid = field_validator("telegram_proxy_url")(_validate_telegram_proxy_secret)
    offline_threshold_seconds: int = Field(default=1_500, ge=1)
    report_burst: int = Field(default=3, ge=1, le=100)
    report_window_seconds: int = Field(default=60, ge=1, le=86_400)
    event_retention_seconds: int = Field(default=2_592_000, ge=600, le=31_536_000)
    max_events_per_agent: int = Field(default=5_000, ge=1, le=100_000)
    completed_notification_retention_seconds: int = Field(
        default=604_800, ge=60, le=31_536_000
    )
    max_completed_notifications: int = Field(default=5_000, ge=1, le=100_000)
    max_dead_letters_per_agent: int = Field(default=100, ge=1, le=10_000)
    max_pending_notifications_per_agent: int = Field(default=100, ge=1, le=10_000)
    max_pending_notifications_global: int = Field(default=10_000, ge=1, le=1_000_000)
    max_pending_chunks_per_agent: int = Field(default=1_000, ge=1, le=100_000)
    max_pending_chunks_global: int = Field(default=100_000, ge=1, le=10_000_000)
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8_000, ge=1, le=65_535)

    @classmethod
    def from_env(cls) -> "CollectorSettings":
        return cls(
            agents_registry_path=os.environ.get("LC_AGENTS_REGISTRY_PATH"),
            database_path=os.environ.get("LC_DATABASE_PATH"),
            telegram_bot_token=_value_from_env("LC_TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=os.environ.get("LC_TELEGRAM_CHAT_ID"),
            telegram_topic_id=os.environ.get("LC_TELEGRAM_TOPIC_ID"),
            telegram_proxy_url=_value_from_env("LC_TELEGRAM_PROXY_URL"),
            offline_threshold_seconds=os.environ.get("LC_OFFLINE_THRESHOLD_SECONDS", 1_500),
            report_burst=os.environ.get("LC_REPORT_BURST", 3),
            report_window_seconds=os.environ.get("LC_REPORT_WINDOW_SECONDS", 60),
            event_retention_seconds=os.environ.get("LC_EVENT_RETENTION_SECONDS", 2_592_000),
            max_events_per_agent=os.environ.get("LC_MAX_EVENTS_PER_AGENT", 5_000),
            completed_notification_retention_seconds=os.environ.get(
                "LC_COMPLETED_NOTIFICATION_RETENTION_SECONDS", 604_800
            ),
            max_completed_notifications=os.environ.get(
                "LC_MAX_COMPLETED_NOTIFICATIONS", 5_000
            ),
            max_dead_letters_per_agent=os.environ.get(
                "LC_MAX_DEAD_LETTERS_PER_AGENT", 100
            ),
            max_pending_notifications_per_agent=os.environ.get(
                "LC_MAX_PENDING_NOTIFICATIONS_PER_AGENT", 100
            ),
            max_pending_notifications_global=os.environ.get(
                "LC_MAX_PENDING_NOTIFICATIONS_GLOBAL", 10_000
            ),
            max_pending_chunks_per_agent=os.environ.get(
                "LC_MAX_PENDING_CHUNKS_PER_AGENT", 1_000
            ),
            max_pending_chunks_global=os.environ.get(
                "LC_MAX_PENDING_CHUNKS_GLOBAL", 100_000
            ),
            bind_host=os.environ.get("LC_BIND_HOST", "127.0.0.1"),
            bind_port=os.environ.get("LC_BIND_PORT", 8_000),
        )

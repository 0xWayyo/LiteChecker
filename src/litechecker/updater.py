"""Transactional signed updater orchestration, independent of platform control."""

from __future__ import annotations

import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import time
import tomllib
from typing import Awaitable, Callable, Protocol
from urllib.parse import urljoin, urlsplit

from filelock import FileLock, Timeout
import httpx

from .update_manifest import (
    ChannelConfig,
    ManifestError,
    MAX_METADATA_BYTES,
    parse_channel_config,
    parse_version,
    verify_release_metadata,
)
from .update_store import StoreError, UpdateStore, validate_source_zip
from . import windows_security


CHECK_INTERVAL = timedelta(hours=1)
TOTAL_DEADLINE_SECONDS = 120.0
MAINTENANCE_WAIT_SECONDS = 60.0
PREPARE_TIMEOUT_SECONDS = 600.0
LOCAL_ACTION_TIMEOUT_SECONDS = 120.0
MAX_REDIRECTS = 5
ERROR_LIMIT = 240
AsyncFetcher = Callable[[str, int], Awaitable[bytes]]


class UpdateAdapter(Protocol):
    @property
    def maintenance_lock(self) -> Path: ...

    @property
    def baseline(self) -> Path: ...

    async def prepare(self, release: Path) -> None: ...

    async def is_running(self) -> bool: ...

    async def activate(self, release: Path, running: bool) -> None: ...

    async def healthy(self, release: Path, running: bool) -> bool: ...


def _utc_now(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValueError("update time must be timezone-aware")
    return result.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _closed(
    status: str,
    state: dict | None = None,
    *,
    error: str | None = None,
    cleanup: dict[str, int] | None = None,
    warning: str | None = None,
) -> dict:
    state = state or {}
    bounded_error = error[:ERROR_LIMIT] if error else None
    result = {
        "status": status,
        "version": state.get("active"),
        "previous": state.get("previous"),
        "error": bounded_error,
        "cleanup": cleanup or {"releases": 0, "temporary": 0},
    }
    if warning:
        result["warning"] = warning[:ERROR_LIMIT]
    return result


def _read_file_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise StoreError("configuration path is unsafe")
    if windows_security.is_windows():
        windows_security.assert_private_file(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if not stat.S_ISREG(details.st_mode) or not 1 <= details.st_size <= limit:
                raise StoreError("configuration size is invalid")
            data = source.read(limit + 1)
    except OSError as error:
        raise StoreError("configuration cannot be read") from error
    if not 1 <= len(data) <= limit:
        raise StoreError("configuration size is invalid")
    return data


def _load_channel(store: UpdateStore) -> ChannelConfig | None:
    store._validate_root()
    if not store.channel_path.exists():
        return None
    return parse_channel_config(_read_file_bounded(store.channel_path, MAX_METADATA_BYTES))


def _channel_document(config: ChannelConfig, *, enabled: bool | None = None) -> dict:
    return {
        "schema": 1,
        "enabled": config.enabled if enabled is None else enabled,
        "public_key": base64.b64encode(config.public_key).decode("ascii"),
        "manifest_urls": list(config.manifest_urls),
    }


def initialize_channel(root: Path, data: bytes) -> bool:
    """Provision a validated first-install channel without replacing trust."""

    config = parse_channel_config(data)
    store = UpdateStore(Path(root))
    store._validate_root()
    if store.channel_path.exists() or store.channel_path.is_symlink():
        if store.channel_path.is_symlink() or not store.channel_path.is_file():
            raise StoreError("installed channel path is unsafe")
        if windows_security.is_windows():
            windows_security.assert_private_file(store.channel_path)
        return False
    store.ensure_layout()
    payload = (
        json.dumps(_channel_document(config), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(store.channel_path, flags, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, "wb") as output:
        if not windows_security.is_windows():
            os.fchmod(output.fileno(), 0o600)
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    if os.name == "posix":
        directory = os.open(store.updates, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return True


def set_updates_enabled(root: Path, enabled: bool) -> None:
    """Toggle only an existing, already trusted channel configuration."""

    if type(enabled) is not bool:
        raise ValueError("enabled must be a bool")
    store = UpdateStore(Path(root))
    channel = _load_channel(store)
    if channel is None:
        raise FileNotFoundError("update channel is not configured")
    store.write_channel(_channel_document(channel, enabled=enabled))


def update_status(root: Path) -> dict:
    """Return updater state without creating or modifying filesystem entries."""

    store = UpdateStore(Path(root))
    try:
        channel = _load_channel(store)
        if channel is None:
            return _closed("unconfigured")
        state = store.read_install()
        if not channel.enabled:
            return _closed("disabled", state)
        return _closed(state["status"], state, error=state["error"])
    except (ManifestError, StoreError, OSError, ValueError):
        return _closed("failed", error="local update state is invalid")


async def _default_fetch(url: str, limit: int) -> bytes:
    current = url
    timeout = httpx.Timeout(TOTAL_DEADLINE_SECONDS)
    async with httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        timeout=timeout,
    ) as client:
        for redirects in range(MAX_REDIRECTS + 1):
            parsed_current = urlsplit(current)
            if (
                parsed_current.scheme != "https"
                or parsed_current.hostname is None
                or parsed_current.username is not None
                or parsed_current.password is not None
                or parsed_current.fragment
            ):
                raise ValueError("download URL is not HTTPS")
            async with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirects == MAX_REDIRECTS:
                        raise ValueError("download redirect limit exceeded")
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("download redirect is invalid")
                    redirected = urljoin(current, location)
                    parsed_redirect = urlsplit(redirected)
                    if (
                        parsed_redirect.scheme != "https"
                        or parsed_redirect.hostname is None
                        or parsed_redirect.username is not None
                        or parsed_redirect.password is not None
                        or parsed_redirect.fragment
                    ):
                        raise ValueError("download redirect is not HTTPS")
                    current = redirected
                    continue
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        if int(content_length) > limit:
                            raise ValueError("download exceeds limit")
                    except ValueError as error:
                        raise ValueError("download length is invalid") from error
                result = bytearray()
                async for chunk in response.aiter_bytes():
                    result.extend(chunk)
                    if len(result) > limit:
                        raise ValueError("download exceeds limit")
                return bytes(result)
    raise ValueError("download failed")


async def _bounded_fetch(
    fetcher: AsyncFetcher,
    url: str,
    limit: int,
    deadline: float,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("update deadline expired")
    data = await asyncio.wait_for(fetcher(url, limit), timeout=remaining)
    if type(data) is not bytes or not 1 <= len(data) <= limit:
        raise ValueError("download size is invalid")
    return data


def _try_lock(path: Path, allowed_root: Path) -> FileLock | None:
    path = Path(path)
    allowed_root = Path(allowed_root)
    if windows_security.is_windows():
        windows_security.assert_private_directory(allowed_root)
        windows_security.reject_reparse_points(path)
    if not path.is_absolute() or not allowed_root.is_absolute() or allowed_root.is_symlink():
        raise StoreError("lock path is unsafe")
    try:
        relative = path.relative_to(allowed_root)
    except ValueError as error:
        raise StoreError("lock path is outside updater root") from error
    if len(relative.parts) < 2:
        raise StoreError("lock path is unsafe")
    cursor = allowed_root
    for component in relative.parts[:-1]:
        cursor = cursor / component
        if cursor.exists() or cursor.is_symlink():
            if cursor.is_symlink() or not cursor.is_dir():
                raise StoreError("lock parent is unsafe")
        else:
            cursor.mkdir(mode=0o700)
        if windows_security.is_windows():
            windows_security.assert_private_directory(cursor)
        if hasattr(os, "getuid") and cursor.stat().st_uid != os.getuid():
            raise StoreError("lock parent has unexpected ownership")
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise StoreError("lock file is unsafe")
        if hasattr(os, "getuid") and path.stat().st_uid != os.getuid():
            raise StoreError("lock file has unexpected ownership")
    else:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
    if windows_security.is_windows():
        windows_security.assert_private_file(path)
    else:
        path.chmod(0o600)
    lock = FileLock(path, preserve_lock_file=True)
    try:
        lock.acquire(timeout=0)
    except Timeout:
        return None
    try:
        if not windows_security.is_windows():
            path.chmod(0o600)
    except OSError:
        lock.release()
        raise
    return lock


async def _maintenance_lock(path: Path, allowed_root: Path, deadline: float) -> FileLock | None:
    while time.monotonic() < deadline:
        lock = _try_lock(path, allowed_root)
        if lock is not None:
            return lock
        await asyncio.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    return None


def _write_outcome(store: UpdateStore, state: dict, status: str, error: str | None) -> None:
    state["status"] = status
    state["error"] = error[:ERROR_LIMIT] if error else None
    store.write_install(state)


def _release_path(store: UpdateStore, adapter: UpdateAdapter, version: str | None) -> Path:
    if version is None:
        return Path(adapter.baseline)
    return store.releases / version


def _baseline_version(store: UpdateStore, adapter: UpdateAdapter) -> tuple[int, int, int]:
    baseline = Path(adapter.baseline)
    if not baseline.is_absolute() or baseline.is_symlink() or not baseline.is_dir():
        raise StoreError("baseline release path is unsafe")
    try:
        baseline.resolve(strict=True).relative_to(store.root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise StoreError("baseline release path is unsafe") from error
    project = baseline / "pyproject.toml"
    try:
        document = tomllib.loads(_read_file_bounded(project, 64 * 1024).decode("utf-8"))
        version = document["project"]["version"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise StoreError("baseline version is invalid") from error
    return parse_version(version)


def _with_cleanup(
    store: UpdateStore,
    state: dict,
    status: str,
    now: datetime,
    *,
    error: str | None = None,
    remove_version: str | None = None,
) -> dict:
    warning = None
    if remove_version is not None:
        try:
            store.remove_release(remove_version)
        except Exception:
            warning = "update-cleanup-failed"
    try:
        counts = store.cleanup(active=state["active"], previous=state["previous"], now=now)
        if counts.get("deferred"):
            warning = "update-cleanup-deferred"
    except Exception:
        counts = {"releases": 0, "temporary": 0}
        warning = "update-cleanup-failed"
    return _closed(status, state, error=error, cleanup=counts, warning=warning)


async def _recover(
    store: UpdateStore,
    adapter: UpdateAdapter,
    state: dict,
    now: datetime,
    deadline: float,
) -> dict | None:
    pending = state["pending"]
    if pending is None:
        return None
    previous = _release_path(store, adapter, pending["from_version"])
    lock = await _maintenance_lock(Path(adapter.maintenance_lock), store.root, deadline)
    if lock is None:
        return _closed("busy", state, error="maintenance window is busy")
    restored = False
    try:
        await asyncio.wait_for(
            adapter.activate(previous, pending["was_running"]),
            timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
        )
        restored = bool(await asyncio.wait_for(
            adapter.healthy(previous, pending["was_running"]),
            timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
        ))
    except Exception:
        restored = False
    finally:
        lock.release()
    if not restored:
        _write_outcome(store, state, "failed", "interrupted update recovery failed")
        return _closed("failed", state, error=state["error"])
    candidate = pending["to_version"]
    state["pending"] = None
    state["failed"] = {"sequence": pending["sequence"], "digest": pending["digest"]}
    _write_outcome(store, state, "rolled-back", "interrupted update was rolled back")
    return _with_cleanup(
        store,
        state,
        "rolled-back",
        now,
        error=state["error"],
        remove_version=candidate,
    )


async def check_for_update(
    root: Path,
    adapter: UpdateAdapter,
    *,
    force: bool = False,
    fetcher: AsyncFetcher | None = None,
    now: datetime | None = None,
) -> dict:
    """Authenticate, stage, prepare and transactionally activate one release."""

    store = UpdateStore(Path(root))
    try:
        checked_at = _utc_now(now)
        channel = _load_channel(store)
    except (ManifestError, StoreError, OSError, ValueError):
        return _closed("failed", error="local update configuration is invalid")
    if channel is None:
        return _closed("unconfigured")
    try:
        state = store.read_install()
    except (StoreError, OSError, ValueError):
        return _closed("failed", error="local update state is invalid")
    if not channel.enabled and state["pending"] is None:
        return _closed("disabled", state)
    if type(force) is not bool:
        return _closed("failed", state, error="force flag is invalid")

    try:
        store.ensure_layout()
        transaction_lock = _try_lock(store.update_lock, store.root)
    except (StoreError, OSError, ValueError):
        return _closed("failed", state, error="update storage is unavailable")
    if transaction_lock is None:
        return _closed("busy", state)
    download_deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    try:
        state = store.read_install()
        recovered = await _recover(
            store,
            adapter,
            state,
            checked_at,
            time.monotonic() + MAINTENANCE_WAIT_SECONDS,
        )
        if recovered is not None:
            return recovered
        if not channel.enabled:
            return _closed("disabled", state)
        if not force and state["last_checked_at"] is not None:
            if checked_at < _read_timestamp(state["last_checked_at"]) + CHECK_INTERVAL:
                return _closed("not-due", state)

        selected = fetcher or _default_fetch
        release = None
        for url in channel.manifest_urls:
            try:
                metadata = await _bounded_fetch(selected, url, MAX_METADATA_BYTES, download_deadline)
                release = verify_release_metadata(metadata, channel.public_key)
                break
            except Exception:
                continue
        state["last_checked_at"] = _timestamp(checked_at)
        if release is None:
            _write_outcome(store, state, "failed", "release metadata is unavailable or invalid")
            return _with_cleanup(
                store, state, "failed", checked_at, error=state["error"]
            )

        sequence = release.sequence
        digest = release.artifact.sha256
        highest = state["highest_sequence"]
        if sequence < highest:
            _write_outcome(store, state, "failed", "release sequence is older than installed state")
            return _closed("failed", state, error=state["error"])
        if sequence == highest:
            if digest == state["highest_digest"] and state["active"] == release.version:
                _write_outcome(store, state, "current", None)
                return _with_cleanup(store, state, "current", checked_at)
            if digest != state["highest_digest"]:
                _write_outcome(store, state, "failed", "release sequence conflicts with installed state")
                return _closed("failed", state, error=state["error"])
        if state["active"] is not None:
            if parse_version(release.version) <= parse_version(state["active"]):
                _write_outcome(store, state, "failed", "release version does not advance installed state")
                return _closed("failed", state, error=state["error"])
        elif parse_version(release.version) < _baseline_version(store, adapter):
            _write_outcome(store, state, "failed", "release version is older than baseline")
            return _closed("failed", state, error=state["error"])
        failed = state["failed"]
        if failed is not None and failed["sequence"] == sequence and failed["digest"] == digest:
            _write_outcome(store, state, "failed", "release previously failed local activation")
            return _closed("failed", state, error=state["error"])
        if sequence > highest:
            state["highest_sequence"] = sequence
            state["highest_digest"] = digest
            try:
                store.write_install(state)
            except Exception:
                return _closed("failed", state, error="release high-water mark could not be persisted")

        validated = None
        for url in release.artifact.urls:
            try:
                archive = await _bounded_fetch(selected, url, release.artifact.size, download_deadline)
                validated = validate_source_zip(
                    archive,
                    expected_sha256=digest,
                    expected_size=release.artifact.size,
                )
                break
            except Exception:
                continue
        if validated is None:
            _write_outcome(store, state, "failed", "release archive is unavailable or invalid")
            return _closed("failed", state, error=state["error"])

        try:
            candidate = store.stage(release.version, validated)
            await asyncio.wait_for(
                adapter.prepare(candidate), timeout=PREPARE_TIMEOUT_SECONDS
            )
            was_running = bool(await asyncio.wait_for(
                adapter.is_running(), timeout=LOCAL_ACTION_TIMEOUT_SECONDS
            ))
        except asyncio.CancelledError:
            store.remove_release(release.version)
            raise
        except Exception:
            store.remove_release(release.version)
            _write_outcome(store, state, "failed", "release preparation failed")
            return _closed("failed", state, error=state["error"])

        state["pending"] = {
            "from_version": state["active"],
            "to_version": release.version,
            "sequence": sequence,
            "digest": digest,
            "was_running": was_running,
        }
        try:
            store.write_install(state)
        except Exception:
            store.remove_release(release.version)
            return _closed("failed", state, error="recovery journal could not be persisted")

        maintenance = await _maintenance_lock(
            Path(adapter.maintenance_lock),
            store.root,
            time.monotonic() + MAINTENANCE_WAIT_SECONDS,
        )
        if maintenance is None:
            state["pending"] = None
            _write_outcome(store, state, "busy", "maintenance window is busy")
            store.remove_release(release.version)
            return _closed("busy", state, error=state["error"])

        old_release = _release_path(store, adapter, state["pending"]["from_version"])
        committed = False
        rollback_ok = False
        permanent_release_failure = True
        try:
            await asyncio.wait_for(
                adapter.activate(candidate, was_running),
                timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
            )
            candidate_healthy = bool(await asyncio.wait_for(
                adapter.healthy(candidate, was_running),
                timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
            ))
            if candidate_healthy:
                permanent_release_failure = False
                committed_state = copy.deepcopy(state)
                old_active = committed_state["active"]
                committed_state["active"] = release.version
                committed_state["previous"] = old_active
                committed_state["highest_sequence"] = sequence
                committed_state["highest_digest"] = digest
                committed_state["pending"] = None
                committed_state["failed"] = None
                _write_outcome(store, committed_state, "updated", None)
                state = committed_state
                committed = True
            else:
                await asyncio.wait_for(
                    adapter.activate(old_release, was_running),
                    timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
                )
                rollback_ok = bool(await asyncio.wait_for(
                    adapter.healthy(old_release, was_running),
                    timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
                ))
        except Exception:
            try:
                await asyncio.wait_for(
                    adapter.activate(old_release, was_running),
                    timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
                )
                rollback_ok = bool(await asyncio.wait_for(
                    adapter.healthy(old_release, was_running),
                    timeout=LOCAL_ACTION_TIMEOUT_SECONDS,
                ))
            except Exception:
                rollback_ok = False
        finally:
            maintenance.release()

        if committed:
            return _with_cleanup(store, state, "updated", checked_at)
        if rollback_ok:
            rolled_back_state = copy.deepcopy(state)
            rolled_back_state["pending"] = None
            if permanent_release_failure:
                rolled_back_state["failed"] = {"sequence": sequence, "digest": digest}
            failure_text = (
                "activation failed; previous release restored"
                if permanent_release_failure
                else "activation commit failed; previous release restored"
            )
            try:
                _write_outcome(
                    store,
                    rolled_back_state,
                    "rolled-back",
                    failure_text,
                )
            except Exception:
                return _closed(
                    "rolled-back",
                    state,
                    error="previous release restored; recovery journal remains pending",
                )
            state = rolled_back_state
            return _with_cleanup(
                store,
                state,
                "rolled-back",
                checked_at,
                error=state["error"],
                remove_version=release.version,
            )
        _write_outcome(store, state, "failed", "activation and rollback failed; recovery remains pending")
        return _closed("failed", state, error=state["error"])
    except asyncio.CancelledError:
        raise
    except Exception:
        try:
            state["last_checked_at"] = _timestamp(checked_at)
            _write_outcome(store, state, "failed", "update operation failed safely")
        except Exception:
            pass
        return _closed("failed", state, error="update operation failed safely")
    finally:
        transaction_lock.release()


def cleanup_updates(root: Path, *, now: datetime | None = None) -> dict:
    """Remove only owned obsolete material under the updater transaction lock."""

    store = UpdateStore(Path(root))
    try:
        checked_at = _utc_now(now)
        channel = _load_channel(store)
        if channel is None:
            return _closed("unconfigured")
        state = store.read_install()
        if not channel.enabled:
            return _closed("disabled", state)
        store.ensure_layout()
        lock = _try_lock(store.update_lock, store.root)
        if lock is None:
            return _closed("busy", state)
        try:
            state = store.read_install()
            if state["pending"] is not None:
                return _closed("busy", state, error="update recovery is pending")
            counts = store.cleanup(active=state["active"], previous=state["previous"], now=checked_at)
            return _closed(state["status"], state, error=state["error"], cleanup=counts)
        finally:
            lock.release()
    except (ManifestError, StoreError, OSError, ValueError):
        return _closed("failed", error="local update state is invalid")

"""Private, bounded storage for authenticated LiteChecker releases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import unicodedata
import uuid
import zipfile

from .update_manifest import SHA256_RE, VERSION_RE
from . import windows_security


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2048
STALE_TEMP_SECONDS = 24 * 60 * 60
OWNED_MARKER = ".litechecker-update-owned"
OWNED_MARKER_BYTES = b"litechecker-updater-v1\n"
ARTIFACT_DIGEST = ".artifact.sha256"
CONTENT_MANIFEST = "CONTENTS.sha256.json"
FORBIDDEN_COMPONENTS = frozenset(
    {
        ".git",
        ".native-direct",
        ".runtime",
        ".updates",
        ".updater-runtime",
        ".venv",
        ".windows-native",
        "__pycache__",
        "dist",
        "node_modules",
        "runtime",
        "secrets",
        "state",
        "venv",
        "windows-state",
    }
)
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
STATE_FIELDS = {
    "schema",
    "active",
    "previous",
    "highest_sequence",
    "highest_digest",
    "last_checked_at",
    "pending",
    "failed",
    "status",
    "error",
}
STATUSES = {
    "unconfigured",
    "disabled",
    "not-due",
    "current",
    "updated",
    "rolled-back",
    "failed",
    "busy",
}


class StoreError(ValueError):
    """An archive or managed updater path/state is unsafe or invalid."""


@dataclass(frozen=True)
class ArchiveFile:
    path: PurePosixPath
    data: bytes
    mode: int


@dataclass(frozen=True)
class ValidatedArchive:
    files: tuple[ArchiveFile, ...]
    sha256: str
    size: int


def _duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StoreError("duplicate JSON field")
        result[key] = value
    return result


def _json_bytes(data: bytes):
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(StoreError("invalid JSON number")),
        )
    except StoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise StoreError("JSON is invalid") from error


def _normalized_name(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _safe_relative(name: str) -> PurePosixPath:
    if not name or len(name.encode("utf-8")) > 1024 or "\\" in name or "\x00" in name or name.startswith("/"):
        raise StoreError("archive path is unsafe")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts:
        raise StoreError("archive path is unsafe")
    for component in path.parts:
        folded = _normalized_name(component)
        private_environment = folded == ".env" or (
            folded.startswith(".env.") and not folded.endswith(".example")
        )
        windows_stem = folded.split(".", 1)[0]
        if (
            component in {"", ".", ".."}
            or len(component.encode("utf-8")) > 255
            or folded in FORBIDDEN_COMPONENTS
            or folded == "native-settings.json"
            or windows_stem in WINDOWS_RESERVED
            or private_environment
            or component.endswith((" ", "."))
            or any(ord(char) < 32 or char in '<>:"|?*' for char in component)
        ):
            raise StoreError("archive path is unsafe")
    if path.name in {OWNED_MARKER, ARTIFACT_DIGEST}:
        raise StoreError("archive path uses a managed name")
    return path


def validate_source_zip(
    data: bytes,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> ValidatedArchive:
    """Validate a complete signed source archive without writing any files."""

    if type(data) is not bytes or not 1 <= len(data) <= MAX_ARCHIVE_BYTES:
        raise StoreError("archive size is invalid")
    digest = hashlib.sha256(data).hexdigest()
    if expected_size is not None and (type(expected_size) is not int or len(data) != expected_size):
        raise StoreError("archive size does not match metadata")
    if expected_sha256 is not None and (
        type(expected_sha256) is not str
        or SHA256_RE.fullmatch(expected_sha256) is None
        or not hmac.compare_digest(digest, expected_sha256)
    ):
        raise StoreError("archive digest does not match metadata")

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not 2 <= len(infos) <= MAX_ENTRIES:
                raise StoreError("archive entry count is invalid")
            names: dict[str, zipfile.ZipInfo] = {}
            total = 0
            for info in infos:
                name = info.filename
                if type(name) is not str or not name.startswith("LiteChecker/"):
                    raise StoreError("archive member is outside LiteChecker")
                relative_name = name[len("LiteChecker/") :]
                _safe_relative(relative_name)
                normalized = _normalized_name(relative_name)
                if normalized in names:
                    raise StoreError("archive contains duplicate or case-colliding members")
                names[normalized] = info
                file_type = stat.S_IFMT(info.external_attr >> 16)
                if info.is_dir() or file_type != stat.S_IFREG or info.flag_bits & 0x1:
                    raise StoreError("archive contains a non-regular member")
                if info.file_size < 0 or info.compress_size < 0:
                    raise StoreError("archive member size is invalid")
                total += info.file_size
                if total > MAX_EXPANDED_BYTES:
                    raise StoreError("archive expanded size exceeds limit")
                if info.file_size > 1024 * 1024 and info.compress_size * 1000 < info.file_size:
                    raise StoreError("archive compression ratio is unsafe")
            for normalized in names:
                parts = normalized.split("/")
                if any("/".join(parts[:index]) in names for index in range(1, len(parts))):
                    raise StoreError("archive contains a file and child path collision")
            manifest_info = names.get(_normalized_name(CONTENT_MANIFEST))
            if manifest_info is None or manifest_info.filename != "LiteChecker/" + CONTENT_MANIFEST:
                raise StoreError("archive content manifest is missing")
            payloads: dict[str, bytes] = {}
            for info in infos:
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    raise StoreError("archive member size changed while reading")
                payloads[info.filename[len("LiteChecker/") :]] = payload
    except StoreError:
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError) as error:
        raise StoreError("archive is invalid") from error

    manifest = _json_bytes(payloads[CONTENT_MANIFEST])
    if type(manifest) is not dict or not manifest:
        raise StoreError("content manifest is invalid")
    expected_names: set[str] = set()
    normalized_manifest: set[str] = set()
    for name, expected in manifest.items():
        if type(name) is not str or type(expected) is not str or SHA256_RE.fullmatch(expected) is None:
            raise StoreError("content manifest entry is invalid")
        safe = _safe_relative(name)
        normalized = _normalized_name(safe.as_posix())
        if normalized in normalized_manifest or name == CONTENT_MANIFEST:
            raise StoreError("content manifest contains duplicate or managed entries")
        normalized_manifest.add(normalized)
        expected_names.add(name)
    if set(payloads) != expected_names | {CONTENT_MANIFEST}:
        raise StoreError("archive members do not exactly match content manifest")
    files: list[ArchiveFile] = []
    info_by_name = {info.filename[len("LiteChecker/") :]: info for info in infos}
    for name in sorted(expected_names):
        payload = payloads[name]
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), manifest[name]):
            raise StoreError("archive member digest mismatch")
        mode = (info_by_name[name].external_attr >> 16) & 0o777
        files.append(ArchiveFile(path=PurePosixPath(name), data=payload, mode=mode))
    return ValidatedArchive(files=tuple(files), sha256=digest, size=len(data))


def default_install_state() -> dict:
    return {
        "schema": 1,
        "active": None,
        "previous": None,
        "highest_sequence": 0,
        "highest_digest": None,
        "last_checked_at": None,
        "pending": None,
        "failed": None,
        "status": "current",
        "error": None,
    }


def _version_or_none(value) -> bool:
    return value is None or type(value) is str and VERSION_RE.fullmatch(value) is not None


def _digest_or_none(value) -> bool:
    return value is None or type(value) is str and SHA256_RE.fullmatch(value) is not None


def _utc_timestamp(value) -> bool:
    if value is None:
        return True
    if type(value) is not str or not value.endswith("Z"):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def validate_install_state(value) -> dict:
    if type(value) is not dict or set(value) != STATE_FIELDS:
        raise StoreError("install state fields are invalid")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise StoreError("install state schema is unsupported")
    if not _version_or_none(value["active"]) or not _version_or_none(value["previous"]):
        raise StoreError("install release selector is invalid")
    if type(value["highest_sequence"]) is not int or value["highest_sequence"] < 0:
        raise StoreError("install sequence is invalid")
    if not _digest_or_none(value["highest_digest"]):
        raise StoreError("install digest is invalid")
    if value["highest_sequence"] == 0 and value["highest_digest"] is not None:
        raise StoreError("install high-water mark is inconsistent")
    if value["highest_sequence"] > 0 and value["highest_digest"] is None:
        raise StoreError("install high-water mark is inconsistent")
    if not _utc_timestamp(value["last_checked_at"]):
        raise StoreError("install check time is invalid")
    pending = value["pending"]
    if pending is not None:
        if type(pending) is not dict or set(pending) != {
            "from_version", "to_version", "sequence", "digest", "was_running"
        }:
            raise StoreError("pending transaction is invalid")
        if (
            not _version_or_none(pending["from_version"])
            or not _version_or_none(pending["to_version"])
            or pending["to_version"] is None
            or type(pending["sequence"]) is not int
            or pending["sequence"] < 1
            or not _digest_or_none(pending["digest"])
            or pending["digest"] is None
            or type(pending["was_running"]) is not bool
        ):
            raise StoreError("pending transaction is invalid")
    failed = value["failed"]
    if failed is not None:
        if type(failed) is not dict or set(failed) != {"sequence", "digest"}:
            raise StoreError("failed release marker is invalid")
        if (
            type(failed["sequence"]) is not int
            or failed["sequence"] < 1
            or not _digest_or_none(failed["digest"])
            or failed["digest"] is None
        ):
            raise StoreError("failed release marker is invalid")
    if type(value["status"]) is not str or value["status"] not in STATUSES:
        raise StoreError("install status is invalid")
    if value["error"] is not None and (
        type(value["error"]) is not str or len(value["error"]) > 240
    ):
        raise StoreError("install error is invalid")
    return value


class UpdateStore:
    """Own `.updates` state while refusing unsafe roots and foreign entries."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.updates = self.root / ".updates"
        self.releases = self.updates / "releases"
        self.temporary = self.updates / "tmp"
        self.install_path = self.updates / "install.json"
        self.channel_path = self.updates / "channel.json"
        self.update_lock = self.updates / "update.lock"

    def _validate_root(self) -> None:
        if not self.root.is_absolute() or not self.root.is_dir() or self.root.is_symlink():
            raise StoreError("updater root is unsafe")
        try:
            if windows_security.is_windows():
                windows_security.assert_private_directory(self.root)
                windows_security.reject_reparse_points(self.updates)
            if self.root.resolve(strict=True) != self.root:
                raise StoreError("updater root contains a symbolic link")
            if hasattr(os, "getuid") and self.root.stat().st_uid != os.getuid():
                raise StoreError("updater root has unexpected ownership")
        except OSError as error:
            raise StoreError("updater root is unsafe") from error
        if self.updates.exists() and (self.updates.is_symlink() or not self.updates.is_dir()):
            raise StoreError("managed updater directory is unsafe")
        if (
            self.updates.exists()
            and hasattr(os, "getuid")
            and self.updates.stat().st_uid != os.getuid()
        ):
            raise StoreError("managed updater directory has unexpected ownership")

    def ensure_layout(self) -> None:
        self._validate_root()
        for directory in (self.updates, self.releases, self.temporary):
            if windows_security.is_windows():
                windows_security.reject_reparse_points(directory)
            if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
                raise StoreError("managed updater directory is unsafe")
            directory.mkdir(mode=0o700, exist_ok=True)
            if windows_security.is_windows():
                windows_security.assert_private_directory(directory)
            else:
                directory.chmod(0o700)

    def _atomic_json(self, path: Path, value: dict) -> None:
        self.ensure_layout()
        if path.parent != self.updates:
            raise StoreError("state destination is unsafe")
        if path.is_symlink():
            raise StoreError("state destination is unsafe")
        if windows_security.is_windows():
            windows_security.reject_reparse_points(path)
            if path.exists():
                windows_security.assert_private_file(path)
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = self.updates / f".{path.name}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                if not windows_security.is_windows():
                    os.fchmod(output.fileno(), 0o600)
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            if windows_security.is_windows():
                windows_security.assert_private_file(path)
            else:
                path.chmod(0o600)
            if os.name == "posix":
                directory = os.open(self.updates, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def read_install(self) -> dict:
        self._validate_root()
        if not self.install_path.exists():
            return default_install_state()
        if self.install_path.is_symlink() or not self.install_path.is_file():
            raise StoreError("install state path is unsafe")
        if windows_security.is_windows():
            windows_security.assert_private_file(self.install_path)
        try:
            descriptor = os.open(
                self.install_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as source:
                details = os.fstat(source.fileno())
                if not stat.S_ISREG(details.st_mode) or not 1 <= details.st_size <= 64 * 1024:
                    raise StoreError("install state size is invalid")
                data = source.read(64 * 1024 + 1)
        except OSError as error:
            raise StoreError("install state cannot be read") from error
        if not 1 <= len(data) <= 64 * 1024:
            raise StoreError("install state size is invalid")
        return validate_install_state(_json_bytes(data))

    def write_install(self, state: dict) -> None:
        self._atomic_json(self.install_path, validate_install_state(state))

    def write_channel(self, value: dict) -> None:
        self._atomic_json(self.channel_path, value)

    def stage(self, version: str, archive: ValidatedArchive) -> Path:
        if type(version) is not str or VERSION_RE.fullmatch(version) is None:
            raise StoreError("release version is invalid")
        if not isinstance(archive, ValidatedArchive):
            raise StoreError("release archive was not validated")
        self.ensure_layout()
        target = self.releases / version
        if windows_security.is_windows():
            windows_security.reject_reparse_points(target)
        if target.exists() or target.is_symlink():
            if self._release_matches(target, archive):
                return target
            raise StoreError("release destination conflicts with existing data")
        work = self.temporary / f"stage-{version}-{uuid.uuid4().hex}"
        try:
            work.mkdir(mode=0o700)
            (work / OWNED_MARKER).write_bytes(OWNED_MARKER_BYTES)
            if not windows_security.is_windows():
                (work / OWNED_MARKER).chmod(0o600)
            for item in archive.files:
                relative = _safe_relative(item.path.as_posix())
                destination = work.joinpath(*relative.parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                cursor = destination.parent
                while cursor != work:
                    if cursor.is_symlink() or not cursor.is_dir():
                        raise StoreError("staging destination is unsafe")
                    cursor = cursor.parent
                with destination.open("xb") as output:
                    output.write(item.data)
                mode = item.mode & 0o755
                if not windows_security.is_windows():
                    destination.chmod(mode or 0o600)
            digest_file = work / ARTIFACT_DIGEST
            digest_file.write_text(archive.sha256 + "\n")
            if not windows_security.is_windows():
                digest_file.chmod(0o600)
            os.replace(work, target)
            return target
        except BaseException:
            self._remove_owned(work, self.temporary)
            raise

    def _owned_directory(self, path: Path, parent: Path) -> bool:
        if path.parent != parent or path.is_symlink() or not path.is_dir():
            return False
        marker = path / OWNED_MARKER
        if marker.is_symlink() or not marker.is_file():
            return False
        try:
            if windows_security.is_windows():
                windows_security.assert_private_directory(path)
                windows_security.assert_private_file(marker)
            return marker.read_bytes() == OWNED_MARKER_BYTES
        except (OSError, ValueError):
            return False

    def _release_matches(self, target: Path, archive: ValidatedArchive) -> bool:
        if not self._owned_directory(target, self.releases):
            return False
        digest_file = target / ARTIFACT_DIGEST
        try:
            if (
                digest_file.is_symlink()
                or not digest_file.is_file()
                or digest_file.read_text().strip() != archive.sha256
            ):
                return False
            for item in archive.files:
                relative = _safe_relative(item.path.as_posix())
                source = target.joinpath(*relative.parts)
                if windows_security.is_windows():
                    windows_security.assert_private_file(source)
                if source.is_symlink() or not source.is_file():
                    return False
                cursor = source.parent
                while cursor != target:
                    if cursor.is_symlink() or not cursor.is_dir():
                        return False
                    cursor = cursor.parent
                if source.stat().st_size != len(item.data):
                    return False
                if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(item.data).digest():
                    return False
                expected_executable = bool(item.mode & 0o111)
                if not windows_security.is_windows() and bool(source.stat().st_mode & 0o111) != expected_executable:
                    return False
        except (OSError, ValueError):
            return False
        return True

    def _remove_owned(self, path: Path, parent: Path) -> bool:
        if not self._owned_directory(path, parent):
            return False
        if windows_security.is_windows():
            # Keep the ownership marker until every other child is gone. Windows
            # can refuse deletion of a loaded image; losing the marker first
            # would make that safe deferred cleanup permanently unrecoverable.
            try:
                for directory, directories, files in os.walk(path, followlinks=False):
                    for name in (*directories, *files):
                        windows_security.reject_reparse_points(Path(directory) / name)
                for entry in path.iterdir():
                    if entry.name == OWNED_MARKER:
                        continue
                    if entry.is_dir():
                        shutil.rmtree(entry)
                    else:
                        entry.unlink()
                marker = path / OWNED_MARKER
                marker.unlink()
                try:
                    path.rmdir()
                except OSError:
                    # A late sharing failure must still leave an owned retry.
                    with marker.open("xb") as output:
                        output.write(OWNED_MARKER_BYTES)
                    return False
            except (OSError, ValueError):
                return False
        else:
            shutil.rmtree(path)
        return True

    def remove_release(self, version: str) -> bool:
        if type(version) is not str or VERSION_RE.fullmatch(version) is None:
            return False
        return self._remove_owned(self.releases / version, self.releases)

    def cleanup(self, *, active: str | None, previous: str | None, now: datetime) -> dict[str, int]:
        self.ensure_layout()
        if now.tzinfo is None:
            raise StoreError("cleanup time must be timezone-aware")
        counts = {"releases": 0, "temporary": 0}
        keep = {value for value in (active, previous) if value is not None}
        for entry in tuple(self.releases.iterdir()):
            if (
                entry.name in keep
                or entry.is_symlink()
                or VERSION_RE.fullmatch(entry.name) is None
            ):
                continue
            if self._remove_owned(entry, self.releases):
                counts["releases"] += 1
            elif windows_security.is_windows() and self._owned_directory(entry, self.releases):
                counts["deferred"] = counts.get("deferred", 0) + 1
        cutoff = now.astimezone(timezone.utc).timestamp() - STALE_TEMP_SECONDS
        for entry in tuple(self.temporary.iterdir()):
            if (
                entry.is_symlink()
                or not entry.is_dir()
                or re.fullmatch(r"stage-(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[0-9a-f]{32}", entry.name) is None
            ):
                continue
            try:
                stale = entry.stat(follow_symlinks=False).st_mtime < cutoff
            except OSError:
                continue
            if stale and self._remove_owned(entry, self.temporary):
                counts["temporary"] += 1
            elif stale and windows_security.is_windows() and self._owned_directory(entry, self.temporary):
                counts["deferred"] = counts.get("deferred", 0) + 1
        return counts

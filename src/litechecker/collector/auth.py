"""Strict local agent registry and constant-time bearer authentication."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from litechecker.security import is_valid_agent_id, is_valid_agent_token


_MAX_REGISTRY_BYTES = 1_048_576
_MAX_AGENTS = 1_000
_MAX_LABEL_LENGTH = 128
_MAX_EXPECTED_INTERVAL = 86_400


class RegistryError(ValueError):
    """Registry input is unsafe or malformed; messages never contain its values."""


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    city: str
    name: str
    expected_interval_seconds: int


@dataclass(frozen=True, repr=False)
class _RegistryRecord:
    digest: bytes
    identity: AgentIdentity


class AgentRegistry:
    """An immutable registry retaining token digests rather than plaintext tokens."""

    def __init__(self, records: tuple[_RegistryRecord, ...]):
        if not records:
            raise RegistryError("registry must contain at least one agent")
        self._records = records
        self._by_id: Mapping[str, AgentIdentity] = MappingProxyType(
            {record.identity.agent_id: record.identity for record in records}
        )

    @classmethod
    def load(cls, path: str | Path) -> "AgentRegistry":
        registry_path = Path(path)
        flags = os.O_RDONLY
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        has_no_follow = hasattr(os, "O_NOFOLLOW")
        if has_no_follow:
            flags |= os.O_NOFOLLOW
        before = None
        if not has_no_follow:
            try:
                before = registry_path.lstat()
            except OSError as exc:
                raise RegistryError("cannot read registry") from exc
        try:
            descriptor = os.open(registry_path, flags)
        except OSError as exc:
            raise RegistryError("cannot read registry") from exc
        try:
            metadata = os.fstat(descriptor)
            _validate_open_file(metadata)
            if not has_no_follow:
                try:
                    after = registry_path.lstat()
                except OSError as exc:
                    raise RegistryError("registry changed while opening") from exc
                if (
                    before is None
                    or stat.S_ISLNK(before.st_mode)
                    or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
                    or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    raise RegistryError("registry changed while opening")
            raw = _read_descriptor(descriptor, metadata.st_size)
        finally:
            os.close(descriptor)
        try:
            payload = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_unique_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistryError("registry is invalid JSON") from exc
        return cls(_parse_registry(payload))

    @property
    def identities(self) -> tuple[AgentIdentity, ...]:
        return tuple(record.identity for record in self._records)

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._by_id.get(agent_id)

    def authenticate(self, token: object) -> AgentIdentity | None:
        """Compare fixed-length digests for every agent, including failed attempts."""
        candidate = token if isinstance(token, str) else ""
        candidate_digest = hashlib.sha256(candidate.encode("utf-8", "replace")).digest()
        matched: AgentIdentity | None = None
        for record in self._records:
            if hmac.compare_digest(candidate_digest, record.digest):
                matched = record.identity
        return matched


def _parse_registry(payload: Any) -> tuple[_RegistryRecord, ...]:
    if not isinstance(payload, dict) or not payload or len(payload) > _MAX_AGENTS:
        raise RegistryError("registry must be a non-empty object")
    records: list[_RegistryRecord] = []
    digests: set[bytes] = set()
    required = {"token", "city", "name", "expected_interval_seconds"}
    for agent_id, entry in payload.items():
        if not is_valid_agent_id(agent_id):
            raise RegistryError("agent id is invalid")
        if not isinstance(entry, dict) or set(entry) != required:
            raise RegistryError("registry entry fields are invalid")
        token = entry["token"]
        if not is_valid_agent_token(token):
            raise RegistryError("agent token is invalid")
        city = _safe_label(entry["city"])
        name = _safe_label(entry["name"])
        interval = entry["expected_interval_seconds"]
        if (
            not isinstance(interval, int)
            or isinstance(interval, bool)
            or not 1 <= interval <= _MAX_EXPECTED_INTERVAL
        ):
            raise RegistryError("expected interval is invalid")
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        if digest in digests:
            raise RegistryError("duplicate token")
        digests.add(digest)
        records.append(
            _RegistryRecord(
                digest=digest,
                identity=AgentIdentity(agent_id, city, name, interval),
            )
        )
    records.sort(key=lambda record: record.identity.agent_id)
    return tuple(records)


def _validate_open_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise RegistryError("registry must be a regular file")
    if os.name == "posix":
        if metadata.st_mode & 0o077:
            raise RegistryError("registry permissions must be 0600")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise RegistryError("registry owner is invalid")
    if metadata.st_size < 2 or metadata.st_size > _MAX_REGISTRY_BYTES:
        raise RegistryError("registry size is invalid")


def _read_descriptor(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65_536))
        if not chunk:
            raise RegistryError("registry changed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise RegistryError("registry changed while reading")
    return b"".join(chunks)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("registry contains duplicate keys")
        result[key] = value
    return result


def _safe_label(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_LABEL_LENGTH
        or value != value.strip()
        or any(not character.isprintable() for character in value)
    ):
        raise RegistryError("display metadata is invalid")
    return value

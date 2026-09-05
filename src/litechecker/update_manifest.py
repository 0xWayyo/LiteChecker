"""Strict parsing and Ed25519 verification for LiteChecker release metadata."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_METADATA_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_URLS = 3
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    """The local channel or remote signed metadata violates the protocol."""


@dataclass(frozen=True)
class Artifact:
    urls: tuple[str, ...]
    sha256: str
    size: int


@dataclass(frozen=True)
class ReleaseMetadata:
    version: str
    sequence: int
    published_at: datetime
    artifact: Artifact
    payload: Mapping[str, object]


@dataclass(frozen=True)
class ChannelConfig:
    enabled: bool
    public_key: bytes
    manifest_urls: tuple[str, ...]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate JSON field")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ManifestError("non-finite JSON number")


def _json(data: bytes, *, limit: int) -> Any:
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise ManifestError("JSON document size is invalid")
    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
    except ManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ManifestError("JSON document is invalid") from error


def _exact_dict(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ManifestError(f"{name} fields are invalid")
    return value


def _https_url(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise ManifestError("URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ManifestError("URL is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path
        or port is not None and not 1 <= port <= 65535
    ):
        raise ManifestError("URL must be a credential-free HTTPS URL")
    return value


def _urls(value: Any) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAX_URLS:
        raise ManifestError("URL list is invalid")
    urls = tuple(_https_url(item) for item in value)
    if len(set(urls)) != len(urls):
        raise ManifestError("URL list contains duplicates")
    return urls


def canonical_payload(payload: Mapping[str, object]) -> bytes:
    """Return the exact bytes covered by the protocol signature."""

    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ManifestError("payload cannot be canonicalized") from error


def _decode_b64(value: Any, size: int, name: str) -> bytes:
    if type(value) is not str:
        raise ManifestError(f"{name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ManifestError(f"{name} is invalid") from error
    if len(decoded) != size:
        raise ManifestError(f"{name} has invalid length")
    return decoded


def parse_version(version: str) -> tuple[int, int, int]:
    if type(version) is not str or VERSION_RE.fullmatch(version) is None:
        raise ManifestError("version is invalid")
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


def verify_release_metadata(data: bytes, public_key: bytes) -> ReleaseMetadata:
    """Strictly parse and authenticate a signed release envelope."""

    envelope = _exact_dict(
        _json(data, limit=MAX_METADATA_BYTES),
        {"schema", "payload", "signature"},
        "envelope",
    )
    if type(envelope["schema"]) is not int or envelope["schema"] != 1:
        raise ManifestError("envelope schema is unsupported")
    payload = _exact_dict(
        envelope["payload"],
        {"version", "sequence", "published_at", "artifact"},
        "payload",
    )
    parse_version(payload["version"])
    sequence = payload["sequence"]
    if type(sequence) is not int or sequence < 1:
        raise ManifestError("sequence is invalid")
    published_text = payload["published_at"]
    if type(published_text) is not str:
        raise ManifestError("published_at is invalid")
    try:
        published_at = datetime.strptime(published_text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ManifestError("published_at is invalid") from error
    artifact_value = _exact_dict(
        payload["artifact"], {"urls", "sha256", "size"}, "artifact"
    )
    urls = _urls(artifact_value["urls"])
    digest = artifact_value["sha256"]
    if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
        raise ManifestError("artifact digest is invalid")
    size = artifact_value["size"]
    if type(size) is not int or not 1 <= size <= MAX_ARCHIVE_BYTES:
        raise ManifestError("artifact size is invalid")
    signature = _decode_b64(envelope["signature"], 64, "signature")
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ManifestError("public key has invalid length")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_payload(payload)
        )
    except (ValueError, InvalidSignature) as error:
        raise ManifestError("release signature is invalid") from error
    artifact = Artifact(urls=urls, sha256=digest, size=size)
    stable_payload: Mapping[str, object] = {
        "version": payload["version"],
        "sequence": sequence,
        "published_at": published_text,
        "artifact": {
            "urls": list(urls),
            "sha256": digest,
            "size": size,
        },
    }
    return ReleaseMetadata(
        version=payload["version"],
        sequence=sequence,
        published_at=published_at,
        artifact=artifact,
        payload=stable_payload,
    )


def parse_channel_config(data: bytes) -> ChannelConfig:
    """Strictly parse a locally provisioned update channel."""

    document = _exact_dict(
        _json(data, limit=MAX_METADATA_BYTES),
        {"schema", "enabled", "public_key", "manifest_urls"},
        "channel",
    )
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise ManifestError("channel schema is unsupported")
    if type(document["enabled"]) is not bool:
        raise ManifestError("channel enabled flag is invalid")
    return ChannelConfig(
        enabled=document["enabled"],
        public_key=_decode_b64(document["public_key"], 32, "public key"),
        manifest_urls=_urls(document["manifest_urls"]),
    )

"""Security primitives for safe target handling, logging, and stable identities."""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from collections.abc import Mapping
from typing import Any


_URL_RE = re.compile(r"\b(?:https?|vless)://[^\s\"'<>]+", re.IGNORECASE)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\b(bearer)\s+[^\s,;]+", re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(
    r"(?P<prefix>(?:[\"']?(?:token|access_?token|authorization|password|private_?key|"
    r"public_?key|short_?id|pbk|sid|uuid)[\"']?\s*(?:=|:)\s*)[\"']?)(?P<value>[^\s,;\"'}]+)",
    re.IGNORECASE,
)
_MAX_REDACTED_LENGTH = 512
_AGENT_TOKEN_RE = re.compile(r"lc_[A-Za-z0-9_-]{43}\Z", re.ASCII)
_AGENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_DNS_LABEL_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII
)


def is_valid_agent_id(value: object) -> bool:
    """Match the exact identity grammar shared by agents and the registry."""
    return isinstance(value, str) and _AGENT_ID_RE.fullmatch(value) is not None


def is_valid_agent_token(value: object) -> bool:
    """Validate ``'lc_' + secrets.token_urlsafe(32)`` style bearer tokens."""
    if not isinstance(value, str) or _AGENT_TOKEN_RE.fullmatch(value) is None:
        return False
    return len(set(value[3:])) >= 8


def generate_agent_token() -> str:
    """Generate a header-safe agent bearer from 256 bits of OS randomness."""
    token = f"lc_{secrets.token_urlsafe(32)}"
    if not is_valid_agent_token(token):  # Defensive against a substituted RNG.
        raise RuntimeError("agent-token-generation-failed")
    return token


def canonical_host(value: str) -> str:
    """Canonicalize an IP literal or an IDNA domain for stable matching."""
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("host is invalid")
    host = value
    bracketed = host.startswith("[") or host.endswith("]")
    if bracketed:
        if not (host.startswith("[") and host.endswith("]")):
            raise ValueError("host is invalid")
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if bracketed:
            raise ValueError("brackets require an IP literal") from None
    try:
        normalized = host.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("host is invalid") from None
    if (
        not normalized
        or len(normalized) > 253
        or normalized.replace(".", "").isdigit()
    ):
        raise ValueError("host is invalid")
    labels = normalized.split(".")
    if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise ValueError("host is invalid")
    return normalized


def is_forbidden_ip(
    value: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = False,
) -> bool:
    """Reject every non-global destination unless a controlled lab opts in."""
    if allow_private:
        return False
    address = ipaddress.ip_address(value)
    return (
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
    )


def redact(value: object) -> str:
    """Produce a bounded, single-line diagnostic with reusable values removed."""
    text = re.sub(r"\s+", " ", str(value)).strip()
    text = _URL_RE.sub("[URL REDACTED]", text)
    text = _BEARER_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = _UUID_RE.sub("[UUID REDACTED]", text)
    text = _SECRET_VALUE_RE.sub(lambda match: f"{match.group('prefix')}[REDACTED]", text)
    if len(text) > _MAX_REDACTED_LENGTH:
        return f"{text[: _MAX_REDACTED_LENGTH - 3]}..."
    return text


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def target_id(
    *,
    protocol: str,
    address: str,
    port: int,
    transport: str | None = None,
    security: str | None = None,
    flow: str | None = None,
) -> str:
    """Hash only the canonical non-secret connection identity."""
    identity = {
        "protocol": protocol.lower(),
        "address": canonical_host(address),
        "port": int(port),
        "transport": (transport or "").lower(),
        "security": (security or "").lower(),
        "flow": (flow or "").lower(),
    }
    return hashlib.sha256(_canonical_json(identity)).hexdigest()


def config_fingerprint(config: Mapping[str, Any], state_key: str | bytes) -> str:
    """HMAC full local probe material without exposing a reusable configuration hash."""
    key = state_key.encode("utf-8") if isinstance(state_key, str) else state_key
    return hmac.new(key, _canonical_json(config), hashlib.sha256).hexdigest()

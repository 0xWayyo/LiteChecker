"""Safe extraction of probe targets from Xray subscription JSON."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from litechecker.models import TargetConfig
from litechecker.security import canonical_host, config_fingerprint, redact, target_id


_MAX_LABEL_LENGTH = 128
_OUTBOUND_FIELDS = frozenset(
    {"protocol", "tag", "settings", "streamSettings", "mux"}
)
_SETTINGS_FIELDS = frozenset({"vnext"})
_SERVER_FIELDS = frozenset({"address", "port", "users"})
_USER_FIELDS = frozenset({"id", "flow", "encryption", "level"})
_STREAM_FIELDS = frozenset(
    {"network", "security", "realitySettings", "tcpSettings"}
)
_MUX_FIELDS = frozenset({"enabled", "concurrency"})
_TCP_FIELDS = frozenset({"header"})
_TCP_HEADER_FIELDS = frozenset({"type"})
_REALITY_FIELDS = frozenset(
    {
        "serverName",
        "fingerprint",
        "show",
        "publicKey",
        "shortId",
        "spiderX",
        "mldsa65Verify",
        "allowInsecure",
    }
)


class SubscriptionError(ValueError):
    """Raised when a subscription cannot safely replace the active snapshot."""


def parse_xray_subscription(
    payload: bytes, state_key: str | bytes, max_endpoints: int
) -> list[TargetConfig]:
    """Extract VPN endpoints and unique SNI hosts without source routing rules."""
    if max_endpoints < 1:
        raise SubscriptionError("endpoint limit must be positive")

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SubscriptionError("subscription is not valid UTF-8 JSON") from exc

    candidates: dict[str, list[_Candidate]] = {}
    visited = 0
    for profile in _profiles(document):
        outbounds = profile.get("outbounds")
        if not isinstance(outbounds, list):
            raise SubscriptionError("invalid VLESS subscription")
        profile_label = _label(profile)
        for outbound in outbounds:
            if not isinstance(outbound, Mapping):
                raise SubscriptionError("invalid VLESS subscription")
            if outbound.get("protocol") != "vless":
                continue
            _validate_fields(outbound, _OUTBOUND_FIELDS)
            _validate_disabled_mux(outbound.get("mux"))
            settings = outbound.get("settings")
            if not isinstance(settings, Mapping):
                raise SubscriptionError("invalid VLESS subscription")
            _validate_fields(settings, _SETTINGS_FIELDS)
            vnext = settings.get("vnext")
            if not isinstance(vnext, list) or not vnext:
                raise SubscriptionError("invalid VLESS subscription")
            stream_settings = _minimal_stream_settings(outbound.get("streamSettings"))
            for server in vnext:
                visited += 1
                if visited > max_endpoints:
                    raise SubscriptionError("endpoint limit exceeded")
                candidate = _candidate_from_server(
                    server,
                    stream_settings=stream_settings,
                    profile_label=profile_label,
                )
                candidates.setdefault(candidate.identity, []).append(candidate)

    targets = _deduplicate(candidates, state_key)
    if not targets:
        raise SubscriptionError("no VLESS targets")
    return with_sni_targets(targets, state_key, max_endpoints)


def with_sni_targets(
    targets: Iterable[TargetConfig], state_key: str | bytes, max_endpoints: int
) -> list[TargetConfig]:
    """Also expand older snapshots; SNI origin checks use their own identity."""
    vpn_targets = [target for target in targets if target.check_kind == "vpn"]
    hosts: set[str] = set()
    for target in vpn_targets:
        stream = target.outbound.get("streamSettings", {})
        reality = stream.get("realitySettings", {})
        server_name = reality.get("serverName")
        if server_name:
            try:
                hosts.add(canonical_host(server_name))
            except (TypeError, ValueError) as exc:
                raise SubscriptionError("invalid SNI hostname") from exc
    if len(vpn_targets) + len(hosts) > max_endpoints:
        raise SubscriptionError("endpoint limit exceeded")
    sni_targets = []
    for host in sorted(hosts):
        identity = target_id(protocol="sni", address=host, port=443, security="tls")
        material = {"check_kind": "sni", "address": host, "port": 443}
        sni_targets.append(TargetConfig(
            target_id=identity,
            config_fingerprint=config_fingerprint(material, state_key),
            label=host,
            address=host,
            port=443,
            address_kind=_address_kind(host),
            outbound={},
            check_kind="sni",
        ))
    return vpn_targets + sni_targets


def _profiles(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, list):
        profiles = document
    elif isinstance(document, Mapping):
        profiles = document.get("profiles", [document])
    else:
        raise SubscriptionError("subscription root must contain profiles")
    if not isinstance(profiles, list):
        raise SubscriptionError("subscription profiles must be a list")
    if not all(isinstance(profile, Mapping) for profile in profiles):
        raise SubscriptionError("invalid VLESS subscription")
    return profiles


def _label(profile: Mapping[str, Any]) -> str:
    for key in ("remarks", "remark", "name", "tag"):
        value = profile.get(key)
        if isinstance(value, str) and value.strip():
            return _sanitize_label(value)
    return "VLESS endpoint"


def _candidate_from_server(
    server: Any,
    *,
    stream_settings: dict[str, Any] | None,
    profile_label: str,
) -> "_Candidate":
    if not isinstance(server, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(server, _SERVER_FIELDS)
    address = server.get("address")
    port = server.get("port")
    if not isinstance(address, str) or not address.strip() or type(port) is not int:
        raise SubscriptionError("invalid VLESS subscription")
    users = server.get("users")
    if not isinstance(users, list) or not users:
        raise SubscriptionError("invalid VLESS subscription")
    normalized_users = [_minimal_user(user) for user in users]
    try:
        canonical_address = canonical_host(address)
    except ValueError as exc:
        raise SubscriptionError("invalid VLESS subscription") from exc
    if not 1 <= port <= 65_535:
        raise SubscriptionError("invalid VLESS subscription")

    normalized: dict[str, Any] = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": canonical_address,
                    "port": port,
                    "users": normalized_users,
                }
            ]
        },
    }
    if stream_settings is not None:
        normalized["streamSettings"] = stream_settings
    first_user = normalized_users[0]
    identity = target_id(
        protocol="vless",
        address=canonical_address,
        port=port,
        transport=_string_field(stream_settings or {}, "network"),
        security=_string_field(stream_settings or {}, "security"),
        flow=_string_field(first_user, "flow"),
    )
    return _Candidate(
        identity=identity,
        label=profile_label,
        outbound=normalized,
        address=canonical_address,
        port=port,
        address_kind=_address_kind(canonical_address),
    )


def _minimal_user(user: Any) -> dict[str, Any]:
    if not isinstance(user, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(user, _USER_FIELDS)
    user_id = user.get("id")
    if not isinstance(user_id, str) or not user_id.strip():
        raise SubscriptionError("invalid VLESS subscription")
    normalized: dict[str, Any] = {"id": user_id}
    for key in ("flow", "encryption"):
        value = user.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise SubscriptionError("invalid VLESS subscription")
            normalized[key] = value
    level = user.get("level")
    if level is not None:
        if type(level) is not int or level < 0:
            raise SubscriptionError("invalid VLESS subscription")
        normalized["level"] = level
    return normalized


def _minimal_stream_settings(value: Any) -> dict[str, Any] | None:
    if value is None:
        raise SubscriptionError("invalid VLESS subscription")
    if not isinstance(value, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(value, _STREAM_FIELDS)
    if value.get("network") != "tcp" or value.get("security") != "reality":
        raise SubscriptionError("unsupported VLESS configuration")
    normalized: dict[str, Any] = {}
    for key in ("network", "security"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str):
                raise SubscriptionError("invalid VLESS subscription")
            normalized[key] = item
    tcp_settings = _minimal_tcp_settings(value.get("tcpSettings"))
    if tcp_settings is not None:
        normalized["tcpSettings"] = tcp_settings
    reality = value.get("realitySettings")
    if not isinstance(reality, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(reality, _REALITY_FIELDS)
    if not isinstance(reality.get("publicKey"), str) or not reality["publicKey"]:
        raise SubscriptionError("invalid VLESS subscription")
    if not isinstance(reality.get("serverName"), str) or not reality["serverName"]:
        raise SubscriptionError("invalid VLESS subscription")
    try:
        canonical_host(reality["serverName"])
    except ValueError as exc:
        raise SubscriptionError("invalid SNI hostname") from exc
    normalized_reality: dict[str, Any] = {}
    for key, item in reality.items():
        expected = bool if key in {"show", "allowInsecure"} else str
        if type(item) is not expected:
            raise SubscriptionError("invalid VLESS subscription")
        if key == "allowInsecure" and item is not False:
            raise SubscriptionError("unsupported VLESS configuration")
        normalized_reality[key] = item
    normalized["realitySettings"] = normalized_reality
    return normalized


def _validate_disabled_mux(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(value, _MUX_FIELDS)
    if value.get("enabled") is not False:
        raise SubscriptionError("unsupported VLESS configuration")
    concurrency = value.get("concurrency")
    if concurrency is not None and (
        type(concurrency) is not int or not -1 <= concurrency <= 1024
    ):
        raise SubscriptionError("invalid VLESS subscription")


def _minimal_tcp_settings(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(value, _TCP_FIELDS)
    header = value.get("header")
    if not isinstance(header, Mapping):
        raise SubscriptionError("invalid VLESS subscription")
    _validate_fields(header, _TCP_HEADER_FIELDS)
    if header.get("type") != "none":
        raise SubscriptionError("unsupported VLESS configuration")
    return {"header": {"type": "none"}}


def _validate_fields(value: Mapping[str, Any], allowed: frozenset[str]) -> None:
    if not set(value).issubset(allowed):
        raise SubscriptionError("unsupported VLESS configuration")


def _deduplicate(
    candidates: Mapping[str, list["_Candidate"]],
    state_key: str | bytes,
) -> list[TargetConfig]:
    targets: list[TargetConfig] = []
    for identity in sorted(candidates):
        group = candidates[identity]
        if len({_outbound_key(candidate.outbound) for candidate in group}) != 1:
            raise SubscriptionError("conflicting VLESS target configurations")
        selected = group[0]
        fingerprint_material = {
            "address": selected.address,
            "port": selected.port,
            "address_kind": selected.address_kind,
            "outbound": selected.outbound,
        }
        targets.append(
            TargetConfig(
                target_id=identity,
                config_fingerprint=config_fingerprint(fingerprint_material, state_key),
                label=_merge_labels(candidate.label for candidate in group),
                address=selected.address,
                port=selected.port,
                address_kind=selected.address_kind,
                outbound=selected.outbound,
            )
        )
    return sorted(targets, key=lambda target: (target.address, target.port, target.target_id))


def _outbound_key(outbound: Mapping[str, Any]) -> str:
    return json.dumps(outbound, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _string_field(value: Mapping[str, Any], key: str) -> str | None:
    candidate = value.get(key)
    return candidate if isinstance(candidate, str) else None


def _address_kind(address: str) -> str:
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return "domain"
    return "ip"


@dataclass(frozen=True)
class _Candidate:
    identity: str
    label: str
    outbound: dict[str, Any]
    address: str
    port: int
    address_kind: str


def _merge_labels(labels: Iterable[str]) -> str:
    return _sanitize_label(" | ".join(sorted(set(labels))))


def _sanitize_label(value: str) -> str:
    cleaned = "".join(character if character.isprintable() else " " for character in redact(value))
    cleaned = " ".join(cleaned.split())
    return cleaned[:_MAX_LABEL_LENGTH].rstrip() or "VLESS endpoint"

"""Best-effort network metadata for the current public egress IP."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from dataclasses import dataclass

import httpx


_LOOKUP_URL = "https://ipinfo.io/json"
_LOOKUP_TIMEOUT_SECONDS = 3.0
_MAX_RESPONSE_BYTES = 8192
_MAX_PROVIDER_LENGTH = 40
_MAX_CITY_LENGTH = 112


@dataclass(frozen=True)
class NetworkIdentity:
    provider: str | None = None
    city: str | None = None
    country: str | None = None


async def lookup_network_identity(
    *, transport: httpx.AsyncBaseTransport | None = None,
) -> NetworkIdentity | None:
    """Resolve IPinfo metadata without sending device data or retaining a stale cache.

    IP attribution describes the public exit network, which may be a VPN or
    hosting provider. Failures leave the configured fallback name and city intact.
    """
    try:
        async with asyncio.timeout(_LOOKUP_TIMEOUT_SECONDS):
            async with httpx.AsyncClient(
                timeout=_LOOKUP_TIMEOUT_SECONDS,
                transport=transport,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    "GET", _LOOKUP_URL,
                    headers={"Accept-Encoding": "identity", "Accept": "application/json"},
                ) as response:
                    if response.status_code != 200:
                        return None
                    body = await _read_bounded(response)
                    if body is None:
                        return None
                    payload = json.loads(body.decode("utf-8"))
                    if (
                        not isinstance(payload, dict)
                        or "error" in payload
                        or payload.get("bogon", False) is not False
                    ):
                        return None
                    public_ip = payload.get("ip")
                    if (
                        not isinstance(public_ip, str)
                        or len(public_ip) > 45
                        or "%" in public_ip
                    ):
                        return None
                    address = ipaddress.ip_address(public_ip)
                    if not address.is_global or address.is_multicast:
                        return None
                    provider = _safe_label(payload.get("org"), _MAX_PROVIDER_LENGTH)
                    city = _safe_label(payload.get("city"), _MAX_CITY_LENGTH)
                    if provider is None and city is None:
                        return None
                    return NetworkIdentity(
                        provider=provider,
                        city=city,
                        country=_country_code(payload.get("country")),
                    )
    except asyncio.CancelledError:
        raise
    except Exception:
        return None


def network_display_name(base_name: str, provider: str | None) -> str:
    """Identify IP attribution explicitly and fit the registry's 128-char limit."""
    label = _safe_label(provider, _MAX_PROVIDER_LENGTH)
    if label is None:
        return base_name
    return f"{base_name[:64]} · сеть по IP: {label}"


def network_display_city(base_city: str, identity: NetworkIdentity | None) -> str:
    """Label approximate IP geolocation, preserving the fallback if unavailable."""
    city = _safe_label(identity.city, _MAX_CITY_LENGTH) if identity else None
    if city is None:
        return base_city
    country = _country_code(identity.country)
    location = f"{city}, {country}" if country else city
    return f"{location} (по IP)"


def _country_code(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[A-Z]{2}", value):
        return value
    return None


def _safe_label(value: object, max_length: int) -> str | None:
    if (
        not isinstance(value, str)
        or len(value) > 256
        or not value.isprintable()
    ):
        return None
    label = value.strip()
    if (
        not any(character.isalnum() for character in label)
        or label.casefold() in {"unknown", "n/a", "none", "null"}
    ):
        return None
    if len(label) > max_length:
        return label[:max_length - 1] + "…"
    return label


async def _read_bounded(response: httpx.Response) -> bytes | None:
    encodings = [
        value.strip().lower()
        for value in response.headers.get_list("content-encoding", split_commas=True)
    ]
    if encodings and encodings != ["identity"]:
        return None
    lengths = response.headers.get_list("content-length")
    if lengths and (
        len(lengths) != 1
        or re.fullmatch(r"[0-9]+", lengths[0]) is None
        or int(lengths[0]) > _MAX_RESPONSE_BYTES
    ):
        return None
    if response.is_stream_consumed:
        return response.content if len(response.content) <= _MAX_RESPONSE_BYTES else None
    body = bytearray()
    async for chunk in response.aiter_raw():
        if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
            return None
        body.extend(chunk)
    return bytes(body)

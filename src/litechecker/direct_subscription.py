"""Trial-only parsing of independently checked VLESS configuration variants."""

from __future__ import annotations

import json
from collections.abc import Mapping

from litechecker.models import TargetConfig
from litechecker.subscription import (
    SubscriptionError,
    _label,
    parse_xray_subscription,
    with_sni_targets,
)


def parse_trial_subscription(
    payload: bytes, state_key: str | bytes, max_endpoints: int,
) -> list[TargetConfig]:
    """Validate every server with the strict parser, then retain distinct variants.

    Every VPN identity includes its complete device-keyed HMAC fingerprint. An
    additional variant therefore cannot rename an already known configuration.
    This function is only for an explicit experimental trial, not the monitor's
    authoritative subscription snapshot.
    """
    if type(max_endpoints) is not int or max_endpoints < 1:
        raise SubscriptionError("endpoint limit must be positive")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SubscriptionError("subscription is not valid UTF-8 JSON") from exc
    if isinstance(document, list):
        profiles = document
    elif isinstance(document, Mapping):
        profiles = document.get("profiles", [document])
    else:
        raise SubscriptionError("subscription root must contain profiles")
    if not isinstance(profiles, list):
        raise SubscriptionError("subscription profiles must be a list")

    variants: dict[str, TargetConfig] = {}
    visited = 0
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise SubscriptionError("invalid VLESS subscription")
        outbounds = profile.get("outbounds")
        if not isinstance(outbounds, list):
            raise SubscriptionError("invalid VLESS subscription")
        labels = {"remarks": _label(profile)}
        for outbound in outbounds:
            if not isinstance(outbound, Mapping):
                raise SubscriptionError("invalid VLESS subscription")
            if outbound.get("protocol") != "vless":
                continue
            settings = outbound.get("settings")
            if not isinstance(settings, Mapping):
                raise SubscriptionError("invalid VLESS subscription")
            servers = settings.get("vnext")
            if not isinstance(servers, list) or not servers:
                raise SubscriptionError("invalid VLESS subscription")
            for server in servers:
                visited += 1
                if visited > max_endpoints:
                    raise SubscriptionError("endpoint limit exceeded")
                # Keep all outbound fields for validation. Profile DNS, routing,
                # and logs are never used by the strict parser or the trial.
                single = {
                    **labels,
                    "outbounds": [{
                        **outbound,
                        "settings": {**settings, "vnext": [server]},
                    }],
                }
                validated = parse_xray_subscription(
                    json.dumps({"profiles": [single]}, ensure_ascii=True).encode("utf-8"),
                    state_key,
                    # One VPN plus its SNI; the trial's combined cap is below.
                    max_endpoints=2,
                )
                target = next(item for item in validated if item.check_kind == "vpn")
                identity = f"{target.target_id}:{target.config_fingerprint}"
                existing = variants.get(identity)
                if existing is None or target.label < existing.label:
                    variants[identity] = target.model_copy(update={"target_id": identity})
    if not variants:
        raise SubscriptionError("no VLESS targets")
    targets = sorted(variants.values(), key=lambda item: (item.address, item.port, item.target_id))
    return with_sni_targets(targets, state_key, max_endpoints)

"""Trial-only configuration variants remain individually validated and counted."""

from __future__ import annotations

import copy
import json

import pytest

from litechecker.subscription import SubscriptionError, parse_xray_subscription


KEY = b"synthetic-device-test-key-32-bytes"


def profile(*, user="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sni="one.example", label="Example"):
    return {
        "remarks": label,
        "outbounds": [{
            "protocol": "vless",
            "tag": "original-proxy",
            "settings": {"vnext": [{
                "address": "8.8.8.8", "port": 443,
                "users": [{"id": user, "flow": "xtls-rprx-vision", "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {"serverName": sni, "publicKey": "synthetic-public-key", "shortId": "1234"},
            },
        }],
    }


def payload(document):
    return json.dumps(document).encode()


def test_trial_bounds_large_profile_labels_before_per_server_serialization(monkeypatch):
    from litechecker import direct_subscription
    document = profile(label="X" * 100_000)
    document["outbounds"][0]["settings"]["vnext"] *= 20
    encoded = payload([document])
    original = direct_subscription.json.dumps
    sizes = []
    def serialize(value, *args, **kwargs):
        result = original(value, *args, **kwargs)
        sizes.append(len(result))
        return result
    monkeypatch.setattr(direct_subscription.json, "dumps", serialize)
    targets = direct_subscription.parse_trial_subscription(encoded, KEY, 25)
    assert len(targets) == 2
    assert max(sizes) < 4096


@pytest.mark.parametrize("change", ["uuid", "sni"])
def test_trial_keeps_conflicting_endpoint_variants_with_independent_ids(change):
    from litechecker.direct_subscription import parse_trial_subscription

    first = profile(label="First")
    second = profile(
        user="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" if change == "uuid" else "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        sni="two.example" if change == "sni" else "one.example", label="Second",
    )
    with pytest.raises(SubscriptionError, match="conflicting"):
        parse_xray_subscription(payload([first, second]), KEY, 10)

    targets = parse_trial_subscription(payload([first, second]), KEY, 10)
    vpn = [target for target in targets if target.check_kind == "vpn"]
    assert len(vpn) == 2
    assert {target.label for target in vpn} == {"First", "Second"}
    assert len({target.target_id for target in vpn}) == 2
    assert {(target.address, target.port) for target in vpn} == {("8.8.8.8", 443)}
    expected = [parse_xray_subscription(payload([item]), KEY, 2)[0] for item in [first, second]]
    assert {target.config_fingerprint for target in vpn} == {target.config_fingerprint for target in expected}
    assert {target.target_id for target in vpn} == {
        f"{target.target_id}:{target.config_fingerprint}" for target in expected
    }
    assert {target.address for target in targets if target.check_kind == "sni"} == (
        {"one.example", "two.example"} if change == "sni" else {"one.example"}
    )


def test_trial_deduplicates_identical_configs_and_chooses_one_deterministic_label():
    from litechecker.direct_subscription import parse_trial_subscription

    targets = parse_trial_subscription(payload([profile(label="Zulu"), profile(label="Alpha")]), KEY, 4)
    assert len(targets) == 2
    assert targets[0].label == "Alpha"
    assert targets[0].check_kind == "vpn"
    assert targets[1].check_kind == "sni"


def test_trial_variant_identity_and_order_are_stable_when_profiles_are_reordered():
    from litechecker.direct_subscription import parse_trial_subscription

    profiles = [profile(label="Zulu"), profile(sni="two.example", label="Second"), profile(label="Alpha")]
    forward = parse_trial_subscription(payload({"profiles": profiles}), KEY, 8)
    backward = parse_trial_subscription(payload({"profiles": profiles[::-1]}), KEY, 8)
    assert forward == backward
    singleton = parse_trial_subscription(payload(profiles[1]), KEY, 8)[0]
    assert singleton.target_id in {item.target_id for item in forward}


def test_trial_splits_vnext_without_discarding_any_servers():
    from litechecker.direct_subscription import parse_trial_subscription

    source = profile()
    alternate = copy.deepcopy(source["outbounds"][0]["settings"]["vnext"][0])
    alternate["users"][0]["id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    source["outbounds"][0]["settings"]["vnext"].append(alternate)
    targets = parse_trial_subscription(payload([source]), KEY, 5)
    vpn = [item for item in targets if item.check_kind == "vpn"]
    assert len(vpn) == 2
    assert {item.outbound["settings"]["vnext"][0]["users"][0]["id"] for item in vpn} == {
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }


def test_trial_does_not_reserialize_unrelated_profile_metadata_per_server(monkeypatch):
    from litechecker import direct_subscription

    source = profile()
    source["routing"] = {"rules": ["irrelevant source routing " * 2048]}
    source["dns"] = {"hosts": {"unused.example": "irrelevant DNS metadata " * 2048}}
    source["log"] = {"access": "irrelevant source log " * 2048}
    server = source["outbounds"][0]["settings"]["vnext"][0]
    source["outbounds"][0]["settings"]["vnext"] = [server] * 200
    original = payload([source])
    real_dumps = json.dumps
    delegated_sizes = []

    def record_serialized_request(value, *args, **kwargs):
        serialized = real_dumps(value, *args, **kwargs)
        if isinstance(value, dict) and "profiles" in value:
            delegated_sizes.append(len(serialized))
        return serialized

    monkeypatch.setattr(direct_subscription.json, "dumps", record_serialized_request)
    result = direct_subscription.parse_trial_subscription(original, KEY, 200)
    assert len(result) == 2
    assert len(delegated_sizes) == 200
    assert max(delegated_sizes) < 4096


@pytest.mark.parametrize("label_field", ["remarks", "remark", "name", "tag"])
def test_trial_preserves_each_supported_profile_label_field(label_field):
    from litechecker.direct_subscription import parse_trial_subscription

    source = profile()
    source.pop("remarks")
    source[label_field] = "Kept label"
    assert parse_trial_subscription(payload(source), KEY, 2)[0].label == "Kept label"


@pytest.mark.parametrize("location", ["outbound", "settings", "server", "user", "stream", "reality"])
def test_trial_preserves_unknown_fields_for_strict_rejection(location):
    from litechecker.direct_subscription import parse_trial_subscription

    source = profile()
    outbound = source["outbounds"][0]
    locations = {
        "outbound": outbound,
        "settings": outbound["settings"],
        "server": outbound["settings"]["vnext"][0],
        "user": outbound["settings"]["vnext"][0]["users"][0],
        "stream": outbound["streamSettings"],
        "reality": outbound["streamSettings"]["realitySettings"],
    }
    locations[location]["unreviewed-option"] = True
    with pytest.raises(SubscriptionError, match="unsupported VLESS"):
        parse_trial_subscription(payload([profile(), source]), KEY, 10)


@pytest.mark.parametrize("different_sni,limit", [(False, 2), (True, 3)])
def test_trial_enforces_combined_vpn_variant_and_unique_sni_limit(different_sni, limit):
    from litechecker.direct_subscription import parse_trial_subscription

    source = [profile(), profile(user="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", sni="two.example" if different_sni else "one.example")]
    with pytest.raises(SubscriptionError, match="endpoint limit"):
        parse_trial_subscription(payload(source), KEY, limit)


def test_trial_limits_raw_server_walk_even_when_every_entry_is_duplicate():
    from litechecker.direct_subscription import parse_trial_subscription

    with pytest.raises(SubscriptionError, match="endpoint limit"):
        parse_trial_subscription(payload([profile()] * 4), KEY, 3)


@pytest.mark.parametrize("document", [None, 1, "text", {}, [], {"profiles": None}, {"profiles": {}}, [None], [{"outbounds": None}], [{"outbounds": [None]}]])
def test_trial_rejects_bad_root_or_malformed_profile(document):
    from litechecker.direct_subscription import parse_trial_subscription

    with pytest.raises(SubscriptionError):
        parse_trial_subscription(payload(document), KEY, 10)


@pytest.mark.parametrize("malformed", [None, {}, {"vnext": []}, {"vnext": None}, {"vnext": [None]}])
def test_trial_rejects_malformed_vless_next_to_valid_profile(malformed):
    from litechecker.direct_subscription import parse_trial_subscription

    invalid = profile()
    invalid["outbounds"][0]["settings"] = malformed
    with pytest.raises(SubscriptionError):
        parse_trial_subscription(payload([profile(), invalid]), KEY, 10)


@pytest.mark.parametrize("invalid_bytes", [b"\xff", b"not json"])
def test_trial_rejects_invalid_encoding_and_json(invalid_bytes):
    from litechecker.direct_subscription import parse_trial_subscription

    with pytest.raises(SubscriptionError):
        parse_trial_subscription(invalid_bytes, KEY, 10)


def test_trial_preserves_non_vless_ignore_behavior():
    from litechecker.direct_subscription import parse_trial_subscription

    original = profile()
    source = copy.deepcopy(original)
    source["outbounds"].append({"protocol": "freedom", "settings": "ignored"})
    assert parse_trial_subscription(payload(source), KEY, 5) == parse_trial_subscription(payload(original), KEY, 5)


def test_trial_variant_suffix_is_device_key_dependent_but_sni_id_is_not():
    from litechecker.direct_subscription import parse_trial_subscription

    first = parse_trial_subscription(payload(profile()), KEY, 5)
    second = parse_trial_subscription(payload(profile()), b"another-synthetic-key", 5)
    assert first[0].target_id != second[0].target_id
    assert first[0].target_id.split(":")[0] == second[0].target_id.split(":")[0]
    assert first[1].target_id == second[1].target_id


@pytest.mark.parametrize("limit", [0, -1])
def test_trial_rejects_nonpositive_limit(limit):
    from litechecker.direct_subscription import parse_trial_subscription

    with pytest.raises(SubscriptionError, match="endpoint limit"):
        parse_trial_subscription(payload(profile()), KEY, limit)

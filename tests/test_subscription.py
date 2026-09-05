import json
from pathlib import Path
import time
import tracemalloc

import pytest

from litechecker.subscription import SubscriptionError, parse_xray_subscription


FIXTURE = Path(__file__).parent / "fixtures" / "xray-subscription.json"


def _vless_outbound(
    *,
    address: str = "edge.example",
    port: int = 443,
    user_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    public_key: str = "fake-public-key-a",
):
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [{"id": user_id, "flow": "xtls-rprx-vision"}],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": "www.example.com",
                "publicKey": public_key,
                "shortId": "fake-short-id",
            },
        },
    }


def _profile(outbound, *, remarks: str = "Synthetic profile"):
    return {"remarks": remarks, "outbounds": [outbound]}


def test_parser_extracts_only_vless_vnext_and_deduplicates(tmp_path):
    payload = FIXTURE.read_bytes()

    targets = parse_xray_subscription(payload, b"k" * 32, max_endpoints=20)

    assert [(target.address, target.port) for target in targets] == [
        ("198.51.100.10", 443),
        ("edge.example", 443),
        ("www.example.com", 443),
    ]
    assert all(target.outbound["protocol"] == "vless" for target in targets if target.check_kind == "vpn")
    assert targets[-1].check_kind == "sni"
    assert targets[-1].outbound == {}
    assert targets[0].label == "Aggregate profile | Duplicate single-server profile"


def test_parser_rejects_empty_or_service_only_subscription():
    with pytest.raises(SubscriptionError, match="no VLESS targets"):
        parse_xray_subscription(
            b'[{"outbounds":[{"protocol":"freedom"}]}]', b"k" * 32, 20
        )


def test_parser_splits_vnext_and_preserves_probe_material_without_source_tags():
    targets = parse_xray_subscription(FIXTURE.read_bytes(), b"k" * 32, max_endpoints=20)

    first = targets[0]
    assert len(first.outbound["settings"]["vnext"]) == 1
    assert "tag" not in first.outbound
    assert first.outbound["streamSettings"]["realitySettings"] == {
        "serverName": "www.example.com",
        "publicKey": "fake-reality-public-key",
        "shortId": "fake-short-id",
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"not json",
        b'{"profiles": []}',
    ],
)
def test_parser_rejects_invalid_or_empty_payloads(payload):
    with pytest.raises(SubscriptionError):
        parse_xray_subscription(payload, b"k" * 32, max_endpoints=20)


def test_parser_rejects_endpoint_count_over_limit():
    with pytest.raises(SubscriptionError, match="endpoint limit"):
        parse_xray_subscription(FIXTURE.read_bytes(), b"k" * 32, max_endpoints=1)


@pytest.mark.parametrize(
    "profiles",
    [
        ["not-a-profile", _profile(_vless_outbound())],
        [{"outbounds": "not-a-list"}, _profile(_vless_outbound())],
        [
            _profile(_vless_outbound()),
            _profile({"protocol": "vless", "settings": {"vnext": [{"address": "edge.example"}]}}),
        ],
        [
            _profile(_vless_outbound()),
            _profile(
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{"address": "edge.example", "port": 443, "users": []}]
                    },
                }
            ),
        ],
    ],
)
def test_parser_rejects_mixed_subscription_with_malformed_vless_data(profiles):
    payload = json.dumps(profiles).encode()

    with pytest.raises(SubscriptionError, match="invalid VLESS"):
        parse_xray_subscription(payload, b"k" * 32, max_endpoints=20)


def test_parser_rejects_conflicting_probe_configs_with_same_target_identity():
    payload = json.dumps(
        [
            _profile(_vless_outbound(user_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
            _profile(_vless_outbound(user_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")),
        ]
    ).encode()

    with pytest.raises(SubscriptionError, match="conflicting VLESS"):
        parse_xray_subscription(payload, b"k" * 32, max_endpoints=20)


def test_parser_canonicalizes_endpoint_data_before_fingerprinting():
    upper = json.dumps([_profile(_vless_outbound(address="EDGE.EXAMPLE."))]).encode()
    lower = json.dumps([_profile(_vless_outbound(address="edge.example"))]).encode()

    upper_target = parse_xray_subscription(upper, b"k" * 32, max_endpoints=20)[0]
    lower_target = parse_xray_subscription(lower, b"k" * 32, max_endpoints=20)[0]

    assert upper_target.target_id == lower_target.target_id
    assert upper_target.config_fingerprint == lower_target.config_fingerprint
    assert upper_target.outbound["settings"]["vnext"][0]["address"] == "edge.example"


def test_parser_redacts_bounds_and_strips_control_characters_from_labels():
    remark = (
        "\x01https://label.example/path?token=fake-token "
        "11111111-1111-4111-8111-111111111111 shortId=fake-short-id "
        + "x" * 200
    )
    payload = json.dumps([_profile(_vless_outbound(), remarks=remark)]).encode()

    label = parse_xray_subscription(payload, b"k" * 32, max_endpoints=20)[0].label

    assert "fake-token" not in label
    assert "11111111" not in label
    assert "fake-short-id" not in label
    assert "\x01" not in label
    assert len(label) <= 128


def test_parser_enforces_endpoint_limit_before_later_malformed_entries():
    """Walking beyond max+1 lets hostile input force unnecessary validation/allocation."""
    outbound = _vless_outbound()
    outbound["settings"]["vnext"] = [
        {
            "address": f"1.1.1.{index}",
            "port": 443,
            "users": [
                {
                    "id": f"00000000-0000-4000-8000-{index:012d}",
                    "flow": "xtls-rprx-vision",
                    "encryption": "none",
                }
            ],
        }
        for index in range(1, 6)
    ]
    outbound["settings"]["vnext"].append({"malformed": True})

    with pytest.raises(SubscriptionError, match="endpoint limit exceeded"):
        parse_xray_subscription(
            json.dumps([_profile(outbound)]).encode(),
            b"k" * 32,
            max_endpoints=3,
        )


def test_parser_does_not_deep_copy_the_full_many_server_outbound_per_candidate():
    """A compact many-server profile must stay linear instead of quadratic in memory."""
    outbound = _vless_outbound()
    outbound["settings"]["vnext"] = [
        {
            "address": f"1.1.{index // 250}.{index % 250 + 1}",
            "port": 443,
            "users": [
                {
                    "id": f"00000000-0000-4000-8000-{index:012d}",
                    "flow": "xtls-rprx-vision",
                    "encryption": "none",
                }
            ],
        }
        for index in range(300)
    ]
    payload = json.dumps([_profile(outbound)], separators=(",", ":")).encode()

    tracemalloc.start()
    started = time.perf_counter()
    try:
        targets = parse_xray_subscription(payload, b"k" * 32, max_endpoints=400)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    elapsed = time.perf_counter() - started

    assert len(targets) == 301
    assert elapsed < 0.5
    assert peak < 4_000_000


def test_sni_hosts_are_deduplicated_separately_from_vpn_addresses():
    first = _vless_outbound(address="www.example.com")
    second = _vless_outbound(address="edge.example")
    second["streamSettings"]["realitySettings"]["serverName"] = "WWW.EXAMPLE.COM."
    targets = parse_xray_subscription(
        json.dumps([_profile(first), _profile(second)]).encode(), b"k" * 32, 20
    )
    sni = [target for target in targets if target.check_kind == "sni"]
    vpn = [target for target in targets if target.check_kind == "vpn"]
    assert len(vpn) == 2
    assert len(sni) == 1
    assert sni[0].address == "www.example.com"
    assert sni[0].target_id not in {target.target_id for target in vpn}
    assert sni[0].outbound == {}


def test_sni_subdomains_are_taken_exactly_without_inventing_parent_domains():
    outbound = _vless_outbound(address="vpn.sub.example")
    outbound["streamSettings"]["realitySettings"]["serverName"] = "cdn.media.example"
    targets = parse_xray_subscription(json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20)
    assert {target.address for target in targets} == {"vpn.sub.example", "cdn.media.example"}


def test_sni_targets_count_toward_total_endpoint_cap():
    with pytest.raises(SubscriptionError, match="endpoint limit"):
        parse_xray_subscription(json.dumps([_profile(_vless_outbound())]).encode(), b"k" * 32, 1)


@pytest.mark.parametrize("server_name", ["https://example.com/path", "bad host", "example.com:443"])
def test_parser_rejects_malformed_sni_before_any_network_probe(server_name):
    outbound = _vless_outbound()
    outbound["streamSettings"]["realitySettings"]["serverName"] = server_name
    with pytest.raises(SubscriptionError, match="SNI hostname"):
        parse_xray_subscription(json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20)


@pytest.mark.parametrize(
    ("location", "name", "value"),
    [
        ("outbound", "mux", {"enabled": True}),
        ("settings", "packetEncoding", "xudp"),
        ("user", "email", "secret@example.invalid"),
        ("stream", "sockopt", {"mark": 1}),
        ("reality", "privateKey", "must-not-forward"),
    ],
)
def test_parser_rejects_subscription_behavior_outside_explicit_allowlist(
    location, name, value
):
    """Forwarding unreviewed nested Xray behavior escapes the minimal probe config."""
    outbound = _vless_outbound()
    if location == "outbound":
        outbound[name] = value
    elif location == "settings":
        outbound["settings"][name] = value
    elif location == "user":
        outbound["settings"]["vnext"][0]["users"][0][name] = value
    elif location == "stream":
        outbound["streamSettings"][name] = value
    else:
        outbound["streamSettings"]["realitySettings"][name] = value

    with pytest.raises(SubscriptionError, match="unsupported VLESS"):
        parse_xray_subscription(
            json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20
        )


def test_parser_reconstructs_only_the_reviewed_vless_reality_fields():
    """The accepted fixture should yield a small explicit outbound, never a source clone."""
    target = parse_xray_subscription(FIXTURE.read_bytes(), b"k" * 32, 20)[0]

    assert set(target.outbound) == {"protocol", "settings", "streamSettings"}
    assert set(target.outbound["settings"]) == {"vnext"}
    server = target.outbound["settings"]["vnext"][0]
    assert set(server) == {"address", "port", "users"}
    assert set(server["users"][0]) == {"id", "flow", "encryption"}
    assert set(target.outbound["streamSettings"]) == {
        "network",
        "security",
        "realitySettings",
    }


def test_parser_accepts_current_disabled_mux_and_plain_tcp_header_fields():
    """Provider boilerplate is accepted only in its inert reviewed form."""
    outbound = _vless_outbound()
    outbound["mux"] = {"enabled": False, "concurrency": -1}
    outbound["streamSettings"]["tcpSettings"] = {"header": {"type": "none"}}
    outbound["streamSettings"]["realitySettings"]["allowInsecure"] = False

    target = parse_xray_subscription(
        json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20
    )[0]

    assert "mux" not in target.outbound
    assert target.outbound["streamSettings"]["tcpSettings"] == {
        "header": {"type": "none"}
    }
    assert target.outbound["streamSettings"]["realitySettings"][
        "allowInsecure"
    ] is False


@pytest.mark.parametrize(
    ("location", "value"),
    [
        ("mux", {"enabled": True, "concurrency": -1}),
        ("tcp", {"header": {"type": "http"}}),
        ("allow_insecure", "false"),
    ],
)
def test_parser_rejects_unsafe_or_malformed_provider_transport_boilerplate(
    location, value
):
    outbound = _vless_outbound()
    if location == "mux":
        outbound["mux"] = value
    elif location == "tcp":
        outbound["streamSettings"]["tcpSettings"] = value
    else:
        outbound["streamSettings"]["realitySettings"]["allowInsecure"] = value

    with pytest.raises(SubscriptionError):
        parse_xray_subscription(
            json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20
        )


@pytest.mark.parametrize(("field", "value"), [("network", "grpc"), ("security", "tls")])
def test_parser_rejects_unreviewed_vless_transport_or_security(field, value):
    """A sparse config for another transport must not slip through without its behavior fields."""
    outbound = _vless_outbound()
    outbound["streamSettings"][field] = value

    with pytest.raises(SubscriptionError, match="unsupported VLESS"):
        parse_xray_subscription(
            json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20
        )


@pytest.mark.parametrize("missing", ["streamSettings", "serverName"])
def test_parser_requires_complete_vless_reality_transport(missing):
    """A VLESS target without reviewed REALITY routing material is outside scope."""
    outbound = _vless_outbound()
    outbound["streamSettings"]["realitySettings"]["serverName"] = "www.example.com"
    if missing == "streamSettings":
        del outbound[missing]
    else:
        del outbound["streamSettings"]["realitySettings"][missing]

    with pytest.raises(SubscriptionError, match="VLESS"):
        parse_xray_subscription(
            json.dumps([_profile(outbound)]).encode(), b"k" * 32, 20
        )

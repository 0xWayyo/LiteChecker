import pytest

from litechecker.security import (
    canonical_host,
    config_fingerprint,
    generate_agent_token,
    is_valid_agent_token,
    is_forbidden_ip,
    redact,
    target_id,
)


def test_agent_token_generation_uses_32_random_bytes_and_shared_format(monkeypatch):
    """Token guidance must produce exactly the format all protocol boundaries accept."""
    calls = []

    def token_urlsafe(byte_count):
        calls.append(byte_count)
        return "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

    monkeypatch.setattr("litechecker.security.secrets.token_urlsafe", token_urlsafe)

    token = generate_agent_token()

    assert token == "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
    assert calls == [32]
    assert is_valid_agent_token(token) is True


def test_redact_removes_urls_tokens_uuids_and_reality_values():
    """Dropping a redaction branch would leak a reusable credential to logs."""
    text = (
        "https://u:p@example/a?token=secret "
        "11111111-1111-4111-8111-111111111111 shortId=abcd publicKey=xyz"
    )

    cleaned = redact(text)

    assert "secret" not in cleaned
    assert "11111111" not in cleaned
    assert "abcd" not in cleaned
    assert "xyz" not in cleaned


def test_redact_returns_single_line_bounded_text_and_redacts_bearer_and_json_secrets():
    """Removing output bounds or JSON secret handling would make hostile errors unsafe."""
    cleaned = redact(
        'Bearer abc.def-123\n{"password":"private", "shortId":"s3cr3t"} ' + "x" * 1000
    )

    assert "\n" not in cleaned
    assert "abc.def-123" not in cleaned
    assert "private" not in cleaned
    assert "s3cr3t" not in cleaned
    assert len(cleaned) <= 512


def test_redact_removes_vless_urls_and_reality_query_aliases():
    """Missing VLESS and pbk/sid handling would leak raw Xray probe material."""
    text = (
        "vless://11111111-1111-4111-8111-111111111111@vpn.example:443"
        "?security=reality&pbk=reality-public-key&sid=reality-short-id "
        "pbk=standalone-public-key sid=standalone-short-id"
    )

    cleaned = redact(text)

    assert "11111111" not in cleaned
    assert "reality-public-key" not in cleaned
    assert "reality-short-id" not in cleaned
    assert "standalone-public-key" not in cleaned
    assert "standalone-short-id" not in cleaned


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("B\u00dcCHER.Example", "xn--bcher-kva.example"),
        ("203.0.113.7", "203.0.113.7"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_canonical_host_normalizes_domains_and_ip_literals(raw, expected):
    """Changing host normalization would produce unstable identities across agents."""
    assert canonical_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    (
        "bad_host.example",
        "-bad.example",
        "bad-.example",
        f"{'a' * 64}.example",
        ".".join(["a" * 63] * 4),
        "bad\n.example",
        " padded.example ",
        "2130706433",
        "127.1",
        "[example.com]",
    ),
)
def test_canonical_host_rejects_ambiguous_or_invalid_dns_names(raw):
    """Targets must use strict DNS wire-compatible hostnames before validation/probing."""
    with pytest.raises(ValueError):
        canonical_host(raw)


@pytest.mark.parametrize(
    "value",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "::1", "2001:db8::1"],
)
def test_is_forbidden_ip_rejects_non_global_addresses(value):
    """Relaxing the policy would allow probes to reach local or metadata networks."""
    assert is_forbidden_ip(value) is True


def test_is_forbidden_ip_allows_a_global_address():
    """Marking a global address forbidden would make every legitimate target fail."""
    assert is_forbidden_ip("1.1.1.1") is False


def test_stable_target_id_excludes_secrets_but_fingerprint_detects_them():
    """Including credentials in IDs leaks rotation into collector-visible identity."""
    common = {
        "protocol": "vless",
        "address": "B\u00dcCHER.Example",
        "port": 443,
        "transport": "tcp",
        "security": "reality",
        "flow": "xtls-rprx-vision",
    }
    target = target_id(**common)
    rotated = target_id(**common)

    first = config_fingerprint({"id": "first-secret", **common}, b"s" * 32)
    second = config_fingerprint({"id": "second-secret", **common}, b"s" * 32)

    assert target == rotated
    assert len(target) == 64
    assert first != second
    assert len(first) == 64

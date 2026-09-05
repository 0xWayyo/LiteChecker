import base64
from datetime import datetime, timezone
import importlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _modules():
    return importlib.import_module("litechecker.update_manifest")


def _key_pair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _payload(**changes):
    payload = {
        "version": "0.2.0",
        "sequence": 2,
        "published_at": "2026-09-05T00:00:00Z",
        "artifact": {
            "urls": ["https://downloads.example/LiteChecker-0.2.0.zip"],
            "sha256": "a" * 64,
            "size": 123,
        },
    }
    payload.update(changes)
    return payload


def _signed(private, payload=None):
    payload = payload or _payload()
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return json.dumps(
        {
            "schema": 1,
            "payload": payload,
            "signature": base64.b64encode(private.sign(canonical)).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def test_verifies_exact_signed_release_metadata():
    module = _modules()
    private, public = _key_pair()

    release = module.verify_release_metadata(_signed(private), public)

    assert release.version == "0.2.0"
    assert release.sequence == 2
    assert release.published_at == datetime(2026, 9, 5, tzinfo=timezone.utc)
    assert release.artifact.urls == (
        "https://downloads.example/LiteChecker-0.2.0.zip",
    )
    assert release.artifact.sha256 == "a" * 64
    assert release.artifact.size == 123


def test_canonical_payload_matches_wire_contract_literal():
    module = _modules()
    assert module.canonical_payload(_payload()) == (
        b'{"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"size":123,"urls":["https://downloads.example/LiteChecker-0.2.0.zip"]},'
        b'"published_at":"2026-09-05T00:00:00Z","sequence":2,"version":"0.2.0"}'
    )


@pytest.mark.parametrize("mutation", ["signature", "payload", "key"])
def test_rejects_wrong_key_or_any_signed_data_tampering(mutation):
    module = _modules()
    private, public = _key_pair()
    data = _signed(private)
    if mutation == "key":
        _, public = _key_pair()
    else:
        envelope = json.loads(data)
        if mutation == "signature":
            envelope["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
        else:
            envelope["payload"]["version"] = "0.3.0"
        data = json.dumps(envelope).encode()

    with pytest.raises(module.ManifestError):
        module.verify_release_metadata(data, public)


@pytest.mark.parametrize(
    "payload_change",
    [
        {"version": "01.2.0"},
        {"version": "0.2"},
        {"sequence": True},
        {"sequence": 0},
        {"published_at": "2026-09-05T00:00:00+00:00"},
        {"extra": "field"},
        {"artifact": {"urls": ["http://downloads.example/a.zip"], "sha256": "a" * 64, "size": 123}},
        {"artifact": {"urls": ["https://a/1", "https://a/2", "https://a/3", "https://a/4"], "sha256": "a" * 64, "size": 123}},
        {"artifact": {"urls": ["https://a/1"], "sha256": "A" * 64, "size": 123}},
        {"artifact": {"urls": ["https://a/1"], "sha256": "a" * 64, "size": True}},
        {"artifact": {"urls": ["https://a/1"], "sha256": "a" * 64, "size": 33 * 1024 * 1024}},
    ],
)
def test_rejects_values_outside_the_strict_metadata_schema(payload_change):
    module = _modules()
    private, public = _key_pair()
    with pytest.raises(module.ManifestError):
        module.verify_release_metadata(_signed(private, _payload(**payload_change)), public)


def test_rejects_duplicate_or_unknown_envelope_fields_and_oversized_metadata():
    module = _modules()
    private, public = _key_pair()
    good = _signed(private)
    duplicate = good[:-1] + b',"schema":1}'
    unknown = json.loads(good)
    unknown["public_key"] = "remote-trust-is-forbidden"

    for data in (duplicate, json.dumps(unknown).encode(), b" " * (64 * 1024 + 1)):
        with pytest.raises(module.ManifestError):
            module.verify_release_metadata(data, public)


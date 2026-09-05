from __future__ import annotations

import json
import multiprocessing
import os

import pytest

from litechecker.collector.auth import AgentRegistry, RegistryError


TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


def _write_registry(path, payload=None, *, mode=0o600):
    if payload is None:
        payload = {
            "agent-1": {
                "token": TOKEN,
                "city": "Tbilisi",
                "name": "Home ISP",
                "expected_interval_seconds": 600,
            }
        }
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    os.chmod(path, mode)
    return path


def test_registry_authenticates_token_without_returning_or_representing_it(tmp_path):
    """Keeping the plaintext token in registry state would make incidental logs unsafe."""
    registry = AgentRegistry.load(_write_registry(tmp_path / "agents.json"))

    identity = registry.authenticate(TOKEN)

    assert identity is not None
    assert identity.agent_id == "agent-1"
    assert identity.city == "Tbilisi"
    assert identity.name == "Home ISP"
    assert identity.expected_interval_seconds == 600
    assert TOKEN not in repr(registry)
    assert TOKEN not in repr(identity)


def test_registry_rejects_unknown_and_malformed_tokens_identically(tmp_path):
    """Distinguishing unknown credentials would disclose registry membership."""
    registry = AgentRegistry.load(_write_registry(tmp_path / "agents.json"))

    assert registry.authenticate("x" * len(TOKEN)) is None
    assert registry.authenticate("") is None
    assert registry.authenticate("Bearer " + TOKEN) is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_registry_rejects_group_or_world_readable_secret_file(tmp_path):
    """Accepting a shared registry file would expose every agent credential."""
    path = _write_registry(tmp_path / "agents.json", mode=0o640)

    with pytest.raises(RegistryError, match="permissions"):
        AgentRegistry.load(path)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"bad agent": {"token": TOKEN, "city": "Tbilisi", "name": "ISP", "expected_interval_seconds": 600}},
        {"agent-1": {"token": "short", "city": "Tbilisi", "name": "ISP", "expected_interval_seconds": 600}},
        {"agent-1": {"token": TOKEN, "city": "Tbilisi\nInjected", "name": "ISP", "expected_interval_seconds": 600}},
        {"agent-1": {"token": TOKEN, "city": "Tbilisi", "name": "ISP", "expected_interval_seconds": 0}},
        {"agent-1": {"token": TOKEN, "city": "Tbilisi", "name": "ISP", "expected_interval_seconds": 600, "extra": True}},
    ],
)
def test_registry_rejects_invalid_or_ambiguous_entries(tmp_path, payload):
    """Weak registry validation would let unsafe metadata enter reports and thresholds."""
    path = _write_registry(tmp_path / "agents.json", payload=payload)

    with pytest.raises(RegistryError):
        AgentRegistry.load(path)


def test_registry_rejects_duplicate_tokens(tmp_path):
    """One bearer credential must resolve to exactly one trusted agent."""
    payload = {
        agent_id: {
            "token": TOKEN,
            "city": city,
            "name": "ISP",
            "expected_interval_seconds": 600,
        }
        for agent_id, city in (("agent-1", "Tbilisi"), ("agent-2", "Batumi"))
    }

    with pytest.raises(RegistryError, match="duplicate token"):
        AgentRegistry.load(_write_registry(tmp_path / "agents.json", payload=payload))


@pytest.mark.parametrize(
    "token",
    [
        "x" * 32,
        "lc_" + "a" * 43,
        "lc_А" + "b" * 42,
        "lc_short",
        "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHy=",
    ],
)
def test_registry_requires_generated_ascii_header_safe_token(tmp_path, token):
    """Loose token formats permit low-entropy or header-unsafe bearer credentials."""
    payload = {
        "agent-1": {
            "token": token,
            "city": "Tbilisi",
            "name": "ISP",
            "expected_interval_seconds": 600,
        }
    }

    with pytest.raises(RegistryError, match="token"):
        AgentRegistry.load(_write_registry(tmp_path / "agents.json", payload=payload))


@pytest.mark.parametrize(
    "raw",
    [
        '{"agent-1":{"token":"' + TOKEN + '","city":"Tbilisi","city":"Batumi","name":"ISP","expected_interval_seconds":600}}',
        '{"agent-1":{"token":"' + TOKEN + '","city":"Tbilisi","name":"ISP","expected_interval_seconds":600},"agent-1":{"token":"' + TOKEN + '","city":"Batumi","name":"ISP","expected_interval_seconds":600}}',
    ],
)
def test_registry_json_rejects_duplicate_keys_at_any_nesting(tmp_path, raw):
    """Normal JSON last-key-wins behavior can hide conflicting registry authority."""
    path = tmp_path / "agents.json"
    path.write_text(raw, encoding="utf-8")
    os.chmod(path, 0o600)

    with pytest.raises(RegistryError, match="duplicate"):
        AgentRegistry.load(path)


def test_registry_reads_only_the_descriptor_that_was_checked(tmp_path, monkeypatch):
    """Reopening a validated path permits a symlink or file swap before parsing."""
    path = _write_registry(tmp_path / "agents.json")

    def unsafe_reopen(*args, **kwargs):
        raise AssertionError("registry path was reopened after metadata validation")

    monkeypatch.setattr(type(path), "read_bytes", unsafe_reopen)

    assert AgentRegistry.load(path).authenticate(TOKEN) is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFOs only")
def test_registry_fifo_is_rejected_without_blocking_startup(tmp_path):
    """A registry FIFO must not block before same-descriptor type validation."""
    fifo = tmp_path / "agents.fifo"
    os.mkfifo(fifo, 0o600)
    context = multiprocessing.get_context("fork")
    outcome = context.Queue()

    def load_registry():
        try:
            AgentRegistry.load(fifo)
        except RegistryError as exc:
            outcome.put(str(exc))

    process = context.Process(target=load_registry)
    process.start()
    process.join(timeout=1)
    if process.is_alive():
        process.terminate()
        process.join(timeout=1)
        pytest.fail("registry open blocked on FIFO")
    assert "regular file" in outcome.get(timeout=1)


def test_portable_no_follow_fallback_detects_path_swap(tmp_path, monkeypatch):
    """Platforms without O_NOFOLLOW must fail closed if the path inode changes."""
    path = _write_registry(tmp_path / "agents.json")
    replacement = _write_registry(tmp_path / "replacement.json")
    original_open = os.open
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    def swapping_open(target, flags):
        os.replace(replacement, path)
        return original_open(target, flags)

    monkeypatch.setattr(os, "open", swapping_open)

    with pytest.raises(RegistryError, match="changed"):
        AgentRegistry.load(path)

"""Direct Telegram delivery through the real agent cycle and durable local outbox."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from litechecker.agent import AgentDependencies, XrayVersionResult
from litechecker.collector.auth import AgentIdentity
from litechecker.collector.db import CollectorDB
from litechecker.collector.telegram import TelegramClient
from litechecker.config import AgentSettings
from litechecker.models import ProbeResult, ProbeStage, ResultStatus
from litechecker.probe import ControlResult
from litechecker.state import CollectorAckStore, PendingReportStore, SequenceStore, SnapshotStore


TOKEN = "123456:fake-telegram-token"
NOW = datetime(2026, 9, 5, 12, tzinfo=UTC)
SUBSCRIPTION = Path(__file__).parent / "fixtures" / "xray-subscription.json"


@pytest.mark.asyncio
async def test_standalone_cycle_waits_for_update_maintenance_boundary(tmp_path):
    from filelock import AsyncFileLock
    from litechecker.standalone import run_standalone

    clock = Clock()
    dependencies = _dependencies(tmp_path, clock)
    async with AsyncFileLock(tmp_path / "maintenance.lock", run_in_executor=True):
        task = asyncio.create_task(run_standalone(
            _settings(tmp_path), once=True, dependencies=dependencies,
            telegram=_telegram(lambda request: _accepted()),
        ))
        await asyncio.sleep(0.1)
        blocked = not dependencies.fetcher.fetched_at
    await asyncio.wait_for(task, 2)
    assert blocked and len(dependencies.fetcher.fetched_at) == 1


def _settings(state_dir):
    agent = AgentSettings(
        agent_id="device-aabbccdd",
        agent_token="lc_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        collector_url="https://unused.invalid",
        subscription_url="https://subscription.example/private",
        state_key="s" * 32,
    )
    return SimpleNamespace(
        agent=agent,
        identity=AgentIdentity(agent.agent_id, "Тбилиси", "Домашний Mac", 600),
        state_dir=state_dir,
        telegram_bot_token=SecretStr(TOKEN),
        telegram_chat_id="-1000000000000",
        telegram_topic_id=17,
        telegram_proxy_url=None,
    )


class Clock:
    def __init__(self, now=NOW):
        self.now = now
        self.elapsed = 0.0

    def wall(self):
        return self.now + timedelta(seconds=self.elapsed)

    def monotonic(self):
        return self.elapsed

    async def sleep(self, delay):
        self.elapsed += delay
        await asyncio.sleep(0)


class Fetcher:
    def __init__(self, clock):
        self.clock = clock
        self.fetched_at = []

    async def fetch(self):
        self.fetched_at.append(self.clock.elapsed)
        return SUBSCRIPTION.read_bytes()


async def _control():
    return ControlResult(ok=True)


async def _version():
    return XrayVersionResult("26.3.27", True, None)


async def _probe(targets, control, deadline):
    return [
        ProbeResult(
            target_id=target.target_id,
            label=target.label,
            address=target.address,
            port=target.port,
            status=ResultStatus.UP,
            stage=ProbeStage.TLS if target.check_kind == "sni" else ProbeStage.E2E,
            check_kind=target.check_kind,
            latency_ms=10,
        )
        for target in targets
    ]


class ForbiddenCollector:
    async def send(self, report):
        raise AssertionError("standalone must not contact a collector")


def _dependencies(state_dir, clock):
    return AgentDependencies(
        fetcher=Fetcher(clock),
        snapshot_store=SnapshotStore(state_dir, state_key="s" * 32),
        sequence_store=SequenceStore(state_dir / "sequence.json"),
        pending_store=PendingReportStore(state_dir / "pending-report.json"),
        ack_store=CollectorAckStore(state_dir / "collector-ack.json"),
        control_checker=_control,
        prober=_probe,
        version_checker=_version,
        sender=ForbiddenCollector(),
        wall_clock=clock.wall,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        boot_id="test-boot",
    )


def _telegram(handler):
    return TelegramClient(
        token=TOKEN,
        chat_id="-1000000000000",
        topic_id=17,
        max_attempts=1,
        transport=httpx.MockTransport(handler),
    )


def _accepted():
    return httpx.Response(200, json={"ok": True, "result": {"message_id": 123}})


def _db(settings):
    return CollectorDB(settings.state_dir / "standalone.sqlite3", [settings.identity])


@pytest.mark.asyncio
async def test_configured_proxy_reaches_default_telegram_sender_without_affecting_probes(tmp_path, monkeypatch):
    from litechecker import standalone

    settings = _settings(tmp_path)
    settings.telegram_proxy_url = SecretStr("socks5://test:private-password@192.0.2.10:1080")
    dependencies = _dependencies(tmp_path, Clock())
    configured = []
    delivered = []

    def handler(request):
        delivered.append(json.loads(request.content))
        return _accepted()

    def make_sender(**kwargs):
        configured.append(kwargs)
        return _telegram(handler)

    monkeypatch.setattr(standalone, "TelegramClient", make_sender)
    result = await standalone.run_standalone(settings, once=True, dependencies=dependencies)
    assert len(result.results) == 3
    assert all(item.status is ResultStatus.UP for item in result.results)
    assert len(delivered) == 1
    assert configured[0].get("proxy_url") == settings.telegram_proxy_url.get_secret_value()


@pytest.mark.asyncio
async def test_once_sends_actual_cycle_to_telegram_and_records_only_telegram_ack(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    clock = Clock()
    dependencies = _dependencies(tmp_path, clock)
    delivered = []

    def telegram(request):
        delivered.append(json.loads(request.content))
        return _accepted()

    report = await standalone.run_standalone(
        settings, once=True, dependencies=dependencies, telegram=_telegram(telegram)
    )

    assert report.sequence == 0
    assert len(report.results) == 3
    assert {result.check_kind for result in report.results} == {"vpn", "sni"}
    assert len(delivered) == 1
    assert delivered[0]["chat_id"] == "-1000000000000"
    assert delivered[0]["message_thread_id"] == 17
    assert "Тбилиси" in delivered[0]["text"]
    assert "Домашний Mac (device-aabbccdd)" in delivered[0]["text"]
    assert "VPN: 2 (IP: 1 / домены: 1)" in delivered[0]["text"]
    assert "SNI: 1" in delivered[0]["text"]
    assert TOKEN not in delivered[0]["text"]
    assert _db(settings).storage_stats()["completed_notifications"] == 1
    assert dependencies.pending_store.load() is None
    assert not (tmp_path / "collector-ack.json").exists()
    assert CollectorAckStore(tmp_path / "telegram-ack.json").is_recent(
        clock.wall(), max_age_seconds=1500
    )


@pytest.mark.asyncio
async def test_once_fails_when_telegram_has_not_accepted_but_preserves_outbox(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    dependencies = _dependencies(tmp_path, Clock())
    with pytest.raises(standalone.StandaloneDeliveryError):
        await standalone.run_standalone(
            settings,
            once=True,
            dependencies=dependencies,
            telegram=_telegram(lambda request: httpx.Response(503)),
        )

    assert _db(settings).pending_notification_count() == 1
    assert dependencies.pending_store.load()["sequence"] == 0
    assert not (tmp_path / "telegram-ack.json").exists()


@pytest.mark.asyncio
async def test_restart_delivers_old_report_before_new_probe_without_duplicate_message(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    with pytest.raises(standalone.StandaloneDeliveryError):
        await standalone.run_standalone(
            settings,
            once=True,
            dependencies=_dependencies(tmp_path, Clock()),
            telegram=_telegram(lambda request: httpx.Response(503)),
        )

    clock = Clock(NOW + timedelta(seconds=61))
    dependencies = _dependencies(tmp_path, clock)
    fetch_counts = []

    def telegram(request):
        fetch_counts.append(len(dependencies.fetcher.fetched_at))
        return _accepted()

    report = await standalone.run_standalone(
        settings, once=True, dependencies=dependencies, telegram=_telegram(telegram)
    )

    assert report.sequence == 1
    assert fetch_counts == [0, 1]
    assert _db(settings).pending_notification_count() == 0
    assert _db(settings).storage_stats()["completed_notifications"] == 2


@pytest.mark.asyncio
async def test_continuous_mode_retries_delivery_between_600_second_probe_cycles(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    clock = Clock()
    dependencies = _dependencies(tmp_path, clock)
    accepted_at = []

    def telegram(request):
        if clock.elapsed < 60:
            return httpx.Response(503)
        accepted_at.append(clock.elapsed)
        return _accepted()

    await standalone.run_standalone(
        settings,
        dependencies=dependencies,
        telegram=_telegram(telegram),
        max_cycles=2,
    )

    assert dependencies.fetcher.fetched_at == [0, 600]
    assert accepted_at == [60, 600]
    assert _db(settings).event_count() == 2
    assert _db(settings).pending_notification_count() == 0


@pytest.mark.asyncio
async def test_restarting_after_long_shutdown_emits_no_offline_or_recovery_alert(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    messages = []

    def telegram(request):
        messages.append(json.loads(request.content)["text"])
        return _accepted()

    for now in (NOW, NOW + timedelta(days=2)):
        await standalone.run_standalone(
            settings,
            once=True,
            dependencies=_dependencies(tmp_path, Clock(now)),
            telegram=_telegram(telegram),
        )

    assert len(messages) == 2
    assert all("снова на связи" not in message for message in messages)
    assert all("OFFLINE" not in message for message in messages)


@pytest.mark.asyncio
async def test_state_lock_rejects_second_process_and_releases_after_cancellation(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    entered = asyncio.Event()

    class BlockedFetcher:
        async def fetch(self):
            entered.set()
            await asyncio.Event().wait()

    dependencies = _dependencies(tmp_path, Clock())
    dependencies.fetcher = BlockedFetcher()
    first = asyncio.create_task(
        standalone.run_standalone(
            settings,
            once=True,
            dependencies=dependencies,
            telegram=_telegram(lambda request: _accepted()),
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), 3)
        with pytest.raises(standalone.StandaloneAlreadyRunning):
            await standalone.run_standalone(
                settings,
                once=True,
                dependencies=_dependencies(tmp_path, Clock()),
                telegram=_telegram(lambda request: _accepted()),
            )
    finally:
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

    report = await standalone.run_standalone(
        settings,
        once=True,
        dependencies=_dependencies(tmp_path, Clock()),
        telegram=_telegram(lambda request: _accepted()),
    )
    assert report.sequence == 0


@pytest.mark.asyncio
async def test_permanent_delivery_error_is_retried_after_restart(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    with pytest.raises(standalone.StandaloneDeliveryError):
        await standalone.run_standalone(
            settings,
            once=True,
            dependencies=_dependencies(tmp_path, Clock()),
            telegram=_telegram(lambda request: httpx.Response(403, json={"ok": False})),
        )
    assert _db(settings).dead_letter_count() == 1

    received = []

    def telegram(request):
        received.append(json.loads(request.content)["text"])
        return _accepted()

    await standalone.run_standalone(
        settings,
        once=True,
        dependencies=_dependencies(tmp_path, Clock(NOW + timedelta(seconds=61))),
        telegram=_telegram(telegram),
    )

    assert len(received) == 2
    assert _db(settings).dead_letter_count() == 0


@pytest.mark.asyncio
async def test_default_pipeline_uses_configured_state_directory(tmp_path, monkeypatch):
    from litechecker import standalone

    settings = _settings(tmp_path / "configured-state")
    dependencies = _dependencies(settings.state_dir, Clock())

    def factory(agent, *, state_dir=None):
        assert state_dir == settings.state_dir
        assert agent is settings.agent
        return dependencies

    monkeypatch.setenv("LC_STATE_DIR", str(tmp_path / "wrong-state"))
    monkeypatch.setattr(standalone, "make_measurement_dependencies", factory)
    report = await standalone.run_standalone(
        settings, once=True, telegram=_telegram(lambda request: _accepted())
    )

    assert report.sequence == 0
    assert (settings.state_dir / "standalone.sqlite3").exists()
    assert not (tmp_path / "wrong-state").exists()


@pytest.mark.asyncio
async def test_network_refreshes_each_probe_cycle_without_changing_device_or_city(tmp_path):
    from litechecker import standalone
    from litechecker.network_identity import NetworkIdentity

    settings = _settings(tmp_path)
    settings.auto_network = True
    original_identity = settings.identity
    original_key = settings.agent.state_key
    clock = Clock()
    dependencies = _dependencies(tmp_path, clock)
    providers = iter([
        NetworkIdentity(provider="First Network", city="Yerevan", country="AM"),
        NetworkIdentity(provider="Second Network", city="Berlin", country="DE"),
        None,
    ])
    looked_up_at = []
    messages = []

    async def lookup():
        looked_up_at.append(clock.elapsed)
        return next(providers)

    def telegram(request):
        if clock.elapsed < 60:
            return httpx.Response(503)
        messages.append(json.loads(request.content)["text"])
        return _accepted()

    report = await standalone.run_standalone(
        settings,
        dependencies=dependencies,
        telegram=_telegram(telegram),
        network_lookup=lookup,
        max_cycles=3,
    )

    assert looked_up_at == [0, 600, 1200]
    assert dependencies.fetcher.fetched_at == [0, 600, 1200]
    assert len(messages) == 3
    assert "Домашний Mac · сеть по IP: First Network" in messages[0]
    assert "Домашний Mac · сеть по IP: Second Network" in messages[1]
    assert "Домашний Mac (device-aabbccdd)" in messages[2]
    assert "сеть по IP:" not in messages[2]
    assert all("Тбилиси" in message and "device-aabbccdd" in message for message in messages)
    assert all("Yerevan" not in message and "Berlin" not in message for message in messages)
    assert report.agent_id == original_identity.agent_id
    assert report.sequence == 2
    assert settings.identity == original_identity
    assert settings.agent.state_key == original_key
    assert _db(settings).event_count() == 3


@pytest.mark.asyncio
async def test_manual_name_default_does_not_lookup_network(tmp_path):
    from litechecker import standalone
    from litechecker.network_identity import NetworkIdentity

    settings = _settings(tmp_path)
    calls = []

    async def lookup():
        calls.append(True)
        return NetworkIdentity(provider="Unrequested Network")

    messages = []

    def telegram(request):
        messages.append(json.loads(request.content)["text"])
        return _accepted()

    await standalone.run_standalone(
        settings,
        once=True,
        dependencies=_dependencies(tmp_path, Clock()),
        telegram=_telegram(telegram),
        network_lookup=lookup,
    )
    assert calls == []
    assert "Домашний Mac (device-aabbccdd)" in messages[0]
    assert "Unrequested Network" not in messages[0]


@pytest.mark.asyncio
async def test_network_lookup_exception_does_not_block_monitoring(tmp_path):
    from litechecker import standalone

    settings = _settings(tmp_path)
    settings.auto_network = True

    async def lookup():
        raise OSError("network unavailable")

    report = await standalone.run_standalone(
        settings,
        once=True,
        dependencies=_dependencies(tmp_path, Clock()),
        telegram=_telegram(lambda request: _accepted()),
        network_lookup=lookup,
    )
    assert report.sequence == 0
    assert len(report.results) == 3
    assert _db(settings).storage_stats()["completed_notifications"] == 1


@pytest.mark.asyncio
async def test_city_and_network_refresh_together_once_per_cycle_with_stable_identity(tmp_path):
    from litechecker import standalone
    from litechecker.network_identity import NetworkIdentity

    settings = _settings(tmp_path)
    settings.auto_network = True
    settings.auto_city = True
    settings.identity = replace(settings.identity, city="Город не определён")
    original_identity = settings.identity
    original_key = settings.agent.state_key
    clock = Clock()
    dependencies = _dependencies(tmp_path, clock)
    identities = iter([
        NetworkIdentity(provider="First Network", city="Yerevan", country="AM"),
        NetworkIdentity(provider="Second Network", city="Tbilisi", country="GE"),
        None,
    ])
    looked_up_at = []
    messages = []

    async def lookup():
        looked_up_at.append(clock.elapsed)
        return next(identities)

    def telegram(request):
        if clock.elapsed < 60:
            return httpx.Response(503)
        messages.append(json.loads(request.content)["text"])
        return _accepted()

    report = await standalone.run_standalone(
        settings,
        dependencies=dependencies,
        telegram=_telegram(telegram),
        network_lookup=lookup,
        max_cycles=3,
    )

    assert looked_up_at == [0, 600, 1200]
    assert dependencies.fetcher.fetched_at == [0, 600, 1200]
    assert len(messages) == 3
    assert "Yerevan, AM (по IP)" in messages[0]
    assert "сеть по IP: First Network" in messages[0]
    assert "Tbilisi, GE (по IP)" in messages[1]
    assert "сеть по IP: Second Network" in messages[1]
    assert "Город не определён" in messages[2]
    assert "Yerevan" not in messages[2] and "Tbilisi" not in messages[2]
    assert "сеть по IP:" not in messages[2]
    assert all("device-aabbccdd" in message for message in messages)
    assert report.agent_id == original_identity.agent_id
    assert settings.identity == original_identity
    assert settings.agent.state_key == original_key
    assert _db(settings).event_count() == 3


@pytest.mark.asyncio
async def test_auto_city_works_with_manual_device_name(tmp_path):
    from litechecker import standalone
    from litechecker.network_identity import NetworkIdentity

    settings = _settings(tmp_path)
    settings.auto_city = True
    settings.auto_network = False
    calls = []
    messages = []

    async def lookup():
        calls.append(True)
        return NetworkIdentity(provider="Network", city="Yerevan", country="AM")

    def telegram(request):
        messages.append(json.loads(request.content)["text"])
        return _accepted()

    await standalone.run_standalone(
        settings,
        once=True,
        dependencies=_dependencies(tmp_path, Clock()),
        telegram=_telegram(telegram),
        network_lookup=lookup,
    )
    assert calls == [True]
    assert "Yerevan, AM (по IP)" in messages[0]
    assert "Домашний Mac (device-aabbccdd)" in messages[0]
    assert "сеть по IP:" not in messages[0]

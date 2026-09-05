"""The native DIRECT daemon is restart-safe, monotonic, and route-isolated."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.direct_check import TrialResult


NOW = datetime(2026, 9, 5, 4, 0, tzinfo=UTC)
TOKEN = "123456789:abcdefghijklmnopqrstuvwxyz12345"
PROXY = "socks5://proxy-user:proxy-password@127.0.0.1:1080"


def secure_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def native_root(tmp_path: Path, *, proxy: bool = False) -> tuple[Path, Path]:
    root = tmp_path / "Native LiteChecker"
    root.mkdir(mode=0o700)
    secure_text(
        root / "native-settings.json",
        json.dumps(
            {
                "LC_AGENT_CITY": "Tbilisi",
                "LC_AGENT_NAME": "Test Mac",
                "LC_TELEGRAM_CHAT_ID": "-5361201677",
                "LC_TELEGRAM_TOPIC_ID": 42,
                "LC_INTERVAL_SECONDS": 17,
                "LC_MAX_CONCURRENCY": 3,
            }
        ),
    )
    secure_text(root / "secrets" / "telegram_bot_token", TOKEN)
    secure_text(root / "secrets" / "subscription_url", "https://subscription.example/private")
    if proxy:
        secure_text(root / "secrets" / "telegram_proxy_url", PROXY)
    xray = root / "runtime" / "xray"
    secure_text(xray, "fixture executable")
    xray.chmod(0o700)
    return root, xray


def test_settings_use_canonical_native_state_and_preserve_identity(tmp_path):
    from litechecker.direct_service import service_settings

    root, xray = native_root(tmp_path)
    first = service_settings(root.resolve(), xray.resolve(), environment={})
    restarted = service_settings(root.resolve(), xray.resolve(), environment={})

    assert first.state_dir == root / "state" / "native-direct"
    assert first.agent.interval_seconds == restarted.agent.interval_seconds == 600
    assert first.agent.allow_private_targets is False
    assert first.agent.xray_binary == str(xray.resolve())
    assert first.identity.agent_id == restarted.identity.agent_id
    assert first.agent.state_key == restarted.agent.state_key
    assert (first.state_dir / "device.json").stat().st_mode & 0o777 == 0o600
    assert not (root / "state" / "direct-trial").exists()


@pytest.mark.parametrize(
    "unsafe",
    [
        {"LC_ALLOW_PRIVATE_TARGETS": True},
        {"UNKNOWN_NATIVE_SETTING": "secret"},
    ],
)
def test_settings_reject_unknown_or_weakened_native_configuration(tmp_path, unsafe):
    from litechecker.direct_service import service_settings

    root, xray = native_root(tmp_path)
    secure_text(
        root / "native-settings.json",
        json.dumps({"LC_TELEGRAM_CHAT_ID": "-1", **unsafe}),
    )
    with pytest.raises(ValueError, match="native configuration is invalid"):
        service_settings(root.resolve(), xray.resolve(), environment={})


def test_settings_reject_symlinked_configuration_without_reading_target(tmp_path):
    from litechecker.direct_service import service_settings

    root, xray = native_root(tmp_path)
    outside = tmp_path / "outside.json"
    secure_text(outside, json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    (root / "native-settings.json").unlink()
    (root / "native-settings.json").symlink_to(outside)

    with pytest.raises(ValueError, match="native configuration is invalid"):
        service_settings(root.resolve(), xray.resolve(), environment={})


@pytest.mark.asyncio
async def test_each_production_cycle_rediscovers_and_refreshes(monkeypatch, tmp_path):
    from litechecker import direct_check
    from litechecker.direct_service import service_settings
    from litechecker.models import AgentReport, ResultStatus

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    calls = {"discover": 0, "cycle": 0}

    class Network:
        interface = "en0"

    class Relay:
        proxy_url = "socks5://u:p@127.0.0.1:10001"

        def __init__(self, network):
            self.network = network

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def discover():
        calls["discover"] += 1
        return Network()

    async def lookup(**kwargs):
        return direct_check.ExitObservation("1.1.1.1", "Tbilisi", "Fixture ISP")

    async def refreshed_cycle(*args):
        calls["cycle"] += 1
        return AgentReport(
            event_id=f"event-{calls['cycle']}",
            agent_id=settings.identity.agent_id,
            boot_id="boot",
            sequence=calls["cycle"],
            observed_at=NOW,
            duration_ms=5,
            control_status=ResultStatus.UP,
            results=[],
        )

    monkeypatch.setattr(direct_check.MacDirectNetwork, "discover", discover)
    monkeypatch.setattr(direct_check, "DirectRelay", Relay)
    monkeypatch.setattr(direct_check, "lookup_exit", lookup)
    monkeypatch.setattr(direct_check, "scoped_dependencies", lambda *args: object())
    monkeypatch.setattr(direct_check, "run_cycle", refreshed_cycle)

    first = await direct_check.run_trial(settings, production=True)
    second = await direct_check.run_trial(settings, production=True)

    assert calls == {"discover": 2, "cycle": 2}
    assert "DIRECT (macOS)" in first.text and "пробный" not in first.text
    assert second.report.event_id == "event-2"


@pytest.mark.asyncio
async def test_scheduler_waits_only_remainder_from_cycle_start_without_overlap(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    monotonic_value = 10.0
    active = 0
    max_active = 0
    starts = []
    sleeps = []

    def monotonic():
        return monotonic_value

    async def sleep(delay):
        nonlocal monotonic_value
        sleeps.append(delay)
        monotonic_value += delay

    async def cycle(_settings):
        nonlocal monotonic_value, active, max_active
        starts.append(monotonic_value)
        active += 1
        max_active = max(max_active, active)
        monotonic_value += 125
        active -= 1
        return TrialResult(f"cycle {len(starts)}", True)

    await run_service(
        settings,
        send=False,
        cycle=cycle,
        monotonic=monotonic,
        wall_clock=lambda: NOW,
        sleep=sleep,
        max_cycles=2,
    )

    assert starts == [10.0, 610.0]
    assert sleeps == [475.0]
    assert max_active == 1


@pytest.mark.asyncio
async def test_cycle_and_telegram_failures_do_not_stop_later_cycles(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    attempts = 0

    async def cycle(_settings):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("private cycle details")
        return TrialResult("fresh second cycle", True)

    class FailingTelegram:
        async def send_chunks(self, chunks):
            raise RuntimeError("private telegram details")

    async def no_wait(delay):
        return None

    await run_service(
        settings,
        cycle=cycle,
        telegram_factory=lambda _settings: FailingTelegram(),
        monotonic=lambda: 0.0,
        wall_clock=lambda: NOW,
        sleep=no_wait,
        max_cycles=2,
    )

    status = json.loads((settings.state_dir / "status.json").read_text())
    assert attempts == 2
    assert status["last_cycle_status"] == "complete"
    assert status["telegram"]["last_error"] == "telegram-delivery-failed"
    assert status["telegram"]["pending_chunks"] == 2
    assert "private" not in (settings.state_dir / "status.json").read_text()


@pytest.mark.asyncio
async def test_restart_sends_persisted_chunk_before_new_cycle(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})

    class FailingTelegram:
        async def send_chunks(self, chunks):
            raise OSError("offline")

    await run_service(
        settings,
        once=True,
        cycle=lambda _settings: asyncio.sleep(0, result=TrialResult("queued first", True)),
        telegram_factory=lambda _settings: FailingTelegram(),
        wall_clock=lambda: NOW,
    )

    sent = []

    class SuccessfulTelegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)

    await run_service(
        settings,
        once=True,
        cycle=lambda _settings: asyncio.sleep(0, result=TrialResult("new second", True)),
        telegram_factory=lambda _settings: SuccessfulTelegram(),
        wall_clock=lambda: NOW + timedelta(minutes=1),
    )

    assert sent == ["🕓 Отложенная доставка — отчёт сформирован ранее.\n\nqueued first", "new second"]
    status = json.loads((settings.state_dir / "status.json").read_text())
    assert status["telegram"]["pending_chunks"] == 0
    assert status["telegram"]["last_accepted_at"] is not None


@pytest.mark.asyncio
async def test_startup_backlog_flush_is_bounded_before_fresh_measurement(tmp_path):
    from litechecker.direct_outbox import DirectOutbox
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    DirectOutbox(settings.state_dir / "direct-outbox.json").enqueue(
        [f"old-{index}" for index in range(20)], created_at=NOW,
    )
    events = []

    class Telegram:
        async def send_chunks(self, chunks):
            events.append(("sent", chunks[0]))

    async def cycle(_settings):
        events.append(("cycle", "fresh"))
        return TrialResult("fresh", True)

    await run_service(
        settings,
        once=True,
        cycle=cycle,
        telegram_factory=lambda _settings: Telegram(),
        wall_clock=lambda: NOW,
    )

    cycle_index = events.index(("cycle", "fresh"))
    assert cycle_index == 8


@pytest.mark.asyncio
async def test_failed_delivery_retries_between_cycles_without_moving_cadence(tmp_path):
    from litechecker.direct_outbox import DirectOutbox
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    DirectOutbox(settings.state_dir / "direct-outbox.json").enqueue(
        ["persisted"], created_at=NOW,
    )
    monotonic_value = 0.0
    events = []
    attempts = 0

    class Telegram:
        async def send_chunks(self, chunks):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("offline")
            events.append(("sent", chunks[0], monotonic_value))

    async def cycle(_settings):
        events.append(("cycle", monotonic_value))
        return TrialResult(f"fresh-{len(events)}", True)

    async def sleep(delay):
        nonlocal monotonic_value
        monotonic_value += delay

    await run_service(
        settings,
        cycle=cycle,
        telegram_factory=lambda _settings: Telegram(),
        monotonic=lambda: monotonic_value,
        wall_clock=lambda: NOW,
        sleep=sleep,
        max_cycles=2,
    )

    second_cycle = events.index(("cycle", 600.0))
    assert any(event[0] == "sent" and event[1].startswith("🕓 Отложенная доставка")
               and event[1].endswith("persisted") for event in events[:second_cycle])
    assert [event for event in events if event[0] == "cycle"] == [
        ("cycle", 0.0),
        ("cycle", 600.0),
    ]


@pytest.mark.asyncio
async def test_default_cycle_selects_production_formatter(monkeypatch, tmp_path):
    from litechecker import direct_service

    root, xray = native_root(tmp_path)
    settings = direct_service.service_settings(root.resolve(), xray.resolve(), environment={})
    seen = []

    async def trial(received, **kwargs):
        seen.append((received, kwargs))
        return TrialResult("production", True)

    monkeypatch.setattr(direct_service, "run_trial", trial)
    result = await direct_service._production_cycle(settings)

    assert result.text == "production"
    assert seen == [(settings, {"production": True})]


@pytest.mark.asyncio
async def test_no_send_neither_constructs_telegram_nor_queues_report(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})

    def forbidden_factory(_settings):
        raise AssertionError("Telegram must remain closed")

    await run_service(
        settings,
        once=True,
        send=False,
        cycle=lambda _settings: asyncio.sleep(0, result=TrialResult("not sent later", True)),
        telegram_factory=forbidden_factory,
        wall_clock=lambda: NOW,
    )

    status = json.loads((settings.state_dir / "status.json").read_text())
    assert status["telegram"]["pending_chunks"] == 0
    assert not (settings.state_dir / "direct-outbox.json").exists()


@pytest.mark.asyncio
async def test_unavailable_cycle_marks_old_observation_not_fresh(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    old_observation = settings.state_dir / "last-observation.json"
    secure_text(old_observation, '{"old":"observation"}')

    await run_service(
        settings,
        once=True,
        send=False,
        cycle=lambda _settings: asyncio.sleep(
            0,
            result=TrialResult(
                "interface unavailable",
                False,
                reason="direct-interface-unavailable",
                observed_at=NOW,
            ),
        ),
        wall_clock=lambda: NOW,
    )

    status = json.loads((settings.state_dir / "status.json").read_text())
    assert status["last_cycle_status"] == "unavailable"
    assert status["last_observation_fresh"] is False
    assert old_observation.read_text() == '{"old":"observation"}'


@pytest.mark.asyncio
async def test_incomplete_current_report_is_not_marked_fresh_complete(tmp_path):
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})

    await run_service(
        settings,
        once=True,
        send=False,
        cycle=lambda _settings: asyncio.sleep(
            0,
            result=TrialResult("incomplete", False, report=object(), observed_at=NOW),
        ),
        wall_clock=lambda: NOW,
    )

    status = json.loads((settings.state_dir / "status.json").read_text())
    assert status["last_cycle_status"] == "incomplete"
    assert status["last_observation_fresh"] is False
    assert status["last_cycle_error"] is None


@pytest.mark.asyncio
async def test_single_instance_lock_rejects_overlap(tmp_path):
    from litechecker.direct_service import ServiceAlreadyRunning, run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_cycle(_settings):
        entered.set()
        await release.wait()
        return TrialResult("done", True)

    first = asyncio.create_task(
        run_service(settings, once=True, send=False, cycle=blocking_cycle, wall_clock=lambda: NOW)
    )
    await entered.wait()
    try:
        with pytest.raises(ServiceAlreadyRunning, match="service-lock-unavailable"):
            await run_service(
                settings,
                once=True,
                send=False,
                cycle=lambda _settings: asyncio.sleep(0, result=TrialResult("wrong", True)),
                wall_clock=lambda: NOW,
            )
    finally:
        release.set()
        await first


def test_telegram_factory_builds_real_client_with_independent_proxy(tmp_path, monkeypatch):
    from litechecker.collector import telegram
    from litechecker.collector.telegram import TelegramClient
    from litechecker.direct_service import service_settings, telegram_client

    root, xray = native_root(tmp_path, proxy=True)
    settings = service_settings(root.resolve(), xray.resolve(), environment={})
    captured = {}

    class Transport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(telegram.httpx, "AsyncHTTPTransport", Transport)
    client = telegram_client(settings)

    assert isinstance(client, TelegramClient)
    assert client._chat_id == "-5361201677"
    assert client._topic_id == 42
    assert captured == {"proxy": PROXY, "trust_env": False}


@pytest.mark.parametrize(
    ("result", "no_send", "expected"),
    [
        (SimpleNamespace(available=False, delivery_accepted=False), False, 1),
        (SimpleNamespace(available=True, delivery_accepted=False), False, 1),
        (SimpleNamespace(available=True, delivery_accepted=None), True, 0),
    ],
)
def test_once_exit_status_requires_complete_cycle_and_requested_delivery(
    monkeypatch, result, no_send, expected,
):
    from litechecker import direct_service

    monkeypatch.setattr(direct_service, "service_settings", lambda *args, **kwargs: object())

    async def service(*args, **kwargs):
        return result

    monkeypatch.setattr(direct_service, "run_service", service)
    arguments = ["--root", "/fixture/root", "--xray", "/fixture/xray", "--once"]
    if no_send:
        arguments.append("--no-send")
    assert direct_service.main(arguments) == expected


@pytest.mark.asyncio
async def test_delayed_backlog_is_labelled_but_current_cycle_is_not(tmp_path):
    from litechecker.direct_outbox import DirectOutbox
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve())
    box = DirectOutbox(settings.state_dir / "direct-outbox.json")
    box.enqueue([f"old-{i}" for i in range(9)], created_at=NOW)
    sent = []

    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)

    result = await run_service(
        settings, once=True, wall_clock=lambda: NOW + timedelta(minutes=20),
        cycle=lambda _: asyncio.sleep(0, result=TrialResult("current", True)),
        telegram_factory=lambda _: Telegram(),
    )
    assert len(sent) == 10 and sent[-1] == "current"
    assert all(part.startswith("🕓 Отложенная доставка") for part in sent[:-1])
    assert all(sent[i].endswith(f"old-{i}") for i in range(9))
    assert result.delivery_accepted is True and box.status()["pending_chunks"] == 0


@pytest.mark.asyncio
async def test_delayed_max_length_chunk_is_labelled_without_losing_content_or_ack(tmp_path):
    from litechecker.direct_outbox import DirectOutbox
    from litechecker.direct_service import _drain

    box = DirectOutbox(tmp_path / "direct-outbox.json")
    box.enqueue(["x" * 4096], created_at=NOW)
    sent = []

    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)

    assert await _drain(box, None, lambda _: Telegram(), lambda: NOW)
    assert len(sent) > 1 and all(len(part) <= 3500 for part in sent)
    assert all(part.startswith("🕓 Отложенная доставка") for part in sent)
    assert sum(part.count("x") for part in sent) == 4096
    assert box.status()["pending_chunks"] == 0


@pytest.mark.asyncio
async def test_delayed_split_partial_failure_preserves_original_pending_chunk(tmp_path):
    from litechecker.direct_outbox import DirectOutbox
    from litechecker.direct_service import _drain

    box = DirectOutbox(tmp_path / "direct-outbox.json")
    box.enqueue(["x" * 4096], created_at=NOW)
    original = box.next_chunk()
    accepted = []

    class BrokenTelegram:
        async def send_chunks(self, chunks):
            accepted.append(chunks[0])
            raise RuntimeError("second part failed")

    assert not await _drain(box, None, lambda _: BrokenTelegram(), lambda: NOW)
    assert accepted and box.next_chunk() == original
    retried = []

    class Telegram:
        async def send_chunks(self, chunks):
            retried.extend(chunks)

    assert await _drain(box, None, lambda _: Telegram(), lambda: NOW)
    assert retried[0] == accepted[0]
    assert sum(part.count("x") for part in retried) == 4096
    assert box.status()["pending_chunks"] == 0


@pytest.mark.asyncio
async def test_native_cycle_waits_for_update_maintenance_boundary(tmp_path):
    from filelock import AsyncFileLock
    from litechecker.direct_service import run_service, service_settings

    root, xray = native_root(tmp_path)
    settings = service_settings(root.resolve(), xray.resolve())
    entered = asyncio.Event()

    async def cycle(_):
        entered.set()
        return TrialResult("fixture", True)

    async with AsyncFileLock(settings.state_dir / "maintenance.lock", run_in_executor=True):
        task = asyncio.create_task(run_service(settings, once=True, send=False, cycle=cycle))
        await asyncio.sleep(0.1)
        blocked = not entered.is_set()
    await asyncio.wait_for(task, 2)
    assert blocked and entered.is_set()

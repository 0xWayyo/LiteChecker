"""A mixed-network cycle must never be delivered as endpoint evidence."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from litechecker import direct_check, macos_network
from litechecker.collector.auth import AgentIdentity
from litechecker.direct_network import DirectNetworkUnavailable
from litechecker.measurement import make_measurement_dependencies
from litechecker.models import ProbeResult, ProbeStage, ResultStatus
from litechecker.probe import ControlResult
from test_agent import _settings, _subscription
from test_direct_network import ACTIVE, HARDWARE, network


def changing_mac(monkeypatch):
    network(monkeypatch)
    state = {"address": "192.168.1.20", "dns": "192.168.1.1", "active": True}

    async def run(*args):
        if args[0].endswith("networksetup"):
            return HARDWARE.split("Hardware Port: USB Ethernet")[0]
        if args[0].endswith("ifconfig"):
            text = ACTIVE.replace("192.168.1.20", state["address"])
            return text if state["active"] else text.replace("status: active", "status: inactive")
        assert args == ("/usr/sbin/ipconfig", "getoption", "en0", "domain_name_server")
        return state["dns"]

    monkeypatch.setattr(macos_network, "_run", run)
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [{"address": "10.0.0.20"}, {"dns": "10.0.0.1"}, {"active": False}])
async def test_same_en0_index_does_not_hide_changed_source_or_dns(monkeypatch, change):
    state = changing_mac(monkeypatch)
    direct = await macos_network.MacDirectNetwork.discover()
    state.update(change)
    validator = getattr(direct, "validate_snapshot", None)
    assert callable(validator), "the old validator only checks en0's numeric index"
    with pytest.raises(DirectNetworkUnavailable):
        await validator()


@pytest.mark.asyncio
async def test_unchanged_snapshot_can_be_validated_without_mutating_the_network(monkeypatch):
    changing_mac(monkeypatch)
    direct = await macos_network.MacDirectNetwork.discover()
    validator = getattr(direct, "validate_snapshot", None)
    assert callable(validator)
    await validator()
    assert direct.source_addresses == ("192.168.1.20", "fe80::abcd")


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    state = changing_mac(monkeypatch)
    events = []
    calls = {"fetch": 0, "control": 0, "probe": 0}
    settings = SimpleNamespace(
        agent=_settings(run_deadline_seconds=10), state_dir=tmp_path,
        identity=AgentIdentity("agent-1", "City", "Test Mac", 600),
    )

    class Relay:
        def __init__(self, net):
            self.net = net
            self.proxy_url = "socks5://" + net.source_addresses[0]
        async def __aenter__(self):
            events.append(("open", self.net.source_addresses[0]))
            return self
        async def __aexit__(self, *args):
            events.append(("close", self.net.source_addresses[0]))

    async def lookup(*, proxy_url=None):
        events.append(("exit", proxy_url))
        ip = "8.8.8.8" if proxy_url and "10.0.0.20" in proxy_url else "1.1.1.1"
        return direct_check.ExitObservation(ip, "New City" if ip == "8.8.8.8" else "Old City")

    async def control():
        calls["control"] += 1
        return ControlResult(ok=True)

    class Fetcher:
        async def fetch(self):
            calls["fetch"] += 1
            return _subscription(calls["fetch"])

    async def probe(targets, control, deadline):
        calls["probe"] += 1
        if calls["probe"] == 1:
            state.update(address="10.0.0.20", dns="10.0.0.1")
            try:
                await asyncio.sleep(0.2)
            finally:
                events.append(("probe-cleaned", calls["probe"]))
        return [ProbeResult(
            target_id=t.target_id, label=t.label, address=t.address, port=t.port,
            status=ResultStatus.UP, stage=ProbeStage.E2E,
        ) for t in targets]

    def dependencies(settings, net, relay):
        deps = make_measurement_dependencies(settings.agent, state_dir=settings.state_dir)
        deps.fetcher = Fetcher()
        deps.control_checker = control
        deps.version_checker = None
        deps.prober = probe
        return deps

    monkeypatch.setattr(direct_check, "DirectRelay", Relay)
    monkeypatch.setattr(direct_check, "lookup_exit", lookup)
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    # Time boundaries only; real discovery parsing, measurement, state and reports remain active.
    monkeypatch.setattr(direct_check, "_NETWORK_RETRY_DELAY", 0.001, raising=False)
    return SimpleNamespace(state=state, events=events, calls=calls, settings=settings)


@pytest.mark.asyncio
async def test_switch_discards_old_targets_and_refetches_on_fresh_network(scenario):
    result = await direct_check.run_trial(scenario.settings, production=True)
    assert result.available
    assert scenario.calls["fetch"] == 2, "network restart must fetch the subscription again"
    assert scenario.calls["control"] == 2
    assert {r.address for r in result.report.results} == {"node-2.example", "www.example.com"}
    assert "Old City" not in result.text and "New City" in result.text
    assert "Сеть изменилась" in result.text
    assert "node-1.example" not in result.text
    assert scenario.events.index(("close", "192.168.1.20")) < scenario.events.index(("open", "10.0.0.20"))
    payload = json.loads((scenario.settings.state_dir / "last-observation.json").read_text())
    assert payload["scoped_exit"]["ip"] == "8.8.8.8"
    assert {r["address"] for r in payload["report"]["results"]} == {"node-2.example", "www.example.com"}


@pytest.mark.asyncio
async def test_unrecoverable_switch_sends_one_notice_without_endpoint_failures(scenario, monkeypatch):
    original = direct_check.scoped_dependencies
    def dependencies(*args):
        deps = original(*args)
        async def lost_network(*args):
            scenario.state["active"] = False
            return []
        deps.prober = lost_network
        return deps
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    sent = []
    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)
    result = await direct_check.run_trial(scenario.settings, send=True, telegram=Telegram())
    assert result.report is None and not result.available
    assert result.reason == "direct-network-unverifiable"
    assert sent == [result.text]
    assert "node-" not in result.text and "Всё доступно" not in result.text
    saved = json.loads((scenario.settings.state_dir / "last-observation.json").read_text())
    assert saved["report"] is None
    assert saved["reason"] == "direct-network-unverifiable"
    attempts = json.loads((scenario.settings.state_dir / "last-probe-attempts.json").read_text())
    assert attempts["attempts"] == []
    assert attempts["interrupted_reason"] == "direct-network-unverifiable"
    assert attempts["event_id"] is None


@pytest.mark.asyncio
async def test_network_flapping_is_bounded_to_one_restart(scenario, monkeypatch):
    original = direct_check.scoped_dependencies
    def dependencies(*args):
        deps = original(*args)
        async def flap(*args):
            scenario.calls["probe"] += 1
            scenario.state["dns"] = f"10.0.0.{scenario.calls['probe']}"
            return []
        deps.prober = flap
        return deps
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    result = await direct_check.run_trial(scenario.settings, production=True)
    assert scenario.calls["probe"] == 2
    assert not result.available and result.report is None
    assert result.reason == "direct-network-changed"
    assert "node-" not in result.text


@pytest.mark.asyncio
async def test_failed_control_on_new_network_does_not_dump_unknown_endpoints(scenario, monkeypatch):
    original = direct_check.scoped_dependencies
    def dependencies(settings, net, relay):
        deps = original(settings, net, relay)
        if net.source_addresses[0] == "10.0.0.20":
            async def failed_control():
                return ControlResult(ok=False, error_code="control-failed")
            deps.control_checker = failed_control
        return deps
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    result = await direct_check.run_trial(scenario.settings, production=True)
    assert not result.available and result.report is None
    assert result.reason == "direct-network-changed"
    assert "node-" not in result.text and "www.example.com" not in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["subscription", "xray", "deadline", "exception"])
async def test_failed_retry_after_switch_sends_only_short_notice(scenario, monkeypatch, failure):
    from litechecker.measurement import SubscriptionFetchError
    from litechecker.direct_service import run_service
    original = direct_check.scoped_dependencies
    lookup = direct_check.lookup_exit

    async def exit_lookup(*, proxy_url=None):
        if failure == "exception" and proxy_url and "10.0.0.20" in proxy_url:
            raise OSError("private diagnostic must not be sent")
        return await lookup(proxy_url=proxy_url)

    def dependencies(settings, net, relay):
        deps = original(settings, net, relay)
        if net.source_addresses[0] != "10.0.0.20":
            return deps
        if failure == "subscription":
            class Unavailable:
                async def fetch(self):
                    raise SubscriptionFetchError("fetch-failed")
            deps.fetcher = Unavailable()
        elif failure in {"xray", "deadline"}:
            async def incomplete(targets, control, deadline):
                if failure == "deadline":
                    raise TimeoutError
                return [ProbeResult(
                    target_id=t.target_id, label=t.label, address=t.address, port=t.port,
                    check_kind=t.check_kind, status=ResultStatus.UNKNOWN,
                    stage=ProbeStage.XRAY, error_code="xray-error",
                ) for t in targets]
            deps.prober = incomplete
        return deps

    monkeypatch.setattr(direct_check, "lookup_exit", exit_lookup)
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    sent = []
    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)
    result = await run_service(scenario.settings, once=True, telegram_factory=lambda _: Telegram())
    assert not result.available and result.report is None
    assert result.reason == "direct-network-changed"
    assert sent == [result.text]
    assert "Сеть изменилась, повтор не завершён" in result.text
    assert "Ниже — результаты" not in result.text and "private diagnostic" not in result.text
    assert "node-" not in result.text and "VPN:" not in result.text
    saved = json.loads((scenario.settings.state_dir / "last-observation.json").read_text())
    assert saved["report"] is None and saved["reason"] == "direct-network-changed"


@pytest.mark.asyncio
async def test_confirmed_down_on_new_network_is_still_reported(scenario, monkeypatch):
    from litechecker import recheck
    monkeypatch.setattr(recheck, "RECHECK_DELAY_SECONDS", 0.001)
    original = direct_check.scoped_dependencies
    confirmations = []
    def dependencies(settings, net, relay):
        deps = original(settings, net, relay)
        if net.source_addresses[0] == "10.0.0.20":
            async def unavailable(targets, control, deadline):
                confirmations.append([t.target_id for t in targets])
                return [ProbeResult(
                    target_id=t.target_id, label=t.label, address=t.address, port=t.port,
                    check_kind=t.check_kind, status=ResultStatus.DOWN,
                    stage=ProbeStage.TCP, error_code="tcp-timeout",
                ) for t in targets]
            deps.prober = unavailable
        return deps
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    result = await direct_check.run_trial(scenario.settings, production=True)
    assert result.available and result.report is not None
    assert len(confirmations) == 2
    assert result.report.refresh_state == "FRESH" and result.reason is None
    assert all(r.status is ResultStatus.DOWN for r in result.report.results)
    assert "Ниже — результаты новой проверки" in result.text and "node-2.example" in result.text
    assert "node-1.example" not in result.text and "Всё доступно" not in result.text


@pytest.mark.asyncio
async def test_mid_probe_change_cancels_and_joins_before_restart(scenario, monkeypatch):
    from litechecker import direct_guard
    monkeypatch.setattr(direct_guard, "_POLL_SECONDS", 0.01)
    original = direct_check.scoped_dependencies
    cancelled = asyncio.Event()
    def dependencies(*args):
        deps = original(*args)
        successful = deps.prober
        async def probe(*args):
            if scenario.calls["probe"] == 0:
                scenario.calls["probe"] += 1
                scenario.state.update(address="10.0.0.20", dns="10.0.0.1")
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(0.01)
                    cancelled.set()
            assert cancelled.is_set(), "old probe cleanup must finish before new probes start"
            return await successful(*args)
        deps.prober = probe
        return deps
    monkeypatch.setattr(direct_check, "scoped_dependencies", dependencies)
    async with asyncio.timeout(2):
        result = await direct_check.run_trial(scenario.settings, production=True)
    assert result.available and cancelled.is_set()
    assert scenario.calls["fetch"] == 2


@pytest.mark.asyncio
async def test_user_stop_during_restart_does_not_restart_or_send(scenario, monkeypatch):
    monkeypatch.setattr(direct_check, "_NETWORK_RETRY_DELAY", 10)
    sent = []
    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)
    task = asyncio.create_task(direct_check.run_trial(scenario.settings, send=True, telegram=Telegram()))
    try:
        async with asyncio.timeout(2):
            path = scenario.settings.state_dir / "last-observation.json"
            while not path.exists():
                await asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not sent
        assert scenario.calls["fetch"] == 1
        assert json.loads(path.read_text())["report"] is None
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_guard_keeps_cleanup_attached_under_repeated_stop():
    from litechecker.direct_guard import guard_network
    entered, cleaning, release, cleaned = (asyncio.Event() for _ in range(4))
    class Network:
        async def validate_snapshot(self):
            pass
    async def operation():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()
            cleaned.set()
    task = asyncio.create_task(guard_network(Network(), operation))
    try:
        await entered.wait()
        task.cancel()
        await cleaning.wait()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not cleaned.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_hung_validation_cancels_measurement_instead_of_approving_it(monkeypatch):
    from litechecker import direct_guard
    monkeypatch.setattr(direct_guard, "_POLL_SECONDS", 0.005)
    monkeypatch.setattr(direct_guard, "_VALIDATION_SECONDS", 0.02)
    cleaned = asyncio.Event()
    validations = 0
    class Network:
        async def validate_snapshot(self):
            nonlocal validations
            validations += 1
            if validations > 1:
                await asyncio.Event().wait()
    async def operation():
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()
    with pytest.raises(direct_guard.NetworkInterrupted, match="direct-network-unverifiable"):
        await direct_guard.guard_network(Network(), operation)
    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_restarted_cycle_shares_original_total_deadline(scenario, monkeypatch):
    from litechecker.direct_guard import NetworkInterrupted
    original_timeout = asyncio.timeout
    calls = []
    def short_deadline(seconds):
        return original_timeout(0.1)
    async def attempt(*args, **kwargs):
        calls.append(len(calls))
        await asyncio.sleep(0.07)
        if len(calls) == 1:
            raise NetworkInterrupted(changed=True)
        raise AssertionError("retry was incorrectly granted a fresh full deadline")
    monkeypatch.setattr(direct_check.asyncio, "timeout", short_deadline)
    monkeypatch.setattr(direct_check, "_run_trial", attempt)
    result = await direct_check.run_trial(scenario.settings, production=True)
    assert len(calls) == 2
    assert not result.available and result.report is None
    assert result.reason == "direct-network-changed"


@pytest.mark.asyncio
async def test_service_outbox_delivers_only_fresh_restarted_result(scenario):
    from litechecker.direct_service import run_service
    sent = []
    class Telegram:
        async def send_chunks(self, chunks):
            sent.extend(chunks)
    result = await run_service(scenario.settings, once=True, telegram_factory=lambda _: Telegram())
    assert result.available and result.delivery_accepted
    assert len(sent) == 1 and "node-1.example" not in sent[0]
    assert "New City" in sent[0] and "Old City" not in sent[0]
    status = json.loads((scenario.settings.state_dir / "status.json").read_text())
    assert status["last_observation_fresh"] is True
    assert status["telegram"]["pending_chunks"] == 0


@pytest.mark.asyncio
async def test_switch_during_probe_deadline_cleanup_does_not_cancel_cleanup_twice(monkeypatch):
    from litechecker import direct_guard, probe
    cleaning, cleaned = asyncio.Event(), asyncio.Event()
    async def target(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await asyncio.sleep(0.03)
            cleaned.set()
    class Network:
        count = 0
        async def validate_snapshot(self):
            self.count += 1
            if self.count > 1:
                await cleaning.wait()
                raise DirectNetworkUnavailable("interface_changed")
    async def operation():
        return await probe.probe_all(
            [object()], control=ControlResult(ok=True), max_concurrency=1, deadline_seconds=0.001,
        )
    monkeypatch.setattr(probe, "probe_target", target)
    monkeypatch.setattr(direct_guard, "_POLL_SECONDS", 0.005)
    with pytest.raises(direct_guard.NetworkInterrupted):
        await direct_guard.guard_network(Network(), operation)
    assert cleaned.is_set(), "second cancellation interrupted the already running child cleanup"


@pytest.mark.asyncio
async def test_stopping_watcher_joins_discovery_process_already_timing_out(monkeypatch):
    killing, release, reaped = (asyncio.Event() for _ in range(3))
    class Process:
        returncode = None
        async def communicate(self):
            raise TimeoutError
        def kill(self):
            killing.set()
        async def wait(self):
            await release.wait()
            reaped.set()
            self.returncode = -9
    async def spawn(*args, **kwargs):
        return Process()
    monkeypatch.setattr(macos_network.asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(macos_network._run("/sbin/ifconfig", "en0"))
    try:
        await killing.wait()
        task.cancel()
        await asyncio.sleep(0.01)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert reaped.is_set(), "cancelled watcher detached a discovery child before wait completed"
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancel_during_natural_relay_close_preserves_client_cleanup():
    from litechecker.direct_relay import DirectRelay
    entered, cleaning, release, cleaned = (asyncio.Event() for _ in range(4))
    async def client():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()
            cleaned.set()
    relay = DirectRelay(object())
    child = asyncio.create_task(client())
    await entered.wait()
    relay._tasks.add(child)
    task = asyncio.create_task(relay.__aexit__(None, None, None))
    try:
        await cleaning.wait()
        task.cancel()
        await asyncio.sleep(0.01)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set(), "relay client cleanup was interrupted during normal __aexit__"
    finally:
        release.set()
        await asyncio.gather(task, child, return_exceptions=True)

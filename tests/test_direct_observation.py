"""Retain one private, credential-free observation for troubleshooting."""

import json
import stat
from datetime import UTC, datetime

from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus


def observation():
    return AgentReport(
        event_id="test:boot:1", agent_id="test", boot_id="boot", sequence=1,
        observed_at=datetime(2026, 9, 5, tzinfo=UTC), duration_ms=20,
        control_status=ResultStatus.UP, run_status=ResultStatus.UNKNOWN,
        run_reason="probe-incomplete",
        results=[ProbeResult(
            target_id="configuration-one", label="Test", address="example.com", port=443,
            status=ResultStatus.UNKNOWN, stage=ProbeStage.POLICY,
            error_code="direct-dns:direct_dns_timeout",
        )],
    )


def test_last_observation_keeps_exact_reason_without_settings_or_credentials(tmp_path):
    from litechecker.direct_check import ExitObservation
    from litechecker.direct_observation import save_last_observation

    state_dir = tmp_path / "state"
    path = save_last_observation(
        state_dir, observation(), interface="en0",
        scoped_exit=ExitObservation("1.1.1.1", "City", "AS123 ISP"),
        ordinary_exit=ExitObservation("8.8.8.8"),
    )
    payload = json.loads(path.read_text())
    assert path == state_dir / "last-observation.json"
    assert payload["report"]["results"][0]["error_code"] == "direct-dns:direct_dns_timeout"
    assert payload["report"]["results"][0]["target_id"] == "configuration-one"
    assert payload["scoped_exit"]["ip"] == "1.1.1.1"
    assert payload["ordinary_exit"]["ip"] == "8.8.8.8"
    assert payload["vpn_bypass_confirmed"] is False
    assert set(payload) == {
        "schema_version", "interface", "scoped_exit", "ordinary_exit",
        "vpn_bypass_confirmed", "report",
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700


def test_latest_cycle_replaces_previous_observation_without_accumulating_files(tmp_path):
    from litechecker.direct_observation import save_last_observation

    first = observation()
    save_last_observation(tmp_path, first, interface="en0", scoped_exit=None, ordinary_exit=None)
    second = first.model_copy(update={"event_id": "test:boot:2", "sequence": 2})
    path = save_last_observation(tmp_path, second, interface="en0", scoped_exit=None, ordinary_exit=None)
    payload = json.loads(path.read_text())
    assert payload["report"]["sequence"] == 2
    assert payload["ordinary_exit"] is None
    assert list(tmp_path.iterdir()) == [path]


def test_existing_symlink_does_not_overwrite_its_destination(tmp_path):
    from litechecker.direct_observation import save_last_observation

    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve this")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "last-observation.json").symlink_to(unrelated)
    path = save_last_observation(state_dir, observation(), interface="en0", scoped_exit=None, ordinary_exit=None)
    assert unrelated.read_text() == "preserve this"
    assert not path.is_symlink()
    assert json.loads(path.read_text())["report"]["sequence"] == 1

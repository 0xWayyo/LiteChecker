"""Version belongs to the loaded agent, never its launcher or renderer."""
import importlib.util
import json
import hashlib
from pathlib import Path

import pytest

from litechecker.models import AgentReport
from test_direct_production_reporting import IDENTITY, NOW, SCOPED, ORDINARY, make_report


def version_module():
    from litechecker import app_version
    return app_version


def load_source_version(tmp_path, project):
    module = version_module()
    root = tmp_path / "managed release"
    package = root / "src/litechecker"
    package.mkdir(parents=True)
    entry = package / "app_version.py"
    entry.write_bytes(Path(module.__file__).read_bytes())
    (root / "pyproject.toml").write_text(project)
    spec = importlib.util.spec_from_file_location("isolated_version", entry)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_source_version_comes_from_loaded_release_not_working_directory(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="litechecker"\nversion="0.1.0"\n')
    monkeypatch.chdir(tmp_path)
    loaded = load_source_version(tmp_path, '[project]\nname="litechecker"\nversion="0.7.2"\n')
    assert loaded.running_version() == "0.7.2"


@pytest.mark.parametrize("project", [
    '[project]\nname="litechecker"\nversion="not-a-version"',
    '[project]\nname="other"\nversion="0.7.2"',
    'invalid toml',
    'project = 42',
    'project = []',
])
def test_broken_source_metadata_does_not_use_installed_baseline_version(tmp_path, project):
    loaded = load_source_version(tmp_path, project)
    assert loaded.running_version() is None


@pytest.mark.parametrize("platform", ["macOS", "Windows"])
@pytest.mark.parametrize("kind", ["healthy", "failed", "incomplete", "empty"])
def test_direct_report_keeps_agent_version_after_storage_roundtrip(platform, kind):
    from litechecker.direct_reporting import format_direct
    from litechecker.models import ResultStatus, ProbeStage
    report = make_report()
    if kind == "failed":
        report.results[0] = report.results[0].model_copy(update={
            "status": ResultStatus.DOWN, "stage": ProbeStage.TCP, "error_code": "tcp-timeout"})
    elif kind == "incomplete":
        report.results[0] = report.results[0].model_copy(update={
            "status": ResultStatus.UNKNOWN, "stage": ProbeStage.XRAY, "error_code": "xray-error"})
    elif kind == "empty":
        report = report.model_copy(update={"results": [], "run_status": ResultStatus.UNKNOWN,
                                           "run_reason": "no-valid-snapshot"})
    payload = report.model_dump(mode="json")
    payload["app_version"] = "0.5.9"
    restored = AgentReport.model_validate_json(json.dumps(payload))
    text = format_direct(restored, IDENTITY, "en0", SCOPED, ORDINARY, platform_label=platform)
    assert text.endswith("ID: device-fixture · v0.5.9")
    assert text.count("v0.5.9") == 1


@pytest.mark.parametrize("platform", ["macOS", "Windows"])
def test_unavailable_report_has_running_version_by_agent_id(monkeypatch, platform):
    from litechecker import direct_reporting
    monkeypatch.setattr(direct_reporting, "running_version", lambda: "0.7.2", raising=False)
    text = direct_reporting.format_unavailable(IDENTITY, "direct-exit-unavailable", NOW, platform_label=platform)
    assert text.endswith("ID: device-fixture · v0.7.2")


def test_collector_uses_reporting_agent_version_not_its_own():
    from litechecker.collector.reporting import format_report
    from test_reporting import _report, AGENT
    payload = _report().model_dump(mode="json")
    payload["app_version"] = "0.5.9"
    report = AgentReport.model_validate(payload)
    text = format_report(report, AGENT, received_at=NOW)
    assert "ID: agent-1 · v0.5.9" in text
    assert text.count("agent-1") == 1


def test_legacy_report_without_version_is_explicitly_unknown():
    from litechecker.direct_reporting import format_direct
    text = format_direct(make_report(), IDENTITY, "en0", SCOPED, ORDINARY)
    assert text.endswith("ID: device-fixture · v?")


def test_legacy_report_digest_is_unchanged_when_version_is_absent():
    from litechecker.collector.db import _safe_report_digest
    # Payload emitted before app_version existed; retrying it after upgrading
    # the collector must still match an already accepted event.
    payload = {
        "schema_version": 1, "event_id": "agent:boot:1", "agent_id": "agent", "boot_id": "boot",
        "sequence": 1, "observed_at": "2026-09-05T02:00:00Z", "duration_ms": 100,
        "subscription_revision": None, "refresh_state": "FRESH", "snapshot_age_seconds": None,
        "diff": {"added": [], "removed": [], "changed": []}, "results": [],
        "control_status": "UP", "run_status": "UP", "run_reason": None,
        "xray_version": None, "dropped_report_count": 0,
    }
    previous_digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True,
                                               separators=(",", ":")).encode()).hexdigest()
    report = AgentReport.model_validate(payload)
    assert _safe_report_digest(report) == previous_digest
    assert _safe_report_digest(report.model_copy(update={"app_version": "0.7.2"})) != previous_digest


@pytest.mark.parametrize("owned", [True, False])
def test_wheel_metadata_must_belong_to_loaded_module(tmp_path, monkeypatch, owned):
    from importlib.metadata import PathDistribution
    module = version_module()
    package = tmp_path / "site-packages/litechecker"
    package.mkdir(parents=True)
    entry = package / "app_version.py"
    entry.write_bytes(Path(module.__file__).read_bytes())
    meta = (package.parent if owned else tmp_path) / "litechecker-0.7.2.dist-info"
    meta.mkdir()
    (meta / "METADATA").write_text("Metadata-Version: 2.1\nName: litechecker\nVersion: 0.7.2\n")
    spec = importlib.util.spec_from_file_location("wheel_version", entry)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    monkeypatch.setattr(loaded.metadata, "distribution", lambda name: PathDistribution(meta))
    assert loaded.running_version() == ("0.7.2" if owned else None)


@pytest.mark.parametrize("platform", ["macOS", "Windows"])
def test_trial_report_has_original_agent_version(platform):
    from litechecker.direct_check import format_trial
    report = make_report().model_copy(update={"app_version": "0.5.9"})
    text = format_trial(report, IDENTITY, "en0", SCOPED, ORDINARY, platform_label=platform)
    assert text.endswith("ID: device-fixture · v0.5.9")
    assert text.count("device-fixture") == 1


@pytest.mark.parametrize("bad", ["https://secret.example", "0.6.1\n", "v0.6.1", "0.6.1\x1b[0m", "1" * 100, ""])
def test_report_version_rejects_untrusted_non_version_values(bad):
    payload = make_report().model_dump(mode="json")
    payload["app_version"] = bad
    with pytest.raises(ValueError):
        AgentReport.model_validate(payload)

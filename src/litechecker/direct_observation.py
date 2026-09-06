"""The last sanitized DIRECT result, kept locally for diagnosis (not delivery)."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from litechecker.models import AgentReport
from litechecker.state import _atomic_write_json
from litechecker.app_version import running_version

if TYPE_CHECKING:
    from litechecker.direct_check import ExitObservation


def save_last_observation(
    state_dir: Path,
    report: AgentReport,
    *,
    interface: str,
    scoped_exit: ExitObservation | None,
    ordinary_exit: ExitObservation | None,
) -> Path:
    """Replace one mode-0600 result; never serialize settings or subscription configs."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state_dir / "last-observation.json"
    _atomic_write_json(path, {
        "schema_version": 1,
        "interface": interface,
        "scoped_exit": asdict(scoped_exit) if scoped_exit else None,
        "ordinary_exit": asdict(ordinary_exit) if ordinary_exit else None,
        "vpn_bypass_confirmed": False,
        "report": report.model_dump(mode="json"),
    })
    return path


def save_interrupted_observation(state_dir: Path, *, agent_id: str, reason: str, observed_at) -> None:
    """Replace old success with a credential-free, explicitly unmeasured record."""
    if reason not in {"direct-network-changed", "direct-network-unverifiable"}:
        raise ValueError("invalid interruption reason")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _atomic_write_json(state_dir / "last-probe-attempts.json", {
        "event_id": None, "observed_at": observed_at.isoformat(),
        "subscription_revision": None, "attempts": [], "interrupted_reason": reason,
    })
    _atomic_write_json(state_dir / "last-observation.json", {
        "schema_version": 1, "agent_id": agent_id, "app_version": running_version(),
        "observed_at": observed_at.isoformat(), "reason": reason, "report": None,
        "interface": None, "scoped_exit": None, "ordinary_exit": None,
        "vpn_bypass_confirmed": False,
    })

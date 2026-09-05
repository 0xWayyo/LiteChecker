"""The last sanitized DIRECT result, kept locally for diagnosis (not delivery)."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from litechecker.models import AgentReport
from litechecker.state import _atomic_write_json

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

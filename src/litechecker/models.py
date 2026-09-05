"""Validated data contracts shared by probe agents and the collector."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResultStatus(StrEnum):
    UP = "UP"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class ProbeStage(StrEnum):
    E2E = "E2E"
    TLS = "TLS"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    TLS_CERTIFICATE = "TLS_CERTIFICATE"
    DNS = "DNS"
    TCP = "TCP"
    VLESS_E2E = "VLESS_E2E"
    AGENT_NETWORK = "AGENT_NETWORK"
    XRAY = "XRAY"
    DEADLINE = "DEADLINE"
    POLICY = "POLICY"


_STATUS_BY_STAGE = {
    ProbeStage.E2E: ResultStatus.UP,
    ProbeStage.TLS: ResultStatus.UP,
    ProbeStage.TLS_HANDSHAKE: ResultStatus.DOWN,
    ProbeStage.TLS_CERTIFICATE: ResultStatus.DOWN,
    ProbeStage.DNS: ResultStatus.DOWN,
    ProbeStage.TCP: ResultStatus.DOWN,
    ProbeStage.VLESS_E2E: ResultStatus.DOWN,
    ProbeStage.AGENT_NETWORK: ResultStatus.UNKNOWN,
    ProbeStage.XRAY: ResultStatus.UNKNOWN,
    ProbeStage.DEADLINE: ResultStatus.UNKNOWN,
    ProbeStage.POLICY: ResultStatus.UNKNOWN,
}


class TargetConfig(BaseModel):
    """Local-only probe material, including the outbound's sensitive details."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    config_fingerprint: str
    label: str
    address: str
    port: int = Field(ge=1, le=65535)
    address_kind: Literal["ip", "domain"]
    outbound: dict[str, Any]
    check_kind: Literal["vpn", "sni"] = "vpn"


class Snapshot(BaseModel):
    """A persisted, last-known-good set of local probe targets."""

    model_config = ConfigDict(extra="forbid")

    targets: list[TargetConfig]
    subscription_revision: str
    observed_at: datetime


class SnapshotDiff(BaseModel):
    """Collector-safe subscription changes expressed only as stable target IDs."""

    model_config = ConfigDict(extra="forbid")

    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    label: str
    address: str
    port: int = Field(ge=1, le=65535)
    status: ResultStatus
    stage: ProbeStage
    latency_ms: int | None = Field(default=None, ge=0)
    resolved_ips: list[str] = Field(default_factory=list, max_length=16)
    error_code: str | None = Field(default=None, max_length=64)
    check_kind: Literal["vpn", "sni"] = "vpn"

    @model_validator(mode="after")
    def _status_matches_evidence_stage(self) -> "ProbeResult":
        if self.status != _STATUS_BY_STAGE[self.stage]:
            raise ValueError("status must match the evidence stage")
        if self.check_kind == "sni" and self.stage in {
            ProbeStage.E2E, ProbeStage.VLESS_E2E,
        }:
            raise ValueError("SNI domain evidence cannot be VPN evidence")
        if self.check_kind == "vpn" and self.stage in {
            ProbeStage.TLS, ProbeStage.TLS_HANDSHAKE, ProbeStage.TLS_CERTIFICATE,
        }:
            raise ValueError("VPN availability requires end-to-end evidence")
        return self


class AgentReport(BaseModel):
    """Sanitized version-1 payload accepted by the collector."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    event_id: str
    agent_id: str
    boot_id: str
    sequence: int = Field(ge=0)
    observed_at: datetime
    subscription_revision: str | None = None
    refresh_state: Literal["FRESH", "STALE", "UNAVAILABLE"] = "FRESH"
    snapshot_age_seconds: int | None = Field(default=None, ge=0)
    diff: SnapshotDiff = Field(default_factory=SnapshotDiff)
    results: list[ProbeResult] = Field(default_factory=list)
    control_status: Literal[ResultStatus.UP, ResultStatus.UNKNOWN] = ResultStatus.UNKNOWN
    run_status: Literal[ResultStatus.UP, ResultStatus.UNKNOWN] = ResultStatus.UP
    run_reason: Literal[
        "no-valid-snapshot",
        "agent-network",
        "xray-version-unavailable",
        "xray-version-mismatch",
        "deadline",
        "probe-incomplete",
        "mass-removal-quarantine",
    ] | None = None
    duration_ms: int = Field(ge=0)
    xray_version: str | None = Field(default=None, max_length=64)
    dropped_report_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _run_status_matches_reason(self) -> "AgentReport":
        if (self.run_status is ResultStatus.UP) != (self.run_reason is None):
            raise ValueError("run status and reason are inconsistent")
        return self

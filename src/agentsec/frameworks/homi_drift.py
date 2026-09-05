"""Layered Homi Drift report (RISK-08A stable subject binding).

Compares a baseline Homi Snapshot with the current Snapshot across explicit
layers: file digests, capability and persona signal states, combination
Finding deltas, policy observation changes, coverage drift, and the
presentation-only Finding score total.  Every layer is deterministic and
report-only; none of them proves runtime behavior, authorizes an action, or
blocks CI.  Cross-agent comparison is rejected as ``identity_mismatch``
instead of being reported as drift.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.frameworks.homi_snapshot import (
    HomiSnapshot,
    HomiSnapshotContextFindingSummary,
    HomiSnapshotFileSummary,
    HomiSnapshotFindingSummary,
    HomiSnapshotObservationSummary,
    HomiSnapshotOperationContextSummary,
    HomiSnapshotSignalSummary,
    HomiSnapshotStatus,
)
from agentsec.versioning import HOMI_DRIFT_REPORT_VERSION

HOMI_DRIFT_FORMAT: Literal["agentsec-homi-drift-report"] = "agentsec-homi-drift-report"
HOMI_DRIFT_FORMAT_VERSION = HOMI_DRIFT_REPORT_VERSION
HOMI_DRIFT_BASIS = (
    "AgentSec RISK-08C directional Homi Drift report 0.4.0",
    "Layered drift is static report-only evidence, not runtime verification",
    "Agent identity is bound only by explicit stable subject_id",
    "Project name and file-name sets never establish Agent identity",
    "Copy-only changes report file drift without raising risk",
    "Baseline Findings are never double-counted as drift",
    "Cross-agent comparison is rejected as identity_mismatch",
)
_HEX = frozenset("0123456789abcdef")
_SUBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class HomiDriftChangeType(StrEnum):
    """One file or signal layer transition."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class HomiDriftFindingDeltaType(StrEnum):
    """One combination Finding lifecycle transition."""

    ADDED = "added"
    RESOLVED = "resolved"
    INCREASED = "increased"
    DECREASED = "decreased"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


@dataclass(frozen=True, slots=True)
class HomiDriftFileChange:
    """One standard-file digest or state transition."""

    name: str
    change_type: HomiDriftChangeType
    before_state: str
    after_state: str
    before_sha256: str | None
    after_sha256: str | None

    def __post_init__(self) -> None:
        _require_text(self.name, "Homi drift file name")
        if not isinstance(self.change_type, HomiDriftChangeType):
            raise ValueError("Homi drift file change type is invalid")
        _require_text(self.before_state, "Homi drift before state")
        _require_text(self.after_state, "Homi drift after state")
        for label, value in (
            ("before_sha256", self.before_sha256),
            ("after_sha256", self.after_sha256),
        ):
            if value is not None:
                _require_digest(value, f"Homi drift {label}")

    def sort_key(self) -> str:
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "change_type": self.change_type.value,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
        }


@dataclass(frozen=True, slots=True)
class HomiDriftSignalChange:
    """One capability or persona signal state transition."""

    signal_id: str
    scope: str
    change_type: HomiDriftChangeType
    before_state: str
    after_state: str

    def __post_init__(self) -> None:
        _require_text(self.signal_id, "Homi drift signal_id")
        _require_text(self.scope, "Homi drift signal scope")
        if not isinstance(self.change_type, HomiDriftChangeType):
            raise ValueError("Homi drift signal change type is invalid")
        _require_text(self.before_state, "Homi drift signal before state")
        _require_text(self.after_state, "Homi drift signal after state")

    def sort_key(self) -> str:
        return self.signal_id

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "scope": self.scope,
            "change_type": self.change_type.value,
            "before_state": self.before_state,
            "after_state": self.after_state,
        }


@dataclass(frozen=True, slots=True)
class HomiDriftFindingDelta:
    """One combination Finding transition keyed by stable Finding ID."""

    finding_id: str
    rule_id: str
    delta_type: HomiDriftFindingDeltaType
    before_severity: str | None
    after_severity: str | None
    before_score: float | None
    after_score: float | None

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "Homi drift finding_id")
        _require_text(self.rule_id, "Homi drift rule_id")
        if not isinstance(self.delta_type, HomiDriftFindingDeltaType):
            raise ValueError("Homi drift finding delta type is invalid")
        for label, value in (
            ("before_score", self.before_score),
            ("after_score", self.after_score),
        ):
            if value is not None and (
                not isinstance(value, (int, float)) or not 0.0 <= value <= 10.0
            ):
                raise ValueError(f"Homi drift {label} is invalid")

    def sort_key(self) -> str:
        return self.finding_id

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "delta_type": self.delta_type.value,
            "before_severity": self.before_severity,
            "after_severity": self.after_severity,
            "before_score": self.before_score,
            "after_score": self.after_score,
        }


@dataclass(frozen=True, slots=True)
class HomiDriftObservationChange:
    """One policy observation lifecycle transition (control layer)."""

    code: str
    kind: str
    change_type: HomiDriftChangeType

    def __post_init__(self) -> None:
        _require_text(self.code, "Homi drift observation code")
        _require_text(self.kind, "Homi drift observation kind")
        if not isinstance(self.change_type, HomiDriftChangeType):
            raise ValueError("Homi drift observation change type is invalid")

    def sort_key(self) -> tuple[str, str]:
        return (self.code, self.kind)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "kind": self.kind,
            "change_type": self.change_type.value,
        }


@dataclass(frozen=True, slots=True)
class HomiDriftReport:
    """Deterministic, layered, report-only drift between two Snapshots."""

    format: Literal["agentsec-homi-drift-report"]
    format_version: str
    status: HomiSnapshotStatus
    baseline_snapshot_digest: str
    current_snapshot_digest: str
    baseline_workspace_fingerprint: str
    current_workspace_fingerprint: str
    baseline_subject_id: str
    current_subject_id: str
    baseline_project_name: str
    current_project_name: str
    baseline_binding: dict[str, object]
    operation_context_changes: tuple[str, ...]
    context_finding_changes: tuple[str, ...]
    context_score_changed: bool
    risk_direction: str
    increased_finding_ids: tuple[str, ...]
    decreased_finding_ids: tuple[str, ...]
    resolved_finding_ids: tuple[str, ...]
    control_weakening_count: int
    control_strengthening_count: int
    file_changes: tuple[HomiDriftFileChange, ...]
    capability_changes: tuple[HomiDriftSignalChange, ...]
    persona_changes: tuple[HomiDriftSignalChange, ...]
    finding_deltas: tuple[HomiDriftFindingDelta, ...]
    observation_changes: tuple[HomiDriftObservationChange, ...]
    coverage_drift: dict[str, dict[str, object]]
    score_delta: dict[str, object]
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_DRIFT_FORMAT:
            raise ValueError("Homi drift format is unsupported")
        if self.format_version != HOMI_DRIFT_FORMAT_VERSION:
            raise ValueError("Homi drift version is unsupported")
        if not isinstance(self.status, HomiSnapshotStatus):
            raise ValueError("Homi drift status is invalid")
        for label, value in (
            ("baseline snapshot digest", self.baseline_snapshot_digest),
            ("current snapshot digest", self.current_snapshot_digest),
            (
                "baseline workspace fingerprint",
                self.baseline_workspace_fingerprint,
            ),
            ("current workspace fingerprint", self.current_workspace_fingerprint),
        ):
            _require_digest(value, f"Homi drift {label}")
        _require_subject_id(self.baseline_subject_id)
        _require_subject_id(self.current_subject_id)
        _require_text(self.baseline_project_name, "Homi drift baseline project name")
        _require_text(self.current_project_name, "Homi drift current project name")
        if not isinstance(self.baseline_binding, dict):
            raise ValueError("Homi drift baseline binding must be an object")
        for label, values in (
            ("Operation Context changes", self.operation_context_changes),
            ("Context Finding changes", self.context_finding_changes),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"Homi drift {label} must be sorted and unique")
        if not isinstance(self.context_score_changed, bool):
            raise TypeError("Homi drift Context Score change flag is invalid")
        if self.risk_direction not in {
            "increased",
            "decreased",
            "unchanged",
            "unknown",
        }:
            raise ValueError("Homi drift risk direction is invalid")
        for label, values in (
            ("increased Finding IDs", self.increased_finding_ids),
            ("decreased Finding IDs", self.decreased_finding_ids),
            ("resolved Finding IDs", self.resolved_finding_ids),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"Homi drift {label} must be sorted and unique")
        _require_count(self.control_weakening_count, "control weakening count")
        _require_count(
            self.control_strengthening_count,
            "control strengthening count",
        )
        if not isinstance(self.coverage_drift, dict):
            raise ValueError("Homi drift coverage drift must be an object")
        if not isinstance(self.score_delta, dict):
            raise ValueError("Homi drift score delta must be an object")
        for label, items in (
            ("file changes", self.file_changes),
            ("capability changes", self.capability_changes),
            ("persona changes", self.persona_changes),
            ("finding deltas", self.finding_deltas),
            ("observation changes", self.observation_changes),
        ):
            keys = tuple(item.sort_key() for item in items)
            if keys != tuple(sorted(set(keys))):
                raise ValueError(f"Homi drift {label} must be sorted and unique")
        if self.report_only is not True or self.runtime_verified is not False:
            raise ValueError("Homi drift authority is invalid")
        if self.ci_blocked is not False:
            raise ValueError("Homi drift cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "basis": list(HOMI_DRIFT_BASIS),
            "status": self.status.value,
            "baseline_snapshot_digest": self.baseline_snapshot_digest,
            "current_snapshot_digest": self.current_snapshot_digest,
            "baseline_workspace_fingerprint": self.baseline_workspace_fingerprint,
            "current_workspace_fingerprint": self.current_workspace_fingerprint,
            "baseline_subject_id": self.baseline_subject_id,
            "current_subject_id": self.current_subject_id,
            "baseline_project_name": self.baseline_project_name,
            "current_project_name": self.current_project_name,
            "baseline_binding": self.baseline_binding,
            "operation_context_changes": list(self.operation_context_changes),
            "context_finding_changes": list(self.context_finding_changes),
            "context_score_changed": self.context_score_changed,
            "risk_direction": self.risk_direction,
            "increased_finding_ids": list(self.increased_finding_ids),
            "decreased_finding_ids": list(self.decreased_finding_ids),
            "resolved_finding_ids": list(self.resolved_finding_ids),
            "control_weakening_count": self.control_weakening_count,
            "control_strengthening_count": self.control_strengthening_count,
            "file_changes": [item.to_dict() for item in self.file_changes],
            "capability_changes": [item.to_dict() for item in self.capability_changes],
            "persona_changes": [item.to_dict() for item in self.persona_changes],
            "finding_deltas": [item.to_dict() for item in self.finding_deltas],
            "observation_changes": [
                item.to_dict() for item in self.observation_changes
            ],
            "coverage_drift": self.coverage_drift,
            "score_delta": self.score_delta,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_drift_report(
    baseline: HomiSnapshot, current: HomiSnapshot
) -> HomiDriftReport:
    """Build the layered drift report between two Snapshots, report-only."""

    if not isinstance(baseline, HomiSnapshot):
        raise TypeError("Homi drift builder requires a baseline HomiSnapshot")
    if not isinstance(current, HomiSnapshot):
        raise TypeError("Homi drift builder requires a current HomiSnapshot")
    binding: dict[str, object] = {
        "subject_id_match": baseline.subject_id == current.subject_id,
        "snapshot_format_version_match": (
            baseline.format_version == current.format_version
        ),
        "adapter_version_match": (baseline.adapter_version == current.adapter_version),
        "profile_model_version_match": (
            baseline.profile_model_version == current.profile_model_version
        ),
        "combination_rule_pack_version_match": (
            baseline.combination_rule_pack_version
            == current.combination_rule_pack_version
        ),
        "operation_context_digest_match": (
            baseline.operation_context_sha256 == current.operation_context_sha256
        ),
        "context_risk_report_digest_match": (
            baseline.context_risk_report_sha256 == current.context_risk_report_sha256
        ),
        "context_score_report_digest_match": (
            baseline.context_score_report_sha256 == current.context_score_report_sha256
        ),
    }
    baseline_files = {item.name: item for item in baseline.files}
    current_files = {item.name: item for item in current.files}
    same_agent = baseline.subject_id == current.subject_id
    if not same_agent:
        return HomiDriftReport(
            format=HOMI_DRIFT_FORMAT,
            format_version=HOMI_DRIFT_FORMAT_VERSION,
            status=HomiSnapshotStatus.IDENTITY_MISMATCH,
            baseline_snapshot_digest=baseline.snapshot_digest,
            current_snapshot_digest=current.snapshot_digest,
            baseline_workspace_fingerprint=baseline.workspace_fingerprint,
            current_workspace_fingerprint=current.workspace_fingerprint,
            baseline_subject_id=baseline.subject_id,
            current_subject_id=current.subject_id,
            baseline_project_name=baseline.project_name,
            current_project_name=current.project_name,
            baseline_binding=binding,
            operation_context_changes=(),
            context_finding_changes=(),
            context_score_changed=False,
            risk_direction="unknown",
            increased_finding_ids=(),
            decreased_finding_ids=(),
            resolved_finding_ids=(),
            control_weakening_count=0,
            control_strengthening_count=0,
            file_changes=(),
            capability_changes=(),
            persona_changes=(),
            finding_deltas=(),
            observation_changes=(),
            coverage_drift={},
            score_delta=_score_delta(baseline, current),
        )
    file_changes = tuple(
        sorted(
            (
                _file_change(name, baseline_files.get(name), current_files.get(name))
                for name in set(baseline_files) | set(current_files)
                if baseline_files.get(name) != current_files.get(name)
            ),
            key=HomiDriftFileChange.sort_key,
        )
    )
    baseline_contexts = {
        item.operation_id: item for item in baseline.operation_contexts
    }
    current_contexts = {item.operation_id: item for item in current.operation_contexts}
    operation_context_changes = tuple(
        sorted(
            operation_id
            for operation_id in set(baseline_contexts) | set(current_contexts)
            if baseline_contexts.get(operation_id) != current_contexts.get(operation_id)
        )
    )
    baseline_context_findings = {
        item.finding_id: item for item in baseline.context_findings
    }
    current_context_findings = {
        item.finding_id: item for item in current.context_findings
    }
    context_finding_changes = tuple(
        sorted(
            finding_id
            for finding_id in set(baseline_context_findings)
            | set(current_context_findings)
            if baseline_context_findings.get(finding_id)
            != current_context_findings.get(finding_id)
        )
    )
    context_score_changed = baseline.context_score != current.context_score
    (
        risk_direction,
        increased_finding_ids,
        decreased_finding_ids,
        resolved_finding_ids,
        control_weakening_count,
        control_strengthening_count,
    ) = _context_risk_direction(baseline, current)
    capability_changes = _signal_changes(
        baseline.capabilities, current.capabilities, "capability"
    )
    persona_changes = _signal_changes(
        baseline.persona_signals, current.persona_signals, "persona"
    )
    finding_deltas = _finding_deltas(baseline.findings, current.findings)
    observation_changes = _observation_changes(
        baseline.observations, current.observations
    )
    coverage_drift = {
        key: {
            "before": baseline.coverage_metrics.get(key),
            "after": current.coverage_metrics.get(key),
        }
        for key in sorted(
            set(baseline.coverage_metrics) | set(current.coverage_metrics)
        )
        if baseline.coverage_metrics.get(key) != current.coverage_metrics.get(key)
    }
    drifted = (
        bool(file_changes)
        or bool(operation_context_changes)
        or bool(context_finding_changes)
        or context_score_changed
        or bool(capability_changes)
        or bool(persona_changes)
        or any(
            item.delta_type is not HomiDriftFindingDeltaType.UNCHANGED
            for item in finding_deltas
        )
        or bool(observation_changes)
        or bool(coverage_drift)
        or not all(binding.values())
    )
    return HomiDriftReport(
        format=HOMI_DRIFT_FORMAT,
        format_version=HOMI_DRIFT_FORMAT_VERSION,
        status=HomiSnapshotStatus.DRIFTED if drifted else HomiSnapshotStatus.VERIFIED,
        baseline_snapshot_digest=baseline.snapshot_digest,
        current_snapshot_digest=current.snapshot_digest,
        baseline_workspace_fingerprint=baseline.workspace_fingerprint,
        current_workspace_fingerprint=current.workspace_fingerprint,
        baseline_subject_id=baseline.subject_id,
        current_subject_id=current.subject_id,
        baseline_project_name=baseline.project_name,
        current_project_name=current.project_name,
        baseline_binding=binding,
        operation_context_changes=operation_context_changes,
        context_finding_changes=context_finding_changes,
        context_score_changed=context_score_changed,
        risk_direction=risk_direction,
        increased_finding_ids=increased_finding_ids,
        decreased_finding_ids=decreased_finding_ids,
        resolved_finding_ids=resolved_finding_ids,
        control_weakening_count=control_weakening_count,
        control_strengthening_count=control_strengthening_count,
        file_changes=file_changes,
        capability_changes=capability_changes,
        persona_changes=persona_changes,
        finding_deltas=finding_deltas,
        observation_changes=observation_changes,
        coverage_drift=coverage_drift,
        score_delta=_score_delta(baseline, current),
    )


def encode_homi_drift_report_json(report: HomiDriftReport) -> str:
    """Encode a deterministic layered drift report as JSON."""

    if not isinstance(report, HomiDriftReport):
        raise TypeError("Homi drift encoder requires HomiDriftReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def export_homi_drift_report_json_schema(output_directory: Path) -> Path:
    """Export the strict JSON Schema for the layered drift report."""

    if not isinstance(output_directory, Path):
        raise TypeError("Homi drift schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "homi-drift-report.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/homi-drift-report.schema.json",
        "title": "AgentSec Homi Layered Drift Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "basis",
            "status",
            "baseline_snapshot_digest",
            "current_snapshot_digest",
            "baseline_workspace_fingerprint",
            "current_workspace_fingerprint",
            "baseline_subject_id",
            "current_subject_id",
            "baseline_project_name",
            "current_project_name",
            "baseline_binding",
            "operation_context_changes",
            "context_finding_changes",
            "context_score_changed",
            "risk_direction",
            "increased_finding_ids",
            "decreased_finding_ids",
            "resolved_finding_ids",
            "control_weakening_count",
            "control_strengthening_count",
            "file_changes",
            "capability_changes",
            "persona_changes",
            "finding_deltas",
            "observation_changes",
            "coverage_drift",
            "score_delta",
            "report_only",
            "runtime_verified",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": HOMI_DRIFT_FORMAT},
            "format_version": {
                "type": "string",
                "const": HOMI_DRIFT_FORMAT_VERSION,
            },
            "basis": {
                "type": "array",
                "items": {"type": "string"},
            },
            "status": {
                "type": "string",
                "enum": [item.value for item in HomiSnapshotStatus],
            },
            "baseline_snapshot_digest": _SCHEMA_SHA256,
            "current_snapshot_digest": _SCHEMA_SHA256,
            "baseline_workspace_fingerprint": _SCHEMA_SHA256,
            "current_workspace_fingerprint": _SCHEMA_SHA256,
            "baseline_subject_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
            },
            "current_subject_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
            },
            "baseline_project_name": {"type": "string", "minLength": 1},
            "current_project_name": {"type": "string", "minLength": 1},
            "baseline_binding": {
                "type": "object",
                "additionalProperties": {"type": "boolean"},
            },
            "operation_context_changes": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "context_finding_changes": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "context_score_changed": {"type": "boolean"},
            "risk_direction": {
                "type": "string",
                "enum": ["increased", "decreased", "unchanged", "unknown"],
            },
            "increased_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "decreased_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "resolved_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "control_weakening_count": {"type": "integer", "minimum": 0},
            "control_strengthening_count": {"type": "integer", "minimum": 0},
            "file_changes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "name",
                        "change_type",
                        "before_state",
                        "after_state",
                        "before_sha256",
                        "after_sha256",
                    ],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "change_type": {
                            "type": "string",
                            "enum": [item.value for item in HomiDriftChangeType],
                        },
                        "before_state": {"type": "string", "minLength": 1},
                        "after_state": {"type": "string", "minLength": 1},
                        "before_sha256": {"anyOf": [_SCHEMA_SHA256, {"type": "null"}]},
                        "after_sha256": {"anyOf": [_SCHEMA_SHA256, {"type": "null"}]},
                    },
                },
            },
            "capability_changes": {"$ref": "#/$defs/signalChanges"},
            "persona_changes": {"$ref": "#/$defs/signalChanges"},
            "finding_deltas": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "finding_id",
                        "rule_id",
                        "delta_type",
                        "before_severity",
                        "after_severity",
                        "before_score",
                        "after_score",
                    ],
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "rule_id": {"type": "string", "minLength": 1},
                        "delta_type": {
                            "type": "string",
                            "enum": [item.value for item in HomiDriftFindingDeltaType],
                        },
                        "before_severity": {
                            "anyOf": [
                                {"type": "string", "minLength": 1},
                                {"type": "null"},
                            ]
                        },
                        "after_severity": {
                            "anyOf": [
                                {"type": "string", "minLength": 1},
                                {"type": "null"},
                            ]
                        },
                        "before_score": {
                            "anyOf": [
                                {"type": "number", "minimum": 0, "maximum": 10},
                                {"type": "null"},
                            ]
                        },
                        "after_score": {
                            "anyOf": [
                                {"type": "number", "minimum": 0, "maximum": 10},
                                {"type": "null"},
                            ]
                        },
                    },
                },
            },
            "observation_changes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "kind", "change_type"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "kind": {"type": "string", "minLength": 1},
                        "change_type": {
                            "type": "string",
                            "enum": [item.value for item in HomiDriftChangeType],
                        },
                    },
                },
            },
            "coverage_drift": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "before": {},
                        "after": {},
                    },
                },
            },
            "score_delta": {
                "type": "object",
                "required": ["before_total", "after_total", "delta"],
                "properties": {
                    "kind": {"type": "string"},
                    "before_total": {"type": "number", "minimum": 0},
                    "after_total": {"type": "number", "minimum": 0},
                    "delta": {"type": "number"},
                    "authority": {"const": "presentation_only"},
                },
            },
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "ci_blocked": {"const": False},
            "authority": _SCHEMA_AUTHORITY,
        },
        "$defs": {
            "signalChanges": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "signal_id",
                        "scope",
                        "change_type",
                        "before_state",
                        "after_state",
                    ],
                    "properties": {
                        "signal_id": {"type": "string", "minLength": 1},
                        "scope": {"type": "string", "minLength": 1},
                        "change_type": {
                            "type": "string",
                            "enum": [item.value for item in HomiDriftChangeType],
                        },
                        "before_state": {"type": "string", "minLength": 1},
                        "after_state": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


_SCHEMA_SHA256: dict[str, object] = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
}
_SCHEMA_AUTHORITY: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["report_only", "runtime_verified", "ci_blocked"],
    "properties": {
        "report_only": {"const": True},
        "runtime_verified": {"const": False},
        "ci_blocked": {"const": False},
    },
}


def _file_change(
    name: str,
    before: HomiSnapshotFileSummary | None,
    after: HomiSnapshotFileSummary | None,
) -> HomiDriftFileChange:
    if before is None:
        change_type = HomiDriftChangeType.ADDED
    elif after is None:
        change_type = HomiDriftChangeType.REMOVED
    elif before != after:
        change_type = HomiDriftChangeType.MODIFIED
    else:
        raise ValueError(f"Homi drift file {name} is unchanged and must be omitted")
    return HomiDriftFileChange(
        name=name,
        change_type=change_type,
        before_state=before.state if before is not None else "absent",
        after_state=after.state if after is not None else "absent",
        before_sha256=before.content_sha256 if before is not None else None,
        after_sha256=after.content_sha256 if after is not None else None,
    )


def _signal_changes(
    before: tuple[HomiSnapshotSignalSummary, ...],
    after: tuple[HomiSnapshotSignalSummary, ...],
    scope: str,
) -> tuple[HomiDriftSignalChange, ...]:
    before_map = {item.signal_id: item for item in before}
    after_map = {item.signal_id: item for item in after}
    changes: list[HomiDriftSignalChange] = []
    for signal_id in sorted(set(before_map) | set(after_map)):
        before_item = before_map.get(signal_id)
        after_item = after_map.get(signal_id)
        if before_item is None:
            change_type = HomiDriftChangeType.ADDED
        elif after_item is None:
            change_type = HomiDriftChangeType.REMOVED
        elif before_item != after_item:
            change_type = HomiDriftChangeType.MODIFIED
        else:
            continue
        changes.append(
            HomiDriftSignalChange(
                signal_id=signal_id,
                scope=scope,
                change_type=change_type,
                before_state=before_item.state if before_item else "absent",
                after_state=after_item.state if after_item else "absent",
            )
        )
    return tuple(changes)


def _finding_deltas(
    before: tuple[HomiSnapshotFindingSummary, ...],
    after: tuple[HomiSnapshotFindingSummary, ...],
) -> tuple[HomiDriftFindingDelta, ...]:
    before_map = {item.finding_id: item for item in before}
    after_map = {item.finding_id: item for item in after}
    deltas: list[HomiDriftFindingDelta] = []
    for finding_id in sorted(set(before_map) | set(after_map)):
        before_item = before_map.get(finding_id)
        after_item = after_map.get(finding_id)
        if before_item is None:
            delta_type = HomiDriftFindingDeltaType.ADDED
        elif after_item is None:
            delta_type = HomiDriftFindingDeltaType.RESOLVED
        elif after_item.score > before_item.score:
            delta_type = HomiDriftFindingDeltaType.INCREASED
        elif after_item.score < before_item.score:
            delta_type = HomiDriftFindingDeltaType.DECREASED
        elif before_item.severity != after_item.severity:
            delta_type = HomiDriftFindingDeltaType.CHANGED
        else:
            delta_type = HomiDriftFindingDeltaType.UNCHANGED
        if after_item is not None:
            rule_id = after_item.rule_id
        elif before_item is not None:
            rule_id = before_item.rule_id
        else:  # pragma: no cover - key union guarantees one side
            raise ValueError("Homi drift Finding delta has no source Finding")
        deltas.append(
            HomiDriftFindingDelta(
                finding_id=finding_id,
                rule_id=rule_id,
                delta_type=delta_type,
                before_severity=before_item.severity if before_item else None,
                after_severity=after_item.severity if after_item else None,
                before_score=before_item.score if before_item else None,
                after_score=after_item.score if after_item else None,
            )
        )
    return tuple(deltas)


def _context_risk_direction(
    baseline: HomiSnapshot,
    current: HomiSnapshot,
) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], int, int]:
    baseline_groups = _context_finding_groups(baseline.context_findings)
    current_groups = _context_finding_groups(current.context_findings)
    added_keys = set(current_groups) - set(baseline_groups)
    resolved_keys = set(baseline_groups) - set(current_groups)
    shared_keys = set(current_groups) & set(baseline_groups)
    increased = tuple(
        sorted(
            item.finding_id
            for key in shared_keys
            if _context_group_rank(current_groups[key])
            > _context_group_rank(baseline_groups[key])
            for item in current_groups[key]
        )
    )
    decreased = tuple(
        sorted(
            item.finding_id
            for key in shared_keys
            if _context_group_rank(current_groups[key])
            < _context_group_rank(baseline_groups[key])
            for item in current_groups[key]
        )
    )
    added = tuple(
        sorted(item.finding_id for key in added_keys for item in current_groups[key])
    )
    resolved = tuple(
        sorted(
            item.finding_id for key in resolved_keys for item in baseline_groups[key]
        )
    )
    risk_context_ids = {
        context_id
        for groups in (baseline_groups, current_groups)
        for values in groups.values()
        for item in values
        for context_id in item.context_ids
    }
    weakening, strengthening = _snapshot_control_transitions(
        baseline,
        current,
        risk_context_ids,
    )
    residual_delta = round(
        current.context_score.residual_risk_score
        - baseline.context_score.residual_risk_score,
        2,
    )
    if added or increased or residual_delta > 0 or weakening > 0:
        direction = "increased"
        increased_ids = tuple(sorted(set(added) | set(increased)))
    elif resolved or decreased or residual_delta < 0 or strengthening > 0:
        direction = "decreased"
        increased_ids = ()
    elif (
        baseline.operation_context_sha256 != current.operation_context_sha256
        or baseline.context_risk_report_sha256 != current.context_risk_report_sha256
        or baseline.context_score_report_sha256 != current.context_score_report_sha256
    ):
        direction = "unknown"
        increased_ids = ()
    else:
        direction = "unchanged"
        increased_ids = ()
    return (
        direction,
        increased_ids,
        decreased,
        resolved,
        weakening,
        strengthening,
    )


def _context_finding_groups(
    findings: tuple[HomiSnapshotContextFindingSummary, ...],
) -> dict[tuple[str, tuple[str, ...]], tuple[HomiSnapshotContextFindingSummary, ...]]:
    grouped: dict[
        tuple[str, tuple[str, ...]], list[HomiSnapshotContextFindingSummary]
    ] = {}
    for item in findings:
        if item.kind != "risk":
            continue
        grouped.setdefault((item.rule_id, item.context_ids), []).append(item)
    return {
        key: tuple(sorted(values, key=lambda item: item.finding_id))
        for key, values in grouped.items()
    }


def _context_group_rank(
    findings: tuple[HomiSnapshotContextFindingSummary, ...],
) -> int:
    ranks = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max((ranks[item.severity] for item in findings), default=0)


def _snapshot_control_transitions(
    baseline: HomiSnapshot,
    current: HomiSnapshot,
    risk_context_ids: set[str],
) -> tuple[int, int]:
    old = {item.operation_id: item for item in baseline.operation_contexts}
    new = {item.operation_id: item for item in current.operation_contexts}
    weakening = 0
    strengthening = 0
    for operation_id in set(old) & set(new) & risk_context_ids:
        before = old[operation_id]
        after = new[operation_id]
        before_states = _snapshot_control_states(before)
        after_states = _snapshot_control_states(after)
        for name in set(before_states) | set(after_states):
            before_state = before_states.get(name, "unknown")
            after_state = after_states.get(name, "unknown")
            if before_state == "present" and after_state in {"absent", "unknown"}:
                weakening += 1
            elif after_state == "present" and before_state in {"absent", "unknown"}:
                strengthening += 1
        before_auth = _snapshot_authorization_strength(before.authorization_state)
        after_auth = _snapshot_authorization_strength(after.authorization_state)
        if after_auth < before_auth:
            weakening += 1
        elif after_auth > before_auth:
            strengthening += 1
    return weakening, strengthening


def _snapshot_control_states(
    context: HomiSnapshotOperationContextSummary,
) -> dict[str, str]:
    states: dict[str, str] = {}
    for state, names in (
        ("present", context.controls_present),
        ("absent", context.controls_absent),
        ("unknown", context.controls_unknown),
        ("not_applicable", context.controls_not_applicable),
    ):
        for name in names:
            states[name] = state
    return states


def _snapshot_authorization_strength(state: str) -> int:
    return {
        "approval_missing": 0,
        "unknown": 1,
        "not_required": 2,
        "approval_required": 3,
        "policy_allowed": 4,
        "user_confirmed": 4,
    }.get(state, 1)


def _observation_changes(
    before: tuple[HomiSnapshotObservationSummary, ...],
    after: tuple[HomiSnapshotObservationSummary, ...],
) -> tuple[HomiDriftObservationChange, ...]:
    before_map = {(item.code, item.kind): item for item in before}
    after_map = {(item.code, item.kind): item for item in after}
    changes: list[HomiDriftObservationChange] = []
    for key in sorted(set(before_map) | set(after_map)):
        if key in before_map and key in after_map:
            if before_map[key] != after_map[key]:
                changes.append(
                    HomiDriftObservationChange(
                        code=key[0],
                        kind=key[1],
                        change_type=HomiDriftChangeType.MODIFIED,
                    )
                )
        else:
            changes.append(
                HomiDriftObservationChange(
                    code=key[0],
                    kind=key[1],
                    change_type=(
                        HomiDriftChangeType.ADDED
                        if key in after_map
                        else HomiDriftChangeType.REMOVED
                    ),
                )
            )
    return tuple(changes)


def _score_delta(baseline: HomiSnapshot, current: HomiSnapshot) -> dict[str, object]:
    before_total = round(sum(item.score for item in baseline.findings), 2)
    after_total = round(sum(item.score for item in current.findings), 2)
    return {
        "kind": "homi_combination_finding_score_total",
        "before_total": before_total,
        "after_total": after_total,
        "delta": round(after_total - before_total, 2),
        "authority": "presentation_only",
    }


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_count(value: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Homi drift {label} is invalid")


def _require_subject_id(value: str) -> None:
    if not isinstance(value, str) or _SUBJECT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("Homi drift subject_id is invalid")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


__all__ = [
    "HOMI_DRIFT_BASIS",
    "HOMI_DRIFT_FORMAT",
    "HOMI_DRIFT_FORMAT_VERSION",
    "HomiDriftChangeType",
    "HomiDriftFileChange",
    "HomiDriftFindingDelta",
    "HomiDriftFindingDeltaType",
    "HomiDriftObservationChange",
    "HomiDriftReport",
    "HomiDriftSignalChange",
    "build_homi_drift_report",
    "encode_homi_drift_report_json",
    "export_homi_drift_report_json_schema",
]

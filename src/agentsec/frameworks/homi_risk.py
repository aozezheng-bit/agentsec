"""Unified context-aware Homi Risk report (RISK-08).

RISK-03 Operation Context, RISK-04 deterministic context rules, and RISK-05
quantification own the authoritative ``risk_score``. Legacy Homi combination
Findings remain visible as declaration signals, but they do not raise the
context-aware risk score by themselves. Snapshot drift remains a separate
identity/file/capability layer. Numeric risk drift is emitted only when an
explicit baseline Operation Context bound to the baseline Snapshot is supplied.

Nothing here executes scanned content, verifies runtime behavior, authorizes an
action, or blocks CI.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agentsec.domain import EvidenceConfidence
from agentsec.frameworks.homi_calibration import build_homi_calibration_report
from agentsec.frameworks.homi_drift import (
    HomiDriftFindingDeltaType,
    build_homi_drift_report,
)
from agentsec.frameworks.homi_operation_context import HomiOperationContextReport
from agentsec.frameworks.homi_pilot import HomiPilotReport, encode_homi_pilot_json
from agentsec.frameworks.homi_snapshot import (
    HomiSnapshot,
    HomiSnapshotStatus,
    build_homi_snapshot,
)
from agentsec.risk.context import canonical_operation_context_sha256
from agentsec.risk.context_rules import (
    DeterministicContextRuleEngine,
    canonical_context_risk_sha256,
)
from agentsec.risk.context_score import DeterministicContextRiskScoreEngine
from agentsec.risk.mapping import severity_for_score
from agentsec.versioning import HOMI_RISK_REPORT_VERSION

HOMI_RISK_FORMAT: Literal["agentsec-homi-risk-report"] = "agentsec-homi-risk-report"
HOMI_RISK_FORMAT_VERSION = HOMI_RISK_REPORT_VERSION
HOMI_RISK_BASIS = (
    "AgentSec RISK-08C directional Homi Risk report 0.5.0",
    "RISK-03 source-bound Operation Context is the deterministic analysis input",
    (
        "RISK-04 context-aware Findings require operation, target, data, trigger, "
        "and control evidence"
    ),
    "RISK-05 residual risk is the authoritative risk_score and is never averaged",
    "Legacy Homi combination Findings are declaration signals, not authoritative risk",
    (
        "Risk drift requires an explicit baseline Operation Context bound to the "
        "baseline Snapshot"
    ),
    "Static report-only evidence does not prove runtime reachability or exploitability",
)
_HEX = frozenset("0123456789abcdef")
_SEVERITIES = frozenset(("none", "low", "medium", "high", "critical"))
_IMPACTS = frozenset(("very_low", "low", "moderate", "high", "very_high"))
_POSTURES = frozenset(
    (
        "template_only",
        "latent_unverified",
        "active_unverified",
        "runtime_attested",
        "not_established",
    )
)
_DRIFT_DIRECTIONS = frozenset(("increased", "decreased", "unchanged", "unknown"))
_CONFIDENCE_ORDER = {
    EvidenceConfidence.A: 0,
    EvidenceConfidence.B: 1,
    EvidenceConfidence.C: 2,
    EvidenceConfidence.D: 3,
}
_SUBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


@dataclass(frozen=True, slots=True)
class HomiRiskFindingSummary:
    """Value-minimized RISK-04/05 Finding and score contribution."""

    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    potential_impact_score: float
    residual_risk_score: float
    control_coverage: str
    context_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale_code: str

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "Homi risk Finding ID")
        _require_text(self.rule_id, "Homi risk Rule ID")
        if self.severity not in _SEVERITIES:
            raise ValueError("Homi risk Finding severity is invalid")
        if self.confidence not in {item.value for item in EvidenceConfidence}:
            raise ValueError("Homi risk Finding confidence is invalid")
        for label, score in (
            ("potential impact", self.potential_impact_score),
            ("residual risk", self.residual_risk_score),
        ):
            _require_score(score, f"Homi risk Finding {label}")
        if self.residual_risk_score > self.potential_impact_score:
            raise ValueError("Homi risk Finding residual risk exceeds potential impact")
        if self.control_coverage not in {"none", "partial", "strong"}:
            raise ValueError("Homi risk Finding control coverage is invalid")
        _require_sorted_unique(self.context_ids, "Homi risk Finding context IDs")
        _require_sorted_unique(self.evidence_ids, "Homi risk Finding Evidence IDs")
        _require_text(self.rationale_code, "Homi risk Finding rationale code")

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.finding_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "potential_impact_score": self.potential_impact_score,
            "residual_risk_score": self.residual_risk_score,
            "control_coverage": self.control_coverage,
            "context_ids": list(self.context_ids),
            "evidence_ids": list(self.evidence_ids),
            "rationale_code": self.rationale_code,
        }


@dataclass(frozen=True, slots=True)
class HomiRiskReport:
    """Deterministic, report-only unified risk output for one Homi workspace."""

    format: Literal["agentsec-homi-risk-report"]
    format_version: str
    subject_id: str
    risk_score: float
    risk_level: str
    risk_basis: str
    risk_reasons: tuple[str, ...]
    potential_impact_score: float
    potential_impact_level: str
    residual_risk_score: float
    residual_risk_level: str
    current_posture: str
    current_posture_score: float | None
    evidence_confidence: str | None
    context_count: int
    context_risk_finding_count: int
    context_coverage_finding_count: int
    context_coverage_complete: bool
    context_unknown_dimensions: tuple[str, ...]
    operation_context_sha256: str
    context_risk_report_sha256: str
    context_score_model_version: str
    context_findings: tuple[HomiRiskFindingSummary, ...]
    limitations: tuple[str, ...]
    declaration_signal_score: float
    declaration_signal_level: str
    declaration_signal_reasons: tuple[str, ...]
    drift_status: str
    drift_risk_score: float | None
    drift_risk_level: str | None
    drift_direction: str | None
    drift_risk_basis: str
    drift_reasons: tuple[str, ...]
    increased_finding_ids: tuple[str, ...]
    decreased_finding_ids: tuple[str, ...]
    resolved_finding_ids: tuple[str, ...]
    control_weakening_count: int
    control_strengthening_count: int
    file_change_count: int
    capability_change_count: int
    persona_change_count: int
    finding_delta_count: int
    suppressed_finding_count: int
    coverage_metrics: dict[str, object]
    baseline_snapshot_digest: str | None
    current_snapshot_digest: str
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_RISK_FORMAT:
            raise ValueError("Homi risk format is unsupported")
        if self.format_version != HOMI_RISK_FORMAT_VERSION:
            raise ValueError("Homi risk version is unsupported")
        _require_subject_id(self.subject_id)
        for label, score in (
            ("risk_score", self.risk_score),
            ("potential_impact_score", self.potential_impact_score),
            ("residual_risk_score", self.residual_risk_score),
            ("declaration_signal_score", self.declaration_signal_score),
        ):
            _require_score(score, f"Homi risk {label}")
        if self.drift_risk_score is not None:
            _require_score(self.drift_risk_score, "Homi risk drift_risk_score")
        if self.current_posture_score is not None:
            _require_score(
                self.current_posture_score, "Homi risk current_posture_score"
            )
        for label, value in (
            ("risk_level", self.risk_level),
            ("risk_basis", self.risk_basis),
            ("potential_impact_level", self.potential_impact_level),
            ("residual_risk_level", self.residual_risk_level),
            ("current_posture", self.current_posture),
            ("declaration_signal_level", self.declaration_signal_level),
            ("drift_status", self.drift_status),
            ("drift_risk_basis", self.drift_risk_basis),
            ("context_score_model_version", self.context_score_model_version),
        ):
            _require_text(value, f"Homi risk {label}")
        if self.risk_level not in _SEVERITIES:
            raise ValueError("Homi risk level is invalid")
        if self.residual_risk_level not in _SEVERITIES:
            raise ValueError("Homi residual risk level is invalid")
        if self.declaration_signal_level not in _SEVERITIES:
            raise ValueError("Homi declaration signal level is invalid")
        if self.potential_impact_level not in _IMPACTS:
            raise ValueError("Homi potential impact level is invalid")
        if self.current_posture not in _POSTURES:
            raise ValueError("Homi current posture is invalid")
        if self.evidence_confidence is not None and self.evidence_confidence not in {
            item.value for item in EvidenceConfidence
        }:
            raise ValueError("Homi risk Evidence Confidence is invalid")
        if self.drift_risk_level is None:
            if self.drift_risk_score is not None:
                raise ValueError("Homi drift risk level is missing")
        elif self.drift_risk_level not in _SEVERITIES:
            raise ValueError("Homi drift risk level is invalid")
        if (
            self.drift_direction is not None
            and self.drift_direction not in _DRIFT_DIRECTIONS
        ):
            raise ValueError("Homi drift direction is invalid")
        for label, values in (
            ("risk_reasons", self.risk_reasons),
            ("context_unknown_dimensions", self.context_unknown_dimensions),
            ("declaration_signal_reasons", self.declaration_signal_reasons),
            ("drift_reasons", self.drift_reasons),
            ("increased_finding_ids", self.increased_finding_ids),
            ("decreased_finding_ids", self.decreased_finding_ids),
            ("resolved_finding_ids", self.resolved_finding_ids),
        ):
            _require_sorted_unique(values, f"Homi risk {label}")
        _require_text_tuple(self.limitations, "Homi risk limitations")
        for label, count in (
            ("context_count", self.context_count),
            ("context_risk_finding_count", self.context_risk_finding_count),
            ("context_coverage_finding_count", self.context_coverage_finding_count),
            ("file_change_count", self.file_change_count),
            ("capability_change_count", self.capability_change_count),
            ("persona_change_count", self.persona_change_count),
            ("finding_delta_count", self.finding_delta_count),
            ("suppressed_finding_count", self.suppressed_finding_count),
            ("control_weakening_count", self.control_weakening_count),
            ("control_strengthening_count", self.control_strengthening_count),
        ):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError(f"Homi risk {label} is invalid")
        if self.context_count < 1:
            raise ValueError("Homi risk context_count must be positive")
        if not isinstance(self.context_coverage_complete, bool):
            raise TypeError("Homi risk context coverage flag is invalid")
        if self.context_findings != tuple(
            sorted(self.context_findings, key=lambda item: item.sort_key())
        ):
            raise ValueError("Homi risk context Findings must be sorted")
        if len(self.context_findings) != self.context_risk_finding_count:
            raise ValueError("Homi risk context Finding count is inconsistent")
        if not isinstance(self.coverage_metrics, dict):
            raise ValueError("Homi risk coverage metrics must be an object")
        _require_digest(self.operation_context_sha256, "Homi Operation Context digest")
        _require_digest(self.context_risk_report_sha256, "Homi context risk digest")
        _require_digest(self.current_snapshot_digest, "Homi risk current digest")
        if self.baseline_snapshot_digest is not None:
            _require_digest(self.baseline_snapshot_digest, "Homi risk baseline digest")
        if self.risk_score != self.residual_risk_score:
            raise ValueError("Homi risk_score must equal RISK-05 residual risk")
        if self.risk_level != self.residual_risk_level:
            raise ValueError("Homi risk level must equal RISK-05 residual level")
        if severity_for_score(self.risk_score).value != self.risk_level:
            raise ValueError("Homi risk level is inconsistent with risk_score")
        if (
            severity_for_score(self.declaration_signal_score).value
            != self.declaration_signal_level
        ):
            raise ValueError("Homi declaration signal level is inconsistent")
        if (
            self.drift_risk_score is not None
            and self.drift_risk_level != severity_for_score(self.drift_risk_score).value
        ):
            raise ValueError("Homi drift risk level is inconsistent")
        if (
            self.report_only is not True
            or self.runtime_verified is not False
            or self.policy_authority is not False
        ):
            raise ValueError("Homi risk authority is invalid")
        if self.ci_blocked is not False:
            raise ValueError("Homi risk cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "subject_id": self.subject_id,
            "basis": list(HOMI_RISK_BASIS),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_basis": self.risk_basis,
            "risk_reasons": list(self.risk_reasons),
            "potential_impact_score": self.potential_impact_score,
            "potential_impact_level": self.potential_impact_level,
            "residual_risk_score": self.residual_risk_score,
            "residual_risk_level": self.residual_risk_level,
            "current_posture": self.current_posture,
            "current_posture_score": self.current_posture_score,
            "evidence_confidence": self.evidence_confidence,
            "context_count": self.context_count,
            "context_risk_finding_count": self.context_risk_finding_count,
            "context_coverage_finding_count": self.context_coverage_finding_count,
            "context_coverage_complete": self.context_coverage_complete,
            "context_unknown_dimensions": list(self.context_unknown_dimensions),
            "operation_context_sha256": self.operation_context_sha256,
            "context_risk_report_sha256": self.context_risk_report_sha256,
            "context_score_model_version": self.context_score_model_version,
            "context_findings": [item.to_dict() for item in self.context_findings],
            "limitations": list(self.limitations),
            "declaration_signal_score": self.declaration_signal_score,
            "declaration_signal_level": self.declaration_signal_level,
            "declaration_signal_reasons": list(self.declaration_signal_reasons),
            "drift_status": self.drift_status,
            "drift_risk_score": self.drift_risk_score,
            "drift_risk_level": self.drift_risk_level,
            "drift_direction": self.drift_direction,
            "drift_risk_basis": self.drift_risk_basis,
            "drift_reasons": list(self.drift_reasons),
            "increased_finding_ids": list(self.increased_finding_ids),
            "decreased_finding_ids": list(self.decreased_finding_ids),
            "resolved_finding_ids": list(self.resolved_finding_ids),
            "control_weakening_count": self.control_weakening_count,
            "control_strengthening_count": self.control_strengthening_count,
            "file_change_count": self.file_change_count,
            "capability_change_count": self.capability_change_count,
            "persona_change_count": self.persona_change_count,
            "finding_delta_count": self.finding_delta_count,
            "suppressed_finding_count": self.suppressed_finding_count,
            "coverage_metrics": self.coverage_metrics,
            "baseline_snapshot_digest": self.baseline_snapshot_digest,
            "current_snapshot_digest": self.current_snapshot_digest,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_risk_report(
    report: HomiPilotReport,
    *,
    subject_id: str,
    operation_context: HomiOperationContextReport,
    baseline: HomiSnapshot | None = None,
    baseline_operation_context: HomiOperationContextReport | None = None,
) -> HomiRiskReport:
    """Run RISK-03/04/05 and aggregate Snapshot drift into one output."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi risk builder requires HomiPilotReport")
    if not isinstance(operation_context, HomiOperationContextReport):
        raise TypeError("Homi risk builder requires HomiOperationContextReport")
    _require_subject_id(subject_id)
    if baseline is not None and not isinstance(baseline, HomiSnapshot):
        raise TypeError("Homi risk baseline must be a HomiSnapshot")
    if baseline_operation_context is not None and not isinstance(
        baseline_operation_context, HomiOperationContextReport
    ):
        raise TypeError("Homi risk context baseline is invalid")
    if baseline_operation_context is not None and baseline is None:
        raise ValueError("Homi risk context baseline requires a baseline Snapshot")
    _require_operation_context_binding(report, operation_context)
    if (
        baseline is not None
        and baseline_operation_context is not None
        and (
            baseline_operation_context.source_report_sha256
            != baseline.source_report_sha256
            or canonical_operation_context_sha256(
                baseline_operation_context.context_set
            )
            != baseline.operation_context_sha256
        )
    ):
        raise ValueError("Homi risk context baseline is not bound to baseline Snapshot")

    calibration = build_homi_calibration_report(report)
    retained_scores = [item.score for item in calibration.retained_findings]
    declaration_signal_score = round(max(retained_scores, default=0.0), 2)
    declaration_signal_reasons = tuple(
        sorted({item.rule_id for item in calibration.retained_findings})
    )

    current = build_homi_snapshot(
        report,
        subject_id=subject_id,
        operation_context=operation_context,
    )
    snapshot_drift = (
        None if baseline is None else build_homi_drift_report(baseline, current)
    )
    identity_mismatch = (
        snapshot_drift is not None
        and snapshot_drift.status is HomiSnapshotStatus.IDENTITY_MISMATCH
    )
    baseline_context_pair = None
    if (
        baseline is not None
        and baseline_operation_context is not None
        and not identity_mismatch
    ):
        baseline_context_report = DeterministicContextRuleEngine().run(
            baseline_operation_context.context_set
        )
        baseline_score_report = DeterministicContextRiskScoreEngine().run(
            baseline_operation_context.context_set,
            baseline_context_report,
        )
        if (
            canonical_context_risk_sha256(baseline_context_report)
            != baseline.context_risk_report_sha256
            or _canonical_dict_sha256(baseline_score_report.to_dict())
            != baseline.context_score_report_sha256
        ):
            raise ValueError(
                "Homi risk baseline context analysis is not bound to Snapshot"
            )
        baseline_context_pair = (
            baseline_operation_context.context_set,
            baseline_context_report,
        )

    context_risk = DeterministicContextRuleEngine().run(operation_context.context_set)
    context_score = DeterministicContextRiskScoreEngine().run(
        operation_context.context_set,
        context_risk,
        baseline=baseline_context_pair,
    )
    contributions = {item.finding_id: item for item in context_score.contributions}
    context_findings = tuple(
        sorted(
            (
                HomiRiskFindingSummary(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    severity=contributions[finding.finding_id].severity.value,
                    confidence=finding.confidence.value,
                    potential_impact_score=contributions[
                        finding.finding_id
                    ].potential_impact_score,
                    residual_risk_score=contributions[
                        finding.finding_id
                    ].residual_risk_score,
                    control_coverage=contributions[
                        finding.finding_id
                    ].control_coverage.value,
                    context_ids=finding.context_ids,
                    evidence_ids=finding.evidence_ids,
                    rationale_code=finding.rationale_code,
                )
                for finding in context_risk.risk_findings
            ),
            key=lambda item: item.sort_key(),
        )
    )
    risk_reasons = tuple(sorted({item.rule_id for item in context_findings}))
    evidence_confidence = _most_conservative_confidence(
        tuple(item.confidence for item in context_score.contributions)
    )

    if snapshot_drift is None:
        drift_status = "not_established"
        file_change_count = 0
        capability_change_count = 0
        persona_change_count = 0
        finding_delta_count = 0
    elif identity_mismatch:
        drift_status = snapshot_drift.status.value
        file_change_count = 0
        capability_change_count = 0
        persona_change_count = 0
        finding_delta_count = 0
    else:
        drift_status = snapshot_drift.status.value
        file_change_count = len(snapshot_drift.file_changes)
        capability_change_count = len(snapshot_drift.capability_changes)
        persona_change_count = len(snapshot_drift.persona_changes)
        finding_delta_count = sum(
            item.delta_type is not HomiDriftFindingDeltaType.UNCHANGED
            for item in snapshot_drift.finding_deltas
        )

    if context_score.drift is None:
        drift_risk_score = None
        drift_risk_level = None
        drift_direction = None
        drift_reasons: tuple[str, ...] = ()
        increased_finding_ids: tuple[str, ...] = ()
        decreased_finding_ids: tuple[str, ...] = ()
        resolved_finding_ids: tuple[str, ...] = ()
        control_weakening_count = 0
        control_strengthening_count = 0
        drift_risk_basis = (
            "identity_mismatch"
            if identity_mismatch
            else "context_baseline_not_supplied"
            if baseline is not None
            else "not_established"
        )
    else:
        drift_risk_score = context_score.drift.drift_score
        drift_risk_level = severity_for_score(drift_risk_score).value
        drift_direction = context_score.drift.direction.value
        added = set(context_score.drift.added_finding_ids)
        drift_reasons = tuple(
            sorted(
                item.rule_id for item in context_findings if item.finding_id in added
            )
        )
        if drift_direction == "increased" and not drift_reasons:
            drift_reasons = risk_reasons
        drift_risk_basis = "operation_context_risk_drift"
        increased_finding_ids = context_score.drift.increased_finding_ids
        if context_score.drift.added_finding_ids:
            increased_finding_ids = tuple(
                sorted(
                    set(increased_finding_ids)
                    | set(context_score.drift.added_finding_ids)
                )
            )
        decreased_finding_ids = context_score.drift.decreased_finding_ids
        resolved_finding_ids = context_score.drift.resolved_finding_ids
        control_weakening_count = context_score.drift.control_weakening_count
        control_strengthening_count = context_score.drift.control_strengthening_count

    return HomiRiskReport(
        format=HOMI_RISK_FORMAT,
        format_version=HOMI_RISK_FORMAT_VERSION,
        subject_id=subject_id,
        risk_score=context_score.residual_risk_score,
        risk_level=context_score.residual_risk_level.value,
        risk_basis="operation_context_residual_risk",
        risk_reasons=risk_reasons,
        potential_impact_score=context_score.potential_impact_score,
        potential_impact_level=context_score.potential_impact_level.value,
        residual_risk_score=context_score.residual_risk_score,
        residual_risk_level=context_score.residual_risk_level.value,
        current_posture=context_score.current_posture.value,
        current_posture_score=context_score.current_posture_score,
        evidence_confidence=(
            evidence_confidence.value if evidence_confidence is not None else None
        ),
        context_count=context_risk.context_count,
        context_risk_finding_count=len(context_risk.risk_findings),
        context_coverage_finding_count=len(context_risk.coverage_findings),
        context_coverage_complete=context_risk.coverage_complete,
        context_unknown_dimensions=context_risk.unknown_dimensions,
        operation_context_sha256=context_risk.source_context_sha256,
        context_risk_report_sha256=canonical_context_risk_sha256(context_risk),
        context_score_model_version=context_score.model_version,
        context_findings=context_findings,
        limitations=context_score.limitations,
        declaration_signal_score=declaration_signal_score,
        declaration_signal_level=severity_for_score(declaration_signal_score).value,
        declaration_signal_reasons=declaration_signal_reasons,
        drift_status=drift_status,
        drift_risk_score=drift_risk_score,
        drift_risk_level=drift_risk_level,
        drift_direction=drift_direction,
        drift_risk_basis=drift_risk_basis,
        drift_reasons=drift_reasons,
        increased_finding_ids=increased_finding_ids,
        decreased_finding_ids=decreased_finding_ids,
        resolved_finding_ids=resolved_finding_ids,
        control_weakening_count=control_weakening_count,
        control_strengthening_count=control_strengthening_count,
        file_change_count=file_change_count,
        capability_change_count=capability_change_count,
        persona_change_count=persona_change_count,
        finding_delta_count=finding_delta_count,
        suppressed_finding_count=calibration.suppressed_finding_count,
        coverage_metrics=current.coverage_metrics,
        baseline_snapshot_digest=(
            baseline.snapshot_digest if baseline is not None else None
        ),
        current_snapshot_digest=current.snapshot_digest,
    )


def encode_homi_risk_report_json(report: HomiRiskReport) -> str:
    """Encode a deterministic unified risk report as JSON."""

    if not isinstance(report, HomiRiskReport):
        raise TypeError("Homi risk encoder requires HomiRiskReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def export_homi_risk_report_json_schema(output_directory: Path) -> Path:
    """Export strict JSON Schema for the unified context-aware risk report."""

    if not isinstance(output_directory, Path):
        raise TypeError("Homi risk schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "homi-risk-report.schema.json"
    nullable_score = {
        "anyOf": [
            {"type": "number", "minimum": 0, "maximum": 10},
            {"type": "null"},
        ]
    }
    nullable_severity = {
        "anyOf": [
            {"type": "string", "enum": sorted(_SEVERITIES)},
            {"type": "null"},
        ]
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/homi-risk-report.schema.json",
        "title": "AgentSec Homi Unified Context-aware Risk Report",
        "type": "object",
        "additionalProperties": False,
        "required": list(HomiRiskReport.__dataclass_fields__) + ["basis", "authority"],
        "properties": {
            "format": {"const": HOMI_RISK_FORMAT},
            "format_version": {"const": HOMI_RISK_FORMAT_VERSION},
            "subject_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
            },
            "basis": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "risk_score": {"type": "number", "minimum": 0, "maximum": 10},
            "risk_level": {"type": "string", "enum": sorted(_SEVERITIES)},
            "risk_basis": {"const": "operation_context_residual_risk"},
            "risk_reasons": _string_array_schema(),
            "potential_impact_score": {"type": "number", "minimum": 0, "maximum": 10},
            "potential_impact_level": {"type": "string", "enum": sorted(_IMPACTS)},
            "residual_risk_score": {"type": "number", "minimum": 0, "maximum": 10},
            "residual_risk_level": {"type": "string", "enum": sorted(_SEVERITIES)},
            "current_posture": {"type": "string", "enum": sorted(_POSTURES)},
            "current_posture_score": nullable_score,
            "evidence_confidence": {
                "anyOf": [
                    {"type": "string", "enum": ["A", "B", "C", "D"]},
                    {"type": "null"},
                ]
            },
            "context_count": {"type": "integer", "minimum": 1},
            "context_risk_finding_count": {"type": "integer", "minimum": 0},
            "context_coverage_finding_count": {"type": "integer", "minimum": 0},
            "context_coverage_complete": {"type": "boolean"},
            "context_unknown_dimensions": _string_array_schema(),
            "operation_context_sha256": _sha256_schema(),
            "context_risk_report_sha256": _sha256_schema(),
            "context_score_model_version": {"type": "string", "minLength": 1},
            "context_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(HomiRiskFindingSummary.__dataclass_fields__),
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "rule_id": {"type": "string", "pattern": "^CTX-RISK-[0-9]{3}$"},
                        "severity": {"type": "string", "enum": sorted(_SEVERITIES)},
                        "confidence": {"type": "string", "enum": ["A", "B", "C", "D"]},
                        "potential_impact_score": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 10,
                        },
                        "residual_risk_score": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 10,
                        },
                        "control_coverage": {
                            "type": "string",
                            "enum": ["none", "partial", "strong"],
                        },
                        "context_ids": _string_array_schema(),
                        "evidence_ids": _string_array_schema(),
                        "rationale_code": {"type": "string", "minLength": 1},
                    },
                },
            },
            "limitations": _string_array_schema(),
            "declaration_signal_score": {"type": "number", "minimum": 0, "maximum": 10},
            "declaration_signal_level": {"type": "string", "enum": sorted(_SEVERITIES)},
            "declaration_signal_reasons": _string_array_schema(),
            "drift_status": {
                "type": "string",
                "enum": ["not_established", "verified", "drifted", "identity_mismatch"],
            },
            "drift_risk_score": nullable_score,
            "drift_risk_level": nullable_severity,
            "drift_direction": {
                "anyOf": [
                    {"type": "string", "enum": sorted(_DRIFT_DIRECTIONS)},
                    {"type": "null"},
                ]
            },
            "drift_risk_basis": {"type": "string", "minLength": 1},
            "drift_reasons": _string_array_schema(),
            "increased_finding_ids": _string_array_schema(),
            "decreased_finding_ids": _string_array_schema(),
            "resolved_finding_ids": _string_array_schema(),
            "control_weakening_count": {"type": "integer", "minimum": 0},
            "control_strengthening_count": {"type": "integer", "minimum": 0},
            "file_change_count": {"type": "integer", "minimum": 0},
            "capability_change_count": {"type": "integer", "minimum": 0},
            "persona_change_count": {"type": "integer", "minimum": 0},
            "finding_delta_count": {"type": "integer", "minimum": 0},
            "suppressed_finding_count": {"type": "integer", "minimum": 0},
            "coverage_metrics": {"type": "object"},
            "baseline_snapshot_digest": {"anyOf": [_sha256_schema(), {"type": "null"}]},
            "current_snapshot_digest": _sha256_schema(),
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "report_only",
                    "runtime_verified",
                    "policy_authority",
                    "ci_blocked",
                ],
                "properties": {
                    "report_only": {"const": True},
                    "runtime_verified": {"const": False},
                    "policy_authority": {"const": False},
                    "ci_blocked": {"const": False},
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _require_operation_context_binding(
    report: HomiPilotReport, operation_context: HomiOperationContextReport
) -> None:
    expected = hashlib.sha256(
        encode_homi_pilot_json(report).encode("utf-8")
    ).hexdigest()
    if operation_context.source_report_sha256 != expected:
        raise ValueError("Homi Operation Context is not bound to Homi Pilot report")


def _canonical_dict_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _most_conservative_confidence(
    values: tuple[EvidenceConfidence, ...],
) -> EvidenceConfidence | None:
    if not values:
        return None
    return max(values, key=_CONFIDENCE_ORDER.__getitem__)


def _require_score(value: float, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0.0 <= value <= 10.0
    ):
        raise ValueError(f"{label} is out of range")


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_subject_id(value: str) -> None:
    if not isinstance(value, str) or _SUBJECT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("Homi risk subject_id is invalid")


def _require_sorted_unique(values: tuple[str, ...], label: str) -> None:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be sorted and unique")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if (
        not values
        or len(values) != len(set(values))
        or any(not isinstance(value, str) or not value.strip() for value in values)
    ):
        raise ValueError(f"{label} must contain unique non-empty text")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _string_array_schema() -> dict[str, object]:
    return {"type": "array", "items": {"type": "string"}, "uniqueItems": True}


def _sha256_schema() -> dict[str, object]:
    return {"type": "string", "pattern": "^[0-9a-f]{64}$"}


__all__ = [
    "HOMI_RISK_BASIS",
    "HOMI_RISK_FORMAT",
    "HOMI_RISK_FORMAT_VERSION",
    "HomiRiskFindingSummary",
    "HomiRiskReport",
    "build_homi_risk_report",
    "encode_homi_risk_report_json",
    "export_homi_risk_report_json_schema",
]

"""Residual-risk and risk-drift scoring for RISK-04 context findings.

This module deliberately keeps three questions separate:

* potential impact: the highest NIST/AgentSec base score implied by a
  context-aware finding;
* residual risk: the same finding after a bounded, explicit control-coverage
  adjustment;
* current posture: whether current runtime exposure has been established.

Static Operation Contexts never establish runtime posture.  Consequently the
current posture score remains ``None`` unless a future, separately supplied
runtime attestation contract is introduced.  This module is report-only and
cannot grant authority or block CI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.domain import EvidenceConfidence, ImpactLevel, LikelihoodLevel, Severity
from agentsec.risk.context import (
    AuthorizationState,
    ControlState,
    OperationContext,
    OperationContextSet,
    canonical_operation_context_sha256,
)
from agentsec.risk.context_rules import (
    ContextRiskFinding,
    ContextRiskFindingKind,
    ContextRiskReport,
    canonical_context_risk_sha256,
)
from agentsec.risk.mapping import (
    agentsec_base_score,
    nist_risk_level,
    severity_for_score,
)
from agentsec.versioning import (
    CONTEXT_RISK_SCORE_MODEL_VERSION,
    CONTEXT_RISK_SCORE_REPORT_VERSION,
)

CONTEXT_RISK_SCORE_FORMAT: Literal["agentsec-context-risk-score"] = (
    "agentsec-context-risk-score"
)
CONTEXT_RISK_SCORE_FORMAT_VERSION = CONTEXT_RISK_SCORE_REPORT_VERSION
CONTEXT_RISK_SCORE_BASIS = (
    "AgentSec RISK-09A calibrated directional context risk contract 0.3.0",
    (
        "Potential impact uses the existing NIST likelihood-impact matrix and "
        "AgentSec representatives"
    ),
    (
        "Residual risk uses bounded explicit control coverage and never averages "
        "away a critical signal"
    ),
    "Static Operation Context does not establish current runtime posture",
    (
        "Only added/increased risk, relevant control weakening, and upward "
        "residual risk score positive drift"
    ),
    "Benign, resolved, decreased, or non-directional context changes score zero drift",
    "Positive drift score cannot exceed current residual risk score",
)

_CONTROL_FACTOR = {
    "none": 1.0,
    "partial": 0.85,
    "strong": 0.70,
}
_CONTROL_VALUES = (
    "approval",
    "user_consent",
    "allowlist",
    "audit",
    "retention",
    "redaction",
    "rate_limit",
)


class ContextRiskScoreError(ValueError):
    """Raised when RISK-05 score inputs are inconsistent."""


class ContextPosture(StrEnum):
    """Evidence state for current posture, not a runtime permission."""

    TEMPLATE_ONLY = "template_only"
    LATENT_UNVERIFIED = "latent_unverified"
    ACTIVE_UNVERIFIED = "active_unverified"
    RUNTIME_ATTESTED = "runtime_attested"
    NOT_ESTABLISHED = "not_established"


class ControlCoverage(StrEnum):
    """Bounded control coverage used for residual-risk adjustment."""

    NONE = "none"
    PARTIAL = "partial"
    STRONG = "strong"


class RiskDriftDirection(StrEnum):
    """Direction of risk change relative to a trusted baseline."""

    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContextRiskScoreContribution:
    """One RISK-04 Finding's potential and residual score contribution."""

    finding_id: str
    rule_id: str
    potential_impact_score: float
    potential_risk_level: str
    potential_impact_level: ImpactLevel
    likelihood: LikelihoodLevel
    severity: Severity
    confidence: EvidenceConfidence
    control_coverage: ControlCoverage
    control_factor: float
    residual_risk_score: float
    context_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "context score finding_id")
        _require_text(self.rule_id, "context score rule_id")
        if not 0.0 <= self.potential_impact_score <= 10.0:
            raise ContextRiskScoreError("potential impact score is out of range")
        if not 0.0 <= self.residual_risk_score <= 10.0:
            raise ContextRiskScoreError("residual risk score is out of range")
        if self.residual_risk_score > self.potential_impact_score:
            raise ContextRiskScoreError(
                "residual risk cannot exceed potential impact score"
            )
        if not isinstance(self.potential_impact_level, ImpactLevel):
            raise TypeError("potential impact level is invalid")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("likelihood is invalid")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity is invalid")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("confidence is invalid")
        if not isinstance(self.control_coverage, ControlCoverage):
            raise TypeError("control coverage is invalid")
        if self.control_factor != _CONTROL_FACTOR[self.control_coverage.value]:
            raise ContextRiskScoreError("control factor is inconsistent")
        if self.context_ids != tuple(sorted(set(self.context_ids))):
            raise ContextRiskScoreError("context IDs must be sorted and unique")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ContextRiskScoreError("evidence IDs must be sorted and unique")

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.finding_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "potential_impact_score": self.potential_impact_score,
            "potential_risk_level": self.potential_risk_level,
            "potential_impact_level": self.potential_impact_level.value,
            "likelihood": self.likelihood.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "control_coverage": self.control_coverage.value,
            "control_factor": self.control_factor,
            "residual_risk_score": self.residual_risk_score,
            "context_ids": list(self.context_ids),
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class ContextRiskDriftAssessment:
    """Upward risk-drift comparison against an explicit prior snapshot."""

    baseline_context_sha256: str
    baseline_risk_report_sha256: str
    baseline_potential_impact_score: float
    baseline_residual_risk_score: float
    potential_impact_delta: float
    residual_risk_delta: float
    drift_score: float
    direction: RiskDriftDirection
    added_finding_ids: tuple[str, ...]
    increased_finding_ids: tuple[str, ...]
    decreased_finding_ids: tuple[str, ...]
    resolved_finding_ids: tuple[str, ...]
    non_directional_finding_ids: tuple[str, ...]
    added_context_ids: tuple[str, ...]
    removed_context_ids: tuple[str, ...]
    modified_context_ids: tuple[str, ...]
    risky_added_context_ids: tuple[str, ...]
    control_weakening_count: int
    control_strengthening_count: int
    basis: tuple[str, ...] = CONTEXT_RISK_SCORE_BASIS

    def __post_init__(self) -> None:
        _require_digest(self.baseline_context_sha256, "baseline context digest")
        _require_digest(self.baseline_risk_report_sha256, "baseline risk digest")
        for value, label in (
            (self.baseline_potential_impact_score, "baseline potential score"),
            (self.baseline_residual_risk_score, "baseline residual score"),
            (self.drift_score, "drift score"),
        ):
            if not 0.0 <= value <= 10.0:
                raise ContextRiskScoreError(f"{label} is out of range")
        if not -10.0 <= self.potential_impact_delta <= 10.0:
            raise ContextRiskScoreError("potential impact delta is out of range")
        if not -10.0 <= self.residual_risk_delta <= 10.0:
            raise ContextRiskScoreError("residual risk delta is out of range")
        if not isinstance(self.direction, RiskDriftDirection):
            raise TypeError("risk drift direction is invalid")
        _validate_sorted_unique(self.added_finding_ids, "added finding IDs")
        _validate_sorted_unique(self.increased_finding_ids, "increased finding IDs")
        _validate_sorted_unique(self.decreased_finding_ids, "decreased finding IDs")
        _validate_sorted_unique(self.resolved_finding_ids, "resolved finding IDs")
        _validate_sorted_unique(
            self.non_directional_finding_ids,
            "non-directional finding IDs",
        )
        _validate_sorted_unique(self.added_context_ids, "added context IDs")
        _validate_sorted_unique(self.removed_context_ids, "removed context IDs")
        _validate_sorted_unique(self.modified_context_ids, "modified context IDs")
        _validate_sorted_unique(
            self.risky_added_context_ids,
            "risky added context IDs",
        )
        for value, label in (
            (self.control_weakening_count, "control weakening count"),
            (self.control_strengthening_count, "control strengthening count"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContextRiskScoreError(f"{label} is invalid")
        if self.basis != CONTEXT_RISK_SCORE_BASIS:
            raise ContextRiskScoreError("risk drift basis is inconsistent")

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_context_sha256": self.baseline_context_sha256,
            "baseline_risk_report_sha256": self.baseline_risk_report_sha256,
            "baseline_potential_impact_score": self.baseline_potential_impact_score,
            "baseline_residual_risk_score": self.baseline_residual_risk_score,
            "potential_impact_delta": self.potential_impact_delta,
            "residual_risk_delta": self.residual_risk_delta,
            "drift_score": self.drift_score,
            "direction": self.direction.value,
            "added_finding_ids": list(self.added_finding_ids),
            "increased_finding_ids": list(self.increased_finding_ids),
            "decreased_finding_ids": list(self.decreased_finding_ids),
            "resolved_finding_ids": list(self.resolved_finding_ids),
            "non_directional_finding_ids": list(self.non_directional_finding_ids),
            "added_context_ids": list(self.added_context_ids),
            "removed_context_ids": list(self.removed_context_ids),
            "modified_context_ids": list(self.modified_context_ids),
            "risky_added_context_ids": list(self.risky_added_context_ids),
            "control_weakening_count": self.control_weakening_count,
            "control_strengthening_count": self.control_strengthening_count,
            "basis": list(self.basis),
        }


@dataclass(frozen=True, slots=True)
class ContextRiskScoreReport:
    """Report-only RISK-05 score bound to RISK-04 and Operation Context."""

    format: Literal["agentsec-context-risk-score"]
    format_version: str
    model_version: str
    source_context_sha256: str
    source_risk_report_sha256: str
    source_context_format: str
    source_risk_report_format: str
    coverage_complete: bool
    unknown_dimensions: tuple[str, ...]
    potential_impact_score: float
    potential_impact_level: ImpactLevel
    residual_risk_score: float
    residual_risk_level: Severity
    current_posture: ContextPosture
    current_posture_score: float | None
    contributions: tuple[ContextRiskScoreContribution, ...]
    drift: ContextRiskDriftAssessment | None
    limitations: tuple[str, ...]
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != CONTEXT_RISK_SCORE_FORMAT:
            raise ContextRiskScoreError("context risk score format is unsupported")
        if self.format_version != CONTEXT_RISK_SCORE_FORMAT_VERSION:
            raise ContextRiskScoreError("context risk score version is unsupported")
        if self.model_version != CONTEXT_RISK_SCORE_MODEL_VERSION:
            raise ContextRiskScoreError("context risk score model is unsupported")
        _require_digest(self.source_context_sha256, "source context digest")
        _require_digest(self.source_risk_report_sha256, "source risk digest")
        _require_text(self.source_context_format, "source context format")
        _require_text(self.source_risk_report_format, "source risk format")
        if not isinstance(self.coverage_complete, bool):
            raise TypeError("coverage_complete must be bool")
        _validate_sorted_unique(self.unknown_dimensions, "unknown dimensions")
        for value, label in (
            (self.potential_impact_score, "potential impact score"),
            (self.residual_risk_score, "residual risk score"),
        ):
            if not 0.0 <= value <= 10.0:
                raise ContextRiskScoreError(f"{label} is out of range")
        if self.residual_risk_score > self.potential_impact_score:
            raise ContextRiskScoreError(
                "residual risk cannot exceed potential impact score"
            )
        if not isinstance(self.potential_impact_level, ImpactLevel):
            raise TypeError("potential impact level is invalid")
        if not isinstance(self.residual_risk_level, Severity):
            raise TypeError("residual risk level is invalid")
        if self.residual_risk_level is not severity_for_score(self.residual_risk_score):
            raise ContextRiskScoreError("residual risk severity is inconsistent")
        if not isinstance(self.current_posture, ContextPosture):
            raise TypeError("current posture is invalid")
        if self.current_posture_score is not None and not (
            0.0 <= self.current_posture_score <= 10.0
        ):
            raise ContextRiskScoreError("current posture score is out of range")
        if self.current_posture is ContextPosture.RUNTIME_ATTESTED:
            raise ContextRiskScoreError(
                "static RISK-05 input cannot claim runtime attestation"
            )
        if self.current_posture_score is not None:
            raise ContextRiskScoreError(
                "static RISK-05 input cannot carry current posture score"
            )
        if self.contributions != tuple(
            sorted(self.contributions, key=lambda item: item.sort_key())
        ):
            raise ContextRiskScoreError("score contributions must be sorted")
        _require_text_tuple(self.limitations, "score limitations")
        if (
            self.report_only is not True
            or self.runtime_verified is not False
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise ContextRiskScoreError("score authority fields are invalid")

    @property
    def drift_score(self) -> float | None:
        return None if self.drift is None else self.drift.drift_score

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "source_context_sha256": self.source_context_sha256,
            "source_risk_report_sha256": self.source_risk_report_sha256,
            "source_context_format": self.source_context_format,
            "source_risk_report_format": self.source_risk_report_format,
            "coverage_complete": self.coverage_complete,
            "unknown_dimensions": list(self.unknown_dimensions),
            "potential_impact_score": self.potential_impact_score,
            "potential_impact_level": self.potential_impact_level.value,
            "residual_risk_score": self.residual_risk_score,
            "residual_risk_level": self.residual_risk_level.value,
            "current_posture": self.current_posture.value,
            "current_posture_score": self.current_posture_score,
            "contribution_count": len(self.contributions),
            "contributions": [item.to_dict() for item in self.contributions],
            "drift": None if self.drift is None else self.drift.to_dict(),
            "drift_score": self.drift_score,
            "limitations": list(self.limitations),
            "scoring_basis": list(CONTEXT_RISK_SCORE_BASIS),
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


class DeterministicContextRiskScoreEngine:
    """Calculate bounded potential, residual, and optional drift scores."""

    def run(
        self,
        context_set: OperationContextSet,
        risk_report: ContextRiskReport,
        *,
        current_posture: ContextPosture | None = None,
        baseline: tuple[OperationContextSet, ContextRiskReport] | None = None,
    ) -> ContextRiskScoreReport:
        if not isinstance(context_set, OperationContextSet):
            raise TypeError("RISK-05 requires OperationContextSet")
        if not isinstance(risk_report, ContextRiskReport):
            raise TypeError("RISK-05 requires ContextRiskReport")
        expected_context_digest = canonical_operation_context_sha256(context_set)
        if risk_report.source_context_sha256 != expected_context_digest:
            raise ContextRiskScoreError(
                "RISK-04 report is not bound to the Operation Context Set"
            )
        context_by_id = {item.operation_id: item for item in context_set.contexts}
        contributions = tuple(
            sorted(
                (
                    self._contribution(finding, context_by_id)
                    for finding in risk_report.risk_findings
                ),
                key=lambda item: item.sort_key(),
            )
        )
        potential = max(
            (item.potential_impact_score for item in contributions), default=0.0
        )
        potential_level = _impact_level_for_score(potential)
        residual = max(
            (item.residual_risk_score for item in contributions), default=0.0
        )
        posture = current_posture or (
            ContextPosture.LATENT_UNVERIFIED
            if contributions
            else ContextPosture.NOT_ESTABLISHED
        )
        drift = None
        if baseline is not None:
            baseline_context, baseline_report = baseline
            if not isinstance(baseline_context, OperationContextSet) or not isinstance(
                baseline_report, ContextRiskReport
            ):
                raise TypeError("RISK-05 baseline is invalid")
            baseline_score = self.run(
                baseline_context,
                baseline_report,
                current_posture=ContextPosture.NOT_ESTABLISHED,
            )
            drift = _build_drift(
                context_set,
                risk_report,
                potential,
                residual,
                baseline_context,
                baseline_report,
                baseline_score,
                contributions,
            )
        limitations = list(
            (
                "Static Operation Context does not prove runtime reachability, "
                "successful execution, or exploitability.",
                "Current posture score remains null until an independent runtime "
                "attestation contract is supplied.",
                "Residual-risk adjustment is an AgentSec policy metric and requires "
                "future human calibration; it is not a loss probability.",
            )
        )
        if not risk_report.coverage_complete or risk_report.unknown_dimensions:
            limitations.append(
                "Coverage is incomplete or contains Unknown dimensions; scores are "
                "provisional and must not be interpreted as a clean pass."
            )
        return ContextRiskScoreReport(
            format=CONTEXT_RISK_SCORE_FORMAT,
            format_version=CONTEXT_RISK_SCORE_FORMAT_VERSION,
            model_version=CONTEXT_RISK_SCORE_MODEL_VERSION,
            source_context_sha256=expected_context_digest,
            source_risk_report_sha256=canonical_context_risk_sha256(risk_report),
            source_context_format=context_set.format,
            source_risk_report_format=risk_report.format,
            coverage_complete=risk_report.coverage_complete,
            unknown_dimensions=risk_report.unknown_dimensions,
            potential_impact_score=potential,
            potential_impact_level=potential_level,
            residual_risk_score=residual,
            residual_risk_level=severity_for_score(residual),
            current_posture=posture,
            current_posture_score=None,
            contributions=contributions,
            drift=drift,
            limitations=tuple(dict.fromkeys(limitations)),
        )

    def _contribution(
        self,
        finding: ContextRiskFinding,
        context_by_id: dict[str, OperationContext],
    ) -> ContextRiskScoreContribution:
        if finding.kind is not ContextRiskFindingKind.RISK:
            raise ContextRiskScoreError("coverage Finding cannot be scored")
        contexts = []
        for context_id in finding.context_ids:
            context = context_by_id.get(context_id)
            if context is None:
                raise ContextRiskScoreError(
                    f"Finding references unknown context: {context_id}"
                )
            contexts.append(context)
        risk_level = nist_risk_level(finding.likelihood, finding.impact)
        potential = agentsec_base_score(risk_level)
        coverage = _control_coverage(contexts)
        factor = _CONTROL_FACTOR[coverage.value]
        residual = round(potential * factor, 2)
        return ContextRiskScoreContribution(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            potential_impact_score=potential,
            potential_risk_level=risk_level.value,
            potential_impact_level=finding.impact,
            likelihood=finding.likelihood,
            severity=severity_for_score(potential),
            confidence=finding.confidence,
            control_coverage=coverage,
            control_factor=factor,
            residual_risk_score=residual,
            context_ids=finding.context_ids,
            evidence_ids=finding.evidence_ids,
        )


def encode_context_risk_score_json(report: ContextRiskScoreReport) -> str:
    """Encode a deterministic RISK-05 report."""

    if not isinstance(report, ContextRiskScoreReport):
        raise TypeError("context risk score encoder requires ContextRiskScoreReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def export_context_risk_score_json_schema(output_directory: Path) -> Path:
    """Export the strict RISK-05 report Schema."""

    if not isinstance(output_directory, Path):
        raise TypeError("context risk score schema directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "context-risk-score.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/context-risk-score.schema.json",
        "title": "AgentSec Context Risk Score Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "model_version",
            "source_context_sha256",
            "source_risk_report_sha256",
            "source_context_format",
            "source_risk_report_format",
            "coverage_complete",
            "unknown_dimensions",
            "potential_impact_score",
            "potential_impact_level",
            "residual_risk_score",
            "residual_risk_level",
            "current_posture",
            "current_posture_score",
            "contribution_count",
            "contributions",
            "drift",
            "drift_score",
            "limitations",
            "scoring_basis",
            "report_only",
            "runtime_verified",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": CONTEXT_RISK_SCORE_FORMAT},
            "format_version": {"const": CONTEXT_RISK_SCORE_FORMAT_VERSION},
            "model_version": {"const": CONTEXT_RISK_SCORE_MODEL_VERSION},
            "source_context_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "source_risk_report_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_context_format": {"const": "agentsec-operation-context-set"},
            "source_risk_report_format": {"const": "agentsec-context-risk-report"},
            "coverage_complete": {"type": "boolean"},
            "unknown_dimensions": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "potential_impact_score": {"type": "number", "minimum": 0, "maximum": 10},
            "potential_impact_level": {"enum": [item.value for item in ImpactLevel]},
            "residual_risk_score": {"type": "number", "minimum": 0, "maximum": 10},
            "residual_risk_level": {"enum": [item.value for item in Severity]},
            "current_posture": {"enum": [item.value for item in ContextPosture]},
            "current_posture_score": {
                "type": ["number", "null"],
                "minimum": 0,
                "maximum": 10,
            },
            "contribution_count": {"type": "integer", "minimum": 0},
            "contributions": {"type": "array", "items": _contribution_schema()},
            "drift": {"anyOf": [{"type": "null"}, _drift_schema()]},
            "drift_score": {"type": ["number", "null"], "minimum": 0, "maximum": 10},
            "limitations": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
            "scoring_basis": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
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


def _contribution_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "rule_id",
            "potential_impact_score",
            "potential_risk_level",
            "potential_impact_level",
            "likelihood",
            "severity",
            "confidence",
            "control_coverage",
            "control_factor",
            "residual_risk_score",
            "context_ids",
            "evidence_ids",
        ],
        "properties": {
            "finding_id": {"type": "string", "minLength": 1},
            "rule_id": {"type": "string", "minLength": 1},
            "potential_impact_score": {"type": "number", "minimum": 0, "maximum": 10},
            "potential_risk_level": {"type": "string", "minLength": 1},
            "potential_impact_level": {"enum": [item.value for item in ImpactLevel]},
            "likelihood": {"enum": [item.value for item in LikelihoodLevel]},
            "severity": {"enum": [item.value for item in Severity]},
            "confidence": {"enum": [item.value for item in EvidenceConfidence]},
            "control_coverage": {"enum": [item.value for item in ControlCoverage]},
            "control_factor": {"type": "number", "minimum": 0, "maximum": 1},
            "residual_risk_score": {"type": "number", "minimum": 0, "maximum": 10},
            "context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "evidence_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
        },
    }


def _drift_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "baseline_context_sha256",
            "baseline_risk_report_sha256",
            "baseline_potential_impact_score",
            "baseline_residual_risk_score",
            "potential_impact_delta",
            "residual_risk_delta",
            "drift_score",
            "direction",
            "added_finding_ids",
            "increased_finding_ids",
            "decreased_finding_ids",
            "resolved_finding_ids",
            "non_directional_finding_ids",
            "added_context_ids",
            "removed_context_ids",
            "modified_context_ids",
            "risky_added_context_ids",
            "control_weakening_count",
            "control_strengthening_count",
            "basis",
        ],
        "properties": {
            "baseline_context_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "baseline_risk_report_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "baseline_potential_impact_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 10,
            },
            "baseline_residual_risk_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 10,
            },
            "potential_impact_delta": {"type": "number", "minimum": -10, "maximum": 10},
            "residual_risk_delta": {"type": "number", "minimum": -10, "maximum": 10},
            "drift_score": {"type": "number", "minimum": 0, "maximum": 10},
            "direction": {"enum": [item.value for item in RiskDriftDirection]},
            "added_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
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
            "non_directional_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "added_context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "removed_context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "modified_context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "risky_added_context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "control_weakening_count": {"type": "integer", "minimum": 0},
            "control_strengthening_count": {"type": "integer", "minimum": 0},
            "basis": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        },
    }


def _build_drift(
    context_set: OperationContextSet,
    risk_report: ContextRiskReport,
    potential: float,
    residual: float,
    baseline_context: OperationContextSet,
    baseline_report: ContextRiskReport,
    baseline_score: ContextRiskScoreReport,
    contributions: tuple[ContextRiskScoreContribution, ...],
) -> ContextRiskDriftAssessment:
    current_contexts = {item.operation_id: item for item in context_set.contexts}
    old_contexts = {item.operation_id: item for item in baseline_context.contexts}
    added_context_ids = tuple(sorted(set(current_contexts) - set(old_contexts)))
    removed_context_ids = tuple(sorted(set(old_contexts) - set(current_contexts)))
    modified_context_ids = tuple(
        sorted(
            operation_id
            for operation_id in set(current_contexts) & set(old_contexts)
            if current_contexts[operation_id] != old_contexts[operation_id]
        )
    )
    current_groups = _contribution_groups(contributions)
    baseline_groups = _contribution_groups(baseline_score.contributions)
    added_keys = set(current_groups) - set(baseline_groups)
    resolved_keys = set(baseline_groups) - set(current_groups)
    shared_keys = set(current_groups) & set(baseline_groups)
    added_finding_ids = tuple(
        sorted(item.finding_id for key in added_keys for item in current_groups[key])
    )
    resolved_finding_ids = tuple(
        sorted(
            item.finding_id for key in resolved_keys for item in baseline_groups[key]
        )
    )
    increased_finding_ids = tuple(
        sorted(
            item.finding_id
            for key in shared_keys
            if _group_residual(current_groups[key])
            > _group_residual(baseline_groups[key])
            for item in current_groups[key]
        )
    )
    decreased_finding_ids = tuple(
        sorted(
            item.finding_id
            for key in shared_keys
            if _group_residual(current_groups[key])
            < _group_residual(baseline_groups[key])
            for item in current_groups[key]
        )
    )
    non_directional_finding_ids = tuple(
        sorted(
            item.finding_id
            for key in shared_keys
            if _group_residual(current_groups[key])
            == _group_residual(baseline_groups[key])
            and _group_finding_ids(current_groups[key])
            != _group_finding_ids(baseline_groups[key])
            for item in current_groups[key]
        )
    )
    risky_context_ids = {
        context_id
        for item in (*contributions, *baseline_score.contributions)
        for context_id in item.context_ids
    }
    risky_added_context_ids = tuple(sorted(set(added_context_ids) & risky_context_ids))
    control_weakening_count, control_strengthening_count = _control_transitions(
        current_contexts,
        old_contexts,
        risky_context_ids,
    )
    potential_delta = round(potential - baseline_score.potential_impact_score, 2)
    residual_delta = round(residual - baseline_score.residual_risk_score, 2)
    if (
        added_finding_ids
        or increased_finding_ids
        or residual_delta > 0
        or control_weakening_count > 0
    ):
        direction = RiskDriftDirection.INCREASED
    elif (
        resolved_finding_ids
        or decreased_finding_ids
        or residual_delta < 0
        or control_strengthening_count > 0
    ):
        direction = RiskDriftDirection.DECREASED
    elif (
        modified_context_ids
        or added_context_ids
        or removed_context_ids
        or non_directional_finding_ids
    ):
        direction = RiskDriftDirection.UNKNOWN
    else:
        direction = RiskDriftDirection.UNCHANGED
    uncapped_drift_score = round(
        max(0.0, residual_delta)
        + 1.5 * len(added_finding_ids)
        + 1.0 * len(increased_finding_ids)
        + 0.75 * control_weakening_count
        + 0.25 * len(risky_added_context_ids),
        2,
    )
    drift_score = min(10.0, residual, uncapped_drift_score)
    return ContextRiskDriftAssessment(
        baseline_context_sha256=canonical_operation_context_sha256(baseline_context),
        baseline_risk_report_sha256=canonical_context_risk_sha256(baseline_report),
        baseline_potential_impact_score=baseline_score.potential_impact_score,
        baseline_residual_risk_score=baseline_score.residual_risk_score,
        potential_impact_delta=potential_delta,
        residual_risk_delta=residual_delta,
        drift_score=drift_score,
        direction=direction,
        added_finding_ids=added_finding_ids,
        increased_finding_ids=increased_finding_ids,
        decreased_finding_ids=decreased_finding_ids,
        resolved_finding_ids=resolved_finding_ids,
        non_directional_finding_ids=non_directional_finding_ids,
        added_context_ids=added_context_ids,
        removed_context_ids=removed_context_ids,
        modified_context_ids=modified_context_ids,
        risky_added_context_ids=risky_added_context_ids,
        control_weakening_count=control_weakening_count,
        control_strengthening_count=control_strengthening_count,
    )


def _contribution_groups(
    contributions: tuple[ContextRiskScoreContribution, ...],
) -> dict[tuple[str, tuple[str, ...]], tuple[ContextRiskScoreContribution, ...]]:
    grouped: dict[tuple[str, tuple[str, ...]], list[ContextRiskScoreContribution]] = {}
    for item in contributions:
        grouped.setdefault((item.rule_id, item.context_ids), []).append(item)
    return {
        key: tuple(sorted(values, key=lambda item: item.finding_id))
        for key, values in grouped.items()
    }


def _group_residual(items: tuple[ContextRiskScoreContribution, ...]) -> float:
    return max((item.residual_risk_score for item in items), default=0.0)


def _group_finding_ids(
    items: tuple[ContextRiskScoreContribution, ...],
) -> tuple[str, ...]:
    return tuple(item.finding_id for item in items)


def _control_transitions(
    current_contexts: dict[str, OperationContext],
    baseline_contexts: dict[str, OperationContext],
    risk_relevant_context_ids: set[str],
) -> tuple[int, int]:
    weakening = 0
    strengthening = 0
    shared_ids = (
        set(current_contexts) & set(baseline_contexts) & risk_relevant_context_ids
    )
    for operation_id in shared_ids:
        current = current_contexts[operation_id]
        baseline = baseline_contexts[operation_id]
        for name in _CONTROL_VALUES:
            before = getattr(baseline.controls, name)
            after = getattr(current.controls, name)
            if before is ControlState.PRESENT and after in {
                ControlState.ABSENT,
                ControlState.UNKNOWN,
            }:
                weakening += 1
            elif after is ControlState.PRESENT and before in {
                ControlState.ABSENT,
                ControlState.UNKNOWN,
            }:
                strengthening += 1
        before_auth = _authorization_strength(baseline.authorization.state)
        after_auth = _authorization_strength(current.authorization.state)
        if after_auth < before_auth:
            weakening += 1
        elif after_auth > before_auth:
            strengthening += 1
    return weakening, strengthening


def _authorization_strength(state: AuthorizationState) -> int:
    return {
        AuthorizationState.APPROVAL_MISSING: 0,
        AuthorizationState.UNKNOWN: 1,
        AuthorizationState.NOT_REQUIRED: 2,
        AuthorizationState.APPROVAL_REQUIRED: 3,
        AuthorizationState.POLICY_ALLOWED: 4,
        AuthorizationState.USER_CONFIRMED: 4,
    }[state]


def _control_coverage(contexts: list[OperationContext]) -> ControlCoverage:
    coverage_by_context = [_single_context_control_coverage(item) for item in contexts]
    ranks = {
        ControlCoverage.NONE: 0,
        ControlCoverage.PARTIAL: 1,
        ControlCoverage.STRONG: 2,
    }
    return min(
        coverage_by_context,
        key=ranks.__getitem__,
        default=ControlCoverage.NONE,
    )


def _single_context_control_coverage(context: OperationContext) -> ControlCoverage:
    present = sum(
        getattr(context.controls, name) is ControlState.PRESENT
        for name in _CONTROL_VALUES
    )
    explicit_authorization = context.authorization.state in {
        AuthorizationState.USER_CONFIRMED,
        AuthorizationState.POLICY_ALLOWED,
    }
    if explicit_authorization:
        present += 1
    if present >= 3 and explicit_authorization:
        return ControlCoverage.STRONG
    if present >= 1:
        return ControlCoverage.PARTIAL
    return ControlCoverage.NONE


def _impact_level_for_score(score: float) -> ImpactLevel:
    if score >= 9.0:
        return ImpactLevel.VERY_HIGH
    if score >= 7.0:
        return ImpactLevel.HIGH
    if score >= 4.0:
        return ImpactLevel.MODERATE
    if score >= 2.0:
        return ImpactLevel.LOW
    return ImpactLevel.VERY_LOW


def _validate_sorted_unique(values: tuple[str, ...], label: str) -> None:
    if values != tuple(sorted(set(values))):
        raise ContextRiskScoreError(f"{label} must be sorted and unique")


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContextRiskScoreError(f"{label} must be non-empty text")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if not values or any(
        not isinstance(item, str) or not item.strip() for item in values
    ):
        raise ContextRiskScoreError(f"{label} must contain non-empty text")
    if len(values) != len(set(values)):
        raise ContextRiskScoreError(f"{label} must be unique")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContextRiskScoreError(f"{label} must be lowercase SHA-256")


__all__ = [
    "CONTEXT_RISK_SCORE_BASIS",
    "CONTEXT_RISK_SCORE_FORMAT",
    "CONTEXT_RISK_SCORE_FORMAT_VERSION",
    "CONTEXT_RISK_SCORE_MODEL_VERSION",
    "CONTEXT_RISK_SCORE_REPORT_VERSION",
    "ContextPosture",
    "ContextRiskDriftAssessment",
    "ContextRiskScoreContribution",
    "ContextRiskScoreError",
    "ContextRiskScoreReport",
    "ControlCoverage",
    "DeterministicContextRiskScoreEngine",
    "RiskDriftDirection",
    "canonical_context_risk_sha256",
    "encode_context_risk_score_json",
    "export_context_risk_score_json_schema",
]

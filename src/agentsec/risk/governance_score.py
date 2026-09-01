"""Deterministic Governance Score calculation (P2-22 Agentic Risk Track)."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal

from agentsec.domain import Severity
from agentsec.manifests import AgentManifest, encode_agent_manifest_json
from agentsec.risk.agentic_factors import (
    AgenticFactorEvidence,
    AgenticFactorVector,
)
from agentsec.risk.cvss import severity_for_cvss_score
from agentsec.risk.drift_score import (
    DriftApprovalStatus,
    DriftBaselineTrust,
    DriftDeploymentScope,
    DriftScoreAssessment,
    DriftScoreContext,
)
from agentsec.risk.threat_mitigation import MitigationState, ThreatMitigationVector
from agentsec.versioning import (
    AGENTIC_FACTOR_MODEL_VERSION,
    DRIFT_SCORE_MODEL_VERSION,
    GOVERNANCE_SCORE_MODEL_VERSION,
    THREAT_MITIGATION_MODEL_VERSION,
)

GOVERNANCE_SCORE_FORMAT: Literal["agentsec-governance-score"] = (
    "agentsec-governance-score"
)
GOVERNANCE_SCORE_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
GOVERNANCE_SCORE_BASIS = (
    "AgentSec P2-22 deterministic Governance Score contract 0.1.0",
    (
        "Governance Score measures governance risk; higher values indicate "
        "weaker governance"
    ),
    "Static control declarations are not runtime enforcement proof",
    "Ownership, review, waiver, baseline, and Coverage context are explicit inputs",
    "The score is an AgentSec policy metric, not a NIST or CVSS formula",
)


class GovernanceDimension(StrEnum):
    """Auditable governance-risk contribution dimensions."""

    CONTROL_MATURITY = "control_maturity"
    COVERAGE = "coverage"
    APPROVAL = "approval"
    BASELINE_TRUST = "baseline_trust"
    CHANGE_REVIEW = "change_review"
    DEPLOYMENT_SCOPE = "deployment_scope"
    OWNERSHIP = "ownership"
    WAIVER = "waiver"


class GovernanceReviewStatus(StrEnum):
    """Review status supplied by a trusted caller or CI adapter."""

    UNKNOWN = "unknown"
    NOT_REVIEWED = "not_reviewed"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class GovernanceScoreContext:
    """Explicit governance context; missing context is scored conservatively."""

    drift: DriftScoreContext = dataclass_field(default_factory=DriftScoreContext)
    review_status: GovernanceReviewStatus = GovernanceReviewStatus.UNKNOWN
    policy_owner: str | None = None
    approval_owner: str | None = None
    waiver_count: int = 0
    expired_waiver_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.drift, DriftScoreContext):
            raise TypeError("governance drift context must be DriftScoreContext")
        if not isinstance(self.review_status, GovernanceReviewStatus):
            raise TypeError("review_status must be GovernanceReviewStatus")
        counts = (
            (self.waiver_count, "waiver_count"),
            (self.expired_waiver_count, "expired_waiver_count"),
        )
        for count, label in counts:
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if self.expired_waiver_count > self.waiver_count:
            raise ValueError("expired_waiver_count cannot exceed waiver_count")
        owners = (
            (self.policy_owner, "policy_owner"),
            (self.approval_owner, "approval_owner"),
        )
        for owner, label in owners:
            if owner is not None and (
                not owner.strip()
                or len(owner) > 128
                or any(
                    char
                    not in (
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                    )
                    for char in owner
                )
            ):
                raise ValueError(f"{label} must be a bounded stable identifier")

    def to_dict(self) -> dict[str, object]:
        return {
            "drift": self.drift.to_dict(),
            "review_status": self.review_status.value,
            "policy_owner": self.policy_owner,
            "approval_owner": self.approval_owner,
            "waiver_count": self.waiver_count,
            "expired_waiver_count": self.expired_waiver_count,
        }


@dataclass(frozen=True, slots=True)
class GovernanceContribution:
    """One auditable governance-risk contribution."""

    dimension: GovernanceDimension
    points: float
    rationale: tuple[str, ...]
    evidence: tuple[AgenticFactorEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, GovernanceDimension):
            raise TypeError("governance dimension must be GovernanceDimension")
        if not 0.0 <= self.points <= 10.0:
            raise ValueError("governance contribution points must be within 0 to 10")
        _validate_unique_strings(self.rationale, "governance rationale")
        if any(not isinstance(item, AgenticFactorEvidence) for item in self.evidence):
            raise TypeError("governance evidence must contain Factor evidence")

    def to_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "points": self.points,
            "rationale": list(self.rationale),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class GovernanceScoreAssessment:
    """Versioned Governance Score with explicit maturity and context inputs."""

    format: Literal["agentsec-governance-score"]
    format_version: Literal["0.1.0"]
    model_version: str
    agentic_factor_model_version: str
    threat_mitigation_model_version: str
    drift_score_model_version: str
    agent_id: str
    manifest_sha256: str
    governance_score: float
    severity: Severity
    context: GovernanceScoreContext
    contributions: tuple[GovernanceContribution, ...] = dataclass_field(repr=False)
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False, default=())

    def __post_init__(self) -> None:
        if self.format != GOVERNANCE_SCORE_FORMAT:
            raise ValueError("Governance Score format is unsupported")
        if self.format_version != GOVERNANCE_SCORE_FORMAT_VERSION:
            raise ValueError("Governance Score format version is unsupported")
        if self.model_version != GOVERNANCE_SCORE_MODEL_VERSION:
            raise ValueError("Governance Score model version is unsupported")
        if self.agentic_factor_model_version != AGENTIC_FACTOR_MODEL_VERSION:
            raise ValueError("Agentic Factor model version is unsupported")
        if self.threat_mitigation_model_version != THREAT_MITIGATION_MODEL_VERSION:
            raise ValueError("Threat/Mitigation model version is unsupported")
        if self.drift_score_model_version != DRIFT_SCORE_MODEL_VERSION:
            raise ValueError("Drift Score model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("Governance Score Agent ID must not be empty")
        _validate_hash(self.manifest_sha256, "manifest_sha256")
        _validate_score(self.governance_score, "governance_score")
        if not isinstance(self.severity, Severity):
            raise TypeError("Governance Score severity must be Severity")
        if severity_for_cvss_score(self.governance_score) is not self.severity:
            raise ValueError("Governance Score severity is inconsistent")
        if not isinstance(self.context, GovernanceScoreContext):
            raise TypeError("Governance Score context is invalid")
        if not self.contributions:
            raise ValueError("Governance Score requires contributions")
        expected = _round_score(
            min(10.0, sum(item.points for item in self.contributions))
        )
        if expected != self.governance_score:
            raise ValueError("governance_score is inconsistent with contributions")
        _validate_unique_strings(self.mapping_basis, "governance mapping basis")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "agentic_factor_model_version": self.agentic_factor_model_version,
            "threat_mitigation_model_version": self.threat_mitigation_model_version,
            "drift_score_model_version": self.drift_score_model_version,
            "agent_id": self.agent_id,
            "manifest_sha256": self.manifest_sha256,
            "governance_score": self.governance_score,
            "severity": self.severity.value,
            "context": self.context.to_dict(),
            "contributions": [item.to_dict() for item in self.contributions],
            "mapping_basis": list(self.mapping_basis),
        }


class GovernanceScoreError(RuntimeError):
    """Safe deterministic Governance Score failure."""


def encode_governance_score_json(assessment: GovernanceScoreAssessment) -> str:
    """Encode Governance Score without raw source values."""

    if not isinstance(assessment, GovernanceScoreAssessment):
        raise TypeError("assessment must be GovernanceScoreAssessment")
    return (
        json.dumps(assessment.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicGovernanceScoreEngine:
    """Calculate governance risk from controls, Coverage, and explicit context."""

    def score(
        self,
        manifest: AgentManifest,
        factors: AgenticFactorVector,
        threats: ThreatMitigationVector,
        *,
        context: GovernanceScoreContext | None = None,
        drift: DriftScoreAssessment | None = None,
    ) -> GovernanceScoreAssessment:
        if not isinstance(manifest, AgentManifest):
            raise TypeError("Governance Score requires AgentManifest")
        if not isinstance(factors, AgenticFactorVector):
            raise TypeError("Governance Score requires AgenticFactorVector")
        if not isinstance(threats, ThreatMitigationVector):
            raise TypeError("Governance Score requires ThreatMitigationVector")
        selected_context = context or GovernanceScoreContext()
        if not isinstance(selected_context, GovernanceScoreContext):
            raise TypeError("Governance Score context must be GovernanceScoreContext")
        if drift is not None and not isinstance(drift, DriftScoreAssessment):
            raise TypeError("drift must be DriftScoreAssessment")
        try:
            manifest_hash = _manifest_sha256(manifest)
            self._validate_bindings(manifest_hash, factors, threats, drift)
            if drift is not None and context is None:
                selected_context = GovernanceScoreContext(drift=drift.context)
            contributions = self._contributions(manifest, threats, selected_context)
            score = _round_score(min(10.0, sum(item.points for item in contributions)))
            return GovernanceScoreAssessment(
                format=GOVERNANCE_SCORE_FORMAT,
                format_version=GOVERNANCE_SCORE_FORMAT_VERSION,
                model_version=GOVERNANCE_SCORE_MODEL_VERSION,
                agentic_factor_model_version=AGENTIC_FACTOR_MODEL_VERSION,
                threat_mitigation_model_version=THREAT_MITIGATION_MODEL_VERSION,
                drift_score_model_version=DRIFT_SCORE_MODEL_VERSION,
                agent_id=manifest.identity.agent_id,
                manifest_sha256=manifest_hash,
                governance_score=score,
                severity=severity_for_cvss_score(score),
                context=selected_context,
                contributions=contributions,
                mapping_basis=GOVERNANCE_SCORE_BASIS,
            )
        except (TypeError, ValueError, KeyError) as error:
            raise GovernanceScoreError(
                "Governance Score calculation failed safely"
            ) from error

    @staticmethod
    def _validate_bindings(
        manifest_hash: str,
        factors: AgenticFactorVector,
        threats: ThreatMitigationVector,
        drift: DriftScoreAssessment | None,
    ) -> None:
        if factors.manifest_sha256 != manifest_hash:
            raise ValueError("Agentic Factor Manifest hash does not match")
        if threats.manifest_sha256 != manifest_hash:
            raise ValueError("Threat/Mitigation Manifest hash does not match")
        if factors.agent_id != threats.agent_id:
            raise ValueError("Agentic Factor and Threat/Mitigation Agent IDs differ")
        if drift is not None:
            if drift.after_manifest_sha256 != manifest_hash:
                raise ValueError("Drift Score after Manifest hash does not match")
            if drift.agent_id != factors.agent_id:
                raise ValueError("Drift Score Agent ID does not match")

    @staticmethod
    def _contributions(
        manifest: AgentManifest,
        threats: ThreatMitigationVector,
        context: GovernanceScoreContext,
    ) -> tuple[GovernanceContribution, ...]:
        contributions = [
            _control_maturity_contribution(threats),
            _coverage_contribution(manifest),
            _approval_contribution(context.drift.approval_status),
            _baseline_contribution(context.drift.baseline_trust),
            _review_contribution(context.review_status),
            _deployment_contribution(context.drift.deployment_scope),
            _ownership_contribution(context),
            _waiver_contribution(context),
        ]
        return tuple(sorted(contributions, key=lambda item: item.dimension.value))


def _control_maturity_contribution(
    threats: ThreatMitigationVector,
) -> GovernanceContribution:
    points_by_state = {
        MitigationState.NOT_APPLICABLE: 0.0,
        MitigationState.DECLARED: 0.2,
        MitigationState.ABSENT: 0.8,
        MitigationState.DISABLED: 1.0,
        MitigationState.UNKNOWN: 1.0,
    }
    points = _round_score(
        min(
            6.0,
            sum(points_by_state[item.mitigation.state] for item in threats.assessments),
        )
    )
    evidence = tuple(
        evidence
        for item in threats.assessments
        for evidence in item.mitigation.evidence
    )
    return GovernanceContribution(
        dimension=GovernanceDimension.CONTROL_MATURITY,
        points=points,
        rationale=(
            "Control maturity is derived from Threat/Mitigation control states.",
            "A static declared control is not treated as runtime enforcement proof.",
        ),
        evidence=evidence,
    )


def _coverage_contribution(manifest: AgentManifest) -> GovernanceContribution:
    unknown_count = len(manifest.unknowns)
    points = 2.0 if not manifest.coverage.complete else min(2.0, unknown_count * 0.25)
    return GovernanceContribution(
        dimension=GovernanceDimension.COVERAGE,
        points=_round_score(points),
        rationale=(
            "Incomplete Coverage or explicit Unknowns weaken governance confidence.",
        ),
    )


def _approval_contribution(status: DriftApprovalStatus) -> GovernanceContribution:
    points = {
        DriftApprovalStatus.UNKNOWN: 1.0,
        DriftApprovalStatus.NOT_REQUIRED: 0.5,
        DriftApprovalStatus.APPROVED: 0.2,
        DriftApprovalStatus.REJECTED: 1.5,
        DriftApprovalStatus.EXPIRED: 1.5,
    }[status]
    return GovernanceContribution(
        dimension=GovernanceDimension.APPROVAL,
        points=points,
        rationale=(f"Approval status is {status.value}.",),
    )


def _baseline_contribution(status: DriftBaselineTrust) -> GovernanceContribution:
    points = {
        DriftBaselineTrust.UNKNOWN: 1.0,
        DriftBaselineTrust.HASH_ONLY: 0.5,
        DriftBaselineTrust.SIGNED_ATTESTED: 0.2,
    }[status]
    return GovernanceContribution(
        dimension=GovernanceDimension.BASELINE_TRUST,
        points=points,
        rationale=(f"Baseline trust posture is {status.value}.",),
    )


def _review_contribution(status: GovernanceReviewStatus) -> GovernanceContribution:
    points = {
        GovernanceReviewStatus.UNKNOWN: 1.0,
        GovernanceReviewStatus.NOT_REVIEWED: 1.0,
        GovernanceReviewStatus.REVIEWED: 0.3,
        GovernanceReviewStatus.APPROVED: 0.1,
        GovernanceReviewStatus.REJECTED: 1.5,
        GovernanceReviewStatus.EXPIRED: 1.5,
    }[status]
    return GovernanceContribution(
        dimension=GovernanceDimension.CHANGE_REVIEW,
        points=points,
        rationale=(f"Change review status is {status.value}.",),
    )


def _deployment_contribution(scope: DriftDeploymentScope) -> GovernanceContribution:
    points = {
        DriftDeploymentScope.UNKNOWN: 0.8,
        DriftDeploymentScope.LOCAL: 0.0,
        DriftDeploymentScope.DEVELOPMENT: 0.1,
        DriftDeploymentScope.TEST: 0.1,
        DriftDeploymentScope.STAGING: 0.3,
        DriftDeploymentScope.PRODUCTION: 0.7,
        DriftDeploymentScope.EXTERNAL: 0.7,
    }[scope]
    return GovernanceContribution(
        dimension=GovernanceDimension.DEPLOYMENT_SCOPE,
        points=points,
        rationale=(f"Deployment scope is {scope.value}.",),
    )


def _ownership_contribution(context: GovernanceScoreContext) -> GovernanceContribution:
    missing = int(context.policy_owner is None) + int(context.approval_owner is None)
    points = min(1.5, missing * 0.75)
    return GovernanceContribution(
        dimension=GovernanceDimension.OWNERSHIP,
        points=points,
        rationale=(
            f"Missing governance owners: {missing}.",
            "Owner identity is required for accountable policy decisions.",
        ),
    )


def _waiver_contribution(context: GovernanceScoreContext) -> GovernanceContribution:
    points = min(
        2.0,
        context.waiver_count * 0.5 + context.expired_waiver_count * 0.5,
    )
    return GovernanceContribution(
        dimension=GovernanceDimension.WAIVER,
        points=_round_score(points),
        rationale=(
            (
                f"Waivers total={context.waiver_count}, "
                f"expired={context.expired_waiver_count}."
            ),
            "Waiver lifecycle is governance evidence, not an automatic risk override.",
        ),
    )


def _manifest_sha256(manifest: AgentManifest) -> str:
    import hashlib

    return hashlib.sha256(
        encode_agent_manifest_json(manifest).encode("utf-8")
    ).hexdigest()


def _validate_hash(value: str, label: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _validate_score(value: float, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 10.0
    ):
        raise ValueError(f"{label} must be finite and within 0 to 10")


def _round_score(value: float) -> float:
    from decimal import ROUND_HALF_UP, Decimal

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("score must be numeric")
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _validate_string_tuple(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{label} must be sorted and unique")


def _validate_unique_strings(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


__all__ = [
    "GOVERNANCE_SCORE_BASIS",
    "GOVERNANCE_SCORE_FORMAT",
    "GOVERNANCE_SCORE_FORMAT_VERSION",
    "DeterministicGovernanceScoreEngine",
    "GovernanceContribution",
    "GovernanceDimension",
    "GovernanceReviewStatus",
    "GovernanceScoreAssessment",
    "GovernanceScoreContext",
    "GovernanceScoreError",
    "encode_governance_score_json",
]

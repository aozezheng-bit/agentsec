"""Deterministic Capability Drift Score calculation (P2-21 Agentic Risk Track)."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from agentsec.change_impact.models import CapabilityChangeImpactReport
from agentsec.domain import Severity
from agentsec.manifests import (
    AgentManifest,
    CapabilityChangeType,
    CapabilityDiffer,
    CapabilityDiffResult,
    CapabilityDimension,
    CapabilityItemChange,
    ManifestSourceLocator,
    ManifestSourceReference,
    encode_agent_manifest_json,
)
from agentsec.risk.cvss import severity_for_cvss_score
from agentsec.versioning import DRIFT_SCORE_MODEL_VERSION

DRIFT_SCORE_FORMAT: Literal["agentsec-drift-score"] = "agentsec-drift-score"
DRIFT_SCORE_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
DRIFT_SCORE_BASIS = (
    "AgentSec P2-21 deterministic Capability Drift Score contract 0.1.0",
    "Capability Diff identifies changed scope without copying raw before/after values",
    "Source, approval, deployment, and baseline context are bounded policy multipliers",
    "Incomplete Coverage has a conservative minimum score and is never a clean pass",
    "The score is an AgentSec policy metric, not a NIST or CVSS formula",
)

DRIFT_DIMENSION_POINTS: Mapping[CapabilityDimension, float] = {
    CapabilityDimension.TOOL: 1.5,
    CapabilityDimension.PERMISSION: 2.5,
    CapabilityDimension.CONTROL: 2.0,
    CapabilityDimension.RUNTIME_IDENTITY: 2.5,
    CapabilityDimension.RELATIONSHIP: 1.5,
    CapabilityDimension.UNKNOWN: 1.5,
}
DRIFT_CHANGE_TYPE_MULTIPLIERS: Mapping[CapabilityChangeType, float] = {
    CapabilityChangeType.ADDED: 1.0,
    CapabilityChangeType.MODIFIED: 0.8,
    CapabilityChangeType.REMOVED: 0.0,
}
DRIFT_INCOMPLETE_FLOOR = 5.0


class DriftChangeSource(StrEnum):
    """Bounded origin classification supplied by the caller or CI adapter."""

    UNKNOWN = "unknown"
    LOCAL_EDIT = "local_edit"
    REVIEWED_CHANGE = "reviewed_change"
    CI_CHANGE = "ci_change"
    RELEASE_CHANGE = "release_change"
    EXTERNAL_CHANGE = "external_change"


class DriftApprovalStatus(StrEnum):
    """Approval status without treating approval as runtime proof."""

    UNKNOWN = "unknown"
    NOT_REQUIRED = "not_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class DriftDeploymentScope(StrEnum):
    """Deployment scope used to contextualize change impact."""

    UNKNOWN = "unknown"
    LOCAL = "local"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"
    EXTERNAL = "external"


class DriftBaselineTrust(StrEnum):
    """Trust posture of the before-state baseline."""

    UNKNOWN = "unknown"
    HASH_ONLY = "hash_only"
    SIGNED_ATTESTED = "signed_attested"


class DriftDirection(StrEnum):
    """Direction of one change's potential exposure contribution."""

    INCREASED = "increased"
    DECREASED = "decreased"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class DriftScoreContext:
    """Explicit context required to avoid guessing governance semantics."""

    change_source: DriftChangeSource = DriftChangeSource.UNKNOWN
    approval_status: DriftApprovalStatus = DriftApprovalStatus.UNKNOWN
    deployment_scope: DriftDeploymentScope = DriftDeploymentScope.UNKNOWN
    baseline_trust: DriftBaselineTrust = DriftBaselineTrust.UNKNOWN
    approval_reference: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.change_source, DriftChangeSource):
            raise TypeError("change_source must be DriftChangeSource")
        if not isinstance(self.approval_status, DriftApprovalStatus):
            raise TypeError("approval_status must be DriftApprovalStatus")
        if not isinstance(self.deployment_scope, DriftDeploymentScope):
            raise TypeError("deployment_scope must be DriftDeploymentScope")
        if not isinstance(self.baseline_trust, DriftBaselineTrust):
            raise TypeError("baseline_trust must be DriftBaselineTrust")
        if self.approval_reference is not None and (
            not self.approval_reference.strip()
            or len(self.approval_reference) > 128
            or any(
                char
                not in (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                )
                for char in self.approval_reference
            )
        ):
            raise ValueError("approval_reference must be a bounded stable identifier")
        if (
            self.approval_status is DriftApprovalStatus.APPROVED
            and not self.approval_reference
        ):
            raise ValueError("approved drift requires an approval_reference")

    def to_dict(self) -> dict[str, object]:
        return {
            "change_source": self.change_source.value,
            "approval_status": self.approval_status.value,
            "deployment_scope": self.deployment_scope.value,
            "baseline_trust": self.baseline_trust.value,
            "approval_reference": self.approval_reference,
        }


@dataclass(frozen=True, slots=True)
class DriftScoreEvidence:
    """Value-free evidence for one before/after Capability change."""

    side: Literal["before", "after"]
    locator: ManifestSourceLocator
    content_sha256: str
    field_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        if self.side not in {"before", "after"}:
            raise ValueError("drift evidence side must be before or after")
        if len(self.content_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.content_sha256
        ):
            raise ValueError("drift evidence content_sha256 must be lowercase SHA-256")
        if self.field_path is not None and not self.field_path.strip():
            raise ValueError("drift evidence field_path must not be empty")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("drift evidence line range must be complete")
        if self.start_line is not None and (
            self.start_line < 1
            or self.end_line is None
            or self.end_line < self.start_line
        ):
            raise ValueError("drift evidence line range is invalid")

    def sort_key(self) -> tuple[str, str, str, str, str, int, int]:
        return (
            self.side,
            *self.locator.sort_key(),
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "side": self.side,
            "scope": self.locator.scope.value,
            "root_id": self.locator.root_id,
            "path": self.locator.path,
            "field_path": self.field_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class DriftChangeContribution:
    """One auditable Capability Diff contribution to Drift Score."""

    dimension: CapabilityDimension
    item_id: str
    change_type: CapabilityChangeType
    changed_fields: tuple[str, ...]
    direction: DriftDirection
    points: float
    evidence: tuple[DriftScoreEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.item_id.strip():
            raise ValueError("drift contribution item_id must not be empty")
        if not self.changed_fields or self.changed_fields != tuple(
            sorted(set(self.changed_fields))
        ):
            raise ValueError(
                "drift contribution changed_fields must be sorted and unique"
            )
        if not isinstance(self.direction, DriftDirection):
            raise TypeError("drift contribution direction must be DriftDirection")
        if not 0.0 <= self.points <= 10.0:
            raise ValueError("drift contribution points must be within 0 to 10")
        _validate_evidence(self.evidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "item_id": self.item_id,
            "change_type": self.change_type.value,
            "changed_fields": list(self.changed_fields),
            "direction": self.direction.value,
            "points": self.points,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class DriftScoreAssessment:
    """Versioned Drift Score with gross score, context, and intermediate values."""

    format: Literal["agentsec-drift-score"]
    format_version: Literal["0.1.0"]
    model_version: str
    capability_diff_schema_version: str
    agent_id: str
    before_manifest_sha256: str
    after_manifest_sha256: str
    coverage_complete: bool
    changed_capabilities: int
    increased_exposure_changes: int
    uncertain_changes: int
    gross_change_score: float
    context: DriftScoreContext
    context_multiplier: float
    drift_score: float
    severity: Severity
    contributions: tuple[DriftChangeContribution, ...] = dataclass_field(repr=False)
    profile_change_score: float = 0.0
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False, default=())

    def __post_init__(self) -> None:
        if self.format != DRIFT_SCORE_FORMAT:
            raise ValueError("Drift Score format is unsupported")
        if self.format_version != DRIFT_SCORE_FORMAT_VERSION:
            raise ValueError("Drift Score format version is unsupported")
        if self.model_version != DRIFT_SCORE_MODEL_VERSION:
            raise ValueError("Drift Score model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("Drift Score Agent ID must not be empty")
        _validate_hash(self.before_manifest_sha256, "before_manifest_sha256")
        _validate_hash(self.after_manifest_sha256, "after_manifest_sha256")
        if self.changed_capabilities < 0:
            raise ValueError("changed_capabilities must not be negative")
        if self.increased_exposure_changes < 0 or self.uncertain_changes < 0:
            raise ValueError("Drift change counts must not be negative")
        _validate_score(self.gross_change_score, "gross_change_score")
        _validate_score(self.context_multiplier, "context_multiplier")
        _validate_score(self.drift_score, "drift_score")
        _validate_score(self.profile_change_score, "profile_change_score")
        if not isinstance(self.context, DriftScoreContext):
            raise TypeError("Drift Score context is invalid")
        if not isinstance(self.severity, Severity):
            raise TypeError("Drift Score severity must be Severity")
        if severity_for_cvss_score(self.drift_score) is not self.severity:
            raise ValueError("Drift Score severity is inconsistent")
        if self.changed_capabilities != len(self.contributions):
            raise ValueError("changed_capabilities must match contributions")
        if self.gross_change_score < self.profile_change_score:
            raise ValueError("gross_change_score cannot be below profile_change_score")
        expected = _round_score(
            max(
                self.gross_change_score * self.context_multiplier,
                DRIFT_INCOMPLETE_FLOOR if not self.coverage_complete else 0.0,
            )
        )
        if self.drift_score != expected:
            raise ValueError("drift_score is inconsistent with context and Coverage")
        if self.mapping_basis != tuple(dict.fromkeys(self.mapping_basis)):
            raise ValueError("Drift mapping basis must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "capability_diff_schema_version": self.capability_diff_schema_version,
            "agent_id": self.agent_id,
            "before_manifest_sha256": self.before_manifest_sha256,
            "after_manifest_sha256": self.after_manifest_sha256,
            "coverage_complete": self.coverage_complete,
            "changed_capabilities": self.changed_capabilities,
            "increased_exposure_changes": self.increased_exposure_changes,
            "uncertain_changes": self.uncertain_changes,
            "gross_change_score": self.gross_change_score,
            "profile_change_score": self.profile_change_score,
            "context": self.context.to_dict(),
            "context_multiplier": self.context_multiplier,
            "drift_score": self.drift_score,
            "severity": self.severity.value,
            "contributions": [item.to_dict() for item in self.contributions],
            "mapping_basis": list(self.mapping_basis),
        }


class DriftScoreError(RuntimeError):
    """Safe deterministic Drift Score failure."""


def encode_drift_score_json(assessment: DriftScoreAssessment) -> str:
    """Encode a Drift Score without raw before/after values."""

    if not isinstance(assessment, DriftScoreAssessment):
        raise TypeError("assessment must be DriftScoreAssessment")
    return (
        json.dumps(assessment.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicDriftScoreEngine:
    """Score Capability Diff changes with explicit governance/deployment context."""

    def score(
        self,
        before: AgentManifest,
        after: AgentManifest,
        *,
        diff: CapabilityDiffResult,
        context: DriftScoreContext | None = None,
        impact_report: CapabilityChangeImpactReport | None = None,
    ) -> DriftScoreAssessment:
        if not isinstance(before, AgentManifest) or not isinstance(
            after, AgentManifest
        ):
            raise TypeError("Drift Score requires before and after AgentManifest")
        if not isinstance(diff, CapabilityDiffResult):
            raise TypeError("Drift Score requires CapabilityDiffResult")
        selected_context = context or DriftScoreContext()
        if not isinstance(selected_context, DriftScoreContext):
            raise TypeError("Drift Score context must be DriftScoreContext")
        if impact_report is not None and not isinstance(
            impact_report, CapabilityChangeImpactReport
        ):
            raise TypeError("impact_report must be CapabilityChangeImpactReport")
        try:
            self._validate_bindings(before, after, diff, impact_report)
            impact_directions = _impact_directions(impact_report)
            before_hash = _manifest_sha256(before)
            after_hash = _manifest_sha256(after)
            source_hashes = _source_hashes(before, after)
            contributions = tuple(
                self._contribution(change, impact_directions, source_hashes)
                for change in diff.changes
            )
            profile_score = _profile_change_score(diff)
            gross_score = _round_score(
                min(10.0, sum(item.points for item in contributions) + profile_score)
            )
            multipliers = _context_multipliers(selected_context)
            context_multiplier = _round_score(
                multipliers[0] * multipliers[1] * multipliers[2] * multipliers[3]
            )
            drift_score = _round_score(
                max(
                    gross_score * context_multiplier,
                    DRIFT_INCOMPLETE_FLOOR if not diff.complete else 0.0,
                )
            )
            return DriftScoreAssessment(
                format=DRIFT_SCORE_FORMAT,
                format_version=DRIFT_SCORE_FORMAT_VERSION,
                model_version=DRIFT_SCORE_MODEL_VERSION,
                capability_diff_schema_version=diff.schema_version,
                agent_id=diff.agent_id,
                before_manifest_sha256=before_hash,
                after_manifest_sha256=after_hash,
                coverage_complete=diff.complete,
                changed_capabilities=len(contributions),
                increased_exposure_changes=sum(
                    item.direction is DriftDirection.INCREASED for item in contributions
                ),
                uncertain_changes=sum(
                    item.direction is DriftDirection.UNCERTAIN for item in contributions
                ),
                gross_change_score=gross_score,
                context=selected_context,
                context_multiplier=context_multiplier,
                drift_score=drift_score,
                severity=severity_for_cvss_score(drift_score),
                contributions=contributions,
                profile_change_score=profile_score,
                mapping_basis=DRIFT_SCORE_BASIS,
            )
        except (TypeError, ValueError, KeyError) as error:
            raise DriftScoreError("Drift Score calculation failed safely") from error

    @staticmethod
    def _validate_bindings(
        before: AgentManifest,
        after: AgentManifest,
        diff: CapabilityDiffResult,
        impact_report: CapabilityChangeImpactReport | None,
    ) -> None:
        if before.identity.agent_id != after.identity.agent_id:
            raise ValueError("Drift Score before/after Agent IDs differ")
        if diff.agent_id != before.identity.agent_id:
            raise ValueError("Drift Score Diff Agent ID does not match Manifests")
        expected_diff = CapabilityDiffer().compare(before=before, after=after)
        if expected_diff != diff:
            raise ValueError("Drift Score Diff does not match the supplied Manifests")
        if impact_report is not None and impact_report.capability_diff != diff:
            raise ValueError("Drift Score Impact Report does not match Diff")

    @staticmethod
    def _contribution(
        change: CapabilityItemChange,
        impact_directions: dict[
            tuple[CapabilityDimension, str, CapabilityChangeType], DriftDirection
        ],
        source_hashes: dict[tuple[str, str, str], tuple[str | None, str | None]],
    ) -> DriftChangeContribution:
        item = change
        direction = impact_directions.get(
            (item.dimension, item.item_id, item.change_type),
            _default_direction(item.change_type, item.dimension),
        )
        field_multiplier = _field_multiplier(item.changed_fields, item.change_type)
        direction_multiplier = {
            DriftDirection.INCREASED: 1.0,
            DriftDirection.UNCERTAIN: 0.6,
            DriftDirection.DECREASED: 0.0,
        }[direction]
        points = _round_score(
            DRIFT_DIMENSION_POINTS[item.dimension]
            * DRIFT_CHANGE_TYPE_MULTIPLIERS[item.change_type]
            * field_multiplier
            * direction_multiplier
        )
        evidence = _drift_evidence(item, source_hashes)
        return DriftChangeContribution(
            dimension=item.dimension,
            item_id=item.item_id,
            change_type=item.change_type,
            changed_fields=item.changed_fields,
            direction=direction,
            points=points,
            evidence=evidence,
        )


def _default_direction(
    change_type: CapabilityChangeType,
    dimension: CapabilityDimension,
) -> DriftDirection:
    if change_type is CapabilityChangeType.ADDED:
        if dimension in {CapabilityDimension.CONTROL, CapabilityDimension.UNKNOWN}:
            return DriftDirection.UNCERTAIN
        return DriftDirection.INCREASED
    if change_type is CapabilityChangeType.REMOVED:
        if dimension is CapabilityDimension.CONTROL:
            return DriftDirection.INCREASED
        return DriftDirection.DECREASED
    return DriftDirection.UNCERTAIN


def _field_multiplier(
    fields: tuple[str, ...], change_type: CapabilityChangeType
) -> float:
    if change_type in {CapabilityChangeType.ADDED, CapabilityChangeType.REMOVED}:
        return 1.0
    sensitive = {
        "action",
        "availability",
        "authentication",
        "effect",
        "environment",
        "kind",
        "privileged",
        "resource",
        "scope",
        "side_effects",
        "state",
        "target",
    }
    return 1.0 if sensitive.intersection(fields) else 0.5


def _profile_change_score(diff: CapabilityDiffResult) -> float:
    score = 0.0
    for change in diff.profile_changes:
        if change.profile.value == "coverage" and change.after == "incomplete":
            score += 3.0
        else:
            score += 0.5
    return _round_score(min(10.0, score))


def _looks_like_impact_report(report: object) -> bool:
    return hasattr(report, "capability_diff") and hasattr(report, "change_impacts")


def _impact_directions(
    report: CapabilityChangeImpactReport | None,
) -> dict[tuple[CapabilityDimension, str, CapabilityChangeType], DriftDirection]:
    if report is None:
        return {}
    result: dict[
        tuple[CapabilityDimension, str, CapabilityChangeType], DriftDirection
    ] = {}
    for item in report.change_impacts:
        direction = {
            "increased_exposure": DriftDirection.INCREASED,
            "reduced_exposure": DriftDirection.DECREASED,
            "uncertain": DriftDirection.UNCERTAIN,
            "mixed": DriftDirection.UNCERTAIN,
            "neutral": DriftDirection.DECREASED,
        }[item.direction.value]
        result[(item.dimension, item.item_id, item.change_type)] = direction
    return result


def _context_multipliers(
    context: DriftScoreContext,
) -> tuple[float, float, float, float]:
    source = {
        DriftChangeSource.UNKNOWN: 1.0,
        DriftChangeSource.LOCAL_EDIT: 0.95,
        DriftChangeSource.REVIEWED_CHANGE: 0.9,
        DriftChangeSource.CI_CHANGE: 0.95,
        DriftChangeSource.RELEASE_CHANGE: 0.95,
        DriftChangeSource.EXTERNAL_CHANGE: 1.0,
    }[context.change_source]
    approval = {
        DriftApprovalStatus.UNKNOWN: 1.0,
        DriftApprovalStatus.NOT_REQUIRED: 0.95,
        DriftApprovalStatus.APPROVED: 0.9,
        DriftApprovalStatus.REJECTED: 1.0,
        DriftApprovalStatus.EXPIRED: 1.0,
    }[context.approval_status]
    deployment = {
        DriftDeploymentScope.UNKNOWN: 1.0,
        DriftDeploymentScope.LOCAL: 0.5,
        DriftDeploymentScope.DEVELOPMENT: 0.6,
        DriftDeploymentScope.TEST: 0.6,
        DriftDeploymentScope.STAGING: 0.8,
        DriftDeploymentScope.PRODUCTION: 1.0,
        DriftDeploymentScope.EXTERNAL: 1.0,
    }[context.deployment_scope]
    baseline = {
        DriftBaselineTrust.UNKNOWN: 1.0,
        DriftBaselineTrust.HASH_ONLY: 0.95,
        DriftBaselineTrust.SIGNED_ATTESTED: 0.9,
    }[context.baseline_trust]
    return source, approval, deployment, baseline


def _source_hashes(
    before: AgentManifest,
    after: AgentManifest,
) -> dict[tuple[str, str, str], tuple[str | None, str | None]]:
    result: dict[tuple[str, str, str], tuple[str | None, str | None]] = {}
    for source in before.sources:
        result[source.locator.sort_key()] = (source.content_sha256, None)
    for source in after.sources:
        key = source.locator.sort_key()
        previous = result.get(key, (None, None))
        result[key] = (previous[0], source.content_sha256)
    return result


def _drift_evidence(
    change: CapabilityItemChange,
    source_hashes: dict[tuple[str, str, str], tuple[str | None, str | None]],
) -> tuple[DriftScoreEvidence, ...]:
    evidence: list[DriftScoreEvidence] = []
    sides: tuple[
        tuple[Literal["before", "after"], tuple[ManifestSourceReference, ...]], ...
    ] = (
        ("before", change.before_sources),
        ("after", change.after_sources),
    )
    for side, references in sides:
        for reference in references:
            source = source_hashes.get(reference.locator.sort_key())
            if source is None:
                raise ValueError("Capability Diff source is missing from Manifest")
            content_hash = source[0] if side == "before" else source[1]
            if content_hash is None:
                raise ValueError("Capability Diff source hash is missing from Manifest")
            evidence.append(
                DriftScoreEvidence(
                    side=side,
                    locator=reference.locator,
                    content_sha256=content_hash,
                    field_path=reference.field_path,
                    start_line=reference.start_line,
                    end_line=reference.end_line,
                )
            )
    return tuple(sorted(set(evidence), key=lambda item: item.sort_key()))


def _manifest_sha256(manifest: AgentManifest) -> str:
    return hashlib.sha256(
        encode_agent_manifest_json(manifest).encode("utf-8")
    ).hexdigest()


def _validate_evidence(evidence: tuple[DriftScoreEvidence, ...]) -> None:
    keys = tuple(item.sort_key() for item in evidence)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError("Drift evidence must be sorted and unique")


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
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("score must be numeric")
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


__all__ = [
    "DRIFT_CHANGE_TYPE_MULTIPLIERS",
    "DRIFT_DIMENSION_POINTS",
    "DRIFT_INCOMPLETE_FLOOR",
    "DRIFT_SCORE_BASIS",
    "DRIFT_SCORE_FORMAT",
    "DRIFT_SCORE_FORMAT_VERSION",
    "DeterministicDriftScoreEngine",
    "DriftApprovalStatus",
    "DriftBaselineTrust",
    "DriftChangeContribution",
    "DriftChangeSource",
    "DriftDeploymentScope",
    "DriftDirection",
    "DriftScoreAssessment",
    "DriftScoreContext",
    "DriftScoreError",
    "DriftScoreEvidence",
    "encode_drift_score_json",
]

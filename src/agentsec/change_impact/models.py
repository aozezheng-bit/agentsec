"""Versioned value-minimizing Capability Change Impact artifact models."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.capability_rules import CapabilityCorrelation
from agentsec.domain import EvidenceConfidence, FindingCategory, Severity
from agentsec.manifests import (
    CapabilityChangeType,
    CapabilityDiffResult,
    CapabilityDimension,
)
from agentsec.risk import NistRiskLevel
from agentsec.versioning import CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION

CAPABILITY_CHANGE_IMPACT_FORMAT: Literal["agentsec-capability-change-impact"] = (
    "agentsec-capability-change-impact"
)
CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION = cast(
    Literal["0.1.0"], CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION
)
CAPABILITY_CHANGE_IMPACT_SCHEMA_FILENAME = "capability-change-impact.schema.json"

NonNegativeInt = Annotated[int, Field(ge=0)]
SafeIdentifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
Sha256String = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ImpactId = Annotated[str, Field(pattern=r"^capability-impact-sha256:[a-f0-9]{64}$")]
FindingDeltaId = Annotated[
    str, Field(pattern=r"^capability-finding-delta-sha256:[a-f0-9]{64}$")
]
FindingId = Annotated[str, Field(pattern=r"^capability-finding-sha256:[a-f0-9]{64}$")]
RuleId = Annotated[str, Field(pattern=r"^CAP-[A-Z][A-Z0-9]*-[0-9]{3}$")]

_SAFE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class _ImpactModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class CapabilityImpactDirection(StrEnum):
    """Deterministic exposure direction, separate from Finding Severity."""

    INCREASED_EXPOSURE = "increased_exposure"
    REDUCED_EXPOSURE = "reduced_exposure"
    MIXED = "mixed"
    NEUTRAL = "neutral"
    UNCERTAIN = "uncertain"


class CapabilityImpactReason(StrEnum):
    """Stable, value-free reasons supporting one change-impact classification."""

    CAPABILITY_ADDED = "capability_added"
    CAPABILITY_REMOVED = "capability_removed"
    TOOL_ENABLED = "tool_enabled"
    TOOL_DISABLED = "tool_disabled"
    SENSITIVE_EFFECT_ADDED = "sensitive_effect_added"
    SENSITIVE_EFFECT_REMOVED = "sensitive_effect_removed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    PERMISSION_EFFECT_WEAKENED = "permission_effect_weakened"
    PERMISSION_EFFECT_STRENGTHENED = "permission_effect_strengthened"
    CONTROL_WEAKENED = "control_weakened"
    CONTROL_STRENGTHENED = "control_strengthened"
    SEMANTIC_STATE_CHANGED = "semantic_state_changed"
    UNKNOWN_STATE = "unknown_state"


class CapabilitySemanticField(StrEnum):
    """Reviewed normalized fields safe to expose as semantic before/after state."""

    ACTION = "action"
    AVAILABILITY = "availability"
    EFFECT = "effect"
    KIND = "kind"
    PARENT_TOOL_ID = "parent_tool_id"
    RESOURCE = "resource"
    SCOPE = "scope"
    SIDE_EFFECTS = "side_effects"
    STATE = "state"
    TARGET = "target"


class CapabilityFindingDeltaStatus(StrEnum):
    """Lifecycle status of one logical deterministic Capability Finding."""

    ADDED = "added"
    RESOLVED = "resolved"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


class CapabilityFindingRiskDirection(StrEnum):
    """Risk-direction interpretation without averaging Finding scores."""

    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"
    UNCERTAIN = "uncertain"


class CapabilitySemanticAttribute(_ImpactModel):
    """One normalized semantic field with bounded trusted values."""

    field: CapabilitySemanticField
    values: tuple[str, ...]

    @model_validator(mode="after")
    def values_must_be_safe_sorted_and_unique(self) -> CapabilitySemanticAttribute:
        if self.values != tuple(sorted(set(self.values))):
            raise ValueError("semantic attribute values must be sorted and unique")
        if any(_SAFE_VALUE_PATTERN.fullmatch(value) is None for value in self.values):
            raise ValueError("semantic attribute contains an unsafe value")
        return self


class CapabilitySemanticState(_ImpactModel):
    """Value-minimizing before or after state for Tool/Permission/Control."""

    dimension: CapabilityDimension
    item_id: SafeIdentifier
    attributes: tuple[CapabilitySemanticAttribute, ...]

    @model_validator(mode="after")
    def state_must_be_coherent(self) -> CapabilitySemanticState:
        if self.dimension not in {
            CapabilityDimension.TOOL,
            CapabilityDimension.PERMISSION,
            CapabilityDimension.CONTROL,
        }:
            raise ValueError("semantic state supports Tool, Permission, or Control")
        fields = tuple(attribute.field.value for attribute in self.attributes)
        if not fields or fields != tuple(sorted(set(fields))):
            raise ValueError("semantic state attributes must be sorted and unique")
        return self


class CapabilityChangeImpact(_ImpactModel):
    """Semantic before/after state plus deterministic exposure direction."""

    impact_id: ImpactId
    dimension: CapabilityDimension
    item_id: SafeIdentifier
    change_type: CapabilityChangeType
    before: CapabilitySemanticState | None
    after: CapabilitySemanticState | None
    direction: CapabilityImpactDirection
    reasons: tuple[CapabilityImpactReason, ...]
    related_finding_delta_ids: tuple[FindingDeltaId, ...] = ()

    @model_validator(mode="after")
    def impact_must_be_coherent(self) -> CapabilityChangeImpact:
        if self.dimension not in {
            CapabilityDimension.TOOL,
            CapabilityDimension.PERMISSION,
            CapabilityDimension.CONTROL,
        }:
            raise ValueError("change impact supports Tool, Permission, or Control")
        if self.change_type is CapabilityChangeType.ADDED:
            if self.before is not None or self.after is None:
                raise ValueError("added impact requires only after state")
        elif self.change_type is CapabilityChangeType.REMOVED:
            if self.before is None or self.after is not None:
                raise ValueError("removed impact requires only before state")
        elif self.before is None or self.after is None:
            raise ValueError("modified impact requires before and after state")
        for state in (self.before, self.after):
            if state is None:
                continue
            if state.dimension is not self.dimension or state.item_id != self.item_id:
                raise ValueError("impact semantic state identity is inconsistent")
        if not self.reasons or self.reasons != tuple(
            sorted(set(self.reasons), key=lambda item: item.value)
        ):
            raise ValueError("impact reasons must be non-empty, sorted, and unique")
        if self.related_finding_delta_ids != tuple(
            sorted(set(self.related_finding_delta_ids))
        ):
            raise ValueError("related Finding Delta IDs must be sorted and unique")
        return self

    def sort_key(self) -> tuple[str, str, str]:
        return (self.dimension.value, self.item_id, self.impact_id)


class CapabilityFindingSnapshot(_ImpactModel):
    """Value-free risk snapshot of one deterministic Capability Finding."""

    finding_id: FindingId
    rule_id: RuleId
    category: FindingCategory
    title_en: str
    title_zh: str
    correlation: CapabilityCorrelation
    risk_level: NistRiskLevel
    score: Annotated[float, Field(ge=0, le=10)]
    severity: Severity
    confidence: EvidenceConfidence
    hard_gate: Literal[False]
    related_ids: tuple[SafeIdentifier, ...]
    evidence_sha256: Sha256String

    @model_validator(mode="after")
    def snapshot_must_be_coherent(self) -> CapabilityFindingSnapshot:
        if not self.title_en.strip() or not self.title_zh.strip():
            raise ValueError("Finding snapshot titles must not be empty")
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError("Finding snapshot related IDs must be sorted and unique")
        return self


class CapabilityFindingDelta(_ImpactModel):
    """Added, resolved, changed, or unchanged logical Capability Finding."""

    delta_id: FindingDeltaId
    rule_id: RuleId
    related_ids: tuple[SafeIdentifier, ...]
    status: CapabilityFindingDeltaStatus
    risk_direction: CapabilityFindingRiskDirection
    before: CapabilityFindingSnapshot | None
    after: CapabilityFindingSnapshot | None
    changed_fields: tuple[str, ...]
    impacted_change_ids: tuple[ImpactId, ...] = ()

    @model_validator(mode="after")
    def delta_must_be_coherent(self) -> CapabilityFindingDelta:
        expected_fields: tuple[str, ...]
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError("Finding Delta related IDs must be sorted and unique")
        if self.status is CapabilityFindingDeltaStatus.ADDED:
            if self.before is not None or self.after is None:
                raise ValueError("added Finding Delta requires only after snapshot")
            expected_fields = ("finding",)
        elif self.status is CapabilityFindingDeltaStatus.RESOLVED:
            if self.before is None or self.after is not None:
                raise ValueError("resolved Finding Delta requires only before snapshot")
            expected_fields = ("finding",)
        elif self.before is None or self.after is None:
            raise ValueError("persisting Finding Delta requires both snapshots")
        elif self.status is CapabilityFindingDeltaStatus.UNCHANGED:
            expected_fields = ()
            if self.before != self.after:
                raise ValueError("unchanged Finding Delta snapshots must be identical")
        else:
            if self.before == self.after:
                raise ValueError("changed Finding Delta snapshots must differ")
            expected_fields = self.changed_fields
            if not expected_fields:
                raise ValueError("changed Finding Delta requires changed fields")
        if self.changed_fields != tuple(sorted(set(self.changed_fields))):
            raise ValueError("Finding Delta changed fields must be sorted and unique")
        if (
            self.status
            in {
                CapabilityFindingDeltaStatus.ADDED,
                CapabilityFindingDeltaStatus.RESOLVED,
            }
            and self.changed_fields != expected_fields
        ):
            raise ValueError("Finding Delta lifecycle fields are inconsistent")
        for snapshot in (self.before, self.after):
            if snapshot is None:
                continue
            if (
                snapshot.rule_id != self.rule_id
                or snapshot.related_ids != self.related_ids
            ):
                raise ValueError("Finding Delta logical identity is inconsistent")
        if self.risk_direction is not expected_finding_risk_direction(
            status=self.status,
            before=self.before,
            after=self.after,
        ):
            raise ValueError("Finding Delta risk direction is inconsistent")
        if self.impacted_change_ids != tuple(sorted(set(self.impacted_change_ids))):
            raise ValueError("Finding Delta impact IDs must be sorted and unique")
        return self

    def sort_key(self) -> tuple[str, tuple[str, ...], str]:
        return (self.rule_id, self.related_ids, self.delta_id)


class CapabilityChangeImpactVersions(_ImpactModel):
    package: str
    agent_manifest_schema: str
    capability_diff_schema: str
    capability_rule_pack: str
    capability_risk_model: str
    capability_change_impact_output: str


class CapabilityChangeImpactPolicy(_ImpactModel):
    enforcement_mode: Literal["report_only"]
    ci_blocking_enabled: Literal[False]
    runtime_capability_verified: Literal[False]
    global_safety_claimed: Literal[False]


class CapabilityChangeImpactSummary(_ImpactModel):
    capability_changes: NonNegativeInt
    assessed_change_impacts: NonNegativeInt
    unassessed_capability_changes: NonNegativeInt
    increased_exposure: NonNegativeInt
    reduced_exposure: NonNegativeInt
    mixed: NonNegativeInt
    neutral: NonNegativeInt
    uncertain: NonNegativeInt
    before_findings: NonNegativeInt
    after_findings: NonNegativeInt
    added_findings: NonNegativeInt
    resolved_findings: NonNegativeInt
    changed_findings: NonNegativeInt
    unchanged_findings: NonNegativeInt
    added_high_or_critical: NonNegativeInt
    resolved_high_or_critical: NonNegativeInt
    highest_before_severity: Severity
    highest_after_severity: Severity
    capability_diff_complete: bool
    before_rule_execution_complete: bool
    after_rule_execution_complete: bool


class CapabilityChangeImpactReport(_ImpactModel):
    """Strict P2-13 semantic Change Impact and Finding Delta artifact."""

    format: Literal["agentsec-capability-change-impact"]
    format_version: Literal["0.1.0"]
    status: Literal["complete", "incomplete"]
    agent_id: SafeIdentifier
    versions: CapabilityChangeImpactVersions
    policy: CapabilityChangeImpactPolicy
    summary: CapabilityChangeImpactSummary
    capability_diff: CapabilityDiffResult
    change_impacts: tuple[CapabilityChangeImpact, ...]
    finding_delta: tuple[CapabilityFindingDelta, ...]
    before_rule_failures: tuple[RuleId, ...] = ()
    after_rule_failures: tuple[RuleId, ...] = ()

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> CapabilityChangeImpactReport:
        if self.capability_diff.agent_id != self.agent_id:
            raise ValueError("Change Impact Agent does not match Capability Diff")
        if self.versions.agent_manifest_schema != (
            self.capability_diff.agent_manifest_schema_version
        ):
            raise ValueError("Change Impact Manifest version is inconsistent")
        if self.versions.capability_diff_schema != self.capability_diff.schema_version:
            raise ValueError("Change Impact Diff version is inconsistent")
        if self.versions.capability_change_impact_output != self.format_version:
            raise ValueError("Change Impact output version is inconsistent")
        impact_keys = tuple(item.sort_key() for item in self.change_impacts)
        if impact_keys != tuple(sorted(set(impact_keys))):
            raise ValueError("Change Impacts must be sorted and unique")
        delta_keys = tuple(item.sort_key() for item in self.finding_delta)
        if delta_keys != tuple(sorted(set(delta_keys))):
            raise ValueError("Finding Delta entries must be sorted and unique")
        for failures in (self.before_rule_failures, self.after_rule_failures):
            if failures != tuple(sorted(set(failures))):
                raise ValueError("Rule failure IDs must be sorted and unique")
        expected_complete = (
            self.capability_diff.complete
            and not self.before_rule_failures
            and not self.after_rule_failures
        )
        if self.status != ("complete" if expected_complete else "incomplete"):
            raise ValueError("Change Impact status is inconsistent")
        if self.summary != derive_change_impact_summary(
            capability_diff=self.capability_diff,
            change_impacts=self.change_impacts,
            finding_delta=self.finding_delta,
            before_rule_failures=self.before_rule_failures,
            after_rule_failures=self.after_rule_failures,
        ):
            raise ValueError("Change Impact summary is inconsistent")
        assessed_keys = {
            (item.dimension, item.item_id, item.change_type)
            for item in self.change_impacts
        }
        expected_keys = {
            (item.dimension, item.item_id, item.change_type)
            for item in self.capability_diff.changes
            if item.dimension
            in {
                CapabilityDimension.TOOL,
                CapabilityDimension.PERMISSION,
                CapabilityDimension.CONTROL,
            }
        }
        if assessed_keys != expected_keys:
            raise ValueError(
                "Change Impact does not cover every Tool/Permission/Control"
            )
        delta_ids = {item.delta_id for item in self.finding_delta}
        for impact in self.change_impacts:
            if not set(impact.related_finding_delta_ids) <= delta_ids:
                raise ValueError("Change Impact references an unknown Finding Delta")
        impact_ids = {item.impact_id for item in self.change_impacts}
        for delta in self.finding_delta:
            if not set(delta.impacted_change_ids) <= impact_ids:
                raise ValueError("Finding Delta references an unknown Change Impact")
        return self


def expected_finding_risk_direction(
    *,
    status: CapabilityFindingDeltaStatus,
    before: CapabilityFindingSnapshot | None,
    after: CapabilityFindingSnapshot | None,
) -> CapabilityFindingRiskDirection:
    if status is CapabilityFindingDeltaStatus.ADDED:
        return CapabilityFindingRiskDirection.INCREASED
    if status is CapabilityFindingDeltaStatus.RESOLVED:
        return CapabilityFindingRiskDirection.DECREASED
    if before is None or after is None:
        return CapabilityFindingRiskDirection.UNCERTAIN
    before_rank = _SEVERITY_RANK[before.severity]
    after_rank = _SEVERITY_RANK[after.severity]
    if after_rank > before_rank or after.score > before.score:
        return CapabilityFindingRiskDirection.INCREASED
    if after_rank < before_rank or after.score < before.score:
        return CapabilityFindingRiskDirection.DECREASED
    return CapabilityFindingRiskDirection.UNCHANGED


def derive_change_impact_summary(
    *,
    capability_diff: CapabilityDiffResult,
    change_impacts: tuple[CapabilityChangeImpact, ...],
    finding_delta: tuple[CapabilityFindingDelta, ...],
    before_rule_failures: tuple[str, ...],
    after_rule_failures: tuple[str, ...],
) -> CapabilityChangeImpactSummary:
    directions = {direction: 0 for direction in CapabilityImpactDirection}
    for impact in change_impacts:
        directions[impact.direction] += 1
    statuses = {status: 0 for status in CapabilityFindingDeltaStatus}
    for delta in finding_delta:
        statuses[delta.status] += 1
    before_snapshots = tuple(
        delta.before for delta in finding_delta if delta.before is not None
    )
    after_snapshots = tuple(
        delta.after for delta in finding_delta if delta.after is not None
    )
    before_unique = {snapshot.finding_id: snapshot for snapshot in before_snapshots}
    after_unique = {snapshot.finding_id: snapshot for snapshot in after_snapshots}
    return CapabilityChangeImpactSummary(
        capability_changes=len(capability_diff.changes),
        assessed_change_impacts=len(change_impacts),
        unassessed_capability_changes=(
            len(capability_diff.changes) - len(change_impacts)
        ),
        increased_exposure=directions[CapabilityImpactDirection.INCREASED_EXPOSURE],
        reduced_exposure=directions[CapabilityImpactDirection.REDUCED_EXPOSURE],
        mixed=directions[CapabilityImpactDirection.MIXED],
        neutral=directions[CapabilityImpactDirection.NEUTRAL],
        uncertain=directions[CapabilityImpactDirection.UNCERTAIN],
        before_findings=len(before_unique),
        after_findings=len(after_unique),
        added_findings=statuses[CapabilityFindingDeltaStatus.ADDED],
        resolved_findings=statuses[CapabilityFindingDeltaStatus.RESOLVED],
        changed_findings=statuses[CapabilityFindingDeltaStatus.CHANGED],
        unchanged_findings=statuses[CapabilityFindingDeltaStatus.UNCHANGED],
        added_high_or_critical=sum(
            delta.status is CapabilityFindingDeltaStatus.ADDED
            and delta.after is not None
            and delta.after.severity in {Severity.HIGH, Severity.CRITICAL}
            for delta in finding_delta
        ),
        resolved_high_or_critical=sum(
            delta.status is CapabilityFindingDeltaStatus.RESOLVED
            and delta.before is not None
            and delta.before.severity in {Severity.HIGH, Severity.CRITICAL}
            for delta in finding_delta
        ),
        highest_before_severity=_highest_severity(tuple(before_unique.values())),
        highest_after_severity=_highest_severity(tuple(after_unique.values())),
        capability_diff_complete=capability_diff.complete,
        before_rule_execution_complete=not before_rule_failures,
        after_rule_execution_complete=not after_rule_failures,
    )


def finding_delta_id(rule_id: str, related_ids: tuple[str, ...]) -> str:
    return "capability-finding-delta-sha256:" + _sha256(
        {"rule_id": rule_id, "related_ids": related_ids}
    )


def change_impact_id(
    *,
    dimension: CapabilityDimension,
    item_id: str,
    change_type: CapabilityChangeType,
    before_sha256: str | None,
    after_sha256: str | None,
) -> str:
    return "capability-impact-sha256:" + _sha256(
        {
            "dimension": dimension.value,
            "item_id": item_id,
            "change_type": change_type.value,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
        }
    )


def evidence_fingerprint(snapshot_payload: object) -> str:
    return _sha256(snapshot_payload)


def _sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _highest_severity(
    snapshots: tuple[CapabilityFindingSnapshot, ...],
) -> Severity:
    return max(
        (snapshot.severity for snapshot in snapshots),
        key=_SEVERITY_RANK.__getitem__,
        default=Severity.NONE,
    )

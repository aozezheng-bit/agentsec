"""Deterministic P2-13 semantic Change Impact and Finding Delta analysis."""

from __future__ import annotations

from collections.abc import Mapping

from agentsec.capability_rules import CapabilityRuleFinding, CapabilityRuleRunResult
from agentsec.manifests import (
    AgentManifest,
    CapabilityChangeType,
    CapabilityDiffResult,
    CapabilityDimension,
    ManifestControl,
    ManifestControlKind,
    ManifestControlState,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestTool,
    ManifestToolAvailability,
    ManifestToolSideEffect,
)
from agentsec.versioning import VersionSet

from .models import (
    CAPABILITY_CHANGE_IMPACT_FORMAT,
    CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION,
    CapabilityChangeImpact,
    CapabilityChangeImpactPolicy,
    CapabilityChangeImpactReport,
    CapabilityChangeImpactVersions,
    CapabilityFindingDelta,
    CapabilityFindingDeltaStatus,
    CapabilityFindingSnapshot,
    CapabilityImpactDirection,
    CapabilityImpactReason,
    CapabilitySemanticAttribute,
    CapabilitySemanticField,
    CapabilitySemanticState,
    change_impact_id,
    derive_change_impact_summary,
    evidence_fingerprint,
    expected_finding_risk_direction,
    finding_delta_id,
)

_SENSITIVE_TOOL_EFFECTS = {
    ManifestToolSideEffect.WRITE,
    ManifestToolSideEffect.EXECUTE,
    ManifestToolSideEffect.NETWORK,
    ManifestToolSideEffect.DESTRUCTIVE,
    ManifestToolSideEffect.SECRET_ACCESS,
    ManifestToolSideEffect.PRIVILEGED,
}
_TOOL_EFFECT_WEIGHT = {
    ManifestToolSideEffect.READ: 1,
    ManifestToolSideEffect.WRITE: 2,
    ManifestToolSideEffect.NETWORK: 2,
    ManifestToolSideEffect.EXECUTE: 3,
    ManifestToolSideEffect.DESTRUCTIVE: 4,
    ManifestToolSideEffect.SECRET_ACCESS: 4,
    ManifestToolSideEffect.PRIVILEGED: 4,
}
_PERMISSION_ACTION_WEIGHT = {
    ManifestPermissionAction.READ: 1,
    ManifestPermissionAction.WRITE: 2,
    ManifestPermissionAction.NETWORK: 2,
    ManifestPermissionAction.EXECUTE: 3,
    ManifestPermissionAction.DELEGATE: 3,
    ManifestPermissionAction.PERSIST: 3,
    ManifestPermissionAction.SECRET_ACCESS: 4,
    ManifestPermissionAction.ADMIN: 4,
    ManifestPermissionAction.DEPLOY: 4,
    ManifestPermissionAction.PUBLISH: 4,
}
_PERMISSION_SCOPE_WEIGHT = {
    ManifestResourceScope.PROJECT: 0,
    ManifestResourceScope.DEVELOPMENT: 0,
    ManifestResourceScope.TEST: 0,
    ManifestResourceScope.USER: 1,
    ManifestResourceScope.STAGING: 1,
    ManifestResourceScope.SYSTEM: 2,
    ManifestResourceScope.EXTERNAL: 2,
    ManifestResourceScope.PRODUCTION: 3,
}
_PERMISSION_EFFECT_FACTOR = {
    ManifestPermissionEffect.DENY: 0,
    ManifestPermissionEffect.PROMPT: 1,
    ManifestPermissionEffect.ALLOW: 2,
}
_PROTECTIVE_CONTROL_KINDS = {
    ManifestControlKind.HUMAN_APPROVAL,
    ManifestControlKind.SANDBOX,
    ManifestControlKind.PREFIX_RULE,
    ManifestControlKind.TRUST,
    ManifestControlKind.TOOL_FILTER,
    ManifestControlKind.TIMEOUT,
    ManifestControlKind.NETWORK_POLICY,
    ManifestControlKind.SECRET_HANDLING,
}


class CapabilityChangeImpactError(RuntimeError):
    """Safe deterministic Change Impact failure."""


class DeterministicCapabilityChangeImpactAnalyzer:
    """Hide state projection, exposure classification, and Finding matching."""

    def analyze(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
        capability_diff: CapabilityDiffResult,
        before_rules: CapabilityRuleRunResult,
        after_rules: CapabilityRuleRunResult,
        versions: VersionSet,
    ) -> CapabilityChangeImpactReport:
        """Return one strict value-minimizing P2-13 report."""

        self._validate_inputs(
            before=before,
            after=after,
            capability_diff=capability_diff,
            before_rules=before_rules,
            after_rules=after_rules,
            versions=versions,
        )
        provisional_impacts = self._change_impacts(
            before=before,
            after=after,
            capability_diff=capability_diff,
        )
        finding_delta = self._finding_delta(
            before_rules=before_rules,
            after_rules=after_rules,
            impacts=provisional_impacts,
        )
        impacts = self._link_impacts(provisional_impacts, finding_delta)
        before_failures = tuple(failure.rule_id for failure in before_rules.failures)
        after_failures = tuple(failure.rule_id for failure in after_rules.failures)
        summary = derive_change_impact_summary(
            capability_diff=capability_diff,
            change_impacts=impacts,
            finding_delta=finding_delta,
            before_rule_failures=before_failures,
            after_rule_failures=after_failures,
        )
        complete = (
            capability_diff.complete and not before_failures and not after_failures
        )
        return CapabilityChangeImpactReport(
            format=CAPABILITY_CHANGE_IMPACT_FORMAT,
            format_version=CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION,
            status="complete" if complete else "incomplete",
            agent_id=capability_diff.agent_id,
            versions=CapabilityChangeImpactVersions(
                package=versions.package,
                agent_manifest_schema=versions.agent_manifest_schema,
                capability_diff_schema=versions.capability_diff_schema,
                capability_rule_pack=versions.capability_rule_pack,
                capability_risk_model=versions.capability_risk_model,
                capability_change_impact_output=(
                    versions.capability_change_impact_output
                ),
            ),
            policy=CapabilityChangeImpactPolicy(
                enforcement_mode="report_only",
                ci_blocking_enabled=False,
                runtime_capability_verified=False,
                global_safety_claimed=False,
            ),
            summary=summary,
            capability_diff=capability_diff,
            change_impacts=impacts,
            finding_delta=finding_delta,
            before_rule_failures=before_failures,
            after_rule_failures=after_failures,
        )

    @staticmethod
    def _validate_inputs(
        *,
        before: AgentManifest,
        after: AgentManifest,
        capability_diff: CapabilityDiffResult,
        before_rules: CapabilityRuleRunResult,
        after_rules: CapabilityRuleRunResult,
        versions: VersionSet,
    ) -> None:
        if not isinstance(before, AgentManifest) or not isinstance(
            after, AgentManifest
        ):
            raise TypeError("before and after must be AgentManifest")
        if not isinstance(capability_diff, CapabilityDiffResult):
            raise TypeError("capability_diff must be CapabilityDiffResult")
        if not isinstance(before_rules, CapabilityRuleRunResult) or not isinstance(
            after_rules, CapabilityRuleRunResult
        ):
            raise TypeError(
                "before_rules and after_rules must be CapabilityRuleRunResult"
            )
        if not isinstance(versions, VersionSet):
            raise TypeError("versions must be VersionSet")
        agent_id = before.identity.agent_id
        if after.identity.agent_id != agent_id or capability_diff.agent_id != agent_id:
            raise CapabilityChangeImpactError(
                "Change Impact requires one compatible Agent identity."
            )
        if before_rules.agent_id != agent_id or after_rules.agent_id != agent_id:
            raise CapabilityChangeImpactError(
                "Change Impact Rule results do not match the Agent identity."
            )
        if before_rules.evaluated_rule_ids != after_rules.evaluated_rule_ids:
            raise CapabilityChangeImpactError(
                "Change Impact requires the same evaluated Capability Rule set."
            )
        if (
            before_rules.capability_rule_pack_version
            != after_rules.capability_rule_pack_version
            or before_rules.capability_risk_model_version
            != after_rules.capability_risk_model_version
        ):
            raise CapabilityChangeImpactError(
                "Change Impact requires matching Capability Rule and Risk versions."
            )

    def _change_impacts(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
        capability_diff: CapabilityDiffResult,
    ) -> tuple[CapabilityChangeImpact, ...]:
        before_items = self._item_indexes(before)
        after_items = self._item_indexes(after)
        impacts: list[CapabilityChangeImpact] = []
        for change in capability_diff.changes:
            if change.dimension not in {
                CapabilityDimension.TOOL,
                CapabilityDimension.PERMISSION,
                CapabilityDimension.CONTROL,
            }:
                continue
            before_item = before_items[change.dimension].get(change.item_id)
            after_item = after_items[change.dimension].get(change.item_id)
            before_state = self._semantic_state(change.dimension, before_item)
            after_state = self._semantic_state(change.dimension, after_item)
            direction, reasons = self._classify(
                dimension=change.dimension,
                change_type=change.change_type,
                before_item=before_item,
                after_item=after_item,
            )
            impacts.append(
                CapabilityChangeImpact(
                    impact_id=change_impact_id(
                        dimension=change.dimension,
                        item_id=change.item_id,
                        change_type=change.change_type,
                        before_sha256=change.before_sha256,
                        after_sha256=change.after_sha256,
                    ),
                    dimension=change.dimension,
                    item_id=change.item_id,
                    change_type=change.change_type,
                    before=before_state,
                    after=after_state,
                    direction=direction,
                    reasons=reasons,
                )
            )
        return tuple(sorted(impacts, key=lambda item: item.sort_key()))

    @staticmethod
    def _item_indexes(
        manifest: AgentManifest,
    ) -> dict[CapabilityDimension, dict[str, object]]:
        return {
            CapabilityDimension.TOOL: {
                item.tool_id: item for item in manifest.tools.tools
            },
            CapabilityDimension.PERMISSION: {
                item.permission_id: item for item in manifest.permissions.permissions
            },
            CapabilityDimension.CONTROL: {
                item.control_id: item for item in manifest.controls.controls
            },
        }

    @staticmethod
    def _semantic_state(
        dimension: CapabilityDimension,
        item: object | None,
    ) -> CapabilitySemanticState | None:
        if item is None:
            return None
        attributes: list[CapabilitySemanticAttribute]
        item_id: str
        if dimension is CapabilityDimension.TOOL and isinstance(item, ManifestTool):
            item_id = item.tool_id
            attributes = [
                _attribute(CapabilitySemanticField.KIND, item.kind.value),
                _attribute(
                    CapabilitySemanticField.AVAILABILITY,
                    item.availability.value,
                ),
                _attribute(
                    CapabilitySemanticField.SIDE_EFFECTS,
                    *(effect.value for effect in item.side_effects),
                ),
            ]
            if item.parent_tool_id is not None:
                attributes.append(
                    _attribute(
                        CapabilitySemanticField.PARENT_TOOL_ID,
                        item.parent_tool_id,
                    )
                )
        elif dimension is CapabilityDimension.PERMISSION and isinstance(
            item, ManifestPermission
        ):
            item_id = item.permission_id
            attributes = [
                _attribute(CapabilitySemanticField.ACTION, item.action.value),
                _attribute(CapabilitySemanticField.EFFECT, item.effect.value),
                _attribute(CapabilitySemanticField.RESOURCE, item.resource.value),
                _attribute(CapabilitySemanticField.SCOPE, item.scope.value),
            ]
            if item.target is not None:
                attributes.append(
                    _attribute(CapabilitySemanticField.TARGET, item.target)
                )
        elif dimension is CapabilityDimension.CONTROL and isinstance(
            item, ManifestControl
        ):
            item_id = item.control_id
            attributes = [
                _attribute(CapabilitySemanticField.KIND, item.kind.value),
                _attribute(CapabilitySemanticField.STATE, item.state.value),
            ]
            if item.target is not None:
                attributes.append(
                    _attribute(CapabilitySemanticField.TARGET, item.target)
                )
        else:
            raise CapabilityChangeImpactError(
                "Change Impact item type does not match its dimension."
            )
        return CapabilitySemanticState(
            dimension=dimension,
            item_id=item_id,
            attributes=tuple(sorted(attributes, key=lambda value: value.field.value)),
        )

    def _classify(
        self,
        *,
        dimension: CapabilityDimension,
        change_type: CapabilityChangeType,
        before_item: object | None,
        after_item: object | None,
    ) -> tuple[CapabilityImpactDirection, tuple[CapabilityImpactReason, ...]]:
        before_score = self._exposure_score(dimension, before_item)
        after_score = self._exposure_score(dimension, after_item)
        reasons = self._reasons(
            dimension=dimension,
            change_type=change_type,
            before_item=before_item,
            after_item=after_item,
        )
        positive_reasons = {
            CapabilityImpactReason.TOOL_ENABLED,
            CapabilityImpactReason.SENSITIVE_EFFECT_ADDED,
            CapabilityImpactReason.PERMISSION_GRANTED,
            CapabilityImpactReason.PERMISSION_EFFECT_WEAKENED,
            CapabilityImpactReason.CONTROL_WEAKENED,
        }
        negative_reasons = {
            CapabilityImpactReason.TOOL_DISABLED,
            CapabilityImpactReason.SENSITIVE_EFFECT_REMOVED,
            CapabilityImpactReason.PERMISSION_REVOKED,
            CapabilityImpactReason.PERMISSION_EFFECT_STRENGTHENED,
            CapabilityImpactReason.CONTROL_STRENGTHENED,
        }
        if before_score is None or after_score is None:
            direction = CapabilityImpactDirection.UNCERTAIN
            reasons.add(CapabilityImpactReason.UNKNOWN_STATE)
        elif reasons & positive_reasons and reasons & negative_reasons:
            direction = CapabilityImpactDirection.MIXED
        elif after_score > before_score:
            direction = CapabilityImpactDirection.INCREASED_EXPOSURE
        elif after_score < before_score:
            direction = CapabilityImpactDirection.REDUCED_EXPOSURE
        elif before_item != after_item:
            direction = CapabilityImpactDirection.NEUTRAL
            reasons.add(CapabilityImpactReason.SEMANTIC_STATE_CHANGED)
        else:
            direction = CapabilityImpactDirection.NEUTRAL
        if not reasons:
            reasons.add(CapabilityImpactReason.SEMANTIC_STATE_CHANGED)
        return direction, tuple(sorted(reasons, key=lambda item: item.value))

    @staticmethod
    def _exposure_score(
        dimension: CapabilityDimension,
        item: object | None,
    ) -> int | None:
        if item is None:
            return 0
        if dimension is CapabilityDimension.TOOL and isinstance(item, ManifestTool):
            if item.availability is ManifestToolAvailability.UNKNOWN or (
                ManifestToolSideEffect.UNKNOWN in item.side_effects
            ):
                return None
            if item.availability is ManifestToolAvailability.DISABLED:
                return 0
            effect_score = max(
                (_TOOL_EFFECT_WEIGHT[effect] for effect in item.side_effects),
                default=1,
            )
            return effect_score
        if dimension is CapabilityDimension.PERMISSION and isinstance(
            item, ManifestPermission
        ):
            if (
                item.action is ManifestPermissionAction.UNKNOWN
                or item.effect is ManifestPermissionEffect.UNKNOWN
                or item.resource is ManifestResourceKind.UNKNOWN
                or item.scope is ManifestResourceScope.UNKNOWN
            ):
                return None
            return _PERMISSION_EFFECT_FACTOR[item.effect] * (
                _PERMISSION_ACTION_WEIGHT[item.action]
                + _PERMISSION_SCOPE_WEIGHT[item.scope]
            )
        if dimension is CapabilityDimension.CONTROL and isinstance(
            item, ManifestControl
        ):
            if item.state is ManifestControlState.UNKNOWN:
                return None
            if item.kind is ManifestControlKind.ENABLEMENT:
                return {
                    ManifestControlState.DISABLED: -2,
                    ManifestControlState.ENABLED: 2,
                }.get(item.state, 0)
            if item.kind is ManifestControlKind.REQUIRED:
                return {
                    ManifestControlState.REQUIRED: 1,
                    ManifestControlState.OPTIONAL: -1,
                }.get(item.state, 0)
            if item.kind in _PROTECTIVE_CONTROL_KINDS:
                return {
                    ManifestControlState.DENY: -3,
                    ManifestControlState.PROMPT: -2,
                    ManifestControlState.REQUIRED: -2,
                    ManifestControlState.ENABLED: -2,
                    ManifestControlState.CONFIGURED: -1,
                    ManifestControlState.OPTIONAL: -1,
                    ManifestControlState.ALLOW: 2,
                    ManifestControlState.DISABLED: 2,
                }.get(item.state, 0)
            return 0
        raise CapabilityChangeImpactError(
            "Change Impact exposure classification received an invalid item."
        )

    @staticmethod
    def _reasons(
        *,
        dimension: CapabilityDimension,
        change_type: CapabilityChangeType,
        before_item: object | None,
        after_item: object | None,
    ) -> set[CapabilityImpactReason]:
        reasons: set[CapabilityImpactReason] = set()
        if change_type is CapabilityChangeType.ADDED:
            reasons.add(CapabilityImpactReason.CAPABILITY_ADDED)
        elif change_type is CapabilityChangeType.REMOVED:
            reasons.add(CapabilityImpactReason.CAPABILITY_REMOVED)
        if dimension is CapabilityDimension.TOOL:
            before_tool = before_item if isinstance(before_item, ManifestTool) else None
            after_tool = after_item if isinstance(after_item, ManifestTool) else None
            before_availability = (
                before_tool.availability
                if before_tool is not None
                else ManifestToolAvailability.DISABLED
            )
            after_availability = (
                after_tool.availability
                if after_tool is not None
                else ManifestToolAvailability.DISABLED
            )
            if before_availability is ManifestToolAvailability.DISABLED and (
                after_availability is not ManifestToolAvailability.DISABLED
            ):
                reasons.add(CapabilityImpactReason.TOOL_ENABLED)
            if after_availability is ManifestToolAvailability.DISABLED and (
                before_availability is not ManifestToolAvailability.DISABLED
            ):
                reasons.add(CapabilityImpactReason.TOOL_DISABLED)
            before_effects = set(before_tool.side_effects if before_tool else ())
            after_effects = set(after_tool.side_effects if after_tool else ())
            if (after_effects - before_effects) & _SENSITIVE_TOOL_EFFECTS:
                reasons.add(CapabilityImpactReason.SENSITIVE_EFFECT_ADDED)
            if (before_effects - after_effects) & _SENSITIVE_TOOL_EFFECTS:
                reasons.add(CapabilityImpactReason.SENSITIVE_EFFECT_REMOVED)
        elif dimension is CapabilityDimension.PERMISSION:
            before_permission = (
                before_item if isinstance(before_item, ManifestPermission) else None
            )
            after_permission = (
                after_item if isinstance(after_item, ManifestPermission) else None
            )
            before_effect = (
                before_permission.effect
                if before_permission is not None
                else ManifestPermissionEffect.DENY
            )
            after_effect = (
                after_permission.effect
                if after_permission is not None
                else ManifestPermissionEffect.DENY
            )
            effect_rank = {
                ManifestPermissionEffect.DENY: 0,
                ManifestPermissionEffect.PROMPT: 1,
                ManifestPermissionEffect.ALLOW: 2,
                ManifestPermissionEffect.UNKNOWN: 3,
            }
            if effect_rank[after_effect] > effect_rank[before_effect]:
                reasons.add(CapabilityImpactReason.PERMISSION_GRANTED)
                reasons.add(CapabilityImpactReason.PERMISSION_EFFECT_WEAKENED)
            elif effect_rank[after_effect] < effect_rank[before_effect]:
                reasons.add(CapabilityImpactReason.PERMISSION_REVOKED)
                reasons.add(CapabilityImpactReason.PERMISSION_EFFECT_STRENGTHENED)
        elif dimension is CapabilityDimension.CONTROL:
            before_control = (
                before_item if isinstance(before_item, ManifestControl) else None
            )
            after_control = (
                after_item if isinstance(after_item, ManifestControl) else None
            )
            if before_control is not None or after_control is not None:
                before_score = (
                    DeterministicCapabilityChangeImpactAnalyzer._exposure_score(
                        dimension, before_control
                    )
                )
                after_score = (
                    DeterministicCapabilityChangeImpactAnalyzer._exposure_score(
                        dimension, after_control
                    )
                )
                if before_score is not None and after_score is not None:
                    if after_score > before_score:
                        reasons.add(CapabilityImpactReason.CONTROL_WEAKENED)
                    elif after_score < before_score:
                        reasons.add(CapabilityImpactReason.CONTROL_STRENGTHENED)
        return reasons

    def _finding_delta(
        self,
        *,
        before_rules: CapabilityRuleRunResult,
        after_rules: CapabilityRuleRunResult,
        impacts: tuple[CapabilityChangeImpact, ...],
    ) -> tuple[CapabilityFindingDelta, ...]:
        before = self._index_findings(before_rules.findings, side="before")
        after = self._index_findings(after_rules.findings, side="after")
        deltas: list[CapabilityFindingDelta] = []
        for logical_key in sorted(before.keys() | after.keys()):
            rule_id, related_ids = logical_key
            before_finding = before.get(logical_key)
            after_finding = after.get(logical_key)
            before_snapshot = self._finding_snapshot(before_finding)
            after_snapshot = self._finding_snapshot(after_finding)
            changed_fields: tuple[str, ...]
            if before_snapshot is None:
                status = CapabilityFindingDeltaStatus.ADDED
                changed_fields = ("finding",)
            elif after_snapshot is None:
                status = CapabilityFindingDeltaStatus.RESOLVED
                changed_fields = ("finding",)
            elif before_snapshot == after_snapshot:
                status = CapabilityFindingDeltaStatus.UNCHANGED
                changed_fields = ()
            else:
                status = CapabilityFindingDeltaStatus.CHANGED
                changed_fields = self._finding_changed_fields(
                    before_snapshot,
                    after_snapshot,
                )
            impacted = tuple(
                impact.impact_id
                for impact in impacts
                if set(related_ids) & {impact.item_id}
            )
            risk_direction = expected_finding_risk_direction(
                status=status,
                before=before_snapshot,
                after=after_snapshot,
            )
            deltas.append(
                CapabilityFindingDelta(
                    delta_id=finding_delta_id(rule_id, related_ids),
                    rule_id=rule_id,
                    related_ids=related_ids,
                    status=status,
                    risk_direction=risk_direction,
                    before=before_snapshot,
                    after=after_snapshot,
                    changed_fields=changed_fields,
                    impacted_change_ids=tuple(sorted(impacted)),
                )
            )
        return tuple(sorted(deltas, key=lambda item: item.sort_key()))

    @staticmethod
    def _index_findings(
        findings: tuple[CapabilityRuleFinding, ...],
        *,
        side: str,
    ) -> Mapping[tuple[str, tuple[str, ...]], CapabilityRuleFinding]:
        indexed: dict[tuple[str, tuple[str, ...]], CapabilityRuleFinding] = {}
        for finding in findings:
            key = (finding.rule_id, finding.related_ids)
            if key in indexed:
                raise CapabilityChangeImpactError(
                    f"Change Impact {side} Findings contain duplicate logical IDs."
                )
            indexed[key] = finding
        return indexed

    @staticmethod
    def _finding_snapshot(
        finding: CapabilityRuleFinding | None,
    ) -> CapabilityFindingSnapshot | None:
        if finding is None:
            return None
        evidence_payload = tuple(item.sort_key() for item in finding.evidence)
        return CapabilityFindingSnapshot(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            category=finding.category,
            title_en=finding.texts[0].title,
            title_zh=finding.texts[1].title,
            correlation=finding.correlation,
            risk_level=finding.risk_level,
            score=finding.score,
            severity=finding.severity,
            confidence=finding.confidence,
            hard_gate=False,
            related_ids=finding.related_ids,
            evidence_sha256=evidence_fingerprint(evidence_payload),
        )

    @staticmethod
    def _finding_changed_fields(
        before: CapabilityFindingSnapshot,
        after: CapabilityFindingSnapshot,
    ) -> tuple[str, ...]:
        fields = {
            "category": (before.category, after.category),
            "correlation": (before.correlation, after.correlation),
            "risk_level": (before.risk_level, after.risk_level),
            "score": (before.score, after.score),
            "severity": (before.severity, after.severity),
            "confidence": (before.confidence, after.confidence),
            "hard_gate": (before.hard_gate, after.hard_gate),
            "evidence": (before.evidence_sha256, after.evidence_sha256),
            "title_en": (before.title_en, after.title_en),
            "title_zh": (before.title_zh, after.title_zh),
        }
        return tuple(
            sorted(name for name, values in fields.items() if values[0] != values[1])
        )

    @staticmethod
    def _link_impacts(
        impacts: tuple[CapabilityChangeImpact, ...],
        deltas: tuple[CapabilityFindingDelta, ...],
    ) -> tuple[CapabilityChangeImpact, ...]:
        linked: list[CapabilityChangeImpact] = []
        for impact in impacts:
            delta_ids = tuple(
                delta.delta_id
                for delta in deltas
                if impact.impact_id in delta.impacted_change_ids
            )
            linked.append(
                impact.model_copy(
                    update={"related_finding_delta_ids": tuple(sorted(delta_ids))}
                )
            )
        return tuple(sorted(linked, key=lambda item: item.sort_key()))


def _attribute(
    field: CapabilitySemanticField,
    *values: str,
) -> CapabilitySemanticAttribute:
    return CapabilitySemanticAttribute(field=field, values=tuple(sorted(set(values))))

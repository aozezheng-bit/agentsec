"""Reviewed deterministic combination-risk Capability Rule Pack v0.2.0."""

# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Callable, Iterable

from agentsec.capability_rules.base import (
    CapabilityCorrelation,
    CapabilityRule,
    CapabilityRuleCandidate,
    CapabilityRuleContext,
    CapabilityRuleEvaluation,
    CapabilityRuleLanguage,
    CapabilityRuleMetadata,
    CapabilityRuleText,
)
from agentsec.domain import FindingCategory, ImpactLevel
from agentsec.manifests import (
    ManifestAuthenticationKind,
    ManifestControlKind,
    ManifestControlState,
    ManifestEnvironmentKind,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestRuntimeIdentity,
    ManifestSourceReference,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestUnknownDimension,
)
from agentsec.risk import ImpactDimension, ImpactRating

BUILTIN_CAPABILITY_RULE_IDS = (
    "CAP-APPROVAL-001",
    "CAP-AUTONETWORK-001",
    "CAP-AUTOPROD-001",
    "CAP-AUTOSECRET-001",
    "CAP-CHAIN-001",
    "CAP-COVERAGE-001",
    "CAP-DELEGATE-001",
    "CAP-DELEGATEEXTERNAL-001",
    "CAP-DELEGATEPERSIST-001",
    "CAP-EXTERNAL-001",
    "CAP-EXTERNALEXEC-001",
    "CAP-EXTERNALPRIVILEGED-001",
    "CAP-EXTERNALUNVERIFIED-001",
    "CAP-EXTERNALWRITE-001",
    "CAP-MEMORYNETWORK-001",
    "CAP-MEMORYPROD-001",
    "CAP-MEMORYSECRET-001",
    "CAP-NONETWORKPOLICY-001",
    "CAP-NOSANDBOX-001",
    "CAP-NOSECRET-001",
    "CAP-PERSIST-001",
    "CAP-PRODADMIN-001",
    "CAP-PRODEXEC-001",
    "CAP-PRODIDENTITY-001",
    "CAP-PRODWRITE-001",
    "CAP-RELATIONUNKNOWN-001",
    "CAP-REQUIREDNOFILTER-001",
    "CAP-REQUIREDNOTIMEOUT-001",
    "CAP-SECRETPROD-001",
)

_STATIC_LIMITATION = (
    "This is a static declaration finding; runtime reachability, successful execution, "
    "and actual authorization are not verified.",
)
_AGENT_WIDE_LIMITATION = (
    "The correlated facts are Agent-wide declarations; capability reachability between "
    "them is not verified.",
    *_STATIC_LIMITATION,
)
_INCOMPLETE_LIMITATION = (
    "Analysis Coverage or a relevant Manifest dimension is incomplete; the visible fact "
    "does not prove exploitability and the result is not exhaustive.",
)


def builtin_capability_rules() -> tuple[CapabilityRule, ...]:
    """Return the complete reviewed Capability Rule inventory."""

    rules: tuple[CapabilityRule, ...] = (
        _approval_rule(),
        _chain_rule(),
        _coverage_rule(),
        _delegation_rule(),
        _external_rule(),
        _persistence_rule(),
        *_extended_capability_rules(),
    )
    ordered = tuple(sorted(rules, key=lambda rule: rule.metadata.rule_id))
    if tuple(rule.metadata.rule_id for rule in ordered) != BUILTIN_CAPABILITY_RULE_IDS:
        raise RuntimeError("Built-in Capability Rule identity is invalid.")
    return ordered


type _Evaluator = Callable[
    ["_CapabilityRule", CapabilityRuleContext], CapabilityRuleEvaluation
]


class _CapabilityRule:
    def __init__(self, metadata: CapabilityRuleMetadata, evaluator: _Evaluator) -> None:
        self.metadata = metadata
        self._evaluator = evaluator

    def evaluate(self, context: CapabilityRuleContext) -> CapabilityRuleEvaluation:
        return self._evaluator(self, context)

    def _candidate(
        self,
        *,
        correlation: CapabilityCorrelation,
        related_ids: Iterable[str],
        references: Iterable[ManifestSourceReference],
        likelihood_basis: tuple[str, ...],
        limitations: tuple[str, ...],
    ) -> CapabilityRuleCandidate:
        return CapabilityRuleCandidate(
            correlation=correlation,
            related_ids=tuple(sorted(set(related_ids))),
            evidence=tuple(sorted(set(references), key=lambda item: item.sort_key())),
            likelihood_basis=likelihood_basis,
            limitations=limitations,
        )


def _approval_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-APPROVAL-001",
            category=FindingCategory.HUMAN_APPROVAL,
            texts=_texts(
                "State-changing capability lacks an effective human approval control",
                "状态变更能力缺少有效人工审批控制",
                "A write, execute, deploy, publish, or admin capability is enabled or not explicitly disabled while the correlated target has no prompt or deny approval control.",
                "能力已启用或未明确禁用，但关联目标缺少 prompt 或 deny 人工审批控制。",
                "Require prompt or deny approval for state-changing capabilities and review inherited parent controls.",
                "为状态变更能力配置 prompt 或 deny 审批，并复核父级工具继承的控制。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "A state-changing capability without confirmation can modify code, configuration, or business state.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.HIGH,
                    "Unreviewed changes can bypass change-control, audit, or compliance decisions.",
                ),
            ),
        ),
        evaluator=_approval_evaluate,
    )


def _chain_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-CHAIN-001",
            category=FindingCategory.SECRET_ACCESS,
            texts=_texts(
                "Execution, secret access, and external network form a potential chain",
                "代码执行、Secret 访问与外部网络形成潜在链路",
                "The same target family or Agent declaration combines execute, secret access, and external network permissions.",
                "同一目标族或 Agent 声明同时具备 execute、secret_access 和 external network 权限。",
                "Separate execution, secret access, and external network capabilities; require least privilege and review each trust boundary.",
                "拆分执行、Secret 访问和外部网络能力，遵循最小权限并分别复核信任边界。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "The combination can expose credentials or protected data to an external destination.",
                ),
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Execution can transform accessed secrets or data into downstream state changes.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "An external identity or service can extend the impact beyond the local Agent.",
                ),
            ),
        ),
        evaluator=_chain_evaluate,
    )


def _coverage_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-COVERAGE-001",
            category=FindingCategory.SCAN_COVERAGE,
            texts=_texts(
                "High-impact capability is visible under incomplete analysis",
                "分析不完整时发现高影响能力",
                "A high-impact permission or relationship is visible while Coverage or a relevant Manifest dimension remains incomplete or Unknown.",
                "发现高影响权限或关系，但 Coverage 或相关 Manifest 维度仍不完整或 Unknown。",
                "Resolve skipped assets and Unknown dimensions before treating the capability assessment as exhaustive.",
                "先解决跳过的资产和 Unknown 维度，再将能力评估视为完整结果。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Unknown controls or capabilities can hide a state-changing path.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.VERY_HIGH,
                    "Incomplete scope can omit tools, identities, or relations outside the inspected inventory.",
                ),
            ),
        ),
        evaluator=_coverage_evaluate,
    )


def _delegation_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-DELEGATE-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            texts=_texts(
                "Delegation reaches a powerful capability without approval evidence",
                "委派可触达高权限能力但缺少审批证据",
                "An explicit delegates_to relationship coexists with a powerful capability and no prompt or deny approval evidence.",
                "存在 delegates_to 关系，同时存在高权限能力且没有 prompt 或 deny 审批证据。",
                "Require explicit approval at the delegation boundary and independently analyze the delegated Agent before granting power.",
                "在委派边界要求明确审批，并在授予高权限前独立分析被委派 Agent。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.VERY_HIGH,
                    "Delegation can extend a powerful capability to another Agent or execution context.",
                ),
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "A delegated powerful action can alter code, configuration, or production state.",
                ),
            ),
        ),
        evaluator=_delegation_evaluate,
    )


def _external_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-EXTERNAL-001",
            category=FindingCategory.NETWORK_ACCESS,
            texts=_texts(
                "Required enabled external MCP uses a credentialed identity",
                "必选启用的外部 MCP 使用凭证化身份",
                "An enabled and required external MCP server has OAuth, ChatGPT, or environment-backed authentication.",
                "外部 MCP Server 已启用且必选，同时使用 OAuth、ChatGPT 或环境凭证认证。",
                "Make external integrations optional where possible, scope credentials, pin destinations, and retain human approval for side effects.",
                "尽量将外部集成设为可选，限制凭证范围、固定目标并保留副作用人工审批。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "A required credentialed external integration can access protected data across a trust boundary.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The external service and identity can affect systems outside the Agent project.",
                ),
            ),
        ),
        evaluator=_external_evaluate,
    )


def _persistence_rule() -> CapabilityRule:
    return _CapabilityRule(
        CapabilityRuleMetadata(
            rule_id="CAP-PERSIST-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            texts=_texts(
                "Persistent memory is combined with a sensitive capability",
                "持久化记忆与敏感能力组合出现",
                "A persists_memory relationship coexists with secret access, external network, write, or admin capability.",
                "存在 persists_memory 关系，同时存在 secret_access、外部网络、write 或 admin 能力。",
                "Limit retained data, set expiration and deletion controls, and exclude secrets and untrusted instructions from persistent memory.",
                "限制保留数据，设置过期和删除控制，并禁止将 Secret 与不可信指令写入持久化记忆。",
            ),
            impact_ratings=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "Persistent memory can extend the lifetime and exposure of sensitive data or credentials.",
                ),
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Persisted untrusted instructions can influence future Agent tasks.",
                ),
            ),
        ),
        evaluator=_persistence_evaluate,
    )


def _texts(
    en_title: str,
    zh_title: str,
    en_description: str,
    zh_description: str,
    en_recommendation: str,
    zh_recommendation: str,
) -> tuple[CapabilityRuleText, ...]:
    return (
        CapabilityRuleText(
            language=CapabilityRuleLanguage.EN,
            title=en_title,
            description=en_description,
            recommendations=(en_recommendation,),
        ),
        CapabilityRuleText(
            language=CapabilityRuleLanguage.ZH,
            title=zh_title,
            description=zh_description,
            recommendations=(zh_recommendation,),
        ),
    )


def _impact(
    *items: tuple[ImpactDimension, ImpactLevel, str],
) -> tuple[ImpactRating, ...]:
    return tuple(
        sorted(
            (
                ImpactRating(dimension=dimension, level=level, rationale=rationale)
                for dimension, level, rationale in items
            ),
            key=lambda item: item.dimension.value,
        )
    )


def _permissions_for_actions(
    context: CapabilityRuleContext, actions: set[ManifestPermissionAction]
) -> tuple[ManifestPermission, ...]:
    return tuple(
        permission
        for target in sorted(context.permissions_by_target)
        for permission in context.permissions_by_target[target]
        if permission.action in actions
        and permission.effect is not ManifestPermissionEffect.DENY
        and not context.target_is_disabled(permission.target or "")
    )


def _approval_status(
    context: CapabilityRuleContext, target: str
) -> ManifestControlState | None:
    controls = context.effective_controls(target)
    states = [
        control.state
        for control in controls
        if control.kind is ManifestControlKind.HUMAN_APPROVAL
    ]
    states.extend(
        {
            ManifestPermissionEffect.ALLOW: ManifestControlState.ALLOW,
            ManifestPermissionEffect.PROMPT: ManifestControlState.PROMPT,
            ManifestPermissionEffect.DENY: ManifestControlState.DENY,
        }.get(permission.effect, ManifestControlState.UNKNOWN)
        for permission in context.permissions_by_target.get(target, ())
    )
    if ManifestControlState.DENY in states:
        return ManifestControlState.DENY
    if ManifestControlState.PROMPT in states:
        return ManifestControlState.PROMPT
    if ManifestControlState.ALLOW in states:
        return ManifestControlState.ALLOW
    return ManifestControlState.UNKNOWN if controls else None


def _target_references(
    context: CapabilityRuleContext, target: str, *, include_parent: bool = True
) -> tuple[ManifestSourceReference, ...]:
    references: list[ManifestSourceReference] = []
    for permission in context.permissions_by_target.get(target, ()):
        references.extend(permission.sources)
    for control in context.effective_controls(target):
        references.extend(control.sources)
    for identity in context.identities_by_tool.get(target, ()):
        references.extend(identity.sources)
    tool = context.tools_by_id.get(target)
    if tool is not None:
        references.extend(tool.sources)
        if include_parent and tool.parent_tool_id is not None:
            references.extend(
                _target_references(context, tool.parent_tool_id, include_parent=False)
            )
    return tuple(sorted(set(references), key=lambda item: item.sort_key()))


def _same_target_candidates(
    context: CapabilityRuleContext,
    *,
    actions: set[ManifestPermissionAction],
    rule: _CapabilityRule,
    require_approval: bool = False,
) -> tuple[CapabilityRuleCandidate, ...]:
    candidates = []
    for target in sorted(context.permissions_by_target):
        permissions = tuple(
            permission
            for permission in context.permissions_by_target[target]
            if permission.action in actions
            and permission.effect is not ManifestPermissionEffect.DENY
            and not context.target_is_disabled(target)
        )
        present = {permission.action for permission in permissions}
        if present != actions:
            continue
        if require_approval and _approval_status(context, target) in {
            ManifestControlState.PROMPT,
            ManifestControlState.DENY,
        }:
            continue
        candidates.append(
            rule._candidate(
                correlation=CapabilityCorrelation.SAME_TARGET,
                related_ids=(target,),
                references=_target_references(context, target),
                likelihood_basis=(
                    "All required static permissions are correlated to one Manifest target.",
                    *_STATIC_LIMITATION,
                ),
                limitations=_STATIC_LIMITATION,
            )
        )
    return tuple(candidates)


def _parent_child_candidates(
    context: CapabilityRuleContext,
    *,
    actions: set[ManifestPermissionAction],
    rule: _CapabilityRule,
) -> tuple[CapabilityRuleCandidate, ...]:
    families: dict[str, list[ManifestPermission]] = {}
    for permission in _permissions_for_actions(context, actions):
        target = permission.target
        if target is None:
            continue
        family = context.tool_family(target)
        if family is None:
            continue
        families.setdefault(family, []).append(permission)

    candidates: list[CapabilityRuleCandidate] = []
    for family in sorted(families):
        permissions = tuple(families[family])
        if {permission.action for permission in permissions} != actions:
            continue
        targets = tuple(
            sorted(
                {permission.target for permission in permissions if permission.target}
            )
        )
        if len(targets) < 2:
            continue
        references = tuple(
            source for permission in permissions for source in permission.sources
        )
        candidates.append(
            rule._candidate(
                correlation=CapabilityCorrelation.PARENT_CHILD,
                related_ids=targets,
                references=references,
                likelihood_basis=(
                    "All required static permissions are correlated within one parent-child tool family.",
                    *_STATIC_LIMITATION,
                ),
                limitations=_STATIC_LIMITATION,
            )
        )
    return tuple(candidates)


def _chain_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    actions = {
        ManifestPermissionAction.EXECUTE,
        ManifestPermissionAction.SECRET_ACCESS,
        ManifestPermissionAction.NETWORK,
    }
    candidates = list(_same_target_candidates(context, actions=actions, rule=self))
    if not candidates:
        candidates.extend(_parent_child_candidates(context, actions=actions, rule=self))
    if not candidates:
        present = _permissions_for_actions(context, actions)
        if {permission.action for permission in present} == actions:
            references = tuple(
                source for permission in present for source in permission.sources
            )
            candidates.append(
                self._candidate(
                    correlation=CapabilityCorrelation.AGENT_WIDE,
                    related_ids=tuple(
                        permission.permission_id for permission in present
                    ),
                    references=references,
                    likelihood_basis=(
                        "All required static permissions are visible in the Agent Manifest.",
                        "The declarations are not proven to share a reachable target.",
                    ),
                    limitations=_AGENT_WIDE_LIMITATION,
                )
            )
    return CapabilityRuleEvaluation(
        candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
    )


def _approval_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    actions = {
        ManifestPermissionAction.WRITE,
        ManifestPermissionAction.EXECUTE,
        ManifestPermissionAction.DEPLOY,
        ManifestPermissionAction.PUBLISH,
        ManifestPermissionAction.ADMIN,
    }
    candidates = []
    for target in sorted(context.permissions_by_target):
        permissions = tuple(
            permission
            for permission in context.permissions_by_target[target]
            if permission.action in actions
            and permission.effect is not ManifestPermissionEffect.DENY
            and not context.target_is_disabled(target)
        )
        if not permissions:
            continue
        if _approval_status(context, target) in {
            ManifestControlState.PROMPT,
            ManifestControlState.DENY,
        }:
            continue
        candidates.append(
            self._candidate(
                correlation=CapabilityCorrelation.SAME_TARGET,
                related_ids=(target,),
                references=_target_references(context, target),
                likelihood_basis=(
                    "A state-changing static permission is correlated to a target without prompt or deny approval.",
                    *_STATIC_LIMITATION,
                ),
                limitations=_STATIC_LIMITATION,
            )
        )
    return CapabilityRuleEvaluation(
        candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
    )


def _persistence_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    relations = context.relations_by_kind.get(ManifestRelationKind.PERSISTS_MEMORY, ())
    sensitive = _permissions_for_actions(
        context,
        {
            ManifestPermissionAction.SECRET_ACCESS,
            ManifestPermissionAction.NETWORK,
            ManifestPermissionAction.WRITE,
            ManifestPermissionAction.ADMIN,
        },
    )
    if not relations or not sensitive:
        return CapabilityRuleEvaluation()
    references = tuple(
        source for relation in relations for source in relation.sources
    ) + tuple(source for permission in sensitive for source in permission.sources)
    return CapabilityRuleEvaluation(
        candidates=(
            self._candidate(
                correlation=CapabilityCorrelation.AGENT_WIDE,
                related_ids=(
                    *(relation.relation_id for relation in relations),
                    *(permission.permission_id for permission in sensitive),
                ),
                references=references,
                likelihood_basis=(
                    "A persistent-memory relation and sensitive permission are both declared.",
                    "The static model does not prove that the relation will carry the permission's data.",
                ),
                limitations=_AGENT_WIDE_LIMITATION,
            ),
        )
    )


def _delegation_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    relations = tuple(
        relation
        for relation in context.relations_by_kind.get(
            ManifestRelationKind.DELEGATES_TO, ()
        )
        if relation.state is ManifestRelationState.DECLARED
    )
    powerful = _permissions_for_actions(
        context,
        {
            ManifestPermissionAction.EXECUTE,
            ManifestPermissionAction.ADMIN,
            ManifestPermissionAction.DEPLOY,
            ManifestPermissionAction.PUBLISH,
            ManifestPermissionAction.PERSIST,
        },
    )
    if not relations or not powerful:
        return CapabilityRuleEvaluation()
    unapproved = tuple(
        permission
        for permission in powerful
        if _approval_status(context, permission.target or "")
        not in {ManifestControlState.PROMPT, ManifestControlState.DENY}
    )
    if not unapproved:
        return CapabilityRuleEvaluation()
    references = tuple(
        source for relation in relations for source in relation.sources
    ) + tuple(source for permission in unapproved for source in permission.sources)
    return CapabilityRuleEvaluation(
        candidates=(
            self._candidate(
                correlation=CapabilityCorrelation.AGENT_WIDE,
                related_ids=(
                    *(relation.relation_id for relation in relations),
                    *(permission.permission_id for permission in unapproved),
                ),
                references=references,
                likelihood_basis=(
                    "An explicit delegation relation and powerful permission coexist without prompt or deny evidence.",
                    "The delegated Agent's independent capability manifest is unavailable.",
                ),
                limitations=_AGENT_WIDE_LIMITATION,
            ),
        )
    )


def _external_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    candidates = []
    for target, identities in context.identities_by_tool.items():
        if context.target_is_disabled(target):
            continue
        tool = context.tools_by_id.get(target)
        if (
            tool is None
            or tool.kind.value != "mcp_server"
            or tool.availability is not ManifestToolAvailability.ENABLED
        ):
            continue
        if not any(
            identity.environment is ManifestEnvironmentKind.EXTERNAL
            for identity in identities
        ):
            continue
        if not any(
            identity.authentication
            in {
                ManifestAuthenticationKind.ENVIRONMENT,
                ManifestAuthenticationKind.OAUTH,
                ManifestAuthenticationKind.CHATGPT,
            }
            for identity in identities
        ):
            continue
        controls = context.effective_controls(target)
        if not any(
            control.kind is ManifestControlKind.REQUIRED
            and control.state is ManifestControlState.REQUIRED
            for control in controls
        ):
            continue
        candidates.append(
            self._candidate(
                correlation=CapabilityCorrelation.SAME_TARGET,
                related_ids=(target,),
                references=_target_references(context, target),
                likelihood_basis=(
                    "The MCP target is statically external, enabled, required, and credentialed.",
                    *_STATIC_LIMITATION,
                ),
                limitations=_STATIC_LIMITATION,
            )
        )
    return CapabilityRuleEvaluation(
        candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
    )


def _coverage_evaluate(
    self: _CapabilityRule, context: CapabilityRuleContext
) -> CapabilityRuleEvaluation:
    candidates = []
    high_impact = {
        ManifestPermissionAction.EXECUTE,
        ManifestPermissionAction.NETWORK,
        ManifestPermissionAction.SECRET_ACCESS,
        ManifestPermissionAction.ADMIN,
        ManifestPermissionAction.DEPLOY,
        ManifestPermissionAction.PUBLISH,
        ManifestPermissionAction.PERSIST,
    }
    for target in sorted(context.permissions_by_target):
        permissions = tuple(
            permission
            for permission in context.permissions_by_target[target]
            if permission.action in high_impact
        )
        if not permissions:
            continue
        relevant_unknowns = context.relevant_unknowns(target, permissions)
        if context.manifest.coverage.complete and not relevant_unknowns:
            continue
        references = tuple(
            source for permission in permissions for source in permission.sources
        ) + tuple(source for unknown in relevant_unknowns for source in unknown.sources)
        candidates.append(
            self._candidate(
                correlation=CapabilityCorrelation.INCOMPLETE_COVERAGE,
                related_ids=(target,),
                references=references,
                likelihood_basis=(
                    "A high-impact permission is visible while Coverage or a relevant Manifest dimension is incomplete.",
                ),
                limitations=_INCOMPLETE_LIMITATION,
            )
        )
    for relation_kind in (
        ManifestRelationKind.PERSISTS_MEMORY,
        ManifestRelationKind.DELEGATES_TO,
    ):
        for relation in context.relations_by_kind.get(relation_kind, ()):
            relationship_unknowns = context.unknowns_by_dimension.get(
                ManifestUnknownDimension.RELATIONSHIPS, ()
            )
            if context.manifest.coverage.complete and not relationship_unknowns:
                continue
            candidates.append(
                self._candidate(
                    correlation=CapabilityCorrelation.INCOMPLETE_COVERAGE,
                    related_ids=(relation.relation_id,),
                    references=relation.sources,
                    likelihood_basis=(
                        "A high-impact relationship is visible while Framework Coverage is incomplete.",
                    ),
                    limitations=_INCOMPLETE_LIMITATION,
                )
            )
    return CapabilityRuleEvaluation(
        candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
    )


# ---------------------------------------------------------------------------
# P2-14 reviewed extension rules
# ---------------------------------------------------------------------------

_STATE_CHANGING_ACTIONS = {
    ManifestPermissionAction.WRITE,
    ManifestPermissionAction.EXECUTE,
    ManifestPermissionAction.DEPLOY,
    ManifestPermissionAction.PUBLISH,
    ManifestPermissionAction.ADMIN,
}
_MEMORY_RELATION_KINDS = {
    ManifestRelationKind.READS_MEMORY,
    ManifestRelationKind.WRITES_MEMORY,
    ManifestRelationKind.PERSISTS_MEMORY,
}
_EXTERNAL_AUTHENTICATIONS = {
    ManifestAuthenticationKind.ENVIRONMENT,
    ManifestAuthenticationKind.OAUTH,
    ManifestAuthenticationKind.CHATGPT,
}


def _extended_capability_rules() -> tuple[CapabilityRule, ...]:
    """Return the reviewed P2-14 extension without changing the risk model."""

    return (
        _permission_scope_rule(
            rule_id="CAP-PRODWRITE-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            actions={ManifestPermissionAction.WRITE},
            predicate=_production_permission,
            texts=_texts(
                "Production write capability is declared",
                "声明了生产环境写入能力",
                "A non-denied write permission targets the production scope or production resource.",
                "非 deny 的 write 权限指向 production 范围或生产资源。",
                "Use a separate read-only identity, minimize production write scope, and require audited approval.",
                "使用独立的只读身份，收敛生产写入范围，并要求可审计审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Production writes can directly change live configuration or business state.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.HIGH,
                    "Unreviewed production changes can violate change-control obligations.",
                ),
            ),
        ),
        _permission_scope_rule(
            rule_id="CAP-PRODEXEC-001",
            category=FindingCategory.CODE_EXECUTION,
            actions={ManifestPermissionAction.EXECUTE},
            predicate=_production_permission,
            texts=_texts(
                "Production execution capability is declared",
                "声明了生产环境执行能力",
                "A non-denied execute permission targets the production scope or production resource.",
                "非 deny 的 execute 权限指向 production 范围或生产资源。",
                "Move execution to an isolated deployment service and restrict production principals to the minimum command set.",
                "将执行移入隔离的部署服务，并将生产身份限制到最小命令集合。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Production execution can alter live systems beyond a single data write.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "A production execution path can affect dependent services and users.",
                ),
            ),
        ),
        _permission_scope_rule(
            rule_id="CAP-PRODADMIN-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            actions={ManifestPermissionAction.ADMIN},
            predicate=_production_permission,
            texts=_texts(
                "Production administrative capability is declared",
                "声明了生产环境管理能力",
                "A non-denied admin permission targets the production scope or production resource.",
                "非 deny 的 admin 权限指向 production 范围或生产资源。",
                "Use a narrowly scoped service identity, remove standing administrator access, and require just-in-time approval.",
                "使用严格限权的服务身份，移除长期管理员权限，并要求按需审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Administrative access can change controls, identities, or production resources.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.VERY_HIGH,
                    "A production administrator can affect multiple systems and tenants.",
                ),
            ),
        ),
        _permission_scope_rule(
            rule_id="CAP-SECRETPROD-001",
            category=FindingCategory.SECRET_ACCESS,
            actions={ManifestPermissionAction.SECRET_ACCESS},
            predicate=_production_permission,
            texts=_texts(
                "Production secret access is declared",
                "声明了生产环境 Secret 访问能力",
                "A non-denied secret_access permission targets the production scope or production resource.",
                "非 deny 的 secret_access 权限指向 production 范围或生产资源。",
                "Use a brokered, short-lived secret, limit the secret set, and keep production credentials out of general Agent context.",
                "使用经代理的短期 Secret，限制 Secret 集合，并禁止生产凭证进入通用 Agent 上下文。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "Production secrets can authorize access to live systems and protected data.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "Compromise of one production secret can extend to dependent services.",
                ),
            ),
        ),
        _permission_scope_rule(
            rule_id="CAP-EXTERNALWRITE-001",
            category=FindingCategory.NETWORK_ACCESS,
            actions={ManifestPermissionAction.WRITE},
            predicate=_external_permission,
            texts=_texts(
                "External write capability crosses a trust boundary",
                "外部写入能力跨越信任边界",
                "A non-denied write permission targets an external resource or scope.",
                "非 deny 的 write 权限指向 external 资源或范围。",
                "Pin the destination, constrain the writable fields, and require approval for externally visible changes.",
                "固定外部目标，限制可写字段，并要求对外部可见变更进行审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "External writes can change state outside the Agent's local trust boundary.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The receiving external system may propagate the change further.",
                ),
            ),
        ),
        _permission_scope_rule(
            rule_id="CAP-EXTERNALEXEC-001",
            category=FindingCategory.CODE_EXECUTION,
            actions={ManifestPermissionAction.EXECUTE},
            predicate=_external_permission,
            texts=_texts(
                "External execution capability crosses a trust boundary",
                "外部执行能力跨越信任边界",
                "A non-denied execute permission targets an external resource or scope.",
                "非 deny 的 execute 权限指向 external 资源或范围。",
                "Isolate the external executor, restrict the command surface, and record the destination and approval policy.",
                "隔离外部执行器，限制命令面，并记录目标与审批策略。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "External execution can modify systems outside the inspected project.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The external executor may reach additional resources not represented in the Manifest.",
                ),
            ),
        ),
        _permission_control_rule(
            rule_id="CAP-AUTOSECRET-001",
            category=FindingCategory.SECRET_ACCESS,
            actions={ManifestPermissionAction.SECRET_ACCESS},
            control_kind=ManifestControlKind.HUMAN_APPROVAL,
            unsafe_states={ManifestControlState.ALLOW},
            texts=_texts(
                "Secret access is allowed without human approval",
                "Secret 访问被允许且无需人工审批",
                "A secret_access permission has an effective allow approval state rather than prompt or deny.",
                "secret_access 权限的有效审批状态为 allow，而不是 prompt 或 deny。",
                "Change the approval state to prompt or deny and provide a narrow, audited secret broker.",
                "将审批状态改为 prompt 或 deny，并提供严格限权且可审计的 Secret 代理。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "Automatic secret access can expose credentials without a human checkpoint.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.HIGH,
                    "Automatic handling of production or regulated secrets weakens review evidence.",
                ),
            ),
            predicate=lambda permission: (
                permission.action is ManifestPermissionAction.SECRET_ACCESS
            ),
        ),
        _permission_control_rule(
            rule_id="CAP-AUTONETWORK-001",
            category=FindingCategory.NETWORK_ACCESS,
            actions={ManifestPermissionAction.NETWORK},
            control_kind=ManifestControlKind.HUMAN_APPROVAL,
            unsafe_states={ManifestControlState.ALLOW},
            texts=_texts(
                "Network access is allowed without human approval",
                "网络访问被允许且无需人工审批",
                "A network permission has an effective allow approval state rather than prompt or deny.",
                "network 权限的有效审批状态为 allow，而不是 prompt 或 deny。",
                "Restrict destinations with a network policy and require prompt approval for side-effecting requests.",
                "使用网络策略限制目标，并对有副作用的请求要求 prompt 审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "Automatic network access can move Agent data across a trust boundary.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "An unrestricted destination can extend impact to external services.",
                ),
            ),
            predicate=lambda permission: (
                permission.action is ManifestPermissionAction.NETWORK
            ),
        ),
        _permission_control_rule(
            rule_id="CAP-AUTOPROD-001",
            category=FindingCategory.HUMAN_APPROVAL,
            actions=_STATE_CHANGING_ACTIONS,
            control_kind=ManifestControlKind.HUMAN_APPROVAL,
            unsafe_states={ManifestControlState.ALLOW},
            texts=_texts(
                "Production state-changing capability is allowed automatically",
                "生产状态变更能力被自动允许",
                "A production write, execute, deploy, publish, or admin permission has an effective allow approval state.",
                "生产 write、execute、deploy、publish 或 admin 权限的有效审批状态为 allow。",
                "Require an explicit prompt or deny control and separate deployment approval from Agent execution.",
                "要求明确的 prompt 或 deny 控制，并将部署审批与 Agent 执行隔离。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Automatic production state changes bypass a human release checkpoint.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.VERY_HIGH,
                    "Unreviewed production changes can violate release and audit controls.",
                ),
            ),
            predicate=lambda permission: _production_permission(permission),
        ),
        _control_gap_rule(
            rule_id="CAP-NOSANDBOX-001",
            category=FindingCategory.CODE_EXECUTION,
            actions=_STATE_CHANGING_ACTIONS,
            control_kind=ManifestControlKind.SANDBOX,
            safe_states={
                ManifestControlState.CONFIGURED,
                ManifestControlState.ENABLED,
            },
            texts=_texts(
                "High-impact capability lacks a configured sandbox",
                "高影响能力缺少已配置的沙箱",
                "A state-changing permission has no configured or enabled sandbox control on its target or parent.",
                "状态变更权限的目标或父级没有 configured 或 enabled 的 sandbox 控制。",
                "Run high-impact tools in a bounded sandbox and record the isolation policy as source-backed configuration.",
                "在受限沙箱中运行高影响工具，并以有来源的配置记录隔离策略。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Without isolation, a state-changing tool may affect more resources than intended.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "Missing isolation expands the possible impact of a mistaken or malicious action.",
                ),
            ),
        ),
        _control_gap_rule(
            rule_id="CAP-NONETWORKPOLICY-001",
            category=FindingCategory.NETWORK_ACCESS,
            actions={ManifestPermissionAction.NETWORK},
            control_kind=ManifestControlKind.NETWORK_POLICY,
            safe_states={ManifestControlState.CONFIGURED},
            predicate=_external_permission,
            texts=_texts(
                "External network capability lacks a network policy",
                "外部网络能力缺少网络策略",
                "An external network permission has no configured network_policy control on its target or parent.",
                "外部 network 权限的目标或父级没有 configured 的 network_policy 控制。",
                "Allow only reviewed destinations, protocols, and data classes through an explicit network policy.",
                "通过明确的网络策略仅允许经过复核的目标、协议和数据类别。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "Without a destination policy, protected data may be sent to an unintended endpoint.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "Unbounded network destinations increase external exposure.",
                ),
            ),
        ),
        _control_gap_rule(
            rule_id="CAP-NOSECRET-001",
            category=FindingCategory.SECRET_ACCESS,
            actions={ManifestPermissionAction.SECRET_ACCESS},
            control_kind=ManifestControlKind.SECRET_HANDLING,
            safe_states={ManifestControlState.CONFIGURED},
            texts=_texts(
                "Secret capability lacks a secret-handling control",
                "Secret 能力缺少 Secret 处理控制",
                "A secret_access permission has no configured secret_handling control on its target or parent.",
                "secret_access 权限的目标或父级没有 configured 的 secret_handling 控制。",
                "Define redaction, lifetime, audience, and non-persistence controls for every secret boundary.",
                "为每个 Secret 边界定义脱敏、生命周期、受众和禁止持久化控制。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "Missing handling controls make secret exposure and retention behavior unclear.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.HIGH,
                    "Secret processing without documented controls weakens auditability.",
                ),
            ),
        ),
        _external_identity_rule(
            rule_id="CAP-EXTERNALUNVERIFIED-001",
            category=FindingCategory.NETWORK_ACCESS,
            predicate=_identity_unverified,
            texts=_texts(
                "External MCP identity or availability is not runtime-verified",
                "外部 MCP 身份或可用性尚未运行时验证",
                "An external MCP declaration has an unknown availability or a runtime identity field that still requires verification.",
                "外部 MCP 声明的可用性未知，或运行时身份字段仍需要验证。",
                "Keep this as an explicit verification task; do not treat static identity metadata as runtime attestation.",
                "将其保留为明确的验证任务；不要把静态身份元数据当作运行时证明。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "The actual external principal or availability may differ from the declaration.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "Unverified external identity can invalidate trust-boundary assumptions.",
                ),
            ),
        ),
        _external_identity_rule(
            rule_id="CAP-EXTERNALPRIVILEGED-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            predicate=lambda identity: identity.privileged is True,
            texts=_texts(
                "External MCP uses an explicitly privileged identity",
                "外部 MCP 使用明确的特权身份",
                "An external MCP server is associated with a runtime identity whose privileged flag is true.",
                "外部 MCP Server 关联的运行时身份 privileged 标记为 true。",
                "Replace the privileged identity with a narrowly scoped principal and document every required elevated operation.",
                "用严格限权的身份替换特权身份，并记录每项需要提升权限的操作。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "A privileged external principal can modify protected resources across a trust boundary.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.VERY_HIGH,
                    "The external principal may reach systems not represented in the local Manifest.",
                ),
            ),
        ),
        _permission_identity_rule(
            rule_id="CAP-PRODIDENTITY-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            actions=_STATE_CHANGING_ACTIONS,
            predicate=lambda permission: _production_permission(permission),
            identity_predicate=lambda identity: (
                identity.environment
                in {
                    ManifestEnvironmentKind.EXTERNAL,
                    ManifestEnvironmentKind.PRODUCTION,
                }
                or identity.authentication in _EXTERNAL_AUTHENTICATIONS
            ),
            texts=_texts(
                "Production capability uses an external or session identity",
                "生产能力使用外部或会话身份",
                "A production state-changing permission is associated with an external environment, OAuth, ChatGPT, or environment-backed identity.",
                "生产状态变更权限关联了 external 环境、OAuth、ChatGPT 或环境凭证身份。",
                "Use a dedicated production principal with explicit scope, short lifetime, and independently reviewed approval.",
                "使用专用生产身份，限制权限范围和生命周期，并进行独立审批复核。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "A session or external identity can carry production state-changing authority outside the local project.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The identity's actual downstream access is not fully represented statically.",
                ),
            ),
        ),
        _required_control_presence_rule(
            rule_id="CAP-REQUIREDNOTIMEOUT-001",
            category=FindingCategory.NETWORK_ACCESS,
            control_kind=ManifestControlKind.TIMEOUT,
            texts=_texts(
                "Required external MCP has no timeout control",
                "必选外部 MCP 缺少超时控制",
                "An enabled required external MCP server has no configured timeout control.",
                "已启用且必选的外部 MCP Server 没有 configured 的 timeout 控制。",
                "Set bounded startup and tool timeouts and fail closed when the control is absent.",
                "设置有界的启动和工具超时；控制缺失时应 fail closed。",
            ),
            impact=_impact(
                (
                    ImpactDimension.AVAILABILITY,
                    ImpactLevel.HIGH,
                    "Missing timeouts can leave a required external dependency hanging or consuming resources.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.MODERATE,
                    "A stuck external call can affect the Agent workflow and dependent services.",
                ),
            ),
        ),
        _required_filter_rule(),
        _relation_permission_rule(
            rule_id="CAP-MEMORYSECRET-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            relation_kinds=_MEMORY_RELATION_KINDS,
            actions={ManifestPermissionAction.SECRET_ACCESS},
            texts=_texts(
                "Memory relationship coexists with secret access",
                "记忆关系与 Secret 访问同时存在",
                "A reads, writes, or persists memory relationship coexists with a secret_access permission.",
                "reads_memory、writes_memory 或 persists_memory 关系与 secret_access 权限同时存在。",
                "Prevent secrets from entering memory, enforce retention limits, and use explicit memory access controls.",
                "禁止 Secret 进入记忆，限制保留期限，并使用明确的记忆访问控制。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "Memory can extend the lifetime and audience of a secret beyond its original boundary.",
                ),
                (
                    ImpactDimension.BUSINESS_COMPLIANCE,
                    ImpactLevel.HIGH,
                    "Secret persistence can violate retention and data-handling requirements.",
                ),
            ),
        ),
        _relation_permission_rule(
            rule_id="CAP-MEMORYNETWORK-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            relation_kinds=_MEMORY_RELATION_KINDS,
            actions={ManifestPermissionAction.NETWORK},
            texts=_texts(
                "Memory relationship coexists with external network access",
                "记忆关系与外部网络访问同时存在",
                "A reads, writes, or persists memory relationship coexists with a network permission.",
                "reads_memory、writes_memory 或 persists_memory 关系与 network 权限同时存在。",
                "Classify memory data before network transfer and require an explicit egress policy.",
                "在网络传输前对记忆数据分类，并要求明确的出站策略。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "Memory data can be transferred to an external destination.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The combination can extend retained data exposure to external systems.",
                ),
            ),
        ),
        _relation_permission_rule(
            rule_id="CAP-MEMORYPROD-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            relation_kinds=_MEMORY_RELATION_KINDS,
            actions={
                ManifestPermissionAction.WRITE,
                ManifestPermissionAction.ADMIN,
                ManifestPermissionAction.DEPLOY,
                ManifestPermissionAction.PUBLISH,
            },
            permission_predicate=_production_permission,
            texts=_texts(
                "Memory relationship coexists with production state change",
                "记忆关系与生产状态变更同时存在",
                "A memory relationship coexists with a production write, admin, deploy, or publish permission.",
                "记忆关系与 production write、admin、deploy 或 publish 权限同时存在。",
                "Separate retained context from production authority and require approval at the state-changing boundary.",
                "将持久化上下文与生产权限隔离，并在状态变更边界要求审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Persisted context may influence future production state changes.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "The combination can carry stale or untrusted memory into live systems.",
                ),
            ),
        ),
        _relation_relation_rule(
            rule_id="CAP-DELEGATEPERSIST-001",
            category=FindingCategory.PERSISTENT_MEMORY,
            left_kind=ManifestRelationKind.DELEGATES_TO,
            right_kind=ManifestRelationKind.PERSISTS_MEMORY,
            texts=_texts(
                "Delegation is combined with persistent memory",
                "委派与持久化记忆同时存在",
                "The Agent declares both a delegates_to relationship and a persists_memory relationship.",
                "Agent 同时声明了 delegates_to 与 persists_memory 关系。",
                "Define ownership, retention, and deletion boundaries before delegated work can write persistent memory.",
                "在委派任务写入持久化记忆前定义所有权、保留和删除边界。",
            ),
            impact=_impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "Delegated work can extend the audience and lifetime of retained context.",
                ),
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Untrusted delegated output may influence future tasks through memory.",
                ),
            ),
        ),
        _relation_permission_rule(
            rule_id="CAP-DELEGATEEXTERNAL-001",
            category=FindingCategory.PRIVILEGED_ACCESS,
            relation_kinds={ManifestRelationKind.DELEGATES_TO},
            actions={
                ManifestPermissionAction.NETWORK,
                ManifestPermissionAction.WRITE,
                ManifestPermissionAction.EXECUTE,
                ManifestPermissionAction.ADMIN,
            },
            permission_predicate=_external_permission,
            texts=_texts(
                "Delegation is combined with an external capability",
                "委派与外部能力同时存在",
                "A delegates_to relationship coexists with an external network, write, execute, or admin permission.",
                "delegates_to 关系与外部 network、write、execute 或 admin 权限同时存在。",
                "Require an explicit delegation contract, destination allowlist, and approval at the external side-effect boundary.",
                "要求明确的委派契约、目标白名单，并在外部副作用边界进行审批。",
            ),
            impact=_impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "Delegated work may reach an external system with state-changing authority.",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.VERY_HIGH,
                    "Delegation can multiply the number of execution contexts crossing the boundary.",
                ),
            ),
        ),
        _relation_unknown_rule(),
    )


def _permission_scope_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    actions: set[ManifestPermissionAction],
    predicate: Callable[[ManifestPermission], bool],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
) -> CapabilityRule:
    """Create one bounded same-target permission declaration Rule."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.permissions_by_target):
            permissions = tuple(
                permission
                for permission in context.permissions_by_target[target]
                if permission.action in actions
                and permission.effect is not ManifestPermissionEffect.DENY
                and predicate(permission)
                and not context.target_is_disabled(target)
            )
            if not permissions:
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target)
                    + tuple(
                        source
                        for permission in permissions
                        for source in permission.sources
                    ),
                    likelihood_basis=(
                        "The reviewed permission condition is correlated to one Manifest target.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _permission_control_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    actions: set[ManifestPermissionAction],
    control_kind: ManifestControlKind,
    unsafe_states: set[ManifestControlState],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
    predicate: Callable[[ManifestPermission], bool],
) -> CapabilityRule:
    """Create a Rule for an explicitly unsafe effective control state."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.permissions_by_target):
            permissions = tuple(
                permission
                for permission in context.permissions_by_target[target]
                if permission.action in actions
                and permission.effect is not ManifestPermissionEffect.DENY
                and predicate(permission)
                and not context.target_is_disabled(target)
            )
            controls = context.effective_controls(target)
            if not permissions or not any(
                control.kind is control_kind and control.state in unsafe_states
                for control in controls
            ):
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target),
                    likelihood_basis=(
                        "The permission and unsafe control state are correlated to one Manifest target.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _control_gap_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    actions: set[ManifestPermissionAction],
    control_kind: ManifestControlKind,
    safe_states: set[ManifestControlState],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
    predicate: Callable[[ManifestPermission], bool] = lambda permission: True,
) -> CapabilityRule:
    """Create a Rule for an absent, disabled, or unknown guardrail."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.permissions_by_target):
            permissions = tuple(
                permission
                for permission in context.permissions_by_target[target]
                if permission.action in actions
                and permission.effect is not ManifestPermissionEffect.DENY
                and predicate(permission)
                and not context.target_is_disabled(target)
            )
            controls = context.effective_controls(target)
            matching = tuple(
                control for control in controls if control.kind is control_kind
            )
            if not permissions or any(
                control.state in safe_states for control in matching
            ):
                continue
            unknowns = context.relevant_unknowns(target, permissions)
            references = _target_references(context, target) + tuple(
                source for unknown in unknowns for source in unknown.sources
            )
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=references,
                    likelihood_basis=(
                        "The high-impact permission lacks a reviewed effective guardrail state.",
                        "Absence or Unknown is treated as a review finding, not proof of exploitability.",
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _external_identity_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    predicate: Callable[[ManifestRuntimeIdentity], bool],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
) -> CapabilityRule:
    """Create a Rule over external MCP identity declarations."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.identities_by_tool):
            tool = context.tools_by_id.get(target)
            if tool is None or tool.kind is not ManifestToolKind.MCP_SERVER:
                continue
            if context.target_is_disabled(target):
                continue
            identities = tuple(
                identity
                for identity in context.identities_by_tool[target]
                if identity.environment is ManifestEnvironmentKind.EXTERNAL
                and predicate(identity)
            )
            if not identities:
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target)
                    + tuple(
                        source for identity in identities for source in identity.sources
                    ),
                    likelihood_basis=(
                        "The external MCP and identity facts are correlated to one target.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _permission_identity_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    actions: set[ManifestPermissionAction],
    predicate: Callable[[ManifestPermission], bool],
    identity_predicate: Callable[[ManifestRuntimeIdentity], bool],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
) -> CapabilityRule:
    """Create a Rule correlating a permission and a runtime identity."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.permissions_by_target):
            permissions = tuple(
                permission
                for permission in context.permissions_by_target[target]
                if permission.action in actions
                and permission.effect is not ManifestPermissionEffect.DENY
                and predicate(permission)
                and not context.target_is_disabled(target)
            )
            identities = tuple(
                identity
                for identity in context.identities_by_tool.get(target, ())
                if identity_predicate(identity)
            )
            if not permissions or not identities:
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target),
                    likelihood_basis=(
                        "The reviewed permission and runtime identity are correlated to one target.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _required_control_presence_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    control_kind: ManifestControlKind,
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
) -> CapabilityRule:
    """Create a Rule for a required enabled external MCP without a control."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.tools_by_id):
            tool = context.tools_by_id[target]
            if tool.kind is not ManifestToolKind.MCP_SERVER:
                continue
            if tool.availability is not ManifestToolAvailability.ENABLED:
                continue
            if not _target_is_external(context, target):
                continue
            controls = context.effective_controls(target)
            if not any(
                control.kind is ManifestControlKind.REQUIRED
                and control.state is ManifestControlState.REQUIRED
                for control in controls
            ):
                continue
            if any(control.kind is control_kind for control in controls):
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target),
                    likelihood_basis=(
                        "The MCP is statically enabled and required while the requested control is absent.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _required_filter_rule() -> CapabilityRule:
    """Return the required MCP tool-filter Rule with a stable independent ID."""

    metadata = CapabilityRuleMetadata(
        rule_id="CAP-REQUIREDNOFILTER-001",
        category=FindingCategory.EXTERNAL_TOOLING,
        texts=_texts(
            "Required external MCP has no tool filter",
            "必选外部 MCP 缺少工具过滤",
            "An enabled required external MCP server has no tool_filter control on itself or its associated child tools.",
            "已启用且必选的外部 MCP Server 自身或关联子工具没有 tool_filter 控制。",
            "Allowlist only the tools required for the workflow and review each side-effecting tool separately.",
            "仅允许工作流必需的工具，并分别复核每个有副作用的工具。",
        ),
        impact_ratings=_impact(
            (
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "Without a tool filter, a required MCP may expose more operations than the workflow needs.",
            ),
            (
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Additional external tools can expand the reachable trust boundary.",
            ),
        ),
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for target in sorted(context.tools_by_id):
            tool = context.tools_by_id[target]
            if tool.kind is not ManifestToolKind.MCP_SERVER:
                continue
            if tool.availability is not ManifestToolAvailability.ENABLED:
                continue
            if not _target_is_external(context, target):
                continue
            controls = context.effective_controls(target)
            if not any(
                control.kind is ManifestControlKind.REQUIRED
                and control.state is ManifestControlState.REQUIRED
                for control in controls
            ):
                continue
            family_targets = (
                target,
                *tuple(
                    child.tool_id
                    for child in context.child_tools_by_parent.get(target, ())
                ),
            )
            if any(
                control.kind is ManifestControlKind.TOOL_FILTER
                for family_target in family_targets
                for control in context.effective_controls(family_target)
            ):
                continue
            candidates.append(
                rule._candidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=(target,),
                    references=_target_references(context, target),
                    likelihood_basis=(
                        "The MCP is statically enabled and required without a visible tool filter.",
                        *_STATIC_LIMITATION,
                    ),
                    limitations=_STATIC_LIMITATION,
                )
            )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _relation_permission_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    relation_kinds: set[ManifestRelationKind],
    actions: set[ManifestPermissionAction],
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
    permission_predicate: Callable[[ManifestPermission], bool] = lambda permission: (
        True
    ),
) -> CapabilityRule:
    """Create one bounded relation-to-permission combination Rule."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        relations = tuple(
            relation
            for kind in sorted(relation_kinds, key=lambda item: item.value)
            for relation in context.relations_by_kind.get(kind, ())
            if relation.state
            in {
                ManifestRelationState.DECLARED,
                ManifestRelationState.ACTIVE,
            }
        )
        permissions = tuple(
            permission
            for permission in _permissions_for_actions(context, actions)
            if permission_predicate(permission)
        )
        if not relations or not permissions:
            return CapabilityRuleEvaluation()
        correlation = CapabilityCorrelation.AGENT_WIDE
        if any(
            relation.target_id == permission.target
            or relation.source_agent_id == permission.target
            for relation in relations
            for permission in permissions
            if permission.target is not None
        ):
            correlation = CapabilityCorrelation.EXPLICIT_RELATION
        references = tuple(
            source for relation in relations for source in relation.sources
        ) + tuple(source for permission in permissions for source in permission.sources)
        return CapabilityRuleEvaluation(
            candidates=(
                rule._candidate(
                    correlation=correlation,
                    related_ids=(
                        *(relation.relation_id for relation in relations),
                        *(permission.permission_id for permission in permissions),
                    ),
                    references=references,
                    likelihood_basis=(
                        "The relationship and permission facts are both present in the finalized Manifest.",
                        "The static model does not prove data flow or delegated reachability.",
                    ),
                    limitations=_AGENT_WIDE_LIMITATION,
                ),
            )
        )

    return _CapabilityRule(metadata, evaluate)


def _relation_relation_rule(
    *,
    rule_id: str,
    category: FindingCategory,
    left_kind: ManifestRelationKind,
    right_kind: ManifestRelationKind,
    texts: tuple[CapabilityRuleText, ...],
    impact: tuple[ImpactRating, ...],
) -> CapabilityRule:
    """Create one bounded relation-to-relation combination Rule."""

    metadata = CapabilityRuleMetadata(
        rule_id=rule_id,
        category=category,
        texts=texts,
        impact_ratings=impact,
    )

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        left = tuple(
            relation
            for relation in context.relations_by_kind.get(left_kind, ())
            if relation.state
            in {
                ManifestRelationState.DECLARED,
                ManifestRelationState.ACTIVE,
            }
        )
        right = tuple(
            relation
            for relation in context.relations_by_kind.get(right_kind, ())
            if relation.state
            in {
                ManifestRelationState.DECLARED,
                ManifestRelationState.ACTIVE,
            }
        )
        if not left or not right:
            return CapabilityRuleEvaluation()
        references = tuple(
            source for relation in (*left, *right) for source in relation.sources
        )
        return CapabilityRuleEvaluation(
            candidates=(
                rule._candidate(
                    correlation=CapabilityCorrelation.AGENT_WIDE,
                    related_ids=(
                        *(relation.relation_id for relation in left),
                        *(relation.relation_id for relation in right),
                    ),
                    references=references,
                    likelihood_basis=(
                        "Both relationship types are declared in the finalized Manifest.",
                        "The static model does not prove that the two relationships share a data path.",
                    ),
                    limitations=_AGENT_WIDE_LIMITATION,
                ),
            )
        )

    return _CapabilityRule(metadata, evaluate)


def _relation_unknown_rule() -> CapabilityRule:
    """Return the explicit Unknown relationship Rule."""

    metadata = CapabilityRuleMetadata(
        rule_id="CAP-RELATIONUNKNOWN-001",
        category=FindingCategory.SCAN_COVERAGE,
        texts=_texts(
            "High-impact relationship is unresolved",
            "高影响关系未解析",
            "A delegation or memory relationship is present with an Unknown relationship state.",
            "存在 delegation 或 memory 关系，但关系状态为 Unknown。",
            "Resolve the relationship source and preserve a fail-closed Unknown state until it is reviewed.",
            "解析关系来源；在完成复核前保留 fail-closed 的 Unknown 状态。",
        ),
        impact_ratings=_impact(
            (
                ImpactDimension.INTEGRITY,
                ImpactLevel.HIGH,
                "An unresolved relationship may hide a state-changing or data-retention path.",
            ),
            (
                ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                ImpactLevel.HIGH,
                "Unknown delegation or memory edges can affect capabilities outside the visible graph.",
            ),
        ),
    )

    high_impact_kinds = {
        ManifestRelationKind.DELEGATES_TO,
        ManifestRelationKind.READS_MEMORY,
        ManifestRelationKind.WRITES_MEMORY,
        ManifestRelationKind.PERSISTS_MEMORY,
    }

    def evaluate(
        rule: _CapabilityRule, context: CapabilityRuleContext
    ) -> CapabilityRuleEvaluation:
        candidates = []
        for kind in sorted(high_impact_kinds, key=lambda item: item.value):
            for relation in context.relations_by_kind.get(kind, ()):
                if relation.state is not ManifestRelationState.UNKNOWN:
                    continue
                candidates.append(
                    rule._candidate(
                        correlation=CapabilityCorrelation.EXPLICIT_RELATION,
                        related_ids=(relation.relation_id,),
                        references=relation.sources,
                        likelihood_basis=(
                            "The relationship is explicitly retained but its state is Unknown.",
                            "Unknown is not treated as absence or safety.",
                        ),
                        limitations=_INCOMPLETE_LIMITATION,
                    )
                )
        return CapabilityRuleEvaluation(
            candidates=tuple(sorted(candidates, key=lambda item: item.sort_key()))
        )

    return _CapabilityRule(metadata, evaluate)


def _production_permission(permission: ManifestPermission) -> bool:
    return (
        permission.scope is ManifestResourceScope.PRODUCTION
        or permission.resource is ManifestResourceKind.PRODUCTION
    )


def _external_permission(permission: ManifestPermission) -> bool:
    return permission.scope is ManifestResourceScope.EXTERNAL


def _target_is_external(context: CapabilityRuleContext, target: str) -> bool:
    return any(
        identity.environment is ManifestEnvironmentKind.EXTERNAL
        for identity in context.identities_by_tool.get(target, ())
    ) or any(
        permission.scope is ManifestResourceScope.EXTERNAL
        for permission in context.permissions_by_target.get(target, ())
    )


def _identity_unverified(identity: ManifestRuntimeIdentity) -> bool:
    return (
        getattr(identity, "privileged", None) is None
        or getattr(identity, "authentication", None)
        is ManifestAuthenticationKind.UNKNOWN
        or getattr(identity, "environment", None) is ManifestEnvironmentKind.UNKNOWN
    )

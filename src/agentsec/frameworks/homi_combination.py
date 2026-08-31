"""Deterministic Homi cross-file combination rules (P2-HOMI-04).

This layer consumes the static P2-HOMI-03 profile only.  It deliberately does
not execute Homi files, connect to declared tools, fetch avatars, or convert a
combination into runtime authority or a CI decision.  Findings are report-only
and retain value-minimized signal provenance.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.frameworks.base import FrameworkAssetLocator
from agentsec.frameworks.homi_profile import (
    HomiCapabilityKind,
    HomiCapabilityProfile,
    HomiCapabilityState,
    HomiEvidenceMethod,
    HomiPersonaSignal,
    HomiProfileSignal,
)
from agentsec.risk import (
    RISK_MAPPING_BASIS,
    ImpactDimension,
    ImpactRating,
    agentsec_base_score,
    nist_risk_level,
    severity_for_score,
)
from agentsec.risk.models import IMPACT_ORDINALS

HOMI_COMBINATION_RULE_PACK_VERSION = "0.1.0"
HOMI_COMBINATION_RISK_MAPPING_BASIS = (
    *RISK_MAPPING_BASIS,
    "AgentSec P2-HOMI-04 deterministic cross-file combination policy 0.1.0",
    "Static Homi combinations are report-only and do not prove runtime reachability",
)

_RULE_ID_PATTERN = re.compile(r"^HOMI-COMB-[0-9]{3}$")
_FINDING_ID_PREFIX = "homi-combination-sha256:"
_MAX_CANDIDATES = 128
_CONFIDENCE_ORDER = {
    EvidenceConfidence.A: 0,
    EvidenceConfidence.B: 1,
    EvidenceConfidence.C: 2,
    EvidenceConfidence.D: 3,
}


class HomiCombinationLanguage(StrEnum):
    """Localized presentation languages for Homi combination findings."""

    EN = "en"
    ZH = "zh"


class HomiCombinationRuleId(StrEnum):
    """Stable report-only Homi combination rule identifiers."""

    PROACTIVE_EXTERNAL = "HOMI-COMB-001"
    HEARTBEAT_EXTERNAL = "HOMI-COMB-002"
    USER_MEMORY = "HOMI-COMB-003"
    SELF_MODIFICATION = "HOMI-COMB-004"
    TOOLS_SKILLS = "HOMI-COMB-005"


@dataclass(frozen=True, slots=True)
class HomiCombinationRuleText:
    """One localized presentation of a reviewed combination rule."""

    language: HomiCombinationLanguage
    title: str
    description: str
    recommendations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.language, HomiCombinationLanguage):
            raise TypeError("Homi combination language is invalid")
        _require_text(self.title, "Homi combination title")
        _require_text(self.description, "Homi combination description")
        _require_text_tuple(self.recommendations, "Homi combination recommendations")


@dataclass(frozen=True, slots=True)
class HomiCombinationRuleMetadata:
    """Trusted risk and localized metadata for one Homi combination rule."""

    rule_id: str
    category: FindingCategory
    texts: tuple[HomiCombinationRuleText, ...]
    likelihood: LikelihoodLevel
    impact_ratings: tuple[ImpactRating, ...]
    deterministic: Literal[True] = True
    report_only: Literal[True] = True

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Homi combination Rule ID must use HOMI-COMB-NNN form")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Homi combination category is invalid")
        if tuple(text.language for text in self.texts) != tuple(
            HomiCombinationLanguage
        ):
            raise ValueError("Homi combination texts must contain ordered en and zh")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("Homi combination likelihood is invalid")
        if not self.impact_ratings:
            raise ValueError("Homi combination requires impact ratings")
        if any(not isinstance(item, ImpactRating) for item in self.impact_ratings):
            raise TypeError("Homi combination impact rating is invalid")
        if (
            tuple(sorted(self.impact_ratings, key=lambda item: item.dimension.value))
            != self.impact_ratings
        ):
            raise ValueError("Homi combination impact ratings must be ordered")
        if len({item.dimension for item in self.impact_ratings}) != len(
            self.impact_ratings
        ):
            raise ValueError("Homi combination impact dimensions must be unique")
        if self.deterministic is not True or self.report_only is not True:
            raise ValueError(
                "Homi combination rules must remain deterministic/report-only"
            )

    @property
    def impact(self) -> ImpactLevel:
        """Return the highest impact dimension without averaging."""

        return max(
            (item.level for item in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )

    def text_for(self, language: HomiCombinationLanguage) -> HomiCombinationRuleText:
        """Return the reviewed localized text for this rule."""

        if not isinstance(language, HomiCombinationLanguage):
            raise TypeError("Homi combination language is invalid")
        return next(text for text in self.texts if text.language is language)


@dataclass(frozen=True, slots=True)
class HomiCombinationEvidence:
    """Value-minimized evidence copied from one Profile signal."""

    signal_id: str
    state: HomiCapabilityState
    confidence: EvidenceConfidence
    method: HomiEvidenceMethod
    sources: tuple[FrameworkAssetLocator, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        _require_text(self.signal_id, "Homi combination signal ID")
        if not isinstance(self.state, HomiCapabilityState):
            raise TypeError("Homi combination evidence state is invalid")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("Homi combination evidence confidence is invalid")
        if not isinstance(self.method, HomiEvidenceMethod):
            raise TypeError("Homi combination evidence method is invalid")
        source_keys = tuple(_locator_key(source) for source in self.sources)
        if source_keys != tuple(sorted(set(source_keys))):
            raise ValueError("Homi combination evidence sources must be sorted/unique")

    @classmethod
    def from_signal(cls, signal: HomiProfileSignal) -> HomiCombinationEvidence:
        """Copy a Profile signal without copying source content or values."""

        if not isinstance(signal, HomiProfileSignal):
            raise TypeError("Homi combination evidence requires a Profile signal")
        return cls(
            signal_id=signal.signal_id,
            state=signal.state,
            confidence=signal.confidence,
            method=signal.method,
            sources=signal.sources,
        )

    def sort_key(self) -> tuple[str, tuple[tuple[str, str, str], ...]]:
        return (self.signal_id, tuple(_locator_key(item) for item in self.sources))

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "state": self.state.value,
            "confidence": self.confidence.value,
            "method": self.method.value,
            "sources": [
                {
                    "scope": source.scope.value,
                    "root_id": source.root_id,
                    "path": source.path,
                }
                for source in self.sources
            ],
        }


@dataclass(frozen=True, slots=True)
class HomiCombinationCandidate:
    """One deterministic match before risk materialization."""

    evidence: tuple[HomiCombinationEvidence, ...]
    rationale: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.evidence) < 2:
            raise ValueError("Homi combination candidate requires two signals")
        if any(not isinstance(item, HomiCombinationEvidence) for item in self.evidence):
            raise TypeError("Homi combination candidate evidence is invalid")
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError(
                "Homi combination candidate evidence must be sorted/unique"
            )
        _require_text_tuple(self.rationale, "Homi combination rationale")
        _require_text_tuple(self.limitations, "Homi combination limitations")

    @property
    def related_signal_ids(self) -> tuple[str, ...]:
        """Return canonical signal IDs supporting this combination."""

        return tuple(item.signal_id for item in self.evidence)

    def sort_key(
        self,
    ) -> tuple[
        tuple[str, ...], tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...]
    ]:
        return (
            self.related_signal_ids,
            tuple(item.sort_key() for item in self.evidence),
        )


@dataclass(frozen=True, slots=True)
class HomiCombinationRuleEvaluation:
    """Validated output from one Homi combination rule."""

    candidates: tuple[HomiCombinationCandidate, ...] = ()

    def __post_init__(self) -> None:
        if any(
            not isinstance(item, HomiCombinationCandidate) for item in self.candidates
        ):
            raise TypeError("Homi combination candidates are invalid")
        if len(self.candidates) > _MAX_CANDIDATES:
            raise ValueError("Homi combination candidate limit exceeded")
        keys = tuple(item.sort_key() for item in self.candidates)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Homi combination candidates must be sorted/unique")


@runtime_checkable
class HomiCombinationRule(Protocol):
    """Pure deterministic rule over a finalized Homi Capability Profile."""

    @property
    def metadata(self) -> HomiCombinationRuleMetadata:
        """Return trusted immutable rule metadata."""

    def evaluate(self, profile: HomiCapabilityProfile) -> HomiCombinationRuleEvaluation:
        """Evaluate Profile facts without filesystem, network, execution, or LLM."""


@dataclass(frozen=True, slots=True)
class HomiCombinationFinding:
    """Report-only finding materialized from a Homi cross-file combination."""

    finding_id: str
    rule_id: str
    category: FindingCategory
    texts: tuple[HomiCombinationRuleText, ...]
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    score: float
    severity: Severity
    confidence: EvidenceConfidence
    related_signal_ids: tuple[str, ...]
    evidence: tuple[HomiCombinationEvidence, ...] = dataclass_field(repr=False)
    rationale: tuple[str, ...]
    limitations: tuple[str, ...]
    impact_ratings: tuple[ImpactRating, ...]
    mapping_basis: tuple[str, ...]
    rule_pack_version: str = HOMI_COMBINATION_RULE_PACK_VERSION
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False

    def __post_init__(self) -> None:
        if not self.finding_id.startswith(_FINDING_ID_PREFIX):
            raise ValueError("Homi combination Finding ID is invalid")
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Homi combination Finding Rule ID is invalid")
        if tuple(text.language for text in self.texts) != tuple(
            HomiCombinationLanguage
        ):
            raise ValueError("Homi combination Finding texts are incomplete")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Homi combination Finding category is invalid")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("Homi combination Finding likelihood is invalid")
        if not isinstance(self.impact, ImpactLevel):
            raise TypeError("Homi combination Finding impact is invalid")
        if not isinstance(self.severity, Severity):
            raise TypeError("Homi combination Finding severity is invalid")
        if not 0.0 <= self.score <= 10.0:
            raise ValueError("Homi combination Finding score is out of range")
        if severity_for_score(self.score) is not self.severity:
            raise ValueError("Homi combination Finding severity is inconsistent")
        if self.related_signal_ids != tuple(sorted(set(self.related_signal_ids))):
            raise ValueError(
                "Homi combination Finding signal IDs must be sorted/unique"
            )
        if tuple(item.signal_id for item in self.evidence) != self.related_signal_ids:
            raise ValueError("Homi combination Finding evidence IDs are inconsistent")
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("Homi combination Finding evidence must be sorted/unique")
        expected_impact = max(
            (item.level for item in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )
        if expected_impact is not self.impact:
            raise ValueError("Homi combination Finding impact is inconsistent")
        expected_score = agentsec_base_score(
            nist_risk_level(self.likelihood, self.impact)
        )
        if self.score != expected_score:
            raise ValueError("Homi combination Finding score is inconsistent")
        if self.confidence is not _weakest_confidence(self.evidence):
            raise ValueError("Homi combination Finding confidence is inconsistent")
        _require_text_tuple(self.rationale, "Homi combination Finding rationale")
        _require_text_tuple(self.limitations, "Homi combination Finding limitations")
        if self.mapping_basis != HOMI_COMBINATION_RISK_MAPPING_BASIS:
            raise ValueError("Homi combination Finding mapping basis is inconsistent")
        if self.rule_pack_version != HOMI_COMBINATION_RULE_PACK_VERSION:
            raise ValueError("Homi combination Rule Pack version is unsupported")
        if self.report_only is not True or self.runtime_verified is not False:
            raise ValueError("Homi combination Finding authority flags are invalid")

    def text_for(self, language: HomiCombinationLanguage) -> HomiCombinationRuleText:
        """Return one localized finding presentation."""

        if not isinstance(language, HomiCombinationLanguage):
            raise TypeError("Homi combination language is invalid")
        return next(text for text in self.texts if text.language is language)

    def sort_key(self) -> tuple[str, tuple[str, ...], str]:
        return (self.rule_id, self.related_signal_ids, self.finding_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "texts": [
                {
                    "language": text.language.value,
                    "title": text.title,
                    "description": text.description,
                    "recommendations": list(text.recommendations),
                }
                for text in self.texts
            ],
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "score": self.score,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "related_signal_ids": list(self.related_signal_ids),
            "evidence": [item.to_dict() for item in self.evidence],
            "rationale": list(self.rationale),
            "limitations": list(self.limitations),
            "impact_ratings": [
                {
                    "dimension": item.dimension.value,
                    "level": item.level.value,
                    "rationale": item.rationale,
                }
                for item in self.impact_ratings
            ],
            "mapping_basis": list(self.mapping_basis),
            "rule_pack_version": self.rule_pack_version,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
        }


@dataclass(frozen=True, slots=True, order=True)
class HomiCombinationRuleFailure:
    """One isolated Homi rule failure retaining only stable Rule identity."""

    rule_id: str

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Homi combination failure Rule ID is invalid")


@dataclass(frozen=True, slots=True)
class HomiCombinationRunResult:
    """Stable Homi combination findings, failures, and example suppressions."""

    evaluated_rule_ids: tuple[str, ...]
    findings: tuple[HomiCombinationFinding, ...] = dataclass_field(repr=False)
    failures: tuple[HomiCombinationRuleFailure, ...] = ()
    suppressed_example_capabilities: tuple[HomiCapabilityKind, ...] = ()
    profile_complete: bool = False
    rule_pack_version: str = HOMI_COMBINATION_RULE_PACK_VERSION

    def __post_init__(self) -> None:
        if self.evaluated_rule_ids != tuple(sorted(set(self.evaluated_rule_ids))):
            raise ValueError("Homi evaluated Rule IDs must be sorted/unique")
        if any(not isinstance(item, HomiCombinationFinding) for item in self.findings):
            raise TypeError("Homi combination findings are invalid")
        finding_keys = tuple(item.sort_key() for item in self.findings)
        if finding_keys != tuple(sorted(set(finding_keys))):
            raise ValueError("Homi combination findings must be sorted/unique")
        if self.failures != tuple(sorted(set(self.failures))):
            raise ValueError("Homi combination failures must be sorted/unique")
        if any(item.rule_id not in self.evaluated_rule_ids for item in self.failures):
            raise ValueError("Homi combination failure was not evaluated")
        if self.suppressed_example_capabilities != tuple(
            sorted(
                set(self.suppressed_example_capabilities), key=lambda item: item.value
            )
        ):
            raise ValueError("Homi example capabilities must be sorted/unique")
        if not isinstance(self.profile_complete, bool):
            raise TypeError("Homi profile_complete must be bool")
        if self.rule_pack_version != HOMI_COMBINATION_RULE_PACK_VERSION:
            raise ValueError("Homi combination Rule Pack version is unsupported")

    @property
    def complete(self) -> bool:
        """Return whether rules ran without failures and Profile coverage is
        complete.
        """

        return self.profile_complete and not self.failures

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_pack_version": self.rule_pack_version,
            "evaluated_rule_ids": list(self.evaluated_rule_ids),
            "findings": [item.to_dict() for item in self.findings],
            "failures": [item.rule_id for item in self.failures],
            "suppressed_example_capabilities": [
                item.value for item in self.suppressed_example_capabilities
            ],
            "profile_complete": self.profile_complete,
            "complete": self.complete,
        }


@runtime_checkable
class HomiCombinationRuleEngine(Protocol):
    """Protocol for deterministic Homi combination evaluation."""

    def run(self, profile: HomiCapabilityProfile) -> HomiCombinationRunResult:
        """Evaluate all registered rules against one Homi Profile."""


@dataclass(frozen=True, slots=True)
class _HomiCombinationRule:
    metadata: HomiCombinationRuleMetadata
    evaluator: Callable[[HomiCapabilityProfile], HomiCombinationRuleEvaluation] = (
        dataclass_field(repr=False)
    )

    def evaluate(self, profile: HomiCapabilityProfile) -> HomiCombinationRuleEvaluation:
        return self.evaluator(profile)


class DeterministicHomiCombinationRuleEngine:
    """Run pure cross-file Homi rules with per-rule failure isolation."""

    def __init__(self, rules: tuple[HomiCombinationRule, ...] | None = None) -> None:
        selected = rules or builtin_homi_combination_rules()
        if not isinstance(selected, tuple) or not selected:
            raise HomiCombinationRuleRegistryError()
        registered: list[HomiCombinationRule] = []
        try:
            for rule in selected:
                metadata = rule.metadata
                if not isinstance(metadata, HomiCombinationRuleMetadata):
                    raise TypeError
                if not callable(getattr(rule, "evaluate", None)):
                    raise TypeError
                registered.append(rule)
        except Exception:
            raise HomiCombinationRuleRegistryError() from None
        registered.sort(key=lambda item: item.metadata.rule_id)
        ids = tuple(item.metadata.rule_id for item in registered)
        if len(set(ids)) != len(ids):
            raise HomiCombinationRuleRegistryError()
        self._rules = tuple(registered)

    def run(self, profile: HomiCapabilityProfile) -> HomiCombinationRunResult:
        """Evaluate all Homi rules without executing source content."""

        if not isinstance(profile, HomiCapabilityProfile):
            raise TypeError("Homi combination engine requires HomiCapabilityProfile")
        findings: list[HomiCombinationFinding] = []
        failures: list[HomiCombinationRuleFailure] = []
        for rule in self._rules:
            rule_id = rule.metadata.rule_id
            try:
                evaluation = rule.evaluate(profile)
                validated = HomiCombinationRuleEvaluation(
                    candidates=evaluation.candidates
                )
                findings.extend(
                    _materialize(rule.metadata, candidate)
                    for candidate in validated.candidates
                )
            except Exception:
                failures.append(HomiCombinationRuleFailure(rule_id=rule_id))
        return HomiCombinationRunResult(
            evaluated_rule_ids=tuple(item.metadata.rule_id for item in self._rules),
            findings=_deduplicate_findings(tuple(findings)),
            failures=tuple(sorted(set(failures))),
            suppressed_example_capabilities=_example_only_capabilities(profile),
            profile_complete=profile.complete,
        )


class HomiCombinationRuleRegistryError(RuntimeError):
    """Safe trusted-registry failure without implementation details."""

    def __init__(self) -> None:
        super().__init__("Homi combination Rule registry validation failed safely.")


class HomiCombinationRulePipelineError(RuntimeError):
    """Safe Homi combination materialization failure."""


def builtin_homi_combination_rules() -> tuple[HomiCombinationRule, ...]:
    """Return the reviewed deterministic Homi combination Rule Pack."""

    return (
        _rule_proactive_external(),
        _rule_heartbeat_external(),
        _rule_user_memory(),
        _rule_self_modification(),
        _rule_tools_skills(),
    )


def _rule_proactive_external() -> HomiCombinationRule:
    return _HomiCombinationRule(
        metadata=_metadata(
            HomiCombinationRuleId.PROACTIVE_EXTERNAL,
            FindingCategory.EXTERNAL_TOOLING,
            LikelihoodLevel.MODERATE,
            _impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "主动行为与外部能力组合可能扩大敏感数据的主动外发范围。",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "外部工具可能将 Agent 行为扩展到当前工作区之外。",
                ),
            ),
            "Proactive behavior is combined with an active external capability",
            "主动行为与外部能力组合出现",
            (
                "The persona encourages proactive behavior while a network, message, "
                "or external tool capability is statically declared."
            ),
            "人格规范鼓励主动行动，同时静态声明了网络、消息或外部工具能力。",
            (
                "Keep external capabilities least-privileged, require approval for "
                "side effects, and verify the runtime Tool Registry separately."
            ),
            "限制外部能力权限，对副作用保留人工审批，并单独核验运行时 Tool Registry。",
        ),
        evaluator=_proactive_external_evaluate,
    )


def _rule_heartbeat_external() -> HomiCombinationRule:
    return _HomiCombinationRule(
        metadata=_metadata(
            HomiCombinationRuleId.HEARTBEAT_EXTERNAL,
            FindingCategory.NETWORK_ACCESS,
            LikelihoodLevel.HIGH,
            _impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.HIGH,
                    "Heartbeat 任务可在对话外周期性触发外部读取或访问。",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "调度路径会把外部能力的影响扩展到多个时间点和上下文。",
                ),
            ),
            "Heartbeat tasks are combined with external access",
            "Heartbeat 任务与外部访问组合出现",
            (
                "A non-empty Heartbeat declaration coexists with external network, "
                "message, or MCP capability."
            ),
            "非空 Heartbeat 声明与外部网络、消息或 MCP 能力同时存在。",
            (
                "Make scheduled external access explicit, bounded, auditable, and "
                "independently attested by the runtime scheduler."
            ),
            "明确限制定时外部访问的目标、频率和审批，并单独核验运行时调度器。",
        ),
        evaluator=_heartbeat_external_evaluate,
    )


def _rule_user_memory() -> HomiCombinationRule:
    return _HomiCombinationRule(
        metadata=_metadata(
            HomiCombinationRuleId.USER_MEMORY,
            FindingCategory.PERSISTENT_MEMORY,
            LikelihoodLevel.MODERATE,
            _impact(
                (
                    ImpactDimension.CONFIDENTIALITY,
                    ImpactLevel.VERY_HIGH,
                    "用户画像与长期记忆组合可能延长敏感上下文的保留和暴露周期。",
                ),
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "持久化用户上下文可能影响未来任务和行为决策。",
                ),
            ),
            "User profile persistence is combined with long-term memory",
            "用户画像持久化与长期记忆组合出现",
            "USER.md persistence guidance coexists with persistent memory behavior.",
            "USER.md 持久化指引与长期记忆行为同时存在。",
            (
                "Define retention, deletion, access, and secret-exclusion controls "
                "for user context and persistent memory."
            ),
            "为用户上下文和长期记忆定义保留、删除、访问和 Secret 排除控制。",
        ),
        evaluator=_user_memory_evaluate,
    )


def _rule_self_modification() -> HomiCombinationRule:
    return _HomiCombinationRule(
        metadata=_metadata(
            HomiCombinationRuleId.SELF_MODIFICATION,
            FindingCategory.SELF_MODIFICATION,
            LikelihoodLevel.MODERATE,
            _impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.VERY_HIGH,
                    "人格或身份文件自修改可能改变后续行为边界和身份声明。",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "被修改的控制文件可能影响后续会话和外部上下文。",
                ),
            ),
            "Persona and identity self-modification are combined",
            "人格与身份自修改能力组合出现",
            (
                "SOUL.md self-evolution guidance coexists with IDENTITY.md "
                "self-assignment guidance."
            ),
            "SOUL.md 的自我演化指引与 IDENTITY.md 的身份自赋值指引同时存在。",
            (
                "Protect control files with review, integrity monitoring, and a "
                "separate runtime write authorization."
            ),
            "对控制文件启用评审、完整性监控，并单独配置运行时写入授权。",
        ),
        evaluator=_self_modification_evaluate,
    )


def _rule_tools_skills() -> HomiCombinationRule:
    return _HomiCombinationRule(
        metadata=_metadata(
            HomiCombinationRuleId.TOOLS_SKILLS,
            FindingCategory.EXTERNAL_TOOLING,
            LikelihoodLevel.MODERATE,
            _impact(
                (
                    ImpactDimension.INTEGRITY,
                    ImpactLevel.HIGH,
                    "Skill 工具扩展与环境绑定组合可能引入未经独立审核的工具路径。",
                ),
                (
                    ImpactDimension.DOWNSTREAM_BLAST_RADIUS,
                    ImpactLevel.HIGH,
                    "工具扩展可把本地环境绑定暴露给更多技能和任务。",
                ),
            ),
            "Tool bindings are combined with Skill-based tool discovery",
            "工具绑定与 Skill 工具发现组合出现",
            (
                "TOOLS.md contains an active tool binding while AGENTS.md permits "
                "or describes Skill tool discovery."
            ),
            "TOOLS.md 包含有效工具绑定，同时 AGENTS.md 声明或允许通过 Skill 发现工具。",
            (
                "Use an allowlisted Runtime Tool Registry, review Skill provenance, "
                "and keep local notes separate from executable tool authority."
            ),
            (
                "使用白名单 Runtime Tool Registry，审核 Skill 来源，并将本地笔记与"
                "可执行工具权限分离。"
            ),
        ),
        evaluator=_tools_skills_evaluate,
    )


def _metadata(
    rule_id: HomiCombinationRuleId,
    category: FindingCategory,
    likelihood: LikelihoodLevel,
    impact_ratings: tuple[ImpactRating, ...],
    en_title: str,
    zh_title: str,
    en_description: str,
    zh_description: str,
    en_recommendation: str,
    zh_recommendation: str,
) -> HomiCombinationRuleMetadata:
    return HomiCombinationRuleMetadata(
        rule_id=rule_id.value,
        category=category,
        texts=(
            HomiCombinationRuleText(
                language=HomiCombinationLanguage.EN,
                title=en_title,
                description=en_description,
                recommendations=(en_recommendation,),
            ),
            HomiCombinationRuleText(
                language=HomiCombinationLanguage.ZH,
                title=zh_title,
                description=zh_description,
                recommendations=(zh_recommendation,),
            ),
        ),
        likelihood=likelihood,
        impact_ratings=impact_ratings,
    )


def _proactive_external_evaluate(
    profile: HomiCapabilityProfile,
) -> HomiCombinationRuleEvaluation:
    proactive = _persona_signal(profile, HomiPersonaSignal.PROACTIVE)
    if proactive is None:
        return HomiCombinationRuleEvaluation()
    external = _active_capabilities(
        profile,
        {
            HomiCapabilityKind.EXTERNAL_NETWORK_READ,
            HomiCapabilityKind.EXTERNAL_MESSAGE_SEND,
            HomiCapabilityKind.MCP_ACCESS,
            HomiCapabilityKind.SSH_ACCESS,
            HomiCapabilityKind.CAMERA_ACCESS,
            HomiCapabilityKind.TTS_OUTPUT,
            HomiCapabilityKind.OAUTH_ACCESS,
            HomiCapabilityKind.SECRET_ACCESS,
        },
    )
    if not external:
        return HomiCombinationRuleEvaluation()
    return HomiCombinationRuleEvaluation(
        candidates=(
            _candidate(
                (proactive, *external),
                (
                    "Proactive persona behavior and one or more active external "
                    "capabilities are present."
                ),
                (
                    "Static declarations do not prove that the runtime can reach or "
                    "use the capability."
                ),
            ),
        )
    )


def _heartbeat_external_evaluate(
    profile: HomiCapabilityProfile,
) -> HomiCombinationRuleEvaluation:
    if profile.heartbeat.state is not HomiCapabilityState.PRESENT:
        return HomiCombinationRuleEvaluation()
    if not profile.heartbeat.tasks_present:
        return HomiCombinationRuleEvaluation()
    external = _active_capabilities(
        profile,
        {
            HomiCapabilityKind.EXTERNAL_NETWORK_READ,
            HomiCapabilityKind.EXTERNAL_MESSAGE_SEND,
            HomiCapabilityKind.MCP_ACCESS,
        },
    )
    if not external:
        return HomiCombinationRuleEvaluation()
    return HomiCombinationRuleEvaluation(
        candidates=(
            _candidate(
                (profile.heartbeat.signal, *external),
                (
                    "Heartbeat contains task content and an active external access "
                    "declaration is present."
                ),
                (
                    "The file does not attest that a scheduler runs or that external "
                    "access succeeds."
                ),
            ),
        )
    )


def _user_memory_evaluate(
    profile: HomiCapabilityProfile,
) -> HomiCombinationRuleEvaluation:
    if profile.user_privacy.persistence.state is not HomiCapabilityState.PRESENT:
        return HomiCombinationRuleEvaluation()
    persistent = _capability_signal(profile, HomiCapabilityKind.PERSISTENT_MEMORY)
    if persistent is None or persistent.state is not HomiCapabilityState.PRESENT:
        return HomiCombinationRuleEvaluation()
    return HomiCombinationRuleEvaluation(
        candidates=(
            _candidate(
                (profile.user_privacy.persistence, persistent),
                (
                    "USER.md persistence guidance and persistent memory behavior are "
                    "both declared."
                ),
                (
                    "No user values are copied; retention and runtime memory behavior "
                    "are not attested."
                ),
            ),
        )
    )


def _self_modification_evaluate(
    profile: HomiCapabilityProfile,
) -> HomiCombinationRuleEvaluation:
    persona = _persona_signal(profile, HomiPersonaSignal.SELF_EVOLUTION)
    identity = profile.identity.self_assignment
    if persona is None or identity.state is not HomiCapabilityState.PRESENT:
        return HomiCombinationRuleEvaluation()
    signals = [persona, identity]
    control = _capability_signal(
        profile, HomiCapabilityKind.CONTROL_FILE_SELF_MODIFICATION
    )
    if control is not None and control.state is HomiCapabilityState.PRESENT:
        signals.append(control)
    return HomiCombinationRuleEvaluation(
        candidates=(
            _candidate(
                tuple(signals),
                (
                    "SOUL.md self-evolution and IDENTITY.md self-assignment are "
                    "both declared."
                ),
                (
                    "Static guidance does not prove that the files are writable at "
                    "runtime."
                ),
            ),
        )
    )


def _tools_skills_evaluate(
    profile: HomiCapabilityProfile,
) -> HomiCombinationRuleEvaluation:
    skill = _capability_signal(profile, HomiCapabilityKind.SKILL_TOOL_DISCOVERY)
    if skill is None or skill.state is not HomiCapabilityState.PRESENT:
        return HomiCombinationRuleEvaluation()
    active_tools = tuple(
        signal
        for signal in _tool_signals(profile)
        if signal.state
        in {
            HomiCapabilityState.PRESENT,
            HomiCapabilityState.CONDITIONAL,
        }
    )
    if not active_tools:
        return HomiCombinationRuleEvaluation()
    return HomiCombinationRuleEvaluation(
        candidates=(
            _candidate(
                (skill, *active_tools),
                (
                    "Skill tool discovery and one or more active TOOLS.md bindings "
                    "are declared."
                ),
                (
                    "TOOLS.md is not a Runtime Tool Registry and no tool execution "
                    "was performed."
                ),
            ),
        )
    )


def _candidate(
    signals: Sequence[HomiProfileSignal],
    rationale: str,
    limitation: str,
) -> HomiCombinationCandidate:
    evidence = tuple(
        sorted(
            (HomiCombinationEvidence.from_signal(signal) for signal in signals),
            key=lambda item: item.sort_key(),
        )
    )
    return HomiCombinationCandidate(
        evidence=evidence,
        rationale=(rationale,),
        limitations=(limitation,),
    )


def _materialize(
    metadata: HomiCombinationRuleMetadata,
    candidate: HomiCombinationCandidate,
) -> HomiCombinationFinding:
    impact = metadata.impact
    risk_level = nist_risk_level(metadata.likelihood, impact)
    score = agentsec_base_score(risk_level)
    evidence = candidate.evidence
    payload = {
        "rule_id": metadata.rule_id,
        "signals": tuple(item.signal_id for item in evidence),
        "evidence": tuple(
            (item.signal_id, item.state.value, item.confidence.value, item.sort_key())
            for item in evidence
        ),
    }
    finding_id = (
        _FINDING_ID_PREFIX
        + hashlib.sha256(
            json.dumps(
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )
    return HomiCombinationFinding(
        finding_id=finding_id,
        rule_id=metadata.rule_id,
        category=metadata.category,
        texts=metadata.texts,
        likelihood=metadata.likelihood,
        impact=impact,
        score=score,
        severity=severity_for_score(score),
        confidence=_weakest_confidence(evidence),
        related_signal_ids=tuple(item.signal_id for item in evidence),
        evidence=evidence,
        rationale=candidate.rationale,
        limitations=candidate.limitations,
        impact_ratings=metadata.impact_ratings,
        mapping_basis=HOMI_COMBINATION_RISK_MAPPING_BASIS,
    )


def _deduplicate_findings(
    findings: tuple[HomiCombinationFinding, ...],
) -> tuple[HomiCombinationFinding, ...]:
    by_id: dict[str, HomiCombinationFinding] = {}
    for finding in findings:
        previous = by_id.get(finding.finding_id)
        if previous is not None and previous != finding:
            raise HomiCombinationRulePipelineError(
                "Homi combination Finding identity conflict detected safely."
            )
        by_id[finding.finding_id] = finding
    return tuple(sorted(by_id.values(), key=lambda item: item.sort_key()))


def _active_capabilities(
    profile: HomiCapabilityProfile,
    kinds: set[HomiCapabilityKind],
) -> tuple[HomiProfileSignal, ...]:
    return tuple(
        capability.signal
        for capability in profile.capabilities
        if capability.kind in kinds
        and capability.signal.state
        in {HomiCapabilityState.PRESENT, HomiCapabilityState.CONDITIONAL}
    )


def _capability_signal(
    profile: HomiCapabilityProfile,
    kind: HomiCapabilityKind,
) -> HomiProfileSignal | None:
    return next(
        (
            capability.signal
            for capability in profile.capabilities
            if capability.kind is kind
        ),
        None,
    )


def _persona_signal(
    profile: HomiCapabilityProfile,
    signal_id: HomiPersonaSignal,
) -> HomiProfileSignal | None:
    return next(
        (
            signal
            for signal in profile.persona.signals
            if signal.signal_id == signal_id.value
        ),
        None,
    )


def _tool_signals(profile: HomiCapabilityProfile) -> tuple[HomiProfileSignal, ...]:
    return (
        profile.tools.camera,
        profile.tools.ssh,
        profile.tools.tts,
        profile.tools.mcp,
        profile.tools.oauth,
        profile.tools.secret_access,
    )


def _example_only_capabilities(
    profile: HomiCapabilityProfile,
) -> tuple[HomiCapabilityKind, ...]:
    by_signal = {
        HomiCapabilityKind.CAMERA_ACCESS: profile.tools.camera,
        HomiCapabilityKind.SSH_ACCESS: profile.tools.ssh,
        HomiCapabilityKind.TTS_OUTPUT: profile.tools.tts,
        HomiCapabilityKind.MCP_ACCESS: profile.tools.mcp,
        HomiCapabilityKind.OAUTH_ACCESS: profile.tools.oauth,
        HomiCapabilityKind.SECRET_ACCESS: profile.tools.secret_access,
    }
    return tuple(
        sorted(
            (
                kind
                for kind, signal in by_signal.items()
                if signal.state is HomiCapabilityState.EXAMPLE_ONLY
            ),
            key=lambda item: item.value,
        )
    )


def _weakest_confidence(
    evidence: Sequence[HomiCombinationEvidence],
) -> EvidenceConfidence:
    return max(
        (item.confidence for item in evidence),
        key=_CONFIDENCE_ORDER.__getitem__,
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


def _locator_key(locator: FrameworkAssetLocator) -> tuple[str, str, str]:
    return (locator.scope.value, locator.root_id, locator.path)


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{label} must be a non-empty tuple")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} must contain non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


__all__ = [
    "HOMI_COMBINATION_RISK_MAPPING_BASIS",
    "HOMI_COMBINATION_RULE_PACK_VERSION",
    "DeterministicHomiCombinationRuleEngine",
    "HomiCombinationCandidate",
    "HomiCombinationEvidence",
    "HomiCombinationFinding",
    "HomiCombinationLanguage",
    "HomiCombinationRule",
    "HomiCombinationRuleEvaluation",
    "HomiCombinationRuleFailure",
    "HomiCombinationRuleId",
    "HomiCombinationRuleMetadata",
    "HomiCombinationRulePipelineError",
    "HomiCombinationRuleRegistryError",
    "HomiCombinationRuleText",
    "HomiCombinationRunResult",
    "builtin_homi_combination_rules",
]

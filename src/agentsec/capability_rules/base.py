"""Framework-neutral deterministic Capability Rule contracts and models."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from dataclasses import replace as dataclass_replace
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, Protocol, runtime_checkable

from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.manifests import (
    AgentManifest,
    ManifestControl,
    ManifestControlKind,
    ManifestControlState,
    ManifestPermission,
    ManifestRelation,
    ManifestRelationKind,
    ManifestRuntimeIdentity,
    ManifestSource,
    ManifestSourceReference,
    ManifestTool,
    ManifestToolAvailability,
    ManifestUnknown,
    ManifestUnknownDimension,
)
from agentsec.risk import (
    RISK_MAPPING_BASIS,
    ImpactRating,
    NistRiskLevel,
    agentsec_base_score,
    nist_risk_level,
    nist_semi_quantitative_value,
    severity_for_score,
)
from agentsec.risk.models import IMPACT_ORDINALS
from agentsec.versioning import (
    AGENT_MANIFEST_SCHEMA_VERSION,
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
    CAPABILITY_SHADOW_GATE_VERSION,
)

_RULE_ID_PATTERN = re.compile(r"^CAP-[A-Z][A-Z0-9]*-[0-9]{3}$")
_GATE_ID_PATTERN = re.compile(r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINDING_ID_PATTERN = re.compile(r"^capability-finding-sha256:[a-f0-9]{64}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_MAX_RULE_CANDIDATES = 4_096

CAPABILITY_CORRELATION_POLICY_BASIS = (
    "AgentSec P2I-02 same-target, parent-child, source, relation, Agent-wide, "
    "and incomplete-Coverage correlation policy"
)
CAPABILITY_RISK_MAPPING_BASIS = (
    *RISK_MAPPING_BASIS,
    CAPABILITY_CORRELATION_POLICY_BASIS,
)


class CapabilityRuleLanguage(StrEnum):
    """Reviewed languages available for Capability Rule presentation."""

    EN = "en"
    ZH = "zh"


class CapabilityCorrelation(StrEnum):
    """Strength and scope of the deterministic fact correlation."""

    SAME_TARGET = "same_target"
    PARENT_CHILD = "parent_child"
    SAME_SOURCE = "same_source"
    EXPLICIT_RELATION = "explicit_relation"
    AGENT_WIDE = "agent_wide"
    INCOMPLETE_COVERAGE = "incomplete_coverage"


_SHADOW_GATE_CORRELATIONS = frozenset(
    {
        CapabilityCorrelation.SAME_TARGET,
        CapabilityCorrelation.PARENT_CHILD,
    }
)


_CORRELATION_CONFIDENCE = {
    CapabilityCorrelation.SAME_TARGET: EvidenceConfidence.B,
    CapabilityCorrelation.PARENT_CHILD: EvidenceConfidence.C,
    CapabilityCorrelation.SAME_SOURCE: EvidenceConfidence.C,
    CapabilityCorrelation.EXPLICIT_RELATION: EvidenceConfidence.C,
    CapabilityCorrelation.AGENT_WIDE: EvidenceConfidence.D,
    CapabilityCorrelation.INCOMPLETE_COVERAGE: EvidenceConfidence.D,
}
_CORRELATION_LIKELIHOOD = {
    CapabilityCorrelation.SAME_TARGET: LikelihoodLevel.MODERATE,
    CapabilityCorrelation.PARENT_CHILD: LikelihoodLevel.MODERATE,
    CapabilityCorrelation.SAME_SOURCE: LikelihoodLevel.MODERATE,
    CapabilityCorrelation.EXPLICIT_RELATION: LikelihoodLevel.MODERATE,
    CapabilityCorrelation.AGENT_WIDE: LikelihoodLevel.LOW,
    CapabilityCorrelation.INCOMPLETE_COVERAGE: LikelihoodLevel.LOW,
}


def confidence_for_correlation(
    correlation: CapabilityCorrelation,
) -> EvidenceConfidence:
    """Return the reviewed evidence grade for one correlation method."""

    if not isinstance(correlation, CapabilityCorrelation):
        raise TypeError("correlation must be CapabilityCorrelation")
    return _CORRELATION_CONFIDENCE[correlation]


def likelihood_for_correlation(
    correlation: CapabilityCorrelation,
) -> LikelihoodLevel:
    """Return the reviewed static likelihood for one correlation method."""

    if not isinstance(correlation, CapabilityCorrelation):
        raise TypeError("correlation must be CapabilityCorrelation")
    return _CORRELATION_LIKELIHOOD[correlation]


@dataclass(frozen=True, slots=True)
class CapabilityRuleText:
    """One reviewed localized presentation of immutable Rule meaning."""

    language: CapabilityRuleLanguage
    title: str
    description: str
    recommendations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.language, CapabilityRuleLanguage):
            raise TypeError("Capability Rule language must be supported")
        _require_text(self.title, "Capability Rule title")
        _require_text(self.description, "Capability Rule description")
        _require_text_tuple(
            self.recommendations,
            "Capability Rule recommendations",
        )


@dataclass(frozen=True, slots=True)
class CapabilityRuleMetadata:
    """Trusted identity, localization, and impact policy for one Rule."""

    rule_id: str
    category: FindingCategory
    texts: tuple[CapabilityRuleText, ...]
    impact_ratings: tuple[ImpactRating, ...]
    deterministic: Literal[True] = True
    hard_gate: Literal[False] = False

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Capability Rule ID must use CAP-TOPIC-NNN form")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Capability Rule category must be FindingCategory")
        if not isinstance(self.texts, tuple) or any(
            not isinstance(text, CapabilityRuleText) for text in self.texts
        ):
            raise TypeError("Capability Rule texts must be a typed tuple")
        expected_languages = tuple(CapabilityRuleLanguage)
        if tuple(text.language for text in self.texts) != expected_languages:
            raise ValueError("Capability Rule texts must contain ordered en and zh")
        if not isinstance(self.impact_ratings, tuple) or not self.impact_ratings:
            raise ValueError("Capability Rule requires impact ratings")
        if any(not isinstance(item, ImpactRating) for item in self.impact_ratings):
            raise TypeError("Capability Rule contains an invalid impact rating")
        ordered = tuple(
            sorted(self.impact_ratings, key=lambda item: item.dimension.value)
        )
        if ordered != self.impact_ratings:
            raise ValueError("Capability Rule impact ratings must be ordered")
        if len({item.dimension for item in ordered}) != len(ordered):
            raise ValueError("Capability Rule impact dimensions must be unique")
        if self.deterministic is not True:
            raise ValueError("Capability Rules must be deterministic")
        if self.hard_gate is not False:
            raise ValueError("P2I-02 Capability Rules must remain report-only")

    @property
    def impact(self) -> ImpactLevel:
        """Return the FIPS-style high-water-mark impact."""

        return max(
            (rating.level for rating in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )

    def text_for(self, language: CapabilityRuleLanguage) -> CapabilityRuleText:
        """Return reviewed localized text without source-dependent translation."""

        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        return next(text for text in self.texts if text.language is language)


@dataclass(frozen=True, slots=True)
class CapabilityRuleContext:
    """Immutable, indexed, data-only view of one finalized Agent Manifest."""

    manifest: AgentManifest = dataclass_field(repr=False)
    tools_by_id: Mapping[str, ManifestTool] = dataclass_field(repr=False)
    permissions_by_target: Mapping[str, tuple[ManifestPermission, ...]] = (
        dataclass_field(repr=False)
    )
    controls_by_target: Mapping[str, tuple[ManifestControl, ...]] = dataclass_field(
        repr=False
    )
    identities_by_tool: Mapping[str, tuple[ManifestRuntimeIdentity, ...]] = (
        dataclass_field(repr=False)
    )
    child_tools_by_parent: Mapping[str, tuple[ManifestTool, ...]] = dataclass_field(
        repr=False
    )
    relations_by_kind: Mapping[ManifestRelationKind, tuple[ManifestRelation, ...]] = (
        dataclass_field(repr=False)
    )
    unknowns_by_dimension: Mapping[
        ManifestUnknownDimension, tuple[ManifestUnknown, ...]
    ] = dataclass_field(repr=False)
    sources_by_locator: Mapping[tuple[str, str, str], ManifestSource] = dataclass_field(
        repr=False
    )

    @classmethod
    def from_manifest(cls, manifest: AgentManifest) -> CapabilityRuleContext:
        """Build deterministic indexes without reading source files or values."""

        if not isinstance(manifest, AgentManifest):
            raise TypeError("Capability Rule context requires AgentManifest")
        if manifest.schema_version != AGENT_MANIFEST_SCHEMA_VERSION:
            raise CapabilityRuleContextError(
                "Capability Rule context Manifest version is unsupported."
            )

        tools_by_id = {tool.tool_id: tool for tool in manifest.tools.tools}
        permissions: dict[str, list[ManifestPermission]] = defaultdict(list)
        for permission in manifest.permissions.permissions:
            if permission.target is not None:
                permissions[permission.target].append(permission)
        controls: dict[str, list[ManifestControl]] = defaultdict(list)
        for control in manifest.controls.controls:
            if control.target is not None:
                controls[control.target].append(control)
        children: dict[str, list[ManifestTool]] = defaultdict(list)
        for tool in manifest.tools.tools:
            if tool.parent_tool_id is not None:
                children[tool.parent_tool_id].append(tool)

        identities: dict[str, list[ManifestRuntimeIdentity]] = defaultdict(list)
        for tool in manifest.tools.tools:
            for identity in manifest.runtime_identities.identities:
                if identity.identity_id == f"identity:{tool.tool_id}" or (
                    _references_related(tool.sources, identity.sources)
                ):
                    identities[tool.tool_id].append(identity)

        relations: dict[ManifestRelationKind, list[ManifestRelation]] = defaultdict(
            list
        )
        for relation in manifest.relationships.relations:
            relations[relation.kind].append(relation)
        unknowns: dict[ManifestUnknownDimension, list[ManifestUnknown]] = defaultdict(
            list
        )
        for unknown in manifest.unknowns:
            unknowns[unknown.dimension].append(unknown)

        return cls(
            manifest=manifest,
            tools_by_id=MappingProxyType(dict(sorted(tools_by_id.items()))),
            permissions_by_target=_tuple_mapping(permissions, _permission_key),
            controls_by_target=_tuple_mapping(controls, _control_key),
            identities_by_tool=_tuple_mapping(identities, _identity_key),
            child_tools_by_parent=_tuple_mapping(children, _tool_key),
            relations_by_kind=_enum_tuple_mapping(relations, _relation_key),
            unknowns_by_dimension=_enum_tuple_mapping(unknowns, _unknown_key),
            sources_by_locator=MappingProxyType(
                {source.locator.sort_key(): source for source in manifest.sources}
            ),
        )

    def tool_family(self, target: str) -> str | None:
        """Return a stable parent MCP/tool family for target correlation."""

        tool = self.tools_by_id.get(target)
        if tool is None:
            return None
        return tool.parent_tool_id or tool.tool_id

    def effective_controls(self, target: str) -> tuple[ManifestControl, ...]:
        """Return target controls plus inherited parent-tool controls."""

        controls = list(self.controls_by_target.get(target, ()))
        tool = self.tools_by_id.get(target)
        if tool is not None and tool.parent_tool_id is not None:
            controls.extend(self.controls_by_target.get(tool.parent_tool_id, ()))
        by_id = {control.control_id: control for control in controls}
        return tuple(by_id[key] for key in sorted(by_id))

    def target_is_disabled(self, target: str) -> bool:
        """Return whether explicit tool or enablement state disables a target."""

        tool = self.tools_by_id.get(target)
        if tool is not None and tool.availability is ManifestToolAvailability.DISABLED:
            return True
        return any(
            control.kind is ManifestControlKind.ENABLEMENT
            and control.state is ManifestControlState.DISABLED
            for control in self.effective_controls(target)
        )

    def relevant_unknowns(
        self,
        target: str,
        permissions: tuple[ManifestPermission, ...],
    ) -> tuple[ManifestUnknown, ...]:
        """Return Unknown facts correlated to one target and its controls/identity."""

        needles = {target, *(permission.permission_id for permission in permissions)}
        needles.update(
            control.control_id for control in self.effective_controls(target)
        )
        needles.update(
            identity.identity_id for identity in self.identities_by_tool.get(target, ())
        )
        selected: dict[str, ManifestUnknown] = {}
        relevant_dimensions = {
            ManifestUnknownDimension.PERMISSIONS,
            ManifestUnknownDimension.CONTROLS,
        }
        if target in self.tools_by_id:
            relevant_dimensions.add(ManifestUnknownDimension.TOOLS)
        if target in self.identities_by_tool:
            relevant_dimensions.add(ManifestUnknownDimension.RUNTIME_IDENTITIES)
        for unknown in self.manifest.unknowns:
            if unknown.dimension is ManifestUnknownDimension.COVERAGE:
                selected[unknown.unknown_id] = unknown
                continue
            if unknown.dimension not in relevant_dimensions:
                continue
            if unknown.field is None:
                continue
            if unknown.field.endswith(".resolution") or any(
                needle in unknown.field for needle in needles
            ):
                selected[unknown.unknown_id] = unknown
        return tuple(selected[key] for key in sorted(selected))

    def evidence_for(
        self,
        references: tuple[ManifestSourceReference, ...],
    ) -> tuple[CapabilityEvidence, ...]:
        """Resolve portable source references to hash-backed evidence."""

        evidence: dict[
            tuple[str, str, str, str, int, int, str], CapabilityEvidence
        ] = {}
        for reference in references:
            source = self.sources_by_locator.get(reference.locator.sort_key())
            if source is None:
                raise CapabilityRuleContextError(
                    "Capability evidence source does not resolve in the Manifest."
                )
            item = CapabilityEvidence(
                scope=reference.locator.scope.value,
                root_id=reference.locator.root_id,
                path=reference.locator.path,
                field_path=reference.field_path,
                start_line=reference.start_line,
                end_line=reference.end_line,
                content_sha256=source.content_sha256,
            )
            evidence[item.sort_key()] = item
        return tuple(evidence[key] for key in sorted(evidence))


@dataclass(frozen=True, slots=True)
class CapabilityRuleCandidate:
    """Trusted deterministic Rule match before risk materialization."""

    correlation: CapabilityCorrelation
    related_ids: tuple[str, ...]
    evidence: tuple[ManifestSourceReference, ...] = dataclass_field(repr=False)
    likelihood_basis: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.correlation, CapabilityCorrelation):
            raise TypeError("Capability candidate correlation is invalid")
        if not isinstance(self.related_ids, tuple) or not self.related_ids:
            raise ValueError("Capability candidate requires related IDs")
        if any(_STABLE_ID_PATTERN.fullmatch(item) is None for item in self.related_ids):
            raise ValueError("Capability candidate contains an invalid related ID")
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError(
                "Capability candidate related IDs must be sorted and unique"
            )
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("Capability candidate requires source evidence")
        if any(not isinstance(item, ManifestSourceReference) for item in self.evidence):
            raise TypeError("Capability candidate contains invalid source evidence")
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("Capability candidate evidence must be sorted and unique")
        _require_text_tuple(self.likelihood_basis, "Capability likelihood basis")
        _require_text_tuple(self.limitations, "Capability limitations")

    def sort_key(
        self,
    ) -> tuple[
        str,
        tuple[str, ...],
        tuple[tuple[str, str, str, str, int, int], ...],
    ]:
        return (
            self.correlation.value,
            self.related_ids,
            tuple(reference.sort_key() for reference in self.evidence),
        )


@dataclass(frozen=True, slots=True)
class CapabilityRuleEvaluation:
    """Bounded deterministic output from one Capability Rule."""

    candidates: tuple[CapabilityRuleCandidate, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple) or any(
            not isinstance(item, CapabilityRuleCandidate) for item in self.candidates
        ):
            raise TypeError("Capability Rule candidates must be a typed tuple")
        if len(self.candidates) > _MAX_RULE_CANDIDATES:
            raise ValueError("Capability Rule candidate limit exceeded")
        keys = tuple(candidate.sort_key() for candidate in self.candidates)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Capability Rule candidates must be sorted and unique")


@runtime_checkable
class CapabilityRule(Protocol):
    """Pure deterministic Rule over one finalized Manifest context."""

    @property
    def metadata(self) -> CapabilityRuleMetadata:
        """Return trusted immutable Rule identity and policy."""

    def evaluate(self, context: CapabilityRuleContext) -> CapabilityRuleEvaluation:
        """Evaluate Manifest facts without filesystem, network, execution, or LLM."""


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """Value-free Manifest provenance retained by a Capability Finding."""

    scope: str
    root_id: str
    path: str
    field_path: str | None
    start_line: int | None
    end_line: int | None
    content_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.scope, "Capability evidence scope")
        _require_text(self.root_id, "Capability evidence root ID")
        _require_text(self.path, "Capability evidence path")
        if self.field_path is not None:
            _require_text(self.field_path, "Capability evidence field path")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("Capability evidence lines must be provided together")
        if self.start_line is not None and (
            self.start_line < 1
            or self.end_line is None
            or self.end_line < self.start_line
        ):
            raise ValueError("Capability evidence line range is invalid")
        if _SHA256_PATTERN.fullmatch(self.content_sha256) is None:
            raise ValueError("Capability evidence requires a SHA-256 digest")

    def sort_key(self) -> tuple[str, str, str, str, int, int, str]:
        return (
            self.scope,
            self.root_id,
            self.path,
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
            self.content_sha256,
        )


@dataclass(frozen=True, slots=True)
class CapabilityShadowGateMatch:
    """One matched shadow-mode Capability Gate condition (P2-15A-PILOT-02)."""

    gate_id: str
    floor: Literal["high", "critical"]
    correlation: CapabilityCorrelation
    related_ids: tuple[str, ...]
    rationale: tuple[str, ...]

    def __post_init__(self) -> None:
        if _GATE_ID_PATTERN.fullmatch(self.gate_id) is None:
            raise ValueError("Capability Shadow Gate ID is invalid")
        if self.floor not in ("high", "critical"):
            raise ValueError("Capability Shadow Gate floor is invalid")
        if not isinstance(self.correlation, CapabilityCorrelation):
            raise TypeError("Capability Shadow Gate correlation is invalid")
        if self.correlation not in _SHADOW_GATE_CORRELATIONS:
            raise ValueError("Capability Shadow Gate correlation is not Gate-eligible")
        if not self.related_ids:
            raise ValueError("Capability Shadow Gate requires related IDs")
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError("Capability Shadow Gate related IDs must be unique")
        _require_text_tuple(self.rationale, "Capability Shadow Gate rationale")


@dataclass(frozen=True, slots=True)
class CapabilityShadowGateAssessment:
    """Shadow-mode, pilot-only Gate evaluation attached to one Finding.

    A shadow Gate is never enforcement: ``mode`` is always ``shadow``,
    ``qualification`` is always ``pilot_only``, and ``blocks`` is always
    ``False``. It never sets ``hard_gate`` and never changes score, Severity,
    Confidence, or CLI exit behavior.
    """

    gate_version: str
    gate_id: str
    finding_id: str
    mode: Literal["shadow"]
    qualification: Literal["pilot_only"]
    matched: bool
    blocks: Literal[False]
    coverage_complete: bool
    relevant_unknowns: int
    match: CapabilityShadowGateMatch | None

    def __post_init__(self) -> None:
        if self.gate_version != CAPABILITY_SHADOW_GATE_VERSION:
            raise ValueError("Capability Shadow Gate version is unsupported")
        if _GATE_ID_PATTERN.fullmatch(self.gate_id) is None:
            raise ValueError("Capability Shadow Gate ID is invalid")
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise ValueError("Capability Shadow Gate Finding ID is invalid")
        if self.mode != "shadow":
            raise ValueError("Capability Shadow Gate mode must be shadow")
        if self.qualification != "pilot_only":
            raise ValueError("Capability Shadow Gate qualification must be pilot_only")
        if not isinstance(self.matched, bool) or not isinstance(
            self.coverage_complete, bool
        ):
            raise TypeError("Capability Shadow Gate flags must be bool")
        if self.blocks is not False:
            raise ValueError("Capability Shadow Gate must never block")
        if (
            isinstance(self.relevant_unknowns, bool)
            or not isinstance(self.relevant_unknowns, int)
            or self.relevant_unknowns < 0
        ):
            raise ValueError("Capability Shadow Gate Unknown count is invalid")
        if self.matched != (self.match is not None):
            raise ValueError("Capability Shadow Gate match state is inconsistent")
        if self.matched and (not self.coverage_complete or self.relevant_unknowns != 0):
            raise ValueError(
                "Capability Shadow Gate cannot match incomplete or Unknown evidence"
            )
        if self.match is not None:
            if not isinstance(self.match, CapabilityShadowGateMatch):
                raise TypeError("Capability Shadow Gate match is invalid")
            if self.match.gate_id != self.gate_id:
                raise ValueError("Capability Shadow Gate match ID is inconsistent")


@dataclass(frozen=True, slots=True)
class CapabilityRuleFinding:
    """Materialized report-only Finding from deterministic Manifest facts."""

    finding_id: str
    rule_id: str
    category: FindingCategory
    texts: tuple[CapabilityRuleText, ...]
    correlation: CapabilityCorrelation
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    risk_level: NistRiskLevel
    nist_semi_quantitative_value: int
    score: float
    severity: Severity
    confidence: EvidenceConfidence
    hard_gate: Literal[False]
    related_ids: tuple[str, ...]
    evidence: tuple[CapabilityEvidence, ...] = dataclass_field(repr=False)
    likelihood_basis: tuple[str, ...]
    impact_ratings: tuple[ImpactRating, ...]
    limitations: tuple[str, ...]
    mapping_basis: tuple[str, ...]
    capability_rule_pack_version: str
    capability_risk_model_version: str
    capability_shadow_gate: CapabilityShadowGateAssessment | None = None

    def __post_init__(self) -> None:
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise ValueError("Capability Finding ID is invalid")
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Capability Finding Rule ID is invalid")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Capability Finding category is invalid")
        if tuple(text.language for text in self.texts) != tuple(CapabilityRuleLanguage):
            raise ValueError("Capability Finding localized texts are incomplete")
        if not isinstance(self.correlation, CapabilityCorrelation):
            raise TypeError("Capability Finding correlation is invalid")
        if self.confidence is not confidence_for_correlation(self.correlation):
            raise ValueError("Capability Finding confidence is inconsistent")
        if self.likelihood is not likelihood_for_correlation(self.correlation):
            raise ValueError("Capability Finding likelihood is inconsistent")
        expected_impact = max(
            (rating.level for rating in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )
        if self.impact is not expected_impact:
            raise ValueError("Capability Finding impact is not the high-water mark")
        expected_level = nist_risk_level(self.likelihood, self.impact)
        if self.risk_level is not expected_level:
            raise ValueError("Capability Finding risk level is inconsistent")
        if self.nist_semi_quantitative_value != nist_semi_quantitative_value(
            expected_level
        ):
            raise ValueError("Capability Finding NIST value is inconsistent")
        if self.score != agentsec_base_score(expected_level):
            raise ValueError("Capability Finding score is inconsistent")
        if self.severity is not severity_for_score(self.score):
            raise ValueError("Capability Finding severity is inconsistent")
        if self.hard_gate is not False:
            raise ValueError("P2I-02 Capability Findings must remain report-only")
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError("Capability Finding related IDs must be sorted and unique")
        if not self.evidence:
            raise ValueError("Capability Finding requires evidence")
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("Capability Finding evidence must be sorted and unique")
        _require_text_tuple(self.likelihood_basis, "Capability likelihood basis")
        _require_text_tuple(self.limitations, "Capability limitations")
        if self.mapping_basis != CAPABILITY_RISK_MAPPING_BASIS:
            raise ValueError("Capability Finding mapping basis is inconsistent")
        if self.capability_rule_pack_version != CAPABILITY_RULE_PACK_VERSION:
            raise ValueError("Capability Finding Rule Pack version is unsupported")
        if self.capability_risk_model_version != CAPABILITY_RISK_MODEL_VERSION:
            raise ValueError("Capability Finding Risk Model version is unsupported")
        if self.capability_shadow_gate is not None:
            if not isinstance(
                self.capability_shadow_gate, CapabilityShadowGateAssessment
            ):
                raise TypeError("Capability Shadow Gate assessment is invalid")
            if self.capability_shadow_gate.finding_id != self.finding_id:
                raise ValueError("Capability Shadow Gate Finding binding is invalid")

    def attach_capability_shadow_gate(
        self, assessment: CapabilityShadowGateAssessment
    ) -> CapabilityRuleFinding:
        """Return a copy with one shadow-mode Gate evaluation attached."""
        if not isinstance(assessment, CapabilityShadowGateAssessment):
            raise TypeError("assessment must be CapabilityShadowGateAssessment")
        return dataclass_replace(self, capability_shadow_gate=assessment)

    def text_for(self, language: CapabilityRuleLanguage) -> CapabilityRuleText:
        """Return one trusted localized presentation."""

        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        return next(text for text in self.texts if text.language is language)

    def sort_key(self) -> tuple[str, tuple[str, ...], str]:
        return (self.rule_id, self.related_ids, self.finding_id)


class CapabilityRuleContextError(RuntimeError):
    """Safe invalid-context failure without Manifest source values."""


class CapabilityRuleContractError(ValueError):
    """Safe invalid Rule output failure without source values."""


def _references_related(
    left: tuple[ManifestSourceReference, ...],
    right: tuple[ManifestSourceReference, ...],
) -> bool:
    for first in left:
        for second in right:
            if first.locator.sort_key() != second.locator.sort_key():
                continue
            first_field = first.field_path or ""
            second_field = second.field_path or ""
            if not first_field or not second_field:
                return True
            if first_field.startswith(second_field) or second_field.startswith(
                first_field
            ):
                return True
    return False


def _tuple_mapping[T](
    values: Mapping[str, list[T]],
    key: Callable[[T], str],
) -> Mapping[str, tuple[T, ...]]:
    return MappingProxyType(
        {name: tuple(sorted(items, key=key)) for name, items in sorted(values.items())}
    )


def _enum_tuple_mapping[K, T](
    values: Mapping[K, list[T]],
    key: Callable[[T], str],
) -> Mapping[K, tuple[T, ...]]:
    return MappingProxyType(
        {
            name: tuple(sorted(items, key=key))
            for name, items in sorted(values.items(), key=lambda item: str(item[0]))
        }
    )


def _permission_key(permission: ManifestPermission) -> str:
    return permission.permission_id


def _control_key(control: ManifestControl) -> str:
    return control.control_id


def _identity_key(identity: ManifestRuntimeIdentity) -> str:
    return identity.identity_id


def _tool_key(tool: ManifestTool) -> str:
    return tool.tool_id


def _relation_key(relation: ManifestRelation) -> str:
    return relation.relation_id


def _unknown_key(unknown: ManifestUnknown) -> str:
    return unknown.unknown_id


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value.strip():
        raise ValueError(f"{label} must not be empty")


def _require_text_tuple(value: tuple[str, ...], label: str) -> None:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{label} must be a non-empty tuple")
    for item in value:
        _require_text(item, label)
    if len(set(value)) != len(value):
        raise ValueError(f"{label} values must be unique")

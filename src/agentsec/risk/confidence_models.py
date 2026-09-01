"""Immutable models and method policy for Evidence Confidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum

from agentsec.domain import EvidenceConfidence, FindingCategory
from agentsec.risk.models import ScoredFinding
from agentsec.versioning import RISK_MODEL_VERSION

_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")
_FIELD_PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9_:-]{0,63}$")

NIST_CONFIDENCE_BASIS = (
    "NIST SP 800-30 Rev. 1 assessment uncertainty and confidence communication"
)
AGENTSEC_CONFIDENCE_BASIS = (
    "AgentSec project plan section 6.7.6 A/B/C/D evidence-source policy"
)
CONFIDENCE_MAPPING_BASIS = (
    NIST_CONFIDENCE_BASIS,
    AGENTSEC_CONFIDENCE_BASIS,
)


class ConfidenceMethod(StrEnum):
    """Evidence-production methods with reviewed confidence strength."""

    RUNTIME_VERIFICATION = "runtime_verification"
    RED_TEAM_REPRODUCTION = "red_team_reproduction"
    ACTUAL_TOOL_ENUMERATION = "actual_tool_enumeration"
    SIGNED_ATTESTATION = "signed_attestation"
    EFFECTIVE_CONFIGURATION = "effective_configuration"
    DETERMINISTIC_STRUCTURED_RULE = "deterministic_structured_rule"
    TRACEABLE_SOURCE_CODE = "traceable_source_code"
    LLM_SEMANTIC_ANALYSIS = "llm_semantic_analysis"
    KEYWORD_MATCH = "keyword_match"
    BOUNDED_REGEX_MATCH = "bounded_regex_match"
    CONTEXTUAL_LEXICAL_MATCH = "contextual_lexical_match"
    PARSER_INDICATOR = "parser_indicator"
    STATIC_REFERENCE = "static_reference"
    PARTIAL_SCAN_INFERENCE = "partial_scan_inference"


_METHOD_CONFIDENCE = {
    ConfidenceMethod.RUNTIME_VERIFICATION: EvidenceConfidence.A,
    ConfidenceMethod.RED_TEAM_REPRODUCTION: EvidenceConfidence.A,
    ConfidenceMethod.ACTUAL_TOOL_ENUMERATION: EvidenceConfidence.A,
    ConfidenceMethod.SIGNED_ATTESTATION: EvidenceConfidence.A,
    ConfidenceMethod.EFFECTIVE_CONFIGURATION: EvidenceConfidence.B,
    ConfidenceMethod.DETERMINISTIC_STRUCTURED_RULE: EvidenceConfidence.B,
    ConfidenceMethod.TRACEABLE_SOURCE_CODE: EvidenceConfidence.B,
    ConfidenceMethod.LLM_SEMANTIC_ANALYSIS: EvidenceConfidence.C,
    ConfidenceMethod.KEYWORD_MATCH: EvidenceConfidence.D,
    ConfidenceMethod.BOUNDED_REGEX_MATCH: EvidenceConfidence.D,
    ConfidenceMethod.CONTEXTUAL_LEXICAL_MATCH: EvidenceConfidence.D,
    ConfidenceMethod.PARSER_INDICATOR: EvidenceConfidence.D,
    ConfidenceMethod.STATIC_REFERENCE: EvidenceConfidence.D,
    ConfidenceMethod.PARTIAL_SCAN_INFERENCE: EvidenceConfidence.D,
}


@dataclass(frozen=True, slots=True, order=True)
class ConfidenceFieldMethod:
    """Trusted Evidence field-prefix override for one confidence method."""

    field_prefix: str
    method: ConfidenceMethod

    def __post_init__(self) -> None:
        if not isinstance(self.field_prefix, str):
            raise TypeError("confidence field prefix must be text")
        if _FIELD_PREFIX_PATTERN.fullmatch(self.field_prefix) is None:
            raise ValueError("confidence field prefix is invalid")
        if not isinstance(self.method, ConfidenceMethod):
            raise TypeError("confidence field method must be ConfidenceMethod")


@dataclass(frozen=True, slots=True)
class ConfidenceProfile:
    """Reviewed Rule-specific source-strength profile."""

    rule_id: str
    category: FindingCategory
    level: EvidenceConfidence
    default_method: ConfidenceMethod
    rationale: tuple[str, ...]
    limitations: tuple[str, ...]
    field_methods: tuple[ConfidenceFieldMethod, ...] = ()

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("confidence profile Rule ID must use canonical format")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("confidence profile category must be FindingCategory")
        if not isinstance(self.level, EvidenceConfidence):
            raise TypeError("confidence profile level must be EvidenceConfidence")
        if not isinstance(self.default_method, ConfidenceMethod):
            raise TypeError("confidence default method must be ConfidenceMethod")
        _validate_method_level(self.default_method, self.level)
        _validate_text_tuple(self.rationale, "confidence rationale")
        _validate_text_tuple(self.limitations, "confidence limitation")
        if not isinstance(self.field_methods, tuple):
            raise TypeError("confidence field methods must be a tuple")
        if any(
            not isinstance(item, ConfidenceFieldMethod) for item in self.field_methods
        ):
            raise TypeError("confidence profile contains an invalid field method")
        ordered = tuple(sorted(self.field_methods))
        prefixes = tuple(item.field_prefix for item in ordered)
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("confidence field prefixes must be unique")
        for index, prefix in enumerate(prefixes):
            for other in prefixes[index + 1 :]:
                if other.startswith(prefix) or prefix.startswith(other):
                    raise ValueError("confidence field prefixes must not overlap")
        for item in ordered:
            _validate_method_level(item.method, self.level)
        object.__setattr__(self, "field_methods", ordered)

    def method_for_field(self, field: str | None) -> ConfidenceMethod:
        """Select a method using only trusted rule-produced Evidence metadata."""

        if field is not None:
            for override in self.field_methods:
                if field.startswith(override.field_prefix):
                    return override.method
        return self.default_method


@dataclass(frozen=True, slots=True)
class ConfidenceAssessment:
    """Traceable A/B/C/D confidence independent from score and Severity."""

    risk_model_version: str
    profile_rule_id: str
    level: EvidenceConfidence
    methods: tuple[ConfidenceMethod, ...]
    rationale: tuple[str, ...]
    limitations: tuple[str, ...]
    mapping_basis: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.risk_model_version != RISK_MODEL_VERSION:
            raise ValueError("confidence assessment version is not supported")
        if _RULE_ID_PATTERN.fullmatch(self.profile_rule_id) is None:
            raise ValueError("confidence assessment profile Rule ID is invalid")
        if not isinstance(self.level, EvidenceConfidence):
            raise TypeError("confidence assessment level must be EvidenceConfidence")
        if not isinstance(self.methods, tuple) or not self.methods:
            raise ValueError("confidence assessment requires methods")
        if any(not isinstance(item, ConfidenceMethod) for item in self.methods):
            raise TypeError("confidence assessment contains an invalid method")
        if self.methods != tuple(
            sorted(set(self.methods), key=lambda item: item.value)
        ):
            raise ValueError("confidence assessment methods must be sorted and unique")
        for method in self.methods:
            _validate_method_level(method, self.level)
        _validate_text_tuple(self.rationale, "confidence rationale")
        _validate_text_tuple(self.limitations, "confidence limitation")
        if self.mapping_basis != CONFIDENCE_MAPPING_BASIS:
            raise ValueError("confidence assessment mapping basis is inconsistent")


@dataclass(frozen=True, slots=True)
class ConfidenceFinding:
    """A scored Finding paired with confidence, before hard-gate policy."""

    scored: ScoredFinding = dataclass_field(repr=False)
    confidence: ConfidenceAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.scored, ScoredFinding):
            raise TypeError("confidence Finding requires a ScoredFinding")
        if not isinstance(self.confidence, ConfidenceAssessment):
            raise TypeError("confidence Finding requires a ConfidenceAssessment")
        if self.scored.unscored.rule_id != self.confidence.profile_rule_id:
            raise ValueError("confidence Finding Rule ID does not match profile")

    def _sort_key(self) -> tuple[str, str, int, str]:
        first = self.scored.unscored.evidence[0]
        return (
            self.scored.unscored.rule_id,
            first.asset_path or "",
            first.start_line or 0,
            self.scored.unscored.finding_id,
        )


def confidence_for_method(method: ConfidenceMethod) -> EvidenceConfidence:
    """Return the approved AgentSec A/B/C/D level for an evidence method."""

    if not isinstance(method, ConfidenceMethod):
        raise TypeError("confidence method must be ConfidenceMethod")
    return _METHOD_CONFIDENCE[method]


def _validate_method_level(
    method: ConfidenceMethod,
    level: EvidenceConfidence,
) -> None:
    if confidence_for_method(method) is not level:
        raise ValueError("confidence method does not match the declared level")


def _validate_text_tuple(value: tuple[str, ...], label: str) -> None:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{label} must be a non-empty tuple")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{label} must contain text")
        if not item.strip():
            raise ValueError(f"{label} must not contain empty text")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} values must be unique")

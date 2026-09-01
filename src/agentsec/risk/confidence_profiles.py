"""Reviewed Evidence Confidence profiles for the Phase 1 Markdown Rule Pack."""

from __future__ import annotations

from agentsec.domain import EvidenceConfidence, FindingCategory
from agentsec.risk.confidence_models import (
    ConfidenceFieldMethod,
    ConfidenceMethod,
    ConfidenceProfile,
)
from agentsec.rules.builtin import BUILTIN_MARKDOWN_RULE_IDS

_STATIC_LIMITATIONS = (
    "Phase 1 analyzes one or more local Markdown assets and does not resolve the "
    "complete effective Agent configuration.",
    "No runtime capability, actual tool inventory, permission grant, signed "
    "attestation, or dynamic reproduction is established by this evidence.",
)


def builtin_confidence_profiles() -> tuple[ConfidenceProfile, ...]:
    """Return one explicit D-level source profile for every production Rule ID."""

    profiles = (
        _lexical("MD-APPROVAL-001", FindingCategory.HUMAN_APPROVAL),
        _lexical("MD-DEPLOY-001", FindingCategory.DESTRUCTIVE_ACTION),
        _profile(
            "MD-DESTRUCT-001",
            FindingCategory.DESTRUCTIVE_ACTION,
            ConfidenceMethod.BOUNDED_REGEX_MATCH,
            "A reviewed bounded regular expression matched a destructive-action "
            "phrase in Markdown source.",
        ),
        _lexical("MD-EXEC-001", FindingCategory.CODE_EXECUTION),
        _profile(
            "MD-EXEC-002",
            FindingCategory.CODE_EXECUTION,
            ConfidenceMethod.BOUNDED_REGEX_MATCH,
            "A reviewed bounded regular expression matched a dynamic-execution "
            "phrase in Markdown source.",
        ),
        _lexical("MD-INSTR-001", FindingCategory.INSTRUCTION_INTEGRITY),
        _lexical("MD-INSTR-002", FindingCategory.INSTRUCTION_INTEGRITY),
        _lexical("MD-MEMORY-001", FindingCategory.PERSISTENT_MEMORY),
        _profile(
            "MD-NET-001",
            FindingCategory.NETWORK_ACCESS,
            ConfidenceMethod.CONTEXTUAL_LEXICAL_MATCH,
            "A reviewed lexical or bounded local-context condition matched an "
            "external-network declaration in Markdown source.",
        ),
        _profile(
            "MD-OBFUSC-001",
            FindingCategory.OBFUSCATION,
            ConfidenceMethod.PARSER_INDICATOR,
            "A deterministic parser indicator identified encoded, invisible, "
            "control, bidi, or confusable source content.",
        ),
        _lexical("MD-PRIV-001", FindingCategory.PRIVILEGED_ACCESS),
        _lexical("MD-PRIV-002", FindingCategory.PRIVILEGED_ACCESS),
        _lexical("MD-SECRET-001", FindingCategory.SECRET_ACCESS),
        _lexical("MD-SELF-001", FindingCategory.SELF_MODIFICATION),
        _profile(
            "MD-TOOL-001",
            FindingCategory.EXTERNAL_TOOLING,
            ConfidenceMethod.KEYWORD_MATCH,
            "A reviewed lexical condition matched external tooling in Markdown "
            "source, unless trusted Evidence metadata identifies a static reference.",
            field_methods=(
                ConfidenceFieldMethod(
                    field_prefix="reference:",
                    method=ConfidenceMethod.STATIC_REFERENCE,
                ),
            ),
        ),
    )
    ordered = tuple(sorted(profiles, key=lambda item: item.rule_id))
    if tuple(profile.rule_id for profile in ordered) != BUILTIN_MARKDOWN_RULE_IDS:
        raise RuntimeError("Built-in confidence profile identity is invalid.")
    return ordered


def _lexical(rule_id: str, category: FindingCategory) -> ConfidenceProfile:
    return _profile(
        rule_id,
        category,
        ConfidenceMethod.KEYWORD_MATCH,
        "A reviewed keyword condition matched a phrase in Markdown source.",
    )


def _profile(
    rule_id: str,
    category: FindingCategory,
    method: ConfidenceMethod,
    rationale: str,
    *,
    field_methods: tuple[ConfidenceFieldMethod, ...] = (),
) -> ConfidenceProfile:
    return ConfidenceProfile(
        rule_id=rule_id,
        category=category,
        level=EvidenceConfidence.D,
        default_method=method,
        rationale=(rationale,),
        limitations=_STATIC_LIMITATIONS,
        field_methods=field_methods,
    )

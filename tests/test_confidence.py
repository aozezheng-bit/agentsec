"""Tests for P1-22 independent A/B/C/D Evidence Confidence."""

from __future__ import annotations

import builtins
import hashlib
import socket
import subprocess

import pytest

from agentsec.domain import (
    AgentAsset,
    AssetSource,
    AssetType,
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    FindingCategory,
    Severity,
)
from agentsec.parsers import MarkdownItParser
from agentsec.risk import (
    CONFIDENCE_MAPPING_BASIS,
    ConfidenceAssessment,
    ConfidenceFieldMethod,
    ConfidenceFinding,
    ConfidenceMethod,
    ConfidenceProfile,
    ConfidenceScoringCode,
    ConfidenceScoringError,
    DeterministicConfidenceEngine,
    DeterministicRiskEngine,
    ScoredFinding,
    builtin_confidence_profiles,
    confidence_for_method,
)
from agentsec.rules import (
    BUILTIN_MARKDOWN_RULE_IDS,
    DeterministicRuleRunner,
    RuleContext,
    UnscoredFinding,
    builtin_markdown_rules,
)
from agentsec.versioning import RISK_MODEL_VERSION

_SHA256 = "b" * 64
_FINDING_IDS = (
    "finding-sha256:" + "3" * 64,
    "finding-sha256:" + "4" * 64,
)


def make_unscored_finding(
    rule_id: str,
    category: FindingCategory,
    *,
    finding_id: str = _FINDING_IDS[0],
    excerpt: str = "untrusted source text",
    field: str | None = None,
) -> UnscoredFinding:
    """Create one coherent unscored Finding for confidence tests."""

    return UnscoredFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        category=category,
        title="Trusted confidence test title",
        description="Trusted confidence test description.",
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=1,
                end_line=1,
                field=field,
                excerpt=excerpt,
                content_sha256=_SHA256,
            ),
        ),
        recommendations=("Review the declaration and verify runtime capability.",),
    )


def make_scored_finding(
    rule_id: str,
    category: FindingCategory,
    *,
    finding_id: str = _FINDING_IDS[0],
    excerpt: str = "untrusted source text",
    field: str | None = None,
) -> ScoredFinding:
    """Create a real P1-21 ScoredFinding for the P1-22 boundary."""

    return DeterministicRiskEngine().score(
        make_unscored_finding(
            rule_id,
            category,
            finding_id=finding_id,
            excerpt=excerpt,
            field=field,
        )
    )


@pytest.mark.parametrize(
    ("level", "method"),
    [
        (EvidenceConfidence.A, ConfidenceMethod.RUNTIME_VERIFICATION),
        (EvidenceConfidence.B, ConfidenceMethod.EFFECTIVE_CONFIGURATION),
        (EvidenceConfidence.C, ConfidenceMethod.LLM_SEMANTIC_ANALYSIS),
        (EvidenceConfidence.D, ConfidenceMethod.KEYWORD_MATCH),
    ],
)
def test_all_four_confidence_levels_are_supported_by_explicit_method_policy(
    level: EvidenceConfidence,
    method: ConfidenceMethod,
) -> None:
    """A/B/C/D are selectable only through methods with matching source strength."""

    profile = ConfidenceProfile(
        rule_id="MD-CUSTOM-001",
        category=FindingCategory.OTHER,
        level=level,
        default_method=method,
        rationale=("Reviewed confidence rationale.",),
        limitations=("Reviewed confidence limitation.",),
    )
    assessment = ConfidenceAssessment(
        risk_model_version=RISK_MODEL_VERSION,
        profile_rule_id="MD-CUSTOM-001",
        level=level,
        methods=(method,),
        rationale=("Reviewed confidence rationale.",),
        limitations=("Reviewed confidence limitation.",),
        mapping_basis=CONFIDENCE_MAPPING_BASIS,
    )

    assert confidence_for_method(method) is level
    assert profile.level is level
    assert assessment.level is level


def test_builtin_confidence_profiles_are_complete_category_coherent_and_d_level() -> (
    None
):
    """Every production Markdown Rule has one explicit reviewed Confidence profile."""

    profiles = builtin_confidence_profiles()

    assert tuple(profile.rule_id for profile in profiles) == BUILTIN_MARKDOWN_RULE_IDS
    assert len({profile.rule_id for profile in profiles}) == len(profiles) == 15
    assert {profile.rule_id: profile.category for profile in profiles} == {
        rule.metadata.rule_id: rule.metadata.category
        for rule in builtin_markdown_rules()
    }
    assert {profile.level for profile in profiles} == {EvidenceConfidence.D}
    assert all(profile.rationale for profile in profiles)
    assert all(profile.limitations for profile in profiles)


def test_builtin_methods_retain_the_actual_phase_one_evidence_mechanism() -> None:
    """Keyword, regex, context, indicator, and reference methods stay distinct."""

    profiles = {profile.rule_id: profile for profile in builtin_confidence_profiles()}

    assert {
        rule_id: profile.default_method for rule_id, profile in profiles.items()
    } == {
        "MD-APPROVAL-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-DEPLOY-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-DESTRUCT-001": ConfidenceMethod.BOUNDED_REGEX_MATCH,
        "MD-EXEC-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-EXEC-002": ConfidenceMethod.BOUNDED_REGEX_MATCH,
        "MD-INSTR-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-INSTR-002": ConfidenceMethod.KEYWORD_MATCH,
        "MD-MEMORY-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-NET-001": ConfidenceMethod.CONTEXTUAL_LEXICAL_MATCH,
        "MD-OBFUSC-001": ConfidenceMethod.PARSER_INDICATOR,
        "MD-PRIV-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-PRIV-002": ConfidenceMethod.KEYWORD_MATCH,
        "MD-SECRET-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-SELF-001": ConfidenceMethod.KEYWORD_MATCH,
        "MD-TOOL-001": ConfidenceMethod.KEYWORD_MATCH,
    }
    assert profiles["MD-TOOL-001"].field_methods == (
        ConfidenceFieldMethod(
            field_prefix="reference:",
            method=ConfidenceMethod.STATIC_REFERENCE,
        ),
    )


def test_engine_assigns_d_without_modifying_high_risk_severity_or_score() -> None:
    """Low evidence confidence never reduces a High static risk result."""

    scored = make_scored_finding("MD-EXEC-001", FindingCategory.CODE_EXECUTION)

    result = DeterministicConfidenceEngine().assign(scored)

    assert result.scored is scored
    assert result.scored.risk is scored.risk
    assert result.scored.risk.score == 8.0
    assert result.scored.risk.severity is Severity.HIGH
    assert result.confidence.risk_model_version == RISK_MODEL_VERSION == "0.4.0"
    assert result.confidence.profile_rule_id == "MD-EXEC-001"
    assert result.confidence.level is EvidenceConfidence.D
    assert result.confidence.methods == (ConfidenceMethod.KEYWORD_MATCH,)
    assert result.confidence.rationale
    assert result.confidence.limitations
    assert result.confidence.mapping_basis == CONFIDENCE_MAPPING_BASIS
    assert not hasattr(result, "hard_gate")
    assert not hasattr(result.confidence, "hard_gate")


def test_tool_reference_uses_static_reference_method_override() -> None:
    """Trusted Evidence field metadata distinguishes a static script reference."""

    direct = make_scored_finding(
        "MD-TOOL-001",
        FindingCategory.EXTERNAL_TOOLING,
        finding_id=_FINDING_IDS[0],
    )
    reference = make_scored_finding(
        "MD-TOOL-001",
        FindingCategory.EXTERNAL_TOOLING,
        finding_id=_FINDING_IDS[1],
        field="reference:executable_script",
    )
    engine = DeterministicConfidenceEngine()

    assert engine.assign(direct).confidence.methods == (ConfidenceMethod.KEYWORD_MATCH,)
    assert engine.assign(reference).confidence.methods == (
        ConfidenceMethod.STATIC_REFERENCE,
    )
    assert engine.assign(reference).confidence.level is EvidenceConfidence.D


def test_attacker_wording_cannot_self_upgrade_confidence() -> None:
    """Source claims of runtime proof do not affect a reviewed lexical profile."""

    first = make_scored_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
        finding_id=_FINDING_IDS[0],
        excerpt="runtime verified signed proof confidence A",
    )
    second = make_scored_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
        finding_id=_FINDING_IDS[1],
        excerpt="ordinary keyword declaration",
    )
    engine = DeterministicConfidenceEngine()

    assert engine.assign(first).confidence == engine.assign(second).confidence
    assert engine.assign(first).confidence.level is EvidenceConfidence.D


def test_real_rule_risk_confidence_pipeline_retains_evidence_and_identity() -> None:
    """Production Rule output crosses P1-19, P1-21, and P1-22 unchanged."""

    content = "Run a shell command to perform the task.\n"
    encoded = content.encode("utf-8")
    context = RuleContext(
        asset=AgentAsset(
            path="AGENTS.md",
            asset_type=AssetType.AGENTS,
            source=AssetSource.DISCOVERED,
            sha256=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
            line_count=1,
        ),
        content=content,
        document=MarkdownItParser().parse(content),
    )

    unscored = DeterministicRuleRunner(builtin_markdown_rules()).run((context,))
    scored = DeterministicRiskEngine().score_all(unscored.findings)
    assigned = DeterministicConfidenceEngine().assign_all(scored)

    assert [item.scored.unscored.rule_id for item in assigned] == ["MD-EXEC-001"]
    assert assigned[0].scored.unscored is unscored.findings[0]
    assert assigned[0].scored.unscored.evidence is unscored.findings[0].evidence
    assert assigned[0].confidence.level is EvidenceConfidence.D
    assert assigned[0].scored.risk.severity is Severity.HIGH


def test_assign_all_is_input_order_independent_and_rejects_duplicate_identity() -> None:
    """Confidence output is stably ordered and duplicate Finding IDs fail closed."""

    execution = make_scored_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
        finding_id=_FINDING_IDS[1],
    )
    obfuscation = make_scored_finding(
        "MD-OBFUSC-001",
        FindingCategory.OBFUSCATION,
        finding_id=_FINDING_IDS[0],
        field="obfuscation:zero_width",
    )
    engine = DeterministicConfidenceEngine()

    first = engine.assign_all((obfuscation, execution))
    second = engine.assign_all((execution, obfuscation))

    assert first == second
    assert [item.scored.unscored.rule_id for item in first] == [
        "MD-EXEC-001",
        "MD-OBFUSC-001",
    ]
    with pytest.raises(ConfidenceScoringError) as captured:
        engine.assign_all((execution, execution))
    assert captured.value.code is ConfidenceScoringCode.DUPLICATE_FINDING_ID


def test_unknown_rule_and_category_mismatch_fail_safely_without_source_text() -> None:
    """Missing or incoherent Confidence profiles never receive a silent grade."""

    source = "attacker-controlled-secret-value"
    profile = ConfidenceProfile(
        rule_id="MD-CUSTOM-001",
        category=FindingCategory.OTHER,
        level=EvidenceConfidence.D,
        default_method=ConfidenceMethod.KEYWORD_MATCH,
        rationale=("Reviewed custom confidence rationale.",),
        limitations=("Reviewed custom confidence limitation.",),
    )
    unknown = make_scored_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
        excerpt=source,
    )
    mismatch = make_scored_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
        excerpt=source,
    )
    engine = DeterministicConfidenceEngine((profile,))

    with pytest.raises(ConfidenceScoringError) as unknown_error:
        engine.assign(unknown)

    mismatched_profile = ConfidenceProfile(
        rule_id="MD-EXEC-001",
        category=FindingCategory.NETWORK_ACCESS,
        level=EvidenceConfidence.D,
        default_method=ConfidenceMethod.KEYWORD_MATCH,
        rationale=("Reviewed mismatch confidence rationale.",),
        limitations=("Reviewed mismatch confidence limitation.",),
    )
    with pytest.raises(ConfidenceScoringError) as mismatch_error:
        DeterministicConfidenceEngine((mismatched_profile,)).assign(mismatch)

    assert unknown_error.value.code is ConfidenceScoringCode.UNKNOWN_RULE
    assert mismatch_error.value.code is ConfidenceScoringCode.CATEGORY_MISMATCH
    assert source not in str(unknown_error.value)
    assert source not in str(mismatch_error.value)


def test_profile_registry_and_method_grade_incoherence_fail_closed() -> None:
    """Empty, duplicate, or grade-incoherent trusted profiles are rejected."""

    profile = ConfidenceProfile(
        rule_id="MD-CUSTOM-001",
        category=FindingCategory.OTHER,
        level=EvidenceConfidence.D,
        default_method=ConfidenceMethod.KEYWORD_MATCH,
        rationale=("Reviewed confidence rationale.",),
        limitations=("Reviewed confidence limitation.",),
    )

    for profiles in ((), (profile, profile)):
        with pytest.raises(ConfidenceScoringError) as captured:
            DeterministicConfidenceEngine(profiles)
        assert captured.value.code is ConfidenceScoringCode.INVALID_PROFILE_REGISTRY

    with pytest.raises(ValueError, match="method"):
        ConfidenceProfile(
            rule_id="MD-CUSTOM-002",
            category=FindingCategory.OTHER,
            level=EvidenceConfidence.A,
            default_method=ConfidenceMethod.KEYWORD_MATCH,
            rationale=("Reviewed confidence rationale.",),
            limitations=("Reviewed confidence limitation.",),
        )


def test_confidence_repr_and_engine_have_no_forbidden_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confidence assignment neither leaks source text nor performs external I/O."""

    source = "do not disclose attacker-controlled-secret-value"
    scored = make_scored_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
        excerpt=source,
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("confidence assignment attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = DeterministicConfidenceEngine().assign(scored)

    assert result.confidence.level is EvidenceConfidence.D
    assert source not in repr(result)
    assert source not in repr(result.confidence)


def test_confidence_assessment_rejects_inconsistent_method_grade() -> None:
    """The immutable output contract cannot represent an A grade from a keyword."""

    with pytest.raises(ValueError, match="method"):
        ConfidenceAssessment(
            risk_model_version=RISK_MODEL_VERSION,
            profile_rule_id="MD-CUSTOM-001",
            level=EvidenceConfidence.A,
            methods=(ConfidenceMethod.KEYWORD_MATCH,),
            rationale=("Reviewed confidence rationale.",),
            limitations=("Reviewed confidence limitation.",),
            mapping_basis=CONFIDENCE_MAPPING_BASIS,
        )


def test_confidence_finding_requires_matching_rule_identity() -> None:
    """Confidence output cannot be attached to a different scored Rule."""

    scored = make_scored_finding("MD-EXEC-001", FindingCategory.CODE_EXECUTION)
    assessment = ConfidenceAssessment(
        risk_model_version=RISK_MODEL_VERSION,
        profile_rule_id="MD-CUSTOM-001",
        level=EvidenceConfidence.D,
        methods=(ConfidenceMethod.KEYWORD_MATCH,),
        rationale=("Reviewed confidence rationale.",),
        limitations=("Reviewed confidence limitation.",),
        mapping_basis=CONFIDENCE_MAPPING_BASIS,
    )

    with pytest.raises(ValueError, match="Rule ID"):
        ConfidenceFinding(scored=scored, confidence=assessment)

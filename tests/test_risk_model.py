"""Tests for P1-21 NIST-style deterministic base risk scoring."""

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
    EvidenceSource,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.parsers import MarkdownItParser
from agentsec.risk import (
    AGENTSEC_SCORE_MAPPING_BASIS,
    IMPACT_AGGREGATION_BASIS,
    NIST_MATRIX_BASIS,
    SEVERITY_MAPPING_BASIS,
    DeterministicRiskEngine,
    ImpactDimension,
    ImpactRating,
    NistRiskLevel,
    RiskProfile,
    RiskScoringCode,
    RiskScoringError,
    builtin_risk_profiles,
    nist_risk_level,
    severity_for_score,
)
from agentsec.rules import (
    BUILTIN_MARKDOWN_RULE_IDS,
    DeterministicRuleRunner,
    RuleContext,
    UnscoredFinding,
    builtin_markdown_rules,
)
from agentsec.versioning import RISK_MODEL_VERSION

_SHA256 = "a" * 64
_FINDING_IDS = (
    "finding-sha256:" + "1" * 64,
    "finding-sha256:" + "2" * 64,
)


def make_finding(
    rule_id: str,
    category: FindingCategory,
    *,
    finding_id: str = _FINDING_IDS[0],
    excerpt: str = "untrusted secret-like source text",
) -> UnscoredFinding:
    """Create one coherent unscored Finding without invoking scanned content."""

    return UnscoredFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        category=category,
        title="Trusted test title",
        description="Trusted test description.",
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=1,
                end_line=1,
                excerpt=excerpt,
                content_sha256=_SHA256,
            ),
        ),
        recommendations=("Review the declaration.",),
    )


@pytest.mark.parametrize(
    ("likelihood", "expected"),
    [
        (
            LikelihoodLevel.VERY_HIGH,
            (
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.MODERATE,
                NistRiskLevel.HIGH,
                NistRiskLevel.VERY_HIGH,
            ),
        ),
        (
            LikelihoodLevel.HIGH,
            (
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.MODERATE,
                NistRiskLevel.HIGH,
                NistRiskLevel.VERY_HIGH,
            ),
        ),
        (
            LikelihoodLevel.MODERATE,
            (
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.MODERATE,
                NistRiskLevel.MODERATE,
                NistRiskLevel.HIGH,
            ),
        ),
        (
            LikelihoodLevel.LOW,
            (
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.LOW,
                NistRiskLevel.MODERATE,
            ),
        ),
        (
            LikelihoodLevel.VERY_LOW,
            (
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.VERY_LOW,
                NistRiskLevel.LOW,
            ),
        ),
    ],
)
def test_nist_matrix_reproduces_all_twenty_five_table_cells(
    likelihood: LikelihoodLevel,
    expected: tuple[NistRiskLevel, ...],
) -> None:
    """The explicit matrix matches NIST SP 800-30 Rev. 1 Table I-2."""

    impacts = (
        ImpactLevel.VERY_LOW,
        ImpactLevel.LOW,
        ImpactLevel.MODERATE,
        ImpactLevel.HIGH,
        ImpactLevel.VERY_HIGH,
    )

    assert tuple(nist_risk_level(likelihood, impact) for impact in impacts) == expected


@pytest.mark.parametrize(
    (
        "likelihood",
        "impact",
        "expected_level",
        "expected_nist_value",
        "expected_score",
        "expected_severity",
    ),
    [
        (
            LikelihoodLevel.VERY_LOW,
            ImpactLevel.VERY_LOW,
            NistRiskLevel.VERY_LOW,
            0,
            0.0,
            Severity.NONE,
        ),
        (
            LikelihoodLevel.LOW,
            ImpactLevel.LOW,
            NistRiskLevel.LOW,
            2,
            2.0,
            Severity.LOW,
        ),
        (
            LikelihoodLevel.MODERATE,
            ImpactLevel.MODERATE,
            NistRiskLevel.MODERATE,
            5,
            5.5,
            Severity.MEDIUM,
        ),
        (
            LikelihoodLevel.HIGH,
            ImpactLevel.HIGH,
            NistRiskLevel.HIGH,
            8,
            8.0,
            Severity.HIGH,
        ),
        (
            LikelihoodLevel.VERY_HIGH,
            ImpactLevel.VERY_HIGH,
            NistRiskLevel.VERY_HIGH,
            10,
            9.5,
            Severity.CRITICAL,
        ),
    ],
)
def test_all_five_matrix_levels_retain_nist_and_agentsec_numeric_mappings(
    likelihood: LikelihoodLevel,
    impact: ImpactLevel,
    expected_level: NistRiskLevel,
    expected_nist_value: int,
    expected_score: float,
    expected_severity: Severity,
) -> None:
    """NIST values and AgentSec 0-10 representatives remain distinguishable."""

    profile = RiskProfile(
        rule_id="MD-CUSTOM-001",
        category=FindingCategory.OTHER,
        likelihood=likelihood,
        likelihood_basis=("Reviewed test likelihood basis.",),
        impact_ratings=(
            ImpactRating(
                dimension=ImpactDimension.INTEGRITY,
                level=impact,
                rationale="Reviewed test impact basis.",
            ),
        ),
    )
    finding = make_finding("MD-CUSTOM-001", FindingCategory.OTHER)

    risk = DeterministicRiskEngine((profile,)).score(finding).risk

    assert risk.risk_level is expected_level
    assert risk.nist_semi_quantitative_value == expected_nist_value
    assert risk.score == expected_score
    assert risk.severity is expected_severity


def test_nist_matrix_is_monotonic_on_both_axes() -> None:
    """Increasing likelihood or impact never lowers the resulting risk level."""

    likelihoods = tuple(LikelihoodLevel)
    impacts = tuple(ImpactLevel)
    ordinals = {level: index for index, level in enumerate(NistRiskLevel, start=1)}

    for likelihood in likelihoods:
        row = [ordinals[nist_risk_level(likelihood, impact)] for impact in impacts]
        assert row == sorted(row)
    for impact in impacts:
        column = [
            ordinals[nist_risk_level(likelihood, impact)] for likelihood in likelihoods
        ]
        assert column == sorted(column)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.NONE),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_uses_cvss_v4_qualitative_ranges(
    score: float,
    expected: Severity,
) -> None:
    """Score boundaries remain compatible with the documented CVSS ranges."""

    assert severity_for_score(score) is expected


@pytest.mark.parametrize("invalid", [-0.1, 10.1, float("inf"), float("nan")])
def test_severity_rejects_out_of_range_or_non_finite_scores(invalid: float) -> None:
    """Malformed score inputs fail without being silently clamped."""

    with pytest.raises(ValueError, match="score"):
        severity_for_score(invalid)


def test_builtin_profiles_are_complete_explicit_and_category_coherent() -> None:
    """Every production Rule ID has one reviewed v0 profile and impact vector."""

    profiles = builtin_risk_profiles()

    assert tuple(profile.rule_id for profile in profiles) == BUILTIN_MARKDOWN_RULE_IDS
    assert len({profile.rule_id for profile in profiles}) == len(profiles) == 15
    assert {profile.rule_id: profile.category for profile in profiles} == {
        rule.metadata.rule_id: rule.metadata.category
        for rule in builtin_markdown_rules()
    }
    assert {
        profile.rule_id: (profile.likelihood, profile.impact) for profile in profiles
    } == {
        "MD-APPROVAL-001": (LikelihoodLevel.MODERATE, ImpactLevel.HIGH),
        "MD-DEPLOY-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-DESTRUCT-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-EXEC-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-EXEC-002": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-INSTR-001": (LikelihoodLevel.MODERATE, ImpactLevel.HIGH),
        "MD-INSTR-002": (LikelihoodLevel.MODERATE, ImpactLevel.HIGH),
        "MD-MEMORY-001": (LikelihoodLevel.LOW, ImpactLevel.HIGH),
        "MD-NET-001": (LikelihoodLevel.MODERATE, ImpactLevel.HIGH),
        "MD-OBFUSC-001": (LikelihoodLevel.LOW, ImpactLevel.MODERATE),
        "MD-PRIV-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-PRIV-002": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-SECRET-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-SELF-001": (LikelihoodLevel.MODERATE, ImpactLevel.VERY_HIGH),
        "MD-TOOL-001": (LikelihoodLevel.LOW, ImpactLevel.HIGH),
    }
    assert all(profile.likelihood_basis for profile in profiles)
    assert all(profile.impact_ratings for profile in profiles)
    assert all(profile.impact_basis for profile in profiles)
    assert all(
        tuple(rating.dimension.value for rating in profile.impact_ratings)
        == tuple(sorted(rating.dimension.value for rating in profile.impact_ratings))
        for profile in profiles
    )


def test_impact_uses_high_water_mark_instead_of_averaging() -> None:
    """One Very High impact dimension remains Very High despite lower dimensions."""

    profile = {item.rule_id: item for item in builtin_risk_profiles()}["MD-EXEC-001"]

    assert {rating.dimension for rating in profile.impact_ratings} >= {
        ImpactDimension.CONFIDENTIALITY,
        ImpactDimension.INTEGRITY,
        ImpactDimension.AVAILABILITY,
    }
    assert any(
        rating.level is ImpactLevel.VERY_HIGH for rating in profile.impact_ratings
    )
    assert profile.impact is ImpactLevel.VERY_HIGH


def test_builtin_rule_runner_output_flows_into_risk_engine() -> None:
    """A real production Rule result crosses the P1-19 to P1-21 boundary."""

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

    assert unscored.complete is True
    assert [item.unscored.rule_id for item in scored] == ["MD-EXEC-001"]
    assert scored[0].risk.score == 8.0
    assert scored[0].risk.severity is Severity.HIGH


def test_engine_scores_a_direct_execution_finding_with_full_traceability() -> None:
    """A direct static execution signal retains profile, matrix, and score basis."""

    finding = make_finding("MD-EXEC-001", FindingCategory.CODE_EXECUTION)

    scored = DeterministicRiskEngine().score(finding)
    risk = scored.risk

    assert scored.unscored is finding
    assert scored.unscored.finding_id == finding.finding_id
    assert scored.unscored.evidence is finding.evidence
    assert risk.risk_model_version == RISK_MODEL_VERSION == "0.4.0"
    assert risk.profile_rule_id == "MD-EXEC-001"
    assert risk.likelihood is LikelihoodLevel.MODERATE
    assert risk.impact is ImpactLevel.VERY_HIGH
    assert risk.likelihood_ordinal == 3
    assert risk.impact_ordinal == 5
    assert risk.risk_level is NistRiskLevel.HIGH
    assert risk.nist_semi_quantitative_value == 8
    assert risk.score == 8.0
    assert risk.severity is Severity.HIGH
    assert risk.likelihood_basis
    assert risk.impact_ratings
    assert risk.mapping_basis == (
        NIST_MATRIX_BASIS,
        IMPACT_AGGREGATION_BASIS,
        AGENTSEC_SCORE_MAPPING_BASIS,
        SEVERITY_MAPPING_BASIS,
    )
    assert not hasattr(risk, "confidence")
    assert not hasattr(risk, "hard_gate")
    assert not hasattr(scored, "confidence")
    assert not hasattr(scored, "hard_gate")


def test_rule_profiles_produce_expected_phase_one_representative_scores() -> None:
    """Direct, indirect, and high-impact profiles retain their reviewed meanings."""

    engine = DeterministicRiskEngine()
    cases = (
        (
            "MD-INSTR-001",
            FindingCategory.INSTRUCTION_INTEGRITY,
            NistRiskLevel.MODERATE,
            5.5,
            Severity.MEDIUM,
        ),
        (
            "MD-OBFUSC-001",
            FindingCategory.OBFUSCATION,
            NistRiskLevel.LOW,
            2.0,
            Severity.LOW,
        ),
        (
            "MD-PRIV-001",
            FindingCategory.PRIVILEGED_ACCESS,
            NistRiskLevel.HIGH,
            8.0,
            Severity.HIGH,
        ),
    )

    for index, (rule_id, category, level, score, severity) in enumerate(cases, start=1):
        finding = make_finding(
            rule_id,
            category,
            finding_id=f"finding-sha256:{index:064x}",
        )
        assessment = engine.score(finding).risk
        assert assessment.risk_level is level
        assert assessment.score == score
        assert assessment.severity is severity


def test_score_all_is_deterministic_input_order_independent_and_non_aggregating() -> (
    None
):
    """Findings are scored independently and returned in stable Rule/source order."""

    high = make_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
        finding_id=_FINDING_IDS[1],
    )
    low = make_finding(
        "MD-OBFUSC-001",
        FindingCategory.OBFUSCATION,
        finding_id=_FINDING_IDS[0],
    )
    engine = DeterministicRiskEngine()

    first = engine.score_all((low, high))
    second = engine.score_all((high, low))

    assert first == second
    assert [item.unscored.rule_id for item in first] == [
        "MD-EXEC-001",
        "MD-OBFUSC-001",
    ]
    assert [item.risk.score for item in first] == [8.0, 2.0]
    assert [item.risk.severity for item in first] == [Severity.HIGH, Severity.LOW]


def test_profile_registry_rejects_empty_or_duplicate_profiles() -> None:
    """An ambiguous or empty trusted profile registry fails before scoring."""

    profile = RiskProfile(
        rule_id="MD-CUSTOM-001",
        category=FindingCategory.OTHER,
        likelihood=LikelihoodLevel.LOW,
        likelihood_basis=("Reviewed test likelihood basis.",),
        impact_ratings=(
            ImpactRating(
                dimension=ImpactDimension.INTEGRITY,
                level=ImpactLevel.LOW,
                rationale="Reviewed test impact basis.",
            ),
        ),
    )

    for profiles in ((), (profile, profile)):
        with pytest.raises(RiskScoringError) as captured:
            DeterministicRiskEngine(profiles)
        assert captured.value.code is RiskScoringCode.INVALID_PROFILE_REGISTRY


def test_score_all_rejects_duplicate_finding_identity() -> None:
    """Duplicate input cannot create ambiguous repeated risk output."""

    finding = make_finding("MD-EXEC-001", FindingCategory.CODE_EXECUTION)

    with pytest.raises(RiskScoringError) as captured:
        DeterministicRiskEngine().score_all((finding, finding))

    assert captured.value.code is RiskScoringCode.DUPLICATE_FINDING_ID


def test_unknown_rule_and_category_mismatch_fail_closed_without_source_text() -> None:
    """Unreviewed or incoherent profiles never receive a silent fallback score."""

    source = "attacker-controlled-token-value"
    unknown = make_finding(
        "MD-CUSTOM-001",
        FindingCategory.OTHER,
        excerpt=source,
    )
    mismatch = make_finding(
        "MD-EXEC-001",
        FindingCategory.NETWORK_ACCESS,
        excerpt=source,
    )
    engine = DeterministicRiskEngine()

    with pytest.raises(RiskScoringError) as unknown_error:
        engine.score(unknown)
    with pytest.raises(RiskScoringError) as mismatch_error:
        engine.score(mismatch)

    assert unknown_error.value.code is RiskScoringCode.UNKNOWN_RULE
    assert mismatch_error.value.code is RiskScoringCode.CATEGORY_MISMATCH
    assert source not in str(unknown_error.value)
    assert source not in str(mismatch_error.value)


def test_scoring_repr_and_execution_do_not_disclose_or_execute_scanned_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Risk scoring remains data-only with no file, shell, import, or network I/O."""

    source = "do not disclose attacker-controlled-secret-value"
    finding = make_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
        excerpt=source,
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("risk scoring attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    scored = DeterministicRiskEngine().score(finding)

    assert scored.risk.severity is Severity.HIGH
    assert source not in repr(scored)
    assert source not in repr(scored.risk)

"""Tests for P1-23 report-only, non-dilutable Hard Gate metadata."""

from __future__ import annotations

import builtins
import socket
import subprocess

import pytest

from agentsec.domain import (
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    Finding,
    FindingCategory,
    Severity,
)
from agentsec.risk import (
    HARD_GATE_MAPPING_BASIS,
    ConfidenceFinding,
    DeterministicConfidenceEngine,
    DeterministicHardGateEngine,
    DeterministicRiskEngine,
    GatedFinding,
    GateEnforcementMode,
    HardGateAssessment,
    HardGateCode,
    HardGateError,
    HardGateFloor,
    HardGateMatch,
    hard_gate_floor_score,
)
from agentsec.rules import UnscoredFinding
from agentsec.versioning import RISK_MODEL_VERSION

_SHA256 = "c" * 64
_FINDING_IDS = (
    "finding-sha256:" + "5" * 64,
    "finding-sha256:" + "6" * 64,
)


def make_confidence_finding(
    rule_id: str,
    category: FindingCategory,
    *,
    finding_id: str = _FINDING_IDS[0],
    excerpt: str = "untrusted gate source text",
) -> ConfidenceFinding:
    """Create a real P1-19 → P1-22 Finding for Hard Gate tests."""

    unscored = UnscoredFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        category=category,
        title="Trusted hard-gate test title",
        description="Trusted hard-gate test description.",
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
        recommendations=("Review and verify the declared capability.",),
    )
    scored = DeterministicRiskEngine().score(unscored)
    return DeterministicConfidenceEngine().assign(scored)


def make_match(
    finding: ConfidenceFinding,
    *,
    gate_id: str = "HG-TEST-001",
    floor: HardGateFloor = HardGateFloor.HIGH,
    rule_ids: tuple[str, ...] | None = None,
) -> HardGateMatch:
    """Create trusted report-only gate metadata for one Finding."""

    return HardGateMatch(
        finding_id=finding.scored.unscored.finding_id,
        gate_id=gate_id,
        floor=floor,
        rule_ids=rule_ids or (finding.scored.unscored.rule_id,),
        rationale=("Reviewed deterministic gate condition matched.",),
    )


def test_default_phase_one_gate_is_report_only_and_not_triggered() -> None:
    """No production match means no floor, no hard_gate flag, and no blocking."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )

    result = DeterministicHardGateEngine().apply(finding)

    assert result.confidence_finding is finding
    assert result.gate.risk_model_version == RISK_MODEL_VERSION == "0.4.0"
    assert result.gate.mode is GateEnforcementMode.REPORT_ONLY
    assert result.gate.matches == ()
    assert result.gate.triggered is False
    assert result.gate.floor is None
    assert result.gate.floor_score is None
    assert result.gate.effective_score == 8.0
    assert result.gate.effective_severity is Severity.HIGH
    assert result.gate.blocks is False
    domain = result.to_domain_finding()
    assert domain.hard_gate is False
    assert domain.score == 8.0
    assert domain.severity is Severity.HIGH


def test_high_floor_raises_medium_result_without_enabling_ci_blocking() -> None:
    """A report-only High gate applies a minimum score while blocks remains false."""

    finding = make_confidence_finding(
        "MD-INSTR-001",
        FindingCategory.INSTRUCTION_INTEGRITY,
    )
    match = make_match(finding, floor=HardGateFloor.HIGH)

    result = DeterministicHardGateEngine().apply(finding, matches=(match,))

    assert finding.scored.risk.score == 5.5
    assert finding.scored.risk.severity is Severity.MEDIUM
    assert finding.confidence.level is EvidenceConfidence.D
    assert result.gate.triggered is True
    assert result.gate.floor is HardGateFloor.HIGH
    assert result.gate.floor_score == 7.0
    assert result.gate.effective_score == 7.0
    assert result.gate.effective_severity is Severity.HIGH
    assert result.gate.blocks is False
    assert result.to_domain_finding().hard_gate is True


def test_critical_floor_raises_high_result_and_confidence_cannot_disable_it() -> None:
    """D Confidence neither lowers nor disables a deterministic Critical floor."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )
    match = make_match(finding, floor=HardGateFloor.CRITICAL)

    result = DeterministicHardGateEngine().apply(finding, matches=(match,))

    assert finding.confidence.level is EvidenceConfidence.D
    assert result.gate.floor_score == 9.0
    assert result.gate.effective_score == 9.0
    assert result.gate.effective_severity is Severity.CRITICAL
    assert result.gate.blocks is False
    domain = result.to_domain_finding()
    assert domain.confidence is EvidenceConfidence.D
    assert domain.hard_gate is True
    assert domain.score == 9.0
    assert domain.severity is Severity.CRITICAL


def test_gate_floor_never_lowers_a_higher_base_score() -> None:
    """Hard Gate uses max(base, floor), never replacement or averaging."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )
    match = make_match(finding, floor=HardGateFloor.HIGH)

    result = DeterministicHardGateEngine().apply(finding, matches=(match,))

    assert result.gate.floor_score == 7.0
    assert result.gate.effective_score == 8.0
    assert result.gate.effective_severity is Severity.HIGH


def test_multiple_matches_use_the_highest_floor_independent_of_input_order() -> None:
    """A Critical match cannot be diluted by a simultaneous High match."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )
    high = make_match(
        finding,
        gate_id="HG-TEST-001",
        floor=HardGateFloor.HIGH,
    )
    critical = make_match(
        finding,
        gate_id="HG-TEST-002",
        floor=HardGateFloor.CRITICAL,
    )
    engine = DeterministicHardGateEngine()

    first = engine.apply(finding, matches=(high, critical))
    second = engine.apply(finding, matches=(critical, high))

    assert first == second
    assert first.gate.floor is HardGateFloor.CRITICAL
    assert first.gate.effective_severity is Severity.CRITICAL
    assert [item.gate_id for item in first.gate.matches] == [
        "HG-TEST-001",
        "HG-TEST-002",
    ]


@pytest.mark.parametrize(
    ("floor", "score", "severity"),
    [
        (HardGateFloor.HIGH, 7.0, Severity.HIGH),
        (HardGateFloor.CRITICAL, 9.0, Severity.CRITICAL),
    ],
)
def test_floor_mapping_uses_severity_threshold_minimums(
    floor: HardGateFloor,
    score: float,
    severity: Severity,
) -> None:
    """High and Critical floors use their minimum CVSS-compatible score bounds."""

    assert hard_gate_floor_score(floor) == score
    finding = make_confidence_finding(
        "MD-INSTR-001",
        FindingCategory.INSTRUCTION_INTEGRITY,
    )
    assessment = HardGateAssessment(
        risk_model_version=RISK_MODEL_VERSION,
        finding_id=finding.scored.unscored.finding_id,
        mode=GateEnforcementMode.REPORT_ONLY,
        base_score=finding.scored.risk.score,
        base_severity=finding.scored.risk.severity,
        matches=(make_match(finding, floor=floor),),
        mapping_basis=HARD_GATE_MAPPING_BASIS,
    )

    assert assessment.floor is floor
    assert assessment.floor_score == score
    assert assessment.effective_severity is severity


def test_final_domain_finding_preserves_identity_evidence_and_confidence() -> None:
    """P1-23 can now assemble the existing final Domain Finding contract."""

    finding = make_confidence_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
    )
    gated = DeterministicHardGateEngine().apply(finding)

    domain = gated.to_domain_finding()

    assert isinstance(domain, Finding)
    assert domain.finding_id == finding.scored.unscored.finding_id
    assert domain.rule_id == finding.scored.unscored.rule_id
    assert domain.category is finding.scored.unscored.category
    assert domain.likelihood is finding.scored.risk.likelihood
    assert domain.impact is finding.scored.risk.impact
    assert domain.score == finding.scored.risk.score
    assert domain.severity is finding.scored.risk.severity
    assert domain.confidence is finding.confidence.level
    assert domain.hard_gate is False
    assert domain.evidence == finding.scored.unscored.evidence
    assert domain.recommendations == finding.scored.unscored.recommendations


def test_apply_all_is_order_independent_and_rejects_unknown_match_target() -> None:
    """Finding and Match order cannot alter output; orphan gate metadata fails."""

    execution = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
        finding_id=_FINDING_IDS[1],
    )
    instruction = make_confidence_finding(
        "MD-INSTR-001",
        FindingCategory.INSTRUCTION_INTEGRITY,
        finding_id=_FINDING_IDS[0],
    )
    match = make_match(instruction, floor=HardGateFloor.HIGH)
    engine = DeterministicHardGateEngine()

    first = engine.apply_all((instruction, execution), matches=(match,))
    second = engine.apply_all((execution, instruction), matches=(match,))

    assert first == second
    assert [item.confidence_finding.scored.unscored.rule_id for item in first] == [
        "MD-EXEC-001",
        "MD-INSTR-001",
    ]

    orphan = HardGateMatch(
        finding_id="finding-sha256:" + "9" * 64,
        gate_id="HG-TEST-002",
        floor=HardGateFloor.HIGH,
        rule_ids=("MD-INSTR-001",),
        rationale=("Reviewed orphan test match.",),
    )
    with pytest.raises(HardGateError) as captured:
        engine.apply_all((instruction, execution), matches=(orphan,))
    assert captured.value.code is HardGateCode.UNKNOWN_FINDING_ID


def test_duplicate_gate_id_and_source_rule_mismatch_fail_closed() -> None:
    """Ambiguous or incorrectly bound trusted gate metadata is rejected."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )
    duplicate = make_match(finding)
    wrong_rule = make_match(
        finding,
        gate_id="HG-TEST-002",
        rule_ids=("MD-NET-001",),
    )
    engine = DeterministicHardGateEngine()

    with pytest.raises(HardGateError) as duplicate_error:
        engine.apply(finding, matches=(duplicate, duplicate))
    with pytest.raises(HardGateError) as rule_error:
        engine.apply(finding, matches=(wrong_rule,))

    assert duplicate_error.value.code is HardGateCode.DUPLICATE_GATE_ID
    assert rule_error.value.code is HardGateCode.SOURCE_RULE_MISMATCH


def test_apply_all_rejects_duplicate_finding_identity() -> None:
    """Duplicate confidence Findings cannot produce ambiguous final output."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )

    with pytest.raises(HardGateError) as captured:
        DeterministicHardGateEngine().apply_all((finding, finding))

    assert captured.value.code is HardGateCode.DUPLICATE_FINDING_ID


def test_hard_gate_match_validates_stable_identity_and_source_ids() -> None:
    """Gate IDs and supporting Rule IDs remain stable, sorted, and unique."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )

    with pytest.raises(ValueError, match="gate ID"):
        HardGateMatch(
            finding_id=finding.scored.unscored.finding_id,
            gate_id="invalid",
            floor=HardGateFloor.HIGH,
            rule_ids=("MD-EXEC-001",),
            rationale=("Reviewed rationale.",),
        )
    with pytest.raises(ValueError, match="Rule IDs"):
        HardGateMatch(
            finding_id=finding.scored.unscored.finding_id,
            gate_id="HG-TEST-001",
            floor=HardGateFloor.HIGH,
            rule_ids=("MD-NET-001", "MD-EXEC-001"),
            rationale=("Reviewed rationale.",),
        )


def test_gated_finding_rejects_assessment_for_another_finding() -> None:
    """Hard Gate metadata cannot be attached to a different Finding identity."""

    finding = make_confidence_finding(
        "MD-EXEC-001",
        FindingCategory.CODE_EXECUTION,
    )
    assessment = HardGateAssessment(
        risk_model_version=RISK_MODEL_VERSION,
        finding_id=_FINDING_IDS[1],
        mode=GateEnforcementMode.REPORT_ONLY,
        base_score=finding.scored.risk.score,
        base_severity=finding.scored.risk.severity,
        matches=(),
        mapping_basis=HARD_GATE_MAPPING_BASIS,
    )

    with pytest.raises(ValueError, match="Finding ID"):
        GatedFinding(confidence_finding=finding, gate=assessment)


def test_gate_repr_and_engine_have_no_forbidden_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Gate metadata neither leaks source text nor performs external I/O."""

    source = "do not disclose attacker-controlled-gate-secret"
    finding = make_confidence_finding(
        "MD-SECRET-001",
        FindingCategory.SECRET_ACCESS,
        excerpt=source,
    )
    match = make_match(finding, floor=HardGateFloor.CRITICAL)

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Hard Gate processing attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = DeterministicHardGateEngine().apply(finding, matches=(match,))

    assert result.gate.triggered is True
    assert result.gate.blocks is False
    assert source not in repr(result)
    assert source not in repr(result.gate)

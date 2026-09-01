"""P3-18 Semantic Gate definition and report-only qualification tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec.semantic import (
    EvidenceConfidenceGrade,
    GoldLabelProvenance,
    ProviderPromotionReport,
    ProviderPromotionState,
    ProviderQualityThresholds,
    QualityGateReport,
    QualityGateStatus,
    SemanticGateCandidate,
    SemanticGateEvidenceConfidence,
    SemanticGateInput,
    SemanticGateQualificationRunner,
    SemanticGateQualificationStatus,
    SemanticGateThresholds,
    build_semantic_gate_candidate,
)

ROOT = Path(__file__).resolve().parents[1]


def _candidate(
    *, required_inputs: tuple[SemanticGateInput, ...] | None = None
) -> SemanticGateCandidate:
    return build_semantic_gate_candidate(
        gate_id="SG-INSTRUCTION-INTEGRITY-001",
        title="Instruction integrity",
        description="Detect semantic instruction integrity risks.",
        signal="instruction_integrity",
        thresholds=SemanticGateThresholds(),
        required_inputs=required_inputs,
    )


def _quality(*, qualified: bool = True) -> QualityGateReport:
    return QualityGateReport(
        reviewer_id="reviewer-a",
        label_provenance=GoldLabelProvenance.HUMAN_AUTHORED,
        provider_id="offline-fixture",
        model_id="agentsec-semantic-fixture-v1",
        status=(
            QualityGateStatus.QUALIFIED
            if qualified
            else QualityGateStatus.NOT_QUALIFIED
        ),
        thresholds=ProviderQualityThresholds(),
        metrics={
            "case_count": 45.0,
            "completed": 45.0,
            "failed": 0.0,
            "precision": 1.0 if qualified else 0.5,
            "recall": 1.0 if qualified else 0.5,
            "f1": 1.0 if qualified else 0.5,
            "evidence_binding_accuracy": 1.0 if qualified else 0.5,
            "complete_coverage_rate": 1.0 if qualified else 0.5,
        },
        failed_checks=() if qualified else ("quality_metrics",),
        reasons=() if qualified else ("quality_threshold_not_met",),
    )


def _promotion(*, approved: bool = True) -> ProviderPromotionReport:
    return ProviderPromotionReport(
        provider_id="offline-fixture",
        model_id="agentsec-semantic-fixture-v1",
        evaluation_report_sha256="0" * 64,
        state=(
            ProviderPromotionState.APPROVED_SHADOW
            if approved
            else ProviderPromotionState.ELIGIBLE_SHADOW
        ),
        quality_passed=True,
        human_review_passed=True,
        adjudication_required=False,
        blocking_reasons=(),
        thresholds=ProviderQualityThresholds(),
    )


def _confidence() -> SemanticGateEvidenceConfidence:
    return SemanticGateEvidenceConfidence(
        grade=EvidenceConfidenceGrade.C,
        reviewer_count=1,
        reviewed_case_count=45,
        adjudication_complete=True,
        rationale_code="joint_expert_review",
    )


def test_gate_candidate_is_digest_bound_and_sorted() -> None:
    candidate = _candidate()

    assert candidate.candidate_id.startswith("semantic-gate-candidate-sha256:")
    assert candidate.required_inputs == (
        SemanticGateInput.HUMAN_CONFIDENCE,
        SemanticGateInput.PROVIDER_PROMOTION,
        SemanticGateInput.PROVIDER_QUALITY,
    )
    assert candidate.authority.can_block_ci is False
    assert candidate.authority.can_publish_rule is False


def test_gate_qualification_passes_report_only_with_p3_05_evidence() -> None:
    report = SemanticGateQualificationRunner().qualify(
        _candidate(),
        quality_report=_quality(),
        provider_promotion=_promotion(),
        evidence_confidence=_confidence(),
        positive_case_count=20,
        eligible_negative_case_count=20,
    )

    assert report.status is SemanticGateQualificationStatus.QUALIFIED
    assert report.eligible_for_report_only_gate is True
    assert report.failed_checks == ()
    assert report.pending_checks == ()
    assert report.authority.blocks is False
    assert report.authority.can_block_ci is False
    assert report.authority.can_publish_rule is False


def test_gate_qualification_is_conditional_when_required_evidence_is_missing() -> None:
    report = SemanticGateQualificationRunner().qualify(
        _candidate(),
        quality_report=_quality(),
        positive_case_count=20,
        eligible_negative_case_count=20,
    )

    assert report.status is SemanticGateQualificationStatus.CONDITIONALLY_QUALIFIED
    assert report.eligible_for_report_only_gate is False
    assert report.failed_checks == ()
    assert report.pending_checks == ("human_confidence", "provider_promotion")


def test_gate_qualification_fails_on_quality_or_promotion_failure() -> None:
    report = SemanticGateQualificationRunner().qualify(
        _candidate(),
        quality_report=_quality(qualified=False),
        provider_promotion=_promotion(approved=False),
        evidence_confidence=_confidence(),
        positive_case_count=20,
        eligible_negative_case_count=20,
    )

    assert report.status is SemanticGateQualificationStatus.NOT_QUALIFIED
    assert report.eligible_for_report_only_gate is False
    assert "provider_quality" in report.failed_checks
    assert "provider_promotion" in report.failed_checks


def test_gate_qualification_supports_p3_07_and_p3_10_input_requirements() -> None:
    required = (
        SemanticGateInput.CANDIDATE_CALIBRATION,
        SemanticGateInput.FINDING_PROMOTION,
        SemanticGateInput.HUMAN_CONFIDENCE,
        SemanticGateInput.PROVIDER_PROMOTION,
        SemanticGateInput.PROVIDER_QUALITY,
        SemanticGateInput.RULE_STAGING,
    )
    report = SemanticGateQualificationRunner().qualify(
        _candidate(required_inputs=required),
        quality_report=_quality(),
        provider_promotion=_promotion(),
        evidence_confidence=_confidence(),
        positive_case_count=20,
        eligible_negative_case_count=20,
    )

    assert report.status is SemanticGateQualificationStatus.CONDITIONALLY_QUALIFIED
    assert report.pending_checks == (
        "candidate_calibration",
        "finding_promotion",
        "rule_staging",
    )


def test_confidence_a_requires_runtime_attestation() -> None:
    with pytest.raises(ValueError, match="runtime attestation"):
        SemanticGateEvidenceConfidence(
            grade=EvidenceConfidenceGrade.A,
            reviewer_count=1,
            reviewed_case_count=1,
            adjudication_complete=True,
            rationale_code="runtime_proof",
        )


def test_semantic_gate_cli_creates_candidate_and_qualification_report(
    tmp_path: Path,
) -> None:
    candidate_path = tmp_path / "candidate.json"
    quality_path = tmp_path / "quality.json"
    promotion_path = tmp_path / "promotion.json"
    confidence_path = tmp_path / "confidence.json"
    output_path = tmp_path / "qualification.json"

    candidate_result = subprocess.run(
        [
            sys.executable,
            "scripts/create-semantic-gate-candidate.py",
            "--gate-id",
            "SG-INSTRUCTION-INTEGRITY-001",
            "--title",
            "Instruction integrity",
            "--description",
            "Detect semantic instruction integrity risks.",
            "--signal",
            "instruction_integrity",
            "--output",
            str(candidate_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert candidate_result.returncode == 0, candidate_result.stderr
    quality_path.write_text(_quality().model_dump_json(indent=2), encoding="utf-8")
    promotion_path.write_text(_promotion().model_dump_json(indent=2), encoding="utf-8")
    confidence_path.write_text(
        _confidence().model_dump_json(indent=2), encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run-semantic-gate-qualification.py",
            "--candidate",
            str(candidate_path),
            "--quality-report",
            str(quality_path),
            "--provider-promotion",
            str(promotion_path),
            "--evidence-confidence",
            str(confidence_path),
            "--positive-cases",
            "20",
            "--eligible-negative-cases",
            "20",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "qualified"
    assert payload["eligible_for_report_only_gate"] is True

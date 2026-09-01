"""P3-20 Provider Evaluation import and Semantic Gate qualification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.semantic import (
    EvidenceConfidenceGrade,
    ProviderPromotionReport,
    ProviderPromotionState,
    ProviderQualityThresholds,
    SemanticEvaluationCaseResult,
    SemanticEvaluationCaseStatus,
    SemanticEvaluationMetrics,
    SemanticEvaluationReport,
    SemanticGateCandidate,
    SemanticGateCaseClass,
    SemanticGateCorpusProvenance,
    SemanticGateCorpusReviewer,
    SemanticGateEvidenceConfidence,
    SemanticGateHumanCase,
    SemanticGateHumanCorpus,
    SemanticGateInput,
    SemanticGateQualificationStatus,
    SemanticGateReportOnlyPromotion,
    SemanticGateThresholds,
    build_semantic_evidence_chunk,
    build_semantic_gate_candidate,
    build_semantic_gate_evaluation_import,
    build_semantic_gate_human_corpus,
    promote_report_only,
    qualify_semantic_gate_evaluation,
)


def _case(case_id: str, case_class: SemanticGateCaseClass) -> SemanticGateHumanCase:
    text = f"reviewed semantic evidence {case_id}"
    asset_sha256 = "a" * 64
    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=asset_sha256,
        start_line=1,
        end_line=1,
        text=text,
    )
    return SemanticGateHumanCase(
        case_id=case_id,
        gate_id="SG-TEST-001",
        signal="instruction_integrity",
        language="en",
        case_class=case_class,
        expected_gate_match=case_class is SemanticGateCaseClass.POSITIVE,
        evidence_id=chunk.evidence_id,
        asset_path=chunk.asset_path,
        asset_sha256=chunk.asset_sha256,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        sanitized_text=chunk.text,
        text_sha256=chunk.text_sha256,
        source_kind="human_review",
        source_label="bounded test evidence",
        reviewer_id="reviewer-a",
        review_provenance=SemanticGateCorpusProvenance.HUMAN_AUTHORED,
        confidence_grade="C",
        confidence_rationale="static evidence reviewed by an expert",
    )


def _corpus() -> SemanticGateHumanCorpus:
    cases = tuple(
        _case(f"case-{index:02d}", SemanticGateCaseClass.POSITIVE)
        for index in range(1, 21)
    ) + tuple(
        _case(f"case-{index:02d}", SemanticGateCaseClass.ELIGIBLE_NEGATIVE)
        for index in range(21, 41)
    )
    reviewer = SemanticGateCorpusReviewer(
        reviewer_id="reviewer-a",
        independence_statement="Independent test review.",
        reviewed_case_count=40,
        reviewed_at="2026-09-01T00:00:00Z",
        provenance=SemanticGateCorpusProvenance.HUMAN_AUTHORED,
    )
    return build_semantic_gate_human_corpus(
        gate_id="SG-TEST-001",
        signal="instruction_integrity",
        cases=cases,
        reviewers=(reviewer,),
    )


def _candidate() -> SemanticGateCandidate:
    return build_semantic_gate_candidate(
        gate_id="SG-TEST-001",
        title="Test Gate",
        description="Test semantic Gate qualification.",
        signal="instruction_integrity",
        thresholds=SemanticGateThresholds(
            min_case_count=40,
            min_positive_case_count=20,
            min_eligible_negative_case_count=20,
            min_precision=1.0,
            min_recall=1.0,
            min_f1=1.0,
            min_evidence_binding_accuracy=1.0,
            min_complete_coverage_rate=1.0,
        ),
        required_inputs=(
            SemanticGateInput.HUMAN_CONFIDENCE,
            SemanticGateInput.HUMAN_CORPUS,
            SemanticGateInput.PROVIDER_PROMOTION,
            SemanticGateInput.PROVIDER_QUALITY,
        ),
    )


def _evaluation(corpus: SemanticGateHumanCorpus) -> SemanticEvaluationReport:
    results = tuple(
        SemanticEvaluationCaseResult(
            case_id=case.case_id,
            status=SemanticEvaluationCaseStatus.COMPLETE,
            expected_count=0,
            predicted_count=0,
            true_positive=0,
            false_positive=0,
            false_negative=0,
            evidence_exact_matches=0,
            evidence_comparisons=0,
            semantic_complete=True,
            invocation_success=True,
        )
        for case in corpus.cases
    )
    return SemanticEvaluationReport(
        provider_id="offline-fixture",
        model_id="agentsec-semantic-fixture-v1",
        cases=results,
        metrics=SemanticEvaluationMetrics(
            case_count=40,
            completed_case_count=40,
            failed_case_count=0,
            true_positive=0,
            false_positive=0,
            false_negative=0,
            precision=1.0,
            recall=1.0,
            f1=1.0,
            evidence_exact_matches=0,
            evidence_comparisons=0,
            evidence_binding_accuracy=1.0,
            complete_coverage_cases=40,
            complete_coverage_rate=1.0,
        ),
    )


def _promotion() -> ProviderPromotionReport:
    return ProviderPromotionReport(
        provider_id="offline-fixture",
        model_id="agentsec-semantic-fixture-v1",
        evaluation_report_sha256="0" * 64,
        state=ProviderPromotionState.APPROVED_SHADOW,
        quality_passed=True,
        human_review_passed=True,
        adjudication_required=False,
        blocking_reasons=(),
        thresholds=ProviderQualityThresholds(min_case_count=40),
    )


def test_evaluation_import_binds_report_to_candidate_and_corpus() -> None:
    corpus = _corpus()
    imported = build_semantic_gate_evaluation_import(
        candidate=_candidate(), corpus=corpus, evaluation=_evaluation(corpus)
    )

    assert imported.gate_id == "SG-TEST-001"
    assert imported.corpus_sha256 == corpus.corpus_sha256
    assert imported.evaluation.metrics.case_count == 40
    assert imported.source.value == "evaluation_report"
    assert imported.report_only is True
    assert imported.ci_authority is False


def test_evaluation_import_rejects_case_set_or_digest_tampering() -> None:
    corpus = _corpus()
    evaluation = _evaluation(corpus)
    altered = evaluation.model_copy(update={"cases": evaluation.cases[:-1]})
    with pytest.raises(ValueError, match="exactly match"):
        build_semantic_gate_evaluation_import(
            candidate=_candidate(), corpus=corpus, evaluation=altered
        )

    imported = build_semantic_gate_evaluation_import(
        candidate=_candidate(), corpus=corpus, evaluation=evaluation
    )
    payload = imported.model_dump(mode="json")
    payload["corpus_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        type(imported).model_validate(payload)


def test_evaluation_import_qualifies_report_only_gate() -> None:
    corpus = _corpus()
    candidate = _candidate()
    imported = build_semantic_gate_evaluation_import(
        candidate=candidate, corpus=corpus, evaluation=_evaluation(corpus)
    )
    confidence = SemanticGateEvidenceConfidence(
        grade=EvidenceConfidenceGrade.C,
        reviewer_count=1,
        reviewed_case_count=40,
        adjudication_complete=True,
        rationale_code="independent_human_review",
    )

    qualification = qualify_semantic_gate_evaluation(
        candidate=candidate,
        corpus=corpus,
        evaluation_import=imported,
        provider_promotion=_promotion(),
        evidence_confidence=confidence,
        thresholds=ProviderQualityThresholds(
            min_case_count=40,
            min_precision=1.0,
            min_recall=1.0,
            min_f1=1.0,
            min_evidence_binding_accuracy=1.0,
            min_complete_coverage_rate=1.0,
        ),
    )

    assert qualification.status is SemanticGateQualificationStatus.QUALIFIED
    assert qualification.eligible_for_report_only_gate is True
    assert qualification.authority.can_block_ci is False

    promotion = promote_report_only(qualification)
    assert isinstance(promotion, SemanticGateReportOnlyPromotion)
    assert promotion.promoted is True
    assert promotion.can_block_ci is False
    assert promotion.can_publish_rule is False


def test_report_only_promotion_is_not_authorization() -> None:
    corpus = _corpus()
    imported = build_semantic_gate_evaluation_import(
        candidate=_candidate(), corpus=corpus, evaluation=_evaluation(corpus)
    )
    assert imported.evaluation.report_only is True
    assert imported.evaluation.runtime_verified is False


def test_evaluation_import_cli_and_qualification_cli(tmp_path: Path) -> None:
    """The P3-20 command path imports, qualifies, and emits report-only promotion."""
    import subprocess
    import sys

    corpus = _corpus()
    candidate = _candidate()
    evaluation = _evaluation(corpus)
    build_semantic_gate_evaluation_import(
        candidate=candidate, corpus=corpus, evaluation=evaluation
    )
    candidate_path = tmp_path / "candidate.json"
    corpus_path = tmp_path / "corpus.json"
    evaluation_path = tmp_path / "evaluation.json"
    imported_path = tmp_path / "evaluation-import.json"
    qualification_path = tmp_path / "qualification.json"
    promotion_path = tmp_path / "promotion.json"
    candidate_path.write_text(candidate.model_dump_json(indent=2), encoding="utf-8")
    corpus_path.write_text(corpus.model_dump_json(indent=2), encoding="utf-8")
    evaluation_path.write_text(evaluation.model_dump_json(indent=2), encoding="utf-8")

    imported_result = subprocess.run(
        [
            sys.executable,
            "scripts/import-semantic-gate-evaluation.py",
            "--candidate",
            str(candidate_path),
            "--human-corpus",
            str(corpus_path),
            "--evaluation-report",
            str(evaluation_path),
            "--output",
            str(imported_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert imported_result.returncode == 0, imported_result.stderr

    promotion_path_input = tmp_path / "provider-promotion.json"
    confidence_path = tmp_path / "confidence.json"
    promotion_path_input.write_text(
        _promotion().model_dump_json(indent=2), encoding="utf-8"
    )
    confidence_path.write_text(
        SemanticGateEvidenceConfidence(
            grade=EvidenceConfidenceGrade.C,
            reviewer_count=1,
            reviewed_case_count=40,
            adjudication_complete=True,
            rationale_code="independent_human_review",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    qualified_result = subprocess.run(
        [
            sys.executable,
            "scripts/run-semantic-gate-qualification.py",
            "--candidate",
            str(candidate_path),
            "--human-corpus",
            str(corpus_path),
            "--evaluation-import",
            str(imported_path),
            "--provider-promotion",
            str(promotion_path_input),
            "--evidence-confidence",
            str(confidence_path),
            "--format",
            "json",
            "--output",
            str(qualification_path),
            "--promotion-output",
            str(promotion_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert qualified_result.returncode == 0, qualified_result.stderr
    assert json.loads(qualification_path.read_text())["status"] == "qualified"
    promotion_payload = json.loads(promotion_path.read_text())
    assert promotion_payload["promoted"] is True
    assert promotion_payload["can_block_ci"] is False

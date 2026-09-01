"""P3-05 Human Review and controlled Shadow Promotion tests."""

from __future__ import annotations

import hashlib
import json

from agentsec.semantic import (
    ProviderPromotionController,
    ProviderPromotionState,
    ProviderQualityThresholds,
    ProviderReviewDecision,
    ProviderReviewDisposition,
    SemanticAnalysisInput,
    SemanticDeterministicContext,
    SemanticEvaluationCase,
    SemanticEvaluationCaseResult,
    SemanticEvaluationCaseStatus,
    SemanticEvaluationMetrics,
    SemanticEvaluationReport,
    SemanticHumanReviewSubmission,
    build_semantic_evidence_chunk,
)


def _report() -> SemanticEvaluationReport:
    c = SemanticEvaluationCase(
        case_id="p3-05-case",
        semantic_input=SemanticAnalysisInput(
            analysis_id="p3-05-case",
            deterministic_context=SemanticDeterministicContext(coverage_complete=True),
            evidence=(
                build_semantic_evidence_chunk(
                    asset_path="AGENTS.md",
                    asset_sha256="a" * 64,
                    start_line=1,
                    end_line=1,
                    text="Search the web.",
                ),
            ),
        ),
        expected=(),
    )
    return SemanticEvaluationReport(
        provider_id="p",
        model_id="m",
        cases=(
            SemanticEvaluationCaseResult(
                case_id=c.case_id,
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
            ),
        ),
        metrics=SemanticEvaluationMetrics(
            case_count=1,
            completed_case_count=1,
            failed_case_count=0,
            true_positive=0,
            false_positive=0,
            false_negative=0,
            precision=1,
            recall=1,
            f1=1,
            evidence_exact_matches=0,
            evidence_comparisons=0,
            evidence_binding_accuracy=1,
            complete_coverage_cases=1,
            complete_coverage_rate=1,
        ),
    )


def _reviews(
    report: SemanticEvaluationReport,
) -> tuple[str, SemanticHumanReviewSubmission, SemanticHumanReviewSubmission]:
    digest = hashlib.sha256(
        json.dumps(
            report.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    d = ProviderReviewDecision(
        case_id="p3-05-case",
        semantic_disposition=ProviderReviewDisposition.ACCEPT,
        evidence_binding_acceptable=True,
        reviewer_confidence="high",
        rationale_code="reviewed",
    )
    return (
        digest,
        SemanticHumanReviewSubmission(
            provider_id="p",
            model_id="m",
            evaluation_report_sha256=digest,
            reviewer_id="a",
            decisions=(d,),
        ),
        SemanticHumanReviewSubmission(
            provider_id="p",
            model_id="m",
            evaluation_report_sha256=digest,
            reviewer_id="b",
            decisions=(d,),
        ),
    )


def test_promotion_requires_quality_and_two_reviewers() -> None:
    r = _report()
    digest, a, b = _reviews(r)
    out = ProviderPromotionController().assess(
        r, a, b, thresholds=ProviderQualityThresholds(min_case_count=1)
    )
    assert out.state is ProviderPromotionState.ELIGIBLE_SHADOW
    approved = ProviderPromotionController().approve_shadow(
        out, owner_id="owner", approval_id="approval"
    )
    assert approved.state is ProviderPromotionState.APPROVED_SHADOW
    assert approved.production_authority is False and approved.ci_authority is False


def test_missing_and_disagreeing_review_is_not_promoted() -> None:
    r = _report()
    digest, a, b = _reviews(r)
    pending = ProviderPromotionController().assess(
        r, thresholds=ProviderQualityThresholds(min_case_count=1)
    )
    assert pending.state is ProviderPromotionState.REVIEW_PENDING
    disagree = b.model_copy(
        update={
            "decisions": (
                b.decisions[0].model_copy(
                    update={"semantic_disposition": ProviderReviewDisposition.REJECT}
                ),
            )
        }
    )
    out = ProviderPromotionController().assess(
        r, a, disagree, thresholds=ProviderQualityThresholds(min_case_count=1)
    )
    assert out.state is ProviderPromotionState.ADJUDICATION_PENDING


def test_promotion_cannot_approve_rejected_report() -> None:
    r = _report()
    _, a, b = _reviews(r)
    out = ProviderPromotionController().assess(r, a, b)
    assert out.state is ProviderPromotionState.REJECTED
    try:
        ProviderPromotionController().approve_shadow(
            out, owner_id="owner", approval_id="id"
        )
    except ValueError:
        pass
    else:
        raise AssertionError("rejected Provider was approved")

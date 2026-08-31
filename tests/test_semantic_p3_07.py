"""P3-07 semantic calibration, promotion review, and Rule replay tests."""

from __future__ import annotations

import hashlib
import json

import pytest

from agentsec.domain import AgentAsset, AssetSource, AssetType, FindingCategory
from agentsec.parsers import MarkdownItParser
from agentsec.rules import KeywordRule, RuleContext, RuleMetadata, RuleScope, RuleTarget
from agentsec.semantic import (
    FindingPromotionDecision,
    FindingPromotionStatus,
    RuleImplementationReplayCase,
    RuleImplementationReplayRunner,
    RuleReplayClassification,
    SemanticAnalysisContract,
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticCalibrationOutcome,
    SemanticCandidateCalibrationCase,
    SemanticCandidateCalibrationRunner,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticFindingIntegrationReport,
    SemanticFindingLink,
    SemanticFindingPromotionReviewer,
    SemanticFindingRelation,
    SemanticInvocationProvenance,
    SemanticModelCandidate,
    SemanticModelOutput,
    SemanticRuleCandidateWorkflow,
)

_HASH = "a" * 64
_CANDIDATE_ID = "semantic-candidate-sha256:" + "b" * 64


def _result_with_candidate() -> SemanticAnalysisResult:
    from agentsec.semantic import build_semantic_evidence_chunk

    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=1,
        end_line=1,
        text="Run a shell command.",
    )
    request = SemanticAnalysisInput(
        analysis_id="p3-07-test",
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(chunk,),
    )
    output = SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(chunk.evidence_id,),
        candidates=(
            SemanticModelCandidate(
                candidate_key="candidate-01",
                kind=SemanticCandidateKind.RISKY_INTENT,
                category=FindingCategory.CODE_EXECUTION,
                disposition=SemanticCandidateDisposition.SUPPORTED,
                summary="The file describes shell execution.",
                evidence_ids=(chunk.evidence_id,),
            ),
        ),
    )
    invocation = SemanticInvocationProvenance(
        provider_id="offline-fixture",
        model_id="fixture-model",
        prompt_version="0.1.0",
        invocation_sha256="d" * 64,
        invocation_mode="offline_fixture",
    )
    return SemanticAnalysisContract().validate(request, output, invocation)


def _empty_result() -> SemanticAnalysisResult:
    from agentsec.semantic import build_semantic_evidence_chunk

    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=1,
        end_line=1,
        text="No risky declaration.",
    )
    request = SemanticAnalysisInput(
        analysis_id="p3-07-empty",
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(chunk,),
    )
    output = SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(chunk.evidence_id,),
        candidates=(),
    )
    invocation = SemanticInvocationProvenance(
        provider_id="offline-fixture",
        model_id="fixture-model",
        prompt_version="0.1.0",
        invocation_sha256="d" * 64,
        invocation_mode="offline_fixture",
    )
    return SemanticAnalysisContract().validate(request, output, invocation)


def _context(content: str) -> RuleContext:
    content_bytes = content.encode()
    return RuleContext(
        asset=AgentAsset(
            path="AGENTS.md",
            asset_type=AssetType.AGENTS,
            source=AssetSource.DISCOVERED,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
        ),
        content=content,
        document=MarkdownItParser().parse(content),
    )


def _rule() -> KeywordRule:
    return KeywordRule(
        RuleMetadata(
            rule_id="SEMANTICEXECUTION-SHELL-001",
            title="Shell execution",
            description="Detects shell execution language.",
            category=FindingCategory.CODE_EXECUTION,
            recommendations=("Review execution approval.",),
            scope=RuleScope.all_markdown(RuleTarget.MARKDOWN_BLOCK),
        ),
        keywords=("shell",),
    )


def test_candidate_calibration_reports_presence_and_field_agreement() -> None:
    result = _result_with_candidate()
    candidate = result.candidates[0]
    cases = (
        SemanticCandidateCalibrationCase(
            case_id="case-present",
            candidate_key="candidate-01",
            expected_present=True,
            expected_kind=candidate.kind,
            expected_category=candidate.category,
            expected_disposition=SemanticCalibrationOutcome.SUPPORTED,
            expected_evidence_ids=candidate.evidence_ids,
            reviewer_id="expert-a",
            rationale_code="reviewed",
        ),
        SemanticCandidateCalibrationCase(
            case_id="case-absent",
            candidate_key="candidate-02",
            expected_present=False,
            reviewer_id="expert-a",
            rationale_code="reviewed",
        ),
    )
    report = SemanticCandidateCalibrationRunner().run(result, cases)
    assert report.metrics.true_positive == 1
    assert report.metrics.true_negative == 1
    assert report.metrics.precision == 1
    assert report.metrics.recall == 1
    assert report.metrics.evidence_agreement == 1
    assert report.reviewer_count == 1
    assert report.finding_authority is False


def test_calibration_finds_false_negative_and_handles_unobserved() -> None:
    result = _empty_result()
    case = SemanticCandidateCalibrationCase(
        case_id="case-missing",
        candidate_key="candidate-01",
        expected_present=True,
        expected_kind=SemanticCandidateKind.RISKY_INTENT,
        expected_category=FindingCategory.CODE_EXECUTION,
        expected_disposition=SemanticCalibrationOutcome.SUPPORTED,
        expected_evidence_ids=("semantic-evidence-sha256:" + "e" * 64,),
        reviewer_id="expert-a",
        rationale_code="reviewed",
    )
    report = SemanticCandidateCalibrationRunner().run(result, (case,))
    assert report.metrics.false_negative == 1
    assert report.metrics.recall == 0


def test_promotion_review_accepts_positive_links_only() -> None:
    link = SemanticFindingLink(
        candidate_id=_CANDIDATE_ID,
        finding_id="finding-001",
        relation=SemanticFindingRelation.SUPPORTS,
        basis=("asset_path", "asset_sha256", "category", "line_overlap"),
        candidate_evidence_count=1,
    )
    report = SemanticFindingIntegrationReport(
        semantic_result_sha256=_HASH,
        links=(link,),
    )
    reviewer = SemanticFindingPromotionReviewer()
    review = reviewer.review(
        link,
        reviewer_id="expert-a",
        decision=FindingPromotionDecision.ACCEPT,
    )
    assert review.status is FindingPromotionStatus.ACCEPTED_FOR_FINDING_REVIEW
    assert review.creates_finding is False
    batch = reviewer.review_report(
        report,
        ((link, FindingPromotionDecision.ACCEPT, "human_reviewed"),),
        reviewer_id="expert-a",
    )
    assert batch.creates_finding is False
    assert batch.reviews[0].finding_id == "finding-001"

    unmatched = link.model_copy(
        update={"finding_id": None, "relation": SemanticFindingRelation.UNMATCHED}
    )
    with pytest.raises(ValueError, match="requires a Finding"):
        reviewer.review(
            unmatched,
            reviewer_id="expert-a",
            decision=FindingPromotionDecision.ACCEPT,
        )


def test_rule_replay_requires_accepted_proposal_and_replays_trusted_rule() -> None:
    proposal = (
        SemanticRuleCandidateWorkflow().propose(_result_with_candidate()).proposals[0]
    )
    with pytest.raises(ValueError, match="accepted"):
        RuleImplementationReplayRunner().run(
            proposal,
            _rule(),
            (
                RuleImplementationReplayCase(
                    case_id="positive",
                    context=_context("Run a shell command.\n"),
                    expected_outcome="match",
                    expected_min_findings=1,
                    expected_max_findings=1,
                ),
            ),
        )

    accepted = SemanticRuleCandidateWorkflow().accept_for_implementation(
        proposal,
        reviewer_id="expert-a",
    )
    report = RuleImplementationReplayRunner().run(
        accepted,
        _rule(),
        (
            RuleImplementationReplayCase(
                case_id="negative",
                context=_context("Use a calculator.\n"),
                expected_outcome="no_match",
            ),
            RuleImplementationReplayCase(
                case_id="positive",
                context=_context("Run a shell command.\n"),
                expected_outcome="match",
                expected_min_findings=1,
                expected_max_findings=1,
            ),
        ),
    )
    assert report.metrics.true_positive == 1
    assert report.metrics.true_negative == 1
    assert report.metrics.precision == 1
    assert report.metrics.recall == 1
    assert report.metrics.evidence_binding_accuracy == 1
    assert report.rule_pack_mutated is False
    assert report.ci_authority is False
    assert all(
        row.classification
        in (
            RuleReplayClassification.TRUE_POSITIVE,
            RuleReplayClassification.TRUE_NEGATIVE,
        )
        for row in report.results
    )


def test_rule_replay_family_binding_and_serialized_reports_are_safe() -> None:
    proposal = SemanticRuleCandidateWorkflow().accept_for_implementation(
        SemanticRuleCandidateWorkflow().propose(_result_with_candidate()).proposals[0],
        reviewer_id="expert-a",
    )
    wrong_rule = _rule().metadata
    wrong = KeywordRule(
        wrong_rule.__class__(
            rule_id="OTHER-FAMILY-001",
            title=wrong_rule.title,
            description=wrong_rule.description,
            category=wrong_rule.category,
            recommendations=wrong_rule.recommendations,
            scope=wrong_rule.scope,
        ),
        keywords=("shell",),
    )
    with pytest.raises(ValueError, match="not bound"):
        RuleImplementationReplayRunner().run(
            proposal,
            wrong,
            (
                RuleImplementationReplayCase(
                    case_id="positive",
                    context=_context("shell\n"),
                    expected_outcome="match",
                    expected_min_findings=1,
                    expected_max_findings=1,
                ),
            ),
        )
    payload = json.dumps(proposal.model_dump(mode="json"))
    assert "automatic_publication" in payload
    assert "shell" not in payload

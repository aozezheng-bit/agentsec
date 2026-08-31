"""P3-06 semantic Finding integration and Rule Candidate workflow tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentsec.domain import (
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    Finding,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.semantic import (
    SemanticAnalysisContract,
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    SemanticFindingIntegrator,
    SemanticFindingRelation,
    SemanticInvocationProvenance,
    SemanticModelCandidate,
    SemanticModelOutput,
    SemanticRuleCandidateWorkflow,
    build_semantic_evidence_chunk,
)

_HASH = "a" * 64


def _chunk(
    *, line: int = 4, text: str = "Run a shell command."
) -> SemanticEvidenceChunk:
    return build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=line,
        end_line=line,
        text=text,
    )


def _result(
    *,
    disposition: SemanticCandidateDisposition = SemanticCandidateDisposition.SUPPORTED,
) -> tuple[SemanticAnalysisResult, SemanticEvidenceChunk]:
    chunk = _chunk()
    request = SemanticAnalysisInput(
        analysis_id="p3-06-test",
        deterministic_context=SemanticDeterministicContext(
            coverage_complete=True,
            finding_ids=("finding-001",),
        ),
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
                disposition=disposition,
                summary="The asset describes shell execution.",
                evidence_ids=(chunk.evidence_id,),
            ),
        ),
    )
    invocation = SemanticInvocationProvenance(
        provider_id="offline-fixture",
        model_id="fixture-model",
        prompt_version="0.1.0",
        invocation_sha256="b" * 64,
        invocation_mode="offline_fixture",
    )
    return SemanticAnalysisContract().validate(request, output, invocation), chunk


def _finding(
    *,
    start_line: int = 4,
    end_line: int = 4,
    category: FindingCategory = FindingCategory.CODE_EXECUTION,
) -> Finding:
    return Finding(
        finding_id="finding-001",
        rule_id="MD-EXEC-001",
        category=category,
        title="Shell execution is declared",
        description="The instruction file declares shell execution capability.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.HIGH,
        severity=Severity.HIGH,
        score=8.0,
        confidence=EvidenceConfidence.C,
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=start_line,
                end_line=end_line,
                excerpt="Run a shell command.",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Require approval before execution.",),
    )


def test_exact_static_evidence_is_reported_as_duplicate_only() -> None:
    result, chunk = _result()
    finding = _finding()
    report = SemanticFindingIntegrator().integrate(result, (finding,), (chunk,))

    assert len(report.links) == 1
    link = report.links[0]
    assert link.relation is SemanticFindingRelation.DUPLICATES
    assert link.finding_id == finding.finding_id
    assert "asset_sha256" in link.basis
    assert report.finding_authority is False
    assert report.severity_authority is False
    assert finding.severity is Severity.HIGH


def test_overlapping_static_evidence_supports_existing_finding() -> None:
    result, chunk = _result()
    report = SemanticFindingIntegrator().integrate(
        result, (_finding(start_line=3, end_line=5),), (chunk,)
    )
    assert report.links[0].relation is SemanticFindingRelation.SUPPORTS
    assert report.links[0].finding_id == "finding-001"


def test_not_supported_candidate_is_report_only_contradiction() -> None:
    result, chunk = _result(
        disposition=SemanticCandidateDisposition.NOT_SUPPORTED,
    )
    report = SemanticFindingIntegrator().integrate(result, (_finding(),), (chunk,))
    assert report.links[0].relation is SemanticFindingRelation.CONTRADICTS


def test_missing_or_mismatched_trusted_evidence_fails_closed_to_unmatched() -> None:
    result, chunk = _result()
    missing = SemanticFindingIntegrator().integrate(result, (_finding(),))
    assert missing.links[0].relation is SemanticFindingRelation.UNMATCHED
    assert "semantic_evidence_not_a_finding" in missing.links[0].basis

    mismatch = _chunk(line=99)
    report = SemanticFindingIntegrator().integrate(result, (_finding(),), (mismatch,))
    assert report.links[0].relation is SemanticFindingRelation.UNMATCHED
    assert "evidence_reference_unavailable" in report.links[0].basis


def test_category_hash_and_non_static_source_are_required_for_match() -> None:
    result, chunk = _result()
    wrong_category = _finding(category=FindingCategory.NETWORK_ACCESS)
    report = SemanticFindingIntegrator().integrate(result, (wrong_category,), (chunk,))
    assert report.links[0].relation is SemanticFindingRelation.UNMATCHED

    # A runtime-only Evidence item cannot be matched by a static semantic chunk.
    runtime = _finding().model_copy(
        update={
            "evidence": (
                Evidence(
                    source_type=EvidenceSource.RUNTIME,
                    field="runtime.attestation",
                    excerpt="verified",
                ),
            )
        }
    )
    report = SemanticFindingIntegrator().integrate(result, (runtime,), (chunk,))
    assert report.links[0].relation is SemanticFindingRelation.UNMATCHED


def test_duplicate_finding_ids_and_duplicate_semantic_evidence_are_rejected() -> None:
    result, chunk = _result()
    finding = _finding()
    with pytest.raises(ValueError, match="Finding IDs"):
        SemanticFindingIntegrator().integrate(result, (finding, finding), (chunk,))
    with pytest.raises(ValueError, match="semantic Evidence IDs"):
        SemanticFindingIntegrator().integrate(result, (finding,), (chunk, chunk))


def test_rule_candidate_uses_fixed_trusted_family_and_requires_review() -> None:
    result, _chunk_value = _result()
    workflow = SemanticRuleCandidateWorkflow()
    first = workflow.propose(result)
    second = workflow.propose(result)

    assert first == second
    assert first.proposals[0].proposed_rule_family == "SEMANTIC_EXECUTION"
    assert first.proposals[0].status.value == "review_required"
    assert first.automatic_rule_publication is False
    assert first.ci_authority is False

    accepted = workflow.accept_for_implementation(
        first.proposals[0], reviewer_id="expert-a"
    )
    assert accepted.status.value == "accepted_for_implementation"
    assert accepted.reviewer_id == "expert-a"
    assert accepted.automatic_publication is False
    assert accepted.deterministic_rule_authority is False


def test_rule_candidate_rejection_and_state_transition_are_controlled() -> None:
    result, _chunk_value = _result()
    workflow = SemanticRuleCandidateWorkflow()
    proposal = workflow.propose(result).proposals[0]
    rejected = workflow.reject(proposal, reviewer_id="expert-b")
    assert rejected.status.value == "rejected"
    assert rejected.reviewer_id == "expert-b"

    with pytest.raises(ValueError, match="only review-required"):
        workflow.accept_for_implementation(rejected, reviewer_id="expert-a")
    with pytest.raises(ValueError, match="reviewer_id"):
        workflow.reject(proposal, reviewer_id=" ")


def test_report_contracts_reject_authority_and_unreviewed_state_forgery() -> None:
    result, _chunk_value = _result()
    proposal = SemanticRuleCandidateWorkflow().propose(result).proposals[0]
    forged = proposal.model_dump(mode="json")
    forged["status"] = "accepted_for_implementation"
    with pytest.raises(ValidationError):
        type(proposal).model_validate(forged)
    # Strict JSON serialization exposes no source excerpt and no authority field.
    payload = json.dumps(proposal.model_dump(mode="json"))
    assert "Run a shell command" not in payload
    assert "severity" not in payload
    assert "block" not in payload

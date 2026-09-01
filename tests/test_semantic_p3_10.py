"""P3-10 controlled Rule promotion and Rule Pack staging tests."""

from __future__ import annotations

from agentsec.domain import FindingCategory
from agentsec.semantic import (
    RuleImplementationReplayCaseResult,
    RuleImplementationReplayMetrics,
    RuleImplementationReplayReport,
    RulePromotionStatus,
    RuleReplayClassification,
    SemanticAnalysisContract,
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticInvocationProvenance,
    SemanticModelCandidate,
    SemanticModelOutput,
    SemanticRuleCandidateWorkflow,
    SemanticRulePromotionController,
    build_semantic_evidence_chunk,
)
from agentsec.semantic.integration import SemanticRuleCandidate


def _proposal() -> SemanticRuleCandidate:
    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256="a" * 64,
        start_line=1,
        end_line=1,
        text="Run a shell command.",
    )
    request = SemanticAnalysisInput(
        analysis_id="p3-10-test",
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
                summary="The asset describes shell execution.",
                evidence_ids=(chunk.evidence_id,),
            ),
        ),
    )
    result = SemanticAnalysisContract().validate(
        request,
        output,
        SemanticInvocationProvenance(
            provider_id="offline-fixture",
            model_id="fixture-model",
            prompt_version="0.1.0",
            invocation_sha256="b" * 64,
            invocation_mode="offline_fixture",
        ),
    )
    proposal = SemanticRuleCandidateWorkflow().propose(result).proposals[0]
    return SemanticRuleCandidateWorkflow().accept_for_implementation(
        proposal,
        reviewer_id="expert-a",
    )


def _replay(
    proposal: SemanticRuleCandidate, *, false_positive: int = 0
) -> RuleImplementationReplayReport:
    results = [
        RuleImplementationReplayCaseResult(
            case_id="positive",
            expected_outcome="match",
            observed_outcome="match",
            classification=RuleReplayClassification.TRUE_POSITIVE,
            observed_findings=1,
            finding_bound_ok=True,
            evidence_binding_ok=True,
            failure=False,
        )
    ]
    if false_positive:
        results.append(
            RuleImplementationReplayCaseResult(
                case_id="negative",
                expected_outcome="no_match",
                observed_outcome="match",
                classification=RuleReplayClassification.FALSE_POSITIVE,
                observed_findings=1,
                finding_bound_ok=True,
                evidence_binding_ok=True,
                failure=False,
            )
        )
    case_count = len(results)
    precision = 1 / (1 + false_positive)
    f1 = 2 / (2 + false_positive)
    return RuleImplementationReplayReport(
        proposal_id=proposal.proposal_id,
        rule_id="SEMANTICEXECUTION-SHELL-001",
        results=tuple(sorted(results, key=lambda item: item.case_id)),
        metrics=RuleImplementationReplayMetrics(
            case_count=case_count,
            true_positive=1,
            false_positive=false_positive,
            false_negative=0,
            true_negative=0,
            precision=precision,
            recall=1,
            f1=f1,
            evidence_binding_accuracy=1,
            finding_bound_accuracy=1,
            failure_count=0,
        ),
    )


def test_promotion_requires_replay_quality_and_produces_value_free_diff() -> None:
    proposal = _proposal()
    replay = _replay(proposal)
    report = SemanticRulePromotionController().assess(
        proposal,
        replay,
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=("MD-EXEC-001",),
    )
    assert report.status is RulePromotionStatus.ELIGIBLE_FOR_STAGING
    assert all(check.passed for check in report.checks)
    assert report.rule_pack_diff.added_rule_ids == ("SEMANTICEXECUTION-SHELL-001",)
    assert report.rule_pack_mutated is False
    assert report.release_authority is False
    assert all(
        getattr(report, field) is False
        for field in (
            "automatic_publication",
            "rule_pack_mutated",
            "finding_authority",
            "policy_authority",
            "ci_authority",
            "hard_gate_authority",
            "release_authority",
        )
    )

    staged = SemanticRulePromotionController().stage(
        report,
        owner_id="release-owner",
        approval_id="approval-001",
        approval_reason="Replay and review passed.",
    )
    assert staged.status is RulePromotionStatus.STAGED
    assert staged.owner_id == "release-owner"
    assert staged.automatic_publication is False


def test_failed_replay_is_rejected_and_cannot_be_staged() -> None:
    proposal = _proposal()
    report = SemanticRulePromotionController().assess(
        proposal,
        _replay(proposal, false_positive=1),
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=(),
    )
    assert report.status is RulePromotionStatus.REJECTED
    assert any(
        check.check_id == "replay_zero_false_positive" and not check.passed
        for check in report.checks
    )
    try:
        SemanticRulePromotionController().stage(
            report,
            owner_id="owner",
            approval_id="approval",
            approval_reason="not eligible",
        )
    except ValueError as error:
        assert "eligible" in str(error)
    else:
        raise AssertionError("rejected promotion was staged")


def test_owner_rejection_is_explicit_and_no_pack_change_occurs() -> None:
    proposal = _proposal()
    report = SemanticRulePromotionController().assess(
        proposal,
        _replay(proposal),
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=(),
    )
    rejected = SemanticRulePromotionController().reject(
        report,
        owner_id="owner",
        approval_id="approval-reject-001",
        approval_reason="Do not stage in this release.",
    )
    assert rejected.status is RulePromotionStatus.REJECTED
    assert rejected.rule_pack_mutated is False
    assert rejected.checks[0].check_id == "owner_rejected"
    assert rejected.checks[0].passed is False


def test_rejected_assessment_preserves_duplicate_rule_id_diff() -> None:
    proposal = _proposal()
    report = SemanticRulePromotionController().assess(
        proposal,
        _replay(proposal),
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=("SEMANTICEXECUTION-SHELL-001",),
    )
    assert report.status is RulePromotionStatus.REJECTED
    assert report.rule_pack_diff.added_rule_ids == ()
    assert any(
        check.check_id == "rule_id_is_new" and not check.passed
        for check in report.checks
    )


def test_staging_requires_an_owner_approval_reason() -> None:
    proposal = _proposal()
    report = SemanticRulePromotionController().assess(
        proposal,
        _replay(proposal),
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=(),
    )
    try:
        SemanticRulePromotionController().stage(
            report,
            owner_id="owner",
            approval_id="approval",
            approval_reason="   ",
        )
    except ValueError as error:
        assert "approval" in str(error)
    else:
        raise AssertionError("staging without rationale was accepted")


def test_staged_report_cannot_be_rejected_again() -> None:
    proposal = _proposal()
    controller = SemanticRulePromotionController()
    report = controller.assess(
        proposal,
        _replay(proposal),
        implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
        implementation_sha256="c" * 64,
        base_rule_pack_version="0.3.1",
        base_rule_ids=(),
    )
    staged = controller.stage(
        report,
        owner_id="owner",
        approval_id="approval",
        approval_reason="Approved for isolated staging.",
    )
    try:
        controller.reject(
            staged,
            owner_id="owner",
            approval_id="approval-reject",
            approval_reason="Too late.",
        )
    except ValueError as error:
        assert "eligible" in str(error)
    else:
        raise AssertionError("staged report was mutated by rejection")


def test_promotion_rejects_unaccepted_or_mismatched_proposals() -> None:
    proposal = _proposal()
    workflow = SemanticRuleCandidateWorkflow()
    # The accepted proposal's replay binding is content-addressed and strict.
    report = _replay(proposal)
    try:
        SemanticRulePromotionController().assess(
            proposal,
            report.model_copy(
                update={"proposal_id": "semantic-rule-proposal-sha256:" + "d" * 64}
            ),
            implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
            implementation_sha256="c" * 64,
            base_rule_pack_version="0.3.1",
            base_rule_ids=(),
        )
    except ValueError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("mismatched replay was accepted")
    del workflow

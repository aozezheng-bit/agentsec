"""P2-22 Agentic Governance Score contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.risk import (
    DeterministicAgenticFactorExtractor,
    DeterministicGovernanceScoreEngine,
    DeterministicThreatMitigationEvaluator,
    DriftApprovalStatus,
    DriftBaselineTrust,
    DriftChangeSource,
    DriftDeploymentScope,
    DriftScoreContext,
    GovernanceReviewStatus,
    GovernanceScoreContext,
    GovernanceScoreError,
    encode_governance_score_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ENGINE = DeterministicGovernanceScoreEngine()


def _inputs(name: str):  # type: ignore[no-untyped-def]
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
    manifest = (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=project, agent_id="capability-drift-agent"
            )
        )
        .manifest
    )
    factors = DeterministicAgenticFactorExtractor().extract(manifest)
    threats = DeterministicThreatMitigationEvaluator().evaluate(manifest, factors)
    return manifest, factors, threats


def test_governance_score_is_deterministic_and_has_all_dimensions() -> None:
    manifest, factors, threats = _inputs("risky-drift")

    first = ENGINE.score(manifest, factors, threats)
    second = ENGINE.score(manifest, factors, threats)

    assert first == second
    assert first.governance_score == 10.0
    assert first.severity.value == "critical"
    assert {item.dimension.value for item in first.contributions} == {
        "control_maturity",
        "coverage",
        "approval",
        "baseline_trust",
        "change_review",
        "deployment_scope",
        "ownership",
        "waiver",
    }
    assert any(item.evidence for item in first.contributions)


def test_explicit_mature_context_reduces_governance_risk_but_not_controls() -> None:
    manifest, factors, threats = _inputs("risky-drift")
    context = GovernanceScoreContext(
        drift=DriftScoreContext(
            change_source=DriftChangeSource.REVIEWED_CHANGE,
            approval_status=DriftApprovalStatus.APPROVED,
            approval_reference="approval-2026-001",
            deployment_scope=DriftDeploymentScope.PRODUCTION,
            baseline_trust=DriftBaselineTrust.HASH_ONLY,
        ),
        review_status=GovernanceReviewStatus.APPROVED,
        policy_owner="security-platform",
        approval_owner="release-security",
        waiver_count=0,
        expired_waiver_count=0,
    )

    assessment = ENGINE.score(manifest, factors, threats, context=context)

    assert assessment.governance_score == 6.9
    assert assessment.severity.value == "medium"
    control = next(
        item
        for item in assessment.contributions
        if item.dimension.value == "control_maturity"
    )
    assert control.points == 3.4


def test_unknown_and_incomplete_governance_context_is_visible() -> None:
    manifest, factors, threats = _inputs("incomplete")

    assessment = ENGINE.score(manifest, factors, threats)

    assert assessment.governance_score == 10.0
    coverage = next(
        item for item in assessment.contributions if item.dimension.value == "coverage"
    )
    assert coverage.points == 2.0
    assert assessment.context.review_status is GovernanceReviewStatus.UNKNOWN


def test_waiver_and_owner_inputs_are_bounded() -> None:
    manifest, factors, threats = _inputs("risky-drift")
    context = GovernanceScoreContext(
        policy_owner="security",
        approval_owner="release",
        waiver_count=2,
        expired_waiver_count=1,
    )
    assessment = ENGINE.score(manifest, factors, threats, context=context)
    waiver = next(
        item for item in assessment.contributions if item.dimension.value == "waiver"
    )
    ownership = next(
        item for item in assessment.contributions if item.dimension.value == "ownership"
    )

    assert waiver.points == 1.5
    assert ownership.points == 0.0

    with pytest.raises(ValueError):
        GovernanceScoreContext(waiver_count=0, expired_waiver_count=1)
    with pytest.raises(ValueError):
        GovernanceScoreContext(policy_owner="unsafe owner")


def test_manifest_binding_is_strict() -> None:
    manifest, factors, threats = _inputs("risky-drift")
    other_manifest, _, _ = _inputs("remediated")

    with pytest.raises(GovernanceScoreError):
        ENGINE.score(other_manifest, factors, threats)

    assert manifest.identity.agent_id == factors.agent_id == threats.agent_id


def test_json_output_is_bounded_and_does_not_expose_source_values() -> None:
    manifest, factors, threats = _inputs("risky-drift")
    assessment = ENGINE.score(manifest, factors, threats)
    encoded = encode_governance_score_json(assessment)
    payload = json.loads(encoded)

    assert payload["format"] == "agentsec-governance-score"
    assert payload["format_version"] == "0.1.0"
    assert len(payload["contributions"]) == 8
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded
    assert encoded.endswith("\n")

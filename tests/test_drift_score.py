"""P2-21 Agentic Capability Drift Score contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.manifests import CapabilityDiffer
from agentsec.risk import (
    DeterministicDriftScoreEngine,
    DriftApprovalStatus,
    DriftBaselineTrust,
    DriftChangeSource,
    DriftDeploymentScope,
    DriftDirection,
    DriftScoreContext,
    DriftScoreError,
    encode_drift_score_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ENGINE = DeterministicDriftScoreEngine()


def _manifest(name: str):  # type: ignore[no-untyped-def]
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
    return (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=project, agent_id="capability-drift-agent"
            )
        )
        .manifest
    )


def _diff(before_name: str, after_name: str):  # type: ignore[no-untyped-def]
    before = _manifest(before_name)
    after = _manifest(after_name)
    return before, after, CapabilityDiffer().compare(before=before, after=after)


def test_drift_score_is_deterministic_and_traces_changes() -> None:
    before, after, diff = _diff("baseline", "risky-drift")

    first = ENGINE.score(before, after, diff=diff)
    second = ENGINE.score(before, after, diff=diff)

    assert first == second
    assert first.coverage_complete is True
    assert first.changed_capabilities == len(diff.changes)
    assert first.gross_change_score == 10.0
    assert first.drift_score == 10.0
    assert first.severity.value == "critical"
    assert first.increased_exposure_changes > 0
    assert first.uncertain_changes > 0
    assert first.contributions
    assert any(item.evidence for item in first.contributions)


def test_control_additions_are_not_assumed_to_increase_exposure() -> None:
    before, after, diff = _diff("baseline", "risky-drift")
    assessment = ENGINE.score(before, after, diff=diff)

    control_changes = [
        item for item in assessment.contributions if item.dimension.value == "control"
    ]

    assert control_changes
    assert all(item.direction is DriftDirection.UNCERTAIN for item in control_changes)


def test_context_is_explicit_and_only_boundedly_reduces_drift() -> None:
    before, after, diff = _diff("baseline", "risky-drift")
    context = DriftScoreContext(
        change_source=DriftChangeSource.REVIEWED_CHANGE,
        approval_status=DriftApprovalStatus.APPROVED,
        approval_reference="approval-2026-001",
        deployment_scope=DriftDeploymentScope.PRODUCTION,
        baseline_trust=DriftBaselineTrust.HASH_ONLY,
    )

    assessment = ENGINE.score(before, after, diff=diff, context=context)

    assert assessment.context_multiplier == 0.8
    assert assessment.gross_change_score == 10.0
    assert assessment.drift_score == 8.0
    assert assessment.context.approval_reference == "approval-2026-001"


def test_incomplete_coverage_has_conservative_floor() -> None:
    before, after, diff = _diff("baseline", "incomplete")

    assessment = ENGINE.score(
        before,
        after,
        diff=diff,
        context=DriftScoreContext(deployment_scope=DriftDeploymentScope.LOCAL),
    )

    assert assessment.coverage_complete is False
    assert assessment.drift_score >= 5.0


def test_no_capability_change_has_zero_drift() -> None:
    before, after, diff = _diff("baseline", "baseline")

    assessment = ENGINE.score(before, after, diff=diff)

    assert assessment.changed_capabilities == 0
    assert assessment.gross_change_score == 0.0
    assert assessment.drift_score == 0.0
    assert assessment.severity.value == "none"


def test_before_after_source_hashes_are_not_swapped() -> None:
    before, after, diff = _diff("risky-drift", "remediated")
    assessment = ENGINE.score(before, after, diff=diff)
    before_hashes = {source.content_sha256 for source in before.sources}
    after_hashes = {source.content_sha256 for source in after.sources}

    evidence = [item for change in assessment.contributions for item in change.evidence]
    assert any(item.side == "before" for item in evidence)
    assert all(
        item.content_sha256
        in (before_hashes if item.side == "before" else after_hashes)
        for item in evidence
    )


def test_context_requires_approval_reference_and_hash_binding() -> None:
    with pytest.raises(ValueError):
        DriftScoreContext(approval_status=DriftApprovalStatus.APPROVED)

    before, after, diff = _diff("baseline", "risky-drift")
    mismatched = _manifest("risky-drift")
    with pytest.raises(DriftScoreError):
        ENGINE.score(mismatched, after, diff=diff)


def test_json_output_is_bounded_and_does_not_expose_source_values() -> None:
    before, after, diff = _diff("baseline", "risky-drift")
    assessment = ENGINE.score(before, after, diff=diff)
    encoded = encode_drift_score_json(assessment)
    payload = json.loads(encoded)

    assert payload["format"] == "agentsec-drift-score"
    assert payload["format_version"] == "0.1.0"
    assert payload["changed_capabilities"] == len(diff.changes)
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded
    assert encoded.endswith("\n")

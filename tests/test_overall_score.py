"""P2-23 Overall Score and report-only Hard Gate tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.domain import EvidenceConfidence
from agentsec.manifests import CapabilityDiffer
from agentsec.risk import (
    DeterministicAgenticFactorExtractor,
    DeterministicDriftScoreEngine,
    DeterministicGovernanceScoreEngine,
    DeterministicOverallScoreEngine,
    DeterministicTechnicalScoreEngine,
    DeterministicThreatMitigationEvaluator,
    DriftApprovalStatus,
    DriftBaselineTrust,
    DriftChangeSource,
    DriftDeploymentScope,
    DriftScoreContext,
    GovernanceReviewStatus,
    GovernanceScoreContext,
    HardGateFloor,
    OverallHardGateMatch,
    OverallHardGateQualification,
    OverallHardGateSource,
    OverallScoreError,
    encode_overall_score_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ENGINE = DeterministicOverallScoreEngine()


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


def _scores(before_name: str, after_name: str, *, mature: bool = False):  # type: ignore[no-untyped-def]
    before = _manifest(before_name)
    after = _manifest(after_name)
    factors = DeterministicAgenticFactorExtractor().extract(after)
    threats = DeterministicThreatMitigationEvaluator().evaluate(after, factors)
    technical = DeterministicTechnicalScoreEngine().score(factors, threats)
    drift_context = (
        DriftScoreContext(
            change_source=DriftChangeSource.REVIEWED_CHANGE,
            approval_status=DriftApprovalStatus.APPROVED,
            approval_reference="approval-2026-001",
            deployment_scope=DriftDeploymentScope.LOCAL,
            baseline_trust=DriftBaselineTrust.SIGNED_ATTESTED,
        )
        if mature
        else DriftScoreContext()
    )
    diff = CapabilityDiffer().compare(before=before, after=after)
    drift = DeterministicDriftScoreEngine().score(
        before, after, diff=diff, context=drift_context
    )
    governance_context = (
        GovernanceScoreContext(
            drift=drift_context,
            review_status=GovernanceReviewStatus.APPROVED,
            policy_owner="security-platform",
            approval_owner="release-security",
        )
        if mature
        else GovernanceScoreContext(drift=drift_context)
    )
    governance = DeterministicGovernanceScoreEngine().score(
        after,
        factors,
        threats,
        context=governance_context,
        drift=drift,
    )
    return technical, drift, governance


def _gate(
    gate_id: str,
    floor: HardGateFloor,
    *,
    confidence: EvidenceConfidence = EvidenceConfidence.B,
) -> OverallHardGateMatch:
    return OverallHardGateMatch(
        gate_id=gate_id,
        floor=floor,
        source=OverallHardGateSource.CAPABILITY,
        qualification=OverallHardGateQualification.ACCEPTED,
        evidence_ids=("capability-finding-sha256:" + "a" * 64,),
        confidence=confidence,
        rationale=("Qualified deterministic report-only Gate matched.",),
    )


def test_overall_score_uses_component_high_water_mark() -> None:
    technical, drift, governance = _scores("baseline", "risky-drift")

    first = ENGINE.score(technical, drift, governance)
    second = ENGINE.score(technical, drift, governance)

    assert first == second
    assert first.base_overall_score == max(
        technical.technical_score,
        drift.drift_score,
        governance.governance_score,
    )
    assert first.overall_score == first.base_overall_score == 10.0
    assert first.base_high_water_source.value == "tie"
    assert first.hard_gate.triggered is False
    assert first.hard_gate.blocks is False


def test_critical_gate_floor_cannot_be_diluted() -> None:
    technical, drift, governance = _scores("baseline", "baseline", mature=True)
    assert (
        max(
            technical.technical_score,
            drift.drift_score,
            governance.governance_score,
        )
        < 9.0
    )

    assessment = ENGINE.score(
        technical,
        drift,
        governance,
        gate_matches=(_gate("HG-CAPCHAIN-001", HardGateFloor.CRITICAL),),
    )

    assert assessment.base_overall_score == 7.8
    assert assessment.hard_gate.floor is HardGateFloor.CRITICAL
    assert assessment.hard_gate.floor_score == 9.0
    assert assessment.overall_score == 9.0
    assert assessment.severity.value == "critical"
    assert assessment.hard_gate.blocks is False


def test_multiple_gates_use_strongest_floor_without_averaging() -> None:
    technical, drift, governance = _scores("baseline", "baseline", mature=True)

    assessment = ENGINE.score(
        technical,
        drift,
        governance,
        gate_matches=(
            _gate("HG-CAPCHAIN-001", HardGateFloor.HIGH),
            _gate("HG-EXTERNALPROD-001", HardGateFloor.CRITICAL),
        ),
    )

    assert assessment.hard_gate.triggered is True
    assert assessment.hard_gate.floor is HardGateFloor.CRITICAL
    assert assessment.overall_score == 9.0
    assert len(assessment.hard_gate.matches) == 2


def test_d_confidence_and_duplicate_gate_ids_are_rejected() -> None:
    with pytest.raises(ValueError):
        _gate(
            "HG-CAPCHAIN-001",
            HardGateFloor.HIGH,
            confidence=EvidenceConfidence.D,
        )

    technical, drift, governance = _scores("baseline", "baseline", mature=True)
    gate = _gate("HG-CAPCHAIN-001", HardGateFloor.HIGH)
    with pytest.raises(OverallScoreError):
        ENGINE.score(
            technical,
            drift,
            governance,
            gate_matches=(gate, gate),
        )


def test_score_component_manifest_binding_is_strict() -> None:
    technical, _, governance = _scores("baseline", "risky-drift")
    _, drift, _ = _scores("baseline", "baseline")

    with pytest.raises(OverallScoreError):
        ENGINE.score(technical, drift, governance)


def test_json_output_is_report_only_and_value_free() -> None:
    technical, drift, governance = _scores("baseline", "baseline", mature=True)
    assessment = ENGINE.score(
        technical,
        drift,
        governance,
        gate_matches=(_gate("HG-CAPCHAIN-001", HardGateFloor.HIGH),),
    )
    encoded = encode_overall_score_json(assessment)
    payload = json.loads(encoded)

    assert payload["format"] == "agentsec-overall-score"
    assert payload["format_version"] == "0.1.0"
    assert payload["hard_gate"]["mode"] == "report_only"
    assert payload["hard_gate"]["blocks"] is False
    assert payload["hard_gate"]["matches"][0]["qualification"] == "accepted"
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded
    assert encoded.endswith("\n")

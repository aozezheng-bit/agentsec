#!/usr/bin/env python3
"""Run the frozen P2-24 scoring replay regression suite."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.domain import EvidenceConfidence
from agentsec.risk import (
    CvssBaseAdapter,
    DeterministicScoringReplayRunner,
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
    ScoringReplayRequest,
    encode_scoring_replay_suite_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = REPOSITORY_ROOT / "demos" / "capability-drift-agent"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "testdata" / "scoring-replay" / "expected.json"


def _manifest(name: str):  # type: ignore[no-untyped-def]
    return (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=DEMO_ROOT / name,
                agent_id="capability-drift-agent",
            )
        )
        .manifest
    )


def _mature_context() -> tuple[DriftScoreContext, GovernanceScoreContext]:
    drift = DriftScoreContext(
        change_source=DriftChangeSource.REVIEWED_CHANGE,
        approval_status=DriftApprovalStatus.APPROVED,
        approval_reference="approval-2026-001",
        deployment_scope=DriftDeploymentScope.LOCAL,
        baseline_trust=DriftBaselineTrust.SIGNED_ATTESTED,
    )
    governance = GovernanceScoreContext(
        drift=drift,
        review_status=GovernanceReviewStatus.APPROVED,
        policy_owner="security-platform",
        approval_owner="release-security",
    )
    return drift, governance


def build_requests() -> tuple[ScoringReplayRequest, ...]:
    baseline = _manifest("baseline")
    risky = _manifest("risky-drift")
    incomplete = _manifest("incomplete")
    remediated = _manifest("remediated")
    mature_drift, mature_governance = _mature_context()
    critical_gate = OverallHardGateMatch(
        gate_id="HG-CAPCHAIN-001",
        floor=HardGateFloor.CRITICAL,
        source=OverallHardGateSource.CAPABILITY,
        qualification=OverallHardGateQualification.ACCEPTED,
        evidence_ids=("capability-finding-sha256:" + "a" * 64,),
        confidence=EvidenceConfidence.B,
        rationale=("Frozen qualified deterministic Gate replay evidence.",),
    )
    cvss = CvssBaseAdapter().adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}
    )
    return (
        ScoringReplayRequest(
            case_id="critical-gate-floor",
            before=baseline,
            after=baseline,
            drift_context=mature_drift,
            governance_context=mature_governance,
            gate_matches=(critical_gate,),
        ),
        ScoringReplayRequest(
            case_id="cvss-high-water",
            before=baseline,
            after=baseline,
            drift_context=mature_drift,
            governance_context=mature_governance,
            cvss=cvss,
        ),
        ScoringReplayRequest(
            case_id="incomplete-coverage",
            before=baseline,
            after=incomplete,
        ),
        ScoringReplayRequest(
            case_id="remediation-drift",
            before=risky,
            after=remediated,
            drift_context=mature_drift,
            governance_context=mature_governance,
        ),
        ScoringReplayRequest(
            case_id="risky-default",
            before=baseline,
            after=risky,
        ),
        ScoringReplayRequest(
            case_id="risky-reviewed",
            before=baseline,
            after=risky,
            drift_context=mature_drift,
            governance_context=mature_governance,
        ),
        ScoringReplayRequest(
            case_id="safe-no-change",
            before=baseline,
            after=baseline,
            drift_context=mature_drift,
            governance_context=mature_governance,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = encode_scoring_replay_suite_json(
        DeterministicScoringReplayRunner().run_suite(build_requests())
    )
    target = args.output or DEFAULT_OUTPUT
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != rendered:
            print(f"Scoring replay mismatch: {target}")
            return 1
        print(f"Scoring replay verified: {target}")
        return 0
    if args.output:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"Scoring replay written: {target}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

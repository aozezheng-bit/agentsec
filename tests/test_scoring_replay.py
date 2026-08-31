"""P2-24 deterministic full scoring replay regression tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.risk import (
    DeterministicScoringReplayRunner,
    DriftApprovalStatus,
    DriftScoreContext,
    GovernanceScoreContext,
    ScoringReplayError,
    ScoringReplayRequest,
    encode_scoring_replay_suite_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED = REPOSITORY_ROOT / "testdata" / "scoring-replay" / "expected.json"
SCRIPT = REPOSITORY_ROOT / "scripts" / "run-scoring-replay.py"


def _manifest(name: str):  # type: ignore[no-untyped-def]
    return (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=(
                    REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
                ),
                agent_id="capability-drift-agent",
            )
        )
        .manifest
    )


def _run_script(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_frozen_scoring_replay_suite_is_current() -> None:
    result = _run_script("--check")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Scoring replay verified" in result.stdout


def test_replay_suite_contains_required_boundary_cases() -> None:
    payload = json.loads(EXPECTED.read_text(encoding="utf-8"))
    cases = {item["case_id"]: item for item in payload["cases"]}

    assert tuple(cases) == tuple(sorted(cases))
    assert set(cases) == {
        "critical-gate-floor",
        "cvss-high-water",
        "incomplete-coverage",
        "remediation-drift",
        "risky-default",
        "risky-reviewed",
        "safe-no-change",
    }
    assert cases["critical-gate-floor"]["overall_score"] == 9.0
    assert cases["critical-gate-floor"]["hard_gate_floor"] == "critical"
    assert cases["cvss-high-water"]["technical_score"] == 9.3
    assert cases["incomplete-coverage"]["coverage_complete"] is False
    assert cases["risky-default"]["overall_score"] == 10.0
    assert cases["risky-reviewed"]["overall_score"] == 5.9
    assert cases["remediation-drift"]["drift_score"] == 2.2


def test_single_case_replay_is_byte_deterministic() -> None:
    request = ScoringReplayRequest(
        case_id="unit-risky",
        before=_manifest("baseline"),
        after=_manifest("risky-drift"),
    )
    runner = DeterministicScoringReplayRunner()

    first = runner.run_suite((request,))
    second = runner.run_suite((request,))

    assert first == second
    assert encode_scoring_replay_suite_json(first) == encode_scoring_replay_suite_json(
        second
    )
    assert first.cases[0].component_hashes == second.cases[0].component_hashes
    assert first.cases[0].replay_sha256 == second.cases[0].replay_sha256


def test_context_changes_only_downstream_replay_components() -> None:
    baseline = _manifest("baseline")
    risky = _manifest("risky-drift")
    default = ScoringReplayRequest(
        case_id="default-context",
        before=baseline,
        after=risky,
    )
    reviewed_drift = DriftScoreContext(
        approval_status=DriftApprovalStatus.APPROVED,
        approval_reference="approval-2026-001",
    )
    reviewed = ScoringReplayRequest(
        case_id="reviewed-context",
        before=baseline,
        after=risky,
        drift_context=reviewed_drift,
        governance_context=GovernanceScoreContext(drift=reviewed_drift),
    )
    runner = DeterministicScoringReplayRunner()

    first = runner.run(default)
    second = runner.run(reviewed)

    assert first.component_hashes.factor_vector == second.component_hashes.factor_vector
    assert (
        first.component_hashes.threat_mitigation
        == second.component_hashes.threat_mitigation
    )
    assert (
        first.component_hashes.technical_score
        == second.component_hashes.technical_score
    )
    assert first.component_hashes.drift_score != second.component_hashes.drift_score
    assert (
        first.component_hashes.governance_score
        != second.component_hashes.governance_score
    )
    assert first.replay_sha256 != second.replay_sha256


def test_replay_rejects_context_mismatch_and_duplicate_case_ids() -> None:
    drift = DriftScoreContext(
        approval_status=DriftApprovalStatus.APPROVED,
        approval_reference="approval-2026-001",
    )
    with pytest.raises(ValueError):
        ScoringReplayRequest(
            case_id="context-mismatch",
            before=_manifest("baseline"),
            after=_manifest("risky-drift"),
            drift_context=drift,
            governance_context=GovernanceScoreContext(),
        )

    request = ScoringReplayRequest(
        case_id="duplicate-case",
        before=_manifest("baseline"),
        after=_manifest("baseline"),
    )
    with pytest.raises(ScoringReplayError):
        DeterministicScoringReplayRunner().run_suite((request, request))


def test_tampered_frozen_output_fails_check(tmp_path: Path) -> None:
    target = tmp_path / "expected.json"
    target.write_text(
        EXPECTED.read_text(encoding="utf-8").replace(
            '"overall_score": 9.0', '"overall_score": 8.9', 1
        ),
        encoding="utf-8",
    )

    result = _run_script("--output", str(target), "--check")

    assert result.returncode == 1
    assert "Scoring replay mismatch" in result.stdout


def test_frozen_output_contains_no_source_secret_values() -> None:
    text = EXPECTED.read_text(encoding="utf-8")

    assert "synthetic-demo-token" not in text
    assert "LOCAL_REVIEW_TOKEN" not in text
    assert "https://example.invalid" not in text
    assert "bearer_token" not in text

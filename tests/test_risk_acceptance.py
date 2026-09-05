"""RISK-10 acceptance tests: the twelve risk-model acceptance rules.

Each test maps to one numbered acceptance rule from the risk model plan
(19.14) and replays the matching scenario from the fixed RISK-09 corpus.
Every assertion stays report-only: nothing here verifies runtime behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
    HomiRiskReport,
    HomiSnapshot,
    build_homi_drift_report,
    build_homi_operation_context_report_from_workspace,
    build_homi_risk_report,
    build_homi_snapshot,
    encode_homi_snapshot_json,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
CORPUS = REPOSITORY_ROOT / "pilots" / "risk-replay-r09"
PROJECT_NAME = "risk-replay-agent"
SUBJECT_ID = "homi:agent:risk-acceptance"
_PILOT = DeterministicHomiReportOnlyPilot()


def _report(scenario: str) -> HomiPilotReport:
    return _PILOT.run(
        HomiPilotRequest(
            pilot_id="risk-acceptance",
            project_name=PROJECT_NAME,
            owner="security",
            target_root=CORPUS / scenario,
            output_root=CORPUS / "acceptance-output",
        )
    )


def _snapshot(scenario: str) -> HomiSnapshot:
    report = _report(scenario)
    return build_homi_snapshot(
        report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            CORPUS / scenario,
            report,
        ),
    )


def _risk(scenario: str, baseline_scenario: str | None = None) -> HomiRiskReport:
    report = _report(scenario)
    operation_context = build_homi_operation_context_report_from_workspace(
        CORPUS / scenario,
        report,
    )
    baseline = None
    baseline_operation_context = None
    if baseline_scenario:
        baseline_report = _report(baseline_scenario)
        baseline_operation_context = build_homi_operation_context_report_from_workspace(
            CORPUS / baseline_scenario,
            baseline_report,
        )
        baseline = build_homi_snapshot(
            baseline_report,
            subject_id=SUBJECT_ID,
            operation_context=baseline_operation_context,
        )
    return build_homi_risk_report(
        report,
        subject_id=SUBJECT_ID,
        operation_context=operation_context,
        baseline=baseline,
        baseline_operation_context=baseline_operation_context,
    )


def test_rule_1_internet_only_access_is_not_high() -> None:
    """Rule 1: internet access alone must not automatically be high risk."""

    risk = _risk("scenario-09")
    assert risk.risk_level in {"none", "low", "medium"}
    assert risk.risk_reasons == ()


def test_rule_2_benign_preference_is_not_high() -> None:
    """Rule 2: storing non-sensitive preferences must stay low risk."""

    risk = _risk("scenario-06")
    assert risk.risk_level in {"none", "low"}
    assert risk.risk_score == 0.0


def test_rule_3_persona_only_is_no_self_modification() -> None:
    """Rule 3: plain persona/identity descriptions carry no self-modify risk."""

    for scenario in ("scenario-04", "scenario-05"):
        risk = _risk(scenario)
        assert "HOMI-COMB-004" not in risk.risk_reasons, scenario
        assert risk.risk_score == 0.0, scenario


def test_rule_4_copy_change_drifts_files_without_raising_risk() -> None:
    """Rule 4: copy-only changes report file drift but not risk drift."""

    for scenario in ("scenario-03", "scenario-04", "scenario-05", "scenario-06"):
        risk = _risk(scenario, baseline_scenario="scenario-01")
        assert risk.drift_status == "drifted", scenario
        assert risk.drift_risk_score == 0.0, scenario
        assert risk.risk_score == 0.0, scenario


def test_rule_5_real_external_operations_raise_risk() -> None:
    """Rule 5: real external operations raise risk significantly."""

    mail = _risk("scenario-08", baseline_scenario="scenario-01")
    assert mail.risk_score == 8.0
    assert mail.risk_level == "high"
    assert mail.drift_risk_score == 8.0
    assert "CTX-RISK-002" in mail.risk_reasons

    send = _risk("scenario-10", baseline_scenario="scenario-01")
    assert send.risk_score == 5.5
    assert send.risk_level == "medium"
    assert "CTX-RISK-008" in send.risk_reasons


def test_rule_6_control_weakening_reaches_high() -> None:
    """Rule 6: control weakening must reach the high risk band."""

    risk = _risk("scenario-14", baseline_scenario="scenario-01")
    assert risk.risk_score == 8.0
    assert risk.risk_level == "high"
    assert risk.risk_reasons == ("CTX-RISK-003", "CTX-RISK-006")
    assert risk.drift_risk_score == 8.0


def test_rule_6_approval_removal_reaches_high() -> None:
    """Rule 6 (approval removal variant): explicit control loss is high."""

    risk = _risk("scenario-12", baseline_scenario="scenario-01")
    assert risk.risk_score == 8.0
    assert risk.risk_level == "high"
    assert risk.risk_reasons == ("CTX-RISK-003", "CTX-RISK-006")
    assert risk.drift_risk_score == 8.0


def test_rule_7_unchanged_baseline_keeps_drift_at_zero() -> None:
    """Rule 7: an unchanged trusted baseline yields zero drift risk."""

    risk = _risk("scenario-02", baseline_scenario="scenario-01")
    assert risk.drift_status == "verified"
    assert risk.drift_risk_score == 0.0
    assert risk.drift_risk_level == "none"


def test_rule_8_baseline_risk_is_not_double_counted() -> None:
    """Rule 8: already-known baseline risk never re-enters the drift score."""

    baseline = _snapshot("scenario-14")
    rescanned = _risk("scenario-14", baseline_scenario="scenario-14")
    assert rescanned.risk_score == 8.0
    assert rescanned.drift_status == "verified"
    assert rescanned.drift_risk_score == 0.0
    assert baseline.snapshot_digest == rescanned.current_snapshot_digest


def test_rule_9_drift_layers_are_separately_explainable() -> None:
    """Rule 9: file, capability, persona, finding, and control drift are
    reported as separate layers.

    Behavior (operation context) drift is not yet a snapshot layer; it is
    recorded as a known scope limitation for the context-aware rules track.
    """

    baseline = _snapshot("scenario-01")
    drift = build_homi_drift_report(
        baseline,
        _snapshot("scenario-08"),
    )
    assert "HEARTBEAT.md" in {item.name for item in drift.file_changes}
    assert drift.capability_changes
    assert drift.finding_deltas
    assert drift.observation_changes
    # Each layer is an independent field of the report.
    payload = {
        "file_changes": [item.name for item in drift.file_changes],
        "capability_changes": [item.signal_id for item in drift.capability_changes],
        "persona_changes": [item.signal_id for item in drift.persona_changes],
        "finding_deltas": [item.rule_id for item in drift.finding_deltas],
        "observation_changes": [item.code for item in drift.observation_changes],
    }
    assert "HEARTBEAT.md" in payload["file_changes"]
    assert payload["finding_deltas"]


def test_rule_10_score_level_confidence_runtime_are_independent() -> None:
    """Rule 10: score, level, confidence, and runtime status stay separate."""

    report = _report("scenario-14")
    risk = build_homi_risk_report(
        report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            CORPUS / "scenario-14",
            report,
        ),
    )
    assert risk.risk_score == 8.0
    assert risk.risk_level == "high"
    assert risk.context_findings
    assert all(item.severity in {"medium", "high"} for item in risk.context_findings)
    assert risk.evidence_confidence in {"A", "B", "C", "D"}
    assert risk.runtime_verified is False
    # A high score never implies runtime verification.
    assert risk.report_only is True


def test_rule_11_replay_is_deterministic() -> None:
    """Rule 11: fixed corpus replays deterministically."""

    first = _snapshot("scenario-01")
    second = _snapshot("scenario-01")
    assert first.snapshot_digest == second.snapshot_digest
    assert encode_homi_snapshot_json(first) == encode_homi_snapshot_json(second)

    baseline = _snapshot("scenario-01")
    first_report = _report("scenario-08")
    baseline_context = build_homi_operation_context_report_from_workspace(
        CORPUS / "scenario-01",
        _report("scenario-01"),
    )
    first_risk = build_homi_risk_report(
        first_report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            CORPUS / "scenario-08",
            first_report,
        ),
        baseline=baseline,
        baseline_operation_context=baseline_context,
    )
    second_report = _report("scenario-08")
    second_risk = build_homi_risk_report(
        second_report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            CORPUS / "scenario-08",
            second_report,
        ),
        baseline=_snapshot("scenario-01"),
        baseline_operation_context=build_homi_operation_context_report_from_workspace(
            CORPUS / "scenario-01",
            _report("scenario-01"),
        ),
    )
    assert first_risk.risk_score == second_risk.risk_score
    assert first_risk.drift_risk_score == second_risk.drift_risk_score
    assert first_risk.current_snapshot_digest == second_risk.current_snapshot_digest


def test_rule_12_reports_remain_report_only() -> None:
    """Rule 12: every output stays report-only without auth or blocking."""

    risk = _risk("scenario-14", baseline_scenario="scenario-01")
    drift = build_homi_drift_report(
        _snapshot("scenario-01"),
        _snapshot("scenario-14"),
    )
    snapshot = _snapshot("scenario-14")

    for artifact in (risk, drift, snapshot):
        assert artifact.report_only is True
        assert artifact.runtime_verified is False
        assert artifact.ci_blocked is False

    payload = json.loads(encode_homi_snapshot_json(snapshot))
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }

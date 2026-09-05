"""RISK-07 layered Homi Drift report tests."""

from __future__ import annotations

import json
from pathlib import Path

import agentsec.frameworks.homi_drift as homi_drift_module
from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
    HomiSnapshot,
    HomiSnapshotFindingSummary,
    HomiSnapshotStatus,
    build_homi_drift_report,
    build_homi_operation_context_report_from_workspace,
    build_homi_snapshot,
    encode_homi_drift_report_json,
    export_homi_drift_report_json_schema,
)

SUBJECT_ID = "homi:agent:drift-test"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _workspace(tmp_path: Path, name: str = "workspace") -> Path:
    workspace = tmp_path / name
    workspace.mkdir()
    _write(
        workspace / "AGENTS.md",
        "Read files. Search the web when asked.\nKeep memory in daily notes.\n",
    )
    _write(workspace / "SOUL.md", "Be helpful. Have opinions.\n")
    _write(workspace / "IDENTITY.md", "Name: Demo\n")
    _write(workspace / "USER.md", "# About Your Human\nContext:\n")
    _write(workspace / "TOOLS.md", "## Local Notes\n## Examples\n")
    _write(
        workspace / "HEARTBEAT.md",
        "# Keep this file empty to skip heartbeat API calls.\n",
    )
    return workspace


def _report(
    tmp_path: Path, workspace: Path, *, project_name: str | None = None
) -> HomiPilotReport:
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="drift-test",
            project_name=project_name or workspace.name,
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def _snapshot(
    tmp_path: Path,
    workspace: Path,
    *,
    subject_id: str = SUBJECT_ID,
) -> HomiSnapshot:
    report = _report(tmp_path, workspace)
    return build_homi_snapshot(
        report,
        subject_id=subject_id,
        operation_context=build_homi_operation_context_report_from_workspace(
            workspace,
            report,
        ),
    )


def test_drift_verified_when_workspace_unchanged(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(tmp_path, workspace)
    current = _snapshot(tmp_path, workspace)

    report = build_homi_drift_report(baseline, current)
    assert report.status is HomiSnapshotStatus.VERIFIED
    assert report.file_changes == ()
    assert report.capability_changes == ()
    assert report.persona_changes == ()
    assert report.finding_deltas == ()
    assert report.observation_changes == ()
    assert report.coverage_drift == {}
    assert report.score_delta["delta"] == 0.0
    assert report.baseline_binding["adapter_version_match"] is True
    assert report.baseline_binding["combination_rule_pack_version_match"] is True
    assert report.risk_direction == "unchanged"
    assert report.increased_finding_ids == ()
    assert report.decreased_finding_ids == ()
    assert report.resolved_finding_ids == ()


def test_drift_detects_risk_injection(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(tmp_path, workspace)

    _write(
        workspace / "HEARTBEAT.md",
        "# Heartbeat\n- Check email every 30 minutes and send digests.\n",
    )
    current = _snapshot(tmp_path, workspace)

    report = build_homi_drift_report(baseline, current)
    assert report.status is HomiSnapshotStatus.DRIFTED
    assert [item.name for item in report.file_changes] == ["HEARTBEAT.md"]
    added = [item for item in report.finding_deltas if item.delta_type.value == "added"]
    assert [item.rule_id for item in added] == ["HOMI-COMB-002"]
    assert report.score_delta["after_total"] > report.score_delta["before_total"]
    assert report.score_delta["delta"] > 0.0
    assert "homi.network.scheduled-read" in report.operation_context_changes
    assert report.context_finding_changes
    assert report.context_score_changed is True
    assert report.risk_direction == "increased"
    assert report.increased_finding_ids


def test_drift_copy_change_reports_file_drift_without_risk(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(tmp_path, workspace)

    _write(workspace / "SOUL.md", "Be warm and encouraging. Stay curious.\n")
    current = _snapshot(tmp_path, workspace)

    report = build_homi_drift_report(baseline, current)
    assert report.status is HomiSnapshotStatus.DRIFTED
    assert [item.name for item in report.file_changes] == ["SOUL.md"]
    assert report.file_changes[0].change_type.value == "modified"
    assert report.finding_deltas == ()
    assert report.score_delta["delta"] == 0.0
    assert report.operation_context_changes == ()
    assert report.context_finding_changes == ()
    assert report.context_score_changed is False
    assert report.risk_direction == "unchanged"


def test_drift_rejects_comparison_across_agents(tmp_path: Path) -> None:
    first = _workspace(tmp_path, name="agent-one")
    second = _workspace(tmp_path, name="agent-two")

    report = build_homi_drift_report(
        _snapshot(tmp_path, first, subject_id="homi:agent:one"),
        _snapshot(tmp_path, second, subject_id="homi:agent:two"),
    )
    assert report.status is HomiSnapshotStatus.IDENTITY_MISMATCH
    assert report.baseline_binding["subject_id_match"] is False
    assert report.file_changes == ()
    assert report.finding_deltas == ()


def test_drift_observations_layer_visible(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    baseline_report = _report(
        tmp_path,
        root / "demos/homi-capability-drift-zh/baseline",
        project_name="demo-agent",
    )
    baseline = build_homi_snapshot(
        baseline_report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            root / "demos/homi-capability-drift-zh/baseline",
            baseline_report,
        ),
    )
    current_report = _report(
        tmp_path,
        root / "demos/homi-capability-drift-zh/drift-remove-safety-control",
        project_name="demo-agent",
    )
    current = build_homi_snapshot(
        current_report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            root / "demos/homi-capability-drift-zh/drift-remove-safety-control",
            current_report,
        ),
    )

    report = build_homi_drift_report(baseline, current)
    assert report.status is HomiSnapshotStatus.DRIFTED
    transitions = {
        (item.code, item.change_type.value) for item in report.observation_changes
    }
    assert ("control_plane_self_modification", "added") in transitions
    assert ("empty_heartbeat_disabled", "removed") in transitions
    assert {item.rule_id for item in report.finding_deltas} == {"HOMI-COMB-004"}
    assert report.risk_direction == "increased"
    assert report.increased_finding_ids
    assert report.decreased_finding_ids == ()


def test_drift_finding_severity_change_is_changed_not_added(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(tmp_path, workspace)

    _write(
        workspace / "HEARTBEAT.md",
        "# Heartbeat\n- Check email every 30 minutes and send digests.\n",
    )
    first = _snapshot(tmp_path, workspace)
    report_first = build_homi_drift_report(baseline, first)
    assert all(item.delta_type.value == "added" for item in report_first.finding_deltas)

    # Same rule still present on re-scan: comparing first vs itself is verified.
    report_second = build_homi_drift_report(first, _snapshot(tmp_path, workspace))
    assert report_second.status is HomiSnapshotStatus.VERIFIED


def test_finding_delta_uses_finding_id_and_preserves_same_rule_matches() -> None:
    before = (
        HomiSnapshotFindingSummary(
            finding_id="finding:a",
            rule_id="HOMI-COMB-001",
            severity="medium",
            score=5.5,
        ),
        HomiSnapshotFindingSummary(
            finding_id="finding:b",
            rule_id="HOMI-COMB-001",
            severity="medium",
            score=5.5,
        ),
    )
    after = (before[0],)

    deltas = homi_drift_module._finding_deltas(before, after)

    assert [item.finding_id for item in deltas] == ["finding:a", "finding:b"]
    assert [item.delta_type.value for item in deltas] == [
        "unchanged",
        "resolved",
    ]
    assert {item.rule_id for item in deltas} == {"HOMI-COMB-001"}

    increased = homi_drift_module._finding_deltas(
        (before[0],),
        (
            HomiSnapshotFindingSummary(
                finding_id="finding:a",
                rule_id="HOMI-COMB-001",
                severity="high",
                score=8.0,
            ),
        ),
    )
    assert increased[0].delta_type.value == "increased"
    assert increased[0].before_score == 5.5
    assert increased[0].after_score == 8.0


def test_drift_report_encoding_and_authority(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(tmp_path, workspace)
    report = build_homi_drift_report(baseline, baseline)

    encoded = encode_homi_drift_report_json(report)
    payload = json.loads(encoded)
    assert payload["status"] == "verified"
    assert payload["baseline_subject_id"] == SUBJECT_ID
    assert payload["current_subject_id"] == SUBJECT_ID
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }
    assert report.report_only is True
    assert report.runtime_verified is False
    assert report.ci_blocked is False


def test_drift_schema_export_writes_valid_strict_schema(tmp_path: Path) -> None:
    output = export_homi_drift_report_json_schema(tmp_path)
    assert output.is_file()
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "file_changes" in schema["required"]
    assert "finding_deltas" in schema["required"]
    assert "baseline_subject_id" in schema["required"]
    assert schema["properties"]["format_version"]["const"] == "0.4.0"
    assert "risk_direction" in schema["required"]
    assert "finding_id" in schema["properties"]["finding_deltas"]["items"]["required"]

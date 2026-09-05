"""RISK-08 unified Homi Risk report tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiOperationContextReport,
    HomiPilotReport,
    HomiPilotRequest,
    HomiRiskReport,
    HomiSnapshot,
    build_homi_operation_context_report_from_workspace,
    build_homi_risk_report,
    build_homi_snapshot,
    encode_homi_operation_context_json,
    encode_homi_risk_report_json,
    encode_homi_snapshot_json,
    export_homi_risk_report_json_schema,
)

runner = CliRunner()
SUBJECT_ID = "homi:agent:risk-test"


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
            pilot_id="risk-test",
            project_name=project_name or workspace.name,
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def _risk_report(
    tmp_path: Path,
    workspace: Path,
    *,
    project_name: str | None = None,
    baseline: HomiSnapshot | None = None,
    baseline_operation_context: HomiOperationContextReport | None = None,
) -> HomiRiskReport:
    pilot_report = _report(tmp_path, workspace, project_name=project_name)
    operation_context = build_homi_operation_context_report_from_workspace(
        workspace,
        pilot_report,
    )
    return build_homi_risk_report(
        pilot_report,
        subject_id=SUBJECT_ID,
        operation_context=operation_context,
        baseline=baseline,
        baseline_operation_context=baseline_operation_context,
    )


def test_risk_default_template_is_low(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report = _risk_report(tmp_path, workspace)

    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert report.risk_reasons == ()
    assert report.potential_impact_score == 0.0
    assert report.residual_risk_score == 0.0
    assert report.current_posture == "not_established"
    assert report.current_posture_score is None
    assert report.evidence_confidence is None
    assert report.context_risk_finding_count == 0
    assert report.context_coverage_finding_count == 1
    assert report.drift_status == "not_established"
    assert report.report_only is True


def _risky_report(tmp_path: Path) -> HomiPilotReport:
    root = Path(__file__).parents[1]
    return _report(
        tmp_path,
        root / "demos/homi-capability-drift-zh/drift-remove-safety-control",
        project_name="demo-agent",
    )


def _clean_snapshot(tmp_path: Path) -> HomiSnapshot:
    workspace = Path(__file__).parents[1] / "demos/homi-capability-drift-zh/baseline"
    report = _report(tmp_path, workspace, project_name="demo-agent")
    return build_homi_snapshot(
        report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            workspace,
            report,
        ),
    )


def test_risk_detects_injected_finding(tmp_path: Path) -> None:
    workspace = (
        Path(__file__).parents[1]
        / "demos/homi-capability-drift-zh/drift-remove-safety-control"
    )
    report = _risk_report(tmp_path, workspace, project_name="demo-agent")

    assert report.risk_score == 8.0
    assert report.risk_level == "high"
    assert report.potential_impact_score == 8.0
    assert report.residual_risk_score == 8.0
    assert report.current_posture == "latent_unverified"
    assert report.evidence_confidence == "D"
    assert report.risk_reasons == ("CTX-RISK-003", "CTX-RISK-006")
    assert report.declaration_signal_score == 8.0
    assert "HOMI-COMB-004" in report.declaration_signal_reasons
    assert {item.rule_id for item in report.context_findings} == {
        "CTX-RISK-003",
        "CTX-RISK-006",
    }
    assert report.suppressed_finding_count == 0


def test_risk_drift_zero_when_baseline_unchanged(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline_report = _report(tmp_path, workspace)
    baseline_context = build_homi_operation_context_report_from_workspace(
        workspace,
        baseline_report,
    )
    baseline = build_homi_snapshot(
        baseline_report,
        subject_id=SUBJECT_ID,
        operation_context=baseline_context,
    )

    report = _risk_report(
        tmp_path,
        workspace,
        baseline=baseline,
        baseline_operation_context=baseline_context,
    )
    assert report.drift_status == "verified"
    assert report.drift_risk_score == 0.0
    assert report.drift_risk_level == "none"
    assert report.drift_direction == "unchanged"
    assert report.drift_reasons == ()


def test_risk_drift_counts_only_new_findings(tmp_path: Path) -> None:
    risky_report = _risky_report(tmp_path)
    baseline_context = build_homi_operation_context_report_from_workspace(
        Path(__file__).parents[1]
        / "demos/homi-capability-drift-zh/drift-remove-safety-control",
        risky_report,
    )
    baseline = build_homi_snapshot(
        risky_report,
        subject_id=SUBJECT_ID,
        operation_context=baseline_context,
    )

    # Same risky workspace re-scanned: the existing risk is not double counted.
    risky_workspace = (
        Path(__file__).parents[1]
        / "demos/homi-capability-drift-zh/drift-remove-safety-control"
    )
    unchanged = _risk_report(
        tmp_path,
        risky_workspace,
        project_name="demo-agent",
        baseline=baseline,
        baseline_operation_context=baseline_context,
    )
    assert unchanged.risk_score == 8.0
    assert unchanged.drift_status == "verified"
    assert unchanged.drift_risk_score == 0.0

    # Escalation from a clean baseline is drift risk.
    operation_context = build_homi_operation_context_report_from_workspace(
        risky_workspace,
        risky_report,
    )
    clean_workspace = (
        Path(__file__).parents[1] / "demos/homi-capability-drift-zh/baseline"
    )
    clean_report = _report(tmp_path, clean_workspace, project_name="demo-agent")
    clean_context = build_homi_operation_context_report_from_workspace(
        clean_workspace,
        clean_report,
    )
    clean_snapshot = build_homi_snapshot(
        clean_report,
        subject_id=SUBJECT_ID,
        operation_context=clean_context,
    )
    escalated = build_homi_risk_report(
        risky_report,
        subject_id=SUBJECT_ID,
        operation_context=operation_context,
        baseline=clean_snapshot,
        baseline_operation_context=clean_context,
    )
    assert escalated.drift_status == "drifted"
    assert escalated.drift_risk_score == 8.0
    assert escalated.drift_risk_level == "high"
    assert escalated.drift_direction == "increased"
    assert escalated.drift_reasons == ("CTX-RISK-003", "CTX-RISK-006")
    assert escalated.increased_finding_ids
    assert escalated.decreased_finding_ids == ()
    assert escalated.resolved_finding_ids == ()
    assert escalated.control_strengthening_count == 0


def test_risk_drift_rejects_cross_agent(tmp_path: Path) -> None:
    first = _workspace(tmp_path, name="agent-one")
    second = _workspace(tmp_path, name="agent-two")

    report = build_homi_risk_report(
        second_report := _report(tmp_path, second),
        subject_id="homi:agent:two",
        operation_context=build_homi_operation_context_report_from_workspace(
            second,
            second_report,
        ),
        baseline=build_homi_snapshot(
            first_report := _report(tmp_path, first),
            subject_id="homi:agent:one",
            operation_context=build_homi_operation_context_report_from_workspace(
                first,
                first_report,
            ),
        ),
    )
    assert report.drift_status == "identity_mismatch"
    assert report.drift_risk_score is None
    assert report.drift_risk_level is None
    assert report.drift_reasons == ()


def test_risk_reports_layer_counts(tmp_path: Path) -> None:
    workspace = (
        Path(__file__).parents[1]
        / "demos/homi-capability-drift-zh/drift-remove-safety-control"
    )
    report = _risk_report(
        tmp_path,
        workspace,
        project_name="demo-agent",
        baseline=_clean_snapshot(tmp_path),
    )

    assert report.file_change_count >= 1
    assert report.finding_delta_count == 1
    assert report.baseline_snapshot_digest is not None
    assert isinstance(report.current_snapshot_digest, str)


def test_risk_snapshot_type_guard(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    with pytest.raises(TypeError):
        build_homi_risk_report(
            pilot_report := _report(tmp_path, workspace),
            subject_id=SUBJECT_ID,
            operation_context=build_homi_operation_context_report_from_workspace(
                workspace,
                pilot_report,
            ),
            baseline="not a snapshot",
        )


def test_risk_encoding_authority_and_schema(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report = _risk_report(tmp_path, workspace)

    payload = json.loads(encode_homi_risk_report_json(report))
    assert payload["subject_id"] == SUBJECT_ID
    assert payload["risk_score"] == 0.0
    assert payload["risk_basis"] == "operation_context_residual_risk"
    assert payload["potential_impact_score"] == 0.0
    assert payload["residual_risk_score"] == 0.0
    assert payload["current_posture_score"] is None
    assert payload["context_coverage_complete"] is False
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "policy_authority": False,
        "ci_blocked": False,
    }
    assert payload["limitations"]
    assert report.ci_blocked is False

    output = export_homi_risk_report_json_schema(tmp_path)
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert "risk_score" in schema["required"]
    assert "potential_impact_score" in schema["required"]
    assert "context_findings" in schema["required"]
    assert "drift_risk_score" in schema["required"]
    assert "subject_id" in schema["required"]
    assert schema["properties"]["format_version"]["const"] == "0.5.0"


def test_risk_rejects_context_from_different_pilot(tmp_path: Path) -> None:
    first = _workspace(tmp_path, name="first")
    second = _workspace(tmp_path, name="second")
    _write(second / "SOUL.md", "Different baseline evidence.\n")
    first_report = _report(tmp_path, first)
    second_report = _report(tmp_path, second)
    wrong_context = build_homi_operation_context_report_from_workspace(
        first,
        first_report,
    )

    with pytest.raises(ValueError, match="not bound"):
        build_homi_risk_report(
            second_report,
            subject_id=SUBJECT_ID,
            operation_context=wrong_context,
        )


def test_risk_rejects_context_baseline_not_bound_to_snapshot(tmp_path: Path) -> None:
    first = _workspace(tmp_path, name="first")
    second = _workspace(tmp_path, name="second")
    _write(second / "SOUL.md", "Different baseline evidence.\n")
    current_report = _report(tmp_path, first, project_name="same-agent")
    baseline_report = _report(tmp_path, first, project_name="same-agent")
    wrong_baseline_report = _report(tmp_path, second, project_name="same-agent")

    with pytest.raises(ValueError, match="not bound to baseline Snapshot"):
        build_homi_risk_report(
            current_report,
            subject_id=SUBJECT_ID,
            operation_context=build_homi_operation_context_report_from_workspace(
                first,
                current_report,
            ),
            baseline=build_homi_snapshot(
                baseline_report,
                subject_id=SUBJECT_ID,
                operation_context=build_homi_operation_context_report_from_workspace(
                    first,
                    baseline_report,
                ),
            ),
            baseline_operation_context=(
                build_homi_operation_context_report_from_workspace(
                    second,
                    wrong_baseline_report,
                )
            ),
        )


def test_homi_risk_cli_runs_context_chain_and_accepts_bound_baseline(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    baseline_workspace = root / "demos/homi-capability-drift-zh/baseline"
    current_workspace = (
        root / "demos/homi-capability-drift-zh/drift-remove-safety-control"
    )
    baseline_report = _report(
        tmp_path,
        baseline_workspace,
        project_name="demo-agent",
    )
    baseline_context = build_homi_operation_context_report_from_workspace(
        baseline_workspace,
        baseline_report,
    )
    baseline_snapshot = build_homi_snapshot(
        baseline_report,
        subject_id=SUBJECT_ID,
        operation_context=baseline_context,
    )
    snapshot_path = tmp_path / "baseline-snapshot.json"
    context_path = tmp_path / "baseline-operation-context.json"
    snapshot_path.write_text(
        encode_homi_snapshot_json(baseline_snapshot),
        encoding="utf-8",
    )
    context_path.write_text(
        encode_homi_operation_context_json(baseline_context),
        encoding="utf-8",
    )

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "risk",
            str(current_workspace),
            "--project-name",
            "demo-agent",
            "--subject-id",
            SUBJECT_ID,
            "--baseline",
            str(snapshot_path),
            "--baseline-context",
            str(context_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["risk_basis"] == "operation_context_residual_risk"
    assert payload["subject_id"] == SUBJECT_ID
    assert payload["risk_score"] == 8.0
    assert payload["drift_direction"] == "increased"
    assert payload["drift_risk_score"] == 8.0
    assert payload["declaration_signal_score"] == 8.0


def test_snapshot_cli_sidecar_binds_risk_cli_baseline(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    baseline_workspace = root / "pilots" / "risk-replay-r09" / "scenario-01"
    current_workspace = root / "pilots" / "risk-replay-r09" / "scenario-08"
    snapshot_path = tmp_path / "baseline.json"

    created = runner.invoke(
        create_app(),
        [
            "homi",
            "snapshot",
            "create",
            str(baseline_workspace),
            "--subject-id",
            SUBJECT_ID,
            "--output",
            str(snapshot_path),
            "--force",
        ],
    )
    assert created.exit_code == 0, created.output
    context_path = tmp_path / "homi-operation-context.json"
    assert context_path.is_file()

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "risk",
            str(current_workspace),
            "--subject-id",
            SUBJECT_ID,
            "--baseline",
            str(snapshot_path),
            "--baseline-context",
            str(context_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["risk_score"] == 8.0
    assert payload["drift_risk_score"] == 8.0
    assert payload["drift_direction"] == "increased"


def test_homi_risk_cli_requires_snapshot_with_context_baseline(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    pilot_report = _report(tmp_path, workspace)
    context_path = tmp_path / "baseline-operation-context.json"
    context_path.write_text(
        encode_homi_operation_context_json(
            build_homi_operation_context_report_from_workspace(
                workspace,
                pilot_report,
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "risk",
            str(workspace),
            "--subject-id",
            SUBJECT_ID,
            "--baseline-context",
            str(context_path),
        ],
    )

    assert result.exit_code != 0
    assert "requires --baseline" in result.output


def test_risk_snapshot_helper_type_is_reexported() -> None:
    # The snapshot type stays importable from the frameworks package surface.
    assert HomiSnapshot is not None

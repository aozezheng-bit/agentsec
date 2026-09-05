"""RISK-06 Homi Agent Snapshot contract tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
    HomiSnapshot,
    HomiSnapshotStatus,
    build_homi_operation_context_report_from_workspace,
    build_homi_snapshot,
    decode_homi_snapshot_json,
    encode_homi_snapshot_json,
    export_homi_snapshot_json_schema,
    verify_homi_snapshot,
)

SUBJECT_ID = "homi:agent:snapshot-test"


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
    tmp_path: Path,
    workspace: Path,
    *,
    pilot_id: str = "snapshot-test",
    owner: str = "security",
    project_name: str | None = None,
) -> HomiPilotReport:
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id=pilot_id,
            project_name=project_name or workspace.name,
            owner=owner,
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def _snapshot(
    workspace: Path,
    report: HomiPilotReport,
    *,
    subject_id: str = SUBJECT_ID,
) -> HomiSnapshot:
    return build_homi_snapshot(
        report,
        subject_id=subject_id,
        operation_context=build_homi_operation_context_report_from_workspace(
            workspace,
            report,
        ),
    )


def test_snapshot_is_deterministic_and_ignores_session_metadata(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)

    first = _snapshot(workspace, _report(tmp_path, workspace, pilot_id="pilot-a"))
    second = _snapshot(workspace, _report(tmp_path, workspace, pilot_id="pilot-b"))

    assert first.snapshot_digest == second.snapshot_digest
    assert first.workspace_fingerprint == second.workspace_fingerprint
    assert first.pilot_id == "pilot-a"
    assert second.pilot_id == "pilot-b"
    assert first.canonical_payload() == second.canonical_payload()
    # Session-bound fields (pilot_id, source report digest) stay in the
    # artifact for audit but never affect the snapshot digest.
    first_json = json.loads(encode_homi_snapshot_json(first))
    second_json = json.loads(encode_homi_snapshot_json(second))
    assert first_json["pilot_id"] == "pilot-a"
    assert second_json["pilot_id"] == "pilot-b"
    assert first_json["subject_id"] == SUBJECT_ID
    assert first_json["snapshot_digest"] == second_json["snapshot_digest"]
    assert "source_report_sha256" in first_json


def test_snapshot_binds_source_report_and_engine_versions(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report = _report(tmp_path, workspace)
    snapshot = _snapshot(workspace, report)

    from agentsec.frameworks.homi_pilot import encode_homi_pilot_json

    expected = hashlib.sha256(
        encode_homi_pilot_json(report).encode("utf-8")
    ).hexdigest()
    assert snapshot.source_report_sha256 == expected
    assert snapshot.adapter_version == report.adapter_version
    assert snapshot.profile_model_version == report.profile_model_version
    assert (
        snapshot.combination_rule_pack_version
        == report.combination_result.rule_pack_version
    )


def test_snapshot_covers_files_capabilities_and_findings(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    snapshot = _snapshot(workspace, _report(tmp_path, workspace))

    names = {item.name for item in snapshot.files}
    assert names == {
        "AGENTS.md",
        "HEARTBEAT.md",
        "IDENTITY.md",
        "SOUL.md",
        "TOOLS.md",
        "USER.md",
    }
    assert snapshot.capabilities
    assert snapshot.findings == ()
    assert snapshot.operation_contexts
    assert snapshot.context_findings
    assert snapshot.context_score.potential_impact_score == 0.0
    assert snapshot.context_score.residual_risk_score == 0.0
    assert snapshot.operation_context_sha256 != snapshot.context_risk_report_sha256
    assert snapshot.context_score_report_sha256
    assert snapshot.coverage_metrics["standard_file_total"] == 6
    assert snapshot.workspace_fingerprint != snapshot.snapshot_digest


def test_snapshot_content_change_changes_digest(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    before = _snapshot(workspace, _report(tmp_path, workspace))

    _write(
        workspace / "AGENTS.md",
        "Read files. Send email automatically every hour.\nKeep memory.\n",
    )
    after = _snapshot(workspace, _report(tmp_path, workspace))

    assert before.workspace_fingerprint != after.workspace_fingerprint
    assert before.snapshot_digest != after.snapshot_digest


def test_snapshot_rejects_operation_context_from_different_pilot(
    tmp_path: Path,
) -> None:
    first = _workspace(tmp_path, name="first")
    second = _workspace(tmp_path, name="second")
    _write(second / "AGENTS.md", "Different workspace operation declaration.\n")
    first_report = _report(tmp_path, first)
    second_report = _report(tmp_path, second)
    wrong_context = build_homi_operation_context_report_from_workspace(
        first,
        first_report,
    )

    with pytest.raises(ValueError, match="not bound"):
        build_homi_snapshot(
            second_report,
            subject_id=SUBJECT_ID,
            operation_context=wrong_context,
        )


def test_snapshot_context_summaries_do_not_copy_raw_source_values(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    marker = "never-copy-this-private-value-4f93"
    _write(
        workspace / "AGENTS.md",
        f"Read workspace files for analysis. Private note: {marker}.\n",
    )
    snapshot = _snapshot(workspace, _report(tmp_path, workspace))
    encoded = encode_homi_snapshot_json(snapshot)

    assert marker not in encoded
    assert snapshot.operation_contexts
    assert all(item.evidence_ids for item in snapshot.operation_contexts)


def test_encode_decode_roundtrip_and_tampering_is_rejected(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    snapshot = _snapshot(workspace, _report(tmp_path, workspace))

    encoded = encode_homi_snapshot_json(snapshot)
    decoded = decode_homi_snapshot_json(encoded)
    assert decoded == snapshot

    payload = json.loads(encoded)
    tampered = dict(payload)
    tampered["files"] = [
        dict(item, content_sha256="0" * 64) for item in payload["files"]
    ]
    with pytest.raises(ValueError, match="digest"):
        decode_homi_snapshot_json(json.dumps(tampered))

    tampered_score = dict(payload)
    tampered_score["context_score"] = dict(
        payload["context_score"],
        potential_impact_score=7.0,
        residual_risk_score=7.0,
        potential_impact_level="high",
        residual_risk_level="high",
    )
    with pytest.raises(ValueError, match="digest"):
        decode_homi_snapshot_json(json.dumps(tampered_score))

    with pytest.raises(ValueError, match="format"):
        decode_homi_snapshot_json(json.dumps({"format": "other"}))

    legacy = dict(payload)
    legacy.pop("subject_id")
    with pytest.raises(ValueError, match="subject_id"):
        decode_homi_snapshot_json(json.dumps(legacy))


def test_verify_reports_verified_for_identical_workspaces(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(workspace, _report(tmp_path, workspace))
    current = _snapshot(workspace, _report(tmp_path, workspace))

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.VERIFIED
    assert verification.file_changes == ()
    assert verification.findings_added == ()
    assert verification.findings_removed == ()
    assert verification.report_only is True


def test_verify_reports_drift_for_changed_workspace(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(workspace, _report(tmp_path, workspace))

    _write(
        workspace / "HEARTBEAT.md",
        "# Heartbeat\n- Check email every 30 minutes and send digests.\n",
    )
    current = _snapshot(workspace, _report(tmp_path, workspace))

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.DRIFTED
    assert "HEARTBEAT.md" in verification.file_changes
    assert verification.findings_added == ("HOMI-COMB-002",)


def test_verify_rejects_comparison_across_agents(tmp_path: Path) -> None:
    first_workspace = _workspace(tmp_path, name="agent-one")
    second_workspace = _workspace(tmp_path, name="agent-two")

    baseline = _snapshot(
        first_workspace,
        _report(tmp_path, first_workspace, project_name="same-display-name"),
        subject_id="homi:agent:one",
    )
    current = _snapshot(
        second_workspace,
        _report(tmp_path, second_workspace, project_name="same-display-name"),
        subject_id="homi:agent:two",
    )

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.IDENTITY_MISMATCH
    assert verification.file_changes == ()
    assert verification.baseline_subject_id == "homi:agent:one"
    assert verification.current_subject_id == "homi:agent:two"


def test_verify_uses_subject_id_not_project_name_or_file_set(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = _snapshot(
        workspace,
        _report(tmp_path, workspace, project_name="Old Display Name"),
        subject_id=SUBJECT_ID,
    )

    (workspace / "TOOLS.md").unlink()
    current = _snapshot(
        workspace,
        _report(tmp_path, workspace, project_name="New Display Name"),
        subject_id=SUBJECT_ID,
    )

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.DRIFTED
    assert verification.baseline_subject_id == SUBJECT_ID
    assert verification.current_subject_id == SUBJECT_ID
    assert "TOOLS.md" in verification.file_changes


def test_subject_id_is_digest_bound_and_never_inferred(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report = _report(tmp_path, workspace)
    first = _snapshot(workspace, report, subject_id="homi:agent:one")
    second = _snapshot(workspace, report, subject_id="homi:agent:two")

    assert first.subject_id == "homi:agent:one"
    assert first.snapshot_digest != second.snapshot_digest
    assert first.workspace_fingerprint == second.workspace_fingerprint

    renamed = _snapshot(
        workspace,
        _report(tmp_path, workspace, project_name="New Display Name"),
        subject_id="homi:agent:one",
    )
    assert renamed.snapshot_digest == first.snapshot_digest

    with pytest.raises(TypeError):
        build_homi_snapshot(report)
    with pytest.raises(ValueError, match="subject_id"):
        build_homi_snapshot(
            report,
            subject_id="invalid subject id",
            operation_context=build_homi_operation_context_report_from_workspace(
                workspace,
                report,
            ),
        )


def test_authority_boundary_is_enforced(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    snapshot = _snapshot(workspace, _report(tmp_path, workspace))

    assert snapshot.report_only is True
    assert snapshot.runtime_verified is False
    assert snapshot.ci_blocked is False

    payload = snapshot.to_dict()
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }

    with pytest.raises(TypeError):
        build_homi_snapshot("not a report", subject_id=SUBJECT_ID)


def test_schema_export_writes_valid_strict_schema(tmp_path: Path) -> None:
    output = export_homi_snapshot_json_schema(tmp_path)
    assert output.is_file()
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "snapshot_digest" in schema["required"]
    assert "subject_id" in schema["required"]
    assert "operation_contexts" in schema["required"]
    assert "context_findings" in schema["required"]
    assert "context_score" in schema["required"]
    assert schema["properties"]["format_version"]["const"] == "0.3.0"

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
    HomiSnapshotStatus,
    build_homi_snapshot,
    decode_homi_snapshot_json,
    encode_homi_snapshot_json,
    export_homi_snapshot_json_schema,
    verify_homi_snapshot,
)


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
) -> HomiPilotReport:
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id=pilot_id,
            project_name=workspace.name,
            owner=owner,
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def test_snapshot_is_deterministic_and_ignores_session_metadata(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)

    first = build_homi_snapshot(_report(tmp_path, workspace, pilot_id="pilot-a"))
    second = build_homi_snapshot(_report(tmp_path, workspace, pilot_id="pilot-b"))

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
    assert first_json["snapshot_digest"] == second_json["snapshot_digest"]
    assert "source_report_sha256" in first_json


def test_snapshot_binds_source_report_and_engine_versions(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report = _report(tmp_path, workspace)
    snapshot = build_homi_snapshot(report)

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
    snapshot = build_homi_snapshot(_report(tmp_path, workspace))

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
    assert snapshot.coverage_metrics["standard_file_total"] == 6
    assert snapshot.workspace_fingerprint != snapshot.snapshot_digest


def test_snapshot_content_change_changes_digest(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    before = build_homi_snapshot(_report(tmp_path, workspace))

    _write(
        workspace / "AGENTS.md",
        "Read files. Send email automatically every hour.\nKeep memory.\n",
    )
    after = build_homi_snapshot(_report(tmp_path, workspace))

    assert before.workspace_fingerprint != after.workspace_fingerprint
    assert before.snapshot_digest != after.snapshot_digest


def test_encode_decode_roundtrip_and_tampering_is_rejected(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    snapshot = build_homi_snapshot(_report(tmp_path, workspace))

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

    with pytest.raises(ValueError, match="format"):
        decode_homi_snapshot_json(json.dumps({"format": "other"}))


def test_verify_reports_verified_for_identical_workspaces(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = build_homi_snapshot(_report(tmp_path, workspace))
    current = build_homi_snapshot(_report(tmp_path, workspace))

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.VERIFIED
    assert verification.file_changes == ()
    assert verification.findings_added == ()
    assert verification.findings_removed == ()
    assert verification.report_only is True


def test_verify_reports_drift_for_changed_workspace(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    baseline = build_homi_snapshot(_report(tmp_path, workspace))

    _write(
        workspace / "HEARTBEAT.md",
        "# Heartbeat\n- Check email every 30 minutes and send digests.\n",
    )
    current = build_homi_snapshot(_report(tmp_path, workspace))

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.DRIFTED
    assert "HEARTBEAT.md" in verification.file_changes
    assert verification.findings_added == ("HOMI-COMB-002",)


def test_verify_rejects_comparison_across_agents(tmp_path: Path) -> None:
    first_workspace = _workspace(tmp_path, name="agent-one")
    second_workspace = _workspace(tmp_path, name="agent-two")

    baseline = build_homi_snapshot(_report(tmp_path, first_workspace))
    current = build_homi_snapshot(_report(tmp_path, second_workspace))

    verification = verify_homi_snapshot(baseline, current)
    assert verification.status is HomiSnapshotStatus.IDENTITY_MISMATCH
    assert verification.file_changes == ()


def test_authority_boundary_is_enforced(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    snapshot = build_homi_snapshot(_report(tmp_path, workspace))

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
        build_homi_snapshot("not a report")


def test_schema_export_writes_valid_strict_schema(tmp_path: Path) -> None:
    output = export_homi_snapshot_json_schema(tmp_path)
    assert output.is_file()
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "snapshot_digest" in schema["required"]

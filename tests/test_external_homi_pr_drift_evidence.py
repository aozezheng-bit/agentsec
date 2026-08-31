"""P2-EXIT-06-03 Homi PR/change drift evidence tests."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotRequest,
    encode_homi_pilot_json,
)

ROOT = Path(__file__).resolve().parents[1]
PILOT_ROOT = ROOT / "pilots" / "external-homi-demo"
EVIDENCE_ROOT = PILOT_ROOT / "pr-change-evidence"
AGGREGATE = EVIDENCE_ROOT / "evidence" / "pr-change-evidence.json"
CLI_REPORT = EVIDENCE_ROOT / "evidence" / "pr-07-cli-validation-report.json"
BASELINE_REPORT = PILOT_ROOT / "results" / "baseline-01" / "homi-pilot-report.json"
FORBIDDEN_VALUES = (
    "192.168.1.100",
    "mdn.alipayobjects.com",
    "prod-bastion.internal",
    "release.write",
    "deployment-token",
    "internal-ops-mcp",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _aggregate() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(AGGREGATE.read_text(encoding="utf-8"))
    return payload


def test_pr_change_aggregate_is_complete_engineering_evidence_only() -> None:
    payload = _aggregate()
    metrics = payload["metrics"]
    review = payload["review"]

    assert payload["format"] == "agentsec-external-homi-pr-change-evidence"
    assert payload["format_version"] == "0.1.0"
    assert payload["task_id"] == "P2-EXIT-06-03"
    assert payload["acceptance_ready"] is False
    assert metrics["scenario_count"] == 10
    assert metrics["pull_request_snapshot_count"] == 10
    assert metrics["contract_pass_count"] == 10
    assert metrics["runtime_execution_count"] == 0
    assert metrics["side_effect_count"] == 0
    assert metrics["ci_block_count"] == 0
    assert review["engineering_review_complete"] is True
    assert review["independent_human_review"] is False
    assert review["tp_fp_fn_complete"] is False
    assert review["calibration_required_scenarios"] == []
    assert metrics["calibration_required_count"] == 0


def test_each_pr_snapshot_report_and_drift_has_pinned_provenance() -> None:
    payload = _aggregate()
    baseline_sha256 = _sha256(BASELINE_REPORT)

    for item in payload["scenarios"]:
        snapshot = EVIDENCE_ROOT / item["snapshot_path"]
        report = EVIDENCE_ROOT / item["report_path"]
        drift = EVIDENCE_ROOT / item["drift_path"]
        assert _sha256(snapshot) == item["snapshot_sha256"]
        assert _sha256(report) == item["report_sha256"]
        assert _sha256(drift) == item["drift_sha256"]
        drift_payload = json.loads(drift.read_text(encoding="utf-8"))
        assert drift_payload["format"] == "agentsec-homi-capability-drift-evidence"
        assert drift_payload["review"]["contract_pass"] is True
        assert drift_payload["expected"] == drift_payload["actual"]
        assert drift_payload["provenance"]["baseline_report_sha256"] == (
            baseline_sha256
        )
        assert (
            drift_payload["provenance"]["snapshot_archive_sha256"]
            == (item["snapshot_sha256"])
        )
        assert (
            drift_payload["provenance"]["snapshot_report_sha256"]
            == (item["report_sha256"])
        )


def test_snapshot_archives_are_flat_safe_utf8_homi_exports() -> None:
    payload = _aggregate()

    for item in payload["scenarios"]:
        snapshot = EVIDENCE_ROOT / item["snapshot_path"]
        with zipfile.ZipFile(snapshot) as bundle:
            names = bundle.namelist()
            expected_count = (
                5 if item["scenario_id"] == "pr-10-tools-coverage-missing" else 6
            )
            assert len(names) == expected_count
            for info in bundle.infolist():
                path = PurePosixPath(info.filename)
                assert not path.is_absolute()
                assert ".." not in path.parts
                assert not stat.S_ISLNK(info.external_attr >> 16)
                bundle.read(info).decode("utf-8")
            if item["scenario_id"] == "pr-10-tools-coverage-missing":
                assert "TOOLS.md" not in names


def test_all_pr_reports_preserve_report_only_and_value_minimization() -> None:
    payload = _aggregate()

    for item in payload["scenarios"]:
        report_path = EVIDENCE_ROOT / item["report_path"]
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
        assert report["report_only"] is True
        assert report["runtime_verified"] is False
        assert report["ci_blocked"] is False
        assert report["acceptance_ready"] is False
        assert report["simulation"]["executed"] is False
        assert report["simulation"]["side_effects"] is False
        assert report["simulation"]["runtime_verified"] is False
        assert "/private/tmp/agentsec-p2-exit-06-03-homi-pr-demo" not in report_text
        assert not any(value in report_text for value in FORBIDDEN_VALUES)


def test_representative_risky_and_coverage_drifts_are_visible() -> None:
    pr_03 = json.loads(
        (EVIDENCE_ROOT / "drift" / "pr-03-real-heartbeat-activation.json").read_text(
            encoding="utf-8"
        )
    )
    pr_07 = json.loads(
        (EVIDENCE_ROOT / "drift" / "pr-07-activate-mcp-oauth-secret.json").read_text(
            encoding="utf-8"
        )
    )
    pr_10 = json.loads(
        (EVIDENCE_ROOT / "drift" / "pr-10-tools-coverage-missing.json").read_text(
            encoding="utf-8"
        )
    )

    assert pr_03["review"]["outcome"] == "contract_pass"
    assert pr_03["actual"]["capability_changes"] == {
        "heartbeat_schedule": ["example_only", "present"]
    }
    assert pr_03["actual"]["file_changes"] == {"HEARTBEAT.md": "modified"}
    assert pr_03["actual"]["added_findings"] == ["HOMI-COMB-002"]
    assert pr_03["actual"]["simulation_changes"] == {
        "HOMI-SIM-001": ["blocked_example_only", "declared_path"]
    }
    assert pr_07["actual"]["added_findings"] == ["HOMI-COMB-005"]
    assert pr_07["actual"]["capability_changes"]["mcp_access"] == [
        "unknown",
        "conditional",
    ]
    assert pr_07["actual"]["capability_changes"]["oauth_access"] == [
        "unknown",
        "conditional",
    ]
    assert pr_07["actual"]["capability_changes"]["secret_access"] == [
        "unknown",
        "conditional",
    ]
    assert pr_07["actual"]["changed_findings"] == ["HOMI-COMB-001"]
    assert pr_10["drill"] == "incomplete_coverage"
    assert pr_10["actual"]["file_changes"]["TOOLS.md"] == "removed"
    assert pr_10["actual"]["simulation_changes"]["HOMI-SIM-005"] == [
        "blocked_example_only",
        "unknown_coverage",
    ]


def test_pr_07_cli_and_api_reports_are_byte_identical() -> None:
    api_report = (
        EVIDENCE_ROOT
        / "results"
        / "pr-07-activate-mcp-oauth-secret"
        / "homi-pilot-report.json"
    )
    assert CLI_REPORT.read_bytes() == api_report.read_bytes()


def test_pr_07_archive_replays_to_same_report(tmp_path: Path) -> None:
    snapshot = EVIDENCE_ROOT / "snapshots" / "pr-07-activate-mcp-oauth-secret.zip"
    target = tmp_path / "pr-07"
    target.mkdir()
    with zipfile.ZipFile(snapshot) as bundle:
        for name in bundle.namelist():
            (target / name).write_bytes(bundle.read(name))
    report = DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="pr-07-activate-mcp-oauth-secret",
            project_name="Homi PR Snapshot pr-07-activate-mcp-oauth-secret",
            owner="homi-agent-platform-owner",
            target_root=target,
            output_root=tmp_path / "output",
        )
    )
    persisted = (
        EVIDENCE_ROOT
        / "results"
        / "pr-07-activate-mcp-oauth-secret"
        / "homi-pilot-report.json"
    )

    assert encode_homi_pilot_json(report) == persisted.read_text(encoding="utf-8")

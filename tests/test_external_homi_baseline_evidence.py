"""P2-EXIT-06-02 user-supplied Homi baseline evidence tests."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotRequest,
    encode_homi_pilot_json,
)

ROOT = Path(__file__).resolve().parents[1]
PILOT_ROOT = ROOT / "pilots" / "external-homi-demo"
ARCHIVE = PILOT_ROOT / "source" / "workspace-files-20260826.zip"
EVIDENCE = PILOT_ROOT / "evidence" / "baseline-evidence.json"
REPORT = PILOT_ROOT / "results" / "baseline-01" / "homi-pilot-report.json"
CLI_REPORT = PILOT_ROOT / "evidence" / "cli-validation-report.json"
STANDARD_FILES = {
    "AGENTS.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "SOUL.md",
    "TOOLS.md",
    "USER.md",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_baseline_evidence_preserves_source_provenance_without_authority() -> None:
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["format"] == "agentsec-external-homi-baseline-evidence"
    assert payload["format_version"] == "0.1.0"
    assert payload["task_id"] == "P2-EXIT-06-02"
    assert payload["source"]["archive_sha256"] == _sha256(ARCHIVE)
    assert payload["source"]["untrusted_input"] is True
    assert payload["source"]["instruction_authority"] is False
    assert payload["workspace"]["deployed_inert"] is True
    assert set(payload["workspace"]["standard_files"]) == STANDARD_FILES
    assert payload["review"]["independent_human_labels_complete"] is False
    assert payload["review"]["tp_fp_fn_complete"] is False
    assert payload["validation"]["api_cli_byte_identical"] is True
    assert payload["validation"]["cli_report_sha256"] == _sha256(CLI_REPORT)
    assert payload["validation"]["heartbeat_template_calibration"] == "pass"


def test_source_zip_contains_exact_bounded_homi_workspace() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    expected_hashes = evidence["workspace"]["file_sha256"]

    with zipfile.ZipFile(ARCHIVE) as bundle:
        assert set(bundle.namelist()) == STANDARD_FILES
        assert len(bundle.infolist()) == 6
        for name in STANDARD_FILES:
            data = bundle.read(name)
            data.decode("utf-8")
            assert len(data) <= 2 * 1024 * 1024
            assert hashlib.sha256(data).hexdigest() == expected_hashes[name]


def test_report_is_value_minimized_report_only_and_conflict_visible() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report_text = REPORT.read_text(encoding="utf-8")
    report = json.loads(report_text)

    assert evidence["report"]["sha256"] == _sha256(REPORT)
    assert report["format"] == "agentsec-homi-report-only-pilot"
    assert report["format_version"] == "0.2.0"
    assert report["adapter_version"] == "0.2.0"
    assert report["profile_model_version"] == "0.2.0"
    assert report["status"] == "partial"
    assert report["inspection_complete"] is True
    assert report["profile_complete"] is False
    assert report["all_standard_files_present"] is True
    assert report["resolution_status"] == "conflict"
    assert report["report_only"] is True
    assert report["runtime_verified"] is False
    assert report["ci_blocked"] is False
    assert report["acceptance_ready"] is False
    assert report["heartbeat"]["state"] == "example_only"
    assert report["heartbeat"]["tasks_present"] is False
    assert report["heartbeat"]["api_calls_enabled_by_file"] is False
    assert report["simulation"]["executed"] is False
    assert report["simulation"]["side_effects"] is False
    assert report["simulation"]["runtime_verified"] is False
    assert "/private/tmp/agentsec-p2-exit-06-02-homi-demo" not in report_text
    assert "192.168.1.100" not in report_text
    assert "mdn.alipayobjects.com" not in report_text


def test_baseline_findings_and_conflict_are_deterministic() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))

    assert {item["code"] for item in report["observations"]} >= {
        "startup_read_policy_conflict",
        "control_plane_self_modification",
        "tools_not_authority",
        "user_profile_main_session_only",
    }
    assert {item["rule_id"] for item in report["combination"]["findings"]} == {
        "HOMI-COMB-001",
        "HOMI-COMB-003",
        "HOMI-COMB-004",
    }
    assert report["combination"]["failures"] == []
    assert len(report["simulation"]["steps"]) == 5
    heartbeat_simulation = next(
        item
        for item in report["simulation"]["steps"]
        if item["scenario_id"] == "HOMI-SIM-001"
    )
    assert heartbeat_simulation["outcome"] == "blocked_example_only"


def test_cli_replay_matches_api_baseline_byte_for_byte() -> None:
    assert _sha256(CLI_REPORT) == _sha256(REPORT)
    assert CLI_REPORT.read_bytes() == REPORT.read_bytes()


def test_archived_workspace_replays_to_same_report(tmp_path: Path) -> None:
    target = tmp_path / "external-homi"
    target.mkdir()
    with zipfile.ZipFile(ARCHIVE) as bundle:
        for name in sorted(STANDARD_FILES):
            (target / name).write_bytes(bundle.read(name))
    report = DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="p2-exit-06-02-homi-baseline",
            project_name="Homi Internal Agent Design Demo",
            owner="homi-agent-platform-owner",
            target_root=target,
            output_root=tmp_path / "output",
        )
    )

    assert encode_homi_pilot_json(report) == REPORT.read_text(encoding="utf-8")

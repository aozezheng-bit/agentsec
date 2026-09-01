"""P2-30 internal pilot integration and evidence tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agentsec.pilot import (
    PILOT_PLAN_SCHEMA_VERSION,
    PILOT_REPORT_OUTPUT_VERSION,
    PilotError,
    PilotPlan,
    PilotReport,
    PilotRunner,
    encode_pilot_report_json,
    export_pilot_plan_schema,
    export_pilot_report_schema,
    load_pilot_plan,
    render_pilot_report_markdown,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN = REPOSITORY_ROOT / "pilots" / "internal-release-agent" / "pilot.yaml"
SCRIPT = REPOSITORY_ROOT / "scripts" / "run-pilot.py"
AGENTSEC = REPOSITORY_ROOT / ".venv" / "bin" / "agentsec"


@pytest.fixture(scope="module")
def pilot_report(tmp_path_factory: pytest.TempPathFactory) -> PilotReport:
    loaded = load_pilot_plan(PLAN, repository_root=REPOSITORY_ROOT)
    return PilotRunner().run(
        loaded,
        repository_root=REPOSITORY_ROOT,
        agentsec_executable=AGENTSEC,
        output_root=tmp_path_factory.mktemp("pilot-evidence"),
    )


def test_pilot_plan_is_strict_sorted_and_bound_to_reviewed_scenarios() -> None:
    loaded = load_pilot_plan(PLAN, repository_root=REPOSITORY_ROOT)

    assert loaded.plan.schema_version == PILOT_PLAN_SCHEMA_VERSION == "0.1.0"
    assert loaded.plan.evidence_mode == "internal_integration"
    assert tuple(item.case_id for item in loaded.plan.cases) == (
        "active-waiver",
        "expired-waiver",
        "incomplete",
        "near-miss",
        "prompt-injection",
        "remediated",
        "risky-block",
        "safe-baseline",
    )
    assert len(loaded.sha256) == 64


def test_pilot_collects_decision_detection_coverage_and_performance(
    pilot_report: PilotReport,
) -> None:
    metrics = pilot_report.metrics

    assert pilot_report.status == "complete"
    assert pilot_report.format_version == PILOT_REPORT_OUTPUT_VERSION == "0.1.0"
    assert metrics.cases == metrics.passed_cases == 8
    assert metrics.failed_cases == 0
    assert metrics.true_positives == 29
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.decision_accuracy == 1.0
    assert metrics.coverage_accuracy == 1.0
    assert metrics.detection_accuracy == 1.0
    assert metrics.total_duration_ms > 0
    assert metrics.max_duration_ms <= 10_000
    assert all(item.json_bytes > 0 for item in pilot_report.cases)
    assert all(item.sarif_bytes > 0 for item in pilot_report.cases)
    assert all(item.sarif_valid for item in pilot_report.cases)


def test_pilot_report_is_value_minimized_and_honest(pilot_report: PilotReport) -> None:
    rendered = encode_pilot_report_json(pilot_report)
    markdown = render_pilot_report_markdown(pilot_report)

    assert "synthetic-demo-token" not in rendered
    assert "EXAMPLE_DEPLOY_TOKEN_DO_NOT_USE" not in rendered
    assert "https://" not in rendered
    assert "excerpt" not in rendered
    assert "internal integration pilot" in rendered
    assert "runtime exploit labels" in rendered
    assert "Decision accuracy: 100.00%" in markdown
    assert "FP/FN: 0/0" in markdown


def test_pilot_schemas_are_frozen_and_round_trip(pilot_report: PilotReport) -> None:
    plan_schema = REPOSITORY_ROOT / "schemas" / "pilot" / "pilot-plan.schema.json"
    report_schema = REPOSITORY_ROOT / "schemas" / "pilot" / "pilot-report.schema.json"

    assert plan_schema.read_text(encoding="utf-8") == export_pilot_plan_schema()
    assert report_schema.read_text(encoding="utf-8") == export_pilot_report_schema()
    assert (
        PilotReport.model_validate_json(encode_pilot_report_json(pilot_report))
        == pilot_report
    )
    assert (
        PilotPlan.model_validate(
            yaml.safe_load(PLAN.read_text(encoding="utf-8"))
        ).pilot_id
        == "internal-release-agent-pilot"
    )


def test_pilot_loader_rejects_escape_duplicate_and_symlink() -> None:
    pilot_dir = REPOSITORY_ROOT / "pilots" / "internal-release-agent"
    escaped = pilot_dir / "escape.tmp.yaml"
    duplicate = pilot_dir / "duplicate.tmp.yaml"
    link = pilot_dir / "link.tmp.yaml"
    escaped.write_text(
        PLAN.read_text(encoding="utf-8").replace(
            "project_root: demos/release-agent/risky-drift",
            "project_root: ../outside",
            1,
        ),
        encoding="utf-8",
    )
    duplicate.write_text(
        PLAN.read_text(encoding="utf-8").replace(
            "pilot_id: internal-release-agent-pilot",
            "pilot_id: first\npilot_id: second",
        ),
        encoding="utf-8",
    )
    link.symlink_to(PLAN)
    try:
        for invalid in (escaped, duplicate, link):
            with pytest.raises(PilotError):
                load_pilot_plan(invalid, repository_root=REPOSITORY_ROOT)
    finally:
        escaped.unlink()
        duplicate.unlink()
        link.unlink()


def test_pilot_github_workflow_preserves_reports_and_enforces_result() -> None:
    workflow = REPOSITORY_ROOT / ".github" / "workflows" / "agentsec-pilot.yml"
    text = workflow.read_text(encoding="utf-8")
    payload = yaml.load(text, Loader=yaml.BaseLoader)

    assert set(payload["on"]) == {"pull_request", "workflow_dispatch"}
    assert "continue-on-error" not in text
    assert "python scripts/run-pilot.py" in text
    assert "if: always()" in text
    assert "Upload pilot evidence" in text
    assert "Enforce pilot acceptance" in text


def test_pilot_cli_writes_shareable_reports(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--plan",
            str(PLAN),
            "--agentsec",
            str(AGENTSEC),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "8/8 cases passed" in result.stdout
    payload = json.loads((tmp_path / "pilot-report.json").read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert (tmp_path / "pilot-report.md").is_file()

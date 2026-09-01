"""P2-31 Pilot-driven deterministic Rule/score calibration tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agentsec.calibration.pilot_tuning import (
    RuleCalibrationRecommendation,
    RuleScoreCalibrationReport,
    export_rule_score_calibration_schema,
)
from agentsec.rules import BUILTIN_MARKDOWN_RULE_IDS
from agentsec.versioning import RISK_MODEL_VERSION, RULE_PACK_VERSION

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-rule-score-calibration.py"
OUTPUT = ROOT / "calibration" / "pilot-rule-score"
SCHEMA = ROOT / "schemas" / "calibration" / "rule-score-calibration-report.schema.json"


def _run(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--agentsec",
            str(ROOT / ".venv" / "bin" / "agentsec"),
            "--output-dir",
            str(output),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_calibration_replays_pilot_and_scoring_chain(tmp_path: Path) -> None:
    result = _run(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    report = RuleScoreCalibrationReport.model_validate_json(
        (tmp_path / "rule-score-calibration-report.json").read_text(encoding="utf-8")
    )
    assert report.status == "complete"
    assert report.calibration_generation == "v1"
    assert report.summary.pilot_false_positives == 0
    assert report.summary.pilot_false_negatives == 0
    assert report.summary.scoring_replay_cases == 7
    assert report.summary.scoring_replay_verified is True
    assert report.decision.internal_mvp_ready is True
    assert report.decision.publish_rule_changes is False
    assert report.decision.publish_score_changes is False


def test_calibration_covers_all_rules_without_unsupported_tuning() -> None:
    report = RuleScoreCalibrationReport.model_validate_json(
        (OUTPUT / "rule-score-calibration-report.json").read_text(encoding="utf-8")
    )

    assert tuple(item.rule_id for item in report.rules) == BUILTIN_MARKDOWN_RULE_IDS
    assert report.summary.covered_rules == 9
    assert report.summary.uncovered_rules == 6
    assert report.summary.retain_current_rules == 9
    assert report.summary.more_data_rules == 6
    assert not report.summary.review_false_positive_rules
    assert not report.summary.review_false_negative_rules
    assert {
        item.rule_id
        for item in report.rules
        if item.recommendation is RuleCalibrationRecommendation.MORE_DATA
    } == {
        "MD-DESTRUCT-001",
        "MD-EXEC-002",
        "MD-MEMORY-001",
        "MD-OBFUSC-001",
        "MD-PRIV-002",
        "MD-SELF-001",
    }


def test_calibration_retains_reviewed_rule_and_risk_versions() -> None:
    payload = json.loads(
        (OUTPUT / "rule-score-calibration-report.json").read_text(encoding="utf-8")
    )
    decision = payload["decision"]

    assert RULE_PACK_VERSION == "0.3.1"
    assert decision["current_rule_pack_version"] == "0.3.0"
    assert decision["candidate_rule_pack_version"] == "0.3.0"
    assert decision["current_risk_model_version"] == RISK_MODEL_VERSION == "0.4.0"
    assert decision["candidate_risk_model_version"] == RISK_MODEL_VERSION
    assert decision["rule_pack_action"] == "retain_current"
    assert decision["risk_model_action"] == "retain_current"


def test_calibration_schema_is_frozen() -> None:
    assert SCHEMA.read_text(encoding="utf-8") == export_rule_score_calibration_schema()


def test_calibration_report_contains_no_scanned_values() -> None:
    text = (OUTPUT / "rule-score-calibration-report.json").read_text(encoding="utf-8")

    assert "EXAMPLE_DEPLOY_TOKEN_DO_NOT_USE" not in text
    assert "synthetic-demo-token" not in text
    assert "https://" not in text
    assert "excerpt" not in text

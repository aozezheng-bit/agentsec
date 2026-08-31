"""P2-15A-PILOT-03 Shadow Gate Demo and coverage report tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "run-shadow-gate-demo.py"
WRAPPER = REPOSITORY_ROOT / "scripts" / "run-shadow-gate-demo.sh"
SCHEMA = (
    REPOSITORY_ROOT
    / "schemas"
    / "calibration"
    / "capability-shadow-gate-demo.schema.json"
)
CORPUS = REPOSITORY_ROOT / "calibration"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _json_report(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stderr
    payload: object = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def test_shadow_gate_demo_reports_live_match_and_no_match_cases() -> None:
    report = _json_report(_run("--corpus", str(CORPUS), "--format", "json"))

    assert report["format"] == "agentsec-capability-shadow-gate-demo"
    assert report["schema_version"] == "0.1.0"
    assert report["status"] == "passed"
    assert report["gate"] == {
        "blocks": False,
        "component_rule_id": "CAP-CHAIN-001",
        "floor": "high",
        "gate_id": "HG-CAPCHAIN-001",
        "gate_version": "0.1.0",
        "mode": "shadow",
        "qualification": "pilot_only",
    }
    assert report["summary"] == {
        "ci_blocking_enabled": False,
        "coverage_exit_code": 0,
        "coverage_status": "ready",
        "demo_match_count": 2,
        "demo_no_match_count": 3,
        "demo_scenario_count": 5,
        "fail_on_enabled": False,
        "hard_gate_enabled": False,
    }
    scenarios = {item["scenario_id"]: item for item in report["scenarios"]}
    assert scenarios["same-target-match"]["actual_match"] is True
    assert scenarios["parent-child-match"]["actual_match"] is True
    assert scenarios["agent-wide-no-match"]["actual_match"] is False
    assert (
        "ineligible_correlation"
        in scenarios["agent-wide-no-match"]["rejection_reasons"]
    )
    assert scenarios["unknown-no-match"]["actual_match"] is False
    assert scenarios["incomplete-coverage-no-match"]["actual_match"] is False
    assert all(
        all(value is True for value in item["risk_unchanged"].values())
        for item in scenarios.values()
    )


def test_shadow_gate_demo_reports_seeded_coverage_metadata() -> None:
    report = _json_report(_run("--corpus", str(CORPUS), "--format", "json"))
    coverage = report["coverage"]
    assert coverage["matrix_expected_match_count"] == 25
    assert coverage["matrix_expected_no_match_count"] == 25
    assert coverage["matrix_expected_no_match_eligible_count"] == 21
    assert coverage["matrix_expected_no_match_unknown_count"] == 4
    assert coverage["eligible_positive_count"] == 25
    assert coverage["eligible_negative_or_near_miss_count"] == 21
    assert report["boundary"] == {
        "ci_blocking_enabled": False,
        "enforcement_mode": "report_only",
        "fail_on_enabled": False,
        "global_safety_claimed": False,
        "ground_truth_used_for_demo": False,
        "hard_gate_enabled": False,
        "matrix_labels_are_seeded_expected_metadata": True,
        "runtime_capability_verified": False,
    }


def test_shadow_gate_demo_chinese_text_is_presenter_friendly() -> None:
    result = _run("--corpus", str(CORPUS), "--language", "zh", "--format", "text")

    assert result.returncode == 0, result.stderr
    assert "Capability Shadow Gate 演示" in result.stdout
    assert "Coverage 统计" in result.stdout
    assert "实时 Match / No-match 场景" in result.stdout
    assert "不阻断 CI" in result.stdout
    assert "https://example.invalid" not in result.stdout
    assert "REMOTE_TOKEN" not in result.stdout


def test_shadow_gate_demo_output_is_private_and_non_clobbering(tmp_path: Path) -> None:
    output = tmp_path / "shadow-gate-demo.json"
    first = _run(
        "--corpus",
        str(CORPUS),
        "--format",
        "json",
        "--output",
        str(output),
    )

    assert first.returncode == 0, first.stderr
    assert output.is_file()
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    second = _run(
        "--corpus",
        str(CORPUS),
        "--format",
        "json",
        "--output",
        str(output),
    )
    assert second.returncode == 4
    assert "already exists" in second.stderr


def test_shadow_gate_demo_wrapper_and_schema_are_present() -> None:
    assert WRAPPER.is_file()
    assert os.access(WRAPPER, os.X_OK)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["properties"]["format"]["const"] == (
        "agentsec-capability-shadow-gate-demo"
    )
    assert schema["properties"]["schema_version"]["const"] == "0.1.0"
    assert schema["$defs"]["Gate"]["properties"]["blocks"]["const"] is False

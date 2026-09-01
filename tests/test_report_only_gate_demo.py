"""P2-15A-PILOT-04 Report-only Gate demo tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts/run-report-only-gate-demo.py"
WRAPPER = REPOSITORY_ROOT / "scripts/run-report-only-gate-demo.sh"
QUALIFICATION = (
    REPOSITORY_ROOT
    / "calibration/p2-15a-capchain-40/human-evidence/"
    / "hg-capchain-001-qualification-report-v2.json"
)
V1_QUALIFICATION = (
    REPOSITORY_ROOT
    / "calibration/p2-15a-capchain-40/human-evidence/"
    / "hg-capchain-001-qualification-report.json"
)


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


def _json(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stderr
    payload: object = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_report_only_gate_demo_reports_qualified_non_enforcing_gate() -> None:
    report = _json(
        _run(
            "--language",
            "zh",
            "--format",
            "json",
            "--qualification-report",
            str(QUALIFICATION),
        )
    )
    assert report["format"] == "agentsec-report-only-gate-demo"
    assert report["status"] == "passed"
    assert report["gate"] == {
        "blocks": False,
        "ci_blocking": False,
        "component_rule_id": "CAP-CHAIN-001",
        "floor": "high",
        "gate_id": "HG-CAPCHAIN-001",
        "hard_gate": False,
        "mode": "report_only",
        "qualification": "accepted",
        "qualification_report_artifact_id": report["gate"][
            "qualification_report_artifact_id"
        ],
    }
    assert report["qualification"]["eligible_for_report_only_gate"] is True
    assert report["qualification"]["metrics"] == {
        "f1": 1.0,
        "false_positive_rate": 0.0,
        "precision": 1.0,
        "recall": 1.0,
    }
    assert report["summary"] == {
        "blocks": False,
        "ci_blocking": False,
        "hard_gate": False,
        "qualification_status": "accepted",
        "qualification_eligible": True,
        "report_only_match_count": 2,
        "report_only_no_match_count": 3,
        "scenario_count": 5,
    }
    assert all(item["hard_gate"] is False for item in report["scenarios"])
    assert all(item["blocks"] is False for item in report["scenarios"])


def test_report_only_gate_demo_chinese_text_is_presenter_friendly() -> None:
    result = _run(
        "--language",
        "zh",
        "--format",
        "text",
        "--qualification-report",
        str(QUALIFICATION),
    )
    assert result.returncode == 0, result.stderr
    assert "Report-only Gate 演示" in result.stdout
    assert "资格=accepted" in result.stdout
    assert "Confidence 校准：1.0" in result.stdout
    assert "不阻断 CI" in result.stdout
    assert "example.invalid" not in result.stdout
    assert "REMOTE_TOKEN" not in result.stdout


def test_report_only_gate_demo_is_not_ready_with_old_qualification(
    tmp_path: Path,
) -> None:
    output = tmp_path / "not-ready.json"
    result = _run(
        "--format",
        "json",
        "--qualification-report",
        str(V1_QUALIFICATION),
        "--output",
        str(output),
    )
    assert result.returncode == 2
    assert output.is_file()
    report = cast(dict[str, Any], json.loads(output.read_text(encoding="utf-8")))
    assert report["status"] == "not_ready"
    assert report["gate"]["hard_gate"] is False
    assert report["gate"]["ci_blocking"] is False


def test_report_only_gate_demo_output_is_private_and_non_clobbering(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report-only.json"
    first = _run(
        "--format",
        "json",
        "--qualification-report",
        str(QUALIFICATION),
        "--output",
        str(output),
    )
    assert first.returncode == 0
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    second = _run(
        "--format",
        "json",
        "--qualification-report",
        str(QUALIFICATION),
        "--output",
        str(output),
    )
    assert second.returncode == 4
    assert "already exists" in second.stderr


def test_report_only_gate_demo_wrapper_exists() -> None:
    assert WRAPPER.is_file()
    assert os.access(WRAPPER, os.X_OK)

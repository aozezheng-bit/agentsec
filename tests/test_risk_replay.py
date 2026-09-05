"""RISK-09 replay runner tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]


def _run_replay(output: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [
            sys.executable,
            "scripts/run-risk-replay.py",
            "--output-dir",
            str(output),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_risk_replay_passes_all_scenarios(tmp_path: Path) -> None:
    result = _run_replay(tmp_path / "out")

    assert result.returncode == 0, result.stderr
    assert "16/16 scenarios passed" in result.stdout
    assert "report-only" in result.stdout

    summary = json.loads(
        (tmp_path / "out" / "replay-summary.json").read_text(encoding="utf-8")
    )
    assert summary["scenario_total"] == 16
    assert summary["scenario_passed"] == 16
    assert summary["all_passed"] is True
    assert summary["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }

    scenarios = summary["scenarios"]
    # Benign copy-only changes report drift but never raise drift risk.
    for name in ("scenario-03", "scenario-04", "scenario-05", "scenario-06"):
        assert scenarios[name]["drift_status"] == "drifted", name
        assert scenarios[name]["drift_risk_score"] == 0.0, name
    # Injected operations raise both risk and drift risk.
    for name in ("scenario-07", "scenario-08", "scenario-12", "scenario-14"):
        assert scenarios[name]["risk_level"] == "high", name
        assert scenarios[name]["drift_risk_score"] == 8.0, name
    assert scenarios["scenario-10"]["risk_level"] == "medium"
    # Identical corpora verify; missing files stay the same agent as drift.
    assert scenarios["scenario-02"]["drift_status"] == "verified"
    assert scenarios["scenario-15"]["drift_status"] == "verified"
    assert scenarios["scenario-16"]["drift_status"] == "drifted"


def test_risk_replay_summary_markdown_is_written(tmp_path: Path) -> None:
    result = _run_replay(tmp_path / "out")
    assert result.returncode == 0, result.stderr

    markdown = (tmp_path / "out" / "replay-summary.md").read_text(encoding="utf-8")
    assert "RISK-09" in markdown
    assert "scenario-16" in markdown
    assert "report_only=true" in markdown

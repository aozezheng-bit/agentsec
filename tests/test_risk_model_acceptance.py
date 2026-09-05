"""RISK-10A formal acceptance and Homi CLI smoke tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-risk-model-acceptance.py"


def test_risk_model_acceptance_and_homi_smoke(tmp_path: Path) -> None:
    output = tmp_path / "acceptance"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--agentsec",
            str(ROOT / ".venv" / "bin" / "agentsec"),
            "--output-dir",
            str(output),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "accepted"
    assert report["replay"] == {
        "scenario_total": 16,
        "scenario_passed": 16,
        "all_passed": True,
    }
    assert report["baseline_checks"]["zero_risk"] is True
    assert report["scenario_results"]["scenario-08"]["risk_score"] == 8.0
    assert report["scenario_results"]["scenario-10"]["risk_score"] == 5.5
    assert report["scenario_results"]["scenario-12"]["risk_score"] == 8.0
    assert report["report_only"] is True
    assert report["runtime_verified"] is False
    assert report["ci_blocked"] is False
    assert report["network_accessed"] is False
    assert report["scanned_content_executed"] is False
    assert (output / "baseline" / "homi-pilot-report.html").is_file()

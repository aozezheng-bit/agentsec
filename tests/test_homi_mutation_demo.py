"""Isolated Markdown mutation and risk-injection demo tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_homi_mutation_demo_detects_text_changes_and_injected_risks(
    tmp_path: Path,
) -> None:
    output = tmp_path / "mutation-demo"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run-homi-mutation-demo.py",
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
    summary = json.loads((output / "demo-summary.json").read_text(encoding="utf-8"))
    assert summary["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }
    stages = {item["stage_id"]: item for item in summary["stages"]}
    assert stages["00-baseline"]["finding_ids"] == []
    assert stages["01-external-message"]["new_findings"] == ["HOMI-COMB-001"]
    assert stages["02-heartbeat-network"]["new_findings"] == [
        "HOMI-COMB-001",
        "HOMI-COMB-002",
    ]
    assert "HOMI-COMB-003" in stages["03-persistent-memory"]["new_findings"]
    assert "HOMI-COMB-004" in stages["04-self-modifying-controls"]["new_findings"]
    assert stages["01-external-message"]["text_file_diff"]["summary"]["modified"] == 2
    assert stages["02-heartbeat-network"]["text_file_diff"]["summary"]["modified"] == 3
    assert (
        output / "diffs" / "04-self-modifying-controls" / "combined-report.html"
    ).is_file()
    final_stage = stages["04-self-modifying-controls"]
    assert (output / "manifests" / "00-baseline-manifest.json").is_file()
    assert Path(final_stage["manifest"]).is_file()
    assert Path(final_stage["score"]).is_file()
    assert final_stage["score_summary"]["technical"] is not None
    assert final_stage["score_summary"]["drift"] is not None
    assert final_stage["score_summary"]["governance"] is not None
    assert final_stage["score_summary"]["overall"] is not None
    combined_html = (
        output / "diffs" / "04-self-modifying-controls" / "combined-report.html"
    ).read_text(encoding="utf-8")
    assert "未提供 Agentic Score" not in combined_html
    assert "三轴风险雷达图" in combined_html
    assert "AgentSec Homi MD" in (output / "demo-summary.md").read_text(
        encoding="utf-8"
    )

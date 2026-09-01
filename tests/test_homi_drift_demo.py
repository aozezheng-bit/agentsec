"""P3-HOMI-03A sanitized Homi capability-drift story tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]
DEMO_ROOT = REPOSITORY_ROOT / "demos" / "homi-capability-drift-zh"
CASES = (
    "baseline",
    "drift-add-external-message",
    "drift-modify-memory-policy",
    "drift-remove-safety-control",
)


def _run_demo(output: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [
            sys.executable,
            "scripts/run-homi-drift-demo.py",
            "--language",
            "zh",
            "--output-dir",
            str(output),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_homi_drift_demo_runs_and_reports_expected_story(tmp_path: Path) -> None:
    result = _run_demo(tmp_path / "output")

    assert result.returncode == 0, result.stderr
    assert "Homi Capability Drift Demo validation passed" in result.stdout
    assert "report-only" in result.stdout

    add = json.loads(
        (tmp_path / "output" / "drift-add-external-message.drift.json").read_text(
            encoding="utf-8"
        )
    )
    memory = json.loads(
        (tmp_path / "output" / "drift-modify-memory-policy.drift.json").read_text(
            encoding="utf-8"
        )
    )
    controls = json.loads(
        (tmp_path / "output" / "drift-remove-safety-control.drift.json").read_text(
            encoding="utf-8"
        )
    )

    assert add["capability_change_summary"] == {
        "added": 1,
        "removed": 0,
        "modified": 0,
    }
    assert add["finding_delta"]["added"] == ["HOMI-COMB-001"]
    assert memory["finding_delta"]["added"] == ["HOMI-COMB-003"]
    assert controls["finding_delta"]["added"] == ["HOMI-COMB-004"]
    assert add["risk_score"]["authority"] == "presentation_only"
    for case in CASES:
        report = json.loads(
            (tmp_path / "output" / f"{case}.report.json").read_text(encoding="utf-8")
        )
        assert report["report_only"] is True
        assert report["runtime_verified"] is False
        assert report["ci_blocked"] is False


def test_homi_drift_demo_fixtures_are_sanitized_and_inert() -> None:
    for case in CASES:
        case_root = DEMO_ROOT / case
        files = sorted(case_root.glob("*.md"))
        assert {item.name for item in files} == {
            "AGENTS.md",
            "HEARTBEAT.md",
            "IDENTITY.md",
            "SOUL.md",
            "TOOLS.md",
            "USER.md",
        }
        for path in files:
            assert not path.is_symlink()
            assert not os.access(path, os.X_OK)
            text = path.read_text(encoding="utf-8")
            assert "BEGIN PRIVATE KEY" not in text
            assert "synthetic-demo-token" not in text
            assert "example.invalid" not in text

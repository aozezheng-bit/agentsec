"""P3-AG-08 seed corpus and calibration runner tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from agentsec.attack_graph import (
    AttackPathCalibrationCase,
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationRunner,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SEED_ROOT = REPOSITORY_ROOT / "calibration" / "attack-path"
SCRIPT = REPOSITORY_ROOT / "scripts" / "run-attack-path-calibration.py"


def test_seed_attack_path_calibration_is_schema_valid_and_report_only() -> None:
    report = AttackPathEvidenceAssociationReport.model_validate_json(
        (SEED_ROOT / "seed-association-report.json").read_text(encoding="utf-8")
    )
    rows = json.loads((SEED_ROOT / "seed-cases.json").read_text(encoding="utf-8"))
    cases = tuple(AttackPathCalibrationCase.model_validate(item) for item in rows)
    calibration = AttackPathEvidenceCalibrationRunner().run(report, cases)

    assert calibration.metrics.accuracy == 1.0
    assert calibration.reviewed_case_count == 3
    assert calibration.reviewer_count == 1
    assert calibration.report_only is True
    assert calibration.blocks is False
    assert calibration.finding_authority is False


def test_seed_calibration_script_emits_json_and_refuses_clobber(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    output = tmp_path / "calibration-report.json"
    first = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--format",
            "json",
            "--output",
            str(output),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    payload = cast(dict[str, Any], json.loads(output.read_text(encoding="utf-8")))
    assert payload["format"] == "agentsec-attack-path-calibration-report"
    assert payload["metrics"]["accuracy"] == 1.0
    assert oct(output.stat().st_mode & 0o777) == "0o600"

    second = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--format",
            "json",
            "--output",
            str(output),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert second.returncode == 4
    assert "already exists" in second.stderr

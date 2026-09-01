#!/usr/bin/env python3
"""Evaluate independent labels against a frozen Attack Path association report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentsec.attack_graph import (
    AttackPathCalibrationCase,
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationRunner,
    encode_attack_path_calibration_json,
    render_attack_path_calibration_text,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = (
    REPOSITORY_ROOT / "calibration/attack-path/seed-association-report.json"
)
DEFAULT_CASES = REPOSITORY_ROOT / "calibration/attack-path/seed-cases.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate Attack Path Evidence relations against reviewed labels."
    )
    parser.add_argument("--association-report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        report = AttackPathEvidenceAssociationReport.model_validate_json(
            _read_json_text(args.association_report)
        )
        payload = json.loads(_read_json_text(args.cases))
        if not isinstance(payload, list):
            raise ValueError("calibration cases must be a JSON array")
        cases = tuple(
            AttackPathCalibrationCase.model_validate(item) for item in payload
        )
        calibration = AttackPathEvidenceCalibrationRunner().run(report, cases)
        rendered = (
            encode_attack_path_calibration_json(calibration)
            if args.format == "json"
            else render_attack_path_calibration_text(calibration)
        )
        _emit(rendered, args.output)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print("Attack Path calibration failed safely.", file=sys.stderr)
        print(str(error), file=sys.stderr)
        return 4
    return 0


def _read_json_text(path: Path) -> str:
    if not isinstance(path, Path):
        raise TypeError("calibration input path must be a Path")
    if path.suffix.lower() != ".json" or path.is_symlink() or not path.is_file():
        raise ValueError("calibration input must be a regular non-symlink JSON file")
    if path.stat().st_size > 67_108_864:
        raise ValueError("calibration input exceeds the hard file-size limit")
    return path.read_text(encoding="utf-8")


def _emit(content: str, output: Path | None) -> None:
    if output is None:
        print(content, end="")
        return
    if output.exists():
        raise ValueError("calibration output already exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    output.chmod(0o600)


if __name__ == "__main__":
    raise SystemExit(main())

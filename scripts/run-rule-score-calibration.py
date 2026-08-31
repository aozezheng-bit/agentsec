#!/usr/bin/env python3
"""Replay P2-30 Pilot and P2-24 scoring data for P2-31 calibration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from agentsec.calibration.pilot_tuning import (
    RuleScoreCalibrationRunner,
    encode_rule_score_calibration_json,
    render_rule_score_calibration_markdown,
)
from agentsec.pilot import PilotRunner, load_pilot_plan

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PILOT_PLAN = ROOT / "pilots" / "internal-release-agent" / "pilot.yaml"
DEFAULT_SCORING_REPLAY = ROOT / "testdata" / "scoring-replay" / "expected.json"
DEFAULT_OUTPUT = ROOT / "calibration" / "pilot-rule-score"


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot-plan", type=Path, default=DEFAULT_PILOT_PLAN)
    parser.add_argument("--scoring-replay", type=Path, default=DEFAULT_SCORING_REPLAY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--agentsec", type=Path, default=ROOT / ".venv" / "bin" / "agentsec"
    )
    return parser.parse_args()


def _write(path: Path, content: str) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing symbolic-link calibration output: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    args = _args()
    try:
        loaded = load_pilot_plan(args.pilot_plan, repository_root=ROOT)
        frozen = args.scoring_replay.resolve(strict=True)
        frozen_bytes = frozen.read_bytes()
        output = args.output_dir.resolve()
        if output.exists() and output.is_symlink():
            raise ValueError("calibration output cannot be a symbolic link")
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="agentsec-p231-") as temporary:
            temporary_root = Path(temporary)
            pilot = PilotRunner().run(
                loaded,
                repository_root=ROOT,
                agentsec_executable=args.agentsec,
                output_root=temporary_root / "pilot-evidence",
            )
            fresh_replay = temporary_root / "scoring-replay.json"
            replay_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run-scoring-replay.py"),
                    "--output",
                    str(fresh_replay),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                check=False,
                capture_output=True,
                text=True,
            )
            if replay_result.returncode != 0:
                raise ValueError("fresh scoring replay failed")
            fresh_bytes = fresh_replay.read_bytes()
        scoring_payload = json.loads(frozen_bytes.decode("utf-8"))
        report = RuleScoreCalibrationRunner().run(
            pilot,
            scoring_replay_payload=scoring_payload,
            scoring_replay_file_sha256=hashlib.sha256(frozen_bytes).hexdigest(),
            scoring_replay_verified=fresh_bytes == frozen_bytes,
        )
        _write(
            output / "rule-score-calibration-report.json",
            encode_rule_score_calibration_json(report),
        )
        _write(
            output / "rule-score-calibration-report.md",
            render_rule_score_calibration_markdown(report),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Calibration failed safely: {error}")
        return 5

    print(
        f"P2-31 calibration {report.status}: "
        f"covered={report.summary.covered_rules}, "
        f"more_data={report.summary.more_data_rules}, "
        f"FP/FN={report.summary.pilot_false_positives}/"
        f"{report.summary.pilot_false_negatives}, "
        "scoring_replay="
        f"{'pass' if report.summary.scoring_replay_verified else 'fail'}."
    )
    print(f"Reports: {output}")
    return 0 if report.status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())

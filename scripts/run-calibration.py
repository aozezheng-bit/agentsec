"""Run the deterministic P2-CAL-02 seed calibration report."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from agentsec.calibration import (
    CalibrationJsonRenderer,
    CalibrationTextRenderer,
    DeterministicCalibrationRunner,
    load_calibration_corpus,
)
from agentsec.capability_rules import CapabilityRuleLanguage


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    corpus = load_calibration_corpus(args.corpus)
    report = DeterministicCalibrationRunner().run(corpus)
    rendered = (
        CalibrationJsonRenderer().render(report)
        if args.format == "json"
        else CalibrationTextRenderer(
            language=CapabilityRuleLanguage(args.language)
        ).render(report)
    )
    if args.output is None:
        print(rendered, end="")
        return
    if args.output.exists():
        raise SystemExit("output already exists; choose a new path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        args.output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(rendered)


if __name__ == "__main__":
    main()

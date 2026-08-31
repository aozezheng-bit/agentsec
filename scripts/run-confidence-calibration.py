"""Run the P2-CAL-03 Evidence Confidence agreement calibration report."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from agentsec.calibration import (
    ConfidenceCalibrationJsonRenderer,
    ConfidenceCalibrationRunner,
    ConfidenceCalibrationTextRenderer,
    load_calibration_corpus,
    load_confidence_review_set,
)
from agentsec.capability_rules import CapabilityRuleLanguage


def _review_path(corpus_root: Path, requested: Path | None) -> str:
    if requested is None:
        return "confidence-reviews.json"
    try:
        return requested.resolve().relative_to(corpus_root.resolve()).as_posix()
    except ValueError as error:
        raise SystemExit("--reviews must be contained by --corpus") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--reviews", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    corpus = load_calibration_corpus(args.corpus)
    review_set = load_confidence_review_set(
        corpus,
        path=_review_path(corpus.root, args.reviews),
    )
    report = ConfidenceCalibrationRunner().run(corpus, review_set)
    rendered = (
        ConfidenceCalibrationJsonRenderer().render(report)
        if args.format == "json"
        else ConfidenceCalibrationTextRenderer(
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

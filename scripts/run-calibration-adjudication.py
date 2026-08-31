"""Run the P2-CAL-04 adjudication and Gate Candidate report."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from agentsec.calibration import (
    CalibrationAdjudicationJsonRenderer,
    CalibrationAdjudicationRunner,
    CalibrationAdjudicationTextRenderer,
    ConfidenceCalibrationRunner,
    load_adjudication_resolution_set,
    load_adjudication_review_set,
    load_calibration_corpus,
    load_confidence_review_set,
)
from agentsec.capability_rules import CapabilityRuleLanguage


def _contained_path(corpus_root: Path, requested: Path | None, default: str) -> str:
    if requested is None:
        return default
    try:
        return requested.resolve().relative_to(corpus_root.resolve()).as_posix()
    except ValueError as error:
        raise SystemExit("review input must be contained by --corpus") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--adjudications", type=Path)
    parser.add_argument("--resolutions", type=Path)
    parser.add_argument("--confidence-reviews", type=Path)
    parser.add_argument("--evidence-mode", choices=("seed", "human"), default="seed")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    corpus = load_calibration_corpus(args.corpus)
    adjudications = load_adjudication_review_set(
        corpus,
        path=_contained_path(
            corpus.root,
            args.adjudications,
            "adjudication-reviews.json",
        ),
    )
    resolutions = (
        None
        if args.resolutions is None
        else load_adjudication_resolution_set(
            corpus,
            path=_contained_path(corpus.root, args.resolutions, ""),
        )
    )
    confidence_report = None
    if args.evidence_mode == "human":
        if args.confidence_reviews is None:
            raise SystemExit("--evidence-mode human requires --confidence-reviews")
        confidence_set = load_confidence_review_set(
            corpus,
            path=_contained_path(corpus.root, args.confidence_reviews, ""),
        )
        confidence_report = ConfidenceCalibrationRunner().run(corpus, confidence_set)
    elif args.confidence_reviews is not None:
        raise SystemExit("--confidence-reviews requires --evidence-mode human")
    report = CalibrationAdjudicationRunner().run(
        corpus,
        adjudications,
        confidence_report,
        resolutions,
        evidence_mode=args.evidence_mode,
    )
    rendered = (
        CalibrationAdjudicationJsonRenderer().render(report)
        if args.format == "json"
        else CalibrationAdjudicationTextRenderer(
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

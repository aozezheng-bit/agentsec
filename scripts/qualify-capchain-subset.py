"""Generate the report-only HG-CAPCHAIN-001 qualification report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentsec.calibration.capchain_qualification import (
    CapchainQualificationError,
    build_qualification_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument(
        "--package-dir", type=Path, default=Path("calibration/p2-15a-capchain-40")
    )
    parser.add_argument(
        "--human-evidence-dir",
        type=Path,
        default=Path("calibration/p2-15a-capchain-40/human-evidence"),
    )
    parser.add_argument(
        "--confidence-path",
        type=Path,
        default=None,
        help="Optional Human Confidence artifact path, for example Confidence v2.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/human-evidence/"
            "hg-capchain-001-qualification-report.json"
        ),
    )
    parser.add_argument(
        "--output-text",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/human-evidence/"
            "hg-capchain-001-qualification-report.txt"
        ),
    )
    args = parser.parse_args()
    try:
        report = build_qualification_report(
            corpus_path=args.corpus,
            package_dir=args.package_dir,
            human_evidence_dir=args.human_evidence_dir,
            confidence_path=args.confidence_path,
            output_json=args.output_json,
            output_text=args.output_text,
        )
    except CapchainQualificationError as error:
        print(f"qualification report failed: {error}", file=sys.stderr)
        raise SystemExit(4) from None
    print(f"Gate: {report['gate_id']}")
    print(f"Status: {report['qualification']['status']}")
    print(
        "Report-only eligible: "
        f"{report['qualification']['eligible_for_report_only_gate']}"
    )
    print(f"Precision: {report['metrics']['precision']}")
    print(f"Recall: {report['metrics']['recall']}")
    print(
        "Confidence calibration: "
        f"{report['confidence_calibration']['human_vs_detector_agreement_rate']}"
    )
    print(f"JSON: {args.output_json.resolve()}")
    print(f"Text: {args.output_text.resolve()}")


if __name__ == "__main__":
    main()

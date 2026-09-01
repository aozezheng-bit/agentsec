"""Import the P2-15A-QUAL-02 Confidence recalibration submissions."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentsec.calibration.confidence_recalibration import (
    ConfidenceRecalibrationError,
    build_confidence_v2,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package-dir", type=Path, default=Path("calibration/confidence-review-20")
    )
    parser.add_argument(
        "--reviewer-a",
        type=Path,
        default=Path(
            "calibration/confidence-review-20/reviewer-a/"
            "reviewer-a-confidence-20-completed.json"
        ),
    )
    parser.add_argument(
        "--reviewer-b",
        type=Path,
        default=Path(
            "calibration/confidence-review-20/reviewer-b/"
            "reviewer-b-confidence-20-completed.json"
        ),
    )
    parser.add_argument(
        "--v1",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/human-evidence/"
            "human-capchain-40-confidence.json"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/human-evidence/"
            "human-capchain-40-confidence-v2.json"
        ),
    )
    args = parser.parse_args()
    try:
        report = build_confidence_v2(
            package_root=args.package_dir,
            reviewer_a_path=args.reviewer_a,
            reviewer_b_path=args.reviewer_b,
            v1_path=args.v1,
            output_path=args.output,
        )
    except ConfidenceRecalibrationError as error:
        print(f"Confidence recalibration import failed: {error}", file=sys.stderr)
        raise SystemExit(4) from None
    print("Task: P2-15A-QUAL-02")
    print(f"Cases: {report['case_count']}")
    print(f"Recalibrated Cases: {report['recalibrated_case_count']}")
    print(f"Reviewer Agreement: {report['reviewer_agreement']}/20")
    print(f"Confidence Distribution: {report['confidence_distribution']}")
    print(f"Output: {report['output']}")


if __name__ == "__main__":
    main()

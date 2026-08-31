"""Import the adjudicated 40-case HG-CAPCHAIN-001 Human Evidence subset."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentsec.calibration.capchain_subset import (
    CapchainSubsetError,
    build_subset_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package-dir",
        type=Path,
        default=Path("calibration/p2-15a-capchain-40"),
    )
    parser.add_argument(
        "--reviewer-a",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/reviewer-a/"
            "reviewer-a-capchain-40-completed.json"
        ),
    )
    parser.add_argument(
        "--reviewer-b",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/reviewer-b/"
            "reviewer-b-capchain-40-completed.json"
        ),
    )
    parser.add_argument(
        "--adjudications",
        type=Path,
        default=Path("calibration/p2-15a-capchain-40/adjudication-decisions.json"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("calibration/p2-15a-capchain-40/human-evidence"),
    )
    args = parser.parse_args()
    try:
        report = build_subset_evidence(
            package_root=args.package_dir,
            reviewer_a_path=args.reviewer_a,
            reviewer_b_path=args.reviewer_b,
            adjudication_path=args.adjudications,
            output_dir=args.output_dir,
        )
    except CapchainSubsetError as error:
        print(f"subset Human Evidence import failed: {error}", file=sys.stderr)
        raise SystemExit(4) from None
    print("Gate: HG-CAPCHAIN-001")
    print(f"Cases: {report['case_count']}")
    print(f"Reviewer rows: {report['review_count']}")
    print(f"A/B agreed rows: {report['agreement_count']}")
    print(f"Adjudicated rows: {report['adjudication_count']}")
    print(f"Output: {report['output_dir']}")


if __name__ == "__main__":
    main()

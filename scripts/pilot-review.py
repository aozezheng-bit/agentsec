"""Validate, report, and merge the 100-question Pilot Review.

This CLI only handles reviewer-label progress. It never reads Calibration
Ground Truth and never emits formal P2-CAL-04 adjudication or Hard Gate results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.calibration.pilot_review import (
    PilotReviewError,
    ReviewerId,
    compare_pilot_reviews,
    create_pilot_adjudication_template,
    import_joint_panel_review,
    merge_pilot_review,
    report_pilot_review,
    validate_joint_expert_evidence,
    validate_pilot_review,
)


def _default_labels(reviewer_id: ReviewerId) -> Path:
    return Path(f"calibration/pilot-review-100/{reviewer_id}-labels.template.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--operation",
        choices=(
            "validate",
            "report",
            "merge",
            "compare",
            "adjudication-template",
            "import-joint-panel",
            "validate-joint-panel",
        ),
        default="report",
    )
    parser.add_argument(
        "--selection",
        type=Path,
        default=Path("calibration/pilot-review-100/selection.json"),
    )
    parser.add_argument("--pack", type=Path, default=Path("calibration/reviewer-pack"))
    parser.add_argument(
        "--reviewer", choices=("reviewer-a", "reviewer-b"), default="reviewer-a"
    )
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--reviewer-a", type=Path)
    parser.add_argument("--reviewer-b", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    reviewer_id: ReviewerId = args.reviewer
    labels_path = args.labels or _default_labels(reviewer_id)
    try:
        if args.operation == "import-joint-panel":
            if args.input is None or args.output is None:
                raise PilotReviewError(
                    "import-joint-panel requires --input and --output"
                )
            payload = import_joint_panel_review(
                selection_path=args.selection,
                pack_root=args.pack,
                input_path=args.input,
                output_path=args.output,
            )
        elif args.operation == "validate-joint-panel":
            if args.input is None:
                raise PilotReviewError("validate-joint-panel requires --input")
            payload = validate_joint_expert_evidence(
                selection_path=args.selection,
                pack_root=args.pack,
                evidence_path=args.input,
            )
        elif args.operation == "merge":
            if args.output is None:
                raise PilotReviewError("merge requires --output")
            summary = merge_pilot_review(
                selection_path=args.selection,
                pack_root=args.pack,
                labels_path=labels_path,
                reviewer_id=reviewer_id,
                output_path=args.output,
            )
            payload = summary.as_json()
            payload["merged_output"] = str(args.output)
        elif args.operation == "compare":
            if args.reviewer_a is None or args.reviewer_b is None:
                raise PilotReviewError("compare requires --reviewer-a and --reviewer-b")
            payload = compare_pilot_reviews(
                selection_path=args.selection,
                pack_root=args.pack,
                reviewer_a_path=args.reviewer_a,
                reviewer_b_path=args.reviewer_b,
            )
        elif args.operation == "adjudication-template":
            if (
                args.reviewer_a is None
                or args.reviewer_b is None
                or args.output is None
            ):
                raise PilotReviewError(
                    "adjudication-template requires --reviewer-a, "
                    "--reviewer-b, and --output"
                )
            payload = create_pilot_adjudication_template(
                selection_path=args.selection,
                pack_root=args.pack,
                reviewer_a_path=args.reviewer_a,
                reviewer_b_path=args.reviewer_b,
                output_path=args.output,
            )
        elif args.operation == "validate":
            summary = validate_pilot_review(
                selection_path=args.selection,
                pack_root=args.pack,
                labels_path=labels_path,
                reviewer_id=reviewer_id,
            )
            payload = summary.as_json()
        else:
            payload = report_pilot_review(
                selection_path=args.selection,
                pack_root=args.pack,
                labels_path=labels_path,
                reviewer_id=reviewer_id,
            )
    except PilotReviewError as error:
        parser.exit(4, f"pilot review operation failed: {error}\n")
    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if args.operation == "import-joint-panel":
        print(f"Pilot Selection: {payload['selection_id']}")
        print(f"Review Panel: {payload['review_panel_id']}")
        print(f"Question set: {payload['question_set_reviewer_id']}")
        print(f"Imported reviewed rows: {payload['reviewed_count']}")
        print(f"Evidence ID: {payload['evidence_id']}")
        print("Qualification: pilot_only (not formal P2-CAL-04 Human Evidence)")
        print(f"Output: {args.output}")
        return
    if args.operation == "validate-joint-panel":
        print(f"Joint Evidence: {payload['evidence_id']}")
        print(f"Pilot Selection: {payload['selection_id']}")
        print(f"Review Panel: {payload['review_panel_id']}")
        print(f"Validated reviewed rows: {payload['reviewed_count']}")
        print("Valid: true")
        print("Qualification: pilot_only (not formal P2-CAL-04 Human Evidence)")
        return
    if args.operation == "compare":
        print(f"Pilot Selection: {payload['selection_id']}")
        print(f"Agreement: {payload['agreement_count']}/{payload['total']}")
        print(f"Disagreements: {payload['disagreement_count']}")
        return
    if args.operation == "adjudication-template":
        print(f"Pilot Selection: {payload['selection_id']}")
        print(f"Disagreements queued: {len(payload['resolutions'])}")
        print(f"Output: {args.output}")
        return
    print(f"Pilot Selection: {payload['selection_id']}")
    print(f"Reviewer: {payload['reviewer_id']}")
    print(f"Reviewed rows: {payload['completed']}/{payload['total']}")
    print(f"Valid completed: {payload['valid_completed']}")
    print(f"Pending: {payload['pending']}")
    print(f"Uncertain: {payload['uncertain']}")
    print(f"Invalid reviewed rows: {payload['invalid_reviewed']}")
    print(f"Validation status: {payload['validation_status']}")
    if "merged_output" in payload:
        print(f"Merged output: {payload['merged_output']}")


if __name__ == "__main__":
    main()

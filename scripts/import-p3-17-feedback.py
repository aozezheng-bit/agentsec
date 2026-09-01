#!/usr/bin/env python3
"""Import a completed P3-17 human feedback submission.

Validates the reviewer identity, the independence statement, per-row
confirm/reject decisions, and the draft binding, then emits a
machine-readable confirmed feedback set (``SemanticFeedbackSet``) for the
FP/FN closed loop. Fails closed on any defect; the submission is read as
JSON data only and no corpus text is copied into the output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentsec.semantic.feedback import (
    FeedbackRowStatus,
    build_semantic_feedback_set,
    encode_semantic_feedback_json,
)
from agentsec.semantic.models import (
    SemanticCandidateDisposition,
    SemanticCandidateKind,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DRAFT = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-feedback-p3-17"
    / "draft"
    / "feedback-draft-submission.template.json"
)
DEFAULT_OUTPUT = REPOSITORY_ROOT / "pilots" / "semantic-feedback-p3-17" / "confirmed"

VALID_ISSUE_TYPES = {"false_positive", "false_negative"}
VALID_PROVENANCE = {"human_authored", "ai_draft_human_confirmed"}


def _fail(message: str) -> int:
    print(f"import failed: {message}")
    return 5


def _validate_row(row: Any) -> str | None:
    if not isinstance(row, dict):
        return "row is not an object"
    for field in (
        "row_id",
        "case_id",
        "issue_type",
        "kind",
        "category",
        "disposition",
    ):
        if not isinstance(row.get(field), str) or not row[field].strip():
            return f"missing or empty {field}"
    issue_type = row["issue_type"]
    if issue_type not in VALID_ISSUE_TYPES:
        return f"invalid issue_type {issue_type}"
    try:
        SemanticCandidateKind(row["kind"])
    except ValueError:
        return f"invalid kind {row['kind']}"
    try:
        SemanticCandidateDisposition(row["disposition"])
    except ValueError:
        return f"invalid disposition {row['disposition']}"
    status = row.get("status")
    if status not in {item.value for item in FeedbackRowStatus}:
        return f"invalid row status {status}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, default=DEFAULT_DRAFT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    try:
        submission = json.loads(args.submission.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return _fail(f"unreadable submission: {error}")

    reviewer_id = submission.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        return _fail("reviewer_id missing")
    independence = submission.get("independence_statement")
    if not isinstance(independence, str) or len(independence.strip()) < 20:
        return _fail("independence_statement missing or too short")
    label_provenance = submission.get("label_provenance", "unspecified")
    if label_provenance not in VALID_PROVENANCE:
        return _fail(f"invalid label_provenance: {label_provenance}")

    draft_rows = submission.get("draft_rows")
    if not isinstance(draft_rows, list) or not draft_rows:
        return _fail("draft_rows missing or empty")

    confirmed_ids: list[str] = []
    notes: dict[str, str] = {}
    for row in draft_rows:
        problem = _validate_row(row)
        if problem is not None:
            return _fail(f"{problem} at {row.get('row_id', '<unknown>')}")
        status = row["status"]
        if status == "rejected":
            continue
        if status != "confirmed":
            return _fail(
                f"unresolved row status {status} at {row['row_id']}; "
                "every row must be confirmed or rejected"
            )
        confirmed_ids.append(row["row_id"])
        note = row.get("note")
        if isinstance(note, str) and note.strip():
            notes[row["row_id"]] = note.strip()

    if not confirmed_ids:
        return _fail("no confirmed rows remain")

    draft = _rebuild_draft(submission)
    if draft is None:
        return _fail("submission draft binding is invalid")
    try:
        feedback_set = build_semantic_feedback_set(
            draft,
            confirmed_row_ids=tuple(sorted(set(confirmed_ids))),
            reviewer_id=reviewer_id,
            independence_statement=independence,
            row_notes=notes,
        )
    except ValueError as error:
        return _fail(f"invalid feedback set: {error}")

    args.output.mkdir(parents=True, exist_ok=True)
    output_path = args.output / "semantic-feedback-set.json"
    output_path.write_text(
        encode_semantic_feedback_json(feedback_set) + "\n", encoding="utf-8"
    )
    print(f"imported {len(confirmed_ids)} confirmed feedback rows")
    print(f"feedback sha256: {feedback_set.feedback_sha256}")
    print(f"feedback set: {output_path}")
    return 0


def _rebuild_draft(
    submission: dict[str, Any],
):
    """Rebuild the draft model from the submission's original draft rows."""

    from agentsec.semantic.feedback import SemanticFeedbackDraft

    rows = []
    for row in submission.get("draft_rows", []) or []:
        normalized = dict(row)
        normalized["status"] = "draft"
        normalized["note"] = None
        rows.append(normalized)
    try:
        return SemanticFeedbackDraft.model_validate(
            {
                "format": "agentsec-p3-17-semantic-feedback-draft",
                "schema_version": "0.1.0",
                "draft_sha256": submission.get("draft_sha256", ""),
                "context": submission.get("context", {}),
                "draft_row_count": len(rows),
                "false_positive_row_count": sum(
                    row.get("issue_type") == "false_positive" for row in rows
                ),
                "false_negative_row_count": sum(
                    row.get("issue_type") == "false_negative" for row in rows
                ),
                "unevaluated_case_count": 0,
                "unevaluated_case_ids": [],
                "rows": rows,
            }
        )
    except ValueError:
        return None


if __name__ == "__main__":
    sys.exit(main())

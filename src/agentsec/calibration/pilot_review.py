"""Safe validation, reporting, and merging for the 100-question Pilot Review.

Pilot Review artifacts are intentionally separate from the formal 431-question
P2-CAL-04 Reviewer Pack. This module never reads Corpus Ground Truth and never
produces formal adjudication, TP/FP/FN/TN, Hard Gate, or CI decisions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

PILOT_SELECTION_FORMAT = "agentsec-pilot-review-selection"
PILOT_LABEL_FORMAT = "agentsec-pilot-review-label-template"
PILOT_SCHEMA_VERSION = "0.1.0"
FULL_LABEL_FORMAT = "agentsec-independent-review-label-template"
FULL_PACK_SCHEMA_VERSION = "0.3.0"
JOINT_EVIDENCE_FORMAT = "agentsec-joint-expert-review-evidence"
JOINT_EVIDENCE_SCHEMA_VERSION = "0.1.0"
JOINT_EVIDENCE_MODE = "joint_expert_review"
JOINT_QUALIFICATION = "pilot_only"
BLINDING_REVIEW_ID_PATTERN = re.compile(r"^review-case-[0-9a-f]{20}$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PACK_ID_PATTERN = re.compile(r"^reviewer-pack-sha256:[0-9a-f]{64}$")
PANEL_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
RATIONALE_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
BLINDING_SALT = "agentsec-p2-cal-04a-reviewer-pack-v2"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_NOTES_LENGTH = 2_000
MAX_SUMMARY_LENGTH = 512
MAX_EVIDENCE_LOCATIONS = 16

ReviewerId = Literal["reviewer-a", "reviewer-b"]
_COMPARE_FIELDS = (
    "human_condition_label",
    "observed_finding",
    "category",
    "confidence",
    "correlation",
    "disposition",
)


class PilotReviewError(ValueError):
    """Raised when a Pilot Review artifact is invalid or tampered."""


@dataclass(frozen=True, slots=True)
class PilotReviewSummary:
    """Human-label-only progress summary for one Pilot Reviewer."""

    selection_id: str
    reviewer_id: ReviewerId
    total: int
    completed: int
    pending: int
    uncertain: int
    by_rule: dict[str, int]
    by_condition: dict[str, int]
    by_confidence: dict[str, int]
    by_correlation: dict[str, int]
    by_disposition: dict[str, int]
    valid_completed: int
    invalid_reviewed: int
    validation_status: Literal["ready", "needs_review_fix"]
    validation_issues: tuple[dict[str, str], ...] = ()

    def as_json(self) -> dict[str, Any]:
        return {
            "format": "agentsec-pilot-review-progress-report",
            "schema_version": PILOT_SCHEMA_VERSION,
            "selection_id": self.selection_id,
            "reviewer_id": self.reviewer_id,
            "total": self.total,
            "completed": self.completed,
            "valid_completed": self.valid_completed,
            "pending": self.pending,
            "uncertain": self.uncertain,
            "invalid_reviewed": self.invalid_reviewed,
            "validation_status": self.validation_status,
            "validation_issues": list(self.validation_issues),
            "by_rule": dict(sorted(self.by_rule.items())),
            "by_condition": dict(sorted(self.by_condition.items())),
            "by_confidence": dict(sorted(self.by_confidence.items())),
            "by_correlation": dict(sorted(self.by_correlation.items())),
            "by_disposition": dict(sorted(self.by_disposition.items())),
            "boundary": {
                "formal_human_evidence": False,
                "hard_gate_qualification": False,
                "ci_blocking": False,
                "fail_on": False,
                "ground_truth_used": False,
            },
        }


@dataclass(frozen=True, slots=True)
class _ValidatedPilot:
    selection: dict[str, Any]
    labels: dict[str, Any]
    canonical_rows: dict[str, dict[str, Any]]
    summary: PilotReviewSummary


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PilotReviewError(f"{label} is missing or unsafe")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PilotReviewError(f"{label} cannot be read") from error
    if len(data) > MAX_JSON_BYTES:
        raise PilotReviewError(f"{label} exceeds the bounded size")
    try:
        payload: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise PilotReviewError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise PilotReviewError(f"{label} must contain a JSON object")
    return cast(dict[str, Any], payload)


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _selection_id(selection: dict[str, Any]) -> str:
    unsigned = dict(selection)
    unsigned["selection_id"] = None
    return (
        "pilot-selection-sha256:"
        + hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    )


def _exact_keys(payload: dict[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        raise PilotReviewError(f"{label} has invalid fields")


def _require_string(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    max_length: int = 512,
) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise PilotReviewError(f"{label} is invalid")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise PilotReviewError(f"{label} is invalid")
    return value


def _optional_choice(
    value: object,
    choices: set[str],
    label: str,
    *,
    required: bool,
) -> str | None:
    if value is None:
        if required:
            raise PilotReviewError(f"{label} is required for a reviewed row")
        return None
    if not isinstance(value, str) or value not in choices:
        raise PilotReviewError(f"{label} is invalid")
    return value


def _optional_text(
    value: object,
    label: str,
    *,
    required: bool,
    max_length: int,
) -> str | None:
    if value is None:
        if required:
            raise PilotReviewError(f"{label} is required for a reviewed row")
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise PilotReviewError(f"{label} is invalid")
    if required and not value.strip():
        raise PilotReviewError(f"{label} is required for a reviewed row")
    return value


def _validate_evidence_locations(
    value: object,
    *,
    accepted_paths: set[str],
    max_line: int,
    required: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PilotReviewError("evidence_locations must be a list")
    if len(value) > MAX_EVIDENCE_LOCATIONS:
        raise PilotReviewError("evidence_locations exceeds the bounded count")
    if required and not value:
        raise PilotReviewError("reviewed rows require evidence_locations")
    result: list[dict[str, Any]] = []
    for location in value:
        if not isinstance(location, dict):
            raise PilotReviewError("evidence location must be an object")
        _exact_keys(location, {"path", "start_line", "end_line"}, "evidence location")
        path = _require_string(location["path"], "evidence location path")
        if (
            SAFE_PATH_PATTERN.fullmatch(path) is None
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path not in accepted_paths
        ):
            raise PilotReviewError("evidence location path is unsafe or mismatched")
        start = location["start_line"]
        end = location["end_line"]
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or isinstance(end, bool)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > max_line
        ):
            raise PilotReviewError("evidence location line range is invalid")
        result.append({"path": path, "start_line": start, "end_line": end})
    return result


def _validate_selection(path: Path, pack_id: str, corpus_hash: str) -> dict[str, Any]:
    selection = _read_json(path, "Pilot selection")
    _exact_keys(
        selection,
        {
            "boundary",
            "format",
            "items",
            "purpose",
            "review_count",
            "reviewer_scopes",
            "schema_version",
            "selection_id",
            "source_corpus_binding_hash",
            "source_pack_id",
            "title",
        },
        "Pilot selection",
    )
    if (
        selection["format"] != PILOT_SELECTION_FORMAT
        or selection["schema_version"] != PILOT_SCHEMA_VERSION
        or selection["source_pack_id"] != pack_id
        or selection["source_corpus_binding_hash"] != corpus_hash
        or selection["review_count"] != 100
        or selection["selection_id"] != _selection_id(selection)
    ):
        raise PilotReviewError("Pilot selection binding or version is invalid")
    scopes = selection["reviewer_scopes"]
    if scopes != ["reviewer-a", "reviewer-b"]:
        raise PilotReviewError("Pilot selection reviewer scopes are invalid")
    boundary = selection["boundary"]
    if (
        not isinstance(boundary, dict)
        or boundary.get("full_pack_remains_authoritative") is not True
    ):
        raise PilotReviewError("Pilot selection formal-pack boundary is invalid")
    items = selection["items"]
    if not isinstance(items, list) or len(items) != 100:
        raise PilotReviewError("Pilot selection must contain 100 items")
    seen: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict):
            raise PilotReviewError("Pilot selection item must be an object")
        _exact_keys(
            raw,
            {
                "input_format",
                "language",
                "question_id",
                "review_case_id",
                "reviewer_a_case_path",
                "reviewer_b_case_path",
                "rule_id",
                "sequence",
            },
            "Pilot selection item",
        )
        review_case_id = _require_string(
            raw["review_case_id"], "review_case_id", pattern=BLINDING_REVIEW_ID_PATTERN
        )
        rule_id = _require_string(raw["rule_id"], "rule_id")
        question_id = _require_string(raw["question_id"], "question_id")
        expected_question_id = f"question:{review_case_id}:{rule_id}"
        if question_id != expected_question_id:
            raise PilotReviewError("Pilot question_id binding is invalid")
        if question_id in seen:
            raise PilotReviewError("Pilot selection contains duplicate questions")
        seen.add(question_id)
        for reviewer_id in ("reviewer-a", "reviewer-b"):
            expected_path = f"{reviewer_id}/cases/{review_case_id}/case.json"
            field_name = f"{reviewer_id.replace('-', '_')}_case_path"
            if raw[field_name] != expected_path:
                raise PilotReviewError("Pilot reviewer case path is invalid")
    return selection


def _load_pack_identity(pack_root: Path) -> tuple[str, str, dict[str, Any]]:
    manifest = _read_json(pack_root / "pack-manifest.json", "Reviewer Pack manifest")
    pack_id = _require_string(
        manifest.get("pack_id"), "Pack ID", pattern=PACK_ID_PATTERN
    )
    corpus_hash = _require_string(
        manifest.get("corpus_binding_hash"),
        "Corpus binding hash",
        pattern=SHA256_PATTERN,
    )
    if manifest.get("schema_version") != FULL_PACK_SCHEMA_VERSION:
        raise PilotReviewError("Reviewer Pack schema version is invalid")
    return pack_id, corpus_hash, manifest


def _load_canonical_rows(
    pack_root: Path,
    reviewer_id: ReviewerId,
    manifest: dict[str, Any],
) -> tuple[str, str, dict[str, dict[str, Any]]]:
    relative = f"{reviewer_id}/labels.template.json"
    manifest_files = {
        item.get("path"): item
        for item in manifest.get("files", [])
        if isinstance(item, dict)
    }
    entry = manifest_files.get(relative)
    if not isinstance(entry, dict):
        raise PilotReviewError("Reviewer Pack label template is absent from manifest")
    path = pack_root / relative
    data = path.read_bytes()
    if _sha256(data) != entry.get("sha256"):
        raise PilotReviewError("Reviewer Pack label template has been modified")
    payload = _read_json(path, "Reviewer Pack label template")
    expected = {
        "corpus_binding_hash",
        "format",
        "pack_id",
        "reviewer_id",
        "reviews",
        "schema_version",
    }
    _exact_keys(payload, expected, "Reviewer Pack label template")
    if (
        payload["format"] != FULL_LABEL_FORMAT
        or payload["schema_version"] != FULL_PACK_SCHEMA_VERSION
        or payload["reviewer_id"] != reviewer_id
    ):
        raise PilotReviewError("Reviewer Pack label template identity is invalid")
    rows = payload["reviews"]
    if not isinstance(rows, list) or not rows:
        raise PilotReviewError("Reviewer Pack label template rows are invalid")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise PilotReviewError("Reviewer Pack label row is invalid")
        review_id = _require_string(row.get("review_id"), "review_id")
        if review_id in result:
            raise PilotReviewError("Reviewer Pack contains duplicate review_id")
        result[review_id] = row
    return payload["pack_id"], payload["corpus_binding_hash"], result


def _validate_label_row(
    row: dict[str, Any],
    canonical: dict[str, Any],
    *,
    reviewer_id: ReviewerId,
    expected_source: str,
    max_line: int,
) -> None:
    if set(row) != set(canonical):
        raise PilotReviewError("Pilot label row fields are invalid")
    immutable = {
        "corpus_binding_hash",
        "pack_id",
        "question_set_sha256",
        "review_case_fingerprint",
        "source_sha256",
        "classification",
        "review_case_id",
        "review_id",
        "reviewer_id",
        "rule_id",
    }
    for key in immutable:
        if row[key] != canonical[key]:
            raise PilotReviewError(f"Pilot label immutable field is invalid: {key}")
    if row["classification"] is not None:
        raise PilotReviewError("Pilot Reviewer must not provide classification")
    status = row["status"]
    if status not in {None, "reviewed"}:
        raise PilotReviewError("Pilot review status is invalid")
    complete = status == "reviewed"
    human_label = _optional_choice(
        row["human_condition_label"],
        {"match", "no_match", "uncertain"},
        "human_condition_label",
        required=complete,
    )
    _optional_choice(
        row["observed_finding"],
        {"present", "absent", "uncertain"},
        "observed_finding",
        required=complete,
    )
    category = _optional_choice(
        row["category"],
        {
            "standard",
            "policy_accepted_risk",
            "out_of_scope",
            "runtime_uncertainty",
            "unresolved",
        },
        "category",
        required=complete,
    )
    _optional_choice(
        row["confidence"], {"A", "B", "C", "D"}, "confidence", required=complete
    )
    _optional_choice(
        row["correlation"],
        {
            "same_target",
            "parent_child",
            "same_source",
            "explicit_relation",
            "agent_wide",
            "incomplete_coverage",
        },
        "correlation",
        required=complete,
    )
    _optional_choice(
        row["disposition"],
        {"keep", "tune", "shadow", "retire", "more_data"},
        "disposition",
        required=complete,
    )
    _optional_text(
        row["finding_summary"],
        "finding_summary",
        required=complete,
        max_length=MAX_SUMMARY_LENGTH,
    )
    rationale = _optional_text(
        row["rationale_code"],
        "rationale_code",
        required=complete,
        max_length=128,
    )
    if rationale is not None and RATIONALE_PATTERN.fullmatch(rationale) is None:
        raise PilotReviewError("rationale_code is invalid")
    notes = _optional_text(
        row["review_notes"],
        "review_notes",
        required=False,
        max_length=MAX_NOTES_LENGTH,
    )
    if notes is None and row["review_notes"] != "":
        raise PilotReviewError("review_notes is invalid")
    _validate_evidence_locations(
        row["evidence_locations"],
        accepted_paths={
            expected_source,
            f"{reviewer_id}/cases/{row['review_case_id']}/{expected_source}",
        },
        max_line=max_line,
        required=complete,
    )
    if human_label == "uncertain" and category not in {
        "out_of_scope",
        "runtime_uncertainty",
        "unresolved",
    }:
        raise PilotReviewError("uncertain labels require an uncertainty category")
    if not complete:
        mutable = (
            row["category"],
            row["confidence"],
            row["correlation"],
            row["disposition"],
            row["finding_summary"],
            row["human_condition_label"],
            row["observed_finding"],
            row["rationale_code"],
            row["review_notes"],
            row["evidence_locations"],
        )
        if mutable != (None, None, None, None, None, None, None, None, "", []):
            raise PilotReviewError(
                "pending Pilot rows must not contain partial human labels"
            )


def _validate_pilot(
    selection_path: Path,
    pack_root: Path,
    labels_path: Path,
    reviewer_id: ReviewerId,
    *,
    strict: bool,
) -> _ValidatedPilot:
    labels = _read_json(labels_path, "Pilot label template")
    return _validate_pilot_labels(
        selection_path, pack_root, labels, reviewer_id, strict=strict
    )


def _validate_pilot_labels(
    selection_path: Path,
    pack_root: Path,
    labels: dict[str, Any],
    reviewer_id: ReviewerId,
    *,
    strict: bool,
) -> _ValidatedPilot:
    pack_id, corpus_hash, manifest = _load_pack_identity(pack_root)
    selection = _validate_selection(selection_path, pack_id, corpus_hash)
    canonical_pack_id, canonical_hash, canonical_rows = _load_canonical_rows(
        pack_root, reviewer_id, manifest
    )
    if (canonical_pack_id, canonical_hash) != (pack_id, corpus_hash):
        raise PilotReviewError("Reviewer Pack label template binding is inconsistent")

    _exact_keys(
        labels,
        {
            "corpus_binding_hash",
            "format",
            "pack_id",
            "pilot_selection_id",
            "reviewer_id",
            "reviews",
            "schema_version",
        },
        "Pilot label template",
    )
    if (
        labels["format"] != PILOT_LABEL_FORMAT
        or labels["schema_version"] != PILOT_SCHEMA_VERSION
        or labels["pilot_selection_id"] != selection["selection_id"]
        or labels["pack_id"] != pack_id
        or labels["corpus_binding_hash"] != corpus_hash
        or labels["reviewer_id"] != reviewer_id
    ):
        raise PilotReviewError("Pilot label template binding is invalid")

    items = selection["items"]
    expected_review_ids = [
        f"review:{reviewer_id}:{item['review_case_id']}:{item['rule_id']}"
        for item in items
    ]
    raw_reviews = labels["reviews"]
    if not isinstance(raw_reviews, list) or len(raw_reviews) != len(
        expected_review_ids
    ):
        raise PilotReviewError("Pilot label template must contain exactly 100 rows")
    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in raw_reviews:
        if not isinstance(row, dict):
            raise PilotReviewError("Pilot label row must be an object")
        review_id = row.get("review_id")
        if not isinstance(review_id, str) or review_id in rows_by_id:
            raise PilotReviewError("Pilot label rows contain duplicate or invalid IDs")
        rows_by_id[review_id] = row
    if list(rows_by_id) != expected_review_ids:
        raise PilotReviewError("Pilot label rows do not match Selection order")

    issues: list[dict[str, str]] = []
    for item, review_id in zip(items, expected_review_ids, strict=True):
        canonical = canonical_rows.get(review_id)
        if canonical is None:
            raise PilotReviewError("Pilot selection references a missing full-pack row")
        row = rows_by_id[review_id]
        case_path = pack_root / item[f"{reviewer_id.replace('-', '_')}_case_path"]
        case_payload = _read_json(case_path, "Reviewer Case")
        source_location = case_payload.get("source_location")
        if not isinstance(source_location, dict):
            raise PilotReviewError("Reviewer Case source location is invalid")
        expected_source = _require_string(source_location.get("path"), "source path")
        max_line = source_location.get("end_line")
        if not isinstance(max_line, int) or max_line < 1:
            raise PilotReviewError("Reviewer Case source line bound is invalid")
        try:
            _validate_label_row(
                row,
                canonical,
                reviewer_id=reviewer_id,
                expected_source=expected_source,
                max_line=max_line,
            )
        except PilotReviewError as error:
            if strict:
                raise
            issues.append({"review_id": review_id, "error": str(error)})

    completed_rows = [row for row in rows_by_id.values() if row["status"] == "reviewed"]
    conditions = Counter(
        row["human_condition_label"]
        for row in completed_rows
        if row["human_condition_label"] is not None
    )
    uncertainties = sum(
        row["human_condition_label"] == "uncertain" for row in completed_rows
    )
    summary = PilotReviewSummary(
        selection_id=selection["selection_id"],
        reviewer_id=reviewer_id,
        total=len(raw_reviews),
        completed=len(completed_rows),
        pending=len(raw_reviews) - len(completed_rows),
        uncertain=uncertainties,
        by_rule=Counter(row["rule_id"] for row in completed_rows),
        by_condition=conditions,
        by_confidence=Counter(
            row["confidence"] for row in completed_rows if row["confidence"] is not None
        ),
        by_correlation=Counter(
            row["correlation"]
            for row in completed_rows
            if row["correlation"] is not None
        ),
        by_disposition=Counter(
            row["disposition"]
            for row in completed_rows
            if row["disposition"] is not None
        ),
        valid_completed=len(completed_rows) - len(issues),
        invalid_reviewed=len(issues),
        validation_status="needs_review_fix" if issues else "ready",
        validation_issues=tuple(issues),
    )
    return _ValidatedPilot(selection, labels, canonical_rows, summary)


def validate_pilot_review(
    *, selection_path: Path, pack_root: Path, labels_path: Path, reviewer_id: ReviewerId
) -> PilotReviewSummary:
    """Validate one Pilot Reviewer template and return label-only progress."""

    return _validate_pilot(
        selection_path, pack_root, labels_path, reviewer_id, strict=True
    ).summary


def report_pilot_review(
    *, selection_path: Path, pack_root: Path, labels_path: Path, reviewer_id: ReviewerId
) -> dict[str, Any]:
    """Return a JSON-safe label-only Pilot progress report."""

    return _validate_pilot(
        selection_path, pack_root, labels_path, reviewer_id, strict=False
    ).summary.as_json()


def compare_pilot_reviews(
    *,
    selection_path: Path,
    pack_root: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
) -> dict[str, Any]:
    """Compare two complete Pilot submissions without reading Ground Truth."""

    validated_a = _validate_pilot(
        selection_path, pack_root, reviewer_a_path, "reviewer-a", strict=True
    )
    validated_b = _validate_pilot(
        selection_path, pack_root, reviewer_b_path, "reviewer-b", strict=True
    )
    if validated_a.summary.selection_id != validated_b.summary.selection_id:
        raise PilotReviewError("Pilot submissions use different selections")

    rows_a = {row["review_id"]: row for row in validated_a.labels["reviews"]}
    rows_b = {row["review_id"]: row for row in validated_b.labels["reviews"]}
    comparison_rows: list[dict[str, Any]] = []
    for sequence, item in enumerate(validated_a.selection["items"], start=1):
        review_id = f"review:reviewer-a:{item['review_case_id']}:{item['rule_id']}"
        review_id_b = f"review:reviewer-b:{item['review_case_id']}:{item['rule_id']}"
        row_a = rows_a[review_id]
        row_b = rows_b[review_id_b]
        differing_fields = [
            field for field in _COMPARE_FIELDS if row_a[field] != row_b[field]
        ]
        comparison_rows.append(
            {
                "sequence": sequence,
                "review_case_id": item["review_case_id"],
                "rule_id": item["rule_id"],
                "agreement": not differing_fields,
                "differing_fields": differing_fields,
            }
        )

    agreement_count = sum(row["agreement"] for row in comparison_rows)
    disagreement_count = len(comparison_rows) - agreement_count
    return {
        "format": "agentsec-pilot-review-comparison-report",
        "schema_version": PILOT_SCHEMA_VERSION,
        "selection_id": validated_a.summary.selection_id,
        "reviewer_ids": ["reviewer-a", "reviewer-b"],
        "total": len(comparison_rows),
        "agreement_count": agreement_count,
        "disagreement_count": disagreement_count,
        "agreement_rate": agreement_count / len(comparison_rows)
        if comparison_rows
        else None,
        "rows": comparison_rows,
        "boundary": {
            "ground_truth_used": False,
            "formal_human_evidence": False,
            "adjudication_completed": False,
            "hard_gate_qualification": False,
            "ci_blocking": False,
            "fail_on": False,
        },
    }


def create_pilot_adjudication_template(
    *,
    selection_path: Path,
    pack_root: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Create a disagreement-only, human-completable Pilot worksheet."""

    comparison = compare_pilot_reviews(
        selection_path=selection_path,
        pack_root=pack_root,
        reviewer_a_path=reviewer_a_path,
        reviewer_b_path=reviewer_b_path,
    )
    resolutions = [
        {
            "review_case_id": row["review_case_id"],
            "rule_id": row["rule_id"],
            "differing_fields": row["differing_fields"],
            "final_human_condition_label": None,
            "final_observed_finding": None,
            "final_category": None,
            "final_confidence": None,
            "final_correlation": None,
            "final_disposition": None,
            "rationale_code": None,
            "adjudication_notes": "",
            "status": None,
        }
        for row in comparison["rows"]
        if not row["agreement"]
    ]
    payload = {
        "format": "agentsec-pilot-adjudication-template",
        "schema_version": PILOT_SCHEMA_VERSION,
        "selection_id": comparison["selection_id"],
        "reviewer_ids": ["reviewer-a", "reviewer-b"],
        "comparison": {
            "agreement_count": comparison["agreement_count"],
            "disagreement_count": comparison["disagreement_count"],
        },
        "resolutions": resolutions,
        "boundary": {
            "ground_truth_used": False,
            "formal_adjudication_evidence": False,
            "hard_gate_qualification": False,
            "ci_blocking": False,
            "fail_on": False,
        },
    }
    if output_path.exists() or output_path.is_symlink():
        raise PilotReviewError("adjudication template output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except OSError as error:
        output_path.unlink(missing_ok=True)
        raise PilotReviewError("adjudication template cannot be created") from error
    return payload


def merge_pilot_review(
    *,
    selection_path: Path,
    pack_root: Path,
    labels_path: Path,
    reviewer_id: ReviewerId,
    output_path: Path,
) -> PilotReviewSummary:
    """Merge valid Pilot rows into a new full-template progress snapshot."""

    validated = _validate_pilot(
        selection_path, pack_root, labels_path, reviewer_id, strict=True
    )
    canonical_path = pack_root / reviewer_id / "labels.template.json"
    full_template = _read_json(canonical_path, "Reviewer Pack label template")
    full_rows = full_template["reviews"]
    pilot_by_id = {row["review_id"]: row for row in validated.labels["reviews"]}
    for row in full_rows:
        pilot_row = pilot_by_id.get(row["review_id"])
        if pilot_row is None:
            continue
        if row["status"] is not None and row != pilot_row:
            raise PilotReviewError("merge would overwrite an existing full-pack review")
        row.update(pilot_row)
    full_template["format"] = FULL_LABEL_FORMAT
    full_template["schema_version"] = FULL_PACK_SCHEMA_VERSION
    full_template.pop("pilot_selection_id", None)
    if output_path.exists() or output_path.is_symlink():
        raise PilotReviewError("merge output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(full_template, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except OSError as error:
        output_path.unlink(missing_ok=True)
        raise PilotReviewError("merge output cannot be created") from error
    return validated.summary


def _validate_joint_panel(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PilotReviewError("joint_panel metadata must be an object")
    _exact_keys(
        value,
        {
            "evidence_mode",
            "review_panel_id",
            "reviewer_count",
            "independent_initial_labels",
            "adjudication_required",
            "qualification",
        },
        "joint_panel metadata",
    )
    if value["evidence_mode"] != JOINT_EVIDENCE_MODE:
        raise PilotReviewError("joint_panel evidence_mode is invalid")
    panel_id = _require_string(
        value["review_panel_id"], "review_panel_id", pattern=PANEL_ID_PATTERN
    )
    reviewer_count = value["reviewer_count"]
    if (
        isinstance(reviewer_count, bool)
        or not isinstance(reviewer_count, int)
        or reviewer_count < 2
        or reviewer_count > 16
    ):
        raise PilotReviewError("joint_panel reviewer_count is invalid")
    if value["independent_initial_labels"] is not False:
        raise PilotReviewError(
            "joint_panel must declare independent_initial_labels=false"
        )
    if value["adjudication_required"] is not False:
        raise PilotReviewError("joint_panel must declare adjudication_required=false")
    if value["qualification"] != JOINT_QUALIFICATION:
        raise PilotReviewError("joint_panel qualification is invalid")
    return {
        "evidence_mode": JOINT_EVIDENCE_MODE,
        "review_panel_id": panel_id,
        "reviewer_count": reviewer_count,
        "independent_initial_labels": False,
        "adjudication_required": False,
        "qualification": JOINT_QUALIFICATION,
    }


def _write_new_artifact(output_path: Path, payload: dict[str, Any], label: str) -> None:
    if output_path.exists() or output_path.is_symlink():
        raise PilotReviewError(f"{label} output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except OSError as error:
        output_path.unlink(missing_ok=True)
        raise PilotReviewError(f"{label} output cannot be created") from error


def import_joint_panel_review(
    *,
    selection_path: Path,
    pack_root: Path,
    input_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Formalize joint expert Pilot results into pilot-only evidence.

    The input is a Pilot label template carrying a ``joint_panel`` metadata
    block. Joint panel conclusions are one consensus label set produced by
    experts reviewing together. They are never Reviewer A/B independent
    evidence, never feed Reviewer agreement or Kappa statistics, and never
    qualify a Hard Gate. The output is bounded
    ``agentsec-joint-expert-review-evidence`` with ``qualification=pilot_only``.
    """

    joint_input = _read_json(input_path, "Joint expert pilot input")
    _exact_keys(
        joint_input,
        {
            "corpus_binding_hash",
            "format",
            "joint_panel",
            "pack_id",
            "pilot_selection_id",
            "reviewer_id",
            "reviews",
            "schema_version",
        },
        "Joint expert pilot input",
    )
    panel = _validate_joint_panel(joint_input["joint_panel"])
    reviewer_id = joint_input["reviewer_id"]
    if reviewer_id not in ("reviewer-a", "reviewer-b"):
        raise PilotReviewError("Joint expert pilot input reviewer_id is invalid")

    # Reuse the full Pilot binding chain: the Pack manifest hash, the
    # Selection binding, and every per-row corpus/pack/question-set/
    # case-fingerprint/source hash must match the current Pack, Selection,
    # and Corpus. Any Case, Corpus, or Pack change fails closed here.
    template = {
        key: value for key, value in joint_input.items() if key != "joint_panel"
    }
    validated = _validate_pilot_labels(
        selection_path,
        pack_root,
        template,
        cast(ReviewerId, reviewer_id),
        strict=True,
    )

    reviewed_rows = [
        row for row in validated.labels["reviews"] if row["status"] == "reviewed"
    ]
    if not reviewed_rows:
        raise PilotReviewError("Joint expert pilot input contains no reviewed rows")

    payload: dict[str, Any] = {
        "format": JOINT_EVIDENCE_FORMAT,
        "schema_version": JOINT_EVIDENCE_SCHEMA_VERSION,
        "evidence_id": None,
        "joint_panel": panel,
        "question_set_reviewer_id": reviewer_id,
        "pack_id": validated.labels["pack_id"],
        "corpus_binding_hash": validated.labels["corpus_binding_hash"],
        "pilot_selection_id": validated.selection["selection_id"],
        "reviewed_count": len(reviewed_rows),
        "reviews": reviewed_rows,
        "boundary": {
            "formal_human_evidence": False,
            "p2_cal_04_human_evidence": False,
            "reviewer_independence": False,
            "reviewer_agreement_computable": False,
            "hard_gate_qualification": False,
            "ci_blocking": False,
            "fail_on": False,
        },
    }
    payload["evidence_id"] = (
        "joint-evidence-sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()
    )
    _write_new_artifact(output_path, payload, "Joint expert evidence")
    return {
        "format": "agentsec-joint-expert-review-import-report",
        "schema_version": JOINT_EVIDENCE_SCHEMA_VERSION,
        "selection_id": validated.selection["selection_id"],
        "review_panel_id": panel["review_panel_id"],
        "question_set_reviewer_id": reviewer_id,
        "reviewed_count": len(reviewed_rows),
        "evidence_id": payload["evidence_id"],
        "boundary": payload["boundary"],
    }


def validate_joint_expert_evidence(
    *,
    selection_path: Path,
    pack_root: Path,
    evidence_path: Path,
) -> dict[str, Any]:
    """Independently validate one checked-in Joint Expert Evidence artifact.

    This validator deliberately uses only the Reviewer Pack, Pilot Selection,
    and the evidence artifact itself. It never reads Calibration Ground Truth
    and never produces agreement, calibration, Hard Gate, or CI conclusions.
    The content-addressed identifier and every immutable row binding are
    checked again so a copied artifact can be audited without trusting the
    importer that originally wrote it.
    """

    payload = _read_json(evidence_path, "Joint expert evidence")
    _exact_keys(
        payload,
        {
            "boundary",
            "corpus_binding_hash",
            "evidence_id",
            "format",
            "joint_panel",
            "pack_id",
            "pilot_selection_id",
            "question_set_reviewer_id",
            "reviewed_count",
            "reviews",
            "schema_version",
        },
        "Joint expert evidence",
    )
    if (
        payload["format"] != JOINT_EVIDENCE_FORMAT
        or payload["schema_version"] != JOINT_EVIDENCE_SCHEMA_VERSION
    ):
        raise PilotReviewError("Joint expert evidence format or version is invalid")

    panel = _validate_joint_panel(payload["joint_panel"])
    if payload["joint_panel"] != panel:
        raise PilotReviewError("Joint expert evidence panel metadata is not canonical")

    reviewer_id = payload["question_set_reviewer_id"]
    if reviewer_id not in ("reviewer-a", "reviewer-b"):
        raise PilotReviewError("Joint expert evidence reviewer_id is invalid")
    reviewer_id = cast(ReviewerId, reviewer_id)

    pack_id, corpus_hash, manifest = _load_pack_identity(pack_root)
    selection = _validate_selection(selection_path, pack_id, corpus_hash)
    if (
        payload["pack_id"] != pack_id
        or payload["corpus_binding_hash"] != corpus_hash
        or payload["pilot_selection_id"] != selection["selection_id"]
    ):
        raise PilotReviewError("Joint expert evidence binding is invalid")

    boundary = payload["boundary"]
    expected_boundary = {
        "formal_human_evidence": False,
        "p2_cal_04_human_evidence": False,
        "reviewer_independence": False,
        "reviewer_agreement_computable": False,
        "hard_gate_qualification": False,
        "ci_blocking": False,
        "fail_on": False,
    }
    if not isinstance(boundary, dict):
        raise PilotReviewError("Joint expert evidence boundary is invalid")
    _exact_keys(boundary, set(expected_boundary), "Joint expert evidence boundary")
    if boundary != expected_boundary:
        raise PilotReviewError("Joint expert evidence boundary is invalid")

    evidence_id = _require_string(
        payload["evidence_id"],
        "Joint expert evidence ID",
        pattern=re.compile(r"^joint-evidence-sha256:[0-9a-f]{64}$"),
    )
    unsigned = dict(payload)
    unsigned["evidence_id"] = None
    expected_evidence_id = (
        "joint-evidence-sha256:" + hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    )
    if evidence_id != expected_evidence_id:
        raise PilotReviewError("Joint expert evidence ID does not match content")

    rows = payload["reviews"]
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise PilotReviewError("Joint expert evidence reviews are invalid")
    reviewed_count = payload["reviewed_count"]
    if (
        isinstance(reviewed_count, bool)
        or not isinstance(reviewed_count, int)
        or reviewed_count != len(rows)
        or reviewed_count < 1
    ):
        raise PilotReviewError("Joint expert evidence reviewed_count is invalid")

    _, _, canonical_rows = _load_canonical_rows(pack_root, reviewer_id, manifest)
    selection_items = selection["items"]
    rows_by_review_id: dict[str, tuple[int, dict[str, Any]]] = {}
    for sequence, item in enumerate(selection_items, start=1):
        review_id = f"review:{reviewer_id}:{item['review_case_id']}:{item['rule_id']}"
        rows_by_review_id[review_id] = (sequence, cast(dict[str, Any], item))

    seen: set[str] = set()
    sequences: list[int] = []
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            raise PilotReviewError("Joint expert evidence review row is invalid")
        row = cast(dict[str, Any], raw_row)
        review_id = _require_string(row.get("review_id"), "review_id")
        if review_id in seen:
            raise PilotReviewError("Joint expert evidence contains duplicate review_id")
        binding = rows_by_review_id.get(review_id)
        if binding is None:
            raise PilotReviewError(
                "Joint expert evidence row is outside Pilot Selection"
            )
        sequence, item = binding
        canonical = canonical_rows.get(review_id)
        if canonical is None:
            raise PilotReviewError(
                "Joint expert evidence references a missing Pack row"
            )
        case_path = pack_root / item[f"{reviewer_id.replace('-', '_')}_case_path"]
        case_payload = _read_json(case_path, "Reviewer Case")
        source_location = case_payload.get("source_location")
        if not isinstance(source_location, dict):
            raise PilotReviewError("Reviewer Case source location is invalid")
        expected_source = _require_string(source_location.get("path"), "source path")
        max_line = source_location.get("end_line")
        if not isinstance(max_line, int) or isinstance(max_line, bool) or max_line < 1:
            raise PilotReviewError("Reviewer Case source line bound is invalid")
        _validate_label_row(
            row,
            canonical,
            reviewer_id=reviewer_id,
            expected_source=expected_source,
            max_line=max_line,
        )
        seen.add(review_id)
        sequences.append(sequence)

    if sequences != sorted(sequences):
        raise PilotReviewError("Joint expert evidence review order is invalid")

    return {
        "format": "agentsec-joint-expert-review-validation-report",
        "schema_version": JOINT_EVIDENCE_SCHEMA_VERSION,
        "valid": True,
        "evidence_id": evidence_id,
        "selection_id": selection["selection_id"],
        "review_panel_id": panel["review_panel_id"],
        "question_set_reviewer_id": reviewer_id,
        "reviewed_count": reviewed_count,
        "boundary": expected_boundary,
    }

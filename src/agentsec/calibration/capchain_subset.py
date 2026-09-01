"""Gate-scoped Human Evidence import for the 40-case CAP-CHAIN pilot.

This module intentionally stays separate from the 431-case P2-CAL-04 importer.
The 40-case package is a bounded, post-review evidence artifact: it preserves
both independent submissions, records only the five user-adjudicated
Correlation differences, and never derives TP/FP/FN/TN or enables a Gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Literal, cast

SUBSET_FORMAT = "agentsec-gate-scoped-human-evidence"
SUBSET_SCHEMA_VERSION = "0.1.0"
SUBSET_ADJUDICATION_INPUT_FORMAT = "agentsec-gate-scoped-adjudication-input"
SUBSET_ADJUDICATION_FORMAT = "agentsec-gate-scoped-adjudication-set"
SUBSET_CONFIDENCE_FORMAT = "agentsec-gate-scoped-human-confidence-set"
SUBSET_RESOLUTION_FORMAT = "agentsec-gate-scoped-human-resolution-set"
REVIEW_LABEL_FORMAT = "agentsec-independent-review-label-template"
PACK_FORMAT = "agentsec-gate-scoped-review-package"
GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"
REVIEWERS = ("reviewer-a", "reviewer-b")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_NOTES_LENGTH = 2_000
MAX_SUMMARY_LENGTH = 512
MAX_EVIDENCE_LOCATIONS = 16
HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PACK_ID_PATTERN = re.compile(r"^reviewer-pack-sha256:[0-9a-f]{64}$")
PACKAGE_ID_PATTERN = re.compile(r"^gate-review-package-sha256:[0-9a-f]{64}$")
SELECTION_ID_PATTERN = re.compile(r"^gate-subset-selection-sha256:[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^review-case-[0-9a-f]{20}$")
RULE_ID_PATTERN = re.compile(r"^CAP-[A-Z0-9]+-[0-9]{3}$")
STABLE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")

_ALLOWED_FIELDS = {
    "human_condition_label",
    "observed_finding",
    "category",
    "confidence",
    "correlation",
    "disposition",
}
_IMMUTABLE_FIELDS = {
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
_REQUIRED_REVIEW_KEYS = {
    "category",
    "classification",
    "confidence",
    "corpus_binding_hash",
    "correlation",
    "disposition",
    "evidence_locations",
    "finding_summary",
    "human_condition_label",
    "observed_finding",
    "pack_id",
    "question_set_sha256",
    "rationale_code",
    "review_case_fingerprint",
    "review_case_id",
    "review_id",
    "review_notes",
    "reviewer_id",
    "rule_id",
    "source_sha256",
    "status",
}


class CapchainSubsetError(ValueError):
    """Raised when a bounded CAP-CHAIN subset artifact is invalid."""


ReviewerId = Literal["reviewer-a", "reviewer-b"]


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _artifact_id(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return (
        "human-evidence-sha256:"
        + hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CapchainSubsetError(f"{label} is missing or unsafe")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CapchainSubsetError(f"{label} cannot be read") from error
    if len(data) > MAX_JSON_BYTES:
        raise CapchainSubsetError(f"{label} exceeds the bounded size")
    try:
        payload: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise CapchainSubsetError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise CapchainSubsetError(f"{label} must be a JSON object")
    return cast(dict[str, Any], payload)


def _exact_keys(payload: dict[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        raise CapchainSubsetError(f"{label} has unsupported or missing fields")


def _require_string(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 512,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CapchainSubsetError(f"{label} is invalid")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CapchainSubsetError(f"{label} is invalid")
    return value


def _choice(value: object, choices: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise CapchainSubsetError(f"{label} is invalid")
    return value


def _validate_package(package_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _read_json(package_root / "package-manifest.json", "package manifest")
    selection = _read_json(package_root / "selection.json", "selection")
    _exact_keys(
        manifest,
        {
            "expected_labels_included",
            "files",
            "format",
            "gate_id",
            "ground_truth_included",
            "joint_evidence_included",
            "package_id",
            "review_count",
            "reviewer_count",
            "schema_version",
            "selection_id",
            "source_corpus_binding_hash",
            "source_pack_id",
        },
        "package manifest",
    )
    if manifest["format"] != PACK_FORMAT or manifest["schema_version"] != "0.1.0":
        raise CapchainSubsetError("package manifest format or version is invalid")
    _require_string(manifest["package_id"], "package_id", pattern=PACKAGE_ID_PATTERN)
    _require_string(
        manifest["selection_id"], "selection_id", pattern=SELECTION_ID_PATTERN
    )
    _require_string(
        manifest["source_pack_id"], "source_pack_id", pattern=PACK_ID_PATTERN
    )
    _require_string(
        manifest["source_corpus_binding_hash"],
        "source_corpus_binding_hash",
        pattern=HASH_PATTERN,
    )
    if (
        manifest["gate_id"] != GATE_ID
        or manifest["review_count"] != 40
        or manifest["reviewer_count"] != 2
        or manifest["expected_labels_included"] is not False
        or manifest["ground_truth_included"] is not False
        or manifest["joint_evidence_included"] is not False
    ):
        raise CapchainSubsetError("package manifest boundary is invalid")
    if (
        selection.get("format") != "agentsec-gate-scoped-independent-review-selection"
        or selection.get("schema_version") != "0.1.0"
        or selection.get("selection_id") != manifest["selection_id"]
        or selection.get("source_pack_id") != manifest["source_pack_id"]
        or selection.get("source_corpus_binding_hash")
        != manifest["source_corpus_binding_hash"]
        or selection.get("gate_id") != GATE_ID
        or selection.get("review_count") != 40
    ):
        raise CapchainSubsetError("selection binding is invalid")
    items = selection.get("items")
    if not isinstance(items, list) or len(items) != 40:
        raise CapchainSubsetError("selection must contain exactly 40 Cases")
    for item in items:
        if not isinstance(item, dict):
            raise CapchainSubsetError("selection item is invalid")
        case_id = _require_string(
            item.get("review_case_id"),
            "selection review_case_id",
            pattern=CASE_ID_PATTERN,
        )
        if item.get("rule_id") != RULE_ID:
            raise CapchainSubsetError("selection rule binding is invalid")
        expected_question = f"question:{case_id}:{RULE_ID}"
        if item.get("question_id") != expected_question:
            raise CapchainSubsetError("selection question binding is invalid")
    return manifest, selection


def _case_context(
    package_root: Path,
    reviewer_id: ReviewerId,
    row: dict[str, Any],
) -> tuple[dict[str, Any], Path, int]:
    case_id = _require_string(
        row.get("review_case_id"), "review_case_id", pattern=CASE_ID_PATTERN
    )
    case_dir = package_root / reviewer_id / "cases" / case_id
    case_path = case_dir / "case.json"
    case = _read_json(case_path, "review Case")
    if (
        case.get("format") != "agentsec-independent-review-case"
        or case.get("schema_version") != "0.3.0"
        or case.get("review_case_id") != case_id
    ):
        if case.get("format") != "agentsec-independent-review-case":
            raise CapchainSubsetError("review Case format is invalid")
        if (
            case.get("schema_version") != "0.3.0"
            or case.get("review_case_id") != case_id
        ):
            raise CapchainSubsetError("review Case binding is invalid")
    source_location = case.get("source_location")
    if not isinstance(source_location, dict):
        raise CapchainSubsetError("review Case source location is invalid")
    source_name = _require_string(source_location.get("path"), "source path")
    if (
        SAFE_PATH_PATTERN.fullmatch(source_name) is None
        or source_name.startswith("/")
        or "\\" in source_name
        or any(part in {"", ".", ".."} for part in source_name.split("/"))
        or not source_name.startswith("source.")
    ):
        raise CapchainSubsetError("review Case source path is unsafe")
    source_path = case_dir / source_name
    if source_path.is_symlink() or not source_path.is_file():
        raise CapchainSubsetError("review Case source is missing or unsafe")
    lines = source_path.read_text(encoding="utf-8").splitlines()
    declared_end = source_location.get("end_line")
    if (
        not isinstance(declared_end, int)
        or declared_end < 1
        or declared_end > len(lines)
    ):
        raise CapchainSubsetError("review Case source line count is invalid")
    source_hash = _sha256(source_path.read_bytes())
    if source_hash != row.get("source_sha256"):
        raise CapchainSubsetError("review source hash does not match the submission")
    return case, source_path, declared_end


def _validate_evidence(
    value: object,
    *,
    source_name: str,
    max_line: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_EVIDENCE_LOCATIONS:
        raise CapchainSubsetError("review evidence_locations is invalid")
    result: list[dict[str, Any]] = []
    for location in value:
        if not isinstance(location, dict) or set(location) != {
            "path",
            "start_line",
            "end_line",
        }:
            raise CapchainSubsetError("review evidence location is invalid")
        path = _require_string(location["path"], "evidence path")
        start = location["start_line"]
        end = location["end_line"]
        if (
            path != source_name
            or SAFE_PATH_PATTERN.fullmatch(path) is None
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or isinstance(start, bool)
            or not isinstance(start, int)
            or isinstance(end, bool)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > max_line
        ):
            raise CapchainSubsetError("review evidence location is unsafe or invalid")
        result.append({"path": path, "start_line": start, "end_line": end})
    return result


def _validate_submission_payload(
    package_root: Path,
    reviewer_id: ReviewerId,
    template_path: Path,
    completed_path: Path,
) -> dict[str, Any]:
    template = _read_json(template_path, f"{reviewer_id} template")
    completed = _read_json(completed_path, f"{reviewer_id} completed submission")
    expected_top = {
        "corpus_binding_hash",
        "format",
        "pack_id",
        "reviewer_id",
        "reviews",
        "schema_version",
    }
    _exact_keys(completed, expected_top, f"{reviewer_id} completed submission")
    if (
        completed.get("format") != REVIEW_LABEL_FORMAT
        or completed.get("schema_version") != "0.3.0"
        or completed.get("reviewer_id") != reviewer_id
        or completed.get("pack_id") != template.get("pack_id")
        or completed.get("corpus_binding_hash") != template.get("corpus_binding_hash")
    ):
        raise CapchainSubsetError(f"{reviewer_id} completed binding is invalid")
    template_rows = template.get("reviews")
    rows = completed.get("reviews")
    if (
        not isinstance(template_rows, list)
        or not isinstance(rows, list)
        or len(rows) != 40
    ):
        raise CapchainSubsetError(f"{reviewer_id} submission must contain 40 rows")
    if len(template_rows) != len(rows):
        raise CapchainSubsetError(f"{reviewer_id} row count differs from template")
    canonical_by_id: dict[str, dict[str, Any]] = {}
    for template_row in template_rows:
        if not isinstance(template_row, dict):
            raise CapchainSubsetError(f"{reviewer_id} template row is invalid")
        review_id = _require_string(template_row.get("review_id"), "template review_id")
        if review_id in canonical_by_id:
            raise CapchainSubsetError("template contains duplicate review_id")
        canonical_by_id[review_id] = template_row
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != _REQUIRED_REVIEW_KEYS:
            raise CapchainSubsetError(f"{reviewer_id} row fields are invalid")
        review_id = _require_string(row.get("review_id"), "review_id")
        canonical = canonical_by_id.get(review_id)
        if canonical is None:
            raise CapchainSubsetError("submission contains an unknown review_id")
        if any(row.get(key) != canonical.get(key) for key in _IMMUTABLE_FIELDS):
            raise CapchainSubsetError("submission changed an immutable binding")
        if row["status"] != "reviewed":
            raise CapchainSubsetError("all submitted rows must be reviewed")
        _choice(
            row["human_condition_label"],
            {"match", "no_match", "uncertain"},
            "human_condition_label",
        )
        _choice(
            row["observed_finding"],
            {"present", "absent", "uncertain"},
            "observed_finding",
        )
        _choice(
            row["category"],
            {
                "standard",
                "policy_accepted_risk",
                "out_of_scope",
                "runtime_uncertainty",
                "unresolved",
            },
            "category",
        )
        _choice(row["confidence"], {"A", "B", "C", "D"}, "confidence")
        _choice(
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
        )
        _choice(
            row["disposition"],
            {"keep", "tune", "shadow", "retire", "more_data"},
            "disposition",
        )
        _require_string(
            row["finding_summary"], "finding_summary", maximum=MAX_SUMMARY_LENGTH
        )
        if not row["finding_summary"].strip():
            raise CapchainSubsetError("finding_summary must not be empty")
        _require_string(
            row["rationale_code"],
            "rationale_code",
            pattern=STABLE_CODE_PATTERN,
            maximum=128,
        )
        if (
            not isinstance(row["review_notes"], str)
            or len(row["review_notes"]) > MAX_NOTES_LENGTH
        ):
            raise CapchainSubsetError("review_notes is invalid")
        if row["classification"] is not None:
            raise CapchainSubsetError(
                "Reviewer submission must not provide classification"
            )
        case, source_path, max_line = _case_context(package_root, reviewer_id, row)
        source_name = str(case["source_location"]["path"])
        evidence = _validate_evidence(
            row["evidence_locations"], source_name=source_name, max_line=max_line
        )
        normalized = dict(row)
        normalized["evidence_locations"] = evidence
        normalized_rows.append(normalized)
    expected_order = [row.get("review_id") for row in template_rows]
    if [row.get("review_id") for row in normalized_rows] != expected_order:
        raise CapchainSubsetError(
            f"{reviewer_id} submission order differs from template"
        )
    return {"metadata": completed, "rows": normalized_rows}


def load_and_validate_submissions(
    package_root: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate package identity and both completed independent submissions."""
    package_root = package_root.resolve()
    manifest, selection = _validate_package(package_root)
    a = _validate_submission_payload(
        package_root,
        "reviewer-a",
        package_root / "reviewer-a" / "labels.template.json",
        reviewer_a_path,
    )
    b = _validate_submission_payload(
        package_root,
        "reviewer-b",
        package_root / "reviewer-b" / "labels.template.json",
        reviewer_b_path,
    )
    if (
        a["metadata"]["pack_id"] != manifest["source_pack_id"]
        or b["metadata"]["pack_id"] != manifest["source_pack_id"]
    ):
        raise CapchainSubsetError(
            "Reviewer Pack binding does not match the subset package"
        )
    return manifest, selection, {"reviewer-a": a, "reviewer-b": b}


def _by_case(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["review_case_id"]: row for row in payload["rows"]}


def compare_submissions(
    submissions: dict[str, dict[str, Any]],
    selection: dict[str, Any],
) -> dict[str, Any]:
    """Compare A/B only on bounded structured review fields."""
    a = _by_case(submissions["reviewer-a"])
    b = _by_case(submissions["reviewer-b"])
    if set(a) != set(b):
        raise CapchainSubsetError("Reviewer A/B Case sets differ")
    rows: list[dict[str, Any]] = []
    for item in selection["items"]:
        case_id = item["review_case_id"]
        ar = a[case_id]
        br = b[case_id]
        differing = [
            field for field in sorted(_ALLOWED_FIELDS) if ar[field] != br[field]
        ]
        rows.append(
            {
                "sequence": item["sequence"],
                "review_case_id": case_id,
                "rule_id": RULE_ID,
                "review_ids": [ar["review_id"], br["review_id"]],
                "differing_fields": differing,
                "agreement": not differing,
            }
        )
    return {
        "total": len(rows),
        "agreement_count": sum(row["agreement"] for row in rows),
        "disagreement_count": sum(not row["agreement"] for row in rows),
        "field_agreement": {
            field: sum(
                a[item["review_case_id"]][field] == b[item["review_case_id"]][field]
                for item in selection["items"]
            )
            for field in sorted(_ALLOWED_FIELDS)
        },
        "rows": rows,
    }


def _validate_adjudication_input(
    path: Path,
    manifest: dict[str, Any],
    selection: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    payload = _read_json(path, "adjudication input")
    _exact_keys(
        payload,
        {
            "adjudicator_id",
            "adjudications",
            "format",
            "gate_id",
            "package_id",
            "rule_id",
            "schema_version",
            "selection_id",
        },
        "adjudication input",
    )
    if (
        payload["format"] != SUBSET_ADJUDICATION_INPUT_FORMAT
        or payload["schema_version"] != SUBSET_SCHEMA_VERSION
        or payload["gate_id"] != GATE_ID
        or payload["rule_id"] != RULE_ID
        or payload["package_id"] != manifest["package_id"]
        or payload["selection_id"] != selection["selection_id"]
    ):
        raise CapchainSubsetError("adjudication input binding is invalid")
    _require_string(payload["adjudicator_id"], "adjudicator_id", maximum=128)
    differences = {
        row["review_case_id"] for row in comparison["rows"] if not row["agreement"]
    }
    raw = payload["adjudications"]
    if (
        not isinstance(raw, list)
        or {item.get("review_case_id") for item in raw if isinstance(item, dict)}
        != differences
    ):
        raise CapchainSubsetError(
            "adjudication input must contain exactly all disagreements"
        )
    result: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {
            "adjudication_notes",
            "final_correlation",
            "final_rationale_code",
            "review_case_id",
        }:
            raise CapchainSubsetError("adjudication record fields are invalid")
        case_id = _require_string(
            item["review_case_id"],
            "adjudication review_case_id",
            pattern=CASE_ID_PATTERN,
        )
        if case_id not in differences:
            raise CapchainSubsetError("adjudication record is not a real disagreement")
        _choice(
            item["final_correlation"],
            {
                "same_target",
                "parent_child",
                "same_source",
                "explicit_relation",
                "agent_wide",
                "incomplete_coverage",
            },
            "final_correlation",
        )
        _require_string(
            item["final_rationale_code"],
            "final_rationale_code",
            pattern=STABLE_CODE_PATTERN,
            maximum=128,
        )
        if (
            not isinstance(item["adjudication_notes"], str)
            or not item["adjudication_notes"].strip()
            or len(item["adjudication_notes"]) > MAX_NOTES_LENGTH
        ):
            raise CapchainSubsetError("adjudication_notes is invalid")
        result[case_id] = dict(item)
    return result


def _union_evidence(*rows: dict[str, Any]) -> list[dict[str, Any]]:
    values = {
        (item["path"], item["start_line"], item["end_line"])
        for row in rows
        for item in row["evidence_locations"]
    }
    return [
        {"path": path, "start_line": start, "end_line": end}
        for path, start, end in sorted(values)
    ]


def build_subset_evidence(
    *,
    package_root: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudication_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Validate and materialize the three bounded Human Evidence artifacts."""
    manifest, selection, submissions = load_and_validate_submissions(
        package_root, reviewer_a_path, reviewer_b_path
    )
    comparison = compare_submissions(submissions, selection)
    adjudications = _validate_adjudication_input(
        adjudication_path, manifest, selection, comparison
    )
    a = _by_case(submissions["reviewer-a"])
    b = _by_case(submissions["reviewer-b"])
    final_rows: list[dict[str, Any]] = []
    adjudication_rows: list[dict[str, Any]] = []
    confidence_reviews: list[dict[str, Any]] = []
    final_confidence: list[dict[str, Any]] = []
    for item in selection["items"]:
        case_id = item["review_case_id"]
        ar = a[case_id]
        br = b[case_id]
        decision = adjudications.get(case_id)
        final = dict(ar)
        final["status"] = "adjudicated"
        final["review_ids"] = [ar["review_id"], br["review_id"]]
        final["adjudication_required"] = decision is not None
        final["evidence_locations"] = _union_evidence(ar, br)
        final.pop("review_id", None)
        final.pop("reviewer_id", None)
        if decision is not None:
            final["correlation"] = decision["final_correlation"]
            final["rationale_code"] = decision["final_rationale_code"]
            final["adjudication_notes"] = decision["adjudication_notes"]
            adjudication_rows.append(
                {
                    "status": "adjudicated",
                    "review_case_id": case_id,
                    "rule_id": RULE_ID,
                    "review_ids": [ar["review_id"], br["review_id"]],
                    "reviewer_a_correlation": ar["correlation"],
                    "reviewer_b_correlation": br["correlation"],
                    "final_correlation": decision["final_correlation"],
                    "final_rationale_code": decision["final_rationale_code"],
                    "adjudication_notes": decision["adjudication_notes"],
                    "evidence_locations": _union_evidence(ar, br),
                    "source_sha256": ar["source_sha256"],
                }
            )
        else:
            final["adjudication_notes"] = (
                "No adjudication required; structured fields agreed."
            )
        final_rows.append(final)
        for reviewer_id, row in (("reviewer-a", ar), ("reviewer-b", br)):
            confidence_reviews.append(
                {
                    "review_case_id": case_id,
                    "rule_id": RULE_ID,
                    "reviewer_id": reviewer_id,
                    "review_id": row["review_id"],
                    "confidence": row["confidence"],
                    "correlation": row["correlation"],
                    "rationale_code": row["rationale_code"],
                    "status": "reviewed",
                }
            )
        final_confidence.append(
            {
                "review_case_id": case_id,
                "rule_id": RULE_ID,
                "confidence": final["confidence"],
                "correlation": final["correlation"],
                "rationale_code": final["rationale_code"],
                "status": "adjudicated",
            }
        )
    common = {
        "schema_version": SUBSET_SCHEMA_VERSION,
        "gate_id": GATE_ID,
        "rule_id": RULE_ID,
        "package_id": manifest["package_id"],
        "selection_id": selection["selection_id"],
        "source_pack_id": manifest["source_pack_id"],
        "source_corpus_binding_hash": manifest["source_corpus_binding_hash"],
        "reviewer_ids": list(REVIEWERS),
        "evidence_mode": "human",
        "boundary": {
            "formal_human_evidence": True,
            "gate_qualification": False,
            "hard_gate": False,
            "ci_blocking": False,
            "runtime_capability_verified": False,
            "ground_truth_used": False,
            "llm_used": False,
        },
    }
    adjudication_artifact = {
        **common,
        "format": SUBSET_ADJUDICATION_FORMAT,
        "status": "complete",
        "adjudicator_id": _read_json(adjudication_path, "adjudication input")[
            "adjudicator_id"
        ],
        "comparison": {
            "total": comparison["total"],
            "agreement_count": comparison["agreement_count"],
            "disagreement_count": comparison["disagreement_count"],
            "field_agreement": comparison["field_agreement"],
        },
        "adjudications": adjudication_rows,
        "artifact_id": None,
    }
    adjudication_artifact["artifact_id"] = _artifact_id(adjudication_artifact)
    confidence_artifact = {
        **common,
        "format": SUBSET_CONFIDENCE_FORMAT,
        "status": "complete",
        "summary": {
            "case_count": 40,
            "review_count": 80,
            "confidence_agreement_count": comparison["field_agreement"]["confidence"],
            "confidence_agreement_rate": comparison["field_agreement"]["confidence"]
            / 40,
            "correlation_agreement_before_adjudication": comparison["field_agreement"][
                "correlation"
            ],
            "correlation_agreement_before_adjudication_rate": comparison[
                "field_agreement"
            ]["correlation"]
            / 40,
            "correlation_agreement_after_adjudication": 40,
            "correlation_agreement_after_adjudication_rate": 1.0,
        },
        "reviews": confidence_reviews,
        "final": final_confidence,
        "artifact_id": None,
    }
    confidence_artifact["artifact_id"] = _artifact_id(confidence_artifact)
    resolution_artifact = {
        **common,
        "format": SUBSET_RESOLUTION_FORMAT,
        "status": "complete",
        "summary": {
            "case_count": 40,
            "adjudication_required_count": len(adjudication_rows),
            "adjudication_completed_count": len(adjudication_rows),
            "unresolved_count": 0,
            "match_count": sum(
                row["human_condition_label"] == "match" for row in final_rows
            ),
            "no_match_count": sum(
                row["human_condition_label"] == "no_match" for row in final_rows
            ),
        },
        "resolutions": final_rows,
        "artifact_id": None,
    }
    resolution_artifact["artifact_id"] = _artifact_id(resolution_artifact)
    outputs = {
        "human-capchain-40-adjudications.json": adjudication_artifact,
        "human-capchain-40-confidence.json": confidence_artifact,
        "human-capchain-40-resolutions.json": resolution_artifact,
    }
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in outputs.items():
        path = output_dir / name
        if path.exists() or path.is_symlink():
            raise CapchainSubsetError(f"output already exists: {name}")
        data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(data)
        except OSError as error:
            path.unlink(missing_ok=True)
            raise CapchainSubsetError(
                "Human Evidence output cannot be created"
            ) from error
    return {
        "case_count": 40,
        "review_count": 80,
        "agreement_count": comparison["agreement_count"],
        "disagreement_count": comparison["disagreement_count"],
        "adjudication_count": len(adjudication_rows),
        "output_dir": str(output_dir),
        "artifact_ids": {
            name: payload["artifact_id"] for name, payload in outputs.items()
        },
    }

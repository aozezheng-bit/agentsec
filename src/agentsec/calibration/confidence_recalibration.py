"""Import the P2-15A-QUAL-02 Confidence-only recalibration round."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

CONFIDENCE_SUBMISSION_FORMAT = "agentsec-confidence-recalibration-submission"
CONFIDENCE_EVIDENCE_FORMAT = "agentsec-gate-scoped-human-confidence-set"
SCHEMA_VERSION = "0.1.0"
TASK_ID = "P2-15A-QUAL-02"
GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"
REVIEWERS = ("reviewer-a", "reviewer-b")
MAX_JSON_BYTES = 8 * 1024 * 1024


class ConfidenceRecalibrationError(ValueError):
    """Raised when a Confidence-only submission cannot be imported safely."""


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _human_artifact_id(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return "human-evidence-sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ConfidenceRecalibrationError(f"{label} is missing or unsafe")
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        raise ConfidenceRecalibrationError(f"{label} exceeds bounded size")
    try:
        payload: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ConfidenceRecalibrationError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise ConfidenceRecalibrationError(f"{label} must be an object")
    return cast(dict[str, Any], payload)


def _write_private(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ConfidenceRecalibrationError(f"output already exists: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as error:
        path.unlink(missing_ok=True)
        raise ConfidenceRecalibrationError(
            "Confidence v2 output cannot be created"
        ) from error


def _validate_submission(
    *,
    package_root: Path,
    reviewer_id: str,
    path: Path,
) -> dict[str, dict[str, Any]]:
    package_manifest = _read_json(
        package_root / "package-manifest.json", "Confidence package manifest"
    )
    selection = _read_json(package_root / "selection.json", "Confidence selection")
    template = _read_json(
        package_root / reviewer_id / "labels.template.json",
        f"{reviewer_id} Confidence template",
    )
    payload = _read_json(path, f"{reviewer_id} Confidence submission")
    expected_top = {
        "format",
        "schema_version",
        "task_id",
        "gate_id",
        "rule_id",
        "package_id",
        "selection_id",
        "reviewer_id",
        "reviews",
    }
    if set(payload) != expected_top:
        raise ConfidenceRecalibrationError("Confidence submission fields are invalid")
    if (
        payload["format"] != CONFIDENCE_SUBMISSION_FORMAT
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["task_id"] != TASK_ID
        or payload["gate_id"] != GATE_ID
        or payload["rule_id"] != RULE_ID
        or payload["package_id"] != package_manifest["package_id"]
        or payload["selection_id"] != selection["selection_id"]
        or payload["reviewer_id"] != reviewer_id
    ):
        raise ConfidenceRecalibrationError("Confidence submission binding is invalid")
    rows = payload["reviews"]
    template_rows = template["reviews"]
    if (
        not isinstance(rows, list)
        or len(rows) != 20
        or not isinstance(template_rows, list)
    ):
        raise ConfidenceRecalibrationError("Confidence submission must contain 20 rows")
    canonical = {row["review_case_id"]: row for row in template_rows}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "review_case_id",
            "review_case_fingerprint",
            "source_sha256",
            "confidence",
            "confidence_rationale",
            "status",
        }:
            raise ConfidenceRecalibrationError("Confidence row fields are invalid")
        case_id = row["review_case_id"]
        expected = canonical.get(case_id)
        if expected is None:
            raise ConfidenceRecalibrationError("Confidence row references unknown Case")
        for key in ("review_case_id", "review_case_fingerprint", "source_sha256"):
            if row[key] != expected[key]:
                raise ConfidenceRecalibrationError(
                    "Confidence immutable binding changed"
                )
        if row["status"] != "reviewed":
            raise ConfidenceRecalibrationError("Confidence row is not reviewed")
        if row["confidence"] not in {"A", "B", "C", "D"}:
            raise ConfidenceRecalibrationError("Confidence grade is invalid")
        if (
            not isinstance(row["confidence_rationale"], str)
            or not row["confidence_rationale"].strip()
            or len(row["confidence_rationale"]) > 2_000
        ):
            raise ConfidenceRecalibrationError("Confidence rationale is invalid")
        if case_id in result:
            raise ConfidenceRecalibrationError("Confidence Case is duplicated")
        result[case_id] = dict(row)
    if set(result) != set(canonical):
        raise ConfidenceRecalibrationError(
            "Confidence submission Case set is incomplete"
        )
    return result


def _validate_v1(v1: dict[str, Any]) -> None:
    if (
        v1.get("format") != CONFIDENCE_EVIDENCE_FORMAT
        or v1.get("schema_version") != SCHEMA_VERSION
        or v1.get("gate_id") != GATE_ID
        or v1.get("rule_id") != RULE_ID
    ):
        raise ConfidenceRecalibrationError("v1 Human Confidence artifact is invalid")
    if v1.get("artifact_id") != _human_artifact_id(v1):
        raise ConfidenceRecalibrationError(
            "v1 Human Confidence artifact hash is invalid"
        )
    if not isinstance(v1.get("reviews"), list) or len(v1["reviews"]) != 80:
        raise ConfidenceRecalibrationError(
            "v1 Human Confidence reviewer rows are invalid"
        )
    if not isinstance(v1.get("final"), list) or len(v1["final"]) != 40:
        raise ConfidenceRecalibrationError("v1 Human Confidence final rows are invalid")


def build_confidence_v2(
    *,
    package_root: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    v1_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Validate A/B Confidence re-review and create a superseding v2 artifact."""
    v1 = _read_json(v1_path, "v1 Human Confidence artifact")
    _validate_v1(v1)
    a = _validate_submission(
        package_root=package_root, reviewer_id="reviewer-a", path=reviewer_a_path
    )
    b = _validate_submission(
        package_root=package_root, reviewer_id="reviewer-b", path=reviewer_b_path
    )
    if set(a) != set(b):
        raise ConfidenceRecalibrationError("Reviewer A/B Confidence Case sets differ")
    v1_final = {row["review_case_id"]: row for row in v1["final"]}
    selected_ids = set(a)
    if selected_ids - set(v1_final):
        raise ConfidenceRecalibrationError(
            "Confidence v1 is missing a recalibration Case"
        )
    reviewer_rows: list[dict[str, Any]] = []
    for old in v1["reviews"]:
        case_id = old["review_case_id"]
        reviewer_id = old["reviewer_id"]
        row = dict(old)
        if case_id in selected_ids:
            source = a if reviewer_id == "reviewer-a" else b
            if case_id not in source:
                raise ConfidenceRecalibrationError(
                    "Confidence v2 is missing a selected Reviewer row"
                )
            row["confidence"] = source[case_id]["confidence"]
            row["confidence_rationale"] = source[case_id]["confidence_rationale"]
            row["calibration_round"] = "v2"
        else:
            row["calibration_round"] = "v1-retained"
        reviewer_rows.append(row)
    final_rows: list[dict[str, Any]] = []
    for old in v1["final"]:
        case_id = old["review_case_id"]
        final = dict(old)
        if case_id in selected_ids:
            final["confidence"] = a[case_id]["confidence"]
            final["confidence_rationale"] = a[case_id]["confidence_rationale"]
            final["confidence_source"] = "independent-confidence-recalibration-v2"
            final["calibration_round"] = "v2"
        else:
            final["confidence_source"] = "v1-retained"
            final["calibration_round"] = "v1-retained"
        final_rows.append(final)
    result = dict(v1)
    result["artifact_id"] = None
    result["supersedes_artifact_id"] = v1["artifact_id"]
    result["calibration_round"] = "v2"
    result["recalibration_task_id"] = TASK_ID
    result["reviews"] = reviewer_rows
    result["final"] = final_rows
    result["summary"] = {
        **dict(v1.get("summary", {})),
        "case_count": 40,
        "review_count": 80,
        "recalibrated_case_count": 20,
        "retained_v1_case_count": 20,
        "recalibrated_reviewer_count": 2,
        "confidence_distribution": {
            grade: sum(row["confidence"] == grade for row in final_rows)
            for grade in ("A", "B", "C", "D")
        },
        "recalibrated_confidence_agreement": sum(
            a[case_id]["confidence"] == b[case_id]["confidence"]
            for case_id in selected_ids
        ),
    }
    result["artifact_id"] = _human_artifact_id(result)
    _write_private(output_path, result)
    return {
        "output": str(output_path.resolve()),
        "artifact_id": result["artifact_id"],
        "supersedes_artifact_id": v1["artifact_id"],
        "case_count": 40,
        "recalibrated_case_count": 20,
        "confidence_distribution": result["summary"]["confidence_distribution"],
        "reviewer_agreement": result["summary"]["recalibrated_confidence_agreement"],
    }

"""Tests for safe Pilot Review progress validation and reporting."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec.calibration.pilot_review import (
    PilotReviewError,
    compare_pilot_reviews,
    create_pilot_adjudication_template,
    merge_pilot_review,
    report_pilot_review,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
SELECTION = REPOSITORY_ROOT / "calibration/pilot-review-100/selection.json"
PACK = REPOSITORY_ROOT / "calibration/reviewer-pack"
PILOT_B = (
    REPOSITORY_ROOT / "calibration/pilot-review-100/reviewer-b-labels.template.json"
)


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _valid_one_review_template(tmp_path: Path) -> Path:
    payload = _load(PILOT_B)
    row = payload["reviews"][0]
    row.update(
        {
            "category": "standard",
            "confidence": "B",
            "correlation": "same_target",
            "disposition": "keep",
            "evidence_locations": [
                {"path": "source.json", "start_line": 1, "end_line": 1}
            ],
            "finding_summary": "The reviewer observed a bounded static condition.",
            "human_condition_label": "match",
            "observed_finding": "present",
            "rationale_code": "pilot_human_observation",
            "status": "reviewed",
        }
    )
    path = tmp_path / "reviewer-b-pilot.json"
    _write(path, payload)
    path.chmod(0o600)
    return path


def _valid_complete_template(tmp_path: Path, reviewer_id: str) -> Path:
    payload = _load(
        REPOSITORY_ROOT
        / f"calibration/pilot-review-100/{reviewer_id}-labels.template.json"
    )
    selection = _load(SELECTION)
    for row, item in zip(payload["reviews"], selection["items"], strict=True):
        case_path = PACK / item[f"{reviewer_id.replace('-', '_')}_case_path"]
        case = _load(case_path)
        source_path = case["source_location"]["path"]
        row.update(
            {
                "category": "standard",
                "confidence": "B",
                "correlation": "same_target",
                "disposition": "keep",
                "evidence_locations": [
                    {"path": source_path, "start_line": 1, "end_line": 1}
                ],
                "finding_summary": "The reviewer observed bounded static evidence.",
                "human_condition_label": "match",
                "observed_finding": "present",
                "rationale_code": "pilot_human_observation",
                "status": "reviewed",
            }
        )
    path = tmp_path / f"{reviewer_id}-complete.json"
    _write(path, payload)
    path.chmod(0o600)
    return path


def test_pilot_report_accepts_pending_template() -> None:
    report = report_pilot_review(
        selection_path=SELECTION,
        pack_root=PACK,
        labels_path=PILOT_B,
        reviewer_id="reviewer-b",
    )

    assert report["completed"] == 0
    assert report["valid_completed"] == 0
    assert report["pending"] == 100
    assert report["validation_status"] == "ready"
    assert report["boundary"]["formal_human_evidence"] is False
    assert report["boundary"]["ground_truth_used"] is False


def test_pilot_report_counts_only_explicit_human_rows(tmp_path: Path) -> None:
    labels = _valid_one_review_template(tmp_path)
    report = report_pilot_review(
        selection_path=SELECTION,
        pack_root=PACK,
        labels_path=labels,
        reviewer_id="reviewer-b",
    )

    assert report["completed"] == 1
    assert report["valid_completed"] == 1
    assert report["pending"] == 99
    assert report["validation_status"] == "ready"
    assert report["by_condition"] == {"match": 1}
    assert report["by_confidence"] == {"B": 1}


def test_pilot_rejects_ground_truth_in_selection(tmp_path: Path) -> None:
    selection = _load(SELECTION)
    selection["items"][0]["expected_outcome"] = "match"
    selection_path = tmp_path / "selection.json"
    _write(selection_path, selection)

    with pytest.raises(PilotReviewError, match="binding or version"):
        report_pilot_review(
            selection_path=selection_path,
            pack_root=PACK,
            labels_path=PILOT_B,
            reviewer_id="reviewer-b",
        )


def test_pilot_merge_creates_non_clobbering_full_progress_snapshot(
    tmp_path: Path,
) -> None:
    labels = _valid_one_review_template(tmp_path)
    output = tmp_path / "merged-full-template.json"
    summary = merge_pilot_review(
        selection_path=SELECTION,
        pack_root=PACK,
        labels_path=labels,
        reviewer_id="reviewer-b",
        output_path=output,
    )

    assert summary.completed == 1
    assert output.is_file()
    assert os.stat(output).st_mode & 0o777 == 0o600
    merged = _load(output)
    assert merged["format"] == "agentsec-independent-review-label-template"
    assert "pilot_selection_id" not in merged
    assert len(merged["reviews"]) == 431
    assert sum(row["status"] == "reviewed" for row in merged["reviews"]) == 1


def test_pilot_compare_reports_disagreements_without_raw_labels(tmp_path: Path) -> None:
    reviewer_a = _valid_complete_template(tmp_path, "reviewer-a")
    reviewer_b = _valid_complete_template(tmp_path, "reviewer-b")
    payload = _load(reviewer_b)
    payload["reviews"][0]["category"] = "runtime_uncertainty"
    payload["reviews"][0]["human_condition_label"] = "uncertain"
    payload["reviews"][0]["observed_finding"] = "uncertain"
    _write(reviewer_b, payload)

    comparison = compare_pilot_reviews(
        selection_path=SELECTION,
        pack_root=PACK,
        reviewer_a_path=reviewer_a,
        reviewer_b_path=reviewer_b,
    )

    assert comparison["total"] == 100
    assert comparison["agreement_count"] == 99
    assert comparison["disagreement_count"] == 1
    assert comparison["boundary"]["ground_truth_used"] is False
    assert "match" not in json.dumps(comparison["rows"][0], ensure_ascii=False)
    assert comparison["rows"][0]["differing_fields"]


def test_pilot_adjudication_template_contains_only_disagreements(
    tmp_path: Path,
) -> None:
    reviewer_a = _valid_complete_template(tmp_path, "reviewer-a")
    reviewer_b = _valid_complete_template(tmp_path, "reviewer-b")
    payload = _load(reviewer_b)
    payload["reviews"][0]["category"] = "runtime_uncertainty"
    payload["reviews"][0]["human_condition_label"] = "uncertain"
    payload["reviews"][0]["observed_finding"] = "uncertain"
    _write(reviewer_b, payload)
    output = tmp_path / "pilot-adjudication-template.json"

    result = create_pilot_adjudication_template(
        selection_path=SELECTION,
        pack_root=PACK,
        reviewer_a_path=reviewer_a,
        reviewer_b_path=reviewer_b,
        output_path=output,
    )

    assert result["format"] == "agentsec-pilot-adjudication-template"
    assert len(result["resolutions"]) == 1
    assert result["resolutions"][0]["status"] is None
    assert result["boundary"]["formal_adjudication_evidence"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_pilot_report_surfaces_invalid_reviewed_row_without_using_it(
    tmp_path: Path,
) -> None:
    labels = _valid_one_review_template(tmp_path)
    payload = _load(labels)
    payload["reviews"][0]["finding_summary"] = None
    _write(labels, payload)

    report = report_pilot_review(
        selection_path=SELECTION,
        pack_root=PACK,
        labels_path=labels,
        reviewer_id="reviewer-b",
    )

    assert report["completed"] == 1
    assert report["valid_completed"] == 0
    assert report["invalid_reviewed"] == 1
    assert report["validation_status"] == "needs_review_fix"
    assert report["validation_issues"][0]["review_id"]


def test_pilot_rejects_reviewed_row_without_summary(tmp_path: Path) -> None:
    labels = _valid_one_review_template(tmp_path)
    payload = _load(labels)
    payload["reviews"][0]["finding_summary"] = None
    _write(labels, payload)

    with pytest.raises(PilotReviewError, match="finding_summary"):
        from agentsec.calibration.pilot_review import validate_pilot_review

        validate_pilot_review(
            selection_path=SELECTION,
            pack_root=PACK,
            labels_path=labels,
            reviewer_id="reviewer-b",
        )

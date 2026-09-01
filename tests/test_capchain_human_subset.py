"""Tests for the bounded HG-CAPCHAIN-001 Human Evidence subset import."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec.calibration.capchain_subset import (
    CapchainSubsetError,
    build_subset_evidence,
    compare_submissions,
    load_and_validate_submissions,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
PACKAGE = REPOSITORY_ROOT / "calibration/p2-15a-capchain-40"
REVIEWER_A = PACKAGE / "reviewer-a/reviewer-a-capchain-40-completed.json"
REVIEWER_B = PACKAGE / "reviewer-b/reviewer-b-capchain-40-completed.json"
ADJUDICATIONS = PACKAGE / "adjudication-decisions.json"


def _load(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_subset_submissions_validate_and_compare() -> None:
    _manifest, selection, submissions = load_and_validate_submissions(
        PACKAGE, REVIEWER_A, REVIEWER_B
    )
    comparison = compare_submissions(submissions, selection)

    assert comparison["total"] == 40
    assert comparison["agreement_count"] == 35
    assert comparison["disagreement_count"] == 5
    assert comparison["field_agreement"] == {
        "category": 40,
        "confidence": 40,
        "correlation": 35,
        "disposition": 40,
        "human_condition_label": 40,
        "observed_finding": 40,
    }


def test_subset_import_materializes_three_deterministic_human_artifacts(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_report = build_subset_evidence(
        package_root=PACKAGE,
        reviewer_a_path=REVIEWER_A,
        reviewer_b_path=REVIEWER_B,
        adjudication_path=ADJUDICATIONS,
        output_dir=first,
    )
    second_report = build_subset_evidence(
        package_root=PACKAGE,
        reviewer_a_path=REVIEWER_A,
        reviewer_b_path=REVIEWER_B,
        adjudication_path=ADJUDICATIONS,
        output_dir=second,
    )

    assert first_report["case_count"] == 40
    assert first_report["review_count"] == 80
    assert first_report["agreement_count"] == 35
    assert first_report["disagreement_count"] == 5
    assert first_report["adjudication_count"] == 5
    assert first_report["artifact_ids"] == second_report["artifact_ids"]

    names = (
        "human-capchain-40-adjudications.json",
        "human-capchain-40-confidence.json",
        "human-capchain-40-resolutions.json",
    )
    for name in names:
        first_path = first / name
        second_path = second / name
        assert first_path.read_bytes() == second_path.read_bytes()
        assert os.stat(first_path).st_mode & 0o777 == 0o600

    adjudications = _load(first / names[0])
    confidence = _load(first / names[1])
    resolutions = _load(first / names[2])
    assert adjudications["boundary"]["formal_human_evidence"] is True
    assert adjudications["boundary"]["gate_qualification"] is False
    assert len(adjudications["adjudications"]) == 5
    assert len(confidence["reviews"]) == 80
    assert len(confidence["final"]) == 40
    assert confidence["summary"]["correlation_agreement_before_adjudication"] == 35
    assert confidence["summary"]["correlation_agreement_after_adjudication"] == 40
    assert len(resolutions["resolutions"]) == 40
    assert resolutions["summary"] == {
        "adjudication_completed_count": 5,
        "adjudication_required_count": 5,
        "case_count": 40,
        "match_count": 20,
        "no_match_count": 20,
        "unresolved_count": 0,
    }
    assert all(row["classification"] is None for row in resolutions["resolutions"])
    adjudicated = {
        row["review_case_id"]: row
        for row in resolutions["resolutions"]
        if row["adjudication_required"]
    }
    assert len(adjudicated) == 5
    assert {row["correlation"] for row in adjudicated.values()} == {"same_source"}


def test_subset_import_rejects_missing_or_extra_adjudication(tmp_path: Path) -> None:
    payload = _load(ADJUDICATIONS)
    payload["adjudications"] = payload["adjudications"][:-1]
    decisions = tmp_path / "decisions.json"
    decisions.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CapchainSubsetError, match="exactly all disagreements"):
        build_subset_evidence(
            package_root=PACKAGE,
            reviewer_a_path=REVIEWER_A,
            reviewer_b_path=REVIEWER_B,
            adjudication_path=decisions,
            output_dir=tmp_path / "out",
        )


def test_subset_import_does_not_clobber_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    existing = output / "human-capchain-40-adjudications.json"
    existing.write_text("do not clobber", encoding="utf-8")

    with pytest.raises(CapchainSubsetError, match="output already exists"):
        build_subset_evidence(
            package_root=PACKAGE,
            reviewer_a_path=REVIEWER_A,
            reviewer_b_path=REVIEWER_B,
            adjudication_path=ADJUDICATIONS,
            output_dir=output,
        )
    assert existing.read_text(encoding="utf-8") == "do not clobber"

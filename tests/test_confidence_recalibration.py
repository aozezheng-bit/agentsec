"""Tests for the P2-15A-QUAL-02 Confidence v2 import."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from agentsec.calibration.confidence_recalibration import build_confidence_v2

REPOSITORY_ROOT = Path(__file__).parents[1]
PACKAGE = REPOSITORY_ROOT / "calibration/confidence-review-20"
V1 = (
    REPOSITORY_ROOT
    / "calibration/p2-15a-capchain-40/human-evidence/"
    / "human-capchain-40-confidence.json"
)
A = PACKAGE / "reviewer-a/reviewer-a-confidence-20-completed.json"
B = PACKAGE / "reviewer-b/reviewer-b-confidence-20-completed.json"


def _load(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_confidence_v2_import_supersedes_v1_without_overwriting(
    tmp_path: Path,
) -> None:
    output = tmp_path / "confidence-v2.json"
    report = build_confidence_v2(
        package_root=PACKAGE,
        reviewer_a_path=A,
        reviewer_b_path=B,
        v1_path=V1,
        output_path=output,
    )
    payload = _load(output)
    v1 = _load(V1)

    assert report["case_count"] == 40
    assert report["recalibrated_case_count"] == 20
    assert report["reviewer_agreement"] == 20
    assert payload["supersedes_artifact_id"] == v1["artifact_id"]
    assert len(payload["reviews"]) == 80
    assert len(payload["final"]) == 40
    assert payload["summary"]["recalibrated_case_count"] == 20
    assert payload["summary"]["retained_v1_case_count"] == 20
    assert payload["summary"]["confidence_distribution"] == {
        "A": 20,
        "B": 20,
        "C": 0,
        "D": 0,
    }
    recalibrated = [row for row in payload["final"] if row["calibration_round"] == "v2"]
    assert len(recalibrated) == 20
    assert {row["confidence"] for row in recalibrated} == {"B"}
    assert v1["artifact_id"] != payload["artifact_id"]

"""Tests for the minimum HG-CAPCHAIN-001 independent-review package."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).parents[1]
BUILDER = REPOSITORY_ROOT / "scripts" / "build-capchain-review-subset.py"


def _build(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _load(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_builder_creates_two_blind_40_question_packets(tmp_path: Path) -> None:
    output = tmp_path / "packet"
    result = _build(output)

    assert result.returncode == 0, result.stderr
    selection = _load(output / "selection.json")
    assert selection["gate_id"] == "HG-CAPCHAIN-001"
    assert selection["review_count"] == 40
    assert selection["positive_count"] == 20
    assert selection["eligible_negative_count"] == 20
    assert len(selection["items"]) == 40
    assert all(
        set(item)
        == {
            "input_format",
            "language",
            "question_id",
            "review_case_id",
            "reviewer_a_case_path",
            "reviewer_b_case_path",
            "rule_id",
            "sequence",
        }
        for item in selection["items"]
    )
    assert all("expected_gate_condition" not in item for item in selection["items"])

    package = _load(output / "package-manifest.json")
    assert package["expected_labels_included"] is False
    assert package["ground_truth_included"] is False
    assert package["joint_evidence_included"] is False
    assert package["review_count"] == 40
    assert package["reviewer_count"] == 2

    for reviewer in ("reviewer-a", "reviewer-b"):
        labels = _load(output / reviewer / "labels.template.json")
        assert len(labels["reviews"]) == 40
        assert {row["status"] for row in labels["reviews"]} == {None}
        assert {row["human_condition_label"] for row in labels["reviews"]} == {None}

    for item in package["files"]:
        path = output / item["path"]
        data = path.read_bytes()
        assert "sha256:" + hashlib.sha256(data).hexdigest() == item["sha256"]
        assert len(data) == item["bytes"]


def test_builder_is_deterministic_and_non_clobbering(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert _build(first).returncode == 0
    assert _build(second).returncode == 0

    first_selection = _load(first / "selection.json")
    second_selection = _load(second / "selection.json")
    assert first_selection == second_selection
    assert (
        _load(first / "package-manifest.json")["package_id"]
        == _load(second / "package-manifest.json")["package_id"]
    )

    repeated = _build(first)
    assert repeated.returncode == 4

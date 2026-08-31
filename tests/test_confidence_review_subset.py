"""Tests for the blind P2-15A-QUAL-02 Confidence review package."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).parents[1]
BUILDER = REPOSITORY_ROOT / "scripts/build-confidence-review-subset.py"


def _load(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_builder_creates_blind_two_reviewer_20_case_package(tmp_path: Path) -> None:
    output = tmp_path / "confidence-review-20"
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    selection = _load(output / "selection.json")
    assert selection["review_count"] == 20
    assert all("expected_confidence" not in item for item in selection["items"])
    assert all("expected_outcome" not in item for item in selection["items"])

    manifest = _load(output / "package-manifest.json")
    assert manifest["expected_labels_included"] is False
    assert manifest["prior_confidence_included"] is False
    assert manifest["ground_truth_included"] is False
    assert manifest["human_evidence_included"] is False
    assert manifest["review_count"] == 20
    assert manifest["reviewer_count"] == 2

    for reviewer in ("reviewer-a", "reviewer-b"):
        labels = _load(output / reviewer / "labels.template.json")
        assert labels["package_id"] == manifest["package_id"]
        assert labels["reviewer_id"] == reviewer
        assert len(labels["reviews"]) == 20
        assert {row["confidence"] for row in labels["reviews"]} == {None}
        assert {row["confidence_rationale"] for row in labels["reviews"]} == {None}
        assert {row["status"] for row in labels["reviews"]} == {None}

    assert not list(output.rglob("*human-capchain-40-confidence*"))
    assert not list(output.rglob("*qualification-report*"))

    for item in manifest["files"]:
        path = output / item["path"]
        data = path.read_bytes()
        assert len(data) == item["bytes"]
        assert "sha256:" + hashlib.sha256(data).hexdigest() == item["sha256"]


def test_builder_is_non_clobbering(tmp_path: Path) -> None:
    output = tmp_path / "confidence-review-20"
    first = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    second = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(output)],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0
    assert second.returncode == 4

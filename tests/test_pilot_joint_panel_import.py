"""Tests for P2-15A-PILOT-01 Joint Expert Review evidence formalization."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec.calibration.pilot_review import (
    JOINT_EVIDENCE_FORMAT,
    JOINT_EVIDENCE_SCHEMA_VERSION,
    PilotReviewError,
    import_joint_panel_review,
    validate_joint_expert_evidence,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
SELECTION = REPOSITORY_ROOT / "calibration/pilot-review-100/selection.json"
PACK = REPOSITORY_ROOT / "calibration/reviewer-pack"
PILOT_B = (
    REPOSITORY_ROOT / "calibration/pilot-review-100/reviewer-b-labels.template.json"
)
CHECKED_IN_INPUT = (
    REPOSITORY_ROOT / "calibration/pilot-review-100/joint-panel-pilot-input.json"
)
CHECKED_IN_EVIDENCE = (
    REPOSITORY_ROOT / "calibration/pilot-review-100/joint-expert-evidence.json"
)

VALID_PANEL = {
    "evidence_mode": "joint_expert_review",
    "review_panel_id": "expert-panel-001",
    "reviewer_count": 2,
    "independent_initial_labels": False,
    "adjudication_required": False,
    "qualification": "pilot_only",
}


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _joint_input(tmp_path: Path, *, reviewed: bool = True) -> Path:
    payload = _load(PILOT_B)
    if reviewed:
        payload["reviews"][0].update(
            {
                "category": "standard",
                "confidence": "B",
                "correlation": "same_target",
                "disposition": "keep",
                "evidence_locations": [
                    {"path": "source.json", "start_line": 1, "end_line": 1}
                ],
                "finding_summary": "The joint panel observed a bounded condition.",
                "human_condition_label": "match",
                "observed_finding": "present",
                "rationale_code": "joint_panel_observation",
                "status": "reviewed",
            }
        )
    payload["joint_panel"] = dict(VALID_PANEL)
    path = tmp_path / "joint-input.json"
    _write(path, payload)
    path.chmod(0o600)
    return path


def _import(input_path: Path, output_path: Path) -> dict[str, Any]:
    return import_joint_panel_review(
        selection_path=SELECTION,
        pack_root=PACK,
        input_path=input_path,
        output_path=output_path,
    )


def test_import_joint_panel_happy_path(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    report = _import(_joint_input(tmp_path), output)

    assert report["reviewed_count"] == 1
    assert report["review_panel_id"] == "expert-panel-001"
    assert report["question_set_reviewer_id"] == "reviewer-b"
    assert report["evidence_id"].startswith("joint-evidence-sha256:")

    evidence = _load(output)
    assert evidence["format"] == JOINT_EVIDENCE_FORMAT
    assert evidence["schema_version"] == JOINT_EVIDENCE_SCHEMA_VERSION
    assert evidence["joint_panel"] == VALID_PANEL
    assert evidence["reviewed_count"] == 1
    assert len(evidence["reviews"]) == 1
    assert evidence["reviews"][0]["status"] == "reviewed"
    assert evidence["boundary"] == {
        "formal_human_evidence": False,
        "p2_cal_04_human_evidence": False,
        "reviewer_independence": False,
        "reviewer_agreement_computable": False,
        "hard_gate_qualification": False,
        "ci_blocking": False,
        "fail_on": False,
    }
    assert oct(output.stat().st_mode & 0o777) == "0o600"


def test_checked_in_joint_evidence_is_reproducible(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    report = import_joint_panel_review(
        selection_path=SELECTION,
        pack_root=PACK,
        input_path=CHECKED_IN_INPUT,
        output_path=output,
    )
    assert report["reviewed_count"] == 50
    assert _canonical(_load(output)) == _canonical(_load(CHECKED_IN_EVIDENCE))


def test_checked_in_joint_evidence_validates_independently() -> None:
    report = validate_joint_expert_evidence(
        selection_path=SELECTION,
        pack_root=PACK,
        evidence_path=CHECKED_IN_EVIDENCE,
    )

    assert report["valid"] is True
    assert report["reviewed_count"] == 50
    assert report["evidence_id"] == _load(CHECKED_IN_EVIDENCE)["evidence_id"]
    assert report["boundary"]["formal_human_evidence"] is False


def test_joint_evidence_validator_rejects_tampered_content_hash(tmp_path: Path) -> None:
    payload = _load(CHECKED_IN_EVIDENCE)
    payload["reviews"][0]["finding_summary"] = "tampered"
    path = tmp_path / "tampered-evidence.json"
    _write(path, payload)

    with pytest.raises(PilotReviewError, match="ID does not match content"):
        validate_joint_expert_evidence(
            selection_path=SELECTION,
            pack_root=PACK,
            evidence_path=path,
        )


def test_import_rejects_missing_joint_panel(tmp_path: Path) -> None:
    input_path = _joint_input(tmp_path)
    payload = _load(input_path)
    del payload["joint_panel"]
    _write(input_path, payload)
    with pytest.raises(PilotReviewError, match="invalid fields"):
        _import(input_path, tmp_path / "out.json")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_mode", "independent_review"),
        ("review_panel_id", "INVALID PANEL"),
        ("reviewer_count", 1),
        ("reviewer_count", True),
        ("independent_initial_labels", True),
        ("adjudication_required", True),
        ("qualification", "formal"),
    ],
)
def test_import_rejects_invalid_panel_metadata(
    tmp_path: Path, field: str, value: object
) -> None:
    input_path = _joint_input(tmp_path)
    payload = _load(input_path)
    payload["joint_panel"][field] = value
    _write(input_path, payload)
    with pytest.raises(PilotReviewError, match="joint_panel|review_panel_id"):
        _import(input_path, tmp_path / "out.json")


def test_import_rejects_tampered_corpus_binding(tmp_path: Path) -> None:
    input_path = _joint_input(tmp_path)
    payload = _load(input_path)
    payload["corpus_binding_hash"] = "sha256:" + "0" * 64
    _write(input_path, payload)
    with pytest.raises(PilotReviewError, match="binding"):
        _import(input_path, tmp_path / "out.json")


def test_import_rejects_tampered_row_source_hash(tmp_path: Path) -> None:
    input_path = _joint_input(tmp_path)
    payload = _load(input_path)
    payload["reviews"][0]["source_sha256"] = "sha256:" + "1" * 64
    _write(input_path, payload)
    with pytest.raises(PilotReviewError, match="immutable field"):
        _import(input_path, tmp_path / "out.json")


def test_import_rejects_input_without_reviewed_rows(tmp_path: Path) -> None:
    input_path = _joint_input(tmp_path, reviewed=False)
    with pytest.raises(PilotReviewError, match="no reviewed rows"):
        _import(input_path, tmp_path / "out.json")


def test_import_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    output.write_text("{}")
    with pytest.raises(PilotReviewError, match="already exists"):
        _import(_joint_input(tmp_path), output)


def test_cli_import_joint_panel(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pilot-review.py",
            "--operation",
            "import-joint-panel",
            "--input",
            str(CHECKED_IN_INPUT),
            "--output",
            str(output),
            "--format",
            "json",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["format"] == "agentsec-joint-expert-review-import-report"
    assert report["reviewed_count"] == 50
    assert report["boundary"]["formal_human_evidence"] is False
    assert output.exists()


def test_cli_import_joint_panel_requires_input_and_output(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pilot-review.py",
            "--operation",
            "import-joint-panel",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 4
    assert "requires --input and --output" in result.stderr


def test_cli_validate_joint_panel(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pilot-review.py",
            "--operation",
            "validate-joint-panel",
            "--input",
            str(CHECKED_IN_EVIDENCE),
            "--format",
            "json",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["reviewed_count"] == 50


def test_cli_validate_joint_panel_requires_input() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pilot-review.py",
            "--operation",
            "validate-joint-panel",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 4
    assert "requires --input" in result.stderr

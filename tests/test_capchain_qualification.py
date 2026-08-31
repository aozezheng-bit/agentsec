"""Tests for the report-only HG-CAPCHAIN-001 qualification report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from agentsec.calibration.capchain_qualification import build_qualification_report

REPOSITORY_ROOT = Path(__file__).parents[1]
CORPUS = REPOSITORY_ROOT / "calibration"
PACKAGE = CORPUS / "p2-15a-capchain-40"
EVIDENCE = PACKAGE / "human-evidence"


def _load(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, Any], payload)


def test_capchain_qualification_reports_perfect_detection_but_blocks_confidence(
    tmp_path: Path,
) -> None:
    report = build_qualification_report(
        corpus_path=CORPUS,
        package_dir=PACKAGE,
        human_evidence_dir=EVIDENCE,
        output_json=tmp_path / "qualification.json",
        output_text=tmp_path / "qualification.txt",
    )

    assert report["status"] == "complete"
    assert report["sample_scope"]["case_count"] == 40
    assert report["sample_scope"]["positive_count"] == 20
    assert report["sample_scope"]["negative_or_near_miss_count"] == 20
    assert report["sample_scope"]["coverage_complete"] is True
    assert report["sample_scope"]["unknown_free"] is True
    assert report["confusion_matrix"] == {
        "true_positive": 20,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 20,
    }
    assert report["metrics"] == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "false_positive_rate": 0.0,
    }
    assert report["confidence_calibration"]["human_distribution"] == {"A": 40}
    assert report["confidence_calibration"]["detector_distribution"] == {"B": 20}
    assert report["confidence_calibration"]["human_vs_detector_agreement_rate"] == 0.0
    assert report["reviewer_agreement"]["confidence_kappa"] == 1.0
    assert report["qualification"]["status"] == "more_data_required"
    assert report["qualification"]["eligible_for_report_only_gate"] is False
    assert report["qualification"]["blocking_reasons"] == [
        "confidence_calibration-below-threshold"
    ]
    assert report["policy"]["hard_gate"] is False
    assert report["policy"]["ci_blocking"] is False


def test_capchain_qualification_outputs_are_deterministic(tmp_path: Path) -> None:
    first = build_qualification_report(
        corpus_path=CORPUS,
        package_dir=PACKAGE,
        human_evidence_dir=EVIDENCE,
        output_json=tmp_path / "first.json",
        output_text=tmp_path / "first.txt",
    )
    second = build_qualification_report(
        corpus_path=CORPUS,
        package_dir=PACKAGE,
        human_evidence_dir=EVIDENCE,
        output_json=tmp_path / "second.json",
        output_text=tmp_path / "second.txt",
    )

    assert first["artifact_id"] == second["artifact_id"]
    assert (tmp_path / "first.json").read_bytes() == (
        tmp_path / "second.json"
    ).read_bytes()
    assert (tmp_path / "first.txt").read_bytes() == (
        tmp_path / "second.txt"
    ).read_bytes()


def test_capchain_qualification_accepts_confidence_v2(tmp_path: Path) -> None:
    report = build_qualification_report(
        corpus_path=CORPUS,
        package_dir=PACKAGE,
        human_evidence_dir=EVIDENCE,
        confidence_path=EVIDENCE / "human-capchain-40-confidence-v2.json",
        output_json=tmp_path / "qualification-v2.json",
        output_text=tmp_path / "qualification-v2.txt",
    )

    assert report["qualification"]["status"] == "accepted"
    assert report["qualification"]["eligible_for_report_only_gate"] is True
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["confidence_calibration"]["human_vs_detector_agreement_rate"] == 1.0
    assert report["qualification"]["blocking_reasons"] == []

"""P2-CAL-03 reviewer agreement, Kappa, and report contracts."""

from __future__ import annotations

import json
import stat
import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest

from agentsec.calibration import (
    ConfidenceCalibrationJsonRenderer,
    ConfidenceCalibrationRunner,
    ConfidenceCalibrationTextRenderer,
    ConfidenceReviewLabel,
    ConfidenceReviewLoadError,
    ConfidenceReviewSet,
    decode_confidence_review_set_json,
    encode_confidence_review_set_json,
    export_confidence_calibration_report_json_schema,
    export_confidence_review_set_json_schema,
    load_calibration_corpus,
    load_confidence_review_set,
)
from agentsec.calibration.confidence_runner import _kappa
from agentsec.calibration.confidence_validation import ConfidenceValidationError
from agentsec.capability_rules import CapabilityCorrelation, CapabilityRuleLanguage
from agentsec.domain import EvidenceConfidence

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
REVIEWS_PATH = CALIBRATION_ROOT / "confidence-reviews.json"


def _review_payload() -> dict[str, object]:
    payload: object = json.loads(REVIEWS_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def _decode_payload(payload: dict[str, object]) -> ConfidenceReviewSet:
    return decode_confidence_review_set_json(
        json.dumps(payload, ensure_ascii=False, sort_keys=True)
    )


def test_seed_confidence_calibration_is_deterministic_and_report_only() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    review_set = load_confidence_review_set(corpus)
    runner = ConfidenceCalibrationRunner()

    first = runner.run(corpus, review_set)
    second = runner.run(corpus, review_set)

    expected_matching = sum(
        1
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
        if expectation.outcome.value == "match"
    )

    assert first == second
    assert first.status == "complete"
    assert first.summary.total_cases == expected_matching
    assert first.summary.total_reviews == expected_matching * len(
        review_set.reviewer_ids
    )
    assert first.summary.total_reviews == len(review_set.reviews)
    assert first.summary.reviewer_count == 2
    assert first.summary.reviewer_agreement.items == expected_matching
    assert first.summary.reviewer_agreement.agreement_rate == 1.0
    assert first.summary.reviewer_agreement.cohens_kappa == 1.0
    assert first.summary.expected_vs_emitted.items == expected_matching
    assert first.summary.expected_vs_emitted.agreement_rate == 1.0
    assert first.summary.expected_vs_emitted.cohens_kappa == 1.0
    # 20-sample threshold per (Rule, correlation) from the Hard Gate plan.
    assert first.summary.insufficient_sample_items == sum(
        item.items < 20 for item in first.by_rule
    )
    assert first.policy.enforcement_mode == "report_only"
    assert first.policy.ci_blocking_enabled is False
    assert first.policy.hard_gate_eligibility_decided is False


def test_known_kappa_fixture_is_not_plain_accuracy() -> None:
    pairs = (
        (EvidenceConfidence.A, EvidenceConfidence.A),
        (EvidenceConfidence.A, EvidenceConfidence.B),
        (EvidenceConfidence.B, EvidenceConfidence.B),
        (EvidenceConfidence.B, EvidenceConfidence.C),
    )

    assert sum(left is right for left, right in pairs) / len(pairs) == 0.5
    assert _kappa(pairs) == 0.2


def test_perturbed_reviewer_label_reduces_kappa() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    review_set = load_confidence_review_set(corpus)
    first = review_set.reviews[0]
    replacement = first.model_copy(update={"confidence": EvidenceConfidence.C})
    perturbed = review_set.model_copy(
        update={"reviews": (replacement,) + review_set.reviews[1:]}
    )

    report = ConfidenceCalibrationRunner().run(corpus, perturbed)

    agreement_rate = report.summary.reviewer_agreement.agreement_rate
    cohens_kappa = report.summary.reviewer_agreement.cohens_kappa
    assert agreement_rate is not None and agreement_rate < 1.0
    assert cohens_kappa is not None and cohens_kappa < 1.0


def test_review_set_round_trip_and_three_reviewer_pair_aggregation() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    review_set = load_confidence_review_set(corpus)
    encoded = encode_confidence_review_set_json(review_set)
    decoded = decode_confidence_review_set_json(encoded)

    assert decoded == review_set

    gamma_labels = tuple(
        ConfidenceReviewLabel(
            **{
                **label.model_dump(),
                "reviewer_id": "reviewer-gamma",
                "review_id": f"review:reviewer-gamma:{label.case_id}:{label.rule_id}",
            }
        )
        for label in review_set.reviews
        if label.reviewer_id == "reviewer-alpha"
    )
    expanded = ConfidenceReviewSet(
        **{
            **review_set.model_dump(),
            "reviewer_ids": (*review_set.reviewer_ids, "reviewer-gamma"),
            "reviews": tuple(
                sorted(
                    (*review_set.reviews, *gamma_labels),
                    key=lambda item: (item.case_id, item.rule_id, item.reviewer_id),
                )
            ),
        }
    )

    report = ConfidenceCalibrationRunner().run(corpus, expanded)

    expected_items = 3 * len(
        {(label.case_id, label.rule_id) for label in review_set.reviews}
    )
    assert report.summary.reviewer_count == 3
    assert report.summary.reviewer_agreement.items == expected_items
    assert len(report.pairwise) == 3


def test_review_loader_rejects_fewer_reviewers_unknown_case_rule_and_correlation() -> (
    None
):
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    base = _review_payload()

    fewer = dict(base)
    fewer["reviewer_ids"] = ["reviewer-alpha"]
    with pytest.raises(ConfidenceValidationError):
        _decode_payload(fewer)

    unknown_case = json.loads(json.dumps(base))
    first = unknown_case["reviews"][0]
    first["case_id"] = "cal-unknown-case"
    first["review_id"] = (
        f"review:{first['reviewer_id']}:{first['case_id']}:{first['rule_id']}"
    )
    with pytest.raises(ConfidenceReviewLoadError, match="invalid"):
        load_confidence_review_set(
            corpus,
            path=_write_review_fixture(unknown_case),
        )

    unknown_rule = json.loads(json.dumps(base))
    first = unknown_rule["reviews"][0]
    first["rule_id"] = "CAP-UNKNOWN-001"
    first["review_id"] = (
        f"review:{first['reviewer_id']}:{first['case_id']}:{first['rule_id']}"
    )
    with pytest.raises(ConfidenceReviewLoadError, match="invalid"):
        load_confidence_review_set(
            corpus,
            path=_write_review_fixture(unknown_rule),
        )

    reviewer_correlation_disagreement = json.loads(json.dumps(base))
    first = next(
        item
        for item in reviewer_correlation_disagreement["reviews"]
        if item["correlation"] == CapabilityCorrelation.SAME_TARGET.value
    )
    first["correlation"] = CapabilityCorrelation.AGENT_WIDE.value
    loaded = load_confidence_review_set(
        corpus,
        path=_write_review_fixture(reviewer_correlation_disagreement),
    )
    changed = next(
        item for item in loaded.reviews if item.review_id == first["review_id"]
    )
    assert changed.correlation is CapabilityCorrelation.AGENT_WIDE


def _write_review_fixture(payload: dict[str, object]) -> str:
    path = CALIBRATION_ROOT / "confidence-review-test.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    # The test fixture is deliberately removed by the caller-independent finalizer
    # below; returning a corpus-relative path keeps loader containment in scope.
    return path.name


@pytest.fixture(autouse=True)
def remove_temporary_review_fixture() -> Generator[None, None, None]:
    yield
    (CALIBRATION_ROOT / "confidence-review-test.json").unlink(missing_ok=True)


def test_text_json_reports_are_bilingual_deterministic_and_schema_backed(
    tmp_path: Path,
) -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    report = ConfidenceCalibrationRunner().run(corpus)
    json_renderer = ConfidenceCalibrationJsonRenderer()

    first = json_renderer.render(report)
    second = json_renderer.render(report)
    english = ConfidenceCalibrationTextRenderer().render(report)
    chinese = ConfidenceCalibrationTextRenderer(
        language=CapabilityRuleLanguage.ZH
    ).render(report)
    review_schema = export_confidence_review_set_json_schema(tmp_path)
    report_schema = export_confidence_calibration_report_json_schema(tmp_path)

    assert first == second
    assert json.loads(first)["format"] == (
        "agentsec-capability-confidence-calibration-report"
    )
    assert "Cohen's Kappa: 1.000" in english
    assert "Grade Matrix" in english
    assert "AgentSec Evidence Confidence 校准" in chinese
    assert "Cohen's Kappa：1.000" in chinese
    assert json.loads(review_schema.read_text())["additionalProperties"] is False
    assert json.loads(report_schema.read_text())["additionalProperties"] is False


def test_schema_exports_are_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_review = export_confidence_review_set_json_schema(first)
    second_review = export_confidence_review_set_json_schema(second)
    first_report = export_confidence_calibration_report_json_schema(first)
    second_report = export_confidence_calibration_report_json_schema(second)

    assert first_review.read_bytes() == second_review.read_bytes()
    assert first_report.read_bytes() == second_report.read_bytes()


def test_confidence_calibration_script_writes_private_json_artifact(
    tmp_path: Path,
) -> None:
    output = tmp_path / "confidence.json"
    result = subprocess.run(
        (
            str(REPOSITORY_ROOT / ".venv" / "bin" / "python"),
            str(REPOSITORY_ROOT / "scripts" / "run-confidence-calibration.py"),
            "--corpus",
            str(CALIBRATION_ROOT),
            "--reviews",
            str(REVIEWS_PATH),
            "--format",
            "json",
            "--output",
            str(output),
        ),
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    payload = json.loads(output.read_text())
    assert payload["summary"]["reviewer_agreement"]["cohens_kappa"] == 1.0

    repeated = subprocess.run(
        (
            str(REPOSITORY_ROOT / ".venv" / "bin" / "python"),
            str(REPOSITORY_ROOT / "scripts" / "run-confidence-calibration.py"),
            "--corpus",
            str(CALIBRATION_ROOT),
            "--reviews",
            str(REVIEWS_PATH),
            "--format",
            "json",
            "--output",
            str(output),
        ),
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert repeated.returncode != 0
    assert "already exists" in repeated.stderr

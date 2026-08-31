"""P2-CAL-04 independent adjudication and Gate Candidate reports."""

from __future__ import annotations

import json
import stat
import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest

from agentsec.calibration import (
    AdjudicationCategory,
    AdjudicationResolutionSet,
    AdjudicationReviewLoadError,
    CalibrationAdjudicationJsonRenderer,
    CalibrationAdjudicationRunner,
    CalibrationAdjudicationTextRenderer,
    RuleDisposition,
    decode_adjudication_resolution_set_json,
    decode_adjudication_review_set_json,
    encode_adjudication_resolution_set_json,
    encode_adjudication_review_set_json,
    export_adjudication_resolution_set_json_schema,
    export_adjudication_review_set_json_schema,
    export_calibration_adjudication_report_json_schema,
    load_adjudication_review_set,
    load_calibration_corpus,
)
from agentsec.capability_rules import CapabilityRuleLanguage

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
ADJUDICATION_PATH = CALIBRATION_ROOT / "adjudication-reviews.json"


def _payload() -> dict[str, object]:
    value: object = json.loads(ADJUDICATION_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _decode(payload: dict[str, object]):  # type: ignore[no-untyped-def]
    return decode_adjudication_review_set_json(
        json.dumps(payload, ensure_ascii=False, sort_keys=True)
    )


def test_seed_adjudication_produces_deterministic_report_only_candidates() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    labels = load_adjudication_review_set(corpus)
    runner = CalibrationAdjudicationRunner()

    first = runner.run(corpus, labels)
    second = runner.run(corpus, labels)

    expected_expectations = sum(
        1 for case in corpus.cases for _ in case.ground_truth.rule_expectations
    )

    assert first == second
    assert first.status == "complete"
    assert first.summary.total_expectations == expected_expectations
    assert first.summary.total_reviews == expected_expectations * len(
        labels.reviewer_ids
    )
    assert first.summary.total_reviews == len(labels.reviews)
    assert first.summary.consensus_count == expected_expectations
    assert first.summary.unresolved_count == 0
    assert first.summary.classification_agreement_rate == 1.0
    assert first.summary.category_agreement_rate == 1.0
    assert first.summary.disposition_agreement_rate == 1.0
    assert first.policy.enforcement_mode == "report_only"
    assert first.policy.ci_blocking_enabled is False
    assert first.policy.hard_gate_eligibility_decided is False
    assert first.policy.automatic_rule_publication is False
    # Promotion policy per Rule: 20/20 sample threshold from the Hard Gate plan.
    for item in first.by_rule:
        assert "seed-labels-not-independent" in item.reason_codes
        if item.positive_samples < 20 or item.negative_samples < 20:
            assert item.recommended_disposition is RuleDisposition.MORE_DATA
        elif "relevant-unknown" in item.reason_codes:
            assert item.recommended_disposition is RuleDisposition.SHADOW
        else:
            assert item.recommended_disposition is RuleDisposition.KEEP
    assert all(
        item.status.value == "more_data_required" for item in first.gate_candidates
    )
    assert all(
        "seed-labels-not-independent" in item.reason_codes
        for item in first.gate_candidates
    )


def test_gate_candidate_counts_exclude_unknown_and_incomplete_cases() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    report = CalibrationAdjudicationRunner().run(corpus)

    gate_rules = {
        "HG-CAPCHAIN-001": ("CAP-CHAIN-001",),
        "HG-PRODAUTO-001": ("CAP-APPROVAL-001", "CAP-AUTOPROD-001"),
        "HG-EXTERNALPROD-001": (
            "CAP-EXTERNALPRIVILEGED-001",
            "CAP-PRODADMIN-001",
            "CAP-PRODIDENTITY-001",
            "CAP-PRODWRITE-001",
        ),
    }
    for candidate in report.gate_candidates:
        required = set(gate_rules[candidate.gate_id])
        scoped = tuple(
            case
            for case in corpus.cases
            if required
            <= {
                expectation.rule_id
                for expectation in case.ground_truth.rule_expectations
            }
        )
        eligible = tuple(
            case
            for case in scoped
            if case.ground_truth.coverage == "complete"
            and not case.ground_truth.unknown_dimensions
        )
        positives = sum(
            all(
                expectation.outcome.value == "match"
                for expectation in case.ground_truth.rule_expectations
                if expectation.rule_id in required
            )
            for case in eligible
        )
        negatives = len(eligible) - positives
        assert candidate.positive_samples == positives
        assert candidate.negative_samples == negatives
        assert candidate.positive_samples >= 20
        assert candidate.negative_samples >= 20
        assert candidate.coverage_complete is True
        assert candidate.unknown_free is True
        assert "relevant-unknown" not in candidate.reason_codes


def test_adjudication_round_trip_and_schema_exports_are_deterministic(
    tmp_path: Path,
) -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    labels = load_adjudication_review_set(corpus)
    encoded = encode_adjudication_review_set_json(labels)
    assert decode_adjudication_review_set_json(encoded) == labels
    resolutions = AdjudicationResolutionSet(
        corpus_id=corpus.index.corpus_id,
        labels_version=corpus.index.labels_version,
        reviewer_ids=labels.reviewer_ids,
    )
    resolution_encoded = encode_adjudication_resolution_set_json(resolutions)
    assert decode_adjudication_resolution_set_json(resolution_encoded) == resolutions

    first_review = export_adjudication_review_set_json_schema(tmp_path / "first")
    second_review = export_adjudication_review_set_json_schema(tmp_path / "second")
    first_resolution = export_adjudication_resolution_set_json_schema(
        tmp_path / "first"
    )
    second_resolution = export_adjudication_resolution_set_json_schema(
        tmp_path / "second"
    )
    first_report = export_calibration_adjudication_report_json_schema(
        tmp_path / "first"
    )
    second_report = export_calibration_adjudication_report_json_schema(
        tmp_path / "second"
    )

    assert first_review.read_bytes() == second_review.read_bytes()
    assert first_resolution.read_bytes() == second_resolution.read_bytes()
    assert first_report.read_bytes() == second_report.read_bytes()
    assert json.loads(first_review.read_text())["additionalProperties"] is False
    assert json.loads(first_report.read_text())["additionalProperties"] is False


def test_loader_rejects_unknown_case_and_labels_version() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    payload = _payload()
    reviews = payload["reviews"]
    assert isinstance(reviews, list)
    first = cast(dict[str, object], reviews[0])
    first["case_id"] = "cal-unknown-case"
    first["adjudication_id"] = (
        f"adjudication:{first['reviewer_id']}:{first['case_id']}:{first['rule_id']}"
    )
    path = CALIBRATION_ROOT / "adjudication-review-test.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        with pytest.raises(AdjudicationReviewLoadError, match="invalid"):
            load_adjudication_review_set(corpus, path=path.name)
    finally:
        path.unlink(missing_ok=True)

    wrong_version = dict(_payload())
    wrong_version["labels_version"] = "9.9.9"
    wrong_path = CALIBRATION_ROOT / "adjudication-review-test.json"
    wrong_path.write_text(json.dumps(wrong_version), encoding="utf-8")
    try:
        with pytest.raises(AdjudicationReviewLoadError, match="labels_version"):
            load_adjudication_review_set(corpus, path=wrong_path.name)
    finally:
        wrong_path.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def remove_temporary_adjudication_fixture() -> Generator[None, None, None]:
    yield
    (CALIBRATION_ROOT / "adjudication-review-test.json").unlink(missing_ok=True)


def test_adjudicated_detection_false_positive_is_visible_as_tuning_signal() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    labels = load_adjudication_review_set(corpus)
    target = next(item for item in labels.reviews if item.rule_id == "CAP-CHAIN-001")
    target_keys = {(target.case_id, target.rule_id)}
    mutated = labels.model_copy(
        update={
            "reviews": tuple(
                item.model_copy(
                    update={
                        "category": AdjudicationCategory.DETECTION_FALSE_POSITIVE,
                        "disposition": RuleDisposition.TUNE,
                    }
                )
                if (item.case_id, item.rule_id) in target_keys
                else item
                for item in labels.reviews
            )
        }
    )

    report = CalibrationAdjudicationRunner().run(corpus, mutated)
    chain = next(item for item in report.by_rule if item.rule_id == "CAP-CHAIN-001")

    assert chain.detection_false_positives == 1
    assert "false-positive-review" in chain.reason_codes
    # CAP-CHAIN-001 meets the 20/20 sample threshold after corpus expansion, so
    # a reviewed detection false positive surfaces as the tuning signal.
    assert chain.recommended_disposition is RuleDisposition.TUNE


def test_text_and_json_reports_are_bilingual_and_deterministic() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    report = CalibrationAdjudicationRunner().run(corpus)
    json_renderer = CalibrationAdjudicationJsonRenderer()

    first = json_renderer.render(report)
    second = json_renderer.render(report)
    english = CalibrationAdjudicationTextRenderer().render(report)
    chinese = CalibrationAdjudicationTextRenderer(
        language=CapabilityRuleLanguage.ZH
    ).render(report)

    assert first == second
    assert json.loads(first)["format"] == (
        "agentsec-capability-calibration-adjudication-report"
    )
    assert "Gate Candidates" in english
    assert "more_data_required" in english
    assert "Hard Gate 候选" in chinese
    assert "more_data_required" in chinese


def test_adjudication_cli_writes_private_json_and_no_clobber(tmp_path: Path) -> None:
    output = tmp_path / "adjudication.json"
    command = (
        str(REPOSITORY_ROOT / ".venv" / "bin" / "python"),
        str(REPOSITORY_ROOT / "scripts" / "run-calibration-adjudication.py"),
        "--corpus",
        str(CALIBRATION_ROOT),
        "--adjudications",
        str(ADJUDICATION_PATH),
        "--format",
        "json",
        "--output",
        str(output),
    )
    result = subprocess.run(
        command,
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
    assert payload["summary"]["unresolved_count"] == 0
    assert all(
        item["status"] == "more_data_required" for item in payload["gate_candidates"]
    )

    repeated = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert repeated.returncode != 0
    assert "already exists" in repeated.stderr


def test_human_evidence_mode_requires_explicit_human_confidence() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    labels = load_adjudication_review_set(corpus)

    with pytest.raises(ValueError, match="human Confidence"):
        CalibrationAdjudicationRunner().run(
            corpus,
            labels,
            evidence_mode="human",
        )

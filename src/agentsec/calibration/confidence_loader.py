"""Safe loading and structural validation of P2-CAL-03 reviewer labels."""

from __future__ import annotations

from .confidence_models import ConfidenceReviewSet
from .confidence_validation import (
    ConfidenceValidationError,
    decode_confidence_review_set_json,
)
from .corpus import LoadedCalibrationCorpus

_MAX_REVIEW_BYTES = 512 * 1024


class ConfidenceReviewLoadError(RuntimeError):
    """Safe reviewer-label loading failure."""


def load_confidence_review_set(
    corpus: LoadedCalibrationCorpus,
    *,
    path: str = "confidence-reviews.json",
) -> ConfidenceReviewSet:
    """Load reviewer labels and verify they reference the loaded Corpus."""

    review_path = (corpus.root / path).resolve()
    try:
        review_path.relative_to(corpus.root.resolve())
    except ValueError as error:
        raise ConfidenceReviewLoadError(
            "Confidence review path escapes corpus root"
        ) from error
    if review_path.is_symlink() or not review_path.is_file():
        raise ConfidenceReviewLoadError("Confidence review file is missing or unsafe")
    data = review_path.read_bytes()
    if len(data) > _MAX_REVIEW_BYTES:
        raise ConfidenceReviewLoadError("Confidence review file exceeds bounded size")
    try:
        review_set = decode_confidence_review_set_json(data.decode("utf-8"))
    except (UnicodeDecodeError, ConfidenceValidationError) as error:
        raise ConfidenceReviewLoadError("Confidence review file is invalid") from error
    if review_set.corpus_id != corpus.index.corpus_id:
        raise ConfidenceReviewLoadError("Confidence review corpus_id does not match")
    case_map = {case.case_id: case for case in corpus.cases}
    keys: set[tuple[str, str, str]] = set()
    expected_review_keys: set[tuple[str, str]] = set()
    for ground_truth_case in corpus.cases:
        for (
            ground_truth_expectation
        ) in ground_truth_case.ground_truth.rule_expectations:
            if ground_truth_expectation.outcome.value == "match":
                expected_review_keys.add(
                    (ground_truth_case.case_id, ground_truth_expectation.rule_id)
                )
    for review in review_set.reviews:
        review_case = case_map.get(review.case_id)
        if review_case is None:
            raise ConfidenceReviewLoadError("Confidence review references unknown Case")
        review_expectation = next(
            (
                item
                for item in review_case.ground_truth.rule_expectations
                if item.rule_id == review.rule_id
            ),
            None,
        )
        if review_expectation is None or review_expectation.outcome.value != "match":
            raise ConfidenceReviewLoadError(
                "Confidence review must reference a matching Rule expectation"
            )
        key = (review.case_id, review.rule_id, review.reviewer_id)
        if key in keys:
            raise ConfidenceReviewLoadError("duplicate Confidence review label")
        keys.add(key)
    expected_count = len(expected_review_keys) * len(review_set.reviewer_ids)
    if len(review_set.reviews) != expected_count:
        raise ConfidenceReviewLoadError(
            "Confidence review set must label every matching Case for every reviewer"
        )
    return review_set

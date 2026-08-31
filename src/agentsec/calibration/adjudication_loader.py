"""Safe loading of P2-CAL-04 independent adjudication labels."""

from __future__ import annotations

from .adjudication_models import AdjudicationResolutionSet, AdjudicationReviewSet
from .adjudication_validation import (
    AdjudicationValidationError,
    decode_adjudication_resolution_set_json,
    decode_adjudication_review_set_json,
)
from .corpus import LoadedCalibrationCorpus

_MAX_ADJUDICATION_BYTES = 768 * 1024


class AdjudicationReviewLoadError(RuntimeError):
    """Safe independent-adjudication loading failure."""


def load_adjudication_review_set(
    corpus: LoadedCalibrationCorpus,
    *,
    path: str = "adjudication-reviews.json",
) -> AdjudicationReviewSet:
    """Load labels and verify they cover the loaded Corpus exactly."""

    review_path = (corpus.root / path).resolve()
    try:
        review_path.relative_to(corpus.root.resolve())
    except ValueError as error:
        raise AdjudicationReviewLoadError(
            "adjudication review path escapes corpus root"
        ) from error
    if review_path.is_symlink() or not review_path.is_file():
        raise AdjudicationReviewLoadError(
            "adjudication review file is missing or unsafe"
        )
    data = review_path.read_bytes()
    if len(data) > _MAX_ADJUDICATION_BYTES:
        raise AdjudicationReviewLoadError(
            "adjudication review file exceeds bounded size"
        )
    try:
        review_set = decode_adjudication_review_set_json(data.decode("utf-8"))
    except (UnicodeDecodeError, AdjudicationValidationError) as error:
        raise AdjudicationReviewLoadError(
            "adjudication review file is invalid"
        ) from error
    if review_set.corpus_id != corpus.index.corpus_id:
        raise AdjudicationReviewLoadError(
            "adjudication review corpus_id does not match"
        )
    if review_set.labels_version != corpus.index.labels_version:
        raise AdjudicationReviewLoadError(
            "adjudication review labels_version does not match"
        )

    expected_keys = {
        (case.case_id, expectation.rule_id)
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    }
    case_map = {case.case_id: case for case in corpus.cases}
    observed_keys: set[tuple[str, str, str]] = set()
    for review in review_set.reviews:
        case = case_map.get(review.case_id)
        if case is None:
            raise AdjudicationReviewLoadError(
                "adjudication review references unknown Case"
            )
        expectation = next(
            (
                item
                for item in case.ground_truth.rule_expectations
                if item.rule_id == review.rule_id
            ),
            None,
        )
        if expectation is None:
            raise AdjudicationReviewLoadError(
                "adjudication review references unknown Rule"
            )
        observed_keys.add((review.case_id, review.rule_id, review.reviewer_id))

    expected_review_keys = {
        (case_id, rule_id, reviewer_id)
        for case_id, rule_id in expected_keys
        for reviewer_id in review_set.reviewer_ids
    }
    if observed_keys != expected_review_keys:
        raise AdjudicationReviewLoadError(
            "adjudication review set must label every Case/Rule for every reviewer"
        )
    return review_set


class AdjudicationResolutionLoadError(RuntimeError):
    """Safe final-resolution loading failure."""


def load_adjudication_resolution_set(
    corpus: LoadedCalibrationCorpus,
    *,
    path: str = "adjudication-resolutions.json",
) -> AdjudicationResolutionSet:
    """Load optional final resolutions without replacing Reviewer labels."""

    resolution_path = (corpus.root / path).resolve()
    try:
        resolution_path.relative_to(corpus.root.resolve())
    except ValueError as error:
        raise AdjudicationResolutionLoadError(
            "adjudication resolution path escapes corpus root"
        ) from error
    if resolution_path.is_symlink() or not resolution_path.is_file():
        raise AdjudicationResolutionLoadError(
            "adjudication resolution file is missing or unsafe"
        )
    data = resolution_path.read_bytes()
    if len(data) > _MAX_ADJUDICATION_BYTES:
        raise AdjudicationResolutionLoadError(
            "adjudication resolution file exceeds bounded size"
        )
    try:
        resolution_set = decode_adjudication_resolution_set_json(data.decode("utf-8"))
    except (UnicodeDecodeError, AdjudicationValidationError) as error:
        raise AdjudicationResolutionLoadError(
            "adjudication resolution file is invalid"
        ) from error
    if resolution_set.corpus_id != corpus.index.corpus_id:
        raise AdjudicationResolutionLoadError(
            "adjudication resolution corpus_id does not match"
        )
    if resolution_set.labels_version != corpus.index.labels_version:
        raise AdjudicationResolutionLoadError(
            "adjudication resolution labels_version does not match"
        )
    expected = {
        (case.case_id, expectation.rule_id)
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    }
    if any(
        (item.case_id, item.rule_id) not in expected
        for item in resolution_set.resolutions
    ):
        raise AdjudicationResolutionLoadError(
            "adjudication resolution references an unknown Case or Rule"
        )
    return resolution_set

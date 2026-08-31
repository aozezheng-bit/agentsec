"""P2-CAL-03 Evidence Confidence agreement and Cohen's Kappa runner."""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations

from agentsec.capability_rules import CapabilityCorrelation
from agentsec.domain import EvidenceConfidence
from agentsec.versioning import CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION

from .confidence_loader import load_confidence_review_set
from .confidence_models import (
    ConfidenceAgreementMetrics,
    ConfidenceCalibrationPolicy,
    ConfidenceCalibrationReport,
    ConfidenceCalibrationSummary,
    ConfidenceCaseEvaluation,
    ConfidenceGradeMatrixRow,
    ConfidenceReviewerPairMetrics,
    ConfidenceReviewSet,
    ConfidenceRuleMetrics,
)
from .corpus import LoadedCalibrationCorpus
from .evaluator import CalibrationCaseEvaluator, DeterministicFactBundleEvaluator
from .models import CalibrationRuleOutcome

_MIN_CONFIDENCE_SAMPLES = 20
_LIMITATIONS = (
    "Seed reviewer labels are seeded rather than independently "
    "adjudicated human labels.",
    "Cohen's Kappa is computed on categorical A/B/C/D grades; it is not "
    "a Severity or score multiplier.",
    "Static Capability Rules do not produce A-level runtime evidence.",
    "Hard Gate eligibility remains undecided until independent adjudication, "
    "Corpus expansion, and P2-15A review.",
)


class ConfidenceCalibrationRunner:
    """Compare reviewer labels with each other and deterministic observations."""

    def __init__(self, evaluator: CalibrationCaseEvaluator | None = None) -> None:
        self._evaluator = evaluator or DeterministicFactBundleEvaluator()

    def run(
        self,
        corpus: LoadedCalibrationCorpus,
        review_set: ConfidenceReviewSet | None = None,
    ) -> ConfidenceCalibrationReport:
        if not isinstance(corpus, LoadedCalibrationCorpus):
            raise TypeError("Confidence runner requires LoadedCalibrationCorpus")
        labels = review_set or load_confidence_review_set(corpus)
        if labels.corpus_id != corpus.index.corpus_id:
            raise ValueError("Confidence review corpus_id does not match corpus")
        by_key = {
            (item.case_id, item.rule_id, item.reviewer_id): item
            for item in labels.reviews
        }
        case_evaluations: list[ConfidenceCaseEvaluation] = []
        for case in corpus.cases:
            for expectation in case.ground_truth.rule_expectations:
                if expectation.outcome is not CalibrationRuleOutcome.MATCH:
                    continue
                observation = self._evaluator.evaluate(
                    corpus_root=corpus.root,
                    case=case,
                    expectation=expectation,
                )
                reviewer_labels = tuple(
                    by_key[(case.case_id, expectation.rule_id, reviewer)]
                    for reviewer in labels.reviewer_ids
                )
                emitted = (
                    observation.confidences[0] if observation.confidences else None
                )
                if emitted is None:
                    raise ValueError("matching Confidence observation has no grade")
                case_evaluations.append(
                    ConfidenceCaseEvaluation(
                        case_id=case.case_id,
                        rule_id=expectation.rule_id,
                        correlation=expectation.correlations[0],
                        expected_confidence=expectation.confidences[0],
                        emitted_confidence=emitted,
                        reviewer_labels=reviewer_labels,
                        reviewer_agreement=len(
                            {item.confidence for item in reviewer_labels}
                        )
                        == 1,
                        expected_vs_emitted=expectation.confidences[0] is emitted,
                    )
                )
        ordered_cases = tuple(
            sorted(case_evaluations, key=lambda item: item.sort_key())
        )
        pairwise = self._pairwise(labels, ordered_cases)
        reviewer_metrics = self._reviewer_metrics(labels, ordered_cases)
        emitted_metrics = self._emitted_metrics(ordered_cases)
        by_rule = self._by_rule(ordered_cases)
        insufficient = sum(item.items < _MIN_CONFIDENCE_SAMPLES for item in by_rule)
        return ConfidenceCalibrationReport(
            format_version=CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION,
            status="complete",
            corpus_id=corpus.index.corpus_id,
            labels_version=labels.labels_version,
            reviewer_ids=labels.reviewer_ids,
            policy=ConfidenceCalibrationPolicy(),
            summary=ConfidenceCalibrationSummary(
                total_cases=len(ordered_cases),
                total_reviews=len(labels.reviews),
                reviewer_count=len(labels.reviewer_ids),
                reviewer_agreement=reviewer_metrics,
                expected_vs_emitted=emitted_metrics,
                insufficient_sample_items=insufficient,
            ),
            pairwise=pairwise,
            by_rule=by_rule,
            by_case=ordered_cases,
            limitations=_LIMITATIONS,
        )

    @staticmethod
    def _pairwise(
        labels: ConfidenceReviewSet,
        cases: tuple[ConfidenceCaseEvaluation, ...],
    ) -> tuple[ConfidenceReviewerPairMetrics, ...]:
        rows: list[ConfidenceReviewerPairMetrics] = []
        for reviewer_a, reviewer_b in combinations(labels.reviewer_ids, 2):
            values = [
                (
                    next(
                        item.confidence
                        for item in case.reviewer_labels
                        if item.reviewer_id == reviewer_a
                    ),
                    next(
                        item.confidence
                        for item in case.reviewer_labels
                        if item.reviewer_id == reviewer_b
                    ),
                )
                for case in cases
            ]
            rows.append(
                ConfidenceReviewerPairMetrics(
                    reviewer_a=reviewer_a,
                    reviewer_b=reviewer_b,
                    items=len(values),
                    agreement_rate=_agreement_rate(values),
                    cohens_kappa=_kappa(values),
                )
            )
        return tuple(rows)

    @staticmethod
    def _reviewer_metrics(
        labels: ConfidenceReviewSet,
        cases: tuple[ConfidenceCaseEvaluation, ...],
    ) -> ConfidenceAgreementMetrics:
        if len(labels.reviewer_ids) < 2:
            raise ValueError("Confidence agreement requires two reviewers")
        pairs = [
            (left.confidence, right.confidence)
            for case in cases
            for left, right in combinations(
                sorted(case.reviewer_labels, key=lambda item: item.reviewer_id),
                2,
            )
        ]
        return _agreement_metrics(pairs)

    @staticmethod
    def _emitted_metrics(
        cases: tuple[ConfidenceCaseEvaluation, ...],
    ) -> ConfidenceAgreementMetrics:
        pairs = tuple(
            (item.expected_confidence, item.emitted_confidence) for item in cases
        )
        return _agreement_metrics(pairs)

    @staticmethod
    def _by_rule(
        cases: tuple[ConfidenceCaseEvaluation, ...],
    ) -> tuple[ConfidenceRuleMetrics, ...]:
        grouped: dict[
            tuple[str, CapabilityCorrelation], list[ConfidenceCaseEvaluation]
        ] = defaultdict(list)
        for case in cases:
            grouped[(case.rule_id, case.correlation)].append(case)
        rows = []
        for (rule_id, correlation), values in sorted(
            grouped.items(), key=lambda item: (item[0][0], item[0][1].value)
        ):
            pairs = [
                (left.confidence, right.confidence)
                for item in values
                for left, right in combinations(
                    sorted(item.reviewer_labels, key=lambda label: label.reviewer_id),
                    2,
                )
            ]
            rows.append(
                ConfidenceRuleMetrics(
                    rule_id=rule_id,
                    correlation=correlation,
                    items=len(values),
                    reviewer_agreement_rate=_agreement_rate(pairs),
                    cohens_kappa=_kappa(pairs),
                    expected_vs_emitted_rate=_agreement_rate(
                        [
                            (item.expected_confidence, item.emitted_confidence)
                            for item in values
                        ]
                    ),
                )
            )
        return tuple(rows)


def _agreement_metrics(
    pairs: list[tuple[EvidenceConfidence, EvidenceConfidence]]
    | tuple[tuple[EvidenceConfidence, EvidenceConfidence], ...],
) -> ConfidenceAgreementMetrics:
    rows = tuple(pairs)
    return ConfidenceAgreementMetrics(
        items=len(rows),
        agreement_count=sum(left is right for left, right in rows),
        agreement_rate=_agreement_rate(rows),
        cohens_kappa=_kappa(rows),
        grade_matrix=_grade_matrix(rows),
    )


def _agreement_rate(
    pairs: list[tuple[EvidenceConfidence, EvidenceConfidence]]
    | tuple[tuple[EvidenceConfidence, EvidenceConfidence], ...],
) -> float | None:
    if not pairs:
        return None
    return round(sum(left is right for left, right in pairs) / len(pairs), 6)


def _kappa(
    pairs: list[tuple[EvidenceConfidence, EvidenceConfidence]]
    | tuple[tuple[EvidenceConfidence, EvidenceConfidence], ...],
) -> float | None:
    if not pairs:
        return None
    categories = tuple(EvidenceConfidence)
    n = len(pairs)
    observed = sum(left is right for left, right in pairs) / n
    row_counts = Counter(left for left, _ in pairs)
    column_counts = Counter(right for _, right in pairs)
    expected = sum(
        row_counts[category] * column_counts[category] for category in categories
    ) / (n * n)
    if expected == 1:
        return 1.0 if observed == 1 else 0.0
    return round((observed - expected) / (1 - expected), 6)


def _grade_matrix(
    pairs: list[tuple[EvidenceConfidence, EvidenceConfidence]]
    | tuple[tuple[EvidenceConfidence, EvidenceConfidence], ...],
) -> tuple[ConfidenceGradeMatrixRow, ...]:
    rows = []
    for expected in EvidenceConfidence:
        counts = Counter(observed for left, observed in pairs if left is expected)
        rows.append(
            ConfidenceGradeMatrixRow(
                expected=expected,
                observed_a=counts[EvidenceConfidence.A],
                observed_b=counts[EvidenceConfidence.B],
                observed_c=counts[EvidenceConfidence.C],
                observed_d=counts[EvidenceConfidence.D],
            )
        )
    return tuple(rows)

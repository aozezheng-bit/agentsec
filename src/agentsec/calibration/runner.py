"""P2-CAL-02 deterministic replay and calibration metric calculation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from agentsec.versioning import CALIBRATION_REPORT_OUTPUT_VERSION

from .corpus import LoadedCalibrationCorpus
from .evaluation import (
    CalibrationAggregateMetrics,
    CalibrationCaseEvaluation,
    CalibrationClassification,
    CalibrationConfusionMatrix,
    CalibrationReport,
    CalibrationReportPolicy,
    CalibrationReportSummary,
    CalibrationRuleMetrics,
)
from .evaluator import (
    CalibrationCaseEvaluator,
    DeterministicFactBundleEvaluator,
)
from .models import CalibrationRuleOutcome

_MIN_POSITIVE_SAMPLES = 20
_MIN_NEGATIVE_SAMPLES = 20
_LIMITATIONS = (
    "Seed fact-bundle replay validates normalized Rule conditions, not parser "
    "recall or runtime grants.",
    "Seed labels are not adjudicated production Precision or Recall measurements.",
    "Hard Gate eligibility remains undecided until independent label collection, "
    "Corpus expansion, and P2-15A review.",
)


class DeterministicCalibrationRunner:
    """Evaluate every labeled expectation and derive reproducible metrics."""

    def __init__(self, evaluator: CalibrationCaseEvaluator | None = None) -> None:
        self._evaluator = evaluator or DeterministicFactBundleEvaluator()

    def run(self, corpus: LoadedCalibrationCorpus) -> CalibrationReport:
        if not isinstance(corpus, LoadedCalibrationCorpus):
            raise TypeError("calibration runner requires LoadedCalibrationCorpus")
        results: list[CalibrationCaseEvaluation] = []
        for case in corpus.cases:
            for expectation in case.ground_truth.rule_expectations:
                try:
                    observation = self._evaluator.evaluate(
                        corpus_root=corpus.root,
                        case=case,
                        expectation=expectation,
                    )
                except Exception:
                    results.append(self._failed_result(case.case_id, expectation))
                    continue
                classification = _classification(
                    expectation.outcome, observation.outcome
                )
                results.append(
                    CalibrationCaseEvaluation(
                        case_id=case.case_id,
                        rule_id=expectation.rule_id,
                        expected_outcome=expectation.outcome,
                        observed_outcome=observation.outcome,
                        classification=classification,
                        expected_correlations=expectation.correlations,
                        observed_correlations=observation.correlations,
                        expected_confidences=expectation.confidences,
                        observed_confidences=observation.confidences,
                        observed_findings=observation.finding_count,
                        correlation_agreement=(
                            expectation.correlations == observation.correlations
                            if expectation.outcome is CalibrationRuleOutcome.MATCH
                            and observation.outcome is CalibrationRuleOutcome.MATCH
                            else None
                        ),
                        confidence_agreement=(
                            expectation.confidences == observation.confidences
                            if expectation.outcome is CalibrationRuleOutcome.MATCH
                            and observation.outcome is CalibrationRuleOutcome.MATCH
                            else None
                        ),
                        evidence_complete=observation.evidence_complete,
                        coverage_visible=observation.coverage_visible,
                        unknowns_visible=observation.unknowns_visible,
                        unknown_applicable=observation.unknown_applicable,
                        duplicate_findings=observation.duplicate_findings,
                        failure=observation.failure,
                    )
                )
        ordered = tuple(sorted(results, key=lambda item: item.sort_key()))
        rules = self._rule_metrics(ordered)
        summary = self._summary(corpus, ordered, rules)
        return CalibrationReport(
            format_version=CALIBRATION_REPORT_OUTPUT_VERSION,
            status="incomplete" if summary.failures else "complete",
            corpus_id=corpus.index.corpus_id,
            labels_version=corpus.index.labels_version,
            evaluator_id=self._evaluator.evaluator_id,
            evaluator_version=self._evaluator.evaluator_version,
            policy=CalibrationReportPolicy(),
            summary=summary,
            rules=rules,
            cases=ordered,
            limitations=_LIMITATIONS,
        )

    @staticmethod
    def _failed_result(case_id: str, expectation: object) -> CalibrationCaseEvaluation:
        from .models import CalibrationRuleExpectation

        if not isinstance(expectation, CalibrationRuleExpectation):
            raise TypeError("failed calibration expectation is invalid")
        return CalibrationCaseEvaluation(
            case_id=case_id,
            rule_id=expectation.rule_id,
            expected_outcome=expectation.outcome,
            observed_outcome=CalibrationRuleOutcome.NO_MATCH,
            classification=(
                CalibrationClassification.FALSE_NEGATIVE
                if expectation.outcome is CalibrationRuleOutcome.MATCH
                else CalibrationClassification.TRUE_NEGATIVE
            ),
            expected_correlations=expectation.correlations,
            expected_confidences=expectation.confidences,
            observed_findings=0,
            correlation_agreement=None,
            confidence_agreement=None,
            evidence_complete=False,
            coverage_visible=False,
            unknowns_visible=False,
            unknown_applicable=False,
            duplicate_findings=0,
            failure=True,
        )

    @staticmethod
    def _rule_metrics(
        results: tuple[CalibrationCaseEvaluation, ...],
    ) -> tuple[CalibrationRuleMetrics, ...]:
        grouped: dict[str, list[CalibrationCaseEvaluation]] = defaultdict(list)
        for result in results:
            grouped[result.rule_id].append(result)
        return tuple(
            _metrics(rule_id, tuple(grouped[rule_id])) for rule_id in sorted(grouped)
        )

    @staticmethod
    def _summary(
        corpus: LoadedCalibrationCorpus,
        results: tuple[CalibrationCaseEvaluation, ...],
        rules: tuple[CalibrationRuleMetrics, ...],
    ) -> CalibrationReportSummary:
        confusion = _confusion(results)
        micro = _aggregate(confusion)
        matching = tuple(
            item
            for item in results
            if item.observed_outcome is CalibrationRuleOutcome.MATCH
        )
        unknown_cases = tuple(
            item
            for item in results
            if next(
                case for case in corpus.cases if case.case_id == item.case_id
            ).ground_truth.unknown_dimensions
        )
        correlation_values = tuple(
            item.correlation_agreement
            for item in results
            if item.correlation_agreement is not None
        )
        confidence_values = tuple(
            item.confidence_agreement
            for item in results
            if item.confidence_agreement is not None
        )
        return CalibrationReportSummary(
            total_cases=len(corpus.cases),
            total_expectations=len(results),
            evaluated_rules=len(rules),
            failures=sum(item.failure for item in results),
            duplicate_findings=sum(item.duplicate_findings for item in results),
            insufficient_sample_rules=sum(
                not item.sufficient_sample_size for item in rules
            ),
            coverage_visibility=_ratio(
                sum(item.coverage_visible for item in results), len(results)
            )
            or 0.0,
            unknown_visibility=(
                _ratio(
                    sum(item.unknowns_visible for item in unknown_cases),
                    len(unknown_cases),
                )
                if unknown_cases
                else None
            ),
            evidence_completeness=(
                _ratio(sum(item.evidence_complete for item in matching), len(matching))
                if matching
                else None
            ),
            correlation_agreement=_boolean_rate(correlation_values),
            confidence_agreement=_boolean_rate(confidence_values),
            micro=micro,
            macro_precision=_average(item.precision for item in rules),
            macro_recall=_average(item.recall for item in rules),
            macro_f1=_average(item.f1 for item in rules),
        )


def _classification(
    expected: CalibrationRuleOutcome,
    observed: CalibrationRuleOutcome,
) -> CalibrationClassification:
    if expected is CalibrationRuleOutcome.MATCH:
        return (
            CalibrationClassification.TRUE_POSITIVE
            if observed is CalibrationRuleOutcome.MATCH
            else CalibrationClassification.FALSE_NEGATIVE
        )
    return (
        CalibrationClassification.FALSE_POSITIVE
        if observed is CalibrationRuleOutcome.MATCH
        else CalibrationClassification.TRUE_NEGATIVE
    )


def _confusion(
    results: tuple[CalibrationCaseEvaluation, ...],
) -> CalibrationConfusionMatrix:
    return CalibrationConfusionMatrix(
        true_positive=sum(
            item.classification is CalibrationClassification.TRUE_POSITIVE
            for item in results
        ),
        false_positive=sum(
            item.classification is CalibrationClassification.FALSE_POSITIVE
            for item in results
        ),
        false_negative=sum(
            item.classification is CalibrationClassification.FALSE_NEGATIVE
            for item in results
        ),
        true_negative=sum(
            item.classification is CalibrationClassification.TRUE_NEGATIVE
            for item in results
        ),
    )


def _metrics(
    rule_id: str,
    results: tuple[CalibrationCaseEvaluation, ...],
) -> CalibrationRuleMetrics:
    confusion = _confusion(results)
    matching = tuple(
        item
        for item in results
        if item.observed_outcome is CalibrationRuleOutcome.MATCH
    )
    unknown = tuple(item for item in results if item.unknown_applicable)
    correlations = tuple(
        item.correlation_agreement
        for item in results
        if item.correlation_agreement is not None
    )
    confidences = tuple(
        item.confidence_agreement
        for item in results
        if item.confidence_agreement is not None
    )
    positive = sum(
        item.expected_outcome is CalibrationRuleOutcome.MATCH for item in results
    )
    negative = len(results) - positive
    return CalibrationRuleMetrics(
        rule_id=rule_id,
        samples=len(results),
        positive_samples=positive,
        negative_samples=negative,
        confusion=confusion,
        precision=_precision(confusion),
        recall=_recall(confusion),
        false_positive_rate=_false_positive_rate(confusion),
        f1=_f1(confusion),
        correlation_agreement=_boolean_rate(correlations),
        confidence_agreement=_boolean_rate(confidences),
        evidence_completeness=(
            _ratio(sum(item.evidence_complete for item in matching), len(matching))
            if matching
            else None
        ),
        coverage_visibility=_ratio(
            sum(item.coverage_visible for item in results), len(results)
        )
        or 0.0,
        unknown_visibility=(
            _ratio(sum(item.unknowns_visible for item in unknown), len(unknown))
            if unknown
            else None
        ),
        duplicate_findings=sum(item.duplicate_findings for item in results),
        failures=sum(item.failure for item in results),
        sufficient_sample_size=(
            positive >= _MIN_POSITIVE_SAMPLES and negative >= _MIN_NEGATIVE_SAMPLES
        ),
    )


def _aggregate(confusion: CalibrationConfusionMatrix) -> CalibrationAggregateMetrics:
    return CalibrationAggregateMetrics(
        confusion=confusion,
        precision=_precision(confusion),
        recall=_recall(confusion),
        false_positive_rate=_false_positive_rate(confusion),
        f1=_f1(confusion),
    )


def _precision(matrix: CalibrationConfusionMatrix) -> float | None:
    return _ratio(matrix.true_positive, matrix.true_positive + matrix.false_positive)


def _recall(matrix: CalibrationConfusionMatrix) -> float | None:
    return _ratio(matrix.true_positive, matrix.true_positive + matrix.false_negative)


def _false_positive_rate(matrix: CalibrationConfusionMatrix) -> float | None:
    return _ratio(matrix.false_positive, matrix.false_positive + matrix.true_negative)


def _f1(matrix: CalibrationConfusionMatrix) -> float | None:
    precision = _precision(matrix)
    recall = _recall(matrix)
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 6)


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _boolean_rate(values: tuple[bool, ...]) -> float | None:
    return _ratio(sum(values), len(values)) if values else None


def _average(values: Iterable[float | None]) -> float | None:
    present = tuple(value for value in values if value is not None)
    if not present:
        return None
    return round(sum(present) / len(present), 6)

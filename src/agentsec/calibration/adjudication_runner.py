"""P2-CAL-04 adjudication, FP/FN calibration, and Gate Candidate runner."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from agentsec.domain import EvidenceConfidence, Severity
from agentsec.versioning import CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION

from .adjudication_loader import load_adjudication_review_set
from .adjudication_models import (
    AdjudicationCategory,
    AdjudicationConsensus,
    AdjudicationReportPolicy,
    AdjudicationResolutionSet,
    AdjudicationReviewSet,
    AdjudicationStatus,
    AdjudicationSummary,
    CalibrationAdjudicationReport,
    GateCandidateAssessment,
    GateCandidateStatus,
    RuleCalibrationAssessment,
    RuleDisposition,
)
from .confidence_models import ConfidenceCalibrationReport, ConfidenceRuleMetrics
from .confidence_runner import ConfidenceCalibrationRunner
from .corpus import LoadedCalibrationCorpus
from .evaluation import (
    CalibrationCaseEvaluation,
    CalibrationReport,
    CalibrationRuleMetrics,
)
from .evaluator import CalibrationCaseEvaluator
from .models import CalibrationCase, CalibrationRuleOutcome
from .runner import DeterministicCalibrationRunner

_MIN_POSITIVE_SAMPLES = 20
_MIN_NEGATIVE_SAMPLES = 20
_MIN_PRECISION = 0.95
_MIN_RECALL = 0.90

_COMMON_LIMITATIONS = (
    "FP/FN metrics are fact-bundle replay metrics; parser and Framework Adapter "
    "recall remain uncalibrated.",
    "Policy-accepted risk, out-of-scope uncertainty, and runtime uncertainty "
    "are not silently counted as deterministic Rule correctness.",
    "Gate Candidate status is report-only; no Capability Rule or Hard Gate is "
    "modified or activated by P2-CAL-04.",
)
_SEED_LIMITATION = (
    "Adjudication labels in the checked-in seed set are seeded rather than "
    "independent production review evidence."
)
_HUMAN_LIMITATION = (
    "Human evidence mode validates supplied Reviewer artifacts but does not "
    "attest reviewer identity, independence, or runtime capability."
)


@dataclass(frozen=True, slots=True)
class _GateDefinition:
    gate_id: str
    title: str
    floor: Severity
    rule_ids: tuple[str, ...]


_GATE_DEFINITIONS = (
    _GateDefinition(
        gate_id="HG-CAPCHAIN-001",
        title="Execution + secret access + external network",
        floor=Severity.HIGH,
        rule_ids=("CAP-CHAIN-001",),
    ),
    _GateDefinition(
        gate_id="HG-PRODAUTO-001",
        title="Production authority without effective approval",
        floor=Severity.HIGH,
        rule_ids=("CAP-APPROVAL-001", "CAP-AUTOPROD-001"),
    ),
    _GateDefinition(
        gate_id="HG-EXTERNALPROD-001",
        title="Privileged external identity with production authority",
        floor=Severity.CRITICAL,
        rule_ids=(
            "CAP-EXTERNALPRIVILEGED-001",
            "CAP-PRODADMIN-001",
            "CAP-PRODIDENTITY-001",
            "CAP-PRODWRITE-001",
        ),
    ),
)


class CalibrationAdjudicationRunner:
    """Produce a deterministic, report-only P2-CAL-04 report."""

    def __init__(self, evaluator: CalibrationCaseEvaluator | None = None) -> None:
        self._deterministic_runner = DeterministicCalibrationRunner(evaluator)
        self._confidence_runner = ConfidenceCalibrationRunner(evaluator)

    def run(
        self,
        corpus: LoadedCalibrationCorpus,
        adjudications: AdjudicationReviewSet | None = None,
        confidence_report: ConfidenceCalibrationReport | None = None,
        resolutions: AdjudicationResolutionSet | None = None,
        *,
        evidence_mode: Literal["seed", "human"] = "seed",
    ) -> CalibrationAdjudicationReport:
        if not isinstance(corpus, LoadedCalibrationCorpus):
            raise TypeError("adjudication runner requires LoadedCalibrationCorpus")
        if evidence_mode not in {"seed", "human"}:
            raise ValueError("unsupported adjudication evidence mode")
        labels = adjudications or load_adjudication_review_set(corpus)
        if labels.corpus_id != corpus.index.corpus_id:
            raise ValueError("adjudication corpus_id does not match corpus")
        if labels.labels_version != corpus.index.labels_version:
            raise ValueError("adjudication labels_version does not match corpus")
        if resolutions is not None:
            if resolutions.corpus_id != corpus.index.corpus_id:
                raise ValueError("adjudication resolution corpus_id does not match")
            if resolutions.labels_version != corpus.index.labels_version:
                raise ValueError(
                    "adjudication resolution labels_version does not match"
                )
            if resolutions.reviewer_ids != labels.reviewer_ids:
                raise ValueError("adjudication resolution reviewer_ids do not match")
        if evidence_mode == "human":
            if confidence_report is None:
                raise ValueError(
                    "human evidence mode requires an explicit human Confidence report"
                )
            if any(item.status is AdjudicationStatus.SEEDED for item in labels.reviews):
                raise ValueError(
                    "human evidence mode rejects seeded adjudication labels"
                )
        deterministic = self._deterministic_runner.run(corpus)
        confidence = confidence_report or self._confidence_runner.run(corpus)
        if confidence.corpus_id != corpus.index.corpus_id:
            raise ValueError("Confidence report corpus_id does not match corpus")
        case_results = {
            (item.case_id, item.rule_id): item for item in deterministic.cases
        }
        consensus = self._consensus(corpus, labels, case_results, resolutions)
        ordered_consensus = tuple(sorted(consensus, key=lambda item: item.sort_key()))
        by_rule = self._rule_assessments(
            corpus,
            deterministic,
            confidence,
            ordered_consensus,
            evidence_mode=evidence_mode,
        )
        gates = self._gate_candidates(
            corpus,
            confidence,
            ordered_consensus,
            by_rule,
            evidence_mode=evidence_mode,
        )
        summary = self._summary(labels, ordered_consensus)
        return CalibrationAdjudicationReport(
            format_version=CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION,
            status="complete",
            corpus_id=corpus.index.corpus_id,
            labels_version=labels.labels_version,
            reviewer_ids=labels.reviewer_ids,
            policy=AdjudicationReportPolicy(evidence_mode=evidence_mode),
            summary=summary,
            by_rule=by_rule,
            gate_candidates=gates,
            by_case=ordered_consensus,
            limitations=(
                (_SEED_LIMITATION if evidence_mode == "seed" else _HUMAN_LIMITATION),
                *_COMMON_LIMITATIONS,
            ),
        )

    @staticmethod
    def _consensus(
        corpus: LoadedCalibrationCorpus,
        labels: AdjudicationReviewSet,
        case_results: Mapping[tuple[str, str], CalibrationCaseEvaluation],
        resolutions: AdjudicationResolutionSet | None,
    ) -> list[AdjudicationConsensus]:
        by_key = {
            (item.case_id, item.rule_id, item.reviewer_id): item
            for item in labels.reviews
        }
        resolution_by_key = (
            {}
            if resolutions is None
            else {
                (item.case_id, item.rule_id): item for item in resolutions.resolutions
            }
        )
        results: list[AdjudicationConsensus] = []
        for case in corpus.cases:
            for expectation in case.ground_truth.rule_expectations:
                result = case_results[(case.case_id, expectation.rule_id)]
                reviewer_labels = tuple(
                    by_key[(case.case_id, expectation.rule_id, reviewer)]
                    for reviewer in labels.reviewer_ids
                )
                classifications = tuple(item.classification for item in reviewer_labels)
                categories = tuple(item.category for item in reviewer_labels)
                dispositions = tuple(item.disposition for item in reviewer_labels)
                classification_agreement = len(set(classifications)) == 1
                category_agreement = len(set(categories)) == 1
                disposition_agreement = len(set(dispositions)) == 1
                consensus = (
                    classification_agreement
                    and category_agreement
                    and disposition_agreement
                )
                resolution = resolution_by_key.get((case.case_id, expectation.rule_id))
                if consensus and resolution is not None:
                    raise ValueError(
                        "adjudication resolution is not allowed for an agreed review"
                    )
                adjudication_required = not consensus
                adjudication_completed = resolution is not None
                final_classification = (
                    classifications[0]
                    if consensus
                    else resolution.final_classification
                    if resolution is not None
                    else None
                )
                final_category = (
                    categories[0]
                    if consensus
                    else resolution.final_category
                    if resolution is not None
                    else AdjudicationCategory.UNRESOLVED
                )
                final_disposition = (
                    dispositions[0]
                    if consensus
                    else resolution.final_disposition
                    if resolution is not None
                    else RuleDisposition.MORE_DATA
                )
                results.append(
                    AdjudicationConsensus(
                        case_id=case.case_id,
                        rule_id=expectation.rule_id,
                        deterministic_classification=result.classification,
                        reviewer_count=len(reviewer_labels),
                        classification_agreement=classification_agreement,
                        category_agreement=category_agreement,
                        disposition_agreement=disposition_agreement,
                        adjudication_required=adjudication_required,
                        adjudication_completed=adjudication_completed,
                        final_classification=final_classification,
                        final_category=final_category,
                        final_disposition=final_disposition,
                    )
                )
        return results

    @staticmethod
    def _summary(
        labels: AdjudicationReviewSet,
        cases: tuple[AdjudicationConsensus, ...],
    ) -> AdjudicationSummary:
        return AdjudicationSummary(
            total_expectations=len(cases),
            total_reviews=len(labels.reviews),
            reviewer_count=len(labels.reviewer_ids),
            consensus_count=sum(
                item.final_category is not AdjudicationCategory.UNRESOLVED
                for item in cases
            ),
            unresolved_count=sum(
                item.final_category is AdjudicationCategory.UNRESOLVED for item in cases
            ),
            adjudication_required_count=sum(
                item.adjudication_required for item in cases
            ),
            adjudication_completed_count=sum(
                item.adjudication_completed for item in cases
            ),
            classification_agreement_rate=_rate(
                item.classification_agreement for item in cases
            ),
            category_agreement_rate=_rate(item.category_agreement for item in cases),
            disposition_agreement_rate=_rate(
                item.disposition_agreement for item in cases
            ),
        )

    @staticmethod
    def _rule_assessments(
        corpus: LoadedCalibrationCorpus,
        deterministic: CalibrationReport,
        confidence: ConfidenceCalibrationReport,
        cases: tuple[AdjudicationConsensus, ...],
        *,
        evidence_mode: Literal["seed", "human"],
    ) -> tuple[RuleCalibrationAssessment, ...]:
        deterministic_by_rule = {item.rule_id: item for item in deterministic.rules}
        confidence_by_rule: dict[str, list[ConfidenceRuleMetrics]] = defaultdict(list)
        for confidence_metric in confidence.by_rule:
            confidence_by_rule[confidence_metric.rule_id].append(confidence_metric)
        cases_by_rule: dict[str, list[AdjudicationConsensus]] = defaultdict(list)
        for consensus_item in cases:
            cases_by_rule[consensus_item.rule_id].append(consensus_item)
        rows: list[RuleCalibrationAssessment] = []
        for rule_id in sorted(deterministic_by_rule):
            metric = deterministic_by_rule[rule_id]
            rule_cases = tuple(cases_by_rule[rule_id])
            counts = _category_counts(rule_cases)
            confidence_values = tuple(
                item.cohens_kappa
                for item in confidence_by_rule[rule_id]
                if item.cohens_kappa is not None
            )
            confidence_kappa = min(confidence_values) if confidence_values else None
            reason_codes = _rule_reason_codes(
                corpus,
                rule_id,
                metric,
                counts,
                rule_cases,
                confidence_kappa,
                evidence_mode=evidence_mode,
            )
            rows.append(
                RuleCalibrationAssessment(
                    rule_id=rule_id,
                    samples=metric.samples,
                    positive_samples=metric.positive_samples,
                    negative_samples=metric.negative_samples,
                    true_positive=metric.confusion.true_positive,
                    false_positive=metric.confusion.false_positive,
                    false_negative=metric.confusion.false_negative,
                    true_negative=metric.confusion.true_negative,
                    precision=metric.precision,
                    recall=metric.recall,
                    f1=metric.f1,
                    detection_false_positives=counts[
                        AdjudicationCategory.DETECTION_FALSE_POSITIVE
                    ],
                    policy_accepted_risks=counts[
                        AdjudicationCategory.POLICY_ACCEPTED_RISK
                    ],
                    in_scope_false_negatives=counts[
                        AdjudicationCategory.IN_SCOPE_FALSE_NEGATIVE
                    ],
                    out_of_scope_cases=counts[AdjudicationCategory.OUT_OF_SCOPE],
                    runtime_uncertainty_cases=counts[
                        AdjudicationCategory.RUNTIME_UNCERTAINTY
                    ],
                    unresolved_cases=counts[AdjudicationCategory.UNRESOLVED],
                    reviewer_agreement_rate=_rate(
                        item.classification_agreement for item in rule_cases
                    ),
                    category_agreement_rate=_rate(
                        item.category_agreement for item in rule_cases
                    ),
                    disposition_agreement_rate=_rate(
                        item.disposition_agreement for item in rule_cases
                    ),
                    confidence_kappa=confidence_kappa,
                    recommended_disposition=_rule_disposition(reason_codes),
                    reason_codes=reason_codes,
                )
            )
        return tuple(rows)

    @staticmethod
    def _gate_candidates(
        corpus: LoadedCalibrationCorpus,
        confidence: ConfidenceCalibrationReport,
        cases: tuple[AdjudicationConsensus, ...],
        rules: tuple[RuleCalibrationAssessment, ...],
        *,
        evidence_mode: Literal["seed", "human"],
    ) -> tuple[GateCandidateAssessment, ...]:
        rule_map = {item.rule_id: item for item in rules}
        confidence_by_rule: dict[str, list[ConfidenceRuleMetrics]] = defaultdict(list)
        for item in confidence.by_rule:
            confidence_by_rule[item.rule_id].append(item)
        rows: list[GateCandidateAssessment] = []
        for definition in _GATE_DEFINITIONS:
            selected = [
                rule_map[rule_id]
                for rule_id in definition.rule_ids
                if rule_id in rule_map
            ]
            reason_codes: set[str] = set()
            if len(selected) != len(definition.rule_ids):
                reason_codes.add("candidate-rule-not-in-corpus")
            candidate_cases = _candidate_cases(corpus, definition.rule_ids)
            positive_cases = tuple(
                case
                for case in candidate_cases
                if _candidate_matches(case, definition.rule_ids)
            )
            positive_samples = sum(
                case.ground_truth.coverage == "complete"
                and not case.ground_truth.unknown_dimensions
                for case in positive_cases
            )
            negative_samples = sum(
                not _candidate_matches(case, definition.rule_ids)
                and case.ground_truth.coverage == "complete"
                and not case.ground_truth.unknown_dimensions
                for case in candidate_cases
            )
            if positive_samples < _MIN_POSITIVE_SAMPLES:
                reason_codes.add("insufficient-positive-samples")
            if negative_samples < _MIN_NEGATIVE_SAMPLES:
                reason_codes.add("insufficient-negative-samples")
            precision_values = tuple(
                item.precision for item in selected if item.precision is not None
            )
            recall_values = tuple(
                item.recall for item in selected if item.recall is not None
            )
            precision = min(precision_values) if precision_values else None
            recall = min(recall_values) if recall_values else None
            if precision is None or precision < _MIN_PRECISION:
                reason_codes.add("precision-below-threshold")
            if recall is None or recall < _MIN_RECALL:
                reason_codes.add("recall-below-threshold")
            candidate_case_ids = {case.case_id for case in candidate_cases}
            selected_case_keys = {
                (item.case_id, item.rule_id)
                for item in cases
                if item.case_id in candidate_case_ids
                and item.rule_id in definition.rule_ids
            }
            selected_cases = tuple(
                item
                for item in cases
                if (item.case_id, item.rule_id) in selected_case_keys
            )
            if any(
                item.final_category is AdjudicationCategory.UNRESOLVED
                for item in selected_cases
            ):
                reason_codes.add("unresolved-adjudication")
            if any(item.adjudication_required for item in selected_cases):
                reason_codes.add("reviewer-disagreement")
            coverage_complete = all(
                case.ground_truth.coverage == "complete" for case in positive_cases
            )
            if not coverage_complete:
                reason_codes.add("incomplete-coverage")
            unknown_free = all(
                not case.ground_truth.unknown_dimensions for case in positive_cases
            )
            if not unknown_free:
                reason_codes.add("relevant-unknown")
            confidence_grades = _candidate_confidence_grades(
                confidence,
                positive_cases,
                definition.rule_ids,
            )
            if EvidenceConfidence.D in confidence_grades:
                reason_codes.add("d-confidence-excluded")
            if definition.floor is Severity.CRITICAL and set(confidence_grades) != {
                EvidenceConfidence.B
            }:
                reason_codes.add("critical-requires-b-confidence")
            kappa_values = tuple(
                item.cohens_kappa
                for rule_id in definition.rule_ids
                for item in confidence_by_rule[rule_id]
                if item.cohens_kappa is not None
            )
            confidence_kappa = min(kappa_values) if kappa_values else None
            if confidence_kappa is None or confidence_kappa < 0.80:
                reason_codes.add("reviewer-kappa-below-target")
            if evidence_mode == "seed":
                reason_codes.add("seed-labels-not-independent")
            status = (
                GateCandidateStatus.MORE_DATA_REQUIRED
                if positive_samples < _MIN_POSITIVE_SAMPLES
                or negative_samples < _MIN_NEGATIVE_SAMPLES
                or "seed-labels-not-independent" in reason_codes
                else (
                    GateCandidateStatus.REJECTED
                    if reason_codes
                    else GateCandidateStatus.ACCEPTED
                )
            )
            rows.append(
                GateCandidateAssessment(
                    gate_id=definition.gate_id,
                    title=definition.title,
                    floor=definition.floor,
                    rule_ids=definition.rule_ids,
                    positive_samples=positive_samples,
                    negative_samples=negative_samples,
                    precision=precision,
                    recall=recall,
                    confidence_kappa=confidence_kappa,
                    confidence_grades=confidence_grades,
                    coverage_complete=coverage_complete,
                    unknown_free=unknown_free,
                    reviewer_consensus=not any(
                        not item.classification_agreement
                        or not item.category_agreement
                        or not item.disposition_agreement
                        for item in selected_cases
                    ),
                    status=status,
                    reason_codes=tuple(sorted(reason_codes)),
                )
            )
        return tuple(sorted(rows, key=lambda item: item.gate_id))


def _candidate_cases(
    corpus: LoadedCalibrationCorpus,
    rule_ids: tuple[str, ...],
) -> tuple[CalibrationCase, ...]:
    required = set(rule_ids)
    return tuple(
        case
        for case in corpus.cases
        if required
        <= {expectation.rule_id for expectation in case.ground_truth.rule_expectations}
    )


def _candidate_matches(case: CalibrationCase, rule_ids: tuple[str, ...]) -> bool:
    expected = {
        item.rule_id: item.outcome
        for item in case.ground_truth.rule_expectations
        if item.rule_id in rule_ids
    }
    return all(
        expected[rule_id] is CalibrationRuleOutcome.MATCH for rule_id in rule_ids
    )


def _candidate_confidence_grades(
    confidence: ConfidenceCalibrationReport,
    positive_cases: tuple[CalibrationCase, ...],
    rule_ids: tuple[str, ...],
) -> tuple[EvidenceConfidence, ...]:
    case_ids = {case.case_id for case in positive_cases}
    grades = {
        label.confidence
        for item in confidence.by_case
        if item.case_id in case_ids and item.rule_id in rule_ids
        for label in item.reviewer_labels
    }
    return tuple(sorted(grades, key=lambda item: item.value))


def _category_counts(
    cases: tuple[AdjudicationConsensus, ...],
) -> dict[AdjudicationCategory, int]:
    return {
        category: sum(item.final_category is category for item in cases)
        for category in AdjudicationCategory
    }


def _rule_reason_codes(
    corpus: LoadedCalibrationCorpus,
    rule_id: str,
    metric: CalibrationRuleMetrics,
    counts: dict[AdjudicationCategory, int],
    cases: tuple[AdjudicationConsensus, ...],
    confidence_kappa: float | None,
    *,
    evidence_mode: Literal["seed", "human"],
) -> tuple[str, ...]:
    reasons: set[str] = set()
    if metric.positive_samples < _MIN_POSITIVE_SAMPLES:
        reasons.add("insufficient-positive-samples")
    if metric.negative_samples < _MIN_NEGATIVE_SAMPLES:
        reasons.add("insufficient-negative-samples")
    if (
        metric.confusion.false_positive
        or counts[AdjudicationCategory.DETECTION_FALSE_POSITIVE]
    ):
        reasons.add("false-positive-review")
    if (
        metric.confusion.false_negative
        or counts[AdjudicationCategory.IN_SCOPE_FALSE_NEGATIVE]
    ):
        reasons.add("false-negative-review")
    if counts[AdjudicationCategory.UNRESOLVED]:
        reasons.add("unresolved-adjudication")
    if (
        counts[AdjudicationCategory.OUT_OF_SCOPE]
        or counts[AdjudicationCategory.RUNTIME_UNCERTAINTY]
    ):
        reasons.add("scope-or-runtime-uncertainty")
    if confidence_kappa is None or confidence_kappa < 0.80:
        reasons.add("reviewer-kappa-below-target")
    if not _unknown_free(corpus, (rule_id,)):
        reasons.add("relevant-unknown")
    if not _coverage_complete(corpus, (rule_id,)):
        reasons.add("incomplete-coverage")
    if not cases:
        reasons.add("no-adjudication-cases")
    if evidence_mode == "seed":
        reasons.add("seed-labels-not-independent")
    return tuple(sorted(reasons))


def _rule_disposition(reason_codes: tuple[str, ...]) -> RuleDisposition:
    if (
        "insufficient-positive-samples" in reason_codes
        or "insufficient-negative-samples" in reason_codes
    ):
        return RuleDisposition.MORE_DATA
    if (
        "false-positive-review" in reason_codes
        or "false-negative-review" in reason_codes
    ):
        return RuleDisposition.TUNE
    if any(
        item in reason_codes
        for item in (
            "scope-or-runtime-uncertainty",
            "relevant-unknown",
            "incomplete-coverage",
            "reviewer-kappa-below-target",
        )
    ):
        return RuleDisposition.SHADOW
    return RuleDisposition.KEEP


def _rate(values: Iterable[bool | int | float]) -> float | None:
    values_tuple = tuple(float(value) for value in values)
    if not values_tuple:
        return None
    return round(sum(values_tuple) / len(values_tuple), 6)


def _coverage_complete(
    corpus: LoadedCalibrationCorpus, rule_ids: tuple[str, ...]
) -> bool:
    for case in corpus.cases:
        for expectation in case.ground_truth.rule_expectations:
            if (
                expectation.rule_id in rule_ids
                and case.ground_truth.coverage != "complete"
            ):
                return False
    return True


def _unknown_free(corpus: LoadedCalibrationCorpus, rule_ids: tuple[str, ...]) -> bool:
    for case in corpus.cases:
        for expectation in case.ground_truth.rule_expectations:
            if (
                expectation.rule_id in rule_ids
                and expectation.outcome.value == "match"
                and case.ground_truth.unknown_dimensions
            ):
                return False
    return True


def _confidence_grades(
    corpus: LoadedCalibrationCorpus,
    rule_ids: tuple[str, ...],
) -> tuple[EvidenceConfidence, ...]:
    grades = {
        confidence
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
        if expectation.rule_id in rule_ids and expectation.outcome.value == "match"
        for confidence in expectation.confidences
    }
    return tuple(sorted(grades, key=lambda item: item.value))

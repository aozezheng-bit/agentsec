"""Deterministic semantic-quality evaluation for Shadow Provider trials."""

from __future__ import annotations

import json
from collections import Counter
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.semantic.invocation import (
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationError,
    SemanticShadowInvocationResult,
)
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
)

SEMANTIC_EVALUATION_SCHEMA_VERSION = "0.1.0"
SEMANTIC_EVALUATION_OUTPUT_VERSION = "0.1.0"
SEMANTIC_EVALUATION_FORMAT = "agentsec-semantic-evaluation-report"
SEMANTIC_EVALUATION_CASE_FORMAT = "agentsec-semantic-evaluation-case"
_MAX_CASES = 256
_MAX_EXPECTED = 128
_MAX_ERROR_CODE = 64


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticEvaluationExpected(_Strict):
    """Gold semantic judgment with Evidence binding supplied by a reviewer."""

    judgment_id: Annotated[str, Field(min_length=1, max_length=64)]
    kind: SemanticCandidateKind
    category: str
    disposition: SemanticCandidateDisposition
    evidence_ids: tuple[str, ...]

    @field_validator("category")
    @classmethod
    def category_must_be_safe(cls, value: str) -> str:
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("semantic evaluation category is unsafe")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError(
                "semantic evaluation Evidence IDs must be sorted and unique"
            )
        return values


class SemanticEvaluationCase(_Strict):
    """One bounded labeled case; source text remains inside the P3-01 input."""

    format: Literal["agentsec-semantic-evaluation-case"] = (
        "agentsec-semantic-evaluation-case"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    language: Literal["zh", "en", "mixed"] = "en"
    semantic_input: SemanticAnalysisInput
    expected: Annotated[
        tuple[SemanticEvaluationExpected, ...], Field(max_length=_MAX_EXPECTED)
    ] = ()

    @model_validator(mode="after")
    def case_must_be_coherent(self) -> SemanticEvaluationCase:
        if self.case_id != self.semantic_input.analysis_id:
            raise ValueError("semantic evaluation case ID must match Analysis ID")
        ids = tuple(item.judgment_id for item in self.expected)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("semantic evaluation judgments must be sorted and unique")
        known = {item.evidence_id for item in self.semantic_input.evidence}
        for item in self.expected:
            if not set(item.evidence_ids) <= known:
                raise ValueError("semantic evaluation expected Evidence is unknown")
        return self


class SemanticEvaluationCaseStatus(StrEnum):
    COMPLETE = "complete"
    FAILED = "failed"


class SemanticEvaluationCaseResult(_Strict):
    """Value-free result for one case, with no raw model output."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    status: SemanticEvaluationCaseStatus
    expected_count: Annotated[int, Field(ge=0)]
    predicted_count: Annotated[int, Field(ge=0)]
    true_positive: Annotated[int, Field(ge=0)]
    false_positive: Annotated[int, Field(ge=0)]
    false_negative: Annotated[int, Field(ge=0)]
    evidence_exact_matches: Annotated[int, Field(ge=0)]
    evidence_comparisons: Annotated[int, Field(ge=0)]
    semantic_complete: bool = False
    invocation_success: bool = False
    error_code: Annotated[str, Field(max_length=_MAX_ERROR_CODE)] | None = None

    @model_validator(mode="after")
    def counts_must_be_coherent(self) -> SemanticEvaluationCaseResult:
        if self.status is SemanticEvaluationCaseStatus.COMPLETE:
            if self.error_code is not None or not self.invocation_success:
                raise ValueError(
                    "complete evaluation case must have successful invocation"
                )
            if self.true_positive + self.false_negative != self.expected_count:
                raise ValueError("evaluation expected counts are inconsistent")
            if self.true_positive + self.false_positive != self.predicted_count:
                raise ValueError("evaluation predicted counts are inconsistent")
        else:
            if self.invocation_success or self.error_code is None:
                raise ValueError("failed evaluation case requires safe error code")
        return self


class SemanticEvaluationMetrics(_Strict):
    """Deterministic semantic and Evidence quality metrics."""

    case_count: Annotated[int, Field(ge=0)]
    completed_case_count: Annotated[int, Field(ge=0)]
    failed_case_count: Annotated[int, Field(ge=0)]
    true_positive: Annotated[int, Field(ge=0)]
    false_positive: Annotated[int, Field(ge=0)]
    false_negative: Annotated[int, Field(ge=0)]
    precision: Annotated[float, Field(ge=0, le=1)]
    recall: Annotated[float, Field(ge=0, le=1)]
    f1: Annotated[float, Field(ge=0, le=1)]
    evidence_exact_matches: Annotated[int, Field(ge=0)]
    evidence_comparisons: Annotated[int, Field(ge=0)]
    evidence_binding_accuracy: Annotated[float, Field(ge=0, le=1)]
    complete_coverage_cases: Annotated[int, Field(ge=0)]
    complete_coverage_rate: Annotated[float, Field(ge=0, le=1)]


class SemanticEvaluationReport(_Strict):
    """Machine-readable Shadow evaluation report; no enforcement decision."""

    format: Literal["agentsec-semantic-evaluation-report"] = (
        "agentsec-semantic-evaluation-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    cases: Annotated[
        tuple[SemanticEvaluationCaseResult, ...], Field(max_length=_MAX_CASES)
    ]
    metrics: SemanticEvaluationMetrics
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticEvaluationReport:
        if self.metrics.case_count != len(self.cases):
            raise ValueError("semantic evaluation case count is inconsistent")
        if self.metrics.completed_case_count != sum(
            case.status is SemanticEvaluationCaseStatus.COMPLETE for case in self.cases
        ):
            raise ValueError("semantic evaluation completed count is inconsistent")
        if (
            self.metrics.failed_case_count
            != self.metrics.case_count - self.metrics.completed_case_count
        ):
            raise ValueError("semantic evaluation failed count is inconsistent")
        return self


class SemanticEvaluationHarness:
    """Run labeled cases through a Shadow Adapter and calculate replay metrics."""

    def evaluate(
        self,
        cases: tuple[SemanticEvaluationCase, ...],
        adapter: SemanticShadowInvocationAdapter,
    ) -> SemanticEvaluationReport:
        if not isinstance(cases, tuple):
            raise TypeError("semantic evaluation cases must be a tuple")
        if len(cases) > _MAX_CASES:
            raise ValueError("semantic evaluation case count exceeds the bound")
        if not isinstance(adapter, SemanticShadowInvocationAdapter):
            raise TypeError(
                "semantic evaluation adapter must be SemanticShadowInvocationAdapter"
            )
        results: list[SemanticEvaluationCaseResult] = []
        for case in cases:
            if not isinstance(case, SemanticEvaluationCase):
                raise TypeError("semantic evaluation case has an invalid type")
            results.append(self._evaluate_case(case, adapter))
        provider = adapter.provider_metadata
        metrics = _calculate_metrics(tuple(results))
        return SemanticEvaluationReport(
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            cases=tuple(results),
            metrics=metrics,
        )

    def _evaluate_case(
        self,
        case: SemanticEvaluationCase,
        adapter: SemanticShadowInvocationAdapter,
    ) -> SemanticEvaluationCaseResult:
        try:
            result = adapter.invoke(case.semantic_input)
        except SemanticShadowInvocationError as error:
            return SemanticEvaluationCaseResult(
                case_id=case.case_id,
                status=SemanticEvaluationCaseStatus.FAILED,
                expected_count=len(case.expected),
                predicted_count=0,
                true_positive=0,
                false_positive=0,
                false_negative=len(case.expected),
                evidence_exact_matches=0,
                evidence_comparisons=0,
                error_code=error.code.value,
            )
        return _compare_case(case, result)


def render_semantic_evaluation_text(report: SemanticEvaluationReport) -> str:
    """Render a bounded bilingual-neutral summary without raw source values."""

    metrics = report.metrics
    lines = [
        "AgentSec Semantic Shadow Evaluation",
        f"Provider: {report.provider_id}",
        f"Model: {report.model_id}",
        (
            "Mode: shadow_only; report_only=true; policy_authority=false; "
            "release_authority=false"
        ),
        (
            f"Cases: {metrics.case_count} "
            f"(complete={metrics.completed_case_count}, "
            f"failed={metrics.failed_case_count})"
        ),
        f"Precision: {metrics.precision:.3f}",
        f"Recall: {metrics.recall:.3f}",
        f"F1: {metrics.f1:.3f}",
        f"Evidence binding accuracy: {metrics.evidence_binding_accuracy:.3f}",
        f"Complete coverage rate: {metrics.complete_coverage_rate:.3f}",
        (
            "LLM output is candidate evidence only; this report grants no Policy "
            "or release authority."
        ),
    ]
    return "\n".join(lines) + "\n"


def encode_semantic_evaluation_json(report: SemanticEvaluationReport) -> str:
    if not isinstance(report, SemanticEvaluationReport):
        raise TypeError("semantic evaluation encoder requires SemanticEvaluationReport")
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _compare_case(
    case: SemanticEvaluationCase,
    result: SemanticShadowInvocationResult,
) -> SemanticEvaluationCaseResult:
    expected_signatures = [
        (item.kind.value, item.category, item.disposition.value)
        for item in case.expected
    ]
    predicted_signatures = [
        (item.kind.value, item.category.value, item.disposition.value)
        for item in result.analysis.candidates
    ]
    expected_counter = Counter(expected_signatures)
    predicted_counter = Counter(predicted_signatures)
    true_positive = sum(
        min(expected_counter[key], predicted_counter[key]) for key in expected_counter
    )
    false_negative = len(expected_signatures) - true_positive
    false_positive = len(predicted_signatures) - true_positive

    evidence_exact_matches = 0
    evidence_comparisons = true_positive
    remaining_expected = list(case.expected)
    for candidate in result.analysis.candidates:
        signature = (
            candidate.kind.value,
            candidate.category.value,
            candidate.disposition.value,
        )
        match = next(
            (
                item
                for item in remaining_expected
                if (item.kind.value, item.category, item.disposition.value) == signature
            ),
            None,
        )
        if match is not None:
            remaining_expected.remove(match)
            if tuple(candidate.evidence_ids) == tuple(match.evidence_ids):
                evidence_exact_matches += 1
    return SemanticEvaluationCaseResult(
        case_id=case.case_id,
        status=SemanticEvaluationCaseStatus.COMPLETE,
        expected_count=len(expected_signatures),
        predicted_count=len(predicted_signatures),
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        evidence_exact_matches=evidence_exact_matches,
        evidence_comparisons=evidence_comparisons,
        semantic_complete=result.analysis.coverage.complete,
        invocation_success=True,
    )


def _calculate_metrics(
    cases: tuple[SemanticEvaluationCaseResult, ...],
) -> SemanticEvaluationMetrics:
    case_count = len(cases)
    completed = sum(
        case.status is SemanticEvaluationCaseStatus.COMPLETE for case in cases
    )
    tp = sum(case.true_positive for case in cases)
    fp = sum(case.false_positive for case in cases)
    fn = sum(case.false_negative for case in cases)
    # No predictions (tp + fp == 0) or no positives (tp + fn == 0) yield 0.0
    # instead of a vacuous 1.0 so an empty evaluation can never look perfect.
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    evidence_matches = sum(case.evidence_exact_matches for case in cases)
    evidence_comparisons = sum(case.evidence_comparisons for case in cases)
    complete_cases = sum(case.semantic_complete for case in cases)
    return SemanticEvaluationMetrics(
        case_count=case_count,
        completed_case_count=completed,
        failed_case_count=case_count - completed,
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1=round(f1, 6),
        evidence_exact_matches=evidence_matches,
        evidence_comparisons=evidence_comparisons,
        evidence_binding_accuracy=round(
            evidence_matches / evidence_comparisons if evidence_comparisons else 1.0,
            6,
        ),
        complete_coverage_cases=complete_cases,
        complete_coverage_rate=round(
            complete_cases / case_count if case_count else 1.0, 6
        ),
    )


class SemanticParityCaseResult(_Strict):
    """Value-free comparison of Offline and Live predictions for one case."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    offline_status: Literal["complete", "failed"]
    live_status: Literal["complete", "failed"]
    prediction_equal: bool
    evidence_equal: bool
    offline_error_code: Annotated[str, Field(max_length=_MAX_ERROR_CODE)] | None = None
    live_error_code: Annotated[str, Field(max_length=_MAX_ERROR_CODE)] | None = None


class SemanticParityMetrics(_Strict):
    """Deterministic Offline/Live parity counters."""

    case_count: Annotated[int, Field(ge=0)]
    comparable_case_count: Annotated[int, Field(ge=0)]
    prediction_equal_cases: Annotated[int, Field(ge=0)]
    evidence_equal_cases: Annotated[int, Field(ge=0)]
    prediction_parity_rate: Annotated[float, Field(ge=0, le=1)]
    evidence_parity_rate: Annotated[float, Field(ge=0, le=1)]


class SemanticParityReport(_Strict):
    """Report-only parity evidence; it cannot promote a Provider."""

    format: Literal["agentsec-semantic-parity-report"] = (
        "agentsec-semantic-parity-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    offline_provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    live_provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    offline_model_id: Annotated[str, Field(min_length=1, max_length=160)]
    live_model_id: Annotated[str, Field(min_length=1, max_length=160)]
    cases: tuple[SemanticParityCaseResult, ...]
    metrics: SemanticParityMetrics
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    release_authority: Literal[False] = False
    provider_promotion_authority: Literal[False] = False


class SemanticParityHarness:
    """Run identical labeled inputs through Offline and Live Shadow adapters."""

    def compare(
        self,
        cases: tuple[SemanticEvaluationCase, ...],
        offline_adapter: SemanticShadowInvocationAdapter,
        live_adapter: SemanticShadowInvocationAdapter,
    ) -> SemanticParityReport:
        if not isinstance(cases, tuple):
            raise TypeError("semantic parity cases must be a tuple")
        if not isinstance(offline_adapter, SemanticShadowInvocationAdapter):
            raise TypeError("offline adapter is invalid")
        if not isinstance(live_adapter, SemanticShadowInvocationAdapter):
            raise TypeError("live adapter is invalid")
        offline_meta = offline_adapter.provider_metadata
        live_meta = live_adapter.provider_metadata
        results: list[SemanticParityCaseResult] = []
        for case in cases:
            if not isinstance(case, SemanticEvaluationCase):
                raise TypeError("semantic parity case is invalid")
            results.append(_compare_parity_case(case, offline_adapter, live_adapter))
        comparable = sum(
            item.offline_status == "complete" and item.live_status == "complete"
            for item in results
        )
        prediction_equal = sum(item.prediction_equal for item in results)
        evidence_equal = sum(item.evidence_equal for item in results)
        return SemanticParityReport(
            offline_provider_id=offline_meta.provider_id,
            live_provider_id=live_meta.provider_id,
            offline_model_id=offline_meta.model_id,
            live_model_id=live_meta.model_id,
            cases=tuple(results),
            metrics=SemanticParityMetrics(
                case_count=len(results),
                comparable_case_count=comparable,
                prediction_equal_cases=prediction_equal,
                evidence_equal_cases=evidence_equal,
                prediction_parity_rate=round(
                    prediction_equal / comparable if comparable else 1.0, 6
                ),
                evidence_parity_rate=round(
                    evidence_equal / comparable if comparable else 1.0, 6
                ),
            ),
        )


def _compare_parity_case(
    case: SemanticEvaluationCase,
    offline_adapter: SemanticShadowInvocationAdapter,
    live_adapter: SemanticShadowInvocationAdapter,
) -> SemanticParityCaseResult:
    outcomes: list[SemanticShadowInvocationResult | SemanticShadowInvocationError] = []
    for adapter in (offline_adapter, live_adapter):
        try:
            outcomes.append(adapter.invoke(case.semantic_input))
        except SemanticShadowInvocationError as error:
            outcomes.append(error)
    offline, live = outcomes
    if isinstance(offline, SemanticShadowInvocationError):
        offline_status: Literal["complete", "failed"] = "failed"
        offline_error_code = offline.code.value
        offline_signature: tuple[object, ...] | None = None
        offline_evidence: tuple[object, ...] | None = None
    else:
        offline_status = "complete"
        offline_error_code = None
        offline_signature = _result_signature(offline)
        offline_evidence = _result_evidence_signature(offline)
    if isinstance(live, SemanticShadowInvocationError):
        live_status: Literal["complete", "failed"] = "failed"
        live_error_code = live.code.value
        live_signature = None
        live_evidence = None
    else:
        live_status = "complete"
        live_error_code = None
        live_signature = _result_signature(live)
        live_evidence = _result_evidence_signature(live)
    comparable = offline_signature is not None and live_signature is not None
    return SemanticParityCaseResult(
        case_id=case.case_id,
        offline_status=offline_status,
        live_status=live_status,
        prediction_equal=comparable and offline_signature == live_signature,
        evidence_equal=comparable and offline_evidence == live_evidence,
        offline_error_code=offline_error_code,
        live_error_code=live_error_code,
    )


def _result_signature(
    result: SemanticShadowInvocationResult,
) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (candidate.kind.value, candidate.category.value, candidate.disposition.value)
        for candidate in result.analysis.candidates
    )


def _result_evidence_signature(
    result: SemanticShadowInvocationResult,
) -> tuple[tuple[str, ...], ...]:
    return tuple(candidate.evidence_ids for candidate in result.analysis.candidates)


__all__ = [
    "SEMANTIC_EVALUATION_CASE_FORMAT",
    "SEMANTIC_EVALUATION_FORMAT",
    "SEMANTIC_EVALUATION_OUTPUT_VERSION",
    "SEMANTIC_EVALUATION_SCHEMA_VERSION",
    "SemanticEvaluationCase",
    "SemanticEvaluationCaseResult",
    "SemanticEvaluationCaseStatus",
    "SemanticEvaluationExpected",
    "SemanticEvaluationHarness",
    "SemanticEvaluationMetrics",
    "SemanticEvaluationReport",
    "SemanticParityCaseResult",
    "SemanticParityHarness",
    "SemanticParityMetrics",
    "SemanticParityReport",
    "encode_semantic_evaluation_json",
    "render_semantic_evaluation_text",
]

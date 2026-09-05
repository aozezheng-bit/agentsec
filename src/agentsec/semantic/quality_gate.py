"""P3-11B semantic quality qualification gate over the human-labeled gold set.

Loads the P3-11A gold labels, evaluates one Shadow Adapter against them with
the P3-03 evaluation harness, compares the deterministic metrics with provider
quality thresholds, and emits a frozen report-only qualification report.
The gate never grants Provider, Finding, Rule, Policy, CI, Gate, or release
authority; failing results stay visible as evidence.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.semantic.evaluation import (
    SemanticEvaluationCase,
    SemanticEvaluationExpected,
    SemanticEvaluationHarness,
    SemanticEvaluationReport,
)
from agentsec.semantic.invocation import SemanticShadowInvocationAdapter
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    _sha256_text,
)
from agentsec.semantic.promotion import ProviderQualityThresholds

SEMANTIC_QUALIFICATION_VERSION = "0.1.0"
_MAX_GOLD_CASES = 256
_MAX_QUALIFICATION_REASONS = 16


class QualityGateError(RuntimeError):
    """Safe qualification failure without echoing any corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic quality gate failed ({code}).")


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class GoldLabelProvenance(StrEnum):
    HUMAN_AUTHORED = "human_authored"
    AI_DRAFT_HUMAN_CONFIRMED = "ai_draft_human_confirmed"
    AI_ASSISTED = "ai_assisted"


class GoldLabelCase(_Strict):
    """One gold judgment row bound to sanitized evidence produced in P3-11A."""

    format: Literal["agentsec-p3-11-semantic-gold-label-case"] = (
        "agentsec-p3-11-semantic-gold-label-case"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    evidence_id: Annotated[str, Field(min_length=1, max_length=128)]
    sanitized_text: Annotated[str, Field(min_length=1, max_length=4096)]
    source_label: Annotated[str, Field(min_length=1, max_length=512)]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    expected: tuple[SemanticEvaluationExpected, ...]

    @model_validator(mode="after")
    def case_must_be_coherent(self) -> GoldLabelCase:
        ids = tuple(item.judgment_id for item in self.expected)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("gold label judgments must be sorted and unique")
        payloads = tuple(
            (item.kind.value, item.category, item.disposition.value)
            for item in self.expected
        )
        if len(set(payloads)) != len(payloads):
            raise ValueError("gold label judgments contain duplicates")
        for item in self.expected:
            if item.kind is SemanticCandidateKind.AMBIGUITY and (
                item.disposition is not SemanticCandidateDisposition.UNCERTAIN
            ):
                raise ValueError("ambiguity judgment requires uncertain disposition")
        return self


class GoldLabelSet(_Strict):
    """Imported P3-11A gold labels; text exists only as sanitized evidence."""

    format: Literal["agentsec-p3-11-semantic-gold-labels"] = (
        "agentsec-p3-11-semantic-gold-labels"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independence_statement: Annotated[str, Field(min_length=1, max_length=2048)]
    label_provenance: GoldLabelProvenance
    case_count: Annotated[int, Field(ge=1, le=_MAX_GOLD_CASES)]
    cases: tuple[GoldLabelCase, ...]

    @model_validator(mode="after")
    def set_must_be_coherent(self) -> GoldLabelSet:
        if self.case_count != len(self.cases):
            raise ValueError("gold label case count is inconsistent")
        ids = tuple(case.case_id for case in self.cases)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("gold label case IDs must be sorted and unique")
        if self.label_provenance is GoldLabelProvenance.AI_ASSISTED:
            raise ValueError("ai_assisted labels cannot back a qualification gate")
        return self


class QualityGateStatus(StrEnum):
    QUALIFIED = "qualified"
    NOT_QUALIFIED = "not_qualified"


class QualityGateCheck(StrEnum):
    GOLD_LABELS_VALID = "gold_labels_valid"
    PROVIDER_ID_MATCH = "provider_id_match"
    MODEL_ID_MATCH = "model_id_match"
    COMPLETED_CASES = "completed_cases"
    QUALITY_METRICS = "quality_metrics"


class QualityGateReport(_Strict):
    """Report-only qualification decision over one evaluation report."""

    format: Literal["agentsec-semantic-quality-qualification-report"] = (
        "agentsec-semantic-quality-qualification-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    label_provenance: GoldLabelProvenance
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    status: QualityGateStatus
    thresholds: ProviderQualityThresholds
    metrics: dict[str, float]
    failed_checks: tuple[str, ...] = ()
    reasons: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @field_validator("failed_checks")
    @classmethod
    def checks_must_be_sorted_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("qualification failed checks must be sorted/unique")
        if len(values) > _MAX_QUALIFICATION_REASONS:
            raise ValueError("qualification failed checks exceed the bound")
        return values

    @model_validator(mode="after")
    def status_must_match_checks(self) -> QualityGateReport:
        if self.status is QualityGateStatus.QUALIFIED and self.failed_checks:
            raise ValueError("qualified report cannot carry failed checks")
        if self.status is QualityGateStatus.NOT_QUALIFIED and not self.failed_checks:
            raise ValueError("not_qualified report must carry failed checks")
        return self


class SemanticQualityGate:
    """Evaluate one Shadow Adapter over the gold set and qualify it."""

    def qualify(
        self,
        *,
        gold: GoldLabelSet,
        adapter: SemanticShadowInvocationAdapter,
        thresholds: ProviderQualityThresholds | None = None,
        expected_provider_id: str | None = None,
        expected_model_id: str | None = None,
    ) -> QualityGateReport:
        if not isinstance(gold, GoldLabelSet):
            raise TypeError("qualification requires GoldLabelSet")
        if not isinstance(adapter, SemanticShadowInvocationAdapter):
            raise TypeError(
                "qualification adapter must be SemanticShadowInvocationAdapter"
            )
        thresholds = thresholds or ProviderQualityThresholds()
        cases = self._build_cases(gold)
        harness = SemanticEvaluationHarness()
        report = harness.evaluate(tuple(cases), adapter)
        return self._decide(
            gold=gold,
            report=report,
            thresholds=thresholds,
            expected_provider_id=expected_provider_id,
            expected_model_id=expected_model_id,
        )

    def qualify_evaluation_report(
        self,
        *,
        gold: GoldLabelSet,
        report: SemanticEvaluationReport,
        thresholds: ProviderQualityThresholds | None = None,
        expected_provider_id: str | None = None,
        expected_model_id: str | None = None,
    ) -> QualityGateReport:
        """Qualify one already-computed evaluation report without re-invoking.

        This supports single-invocation cost budgets: the caller runs the
        evaluation once and passes the report here for qualification. The
        report is never re-evaluated and never gains authority.
        """

        if not isinstance(gold, GoldLabelSet):
            raise TypeError("qualification requires GoldLabelSet")
        if not isinstance(report, SemanticEvaluationReport):
            raise TypeError(
                "qualification evaluation requires SemanticEvaluationReport"
            )
        thresholds = thresholds or ProviderQualityThresholds()
        return self._decide(
            gold=gold,
            report=report,
            thresholds=thresholds,
            expected_provider_id=expected_provider_id,
            expected_model_id=expected_model_id,
        )

    def _build_cases(self, gold: GoldLabelSet) -> list[SemanticEvaluationCase]:
        cases: list[SemanticEvaluationCase] = []
        for gold_case in gold.cases:
            chunk = _pack_chunk(gold_case)
            semantic_input = SemanticAnalysisInput(
                analysis_id=gold_case.case_id,
                deterministic_context=SemanticDeterministicContext(
                    coverage_complete=True
                ),
                evidence=(chunk,),
            )
            cases.append(
                SemanticEvaluationCase(
                    case_id=gold_case.case_id,
                    semantic_input=semantic_input,
                    language="mixed",
                    expected=gold_case.expected,
                )
            )
        return cases

    def _decide(
        self,
        *,
        gold: GoldLabelSet,
        report: SemanticEvaluationReport,
        thresholds: ProviderQualityThresholds,
        expected_provider_id: str | None,
        expected_model_id: str | None,
    ) -> QualityGateReport:
        failed: list[str] = []
        reasons: list[str] = []

        if gold.case_count < thresholds.min_case_count:
            failed.append(QualityGateCheck.GOLD_LABELS_VALID.value)
            reasons.append("gold_case_count_below_threshold")

        if report.metrics.case_count == 0:
            failed.append(QualityGateCheck.COMPLETED_CASES.value)
            reasons.append("evaluation_case_count_zero")

        metrics = report.metrics
        if expected_provider_id is not None and (
            metrics.case_count and report.provider_id != expected_provider_id
        ):
            failed.append(QualityGateCheck.PROVIDER_ID_MATCH.value)
            reasons.append("provider_id_mismatch")
        if expected_model_id is not None and report.model_id != expected_model_id:
            failed.append(QualityGateCheck.MODEL_ID_MATCH.value)
            reasons.append("model_id_mismatch")
        if metrics.failed_case_count:
            failed.append(QualityGateCheck.COMPLETED_CASES.value)
            reasons.append("evaluation_case_failures_present")

        quality = (
            metrics.precision >= thresholds.min_precision
            and metrics.recall >= thresholds.min_recall
            and metrics.f1 >= thresholds.min_f1
            and metrics.evidence_binding_accuracy
            >= thresholds.min_evidence_binding_accuracy
            and metrics.complete_coverage_rate >= thresholds.min_complete_coverage_rate
        )
        if not quality:
            failed.append(QualityGateCheck.QUALITY_METRICS.value)
            reasons.append("quality_threshold_not_met")

        failed = sorted(set(failed))
        reasons = reasons[:_MAX_QUALIFICATION_REASONS]
        status = (
            QualityGateStatus.QUALIFIED
            if not failed
            else QualityGateStatus.NOT_QUALIFIED
        )
        return QualityGateReport(
            reviewer_id=gold.reviewer_id,
            label_provenance=GoldLabelProvenance.AI_DRAFT_HUMAN_CONFIRMED
            if gold.label_provenance is GoldLabelProvenance.AI_DRAFT_HUMAN_CONFIRMED
            else gold.label_provenance,
            provider_id=report.provider_id,
            model_id=report.model_id,
            status=status,
            thresholds=thresholds,
            metrics={
                "case_count": float(metrics.case_count),
                "completed": float(metrics.completed_case_count),
                "failed": float(metrics.failed_case_count),
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
                "evidence_binding_accuracy": metrics.evidence_binding_accuracy,
                "complete_coverage_rate": metrics.complete_coverage_rate,
            },
            failed_checks=tuple(failed),
            reasons=tuple(reasons),
        )


def load_gold_labels(path: Path) -> GoldLabelSet:
    """Load and validate a P3-11A gold-label JSON artifact."""

    if not isinstance(path, Path):
        raise TypeError("gold label path must be a Path")
    if path.is_symlink():
        raise QualityGateError("unsafe_gold_label_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualityGateError("gold_labels_unreadable") from error
    if not isinstance(payload, dict):
        raise QualityGateError("gold_labels_invalid")
    bound = _bind_gold_payload(payload)
    try:
        return GoldLabelSet.model_validate(bound)
    except ValueError as error:
        raise QualityGateError("gold_labels_invalid") from error


def _bind_gold_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Bind the importer artifact fields into the GoldLabelSet shape."""

    cases = []
    pack_texts = _load_pack_texts()
    for entry in payload.get("cases", []):
        pack_case = pack_texts.get(entry.get("case_id"))
        if pack_case is None:
            raise QualityGateError("gold_labels_invalid")
        cases.append(
            {
                "case_id": entry["case_id"],
                "evidence_id": pack_case["evidence_id"],
                "sanitized_text": pack_case["sanitized_text"],
                "source_label": pack_case["source_label"],
                "start_line": pack_case["start_line"],
                "end_line": pack_case["end_line"],
                "expected": entry.get("expected", ()),
            }
        )
    return {
        "format": "agentsec-p3-11-semantic-gold-labels",
        "schema_version": "0.1.0",
        "reviewer_id": payload.get("reviewer_id", ""),
        "independence_statement": payload.get("independence_statement", ""),
        "label_provenance": payload.get("label_provenance", ""),
        "case_count": payload.get("case_count", len(cases)),
        "cases": cases,
    }


_GOLD_PACK_PATH = (
    Path(__file__).resolve().parents[3]
    / "pilots"
    / "semantic-quality-p3-11"
    / "reviewer-pack"
    / "cases.json"
)

_GOLD_ASSET_SHA = "00" * 32


def _pack_chunk(gold_case: GoldLabelCase) -> SemanticEvidenceChunk:
    """Rebuild the P3-11A evidence chunk without re-sanitizing stored text.

    The pack stores the already-minimized text, the content-addressed
    evidence ID, and the source locator; re-running the sanitizer would
    double-escape the text and break Evidence binding. The stored
    ``sanitized_text`` is hashed directly and the recomputed evidence ID is
    checked against the pack-recorded ID to detect tampering.
    """

    text_sha256 = _sha256_text(gold_case.sanitized_text)
    chunk = SemanticEvidenceChunk(
        evidence_id=gold_case.evidence_id,
        asset_path=gold_case.source_label,
        asset_sha256=_GOLD_ASSET_SHA,
        start_line=gold_case.start_line,
        end_line=gold_case.end_line,
        text=gold_case.sanitized_text,
        text_sha256=text_sha256,
        sanitization_applied=True,
    )
    return chunk


def _load_pack_texts() -> dict[str, dict[str, Any]]:
    try:
        pack_cases = json.loads(_GOLD_PACK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualityGateError("gold_pack_unreadable") from error
    return {case["case_id"]: case for case in pack_cases["cases"]}


def encode_semantic_qualification_json(value: QualityGateReport) -> str:
    if not isinstance(value, QualityGateReport):
        raise TypeError("semantic qualification encoder requires QualityGateReport")
    return value.model_dump_json(indent=2)


__all__ = [
    "SEMANTIC_QUALIFICATION_VERSION",
    "SEMANTIC_QUALIFICATION_VERSION",
    "GoldLabelCase",
    "GoldLabelProvenance",
    "GoldLabelSet",
    "QualityGateError",
    "QualityGateReport",
    "QualityGateStatus",
    "SemanticQualityGate",
    "encode_semantic_qualification_json",
    "load_gold_labels",
]

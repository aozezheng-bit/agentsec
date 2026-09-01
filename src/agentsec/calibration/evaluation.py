"""P2-CAL-02 deterministic evaluation result and metric contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from agentsec.capability_rules import CapabilityCorrelation
from agentsec.domain import EvidenceConfidence
from agentsec.manifests.models import InterfaceVersionString
from agentsec.versioning import (
    CALIBRATION_REPORT_OUTPUT_VERSION,
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
)

from .models import (
    CalibrationModel,
    CalibrationRuleOutcome,
    NonEmptyText,
    StableId,
)

CALIBRATION_REPORT_FORMAT = "agentsec-capability-calibration-report"
CALIBRATION_REPORT_SCHEMA_FILENAME = "calibration-report.schema.json"
NonNegativeInt = Annotated[int, Field(ge=0)]
Rate = Annotated[float, Field(ge=0, le=1)]


class CalibrationClassification(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"


class CalibrationObservation(CalibrationModel):
    """Observed result from one safe deterministic Case evaluator."""

    outcome: CalibrationRuleOutcome
    correlations: tuple[CapabilityCorrelation, ...] = ()
    confidences: tuple[EvidenceConfidence, ...] = ()
    finding_count: NonNegativeInt = 0
    evidence_items: NonNegativeInt = 0
    evidence_complete: bool
    coverage_visible: bool
    unknowns_visible: bool
    unknown_applicable: bool = False
    duplicate_findings: NonNegativeInt = 0
    failure: bool = False

    @model_validator(mode="after")
    def observation_must_be_coherent(self) -> CalibrationObservation:
        if self.correlations != tuple(
            sorted(set(self.correlations), key=lambda item: item.value)
        ):
            raise ValueError("observed correlations must be sorted and unique")
        if self.confidences != tuple(
            sorted(set(self.confidences), key=lambda item: item.value)
        ):
            raise ValueError("observed confidences must be sorted and unique")
        if self.outcome is CalibrationRuleOutcome.MATCH:
            if self.finding_count < 1 or not self.correlations or not self.confidences:
                raise ValueError("observed match requires Finding and evidence grades")
        elif self.finding_count or self.correlations or self.confidences:
            raise ValueError("observed no-match cannot contain Finding metadata")
        return self


class CalibrationCaseEvaluation(CalibrationModel):
    case_id: NonEmptyText
    rule_id: NonEmptyText
    expected_outcome: CalibrationRuleOutcome
    observed_outcome: CalibrationRuleOutcome
    classification: CalibrationClassification
    expected_correlations: tuple[CapabilityCorrelation, ...] = ()
    observed_correlations: tuple[CapabilityCorrelation, ...] = ()
    expected_confidences: tuple[EvidenceConfidence, ...] = ()
    observed_confidences: tuple[EvidenceConfidence, ...] = ()
    observed_findings: NonNegativeInt
    correlation_agreement: bool | None
    confidence_agreement: bool | None
    evidence_complete: bool
    coverage_visible: bool
    unknowns_visible: bool
    unknown_applicable: bool = False
    duplicate_findings: NonNegativeInt
    failure: bool

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.case_id)


class CalibrationConfusionMatrix(CalibrationModel):
    true_positive: NonNegativeInt
    false_positive: NonNegativeInt
    false_negative: NonNegativeInt
    true_negative: NonNegativeInt

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.false_negative
            + self.true_negative
        )


class CalibrationRuleMetrics(CalibrationModel):
    rule_id: NonEmptyText
    samples: NonNegativeInt
    positive_samples: NonNegativeInt
    negative_samples: NonNegativeInt
    confusion: CalibrationConfusionMatrix
    precision: Rate | None
    recall: Rate | None
    false_positive_rate: Rate | None
    f1: Rate | None
    correlation_agreement: Rate | None
    confidence_agreement: Rate | None
    evidence_completeness: Rate | None
    coverage_visibility: Rate
    unknown_visibility: Rate | None
    duplicate_findings: NonNegativeInt
    failures: NonNegativeInt
    sufficient_sample_size: bool


class CalibrationAggregateMetrics(CalibrationModel):
    confusion: CalibrationConfusionMatrix
    precision: Rate | None
    recall: Rate | None
    false_positive_rate: Rate | None
    f1: Rate | None


class CalibrationReportSummary(CalibrationModel):
    total_cases: NonNegativeInt
    total_expectations: NonNegativeInt
    evaluated_rules: NonNegativeInt
    failures: NonNegativeInt
    duplicate_findings: NonNegativeInt
    insufficient_sample_rules: NonNegativeInt
    coverage_visibility: Rate
    unknown_visibility: Rate | None
    evidence_completeness: Rate | None
    correlation_agreement: Rate | None
    confidence_agreement: Rate | None
    micro: CalibrationAggregateMetrics
    macro_precision: Rate | None
    macro_recall: Rate | None
    macro_f1: Rate | None


class CalibrationReportPolicy(CalibrationModel):
    enforcement_mode: Literal["report_only"] = "report_only"
    ci_blocking_enabled: Literal[False] = False
    runtime_capability_verified: Literal[False] = False
    hard_gate_eligibility_decided: Literal[False] = False


class CalibrationReport(CalibrationModel):
    """Versioned deterministic P2-CAL-02 report."""

    format: Literal["agentsec-capability-calibration-report"] = (
        "agentsec-capability-calibration-report"
    )
    format_version: InterfaceVersionString = CALIBRATION_REPORT_OUTPUT_VERSION
    status: Literal["complete", "incomplete"]
    corpus_id: StableId
    labels_version: InterfaceVersionString
    evaluator_id: StableId
    evaluator_version: InterfaceVersionString
    capability_rule_pack_version: InterfaceVersionString = CAPABILITY_RULE_PACK_VERSION
    capability_risk_model_version: InterfaceVersionString = (
        CAPABILITY_RISK_MODEL_VERSION
    )
    policy: CalibrationReportPolicy
    summary: CalibrationReportSummary
    rules: tuple[CalibrationRuleMetrics, ...]
    cases: tuple[CalibrationCaseEvaluation, ...]
    limitations: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def report_must_be_ordered_and_consistent(self) -> CalibrationReport:
        rule_ids = tuple(item.rule_id for item in self.rules)
        if rule_ids != tuple(sorted(set(rule_ids))):
            raise ValueError("calibration Rule metrics must be sorted and unique")
        case_keys = tuple(item.sort_key() for item in self.cases)
        if case_keys != tuple(sorted(set(case_keys))):
            raise ValueError("calibration Case evaluations must be sorted and unique")
        if self.summary.evaluated_rules != len(self.rules):
            raise ValueError("calibration evaluated Rule count is inconsistent")
        if self.summary.total_expectations != len(self.cases):
            raise ValueError("calibration expectation count is inconsistent")
        if self.status == "complete" and self.summary.failures:
            raise ValueError("complete calibration report cannot contain failures")
        return self

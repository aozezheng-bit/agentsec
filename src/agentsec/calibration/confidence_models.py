"""P2-CAL-03 reviewer Confidence label contracts and metrics."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from agentsec.capability_rules import CapabilityCorrelation
from agentsec.domain import EvidenceConfidence
from agentsec.manifests.models import InterfaceVersionString
from agentsec.versioning import (
    CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION,
    CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION,
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
)

from .models import CalibrationModel, NonEmptyText, StableId

CONFIDENCE_REVIEW_FORMAT = "agentsec-capability-confidence-review-set"
CONFIDENCE_REPORT_FORMAT = "agentsec-capability-confidence-calibration-report"
CONFIDENCE_REVIEW_SCHEMA_FILENAME = "confidence-review-set.schema.json"
CONFIDENCE_REPORT_SCHEMA_FILENAME = "confidence-calibration-report.schema.json"
Rate = Annotated[float, Field(ge=-1, le=1)]
UnitRate = Annotated[float, Field(ge=0, le=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class ConfidenceReviewStatus(StrEnum):
    SEEDED = "seeded"
    REVIEWED = "reviewed"
    ADJUDICATED = "adjudicated"


class ConfidenceReviewLabel(CalibrationModel):
    """One reviewer label for one expected deterministic Finding."""

    review_id: StableId
    case_id: StableId
    rule_id: StableId
    reviewer_id: StableId
    confidence: EvidenceConfidence
    correlation: CapabilityCorrelation
    status: ConfidenceReviewStatus
    rationale_code: StableId

    @model_validator(mode="after")
    def review_id_must_be_stable(self) -> ConfidenceReviewLabel:
        if self.review_id != f"review:{self.reviewer_id}:{self.case_id}:{self.rule_id}":
            raise ValueError("review_id must be derived from reviewer, Case, and Rule")
        return self


class ConfidenceReviewSet(CalibrationModel):
    """Versioned, deterministic reviewer-label collection."""

    format: Literal["agentsec-capability-confidence-review-set"] = (
        "agentsec-capability-confidence-review-set"
    )
    schema_version: InterfaceVersionString = (
        CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION
    )
    corpus_id: StableId
    labels_version: InterfaceVersionString
    reviewer_ids: tuple[StableId, ...]
    reviews: tuple[ConfidenceReviewLabel, ...]

    @model_validator(mode="after")
    def review_set_must_be_sorted_and_have_two_reviewers(
        self,
    ) -> ConfidenceReviewSet:
        if len(self.reviewer_ids) < 2:
            raise ValueError("Confidence review set requires at least two reviewers")
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("reviewer_ids must be sorted and unique")
        keys = tuple(
            (item.case_id, item.rule_id, item.reviewer_id) for item in self.reviews
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Confidence reviews must be sorted and unique")
        if any(item.reviewer_id not in self.reviewer_ids for item in self.reviews):
            raise ValueError("review contains an undeclared reviewer")
        return self


class ConfidenceGradeMatrixRow(CalibrationModel):
    expected: EvidenceConfidence
    observed_a: NonNegativeInt
    observed_b: NonNegativeInt
    observed_c: NonNegativeInt
    observed_d: NonNegativeInt


class ConfidenceAgreementMetrics(CalibrationModel):
    """Agreement metrics for one categorical comparison population."""

    items: NonNegativeInt
    agreement_count: NonNegativeInt
    agreement_rate: UnitRate | None
    cohens_kappa: Rate | None
    grade_matrix: tuple[ConfidenceGradeMatrixRow, ...]


class ConfidenceRuleMetrics(CalibrationModel):
    rule_id: NonEmptyText
    correlation: CapabilityCorrelation
    items: NonNegativeInt
    reviewer_agreement_rate: UnitRate | None
    cohens_kappa: Rate | None
    expected_vs_emitted_rate: UnitRate | None


class ConfidenceCaseEvaluation(CalibrationModel):
    case_id: StableId
    rule_id: StableId
    correlation: CapabilityCorrelation
    expected_confidence: EvidenceConfidence
    emitted_confidence: EvidenceConfidence
    reviewer_labels: tuple[ConfidenceReviewLabel, ...]
    reviewer_agreement: bool
    expected_vs_emitted: bool

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.case_id)


class ConfidenceReviewerPairMetrics(CalibrationModel):
    reviewer_a: StableId
    reviewer_b: StableId
    items: NonNegativeInt
    agreement_rate: UnitRate | None
    cohens_kappa: Rate | None


class ConfidenceCalibrationSummary(CalibrationModel):
    total_cases: NonNegativeInt
    total_reviews: NonNegativeInt
    reviewer_count: NonNegativeInt
    reviewer_agreement: ConfidenceAgreementMetrics
    expected_vs_emitted: ConfidenceAgreementMetrics
    insufficient_sample_items: NonNegativeInt


class ConfidenceCalibrationPolicy(CalibrationModel):
    enforcement_mode: Literal["report_only"] = "report_only"
    ci_blocking_enabled: Literal[False] = False
    hard_gate_eligibility_decided: Literal[False] = False


class ConfidenceCalibrationReport(CalibrationModel):
    """Versioned P2-CAL-03 report-only Confidence calibration output."""

    format: Literal["agentsec-capability-confidence-calibration-report"] = (
        "agentsec-capability-confidence-calibration-report"
    )
    format_version: InterfaceVersionString = (
        CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION
    )
    status: Literal["complete", "incomplete"]
    corpus_id: StableId
    labels_version: InterfaceVersionString
    reviewer_ids: tuple[StableId, ...]
    capability_rule_pack_version: InterfaceVersionString = CAPABILITY_RULE_PACK_VERSION
    capability_risk_model_version: InterfaceVersionString = (
        CAPABILITY_RISK_MODEL_VERSION
    )
    policy: ConfidenceCalibrationPolicy
    summary: ConfidenceCalibrationSummary
    pairwise: tuple[ConfidenceReviewerPairMetrics, ...]
    by_rule: tuple[ConfidenceRuleMetrics, ...]
    by_case: tuple[ConfidenceCaseEvaluation, ...]
    limitations: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def report_must_be_ordered(self) -> ConfidenceCalibrationReport:
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("report reviewer_ids must be sorted and unique")
        rule_keys = tuple((item.rule_id, item.correlation) for item in self.by_rule)
        if rule_keys != tuple(
            sorted(set(rule_keys), key=lambda item: (item[0], item[1].value))
        ):
            raise ValueError("Confidence Rule metrics must be sorted and unique")
        keys = tuple(item.sort_key() for item in self.by_case)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Confidence Case evaluations must be sorted and unique")
        if self.summary.reviewer_count != len(self.reviewer_ids):
            raise ValueError("Confidence reviewer count is inconsistent")
        pair_keys = tuple((item.reviewer_a, item.reviewer_b) for item in self.pairwise)
        if pair_keys != tuple(sorted(set(pair_keys))):
            raise ValueError("Confidence reviewer pairs must be sorted and unique")
        if self.status == "complete" and not self.by_case:
            raise ValueError("complete Confidence report requires evaluations")
        return self

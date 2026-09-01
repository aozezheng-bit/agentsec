"""P2-CAL-04 independent adjudication and Gate Candidate contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from agentsec.domain import EvidenceConfidence, Severity
from agentsec.manifests.models import InterfaceVersionString
from agentsec.versioning import (
    CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION,
    CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION,
    CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION,
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
)

from .evaluation import CalibrationClassification
from .models import CalibrationModel, NonEmptyText, StableId

ADJUDICATION_REVIEW_FORMAT = "agentsec-capability-calibration-adjudication-set"
ADJUDICATION_RESOLUTION_FORMAT = (
    "agentsec-capability-calibration-adjudication-resolution-set"
)
ADJUDICATION_REPORT_FORMAT = "agentsec-capability-calibration-adjudication-report"
ADJUDICATION_REVIEW_SCHEMA_FILENAME = "calibration-adjudication-set.schema.json"
ADJUDICATION_RESOLUTION_SCHEMA_FILENAME = (
    "calibration-adjudication-resolution-set.schema.json"
)
ADJUDICATION_REPORT_SCHEMA_FILENAME = "calibration-adjudication-report.schema.json"
Rate = Annotated[float, Field(ge=0, le=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class AdjudicationStatus(StrEnum):
    SEEDED = "seeded"
    REVIEWED = "reviewed"
    ADJUDICATED = "adjudicated"


class AdjudicationCategory(StrEnum):
    """Reviewer interpretation of a deterministic classification."""

    CONFIRMED_TRUE_POSITIVE = "confirmed_true_positive"
    CONFIRMED_TRUE_NEGATIVE = "confirmed_true_negative"
    DETECTION_FALSE_POSITIVE = "detection_false_positive"
    POLICY_ACCEPTED_RISK = "policy_accepted_risk"
    IN_SCOPE_FALSE_NEGATIVE = "in_scope_false_negative"
    OUT_OF_SCOPE = "out_of_scope"
    RUNTIME_UNCERTAINTY = "runtime_uncertainty"
    UNRESOLVED = "unresolved"


class RuleDisposition(StrEnum):
    """Deterministic recommendation, never an automatic Rule mutation."""

    KEEP = "keep"
    TUNE = "tune"
    SHADOW = "shadow"
    RETIRE = "retire"
    MORE_DATA = "more_data"


class GateCandidateStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MORE_DATA_REQUIRED = "more_data_required"


class AdjudicationReviewLabel(CalibrationModel):
    """One independent review of a Case/Rule calibration outcome."""

    adjudication_id: StableId
    case_id: StableId
    rule_id: StableId
    reviewer_id: StableId
    classification: CalibrationClassification
    category: AdjudicationCategory
    disposition: RuleDisposition
    status: AdjudicationStatus
    rationale_code: StableId

    @model_validator(mode="after")
    def adjudication_id_must_be_stable(self) -> AdjudicationReviewLabel:
        expected = f"adjudication:{self.reviewer_id}:{self.case_id}:{self.rule_id}"
        if self.adjudication_id != expected:
            raise ValueError(
                "adjudication_id must be derived from reviewer, Case, and Rule"
            )
        return self


class AdjudicationReviewSet(CalibrationModel):
    """Bounded reviewer labels for every labeled Case/Rule expectation."""

    format: Literal["agentsec-capability-calibration-adjudication-set"] = (
        "agentsec-capability-calibration-adjudication-set"
    )
    schema_version: InterfaceVersionString = (
        CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION
    )
    corpus_id: StableId
    labels_version: InterfaceVersionString
    reviewer_ids: tuple[StableId, ...]
    reviews: tuple[AdjudicationReviewLabel, ...]

    @model_validator(mode="after")
    def review_set_must_be_sorted_and_complete(
        self,
    ) -> AdjudicationReviewSet:
        if len(self.reviewer_ids) < 2:
            raise ValueError("adjudication review set requires at least two reviewers")
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("adjudication reviewer_ids must be sorted and unique")
        keys = tuple(
            (item.case_id, item.rule_id, item.reviewer_id) for item in self.reviews
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("adjudication reviews must be sorted and unique")
        if any(item.reviewer_id not in self.reviewer_ids for item in self.reviews):
            raise ValueError("adjudication review contains an undeclared reviewer")
        return self


class AdjudicationResolution(CalibrationModel):
    """One final human resolution that never replaces independent labels."""

    resolution_id: StableId
    case_id: StableId
    rule_id: StableId
    reviewer_ids: tuple[StableId, ...]
    final_classification: CalibrationClassification
    final_category: AdjudicationCategory
    final_disposition: RuleDisposition
    status: Literal["adjudicated"] = "adjudicated"
    rationale_code: StableId

    @model_validator(mode="after")
    def resolution_must_be_stable(self) -> AdjudicationResolution:
        expected = f"resolution:{self.case_id}:{self.rule_id}"
        if self.resolution_id != expected:
            raise ValueError("resolution_id must be derived from Case and Rule")
        if len(self.reviewer_ids) < 2 or self.reviewer_ids != tuple(
            sorted(set(self.reviewer_ids))
        ):
            raise ValueError("resolution reviewer_ids must be sorted and unique")
        if self.final_category is AdjudicationCategory.UNRESOLVED:
            raise ValueError("completed resolution cannot remain unresolved")
        return self


class AdjudicationResolutionSet(CalibrationModel):
    """Optional final resolutions kept separate from independent Reviewer labels."""

    format: Literal["agentsec-capability-calibration-adjudication-resolution-set"] = (
        "agentsec-capability-calibration-adjudication-resolution-set"
    )
    schema_version: InterfaceVersionString = (
        CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION
    )
    corpus_id: StableId
    labels_version: InterfaceVersionString
    reviewer_ids: tuple[StableId, ...]
    resolutions: tuple[AdjudicationResolution, ...] = ()

    @model_validator(mode="after")
    def resolution_set_must_be_ordered(self) -> AdjudicationResolutionSet:
        if len(self.reviewer_ids) < 2 or self.reviewer_ids != tuple(
            sorted(set(self.reviewer_ids))
        ):
            raise ValueError("resolution reviewer_ids must be sorted and unique")
        keys = tuple((item.case_id, item.rule_id) for item in self.resolutions)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("adjudication resolutions must be sorted and unique")
        if any(item.reviewer_ids != self.reviewer_ids for item in self.resolutions):
            raise ValueError("resolution reviewer_ids must match the resolution set")
        return self


class AdjudicationConsensus(CalibrationModel):
    """Deterministic consensus derived from independent reviewer labels."""

    case_id: StableId
    rule_id: StableId
    deterministic_classification: CalibrationClassification
    reviewer_count: NonNegativeInt
    classification_agreement: bool
    category_agreement: bool
    disposition_agreement: bool
    adjudication_required: bool
    adjudication_completed: bool
    final_classification: CalibrationClassification | None
    final_category: AdjudicationCategory
    final_disposition: RuleDisposition

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.case_id)


class AdjudicationSummary(CalibrationModel):
    total_expectations: NonNegativeInt
    total_reviews: NonNegativeInt
    reviewer_count: NonNegativeInt
    consensus_count: NonNegativeInt
    unresolved_count: NonNegativeInt
    adjudication_required_count: NonNegativeInt
    adjudication_completed_count: NonNegativeInt
    classification_agreement_rate: Rate | None
    category_agreement_rate: Rate | None
    disposition_agreement_rate: Rate | None


class RuleCalibrationAssessment(CalibrationModel):
    """FP/FN, adjudication, and deterministic Rule tuning summary."""

    rule_id: NonEmptyText
    samples: NonNegativeInt
    positive_samples: NonNegativeInt
    negative_samples: NonNegativeInt
    true_positive: NonNegativeInt
    false_positive: NonNegativeInt
    false_negative: NonNegativeInt
    true_negative: NonNegativeInt
    precision: Rate | None
    recall: Rate | None
    f1: Rate | None
    detection_false_positives: NonNegativeInt
    policy_accepted_risks: NonNegativeInt
    in_scope_false_negatives: NonNegativeInt
    out_of_scope_cases: NonNegativeInt
    runtime_uncertainty_cases: NonNegativeInt
    unresolved_cases: NonNegativeInt
    reviewer_agreement_rate: Rate | None
    category_agreement_rate: Rate | None
    disposition_agreement_rate: Rate | None
    confidence_kappa: float | None = Field(default=None, ge=-1, le=1)
    recommended_disposition: RuleDisposition
    reason_codes: tuple[StableId, ...]

    @model_validator(mode="after")
    def metrics_must_be_coherent(self) -> RuleCalibrationAssessment:
        if self.samples != self.positive_samples + self.negative_samples:
            raise ValueError("Rule sample count is inconsistent")
        if self.samples != (
            self.true_positive
            + self.false_positive
            + self.false_negative
            + self.true_negative
        ):
            raise ValueError("Rule confusion count is inconsistent")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("Rule reason codes must be sorted and unique")
        return self


class GateCandidateAssessment(CalibrationModel):
    """Report-only Hard Gate candidate qualification result."""

    gate_id: StableId
    title: NonEmptyText
    floor: Severity
    rule_ids: tuple[StableId, ...]
    positive_samples: NonNegativeInt
    negative_samples: NonNegativeInt
    precision: Rate | None
    recall: Rate | None
    confidence_kappa: float | None = Field(default=None, ge=-1, le=1)
    confidence_grades: tuple[EvidenceConfidence, ...]
    coverage_complete: bool
    unknown_free: bool
    reviewer_consensus: bool
    status: GateCandidateStatus
    reason_codes: tuple[StableId, ...]

    @model_validator(mode="after")
    def candidate_must_be_ordered(self) -> GateCandidateAssessment:
        if self.rule_ids != tuple(sorted(set(self.rule_ids))):
            raise ValueError("Gate candidate Rule IDs must be sorted and unique")
        if self.confidence_grades != tuple(
            sorted(set(self.confidence_grades), key=lambda item: item.value)
        ):
            raise ValueError("Gate candidate Confidence grades must be sorted")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("Gate candidate reason codes must be sorted and unique")
        return self


class AdjudicationReportPolicy(CalibrationModel):
    evidence_mode: Literal["seed", "human"] = "seed"
    enforcement_mode: Literal["report_only"] = "report_only"
    ci_blocking_enabled: Literal[False] = False
    hard_gate_eligibility_decided: Literal[False] = False
    automatic_rule_publication: Literal[False] = False


class CalibrationAdjudicationReport(CalibrationModel):
    """P2-CAL-04 report-only adjudication and Gate Candidate output."""

    format: Literal["agentsec-capability-calibration-adjudication-report"] = (
        "agentsec-capability-calibration-adjudication-report"
    )
    format_version: InterfaceVersionString = (
        CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION
    )
    status: Literal["complete", "incomplete"]
    corpus_id: StableId
    labels_version: InterfaceVersionString
    reviewer_ids: tuple[StableId, ...]
    capability_rule_pack_version: InterfaceVersionString = CAPABILITY_RULE_PACK_VERSION
    capability_risk_model_version: InterfaceVersionString = (
        CAPABILITY_RISK_MODEL_VERSION
    )
    policy: AdjudicationReportPolicy
    summary: AdjudicationSummary
    by_rule: tuple[RuleCalibrationAssessment, ...]
    gate_candidates: tuple[GateCandidateAssessment, ...]
    by_case: tuple[AdjudicationConsensus, ...]
    limitations: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def report_must_be_ordered(self) -> CalibrationAdjudicationReport:
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("adjudication report reviewer_ids must be sorted")
        rule_ids = tuple(item.rule_id for item in self.by_rule)
        if rule_ids != tuple(sorted(set(rule_ids))):
            raise ValueError("Rule assessments must be sorted and unique")
        gate_ids = tuple(item.gate_id for item in self.gate_candidates)
        if gate_ids != tuple(sorted(set(gate_ids))):
            raise ValueError("Gate candidates must be sorted and unique")
        case_keys = tuple(item.sort_key() for item in self.by_case)
        if case_keys != tuple(sorted(set(case_keys))):
            raise ValueError("adjudication Cases must be sorted and unique")
        if self.summary.reviewer_count != len(self.reviewer_ids):
            raise ValueError("adjudication reviewer count is inconsistent")
        if self.summary.total_expectations != len(self.by_case):
            raise ValueError("adjudication expectation count is inconsistent")
        if self.status == "complete" and not self.by_case:
            raise ValueError("complete adjudication report requires Cases")
        return self

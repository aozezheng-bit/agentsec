"""P3-05 Provider quality review and controlled Shadow promotion."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.evaluation import SemanticEvaluationReport

SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION = "0.1.0"
SEMANTIC_PROMOTION_SCHEMA_VERSION = "0.1.0"
SEMANTIC_PROMOTION_REPORT_VERSION = "0.1.0"
SEMANTIC_PROMOTION_FORMAT = "agentsec-semantic-provider-promotion-report"
SEMANTIC_HUMAN_REVIEW_FORMAT = "agentsec-semantic-human-review-submission"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ProviderReviewDisposition(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    UNCERTAIN = "uncertain"


class ProviderReviewDecision(_Strict):
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    semantic_disposition: ProviderReviewDisposition
    evidence_binding_acceptable: bool
    reviewer_confidence: Literal["high", "medium", "low"]
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,63}$")]


class SemanticHumanReviewSubmission(_Strict):
    format: Literal["agentsec-semantic-human-review-submission"] = (
        "agentsec-semantic-human-review-submission"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    evaluation_report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independent: Literal[True] = True
    decisions: tuple[ProviderReviewDecision, ...]

    @model_validator(mode="after")
    def decisions_sorted_unique(self) -> SemanticHumanReviewSubmission:
        ids = tuple(item.case_id for item in self.decisions)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("human review cases must be sorted and unique")
        return self


class ProviderAdjudication(_Strict):
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    final_disposition: ProviderReviewDisposition
    evidence_binding_acceptable: bool
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,63}$")]


class ProviderQualityThresholds(_Strict):
    min_case_count: Annotated[int, Field(ge=1)] = 20
    min_precision: float = 0.95
    min_recall: float = 0.95
    min_f1: float = 0.95
    min_evidence_binding_accuracy: float = 0.98
    min_complete_coverage_rate: float = 1.0

    @model_validator(mode="after")
    def values_in_range(self) -> ProviderQualityThresholds:
        for value in (
            self.min_precision,
            self.min_recall,
            self.min_f1,
            self.min_evidence_binding_accuracy,
            self.min_complete_coverage_rate,
        ):
            if not 0 <= value <= 1:
                raise ValueError("promotion thresholds must be between zero and one")
        return self


class ProviderPromotionState(StrEnum):
    TRIAL = "trial"
    REVIEW_PENDING = "review_pending"
    ADJUDICATION_PENDING = "adjudication_pending"
    ELIGIBLE_SHADOW = "eligible_shadow"
    APPROVED_SHADOW = "approved_shadow"
    REJECTED = "rejected"
    REVOKED = "revoked"


class ProviderPromotionReport(_Strict):
    format: Literal["agentsec-semantic-provider-promotion-report"] = (
        "agentsec-semantic-provider-promotion-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    evaluation_report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    state: ProviderPromotionState
    quality_passed: bool
    human_review_passed: bool
    adjudication_required: bool
    blocking_reasons: tuple[str, ...]
    thresholds: ProviderQualityThresholds
    report_only: Literal[True] = True
    shadow_only: Literal[True] = True
    production_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    runtime_authority: Literal[False] = False


class ProviderPromotionController:
    """Qualify and explicitly promote a Provider for Shadow use only."""

    def assess(
        self,
        report: SemanticEvaluationReport,
        reviewer_a: SemanticHumanReviewSubmission | None = None,
        reviewer_b: SemanticHumanReviewSubmission | None = None,
        adjudications: tuple[ProviderAdjudication, ...] = (),
        thresholds: ProviderQualityThresholds | None = None,
    ) -> ProviderPromotionReport:
        if not isinstance(report, SemanticEvaluationReport):
            raise TypeError("promotion requires SemanticEvaluationReport")
        thresholds = thresholds or ProviderQualityThresholds()
        report_hash = _report_sha256(report)
        reasons: list[str] = []
        metrics = report.metrics
        quality = (
            metrics.case_count >= thresholds.min_case_count
            and metrics.precision >= thresholds.min_precision
            and metrics.recall >= thresholds.min_recall
            and metrics.f1 >= thresholds.min_f1
            and metrics.evidence_binding_accuracy
            >= thresholds.min_evidence_binding_accuracy
            and metrics.complete_coverage_rate >= thresholds.min_complete_coverage_rate
        )
        if not quality:
            reasons.append("quality_threshold_not_met")
        if reviewer_a is None or reviewer_b is None:
            reasons.append("independent_human_review_missing")
            return self._report(
                report,
                report_hash,
                ProviderPromotionState.REVIEW_PENDING,
                quality,
                False,
                False,
                reasons,
                thresholds,
            )
        if reviewer_a.reviewer_id == reviewer_b.reviewer_id:
            reasons.append("reviewers_not_independent")
        if (
            reviewer_a.evaluation_report_sha256 != report_hash
            or reviewer_b.evaluation_report_sha256 != report_hash
        ):
            reasons.append("review_report_binding_mismatch")
        if (
            reviewer_a.provider_id != report.provider_id
            or reviewer_b.provider_id != report.provider_id
            or reviewer_a.model_id != report.model_id
            or reviewer_b.model_id != report.model_id
        ):
            reasons.append("provider_binding_mismatch")
        a = {d.case_id: d for d in reviewer_a.decisions}
        b = {d.case_id: d for d in reviewer_b.decisions}
        case_ids = {c.case_id for c in report.cases}
        if set(a) != case_ids or set(b) != case_ids:
            reasons.append("review_coverage_incomplete")
        disagreements = [
            case_id
            for case_id in case_ids
            if case_id in a
            and case_id in b
            and (
                a[case_id].semantic_disposition != b[case_id].semantic_disposition
                or a[case_id].evidence_binding_acceptable
                != b[case_id].evidence_binding_acceptable
            )
        ]
        if disagreements and not adjudications:
            reasons.append("reviewer_disagreement_requires_adjudication")
            return self._report(
                report,
                report_hash,
                ProviderPromotionState.ADJUDICATION_PENDING,
                quality,
                False,
                True,
                reasons,
                thresholds,
            )
        resolved = {item.case_id: item for item in adjudications}
        human_passed = not reasons
        if disagreements:
            if set(resolved) != set(disagreements):
                reasons.append("adjudication_coverage_incomplete")
            elif any(
                resolved[x].final_disposition is not ProviderReviewDisposition.ACCEPT
                or not resolved[x].evidence_binding_acceptable
                for x in disagreements
            ):
                reasons.append("adjudication_rejected_case")
        if any(
            d.semantic_disposition is not ProviderReviewDisposition.ACCEPT
            or not d.evidence_binding_acceptable
            for d in a.values()
        ) or any(
            d.semantic_disposition is not ProviderReviewDisposition.ACCEPT
            or not d.evidence_binding_acceptable
            for d in b.values()
        ):
            reasons.append("human_review_rejected_case")
        human_passed = not any(
            x in reasons
            for x in (
                "reviewers_not_independent",
                "review_report_binding_mismatch",
                "provider_binding_mismatch",
                "review_coverage_incomplete",
                "adjudication_coverage_incomplete",
                "adjudication_rejected_case",
                "human_review_rejected_case",
            )
        )
        state = (
            ProviderPromotionState.ELIGIBLE_SHADOW
            if quality and human_passed and not reasons
            else ProviderPromotionState.REJECTED
        )
        return self._report(
            report,
            report_hash,
            state,
            quality,
            human_passed,
            bool(disagreements),
            reasons,
            thresholds,
        )

    def approve_shadow(
        self, report: ProviderPromotionReport, *, owner_id: str, approval_id: str
    ) -> ProviderPromotionReport:
        if not owner_id or not approval_id:
            raise ValueError("explicit owner and approval ID are required")
        if report.state is not ProviderPromotionState.ELIGIBLE_SHADOW:
            raise ValueError("only an eligible Shadow Provider can be approved")
        return report.model_copy(
            update={"state": ProviderPromotionState.APPROVED_SHADOW}
        )

    @staticmethod
    def _report(
        report: SemanticEvaluationReport,
        digest: str,
        state: ProviderPromotionState,
        quality: bool,
        human: bool,
        required: bool,
        reasons: list[str],
        thresholds: ProviderQualityThresholds,
    ) -> ProviderPromotionReport:
        return ProviderPromotionReport(
            provider_id=report.provider_id,
            model_id=report.model_id,
            evaluation_report_sha256=digest,
            state=state,
            quality_passed=quality,
            human_review_passed=human,
            adjudication_required=required,
            blocking_reasons=tuple(sorted(set(reasons))),
            thresholds=thresholds,
        )


def _report_sha256(report: SemanticEvaluationReport) -> str:
    return hashlib.sha256(
        json.dumps(
            report.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


__all__ = [
    "ProviderAdjudication",
    "ProviderPromotionController",
    "ProviderPromotionReport",
    "ProviderPromotionState",
    "ProviderQualityThresholds",
    "ProviderReviewDecision",
    "ProviderReviewDisposition",
    "SEMANTIC_HUMAN_REVIEW_FORMAT",
    "SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION",
    "SEMANTIC_PROMOTION_FORMAT",
    "SEMANTIC_PROMOTION_REPORT_VERSION",
    "SEMANTIC_PROMOTION_SCHEMA_VERSION",
    "SemanticHumanReviewSubmission",
]

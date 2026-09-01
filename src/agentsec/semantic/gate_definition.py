"""P3-18 semantic Gate definitions and report-only qualification.

A semantic Gate is a reviewed, versioned description of which semantic
signals may be presented together and what evidence is required to call the
Gate qualified. Qualification is deterministic and report-only: it never
creates a Finding, publishes a Rule, blocks CI, approves a waiver, or grants
runtime authority.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.gate_corpus import SemanticGateHumanCorpus
from agentsec.semantic.p3_07 import (
    SemanticCandidateCalibrationReport,
    SemanticFindingPromotionReport,
)
from agentsec.semantic.promotion import (
    ProviderPromotionReport,
    ProviderPromotionState,
)
from agentsec.semantic.quality_gate import QualityGateReport, QualityGateStatus
from agentsec.semantic.rule_promotion import (
    RulePromotionStatus,
    SemanticRulePromotionReport,
)
from agentsec.versioning import (
    SEMANTIC_GATE_DEFINITION_VERSION,
    SEMANTIC_GATE_QUALIFICATION_VERSION,
)

SEMANTIC_GATE_CANDIDATE_FORMAT = "agentsec-semantic-gate-candidate"
SEMANTIC_GATE_QUALIFICATION_FORMAT = "agentsec-semantic-gate-qualification-report"

_GATE_ID_PATTERN = r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_TEXT_PATTERN = r"^[^\x00-\x1f\x7f]{1,512}$"
_CANDIDATE_ID_PATTERN = r"^semantic-gate-candidate-sha256:[0-9a-f]{64}$"
_QUALIFICATION_ID_PATTERN = r"^semantic-gate-qualification-sha256:[0-9a-f]{64}$"


class SemanticGateError(RuntimeError):
    """Safe Gate qualification failure without echoing corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic Gate failed ({code}).")


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticGateInput(StrEnum):
    """Evidence families that a Gate may require."""

    PROVIDER_QUALITY = "provider_quality"
    PROVIDER_PROMOTION = "provider_promotion"
    CANDIDATE_CALIBRATION = "candidate_calibration"
    FINDING_PROMOTION = "finding_promotion"
    RULE_STAGING = "rule_staging"
    HUMAN_CONFIDENCE = "human_confidence"
    HUMAN_CORPUS = "human_corpus"


class EvidenceConfidenceGrade(StrEnum):
    """Human evidence-strength grade; A is reserved for runtime proof."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"

    @property
    def rank(self) -> int:
        return {"A": 0, "B": 1, "C": 2, "D": 3}[self.value]


class SemanticGateCandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    SUPERSEDED = "superseded"


class SemanticGateQualificationStatus(StrEnum):
    QUALIFIED = "qualified"
    CONDITIONALLY_QUALIFIED = "conditionally_qualified"
    NOT_QUALIFIED = "not_qualified"


class GateQualificationCheckStatus(StrEnum):
    PASS = "pass"
    PENDING = "pending"
    FAIL = "fail"


class SemanticGateThresholds(_Strict):
    """Minimum evidence quality and sample thresholds for one Gate."""

    min_case_count: Annotated[int, Field(ge=1)] = 40
    min_positive_case_count: Annotated[int, Field(ge=1)] = 20
    min_eligible_negative_case_count: Annotated[int, Field(ge=1)] = 20
    min_precision: float = 0.95
    min_recall: float = 0.95
    min_f1: float = 0.95
    min_evidence_binding_accuracy: float = 0.98
    min_complete_coverage_rate: float = 1.0
    max_unevaluated_case_count: Annotated[int, Field(ge=0)] = 0
    min_human_reviewer_count: Annotated[int, Field(ge=1)] = 1

    @model_validator(mode="after")
    def values_must_be_bounded(self) -> SemanticGateThresholds:
        for value in (
            self.min_precision,
            self.min_recall,
            self.min_f1,
            self.min_evidence_binding_accuracy,
            self.min_complete_coverage_rate,
        ):
            if not 0 <= value <= 1:
                raise ValueError(
                    "semantic Gate thresholds must be between zero and one"
                )
        return self


class SemanticGateAuthority(_Strict):
    """Immutable authority boundary for Gate candidates and qualification."""

    report_only: Literal[True] = True
    blocks: Literal[False] = False
    can_block_ci: Literal[False] = False
    can_publish_rule: Literal[False] = False
    can_approve_waiver: Literal[False] = False
    can_grant_runtime_authority: Literal[False] = False


class SemanticGateCandidate(_Strict):
    """Versioned Gate candidate; qualification never promotes it automatically."""

    format: Literal["agentsec-semantic-gate-candidate"] = (
        "agentsec-semantic-gate-candidate"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    candidate_id: Annotated[str, Field(pattern=_CANDIDATE_ID_PATTERN)]
    gate_id: Annotated[str, Field(pattern=_GATE_ID_PATTERN)]
    title: Annotated[str, Field(pattern=_TEXT_PATTERN)]
    description: Annotated[str, Field(pattern=_TEXT_PATTERN)]
    signal: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]
    thresholds: SemanticGateThresholds = SemanticGateThresholds()
    required_inputs: tuple[SemanticGateInput, ...] = (
        SemanticGateInput.HUMAN_CONFIDENCE,
        SemanticGateInput.PROVIDER_PROMOTION,
        SemanticGateInput.PROVIDER_QUALITY,
    )
    minimum_evidence_confidence: EvidenceConfidenceGrade = EvidenceConfidenceGrade.C
    status: SemanticGateCandidateStatus = SemanticGateCandidateStatus.CANDIDATE
    authority: SemanticGateAuthority = SemanticGateAuthority()

    @model_validator(mode="after")
    def candidate_must_be_coherent(self) -> SemanticGateCandidate:
        if self.required_inputs != tuple(
            sorted(set(self.required_inputs), key=lambda item: item.value)
        ):
            raise ValueError("semantic Gate inputs must be sorted and unique")
        if SemanticGateInput.PROVIDER_QUALITY not in self.required_inputs:
            raise ValueError(
                "semantic Gate candidates require provider quality evidence"
            )
        if self.minimum_evidence_confidence is EvidenceConfidenceGrade.D:
            raise ValueError("semantic Gate minimum confidence cannot be D")
        expected = _candidate_digest(
            self.gate_id,
            self.title,
            self.description,
            self.signal,
            self.thresholds,
            self.required_inputs,
            self.minimum_evidence_confidence,
        )
        if self.candidate_id != expected:
            raise ValueError("semantic Gate candidate digest is inconsistent")
        return self


class SemanticGateEvidenceConfidence(_Strict):
    """Human-calibrated confidence summary, separate from severity/quality."""

    grade: EvidenceConfidenceGrade
    reviewer_count: Annotated[int, Field(ge=1)]
    reviewed_case_count: Annotated[int, Field(ge=1)]
    adjudication_complete: bool
    runtime_attestation_present: bool = False
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]

    @model_validator(mode="after")
    def grade_must_not_overclaim(self) -> SemanticGateEvidenceConfidence:
        if (
            self.grade is EvidenceConfidenceGrade.A
            and not self.runtime_attestation_present
        ):
            raise ValueError("confidence A requires runtime attestation evidence")
        if self.grade is EvidenceConfidenceGrade.D and self.adjudication_complete:
            raise ValueError("complete adjudication cannot be graded D")
        return self


class SemanticGateQualificationMetrics(_Strict):
    case_count: Annotated[int, Field(ge=0)]
    positive_case_count: Annotated[int, Field(ge=0)]
    eligible_negative_case_count: Annotated[int, Field(ge=0)]
    unevaluated_case_count: Annotated[int, Field(ge=0)]
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    evidence_binding_accuracy: float = Field(ge=0, le=1)
    complete_coverage_rate: float = Field(ge=0, le=1)
    evidence_confidence_grade: EvidenceConfidenceGrade | None = None

    @model_validator(mode="after")
    def counts_must_be_coherent(self) -> SemanticGateQualificationMetrics:
        if (
            self.positive_case_count + self.eligible_negative_case_count
            > self.case_count
        ):
            raise ValueError("Gate positive and negative counts exceed case count")
        return self


class SemanticGateQualificationCheck(_Strict):
    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]
    status: GateQualificationCheckStatus
    required: bool
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]


class SemanticGateQualificationReport(_Strict):
    """Deterministic report-only Gate qualification result."""

    format: Literal["agentsec-semantic-gate-qualification-report"] = (
        "agentsec-semantic-gate-qualification-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    qualification_id: Annotated[str, Field(pattern=_QUALIFICATION_ID_PATTERN)]
    candidate_id: Annotated[str, Field(pattern=_CANDIDATE_ID_PATTERN)]
    gate_id: Annotated[str, Field(pattern=_GATE_ID_PATTERN)]
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    status: SemanticGateQualificationStatus
    eligible_for_report_only_gate: bool
    metrics: SemanticGateQualificationMetrics
    checks: tuple[SemanticGateQualificationCheck, ...] = Field(min_length=1)
    failed_checks: tuple[str, ...] = ()
    pending_checks: tuple[str, ...] = ()
    reasons: tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")], ...] = ()
    evidence_confidence: SemanticGateEvidenceConfidence | None = None
    authority: SemanticGateAuthority = SemanticGateAuthority()

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticGateQualificationReport:
        ids = tuple(item.check_id for item in self.checks)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("Gate qualification checks must be sorted and unique")
        if self.failed_checks != tuple(sorted(set(self.failed_checks))):
            raise ValueError("Gate failed checks must be sorted and unique")
        if self.pending_checks != tuple(sorted(set(self.pending_checks))):
            raise ValueError("Gate pending checks must be sorted and unique")
        check_map = {item.check_id: item for item in self.checks}
        if self.failed_checks != tuple(
            sorted(
                item.check_id
                for item in self.checks
                if item.status is GateQualificationCheckStatus.FAIL
            )
        ):
            raise ValueError("Gate failed-check summary is inconsistent")
        if self.pending_checks != tuple(
            sorted(
                item.check_id
                for item in self.checks
                if item.status is GateQualificationCheckStatus.PENDING
            )
        ):
            raise ValueError("Gate pending-check summary is inconsistent")
        unknown_summaries = set(self.failed_checks + self.pending_checks) - set(
            check_map
        )
        if unknown_summaries:
            raise ValueError("Gate summary references an unknown check")
        if any(
            check_map[item].required is False
            for item in self.failed_checks + self.pending_checks
        ):
            raise ValueError("optional Gate checks cannot block qualification")
        expected_status = (
            SemanticGateQualificationStatus.NOT_QUALIFIED
            if self.failed_checks
            else SemanticGateQualificationStatus.CONDITIONALLY_QUALIFIED
            if self.pending_checks
            else SemanticGateQualificationStatus.QUALIFIED
        )
        if self.status is not expected_status:
            raise ValueError("Gate qualification status is inconsistent")
        if self.eligible_for_report_only_gate != (
            self.status is SemanticGateQualificationStatus.QUALIFIED
        ):
            raise ValueError("Gate eligibility is inconsistent")
        if self.status is SemanticGateQualificationStatus.QUALIFIED and self.reasons:
            raise ValueError("qualified Gate cannot carry blocking reasons")
        return self


class SemanticGateQualificationRunner:
    """Evaluate a Gate candidate against P3-05/P3-07/P3-10 evidence."""

    def qualify(
        self,
        candidate: SemanticGateCandidate,
        *,
        quality_report: QualityGateReport,
        provider_promotion: ProviderPromotionReport | None = None,
        candidate_calibration: SemanticCandidateCalibrationReport | None = None,
        finding_promotion: SemanticFindingPromotionReport | None = None,
        rule_staging: SemanticRulePromotionReport | None = None,
        evidence_confidence: SemanticGateEvidenceConfidence | None = None,
        human_corpus: SemanticGateHumanCorpus | None = None,
        positive_case_count: int | None = None,
        eligible_negative_case_count: int | None = None,
        unevaluated_case_count: int = 0,
    ) -> SemanticGateQualificationReport:
        if not isinstance(candidate, SemanticGateCandidate):
            raise TypeError("semantic Gate candidate is required")
        if not isinstance(quality_report, QualityGateReport):
            raise TypeError("semantic quality report is required")
        for value, expected, label in (
            (provider_promotion, ProviderPromotionReport, "provider promotion"),
            (
                candidate_calibration,
                SemanticCandidateCalibrationReport,
                "candidate calibration",
            ),
            (
                finding_promotion,
                SemanticFindingPromotionReport,
                "Finding promotion",
            ),
            (rule_staging, SemanticRulePromotionReport, "Rule staging"),
            (
                evidence_confidence,
                SemanticGateEvidenceConfidence,
                "evidence confidence",
            ),
            (human_corpus, SemanticGateHumanCorpus, "human corpus"),
        ):
            if value is not None and not isinstance(value, expected):
                raise TypeError(f"{label} evidence is invalid")
        if human_corpus is not None and human_corpus.gate_id != candidate.gate_id:
            raise ValueError("human corpus Gate ID does not match candidate")
        if human_corpus is not None and int(
            quality_report.metrics.get("case_count", 0)
        ) != len(human_corpus.cases):
            raise ValueError(
                "human corpus case count must match Provider quality case count"
            )
        if human_corpus is not None:
            corpus_coverage = human_corpus.coverage
            if positive_case_count is None:
                positive_case_count = corpus_coverage.positive_count
            if eligible_negative_case_count is None:
                eligible_negative_case_count = (
                    corpus_coverage.eligible_negative_count
                    + corpus_coverage.near_miss_count
                )
        if positive_case_count is None or eligible_negative_case_count is None:
            raise ValueError("Gate positive and eligible-negative counts are required")
        if human_corpus is not None and SemanticGateInput.HUMAN_CORPUS in set(
            candidate.required_inputs
        ):
            corpus_ok = (
                human_corpus.coverage.human_confirmed
                and human_corpus.coverage.unknown_count == 0
                and human_corpus.coverage.unresolved_count == 0
                and human_corpus.coverage.minimum_positive_met
                and human_corpus.coverage.minimum_eligible_negative_or_near_miss_met
            )
        else:
            corpus_ok = False
        counts = (
            positive_case_count,
            eligible_negative_case_count,
            unevaluated_case_count,
        )
        if any(not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("Gate case counts must be non-negative integers")

        thresholds = candidate.thresholds
        metrics = SemanticGateQualificationMetrics(
            case_count=int(quality_report.metrics.get("case_count", 0)),
            positive_case_count=positive_case_count,
            eligible_negative_case_count=eligible_negative_case_count,
            unevaluated_case_count=unevaluated_case_count,
            precision=float(quality_report.metrics.get("precision", 0.0)),
            recall=float(quality_report.metrics.get("recall", 0.0)),
            f1=float(quality_report.metrics.get("f1", 0.0)),
            evidence_binding_accuracy=float(
                quality_report.metrics.get("evidence_binding_accuracy", 0.0)
            ),
            complete_coverage_rate=float(
                quality_report.metrics.get("complete_coverage_rate", 0.0)
            ),
            evidence_confidence_grade=(
                evidence_confidence.grade if evidence_confidence is not None else None
            ),
        )
        checks: list[SemanticGateQualificationCheck] = []
        required_inputs = set(candidate.required_inputs)
        checks.extend(
            (
                _check(
                    "provider_quality",
                    GateQualificationCheckStatus.PASS
                    if (
                        quality_report.status is QualityGateStatus.QUALIFIED
                        and quality_report.label_provenance.value != "ai_assisted"
                        and quality_report.report_only
                        and not quality_report.reasons
                        and not quality_report.policy_authority
                        and not quality_report.ci_authority
                        and not quality_report.release_authority
                        and not quality_report.runtime_verified
                    )
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "provider_quality_qualified"
                    if (
                        quality_report.status is QualityGateStatus.QUALIFIED
                        and quality_report.label_provenance.value != "ai_assisted"
                        and quality_report.report_only
                        and not quality_report.reasons
                        and not quality_report.policy_authority
                        and not quality_report.ci_authority
                        and not quality_report.release_authority
                        and not quality_report.runtime_verified
                    )
                    else "provider_quality_not_qualified",
                ),
                _check(
                    "minimum_case_count",
                    GateQualificationCheckStatus.PASS
                    if metrics.case_count >= thresholds.min_case_count
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "case_count_meets_threshold"
                    if metrics.case_count >= thresholds.min_case_count
                    else "case_count_below_threshold",
                ),
                _check(
                    "positive_case_coverage",
                    GateQualificationCheckStatus.PASS
                    if positive_case_count >= thresholds.min_positive_case_count
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "positive_cases_meet_threshold"
                    if positive_case_count >= thresholds.min_positive_case_count
                    else "positive_cases_below_threshold",
                ),
                _check(
                    "eligible_negative_case_coverage",
                    GateQualificationCheckStatus.PASS
                    if eligible_negative_case_count
                    >= thresholds.min_eligible_negative_case_count
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "negative_cases_meet_threshold"
                    if eligible_negative_case_count
                    >= thresholds.min_eligible_negative_case_count
                    else "negative_cases_below_threshold",
                ),
                _check(
                    "unevaluated_cases",
                    GateQualificationCheckStatus.PASS
                    if unevaluated_case_count <= thresholds.max_unevaluated_case_count
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "no_unevaluated_cases"
                    if unevaluated_case_count <= thresholds.max_unevaluated_case_count
                    else "unevaluated_cases_present",
                ),
                _check(
                    "quality_metrics",
                    GateQualificationCheckStatus.PASS
                    if _metrics_pass(metrics, thresholds)
                    else GateQualificationCheckStatus.FAIL,
                    True,
                    "quality_metrics_meet_thresholds"
                    if _metrics_pass(metrics, thresholds)
                    else "quality_metrics_below_threshold",
                ),
            )
        )
        checks.append(
            _evidence_check(
                SemanticGateInput.PROVIDER_PROMOTION,
                "provider_promotion",
                provider_promotion,
                required=SemanticGateInput.PROVIDER_PROMOTION in required_inputs,
                passed=(
                    provider_promotion is not None
                    and provider_promotion.provider_id == quality_report.provider_id
                    and provider_promotion.model_id == quality_report.model_id
                    and provider_promotion.state
                    is ProviderPromotionState.APPROVED_SHADOW
                    and provider_promotion.quality_passed
                    and provider_promotion.human_review_passed
                    and not provider_promotion.blocking_reasons
                    and provider_promotion.report_only
                    and provider_promotion.shadow_only
                    and not provider_promotion.production_authority
                    and not provider_promotion.policy_authority
                    and not provider_promotion.ci_authority
                    and not provider_promotion.runtime_authority
                ),
                pending_code="provider_promotion_pending",
                fail_code="provider_promotion_not_approved_shadow",
            )
        )
        checks.append(
            _evidence_check(
                SemanticGateInput.CANDIDATE_CALIBRATION,
                "candidate_calibration",
                candidate_calibration,
                required=SemanticGateInput.CANDIDATE_CALIBRATION in required_inputs,
                passed=(
                    candidate_calibration is not None
                    and candidate_calibration.report_only
                    and candidate_calibration.metrics.precision is not None
                    and candidate_calibration.metrics.recall is not None
                    and candidate_calibration.metrics.f1 is not None
                    and candidate_calibration.metrics.precision
                    >= thresholds.min_precision
                    and candidate_calibration.metrics.recall >= thresholds.min_recall
                    and candidate_calibration.metrics.f1 >= thresholds.min_f1
                    and candidate_calibration.reviewer_count
                    >= thresholds.min_human_reviewer_count
                ),
                pending_code="candidate_calibration_pending",
                fail_code="candidate_calibration_below_threshold",
            )
        )
        checks.append(
            _evidence_check(
                SemanticGateInput.FINDING_PROMOTION,
                "finding_promotion",
                finding_promotion,
                required=SemanticGateInput.FINDING_PROMOTION in required_inputs,
                passed=(
                    finding_promotion is not None
                    and finding_promotion.report_only
                    and not finding_promotion.creates_finding
                    and not finding_promotion.modifies_finding
                    and not finding_promotion.policy_authority
                    and not finding_promotion.ci_authority
                ),
                pending_code="finding_promotion_pending",
                fail_code="finding_promotion_authority_contract_invalid",
            )
        )
        checks.append(
            _evidence_check(
                SemanticGateInput.RULE_STAGING,
                "rule_staging",
                rule_staging,
                required=SemanticGateInput.RULE_STAGING in required_inputs,
                passed=(
                    rule_staging is not None
                    and rule_staging.status
                    in {
                        RulePromotionStatus.ELIGIBLE_FOR_STAGING,
                        RulePromotionStatus.STAGED,
                    }
                    and not rule_staging.automatic_publication
                    and not rule_staging.rule_pack_mutated
                    and not rule_staging.finding_authority
                    and not rule_staging.policy_authority
                    and not rule_staging.ci_authority
                    and not rule_staging.hard_gate_authority
                    and not rule_staging.release_authority
                ),
                pending_code="rule_staging_pending",
                fail_code="rule_staging_not_eligible",
            )
        )
        checks.append(
            _check(
                "human_confidence",
                (
                    GateQualificationCheckStatus.PASS
                    if evidence_confidence is not None
                    and evidence_confidence.reviewer_count
                    >= thresholds.min_human_reviewer_count
                    and evidence_confidence.reviewed_case_count
                    >= thresholds.min_case_count
                    and evidence_confidence.adjudication_complete
                    and evidence_confidence.grade.rank
                    <= candidate.minimum_evidence_confidence.rank
                    else GateQualificationCheckStatus.PENDING
                    if evidence_confidence is None
                    else GateQualificationCheckStatus.FAIL
                ),
                SemanticGateInput.HUMAN_CONFIDENCE in required_inputs,
                (
                    "confidence_meets_threshold"
                    if evidence_confidence is not None
                    and evidence_confidence.reviewer_count
                    >= thresholds.min_human_reviewer_count
                    and evidence_confidence.reviewed_case_count
                    >= thresholds.min_case_count
                    and evidence_confidence.adjudication_complete
                    and evidence_confidence.grade.rank
                    <= candidate.minimum_evidence_confidence.rank
                    else "confidence_review_pending"
                    if evidence_confidence is None
                    else "confidence_below_threshold"
                ),
            )
        )
        checks.append(
            _evidence_check(
                SemanticGateInput.HUMAN_CORPUS,
                "human_corpus",
                human_corpus,
                required=SemanticGateInput.HUMAN_CORPUS in required_inputs,
                passed=corpus_ok,
                pending_code="human_corpus_pending",
                fail_code="human_corpus_coverage_or_integrity_invalid",
            )
        )
        ordered = tuple(sorted(checks, key=lambda item: item.check_id))
        failed = tuple(
            item.check_id
            for item in ordered
            if item.required and item.status is GateQualificationCheckStatus.FAIL
        )
        pending = tuple(
            item.check_id
            for item in ordered
            if item.required and item.status is GateQualificationCheckStatus.PENDING
        )
        reasons = tuple(
            sorted(
                {
                    item.rationale_code
                    for item in ordered
                    if item.required
                    and item.status is not GateQualificationCheckStatus.PASS
                }
            )
        )
        status = (
            SemanticGateQualificationStatus.NOT_QUALIFIED
            if failed
            else SemanticGateQualificationStatus.CONDITIONALLY_QUALIFIED
            if pending
            else SemanticGateQualificationStatus.QUALIFIED
        )
        qualification_id = _qualification_digest(candidate, metrics, ordered)
        return SemanticGateQualificationReport(
            qualification_id=qualification_id,
            candidate_id=candidate.candidate_id,
            gate_id=candidate.gate_id,
            provider_id=quality_report.provider_id,
            model_id=quality_report.model_id,
            status=status,
            eligible_for_report_only_gate=status
            is SemanticGateQualificationStatus.QUALIFIED,
            metrics=metrics,
            checks=ordered,
            failed_checks=failed,
            pending_checks=pending,
            reasons=reasons,
            evidence_confidence=evidence_confidence,
        )


def build_semantic_gate_candidate(
    *,
    gate_id: str,
    title: str,
    description: str,
    signal: str,
    thresholds: SemanticGateThresholds | None = None,
    required_inputs: tuple[SemanticGateInput, ...] | None = None,
    minimum_evidence_confidence: EvidenceConfidenceGrade = EvidenceConfidenceGrade.C,
) -> SemanticGateCandidate:
    """Build a digest-bound Gate candidate from reviewed definition fields."""

    threshold_value = thresholds or SemanticGateThresholds()
    raw_inputs = (
        required_inputs
        if required_inputs is not None
        else (
            SemanticGateInput.HUMAN_CONFIDENCE,
            SemanticGateInput.PROVIDER_PROMOTION,
            SemanticGateInput.PROVIDER_QUALITY,
        )
    )
    input_value = tuple(sorted(set(raw_inputs), key=lambda item: item.value))
    return SemanticGateCandidate(
        candidate_id=_candidate_digest(
            gate_id,
            title,
            description,
            signal,
            threshold_value,
            input_value,
            minimum_evidence_confidence,
        ),
        gate_id=gate_id,
        title=title,
        description=description,
        signal=signal,
        thresholds=threshold_value,
        required_inputs=input_value,
        minimum_evidence_confidence=minimum_evidence_confidence,
    )


def encode_semantic_gate_candidate_json(value: SemanticGateCandidate) -> str:
    if not isinstance(value, SemanticGateCandidate):
        raise TypeError(
            "semantic Gate candidate encoder requires SemanticGateCandidate"
        )
    return (
        json.dumps(
            value.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def encode_semantic_gate_qualification_json(
    value: SemanticGateQualificationReport,
) -> str:
    if not isinstance(value, SemanticGateQualificationReport):
        raise TypeError(
            "semantic Gate qualification encoder requires "
            "SemanticGateQualificationReport"
        )
    return (
        json.dumps(
            value.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def render_semantic_gate_qualification_text(
    value: SemanticGateQualificationReport,
) -> str:
    if not isinstance(value, SemanticGateQualificationReport):
        raise TypeError("semantic Gate qualification renderer requires a report")
    lines = [
        "AgentSec Semantic Gate Qualification",
        f"Gate: {value.gate_id}",
        f"Provider: {value.provider_id}",
        f"Model: {value.model_id}",
        f"Status: {value.status.value}",
        f"Eligible for report-only Gate: {value.eligible_for_report_only_gate}",
        (
            f"Cases: {value.metrics.case_count}; "
            f"positive={value.metrics.positive_case_count}; "
            f"eligible_negative={value.metrics.eligible_negative_case_count}; "
            f"unevaluated={value.metrics.unevaluated_case_count}"
        ),
        f"Precision: {value.metrics.precision:.3f}",
        f"Recall: {value.metrics.recall:.3f}",
        f"F1: {value.metrics.f1:.3f}",
        f"Evidence binding accuracy: {value.metrics.evidence_binding_accuracy:.3f}",
        f"Complete coverage rate: {value.metrics.complete_coverage_rate:.3f}",
        "Checks:",
    ]
    lines.extend(
        f"  {item.check_id}: {item.status.value} "
        f"({'required' if item.required else 'optional'}) - {item.rationale_code}"
        for item in value.checks
    )
    lines.extend(
        (
            "Authority: report_only=true; blocks=false; can_block_ci=false; "
            "can_publish_rule=false; can_approve_waiver=false; "
            "can_grant_runtime_authority=false",
            "LLM/provider output remains candidate evidence only.",
        )
    )
    return "\n".join(lines) + "\n"


def _candidate_digest(
    gate_id: str,
    title: str,
    description: str,
    signal: str,
    thresholds: SemanticGateThresholds,
    required_inputs: tuple[SemanticGateInput, ...],
    minimum_confidence: EvidenceConfidenceGrade,
) -> str:
    payload = {
        "description": description,
        "gate_id": gate_id,
        "minimum_evidence_confidence": minimum_confidence.value,
        "required_inputs": [item.value for item in required_inputs],
        "signal": signal,
        "thresholds": thresholds.model_dump(mode="json"),
        "title": title,
        "version": SEMANTIC_GATE_DEFINITION_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    return f"semantic-gate-candidate-sha256:{digest}"


def _qualification_digest(
    candidate: SemanticGateCandidate,
    metrics: SemanticGateQualificationMetrics,
    checks: tuple[SemanticGateQualificationCheck, ...],
) -> str:
    payload = {
        "candidate_id": candidate.candidate_id,
        "checks": [item.model_dump(mode="json") for item in checks],
        "metrics": metrics.model_dump(mode="json"),
        "version": SEMANTIC_GATE_QUALIFICATION_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    return f"semantic-gate-qualification-sha256:{digest}"


def _metrics_pass(
    metrics: SemanticGateQualificationMetrics,
    thresholds: SemanticGateThresholds,
) -> bool:
    return (
        metrics.precision >= thresholds.min_precision
        and metrics.recall >= thresholds.min_recall
        and metrics.f1 >= thresholds.min_f1
        and metrics.evidence_binding_accuracy
        >= thresholds.min_evidence_binding_accuracy
        and metrics.complete_coverage_rate >= thresholds.min_complete_coverage_rate
    )


def _check(
    check_id: str,
    status: GateQualificationCheckStatus,
    required: bool,
    rationale_code: str,
) -> SemanticGateQualificationCheck:
    return SemanticGateQualificationCheck(
        check_id=check_id,
        status=status,
        required=required,
        rationale_code=rationale_code,
    )


def _evidence_check(
    input_kind: SemanticGateInput,
    check_id: str,
    evidence: BaseModel | None,
    *,
    required: bool,
    passed: bool,
    pending_code: str,
    fail_code: str,
) -> SemanticGateQualificationCheck:
    if input_kind.value not in {item.value for item in SemanticGateInput}:
        raise SemanticGateError("unsupported_input")
    if not required and evidence is None:
        return _check(
            check_id, GateQualificationCheckStatus.PASS, False, "optional_not_required"
        )
    if evidence is None:
        return _check(
            check_id, GateQualificationCheckStatus.PENDING, True, pending_code
        )
    return _check(
        check_id,
        GateQualificationCheckStatus.PASS
        if passed
        else GateQualificationCheckStatus.FAIL,
        required,
        "evidence_contract_valid" if passed else fail_code,
    )


__all__ = [
    "EvidenceConfidenceGrade",
    "GateQualificationCheckStatus",
    "SEMANTIC_GATE_CANDIDATE_FORMAT",
    "SEMANTIC_GATE_QUALIFICATION_FORMAT",
    "SEMANTIC_GATE_DEFINITION_VERSION",
    "SEMANTIC_GATE_QUALIFICATION_VERSION",
    "SemanticGateAuthority",
    "SemanticGateCandidate",
    "SemanticGateCandidateStatus",
    "SemanticGateError",
    "SemanticGateEvidenceConfidence",
    "SemanticGateInput",
    "SemanticGateQualificationCheck",
    "SemanticGateQualificationMetrics",
    "SemanticGateQualificationReport",
    "SemanticGateQualificationRunner",
    "SemanticGateQualificationStatus",
    "SemanticGateThresholds",
    "build_semantic_gate_candidate",
    "encode_semantic_gate_candidate_json",
    "encode_semantic_gate_qualification_json",
    "render_semantic_gate_qualification_text",
]

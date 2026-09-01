"""P3-07 semantic calibration, promotion review, and Rule replay contracts.

All outputs in this module are review evidence.  They never create Findings,
modify the deterministic Rule Pack, or grant Policy/CI/Hard-Gate authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import FindingCategory
from agentsec.rules import Rule, RuleContext
from agentsec.semantic.integration import (
    RuleCandidateStatus,
    SemanticFindingIntegrationReport,
    SemanticFindingLink,
    SemanticFindingRelation,
    SemanticRuleCandidate,
)
from agentsec.semantic.models import (
    CandidateKey,
    SemanticAnalysisResult,
    SemanticCandidateKind,
)

SEMANTIC_CANDIDATE_CALIBRATION_VERSION = "0.1.0"
SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION = "0.1.0"
SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION = "0.1.0"

_CANDIDATE_ID = Annotated[
    str, Field(pattern=r"^semantic-candidate-sha256:[0-9a-f]{64}$")
]
_PROPOSAL_ID = Annotated[
    str, Field(pattern=r"^semantic-rule-proposal-sha256:[0-9a-f]{64}$")
]
_FINDING_ID = Annotated[str, Field(min_length=1, max_length=256)]
_REVIEWER_ID = Annotated[str, Field(min_length=1, max_length=128)]
_RATIONALE = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SemanticCalibrationOutcome(StrEnum):
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    UNCERTAIN = "uncertain"


class SemanticCalibrationClassification(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"


class SemanticCandidateCalibrationCase(_Strict):
    """One human-labeled expectation for one model candidate key."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_key: CandidateKey
    expected_present: bool
    expected_kind: SemanticCandidateKind | None = None
    expected_category: FindingCategory | None = None
    expected_disposition: SemanticCalibrationOutcome | None = None
    expected_evidence_ids: tuple[
        Annotated[str, Field(pattern=r"^semantic-evidence-sha256:[0-9a-f]{64}$")], ...
    ] = ()
    reviewer_id: _REVIEWER_ID
    rationale_code: _RATIONALE

    @field_validator("expected_evidence_ids")
    @classmethod
    def evidence_ids_must_be_sorted_unique(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("calibration Evidence IDs must be sorted and unique")
        return value

    @model_validator(mode="after")
    def labels_must_be_coherent(self) -> SemanticCandidateCalibrationCase:
        supplied = (
            self.expected_kind,
            self.expected_category,
            self.expected_disposition,
        )
        if self.expected_present and any(item is None for item in supplied):
            raise ValueError("present calibration labels require candidate fields")
        if not self.expected_present and any(item is not None for item in supplied):
            raise ValueError(
                "absent calibration labels cannot declare candidate fields"
            )
        if self.expected_present and not self.expected_evidence_ids:
            raise ValueError("present calibration labels require Evidence IDs")
        if not self.expected_present and self.expected_evidence_ids:
            raise ValueError("absent calibration labels cannot declare Evidence IDs")
        return self


class SemanticCandidateCalibrationCaseResult(_Strict):
    case_id: str
    candidate_key: CandidateKey
    observed_present: bool
    classification: SemanticCalibrationClassification
    kind_agreement: bool | None = None
    category_agreement: bool | None = None
    disposition_agreement: bool | None = None
    evidence_agreement: bool | None = None


class SemanticCandidateCalibrationMetrics(_Strict):
    case_count: int = Field(ge=1)
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)
    kind_agreement: float | None = Field(default=None, ge=0, le=1)
    category_agreement: float | None = Field(default=None, ge=0, le=1)
    disposition_agreement: float | None = Field(default=None, ge=0, le=1)
    evidence_agreement: float | None = Field(default=None, ge=0, le=1)


class SemanticCandidateCalibrationReport(_Strict):
    format: Literal["agentsec-semantic-candidate-calibration-report"] = (
        "agentsec-semantic-candidate-calibration-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    semantic_result_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    cases: tuple[SemanticCandidateCalibrationCaseResult, ...]
    metrics: SemanticCandidateCalibrationMetrics
    reviewer_count: int = Field(ge=1)
    report_only: Literal[True] = True
    finding_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticCandidateCalibrationReport:
        if len(self.cases) != self.metrics.case_count:
            raise ValueError("calibration case count is inconsistent")
        keys = tuple((item.case_id, item.candidate_key) for item in self.cases)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("calibration results must be sorted and unique")
        return self


class SemanticCandidateCalibrationRunner:
    """Compare semantic output with a complete, human-labeled candidate set."""

    def run(
        self,
        result: SemanticAnalysisResult,
        cases: tuple[SemanticCandidateCalibrationCase, ...],
    ) -> SemanticCandidateCalibrationReport:
        if not isinstance(result, SemanticAnalysisResult):
            raise TypeError("semantic result is required")
        if not isinstance(cases, tuple) or not cases:
            raise TypeError("calibration cases must be a non-empty tuple")
        if any(
            not isinstance(item, SemanticCandidateCalibrationCase) for item in cases
        ):
            raise TypeError("calibration cases contain an invalid case")
        case_keys = tuple(item.candidate_key for item in cases)
        if case_keys != tuple(sorted(set(case_keys))):
            raise ValueError("calibration candidate keys must be sorted and unique")
        candidates = {item.model_candidate_key: item for item in result.candidates}
        if not set(candidates) <= set(case_keys):
            raise ValueError("calibration cases must cover every observed candidate")

        rows: list[SemanticCandidateCalibrationCaseResult] = []
        for case in cases:
            candidate = candidates.get(case.candidate_key)
            observed = candidate is not None
            expected = case.expected_present
            if expected and observed:
                classification = SemanticCalibrationClassification.TRUE_POSITIVE
            elif expected and not observed:
                classification = SemanticCalibrationClassification.FALSE_NEGATIVE
            elif not expected and observed:
                classification = SemanticCalibrationClassification.FALSE_POSITIVE
            else:
                classification = SemanticCalibrationClassification.TRUE_NEGATIVE
            rows.append(
                SemanticCandidateCalibrationCaseResult(
                    case_id=case.case_id,
                    candidate_key=case.candidate_key,
                    observed_present=observed,
                    classification=classification,
                    kind_agreement=(
                        candidate.kind is case.expected_kind
                        if expected and candidate is not None
                        else None
                    ),
                    category_agreement=(
                        candidate.category is case.expected_category
                        if expected and candidate is not None
                        else None
                    ),
                    disposition_agreement=(
                        candidate.disposition.value == case.expected_disposition.value
                        if expected
                        and candidate is not None
                        and case.expected_disposition is not None
                        else None
                    ),
                    evidence_agreement=(
                        candidate.evidence_ids == case.expected_evidence_ids
                        if expected and candidate is not None
                        else None
                    ),
                )
            )
        ordered = tuple(
            sorted(rows, key=lambda item: (item.case_id, item.candidate_key))
        )
        tp = sum(
            item.classification is SemanticCalibrationClassification.TRUE_POSITIVE
            for item in ordered
        )
        fp = sum(
            item.classification is SemanticCalibrationClassification.FALSE_POSITIVE
            for item in ordered
        )
        fn = sum(
            item.classification is SemanticCalibrationClassification.FALSE_NEGATIVE
            for item in ordered
        )
        tn = sum(
            item.classification is SemanticCalibrationClassification.TRUE_NEGATIVE
            for item in ordered
        )
        return SemanticCandidateCalibrationReport(
            semantic_result_sha256=_result_digest(result),
            cases=ordered,
            metrics=SemanticCandidateCalibrationMetrics(
                case_count=len(ordered),
                true_positive=tp,
                false_positive=fp,
                false_negative=fn,
                true_negative=tn,
                precision=_ratio(tp, tp + fp),
                recall=_ratio(tp, tp + fn),
                f1=_f1(tp, fp, fn),
                kind_agreement=_agreement(ordered, "kind_agreement"),
                category_agreement=_agreement(ordered, "category_agreement"),
                disposition_agreement=_agreement(ordered, "disposition_agreement"),
                evidence_agreement=_agreement(ordered, "evidence_agreement"),
            ),
            reviewer_count=len({item.reviewer_id for item in cases}),
        )


class FindingPromotionDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class FindingPromotionStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    ACCEPTED_FOR_FINDING_REVIEW = "accepted_for_finding_review"
    REJECTED = "rejected"


class SemanticFindingPromotionReview(_Strict):
    """Human review of a link; acceptance never creates a Finding."""

    candidate_id: _CANDIDATE_ID
    finding_id: _FINDING_ID | None = None
    relation: SemanticFindingRelation
    decision: FindingPromotionDecision
    status: FindingPromotionStatus
    reviewer_id: _REVIEWER_ID
    rationale_code: _RATIONALE
    report_only: Literal[True] = True
    creates_finding: Literal[False] = False
    modifies_finding: Literal[False] = False
    severity_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def decision_must_be_coherent(self) -> SemanticFindingPromotionReview:
        expected = (
            FindingPromotionStatus.ACCEPTED_FOR_FINDING_REVIEW
            if self.decision is FindingPromotionDecision.ACCEPT
            else FindingPromotionStatus.REJECTED
        )
        if self.status is not expected:
            raise ValueError("promotion review status does not match decision")
        if self.decision is FindingPromotionDecision.ACCEPT and self.relation not in (
            SemanticFindingRelation.SUPPORTS,
            SemanticFindingRelation.DUPLICATES,
        ):
            raise ValueError("only positive deterministic links can be accepted")
        return self


class SemanticFindingPromotionReport(_Strict):
    """Batch report for human review of semantic-to-Finding links."""

    format: Literal["agentsec-semantic-finding-promotion-report"] = (
        "agentsec-semantic-finding-promotion-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    integration_report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    reviews: tuple[SemanticFindingPromotionReview, ...] = Field(min_length=1)
    report_only: Literal[True] = True
    creates_finding: Literal[False] = False
    modifies_finding: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def reviews_must_be_stable(self) -> SemanticFindingPromotionReport:
        keys = tuple(
            (item.candidate_id, item.finding_id or "") for item in self.reviews
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("promotion reviews must be sorted and unique")
        return self


class SemanticFindingPromotionReviewer:
    """Apply explicit human decisions to integration links only."""

    def review(
        self,
        link: SemanticFindingLink,
        *,
        reviewer_id: str,
        decision: FindingPromotionDecision,
        rationale_code: str = "human_reviewed",
    ) -> SemanticFindingPromotionReview:
        if not isinstance(link, SemanticFindingLink):
            raise TypeError("Finding link is required")
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("reviewer_id is required")
        if not isinstance(decision, FindingPromotionDecision):
            raise TypeError("promotion decision is required")
        if decision is FindingPromotionDecision.ACCEPT and link.finding_id is None:
            raise ValueError("accepted promotion review requires a Finding link")
        return SemanticFindingPromotionReview(
            candidate_id=link.candidate_id,
            finding_id=link.finding_id,
            relation=link.relation,
            decision=decision,
            status=(
                FindingPromotionStatus.ACCEPTED_FOR_FINDING_REVIEW
                if decision is FindingPromotionDecision.ACCEPT
                else FindingPromotionStatus.REJECTED
            ),
            reviewer_id=reviewer_id.strip(),
            rationale_code=rationale_code,
        )

    def review_report(
        self,
        integration_report: SemanticFindingIntegrationReport,
        decisions: tuple[
            tuple[SemanticFindingLink, FindingPromotionDecision, str], ...
        ],
        *,
        reviewer_id: str,
    ) -> SemanticFindingPromotionReport:
        if not isinstance(integration_report, SemanticFindingIntegrationReport):
            raise TypeError("integration report is required")
        links = {
            (item.candidate_id, item.finding_id or ""): item
            for item in integration_report.links
        }
        reviews: list[SemanticFindingPromotionReview] = []
        for link, decision, rationale_code in decisions:
            key = (link.candidate_id, link.finding_id or "")
            if links.get(key) != link:
                raise ValueError(
                    "promotion decision references an unknown integration link"
                )
            reviews.append(
                self.review(
                    link,
                    reviewer_id=reviewer_id,
                    decision=decision,
                    rationale_code=rationale_code,
                )
            )
        digest = hashlib.sha256(
            json.dumps(
                integration_report.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return SemanticFindingPromotionReport(
            integration_report_sha256=digest,
            reviews=tuple(
                sorted(
                    reviews,
                    key=lambda item: (item.candidate_id, item.finding_id or ""),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class RuleImplementationReplayCase:
    """Trusted in-memory Rule replay input; source data never enters reports."""

    case_id: str
    context: RuleContext = dataclass_field(repr=False)
    expected_outcome: Literal["match", "no_match"]
    expected_min_findings: int = 0
    expected_max_findings: int = 0

    def __post_init__(self) -> None:
        if not self.case_id.strip():
            raise ValueError("replay case_id is required")
        if not isinstance(self.context, RuleContext):
            raise TypeError("replay context must be RuleContext")
        if self.expected_outcome == "match":
            if self.expected_min_findings < 1:
                raise ValueError("matching replay cases require a positive minimum")
            if self.expected_max_findings < self.expected_min_findings:
                raise ValueError("replay finding bounds are incoherent")
        elif self.expected_outcome == "no_match":
            if self.expected_min_findings != 0 or self.expected_max_findings != 0:
                raise ValueError("no-match replay cases require zero finding bounds")
        else:
            raise ValueError("replay expected outcome is invalid")


class RuleReplayClassification(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"


class RuleImplementationReplayCaseResult(_Strict):
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    expected_outcome: Literal["match", "no_match"]
    observed_outcome: Literal["match", "no_match"]
    classification: RuleReplayClassification
    observed_findings: int = Field(ge=0)
    finding_bound_ok: bool
    evidence_binding_ok: bool
    failure: bool


class RuleImplementationReplayMetrics(_Strict):
    case_count: int = Field(ge=1)
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)
    evidence_binding_accuracy: float = Field(ge=0, le=1)
    finding_bound_accuracy: float = Field(ge=0, le=1)
    failure_count: int = Field(ge=0)


class RuleImplementationReplayReport(_Strict):
    format: Literal["agentsec-semantic-rule-implementation-replay-report"] = (
        "agentsec-semantic-rule-implementation-replay-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    proposal_id: _PROPOSAL_ID
    rule_id: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")]
    results: tuple[RuleImplementationReplayCaseResult, ...] = Field(min_length=1)
    metrics: RuleImplementationReplayMetrics
    report_only: Literal[True] = True
    rule_pack_mutated: Literal[False] = False
    finding_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def results_must_be_stable(self) -> RuleImplementationReplayReport:
        if len(self.results) != self.metrics.case_count:
            raise ValueError("replay case count is inconsistent")
        case_ids = tuple(item.case_id for item in self.results)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("replay results must be sorted and unique")
        return self


class RuleImplementationReplayRunner:
    """Replay one accepted proposal through a trusted deterministic Rule."""

    def run(
        self,
        proposal: SemanticRuleCandidate,
        rule: Rule,
        cases: tuple[RuleImplementationReplayCase, ...],
    ) -> RuleImplementationReplayReport:
        if not isinstance(proposal, SemanticRuleCandidate):
            raise TypeError("Rule Candidate proposal is required")
        if proposal.status is not RuleCandidateStatus.ACCEPTED_FOR_IMPLEMENTATION:
            raise ValueError("Rule replay requires an accepted implementation proposal")
        if not isinstance(rule, Rule):
            raise TypeError("replay requires a trusted Rule")
        if not isinstance(cases, tuple) or not cases:
            raise TypeError("replay cases must be a non-empty tuple")
        if not rule.metadata.rule_id.startswith(
            proposal.proposed_rule_family.replace("_", "") + "-"
        ):
            raise ValueError("Rule ID is not bound to the proposal family")

        from agentsec.rules import DeterministicRuleRunner

        rows: list[RuleImplementationReplayCaseResult] = []
        for case in cases:
            replay = DeterministicRuleRunner((rule,)).run((case.context,))
            findings = replay.findings
            observed: Literal["match", "no_match"] = "match" if findings else "no_match"
            expected = case.expected_outcome
            classification = _binary_classification(expected, observed)
            bound = all(
                item.category is rule.metadata.category
                and all(
                    evidence.asset_path == case.context.asset.path
                    and evidence.content_sha256 == case.context.asset.sha256
                    for evidence in item.evidence
                )
                for item in findings
            )
            count_ok = (
                case.expected_min_findings
                <= len(findings)
                <= case.expected_max_findings
            )
            rows.append(
                RuleImplementationReplayCaseResult(
                    case_id=case.case_id,
                    expected_outcome=expected,
                    observed_outcome=observed,
                    classification=classification,
                    observed_findings=len(findings),
                    finding_bound_ok=count_ok,
                    evidence_binding_ok=bound,
                    failure=bool(replay.failures),
                )
            )
        ordered = tuple(sorted(rows, key=lambda item: item.case_id))
        tp = sum(
            item.classification is RuleReplayClassification.TRUE_POSITIVE
            for item in ordered
        )
        fp = sum(
            item.classification is RuleReplayClassification.FALSE_POSITIVE
            for item in ordered
        )
        fn = sum(
            item.classification is RuleReplayClassification.FALSE_NEGATIVE
            for item in ordered
        )
        tn = sum(
            item.classification is RuleReplayClassification.TRUE_NEGATIVE
            for item in ordered
        )
        return RuleImplementationReplayReport(
            proposal_id=proposal.proposal_id,
            rule_id=rule.metadata.rule_id,
            results=ordered,
            metrics=RuleImplementationReplayMetrics(
                case_count=len(ordered),
                true_positive=tp,
                false_positive=fp,
                false_negative=fn,
                true_negative=tn,
                precision=_ratio(tp, tp + fp),
                recall=_ratio(tp, tp + fn),
                f1=_f1(tp, fp, fn),
                evidence_binding_accuracy=sum(
                    item.evidence_binding_ok for item in ordered
                )
                / len(ordered),
                finding_bound_accuracy=sum(item.finding_bound_ok for item in ordered)
                / len(ordered),
                failure_count=sum(item.failure for item in ordered),
            ),
        )


def _result_digest(result: SemanticAnalysisResult) -> str:
    payload = json.dumps(
        result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(tp: int, fp: int, fn: int) -> float | None:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _agreement(
    rows: tuple[SemanticCandidateCalibrationCaseResult, ...], field: str
) -> float | None:
    values = [getattr(row, field) for row in rows if getattr(row, field) is not None]
    return sum(values) / len(values) if values else None


def _binary_classification(expected: str, observed: str) -> RuleReplayClassification:
    if expected == "match":
        return (
            RuleReplayClassification.TRUE_POSITIVE
            if observed == "match"
            else RuleReplayClassification.FALSE_NEGATIVE
        )
    return (
        RuleReplayClassification.FALSE_POSITIVE
        if observed == "match"
        else RuleReplayClassification.TRUE_NEGATIVE
    )


__all__ = [
    "SEMANTIC_CANDIDATE_CALIBRATION_VERSION",
    "SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION",
    "SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION",
    "FindingPromotionDecision",
    "FindingPromotionStatus",
    "RuleImplementationReplayCase",
    "RuleImplementationReplayCaseResult",
    "RuleImplementationReplayMetrics",
    "RuleImplementationReplayReport",
    "RuleImplementationReplayRunner",
    "RuleReplayClassification",
    "SemanticCandidateCalibrationCase",
    "SemanticCandidateCalibrationCaseResult",
    "SemanticCandidateCalibrationReport",
    "SemanticCandidateCalibrationRunner",
    "SemanticCandidateCalibrationMetrics",
    "SemanticCalibrationClassification",
    "SemanticCalibrationOutcome",
    "SemanticFindingPromotionReport",
    "SemanticFindingPromotionReview",
    "SemanticFindingPromotionReviewer",
]

"""P3-19 Gate-scoped human corpus and review import contracts.

This module deliberately keeps the corpus separate from the Provider quality
report.  A corpus records human-reviewed semantic evidence; it does not grant
any CI, Policy, Finding, Rule, waiver, runtime, or release authority.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.semantic.evaluation import (
    SemanticEvaluationCase,
    SemanticEvaluationExpected,
)
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    build_semantic_evidence_chunk,
)

SEMANTIC_GATE_HUMAN_CORPUS_VERSION = "0.1.0"
SEMANTIC_GATE_HUMAN_CORPUS_FORMAT = "agentsec-semantic-gate-human-corpus"
SEMANTIC_GATE_REVIEW_SUBMISSION_FORMAT = "agentsec-semantic-gate-review-submission"
_MAX_CASES = 512
_MAX_REVIEWERS = 16
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CORPUS_ID_PATTERN = r"^semantic-gate-human-corpus-sha256:[0-9a-f]{64}$"
_REVIEWED_AT_PATTERN = r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T"


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticGateCaseClass(StrEnum):
    """Gate-oriented class used for coverage accounting."""

    POSITIVE = "positive"
    ELIGIBLE_NEGATIVE = "eligible_negative"
    NEAR_MISS = "near_miss"
    UNKNOWN = "unknown"


class SemanticGateReviewStatus(StrEnum):
    """Lifecycle state of one human corpus case."""

    DRAFT = "draft"
    REVIEWED = "reviewed"
    ADJUDICATED = "adjudicated"


class SemanticGateCorpusProvenance(StrEnum):
    """Provenance state; AI-only labels remain explicitly draft-only."""

    HUMAN_AUTHORED = "human_authored"
    AI_DRAFT_HUMAN_CONFIRMED = "ai_draft_human_confirmed"
    AI_DRAFT = "ai_draft"


class SemanticGateHumanCase(_Strict):
    """One sanitized, gate-scoped human-labeled evidence case."""

    format: Literal["agentsec-semantic-gate-human-case"] = (
        "agentsec-semantic-gate-human-case"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    signal: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]
    language: Literal["zh", "en", "mixed"] = "en"
    case_class: SemanticGateCaseClass
    expected_gate_match: bool
    evidence_id: Annotated[str, Field(min_length=1, max_length=160)]
    asset_path: Annotated[str, Field(min_length=1, max_length=512)]
    asset_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    sanitized_text: Annotated[str, Field(min_length=1, max_length=4096)]
    text_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    expected: tuple[SemanticEvaluationExpected, ...] = ()
    source_kind: Annotated[str, Field(min_length=1, max_length=80)]
    source_label: Annotated[str, Field(min_length=1, max_length=512)]
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    review_provenance: SemanticGateCorpusProvenance
    review_status: SemanticGateReviewStatus = SemanticGateReviewStatus.REVIEWED
    confidence_grade: Literal["A", "B", "C", "D"] = "C"
    confidence_rationale: Annotated[str, Field(min_length=1, max_length=512)]

    @field_validator("asset_path")
    @classmethod
    def asset_path_must_be_relative(cls, value: str) -> str:
        from agentsec.domain.base import validate_relative_path

        return validate_relative_path(value)

    @field_validator("sanitized_text")
    @classmethod
    def sanitized_text_must_not_have_controls(cls, value: str) -> str:
        if any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise ValueError("sanitized corpus text contains unsafe controls")
        if value != value.strip():
            raise ValueError("sanitized corpus text must be exact text")
        return value

    @model_validator(mode="after")
    def evidence_and_label_must_be_coherent(self) -> SemanticGateHumanCase:
        if self.end_line < self.start_line:
            raise ValueError("corpus evidence line range is incoherent")
        chunk = build_semantic_evidence_chunk(
            asset_path=self.asset_path,
            asset_sha256=self.asset_sha256,
            start_line=self.start_line,
            end_line=self.end_line,
            text=self.sanitized_text,
        )
        if chunk.text != self.sanitized_text:
            raise ValueError("corpus evidence text is not already sanitized")
        if chunk.evidence_id != self.evidence_id:
            raise ValueError("corpus evidence ID is inconsistent")
        if chunk.text_sha256 != self.text_sha256:
            raise ValueError("corpus evidence text digest is inconsistent")
        expected_ids = {
            evidence_id for item in self.expected for evidence_id in item.evidence_ids
        }
        if not expected_ids <= {self.evidence_id}:
            raise ValueError("corpus expected judgment references unknown evidence")
        if self.case_class is SemanticGateCaseClass.POSITIVE:
            if not self.expected_gate_match:
                raise ValueError("positive case must expect a Gate match")
        elif (
            self.case_class
            in {
                SemanticGateCaseClass.ELIGIBLE_NEGATIVE,
                SemanticGateCaseClass.NEAR_MISS,
            }
            and self.expected_gate_match
        ):
            raise ValueError("negative or near-miss case must expect no Gate match")
        if self.review_status is SemanticGateReviewStatus.DRAFT:
            if self.review_provenance is not SemanticGateCorpusProvenance.AI_DRAFT:
                raise ValueError("draft case must be marked ai_draft")
            if self.reviewer_id != "pending-review":
                raise ValueError("draft case must use the pending-review reviewer")
        elif self.review_provenance not in {
            SemanticGateCorpusProvenance.HUMAN_AUTHORED,
            SemanticGateCorpusProvenance.AI_DRAFT_HUMAN_CONFIRMED,
        }:
            raise ValueError("final corpus requires human-confirmed provenance")
        return self

    def evidence_chunk(self) -> SemanticEvidenceChunk:
        """Return the already-sanitized evidence as the trusted input chunk."""

        return SemanticEvidenceChunk(
            evidence_id=self.evidence_id,
            asset_path=self.asset_path,
            asset_sha256=self.asset_sha256,
            start_line=self.start_line,
            end_line=self.end_line,
            text=self.sanitized_text,
            text_sha256=self.text_sha256,
            sanitization_applied=False,
        )

    def evaluation_case(self) -> SemanticEvaluationCase:
        """Convert the case into the existing Provider evaluation contract."""

        semantic_input = SemanticAnalysisInput(
            analysis_id=self.case_id,
            deterministic_context=SemanticDeterministicContext(coverage_complete=True),
            evidence=(self.evidence_chunk(),),
        )
        return SemanticEvaluationCase(
            case_id=self.case_id,
            language=self.language,
            semantic_input=semantic_input,
            expected=self.expected,
        )


class SemanticGateCorpusReviewer(_Strict):
    """Reviewer identity and independence evidence for one corpus."""

    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independence_statement: Annotated[str, Field(min_length=1, max_length=2048)]
    reviewed_case_count: Annotated[int, Field(ge=0)]
    reviewed_at: Annotated[str, Field(pattern=_REVIEWED_AT_PATTERN)]
    provenance: SemanticGateCorpusProvenance

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_must_be_iso8601(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("reviewed_at must be an ISO-8601 timestamp") from error
        return value


class SemanticGateCorpusCoverage(_Strict):
    """Deterministic coverage counters used by P3-18 qualification."""

    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    case_count: Annotated[int, Field(ge=0)]
    positive_count: Annotated[int, Field(ge=0)]
    eligible_negative_count: Annotated[int, Field(ge=0)]
    near_miss_count: Annotated[int, Field(ge=0)]
    unknown_count: Annotated[int, Field(ge=0)]
    unresolved_count: Annotated[int, Field(ge=0)]
    reviewer_count: Annotated[int, Field(ge=0)]
    human_confirmed: bool
    minimum_positive_met: bool
    minimum_eligible_negative_or_near_miss_met: bool


class SemanticGateHumanCorpus(_Strict):
    """Digest-bound final corpus for one Semantic Gate."""

    format: Literal["agentsec-semantic-gate-human-corpus"] = (
        "agentsec-semantic-gate-human-corpus"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    corpus_id: Annotated[str, Field(pattern=_CORPUS_ID_PATTERN)]
    corpus_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    signal: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]
    cases: Annotated[
        tuple[SemanticGateHumanCase, ...], Field(min_length=1, max_length=_MAX_CASES)
    ]
    reviewers: Annotated[
        tuple[SemanticGateCorpusReviewer, ...],
        Field(min_length=1, max_length=_MAX_REVIEWERS),
    ]
    authority_report_only: Literal[True] = True
    authority_blocks: Literal[False] = False
    authority_can_block_ci: Literal[False] = False
    authority_can_publish_rule: Literal[False] = False
    authority_can_approve_waiver: Literal[False] = False
    authority_can_grant_runtime: Literal[False] = False

    @model_validator(mode="after")
    def corpus_must_be_coherent(self) -> SemanticGateHumanCorpus:
        ids = tuple(item.case_id for item in self.cases)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("corpus case IDs must be sorted and unique")
        if any(
            item.gate_id != self.gate_id or item.signal != self.signal
            for item in self.cases
        ):
            raise ValueError("corpus cases must belong to the declared Gate and signal")
        reviewer_ids = tuple(item.reviewer_id for item in self.reviewers)
        if reviewer_ids != tuple(sorted(set(reviewer_ids))):
            raise ValueError("corpus reviewers must be sorted and unique")
        reviewer_set = set(reviewer_ids)
        if any(item.reviewer_id not in reviewer_set for item in self.cases):
            raise ValueError("corpus case references an unknown reviewer")
        if any(
            item.review_status is SemanticGateReviewStatus.DRAFT
            and item.reviewer_id != "pending-review"
            for item in self.cases
        ):
            raise ValueError("draft corpus cases must use pending-review")
        if any(
            item.review_provenance
            is SemanticGateCorpusProvenance.AI_DRAFT_HUMAN_CONFIRMED
            and not item.reviewer_id
            for item in self.cases
        ):
            raise ValueError("AI-drafted cases require a human reviewer")
        expected_hash = _corpus_digest(self)
        if self.corpus_sha256 != expected_hash:
            raise ValueError("corpus digest is inconsistent")
        if self.corpus_id != f"semantic-gate-human-corpus-sha256:{expected_hash}":
            raise ValueError("corpus ID is inconsistent")
        return self

    @property
    def coverage(self) -> SemanticGateCorpusCoverage:
        classes = [item.case_class for item in self.cases]
        negative = classes.count(
            SemanticGateCaseClass.ELIGIBLE_NEGATIVE
        ) + classes.count(SemanticGateCaseClass.NEAR_MISS)
        return SemanticGateCorpusCoverage(
            gate_id=self.gate_id,
            case_count=len(self.cases),
            positive_count=classes.count(SemanticGateCaseClass.POSITIVE),
            eligible_negative_count=classes.count(
                SemanticGateCaseClass.ELIGIBLE_NEGATIVE
            ),
            near_miss_count=classes.count(SemanticGateCaseClass.NEAR_MISS),
            unknown_count=classes.count(SemanticGateCaseClass.UNKNOWN),
            unresolved_count=sum(
                item.review_status is SemanticGateReviewStatus.DRAFT
                for item in self.cases
            ),
            reviewer_count=len(self.reviewers),
            human_confirmed=all(
                item.review_status is not SemanticGateReviewStatus.DRAFT
                for item in self.cases
            ),
            minimum_positive_met=classes.count(SemanticGateCaseClass.POSITIVE) >= 20,
            minimum_eligible_negative_or_near_miss_met=negative >= 20,
        )

    def evaluation_cases(
        self, *, max_cases: int | None = None
    ) -> tuple[SemanticEvaluationCase, ...]:
        selected = self.cases if max_cases is None else self.cases[:max_cases]
        return tuple(item.evaluation_case() for item in selected)


class SemanticGateReviewDecision(_Strict):
    """One independent review row; it contains no raw source text."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    case_class: SemanticGateCaseClass
    expected_gate_match: bool
    confidence_grade: Literal["A", "B", "C", "D"]
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")]
    expected: tuple[SemanticEvaluationExpected, ...] = ()

    @model_validator(mode="after")
    def decision_must_be_coherent(self) -> SemanticGateReviewDecision:
        if (
            self.case_class is SemanticGateCaseClass.POSITIVE
            and not self.expected_gate_match
        ):
            raise ValueError("positive review decision must expect a match")
        if (
            self.case_class
            in {
                SemanticGateCaseClass.ELIGIBLE_NEGATIVE,
                SemanticGateCaseClass.NEAR_MISS,
            }
            and self.expected_gate_match
        ):
            raise ValueError("negative review decision must expect no match")
        return self


class SemanticGateReviewSubmission(_Strict):
    """Independent reviewer submission to be imported after review."""

    format: Literal["agentsec-semantic-gate-review-submission"] = (
        "agentsec-semantic-gate-review-submission"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    corpus_id: Annotated[str, Field(pattern=_CORPUS_ID_PATTERN)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independence_statement: Annotated[str, Field(min_length=1, max_length=2048)]
    reviewed_at: Annotated[str, Field(pattern=_REVIEWED_AT_PATTERN)]
    decisions: Annotated[
        tuple[SemanticGateReviewDecision, ...],
        Field(min_length=1, max_length=_MAX_CASES),
    ]
    independent: Literal[True] = True

    @model_validator(mode="after")
    def submission_must_be_coherent(self) -> SemanticGateReviewSubmission:
        ids = tuple(item.case_id for item in self.decisions)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("review decisions must be sorted and unique")
        try:
            datetime.fromisoformat(self.reviewed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("reviewed_at must be an ISO-8601 timestamp") from error
        return self


class SemanticGateAdjudication(_Strict):
    """Final human resolution for a disagreement between reviewers."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    case_class: SemanticGateCaseClass
    expected_gate_match: bool
    confidence_grade: Literal["A", "B", "C", "D"]
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")]
    expected: tuple[SemanticEvaluationExpected, ...] = ()

    @model_validator(mode="after")
    def adjudication_must_be_coherent(self) -> SemanticGateAdjudication:
        SemanticGateReviewDecision(
            case_id=self.case_id,
            case_class=self.case_class,
            expected_gate_match=self.expected_gate_match,
            confidence_grade=self.confidence_grade,
            rationale_code=self.rationale_code,
            expected=self.expected,
        )
        return self


def build_semantic_gate_human_corpus(
    *,
    gate_id: str,
    signal: str,
    cases: tuple[SemanticGateHumanCase, ...],
    reviewers: tuple[SemanticGateCorpusReviewer, ...],
) -> SemanticGateHumanCorpus:
    """Build a digest-bound corpus after human review has completed."""

    provisional = SemanticGateHumanCorpus.model_construct(
        corpus_id="semantic-gate-human-corpus-sha256:" + "0" * 64,
        corpus_sha256="0" * 64,
        gate_id=gate_id,
        signal=signal,
        cases=tuple(sorted(cases, key=lambda item: item.case_id)),
        reviewers=tuple(sorted(reviewers, key=lambda item: item.reviewer_id)),
        authority_report_only=True,
        authority_blocks=False,
        authority_can_block_ci=False,
        authority_can_publish_rule=False,
        authority_can_approve_waiver=False,
        authority_can_grant_runtime=False,
    )
    digest = _corpus_digest(provisional)
    return provisional.model_copy(
        update={
            "corpus_sha256": digest,
            "corpus_id": f"semantic-gate-human-corpus-sha256:{digest}",
        }
    )


def import_semantic_gate_review(
    corpus: SemanticGateHumanCorpus,
    *,
    reviewer_submissions: tuple[SemanticGateReviewSubmission, ...],
    adjudications: tuple[SemanticGateAdjudication, ...] = (),
) -> SemanticGateHumanCorpus:
    """Apply independent review decisions and adjudications to a corpus.

    The function never changes evidence or semantic judgments. It only applies
    gate class, match expectation, and confidence fields from the submissions;
    disagreements must be explicitly adjudicated.
    """

    if not isinstance(corpus, SemanticGateHumanCorpus):
        raise TypeError("semantic Gate corpus is required")
    submissions = tuple(reviewer_submissions)
    if not submissions:
        raise ValueError("at least one reviewer submission is required")
    if any(
        item.corpus_id != corpus.corpus_id or item.gate_id != corpus.gate_id
        for item in submissions
    ):
        raise ValueError("review submission is not bound to this corpus")
    if len({item.reviewer_id for item in submissions}) != len(submissions):
        raise ValueError("reviewer submissions must have unique reviewer IDs")
    by_case = {case.case_id: case for case in corpus.cases}
    decisions_by_case: dict[str, list[SemanticGateReviewDecision]] = {}
    for submission in submissions:
        if {item.case_id for item in submission.decisions} != set(by_case):
            raise ValueError("review submission does not cover every corpus case")
        for decision in submission.decisions:
            decisions_by_case.setdefault(decision.case_id, []).append(decision)
    adjudication_by_case = {item.case_id: item for item in adjudications}
    if len(adjudication_by_case) != len(adjudications):
        raise ValueError("adjudications must have unique case IDs")
    disagreement_ids = {
        case_id
        for case_id, decisions in decisions_by_case.items()
        if len(
            {
                (d.case_class, d.expected_gate_match, tuple(d.expected))
                for d in decisions
            }
        )
        > 1
    }
    if set(adjudication_by_case) - disagreement_ids:
        raise ValueError("adjudication contains a case without a disagreement")
    updated: list[SemanticGateHumanCase] = []
    for case in corpus.cases:
        decisions = decisions_by_case[case.case_id]
        signatures = {
            (d.case_class, d.expected_gate_match, tuple(d.expected)) for d in decisions
        }
        if len(signatures) > 1:
            adjudication = adjudication_by_case.get(case.case_id)
            if adjudication is None:
                raise ValueError("reviewer disagreement requires adjudication")
            final_class = adjudication.case_class
            final_match = adjudication.expected_gate_match
            final_confidence = adjudication.confidence_grade
            rationale = adjudication.rationale_code
            final_expected = adjudication.expected
            status = SemanticGateReviewStatus.ADJUDICATED
        else:
            decision = decisions[0]
            final_class = decision.case_class
            final_match = decision.expected_gate_match
            final_confidence = min(
                (d.confidence_grade for d in decisions), key=lambda x: "ABCD".index(x)
            )
            rationale = decision.rationale_code
            final_expected = decision.expected
            status = SemanticGateReviewStatus.REVIEWED
        expected_ids = {
            evidence_id for item in final_expected for evidence_id in item.evidence_ids
        }
        if expected_ids - {case.evidence_id}:
            raise ValueError("review decision references unknown case evidence")
        updated.append(
            case.model_copy(
                update={
                    "case_class": final_class,
                    "expected_gate_match": final_match,
                    "confidence_grade": final_confidence,
                    "confidence_rationale": rationale,
                    "expected": final_expected,
                    "reviewer_id": sorted(item.reviewer_id for item in submissions)[0],
                    "review_status": status,
                    "review_provenance": (
                        SemanticGateCorpusProvenance.AI_DRAFT_HUMAN_CONFIRMED
                        if case.review_provenance
                        is SemanticGateCorpusProvenance.AI_DRAFT
                        else SemanticGateCorpusProvenance.HUMAN_AUTHORED
                    ),
                }
            )
        )
    reviewers = tuple(
        SemanticGateCorpusReviewer(
            reviewer_id=item.reviewer_id,
            independence_statement=item.independence_statement,
            reviewed_case_count=len(item.decisions),
            reviewed_at=item.reviewed_at,
            provenance=(
                SemanticGateCorpusProvenance.AI_DRAFT_HUMAN_CONFIRMED
                if any(
                    case.review_provenance is SemanticGateCorpusProvenance.AI_DRAFT
                    for case in corpus.cases
                )
                else SemanticGateCorpusProvenance.HUMAN_AUTHORED
            ),
        )
        for item in submissions
    )
    return build_semantic_gate_human_corpus(
        gate_id=corpus.gate_id,
        signal=corpus.signal,
        cases=tuple(updated),
        reviewers=reviewers,
    )


def merge_semantic_gate_human_corpora(
    base: SemanticGateHumanCorpus,
    supplement: SemanticGateHumanCorpus,
) -> SemanticGateHumanCorpus:
    """Append a reviewed, non-overlapping supplement to a Gate corpus."""

    if not isinstance(base, SemanticGateHumanCorpus):
        raise TypeError("base semantic Gate corpus is required")
    if not isinstance(supplement, SemanticGateHumanCorpus):
        raise TypeError("supplement semantic Gate corpus is required")
    if base.gate_id != supplement.gate_id or base.signal != supplement.signal:
        raise ValueError("corpus Gate and signal must match")
    base_ids = {case.case_id for case in base.cases}
    supplement_ids = {case.case_id for case in supplement.cases}
    if base_ids & supplement_ids:
        raise ValueError("corpus supplements must not reuse Case IDs")
    if any(
        case.review_status is SemanticGateReviewStatus.DRAFT
        for case in supplement.cases
    ):
        raise ValueError("corpus supplement must be human-reviewed before merge")
    reviewers_by_id = {item.reviewer_id: item for item in base.reviewers}
    for reviewer in supplement.reviewers:
        existing = reviewers_by_id.get(reviewer.reviewer_id)
        if existing is None:
            reviewers_by_id[reviewer.reviewer_id] = reviewer
            continue
        if existing.provenance is not reviewer.provenance:
            raise ValueError("reviewer provenance conflicts across corpora")
        reviewed_at = max(existing.reviewed_at, reviewer.reviewed_at)
        statement = existing.independence_statement
        if reviewer.independence_statement not in statement:
            statement = f"{statement} {reviewer.independence_statement}"[:2048]
        reviewers_by_id[reviewer.reviewer_id] = existing.model_copy(
            update={
                "independence_statement": statement,
                "reviewed_case_count": existing.reviewed_case_count
                + reviewer.reviewed_case_count,
                "reviewed_at": reviewed_at,
            }
        )
    return build_semantic_gate_human_corpus(
        gate_id=base.gate_id,
        signal=base.signal,
        cases=base.cases + supplement.cases,
        reviewers=tuple(reviewers_by_id.values()),
    )


def verify_semantic_gate_human_corpus(corpus: SemanticGateHumanCorpus) -> bool:
    """Recompute the corpus digest without trusting serialized IDs."""

    if not isinstance(corpus, SemanticGateHumanCorpus):
        raise TypeError("semantic Gate corpus is required")
    return (
        corpus.corpus_sha256 == _corpus_digest(corpus)
        and corpus.corpus_id
        == f"semantic-gate-human-corpus-sha256:{corpus.corpus_sha256}"
    )


def load_semantic_gate_human_corpus(path: Path) -> SemanticGateHumanCorpus:
    """Load one bounded, regular, non-symlink corpus JSON file."""

    payload = _read_json(path, max_bytes=2_000_000, label="human corpus")
    return SemanticGateHumanCorpus.model_validate(payload)


def load_semantic_gate_review_submission(path: Path) -> SemanticGateReviewSubmission:
    """Load one bounded reviewer submission without exposing its contents."""

    payload = _read_json(path, max_bytes=2_000_000, label="review submission")
    return SemanticGateReviewSubmission.model_validate(payload)


def encode_semantic_gate_human_corpus_json(corpus: SemanticGateHumanCorpus) -> str:
    if not isinstance(corpus, SemanticGateHumanCorpus):
        raise TypeError("semantic Gate corpus encoder requires SemanticGateHumanCorpus")
    return (
        json.dumps(
            corpus.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def encode_semantic_gate_review_submission_json(
    submission: SemanticGateReviewSubmission,
) -> str:
    if not isinstance(submission, SemanticGateReviewSubmission):
        raise TypeError(
            "semantic Gate review encoder requires SemanticGateReviewSubmission"
        )
    return (
        json.dumps(
            submission.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_semantic_gate_corpus_text(corpus: SemanticGateHumanCorpus) -> str:
    coverage = corpus.coverage
    coverage_ready = (
        coverage.minimum_positive_met
        and coverage.minimum_eligible_negative_or_near_miss_met
    )
    return (
        "\n".join(
            (
                "AgentSec Semantic Gate Human Corpus",
                f"Gate: {corpus.gate_id}",
                f"Signal: {corpus.signal}",
                f"Corpus: {corpus.corpus_id}",
                f"Cases: {coverage.case_count}",
                f"Positive: {coverage.positive_count}",
                f"Eligible negative: {coverage.eligible_negative_count}",
                f"Near-miss: {coverage.near_miss_count}",
                f"Unknown: {coverage.unknown_count}",
                f"Reviewers: {coverage.reviewer_count}",
                (f"Coverage ready: {coverage_ready}"),
                "Authority: report_only=true; blocks=false; can_block_ci=false",
                "Human corpus is evidence only; it does not authorize a Gate.",
            )
        )
        + "\n"
    )


def _read_json(path: Path, *, max_bytes: int, label: str) -> dict[str, Any]:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds the safe size limit")
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is unreadable") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _corpus_digest(corpus: SemanticGateHumanCorpus) -> str:
    payload = corpus.model_dump(mode="json")
    payload.pop("corpus_id", None)
    payload.pop("corpus_sha256", None)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "SEMANTIC_GATE_HUMAN_CORPUS_FORMAT",
    "SEMANTIC_GATE_HUMAN_CORPUS_VERSION",
    "SEMANTIC_GATE_REVIEW_SUBMISSION_FORMAT",
    "SemanticGateAdjudication",
    "SemanticGateCaseClass",
    "SemanticGateCorpusCoverage",
    "SemanticGateCorpusProvenance",
    "SemanticGateCorpusReviewer",
    "SemanticGateHumanCase",
    "SemanticGateHumanCorpus",
    "SemanticGateReviewDecision",
    "SemanticGateReviewStatus",
    "SemanticGateReviewSubmission",
    "build_semantic_gate_human_corpus",
    "encode_semantic_gate_human_corpus_json",
    "encode_semantic_gate_review_submission_json",
    "import_semantic_gate_review",
    "merge_semantic_gate_human_corpora",
    "load_semantic_gate_human_corpus",
    "load_semantic_gate_review_submission",
    "render_semantic_gate_corpus_text",
    "verify_semantic_gate_human_corpus",
]

"""P3-17 human feedback on false positives and false negatives.

Records reviewer-confirmed feedback about semantic misdetections and
closes the loop over later runs: every feedback row targets one case
judgment (kind, category, disposition) as either a false positive (the
candidate should not have been flagged) or a false negative (an expected
judgment was missed), and ``evaluate_feedback_resolution`` re-runs the
same frozen scenario packs to report which rows are now resolved.

The drafting path is deterministic and value-free: ``SemanticFeedbackDraft``
compares one Shadow adapter run against the gold-inherited expectations
of the P3-12/P3-13 packs (populated through their converted evaluation
cases) and emits DRAFT rows; a human reviewer confirms or rejects each
row through the submission workflow, and only ``ai_draft_human_confirmed``
or ``human_authored`` sets are accepted — ``ai_assisted`` provenance is
rejected outright, mirroring ADR-0092's gold-label rule because
``LLM output is evidence, not an authorization decision``.

Feedback grants no calibration, rule-publication, Policy, CI, Hard Gate,
or release authority; resolution reports are evidence for human review
only and never claim runtime facts.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.semantic.evaluation import SemanticEvaluationCase
from agentsec.semantic.invocation import (
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationError,
)
from agentsec.semantic.models import (
    SemanticCandidateDisposition,
    SemanticCandidateKind,
)
from agentsec.semantic.scenarios import (
    AgentDojoScenarioSet,
    InjecAgentScenarioSet,
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
)

SEMANTIC_FEEDBACK_SET_VERSION = "0.1.0"
SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION = "0.1.0"
_MAX_FEEDBACK_ROWS = 256
_MAX_FEEDBACK_CASES = 256
_MAX_NOTE_CHARACTERS = 512
_MAX_STATEMENT_CHARACTERS = 2048
_MAX_UNEVALUATED_CASES = 64
_ROW_ID_PATTERN = r"^[a-z][a-z0-9._:-]{3,255}$"
_FEEDBACK_EVIDENCE_ID = Annotated[
    str, Field(pattern=r"^semantic-evidence-sha256:[0-9a-f]{64}$")
]
_SHA_PATTERN = r"^[0-9a-f]{64}$"
_CASE_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_FORBIDDEN_CATEGORY = "scan_coverage"
_EPSILON = 1e-9

_FEEDBACK_NOTE = (
    "Reviewer-confirmed false-positive and false-negative rows over the "
    "frozen scenario packs. Resolution reports are detection-based "
    "evidence for human review; feedback never gains calibration, "
    "publication, Policy, CI, or runtime authority."
)


class SemanticFeedbackError(RuntimeError):
    """Safe feedback failure without echoing any corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic feedback failed ({code}).")


FeedbackPack = AgentDojoScenarioSet | InjecAgentScenarioSet


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class FeedbackIssueType(StrEnum):
    """The misdetection kind one feedback row reports."""

    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class FeedbackRationaleCode(StrEnum):
    """Closed reviewer rationale vocabulary, aligned to the issue type."""

    MISSED_JUDGMENT = "missed_judgment"
    OVERFLAGGED_JUDGMENT = "overflagged_judgment"


class FeedbackRowStatus(StrEnum):
    """Draft rows await confirmation; sets only carry confirmed rows."""

    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class FeedbackProvenance(StrEnum):
    """How the judgments in a feedback set were authored."""

    HUMAN_AUTHORED = "human_authored"
    AI_DRAFT_HUMAN_CONFIRMED = "ai_draft_human_confirmed"
    AI_ASSISTED = "ai_assisted"


class FeedbackResolutionOutcome(StrEnum):
    """One row's issue status against a later Shadow run."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    UNEVALUATED = "unevaluated"


class SemanticFeedbackCaseRow(_Strict):
    """One feedback row: one case judgment plus its issue type."""

    format: Literal["agentsec-p3-17-feedback-row"] = "agentsec-p3-17-feedback-row"
    schema_version: Literal["0.1.0"] = "0.1.0"
    row_id: Annotated[str, Field(pattern=_ROW_ID_PATTERN)]
    case_id: Annotated[str, Field(pattern=_CASE_ID_PATTERN)]
    issue_type: FeedbackIssueType
    kind: SemanticCandidateKind
    category: Annotated[str, Field(min_length=1, max_length=64)]
    disposition: SemanticCandidateDisposition
    evidence_ids: tuple[_FEEDBACK_EVIDENCE_ID, ...]
    rationale_code: FeedbackRationaleCode
    status: FeedbackRowStatus
    note: Annotated[str, Field(max_length=_MAX_NOTE_CHARACTERS)] | None = None

    @field_validator("category", "note")
    @classmethod
    def text_must_be_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("feedback text contains unsafe characters")
        return value

    @field_validator("category")
    @classmethod
    def category_must_not_redefine_coverage(cls, value: str) -> str:
        if value == _FORBIDDEN_CATEGORY:
            raise ValueError("feedback rows cannot target scan coverage")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if not values or values != tuple(sorted(set(values))):
            raise ValueError(
                "feedback Evidence IDs must be sorted, unique, and non-empty"
            )
        return values

    @model_validator(mode="after")
    def row_must_be_coherent(self) -> SemanticFeedbackCaseRow:
        if self.issue_type is FeedbackIssueType.FALSE_NEGATIVE and (
            self.rationale_code is not FeedbackRationaleCode.MISSED_JUDGMENT
        ):
            raise ValueError("false-negative rows require missed_judgment rationale")
        if self.issue_type is FeedbackIssueType.FALSE_POSITIVE and (
            self.rationale_code is not FeedbackRationaleCode.OVERFLAGGED_JUDGMENT
        ):
            raise ValueError(
                "false-positive rows require overflagged_judgment rationale"
            )
        return self

    def row_digest_payload(self) -> dict[str, object]:
        return {
            "row_id": self.row_id,
            "case_id": self.case_id,
            "issue_type": self.issue_type.value,
            "kind": self.kind.value,
            "category": self.category,
            "disposition": self.disposition.value,
            "evidence_ids": list(self.evidence_ids),
            "rationale_code": self.rationale_code.value,
            "status": self.status.value,
            "note": self.note,
        }


class _FeedbackContext(_Strict):
    """Value-free binding of feedback to its drafting run and packs."""

    source_pack_sha256: Annotated[
        tuple[Annotated[str, Field(pattern=_SHA_PATTERN)], ...],
        Field(min_length=1, max_length=4),
    ]
    evaluation_provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    evaluation_model_id: Annotated[str, Field(min_length=1, max_length=160)]
    evaluation_case_count: Annotated[int, Field(ge=1, le=_MAX_FEEDBACK_CASES)]

    @field_validator("source_pack_sha256")
    @classmethod
    def pack_digests_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("feedback source pack digests must be sorted and unique")
        return values


class SemanticFeedbackDraft(_Strict):
    """Deterministic draft of FP/FN rows for one drafting Shadow run."""

    format: Literal["agentsec-p3-17-semantic-feedback-draft"] = (
        "agentsec-p3-17-semantic-feedback-draft"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    draft_sha256: Annotated[str, Field(pattern=_SHA_PATTERN)]
    context: _FeedbackContext
    draft_row_count: Annotated[int, Field(ge=0, le=_MAX_FEEDBACK_ROWS)]
    false_positive_row_count: Annotated[int, Field(ge=0)]
    false_negative_row_count: Annotated[int, Field(ge=0)]
    unevaluated_case_count: Annotated[int, Field(ge=0, le=_MAX_UNEVALUATED_CASES)]
    unevaluated_case_ids: Annotated[
        tuple[Annotated[str, Field(pattern=_CASE_ID_PATTERN)], ...],
        Field(max_length=_MAX_UNEVALUATED_CASES),
    ] = ()
    rows: Annotated[
        tuple[SemanticFeedbackCaseRow, ...],
        Field(max_length=_MAX_FEEDBACK_ROWS),
    ]
    report_only: Literal[True] = True
    blocks: Literal[False] = False

    @model_validator(mode="after")
    def draft_must_be_coherent(self) -> SemanticFeedbackDraft:
        if self.draft_row_count != len(self.rows):
            raise ValueError("feedback draft row count is inconsistent")
        row_ids = tuple(row.row_id for row in self.rows)
        if row_ids != tuple(sorted(set(row_ids))):
            raise ValueError("feedback draft rows must be sorted by row ID and unique")
        if any(row.status is not FeedbackRowStatus.DRAFT for row in self.rows):
            raise ValueError("feedback drafts may only carry draft rows")
        if (
            self.false_positive_row_count + self.false_negative_row_count
            != self.draft_row_count
        ):
            raise ValueError("feedback draft issue counts are inconsistent")
        if len(self.unevaluated_case_ids) != self.unevaluated_case_count:
            raise ValueError("feedback draft unevaluated counts are inconsistent")
        expected = _feedback_digest(
            "agentsec-p3-17-semantic-feedback-draft",
            [row.row_digest_payload() for row in self.rows],
            self.context,
        )
        if self.draft_sha256 != expected:
            raise ValueError("feedback draft digest is inconsistent")
        return self


class SemanticFeedbackSet(_Strict):
    """Reviewer-confirmed FP/FN rows; the import target of the workflow."""

    format: Literal["agentsec-p3-17-semantic-feedback-set"] = (
        "agentsec-p3-17-semantic-feedback-set"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    feedback_sha256: Annotated[str, Field(pattern=_SHA_PATTERN)]
    label_provenance: FeedbackProvenance
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independence_statement: Annotated[
        str, Field(min_length=20, max_length=_MAX_STATEMENT_CHARACTERS)
    ]
    context: _FeedbackContext
    row_count: Annotated[int, Field(ge=1, le=_MAX_FEEDBACK_ROWS)]
    false_positive_row_count: Annotated[int, Field(ge=0)]
    false_negative_row_count: Annotated[int, Field(ge=0)]
    rows: Annotated[
        tuple[SemanticFeedbackCaseRow, ...],
        Field(min_length=1, max_length=_MAX_FEEDBACK_ROWS),
    ]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _FEEDBACK_NOTE
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    calibration_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    gate_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def set_must_be_coherent(self) -> SemanticFeedbackSet:
        if self.label_provenance is FeedbackProvenance.AI_ASSISTED:
            raise ValueError("ai_assisted feedback cannot back a confirmed set")
        if self.row_count != len(self.rows):
            raise ValueError("feedback row count is inconsistent")
        row_ids = tuple(row.row_id for row in self.rows)
        if row_ids != tuple(sorted(set(row_ids))):
            raise ValueError("feedback rows must be sorted by row ID and unique")
        if any(row.status is not FeedbackRowStatus.CONFIRMED for row in self.rows):
            raise ValueError("confirmed feedback sets may only carry confirmed rows")
        if (
            self.false_positive_row_count + self.false_negative_row_count
            != self.row_count
        ):
            raise ValueError("feedback issue counts are inconsistent")
        true_positive = sum(
            row.issue_type is FeedbackIssueType.FALSE_POSITIVE for row in self.rows
        )
        if true_positive != self.false_positive_row_count:
            raise ValueError("feedback false-positive count is inconsistent")
        expected = _feedback_digest(
            "agentsec-p3-17-semantic-feedback-set",
            [row.row_digest_payload() for row in self.rows],
            self.context,
        )
        if self.feedback_sha256 != expected:
            raise ValueError("feedback set digest is inconsistent")
        return self


class FeedbackResolutionRow(_Strict):
    """One row's outcome in a feedback loop evaluation; value-free."""

    row_id: Annotated[str, Field(pattern=_ROW_ID_PATTERN)]
    case_id: Annotated[str, Field(pattern=_CASE_ID_PATTERN)]
    issue_type: FeedbackIssueType
    outcome: FeedbackResolutionOutcome

    @model_validator(mode="after")
    def outcome_must_have_a_reason(self) -> FeedbackResolutionRow:
        _assert_row_id_matches(self.row_id, self.case_id, self.issue_type)
        return self


class SemanticFeedbackLoopReport(_Strict):
    """Report-only resolution status of one set against one later run."""

    format: Literal["agentsec-p3-17-semantic-feedback-loop-report"] = (
        "agentsec-p3-17-semantic-feedback-loop-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    loop_sha256: Annotated[str, Field(pattern=_SHA_PATTERN)]
    feedback_sha256: Annotated[str, Field(pattern=_SHA_PATTERN)]
    source_pack_sha256: Annotated[
        tuple[Annotated[str, Field(pattern=_SHA_PATTERN)], ...],
        Field(min_length=1),
    ]
    evaluation_provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    evaluation_model_id: Annotated[str, Field(min_length=1, max_length=160)]
    row_outcome_count: Annotated[int, Field(ge=1, le=_MAX_FEEDBACK_ROWS)]
    resolved_row_count: Annotated[int, Field(ge=0)]
    unresolved_row_count: Annotated[int, Field(ge=0)]
    unevaluated_row_count: Annotated[int, Field(ge=0)]
    resolution_rate: Annotated[float, Field(ge=0, le=1)]
    evaluation_complete: bool
    rows: Annotated[
        tuple[FeedbackResolutionRow, ...],
        Field(min_length=1, max_length=_MAX_FEEDBACK_ROWS),
    ]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _FEEDBACK_NOTE
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    calibration_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    gate_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def loop_report_must_be_coherent(self) -> SemanticFeedbackLoopReport:
        if self.row_outcome_count != len(self.rows):
            raise ValueError("feedback loop row count is inconsistent")
        row_ids = tuple(row.row_id for row in self.rows)
        if row_ids != tuple(sorted(set(row_ids))):
            raise ValueError("feedback loop rows must be sorted and unique")
        classified = (
            self.resolved_row_count
            + self.unresolved_row_count
            + self.unevaluated_row_count
        )
        if classified != self.row_outcome_count:
            raise ValueError("feedback loop outcome counts are inconsistent")
        by_outcome = {
            FeedbackResolutionOutcome.RESOLVED: sum(
                row.outcome is FeedbackResolutionOutcome.RESOLVED for row in self.rows
            ),
            FeedbackResolutionOutcome.UNRESOLVED: sum(
                row.outcome is FeedbackResolutionOutcome.UNRESOLVED for row in self.rows
            ),
            FeedbackResolutionOutcome.UNEVALUATED: sum(
                row.outcome is FeedbackResolutionOutcome.UNEVALUATED
                for row in self.rows
            ),
        }
        if (
            by_outcome[FeedbackResolutionOutcome.RESOLVED] != self.resolved_row_count
            or by_outcome[FeedbackResolutionOutcome.UNRESOLVED]
            != self.unresolved_row_count
            or by_outcome[FeedbackResolutionOutcome.UNEVALUATED]
            != self.unevaluated_row_count
        ):
            raise ValueError("feedback loop rows do not match outcome counts")
        if self.evaluation_complete and self.unevaluated_row_count:
            raise ValueError("complete loop evaluation cannot carry unevaluated rows")
        total_evaluated = self.resolved_row_count + self.unresolved_row_count
        if total_evaluated == 0:
            if abs(self.resolution_rate) > _EPSILON:
                raise ValueError("empty loop evaluation cannot claim resolutions")
        elif abs(self.resolution_rate - (self.resolved_row_count / total_evaluated)) > (
            _EPSILON
        ):
            raise ValueError("resolution rate does not match resolved rows")
        expected = _feedback_digest(
            "agentsec-p3-17-semantic-feedback-loop-report",
            [
                {
                    "row_id": row.row_id,
                    "issue_type": row.issue_type.value,
                    "outcome": row.outcome.value,
                }
                for row in self.rows
            ],
            {
                "feedback_sha256": self.feedback_sha256,
                "source_pack_sha256": list(self.source_pack_sha256),
                "evaluation_provider_id": self.evaluation_provider_id,
                "evaluation_model_id": self.evaluation_model_id,
            },
        )
        if self.loop_sha256 != expected:
            raise ValueError("feedback loop digest is inconsistent")
        return self


def build_semantic_feedback_draft(
    packs: tuple[FeedbackPack, ...],
    adapter: SemanticShadowInvocationAdapter,
    *,
    source_pack_sha256: tuple[str, ...],
) -> SemanticFeedbackDraft:
    """Derive deterministic FP/FN draft rows from one Shadow run."""

    if not isinstance(packs, tuple) or not packs:
        raise SemanticFeedbackError("packs_missing")
    if not isinstance(adapter, SemanticShadowInvocationAdapter):
        raise TypeError("feedback drafting requires SemanticShadowInvocationAdapter")
    if not isinstance(source_pack_sha256, tuple) or not source_pack_sha256:
        raise SemanticFeedbackError("source_pack_sha_missing")
    for digest in source_pack_sha256:
        if not isinstance(digest, str) or len(digest) != 64:
            raise SemanticFeedbackError("source_pack_sha_invalid")
    cases = _pack_evaluation_cases(packs)
    if len(cases) > _MAX_FEEDBACK_CASES:
        raise SemanticFeedbackError("case_bound_exceeded")
    signatures, unevaluated = _case_signatures(cases, adapter)
    metadata = adapter.provider_metadata

    rows: list[SemanticFeedbackCaseRow] = []
    for case in cases:
        case_id = case.case_id
        predicted = signatures.get(case_id)
        if predicted is None:
            continue
        expected = frozenset(_expected_signature_counter(case))
        for signature in sorted(expected - predicted):
            rows.append(
                _feedback_row(
                    case_id=case_id,
                    issue_type=FeedbackIssueType.FALSE_NEGATIVE,
                    signature=signature,
                    evidence_ids=case_evidence_ids(case),
                )
            )
        for signature in sorted(predicted - expected):
            rows.append(
                _feedback_row(
                    case_id=case_id,
                    issue_type=FeedbackIssueType.FALSE_POSITIVE,
                    signature=signature,
                    evidence_ids=case_evidence_ids(case),
                )
            )
    rows.sort(key=lambda row: row.row_id)
    if len(rows) > _MAX_FEEDBACK_ROWS:
        raise SemanticFeedbackError("row_bound_exceeded")
    context = _FeedbackContext(
        source_pack_sha256=tuple(sorted(set(source_pack_sha256))),
        evaluation_provider_id=metadata.provider_id,
        evaluation_model_id=metadata.model_id,
        evaluation_case_count=len(cases),
    )
    return SemanticFeedbackDraft(
        draft_sha256=_feedback_digest(
            "agentsec-p3-17-semantic-feedback-draft",
            [row.row_digest_payload() for row in rows],
            context,
        ),
        context=context,
        draft_row_count=len(rows),
        false_positive_row_count=sum(
            row.issue_type is FeedbackIssueType.FALSE_POSITIVE for row in rows
        ),
        false_negative_row_count=sum(
            row.issue_type is FeedbackIssueType.FALSE_NEGATIVE for row in rows
        ),
        unevaluated_case_count=len(unevaluated),
        unevaluated_case_ids=tuple(sorted(unevaluated)),
        rows=tuple(rows),
    )


def evaluate_feedback_resolution(
    feedback: SemanticFeedbackSet,
    packs: tuple[FeedbackPack, ...],
    adapter: SemanticShadowInvocationAdapter,
) -> SemanticFeedbackLoopReport:
    """Report which confirmed FP/FN rows a later run has resolved."""

    if not isinstance(feedback, SemanticFeedbackSet):
        raise TypeError("feedback resolution requires SemanticFeedbackSet")
    if not isinstance(packs, tuple) or not packs:
        raise SemanticFeedbackError("packs_missing")
    if not isinstance(adapter, SemanticShadowInvocationAdapter):
        raise TypeError("feedback resolution requires SemanticShadowInvocationAdapter")
    cases = _pack_evaluation_cases(packs)
    case_by_id = {case.case_id: case for case in cases}
    signatures, unevaluated = _case_signatures(cases, adapter)
    metadata = adapter.provider_metadata

    outcome_rows: list[FeedbackResolutionRow] = []
    resolved = unresolved = unevaluated_rows = 0
    for row in feedback.rows:
        if row.case_id in case_by_id and row.case_id not in unevaluated:
            predicted_signatures = signatures.get(row.case_id)
        else:
            predicted_signatures = None
        if predicted_signatures is None:
            outcome = FeedbackResolutionOutcome.UNEVALUATED
        else:
            signature = _row_signature(row)
            if row.issue_type is FeedbackIssueType.FALSE_NEGATIVE:
                matched = signature in predicted_signatures
            else:
                matched = signature not in predicted_signatures
            outcome = (
                FeedbackResolutionOutcome.RESOLVED
                if matched
                else FeedbackResolutionOutcome.UNRESOLVED
            )
        if outcome is FeedbackResolutionOutcome.RESOLVED:
            resolved += 1
        elif outcome is FeedbackResolutionOutcome.UNRESOLVED:
            unresolved += 1
        else:
            unevaluated_rows += 1
        outcome_rows.append(
            FeedbackResolutionRow(
                row_id=row.row_id,
                case_id=row.case_id,
                issue_type=row.issue_type,
                outcome=outcome,
            )
        )
    outcome_rows.sort(key=lambda item: item.row_id)
    total_evaluated = resolved + unresolved
    resolution_rate = resolved / total_evaluated if total_evaluated else 0.0
    source_digests = tuple(sorted(set(feedback.context.source_pack_sha256)))
    return SemanticFeedbackLoopReport(
        loop_sha256=_feedback_digest(
            "agentsec-p3-17-semantic-feedback-loop-report",
            [
                {
                    "row_id": row.row_id,
                    "issue_type": row.issue_type.value,
                    "outcome": row.outcome.value,
                }
                for row in outcome_rows
            ],
            {
                "feedback_sha256": feedback.feedback_sha256,
                "source_pack_sha256": list(source_digests),
                "evaluation_provider_id": metadata.provider_id,
                "evaluation_model_id": metadata.model_id,
            },
        ),
        feedback_sha256=feedback.feedback_sha256,
        source_pack_sha256=source_digests,
        evaluation_provider_id=metadata.provider_id,
        evaluation_model_id=metadata.model_id,
        row_outcome_count=len(outcome_rows),
        resolved_row_count=resolved,
        unresolved_row_count=unresolved,
        unevaluated_row_count=unevaluated_rows,
        resolution_rate=resolution_rate,
        evaluation_complete=unevaluated_rows == 0,
        rows=tuple(outcome_rows),
    )


def build_semantic_feedback_set(
    draft: SemanticFeedbackDraft,
    *,
    confirmed_row_ids: tuple[str, ...],
    reviewer_id: str,
    independence_statement: str,
    label_provenance: FeedbackProvenance = (
        FeedbackProvenance.AI_DRAFT_HUMAN_CONFIRMED
    ),
    row_notes: dict[str, str] | None = None,
) -> SemanticFeedbackSet:
    """Confirm selected draft rows into a feedback set.

    The import path for the human-in-the-loop workflow: the reviewer
    confirms a subset of draft rows (rejected rows are dropped), and the
    resulting set binds reviewer identity, an independence statement,
    provenance, and a recomputed digest. ``ai_assisted`` provenance is
    rejected by the set model itself.
    """

    if not isinstance(draft, SemanticFeedbackDraft):
        raise TypeError("feedback set confirmation requires SemanticFeedbackDraft")
    if not isinstance(confirmed_row_ids, tuple):
        raise SemanticFeedbackError("confirmed_row_ids_invalid")
    if not confirmed_row_ids:
        raise SemanticFeedbackError("confirmed_row_ids_missing")
    notes = row_notes or {}
    by_id = {row.row_id: row for row in draft.rows}
    for row_id in confirmed_row_ids:
        if row_id not in by_id:
            raise SemanticFeedbackError("unknown_row_id")
    confirmed_ids = sorted(set(confirmed_row_ids))
    rows: list[dict[str, object]] = []
    for row_id in confirmed_ids:
        row = by_id[row_id]
        payload = row.row_digest_payload()
        payload["status"] = FeedbackRowStatus.CONFIRMED.value
        note = notes.get(row_id)
        if note is not None:
            payload["note"] = note
        rows.append(payload)
    context_payload = {
        "source_pack_sha256": list(draft.context.source_pack_sha256),
        "evaluation_provider_id": draft.context.evaluation_provider_id,
        "evaluation_model_id": draft.context.evaluation_model_id,
        "evaluation_case_count": draft.context.evaluation_case_count,
    }
    false_positive = sum(
        row["issue_type"] == FeedbackIssueType.FALSE_POSITIVE.value for row in rows
    )
    digest = _feedback_digest(
        "agentsec-p3-17-semantic-feedback-set",
        rows,
        context_payload,
    )
    return SemanticFeedbackSet(
        feedback_sha256=digest,
        label_provenance=label_provenance,
        reviewer_id=reviewer_id,
        independence_statement=independence_statement,
        context=context_payload,  # type: ignore[arg-type]
        row_count=len(rows),
        false_positive_row_count=false_positive,
        false_negative_row_count=len(rows) - false_positive,
        rows=rows,  # type: ignore[arg-type]
    )


def load_semantic_feedback_set(path: Path) -> SemanticFeedbackSet:
    """Load and validate a confirmed feedback set JSON artifact."""

    if not isinstance(path, Path):
        raise TypeError("feedback set path must be a Path")
    if path.is_symlink():
        raise SemanticFeedbackError("unsafe_feedback_set_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticFeedbackError("feedback_set_unreadable") from error
    if not isinstance(payload, dict):
        raise SemanticFeedbackError("feedback_set_invalid")
    try:
        return SemanticFeedbackSet.model_validate(payload)
    except ValueError as error:
        raise SemanticFeedbackError("feedback_set_invalid") from error


def encode_semantic_feedback_json(value: SemanticFeedbackSet) -> str:
    """Encode a confirmed feedback set as canonical versioned JSON."""

    if not isinstance(value, SemanticFeedbackSet):
        raise TypeError("feedback encoder requires SemanticFeedbackSet")
    return value.model_dump_json(indent=2)


def encode_semantic_feedback_loop_json(
    value: SemanticFeedbackLoopReport,
) -> str:
    """Encode a feedback loop report as canonical versioned JSON."""

    if not isinstance(value, SemanticFeedbackLoopReport):
        raise TypeError("feedback loop encoder requires SemanticFeedbackLoopReport")
    return value.model_dump_json(indent=2)


def _pack_evaluation_cases(
    packs: tuple[FeedbackPack, ...],
) -> tuple[SemanticEvaluationCase, ...]:
    """Merge pack cases; shared case IDs must be identical across packs.

    The P3-12/P3-13 packs intentionally reuse a small set of normal cases
    (ADR-0095): one case ID may appear in both packs with exactly the same
    content. Duplicate IDs with divergent content fail closed.
    """

    cases: list[SemanticEvaluationCase] = []
    for pack in packs:
        if isinstance(pack, AgentDojoScenarioSet):
            cases.extend(build_scenario_evaluation_cases(pack))
        elif isinstance(pack, InjecAgentScenarioSet):
            cases.extend(build_injecagent_evaluation_cases(pack))
        else:
            raise SemanticFeedbackError("packs_invalid")
    by_id: dict[str, SemanticEvaluationCase] = {}
    for case in cases:
        existing = by_id.get(case.case_id)
        if existing is not None:
            if existing.model_dump(mode="json") != case.model_dump(mode="json"):
                raise SemanticFeedbackError("duplicate_analysis_id")
            continue
        by_id[case.case_id] = case
    merged = list(by_id.values())
    merged.sort(key=lambda case: case.case_id)
    return tuple(merged)


def _case_signatures(
    cases: tuple[SemanticEvaluationCase, ...],
    adapter: SemanticShadowInvocationAdapter,
) -> tuple[dict[str, frozenset[tuple[str, str, str]]], set[str]]:
    """Invoke every case once and collect its predicted signatures."""

    signatures: dict[str, frozenset[tuple[str, str, str]]] = {}
    unevaluated: set[str] = set()
    for case in cases:
        try:
            result = adapter.invoke(case.semantic_input)
        except SemanticShadowInvocationError:
            unevaluated.add(case.case_id)
            continue
        signatures[case.case_id] = frozenset(
            (
                candidate.kind.value,
                candidate.category.value,
                candidate.disposition.value,
            )
            for candidate in result.analysis.candidates
        )
    return signatures, unevaluated


def _expected_signature_counter(
    case: SemanticEvaluationCase,
) -> dict[tuple[str, str, str], int]:
    return {
        (item.kind.value, item.category, item.disposition.value): 1
        for item in case.expected
    }


def case_evidence_ids(case: SemanticEvaluationCase) -> tuple[str, ...]:
    """Return a case's sorted unique Evidence IDs."""

    return tuple(sorted({chunk.evidence_id for chunk in case.semantic_input.evidence}))


def _feedback_row(
    *,
    case_id: str,
    issue_type: FeedbackIssueType,
    signature: tuple[str, str, str],
    evidence_ids: tuple[str, ...],
) -> SemanticFeedbackCaseRow:
    kind, category, disposition = signature
    row_id = f"{case_id}:{issue_type.value}:{kind}:{category}:{disposition}"
    return SemanticFeedbackCaseRow(
        row_id=row_id,
        case_id=case_id,
        issue_type=issue_type,
        kind=SemanticCandidateKind(kind),
        category=category,
        disposition=SemanticCandidateDisposition(disposition),
        evidence_ids=evidence_ids,
        rationale_code=(
            FeedbackRationaleCode.MISSED_JUDGMENT
            if issue_type is FeedbackIssueType.FALSE_NEGATIVE
            else FeedbackRationaleCode.OVERFLAGGED_JUDGMENT
        ),
        status=FeedbackRowStatus.DRAFT,
    )


def _row_signature(row: SemanticFeedbackCaseRow) -> tuple[str, str, str]:
    return (row.kind.value, row.category, row.disposition.value)


def _assert_row_id_matches(
    row_id: str, case_id: str, issue_type: FeedbackIssueType
) -> None:
    prefix = f"{case_id}:{issue_type.value}:"
    if not row_id.startswith(prefix):
        raise ValueError("feedback row ID does not match its case and issue type")


def _feedback_digest(
    family: str,
    row_payloads: list[dict[str, object]],
    context: dict[str, object] | _FeedbackContext,
) -> str:
    if isinstance(context, _FeedbackContext):
        context_payload: dict[str, object] = {
            "source_pack_sha256": list(context.source_pack_sha256),
            "evaluation_provider_id": context.evaluation_provider_id,
            "evaluation_model_id": context.evaluation_model_id,
            "evaluation_case_count": context.evaluation_case_count,
        }
    else:
        context_payload = dict(context)
    payload = {
        "family": family,
        "rows": row_payloads,
        "context": context_payload,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


__all__ = [
    "SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION",
    "SEMANTIC_FEEDBACK_SET_VERSION",
    "FeedbackIssueType",
    "FeedbackProvenance",
    "FeedbackRationaleCode",
    "FeedbackResolutionOutcome",
    "FeedbackRowStatus",
    "SemanticFeedbackCaseRow",
    "SemanticFeedbackDraft",
    "SemanticFeedbackError",
    "SemanticFeedbackLoopReport",
    "SemanticFeedbackSet",
    "build_semantic_feedback_draft",
    "build_semantic_feedback_set",
    "encode_semantic_feedback_json",
    "encode_semantic_feedback_loop_json",
    "evaluate_feedback_resolution",
    "load_semantic_feedback_set",
]

"""P3-17 human FP/FN feedback and closed-loop resolution tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentsec.semantic import (
    FeedbackIssueType,
    FeedbackProvenance,
    FeedbackResolutionOutcome,
    FeedbackRowStatus,
    SemanticFeedbackDraft,
    SemanticFeedbackError,
    SemanticFeedbackLoopReport,
    SemanticFeedbackSet,
    SemanticShadowInvocationAdapter,
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
    build_semantic_feedback_draft,
    build_semantic_feedback_set,
    encode_semantic_feedback_json,
    encode_semantic_feedback_loop_json,
    evaluate_feedback_resolution,
    export_semantic_feedback_json_schemas,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
    load_semantic_feedback_set,
)
from agentsec.semantic.invocation import (
    SemanticShadowInvocationError,
    SemanticShadowInvocationErrorCode,
)
from agentsec.semantic.models import (
    SemanticCandidateKind,
    SemanticModelOutput,
)
from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderResponse,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
P3_12_PACK = REPOSITORY_ROOT / "pilots" / "agentdojo-style-p3-12" / "scenarios.json"
P3_13_PACK = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13" / "scenarios.json"
DRAFT_SUBMISSION = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-feedback-p3-17"
    / "draft"
    / "feedback-draft-submission.template.json"
)
FROZEN_FEEDBACK_SCHEMAS = (
    REPOSITORY_ROOT
    / "schemas"
    / "semantic-analysis"
    / "semantic-feedback-set.schema.json",
    REPOSITORY_ROOT
    / "schemas"
    / "semantic-analysis"
    / "semantic-feedback-loop-report.schema.json",
)


def _packs() -> tuple[Any, Any]:
    assert P3_12_PACK.exists() and P3_13_PACK.exists()
    return (
        load_agent_dojo_scenario_set(P3_12_PACK),
        load_injecagent_scenario_set(P3_13_PACK),
    )


def _pack_digests() -> tuple[str, ...]:
    return (
        hashlib.sha256(P3_12_PACK.read_bytes()).hexdigest(),
        hashlib.sha256(P3_13_PACK.read_bytes()).hexdigest(),
    )


def _case_map() -> dict[str, Any]:
    p12, p13 = _packs()
    merged = {
        case.case_id: case
        for case in (
            build_scenario_evaluation_cases(p12)
            + build_injecagent_evaluation_cases(p13)
        )
    }
    return merged


def _attack_ids() -> set[str]:
    p12, p13 = _packs()
    return {s.attack_case.case_id for s in p12.scenarios} | {
        s.attack_case.case_id for s in p13.scenarios
    }


class _FeedbackEchoProvider:
    """Approved fixture whose per-case controls drive drafts and loops."""

    def __init__(
        self,
        *,
        drop: set[str] | None = None,
        extra: set[str] | None = None,
        fail: set[str] | None = None,
    ) -> None:
        all_cases = _case_map()
        self._all = all_cases
        self.drop = set() if drop is None else drop
        self.extra = set() if extra is None else extra
        self.fail = set() if fail is None else fail
        self.metadata = SemanticProviderMetadata()

    def invoke(self, request: Any) -> SemanticProviderResponse:
        if request.analysis_id in self.fail:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE,
            )
        case = self._all[request.analysis_id]
        evidence_id = case.semantic_input.evidence[0].evidence_id
        items: list[dict[str, str]] = []
        if request.analysis_id not in self.drop:
            items = [
                {
                    "kind": item.kind.value,
                    "category": item.category,
                    "disposition": item.disposition.value,
                }
                for item in case.expected
            ]
        if request.analysis_id in self.extra:
            used = {
                (item["kind"], item["category"], item["disposition"]) for item in items
            }
            for kind in SemanticCandidateKind:
                signature = (kind.value, "obfuscation", "supported")
                if signature not in used:
                    items.append(
                        {
                            "kind": signature[0],
                            "category": signature[1],
                            "disposition": signature[2],
                        }
                    )
                    break
        output = SemanticModelOutput.model_validate(
            {
                "analysis_id": request.analysis_id,
                "analyzed_evidence_ids": [evidence_id],
                "candidates": [
                    {
                        "candidate_key": f"candidate-{index:02d}",
                        "kind": item["kind"],
                        "category": item["category"],
                        "disposition": item["disposition"],
                        "summary": "Fixture judgment for feedback replay.",
                        "evidence_ids": [evidence_id],
                    }
                    for index, item in enumerate(items, start=1)
                ],
            }
        )
        raw = json.dumps(
            output.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
        )
        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            completion_status="complete",
            output_json=raw,
            output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            input_tokens=1,
            output_tokens=1,
        )


def _adapter(**controls: Any) -> SemanticShadowInvocationAdapter:
    return SemanticShadowInvocationAdapter(provider=_FeedbackEchoProvider(**controls))


def _draft(
    *,
    drop: set[str] | None = None,
    extra: set[str] | None = None,
) -> SemanticFeedbackDraft:
    p12, p13 = _packs()
    return build_semantic_feedback_draft(
        (p12, p13),
        _adapter(drop=drop, extra=extra),
        source_pack_sha256=_pack_digests(),
    )


def _confirmed_set(
    draft: SemanticFeedbackDraft,
    *,
    reviewer: str = "呈屿",
    statement: str = ("本人逐行复核了 AI 起草的 FP/FN 反馈行，并确认每行最终判断。"),
    select: set[str] | None = None,
) -> SemanticFeedbackSet:
    row_ids = (
        tuple(sorted(row.row_id for row in draft.rows))
        if select is None
        else tuple(sorted(select))
    )
    return build_semantic_feedback_set(
        draft,
        confirmed_row_ids=row_ids,
        reviewer_id=reviewer,
        independence_statement=statement,
    )


def test_draft_identifies_false_negatives_and_false_positives() -> None:
    attack_ids = sorted(_attack_ids())
    normal_ids = sorted(
        case_id for case_id in _case_map() if case_id not in _attack_ids()
    )
    draft = _draft(drop=set(attack_ids[:3]), extra=set(normal_ids[:2]))
    assert draft.draft_row_count >= 4
    assert draft.false_positive_row_count == 2
    assert draft.false_negative_row_count >= 3
    fn_rows = {
        row.issue_type is FeedbackIssueType.FALSE_NEGATIVE
        for row in draft.rows
        if row.case_id in set(attack_ids[:3])
    }
    assert fn_rows == {True}
    fp_rows = [
        row for row in draft.rows if row.issue_type is FeedbackIssueType.FALSE_POSITIVE
    ]
    assert {row.case_id for row in fp_rows} == set(normal_ids[:2])
    dropped_expected = {
        (item.kind.value, item.category, item.disposition.value)
        for case_id in attack_ids[:3]
        for item in _case_map()[case_id].expected
    }
    fn_signatures = {
        (row.kind.value, row.category, row.disposition.value)
        for row in draft.rows
        if row.issue_type is FeedbackIssueType.FALSE_NEGATIVE
    }
    assert fn_signatures == dropped_expected


def test_draft_is_deterministic_and_value_free() -> None:
    first = _draft(drop=set(sorted(_case_map())[:2]))
    second = _draft(drop=set(sorted(_case_map())[:2]))
    assert first == second
    encoded = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    p12, _p13 = _packs()
    for scenario in p12.scenarios[:4]:
        for slot in (scenario.normal_case, scenario.attack_case):
            snippet = slot.sanitized_text[:40]
            if snippet.strip():
                assert snippet not in encoded


def test_draft_context_binds_packs_and_provider() -> None:
    draft = _draft()
    assert draft.context.evaluation_provider_id == "offline-fixture"
    assert set(draft.context.source_pack_sha256) == set(_pack_digests())
    assert draft.context.evaluation_case_count >= 25


def test_confirmed_set_requires_human_confirmed_provenance() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:1]))
    row_ids = tuple(sorted(row.row_id for row in draft.rows))
    with pytest.raises(ValueError, match="ai_assisted"):
        build_semantic_feedback_set(
            draft,
            confirmed_row_ids=row_ids,
            reviewer_id="r",
            independence_statement="x" * 40,
            label_provenance=FeedbackProvenance.AI_ASSISTED,
        )


def test_confirmed_set_drops_rejected_rows_and_binds_digest() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:3]))
    row_ids = sorted(row.row_id for row in draft.rows)
    selected = set(row_ids[:-2])
    feedback = _confirmed_set(draft, select=selected)
    assert feedback.row_count == len(selected)
    statuses = {row.status for row in feedback.rows}
    assert statuses == {FeedbackRowStatus.CONFIRMED}
    assert feedback.false_positive_row_count + feedback.false_negative_row_count == (
        feedback.row_count
    )
    assert len(feedback.feedback_sha256) == 64
    payload = json.loads(encode_semantic_feedback_json(feedback))
    tampered = {**payload, "row_count": payload["row_count"] + 1}
    with pytest.raises(ValueError):
        SemanticFeedbackSet.model_validate(tampered)


def test_confirmation_of_unknown_row_fails_closed() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:1]))
    with pytest.raises(SemanticFeedbackError) as error:
        build_semantic_feedback_set(
            draft,
            confirmed_row_ids=("no-such-row",),
            reviewer_id="r",
            independence_statement="x" * 40,
        )
    assert error.value.code == "unknown_row_id"


def test_loop_resolves_all_issues_after_perfect_rerun() -> None:
    attack_ids = sorted(_attack_ids())
    normal_ids = sorted(
        case_id for case_id in _case_map() if case_id not in _attack_ids()
    )
    draft = _draft(drop=set(attack_ids[:3]), extra=set(normal_ids[:2]))
    feedback = _confirmed_set(draft)
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(feedback, (p12, p13), _adapter())
    assert loop.resolved_row_count == feedback.row_count
    assert loop.unresolved_row_count == 0
    assert loop.resolution_rate == 1.0
    assert loop.evaluation_complete is True


def test_loop_detects_unchanged_detections() -> None:
    attack_ids = sorted(_attack_ids())
    normal_ids = sorted(
        case_id for case_id in _case_map() if case_id not in _attack_ids()
    )
    drop = set(attack_ids[:3])
    extra = set(normal_ids[:2])
    draft = _draft(drop=drop, extra=extra)
    feedback = _confirmed_set(draft)
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(
        feedback, (p12, p13), _adapter(drop=drop, extra=extra)
    )
    assert loop.resolved_row_count == 0
    assert loop.unresolved_row_count == feedback.row_count
    assert loop.resolution_rate == 0.0


def test_loop_records_partial_fixes_per_issue_type() -> None:
    attack_ids = sorted(_attack_ids())
    normal_ids = sorted(
        case_id for case_id in _case_map() if case_id not in _attack_ids()
    )
    drop = set(attack_ids[:3])
    extra = set(normal_ids[:2])
    draft = _draft(drop=drop, extra=extra)
    feedback = _confirmed_set(draft)
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(feedback, (p12, p13), _adapter(drop=drop))
    assert loop.resolved_row_count == feedback.false_positive_row_count
    unresolved_rows = [
        row for row in loop.rows if row.outcome is FeedbackResolutionOutcome.UNRESOLVED
    ]
    assert all(
        row.issue_type is FeedbackIssueType.FALSE_NEGATIVE for row in unresolved_rows
    )


def test_loop_marks_invocation_failures_unevaluated() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:2]))
    feedback = _confirmed_set(draft)
    failing_case = sorted(_case_map())[0]
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(
        feedback, (p12, p13), _adapter(fail={failing_case})
    )
    assert loop.unevaluated_row_count > 0
    assert loop.evaluation_complete is False
    rows = [row for row in loop.rows if row.case_id == failing_case]
    assert rows
    assert all(row.outcome is FeedbackResolutionOutcome.UNEVALUATED for row in rows)


def test_round_trips_and_exported_schemas_match_frozen(
    tmp_path: Path,
) -> None:
    draft = _draft(drop=set(sorted(_case_map())[:2]))
    feedback = _confirmed_set(draft)
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(feedback, (p12, p13), _adapter())
    set_encoding = encode_semantic_feedback_json(feedback)
    assert SemanticFeedbackSet.model_validate_json(set_encoding) == feedback
    loop_encoding = encode_semantic_feedback_loop_json(loop)
    assert SemanticFeedbackLoopReport.model_validate_json(loop_encoding) == loop
    exported = export_semantic_feedback_json_schemas(tmp_path)
    for exported_path, frozen_path in zip(
        exported, FROZEN_FEEDBACK_SCHEMAS, strict=True
    ):
        assert frozen_path.exists()
        assert exported_path.read_bytes() == frozen_path.read_bytes()


def test_load_feedback_set_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(SemanticFeedbackError):
        load_semantic_feedback_set(bad)
    original = tmp_path / "set.json"
    original.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(original)
    with pytest.raises(SemanticFeedbackError) as error:
        load_semantic_feedback_set(link)
    assert error.value.code == "unsafe_feedback_set_path"


def test_shipped_draft_pack_loads_with_draft_rows() -> None:
    assert DRAFT_SUBMISSION.exists()
    submission = json.loads(DRAFT_SUBMISSION.read_text(encoding="utf-8"))
    assert submission["format"] == "agentsec-p3-17-feedback-submission"
    assert submission["reviewer_id"] is None
    draft = SemanticFeedbackDraft.model_validate(
        {
            "format": "agentsec-p3-17-semantic-feedback-draft",
            "schema_version": "0.1.0",
            "draft_sha256": submission["draft_sha256"],
            "context": submission["context"],
            "draft_row_count": len(submission["draft_rows"]),
            "false_positive_row_count": sum(
                row["issue_type"] == "false_positive"
                for row in submission["draft_rows"]
            ),
            "false_negative_row_count": sum(
                row["issue_type"] == "false_negative"
                for row in submission["draft_rows"]
            ),
            "unevaluated_case_count": 0,
            "unevaluated_case_ids": [],
            "rows": submission["draft_rows"],
        }
    )
    assert draft.draft_row_count >= 50
    assert draft.false_negative_row_count == draft.draft_row_count
    assert draft.false_positive_row_count == 0
    statuses = {row["status"] for row in submission["draft_rows"]}
    assert statuses == {"draft"}


def test_row_contract_rejects_incoherent_rows() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:1]))
    good_row = draft.rows[0].model_dump(mode="json")
    wrong_rationale = {
        **good_row,
        "rationale_code": (
            "overflagged_judgment"
            if good_row["issue_type"] == "false_negative"
            else "missed_judgment"
        ),
    }
    with pytest.raises(ValueError):
        type(draft.rows[0]).model_validate(wrong_rationale)
    forbidden_category = {**good_row, "category": "scan_coverage"}
    with pytest.raises(ValueError):
        type(draft.rows[0]).model_validate(forbidden_category)
    swapped_status = {**good_row, "status": "confirmed"}
    draft_model = {
        "format": "agentsec-p3-17-semantic-feedback-draft",
        "schema_version": "0.1.0",
        "draft_sha256": draft.draft_sha256,
        "context": draft.context.model_dump(mode="json"),
        "draft_row_count": 1,
        "false_positive_row_count": (
            1 if swapped_status["issue_type"] == "false_positive" else 0
        ),
        "false_negative_row_count": (
            1 if swapped_status["issue_type"] == "false_negative" else 0
        ),
        "unevaluated_case_count": 0,
        "unevaluated_case_ids": [],
        "rows": [swapped_status],
    }
    with pytest.raises(ValueError):
        SemanticFeedbackDraft.model_validate(draft_model)


def test_loop_report_validation_rejects_tampering() -> None:
    draft = _draft(drop=set(sorted(_case_map())[:2]))
    feedback = _confirmed_set(draft)
    p12, p13 = _packs()
    loop = evaluate_feedback_resolution(feedback, (p12, p13), _adapter())
    payload = json.loads(encode_semantic_feedback_loop_json(loop))
    bad_rate = {**payload, "resolution_rate": 0.123}
    with pytest.raises(ValueError):
        SemanticFeedbackLoopReport.model_validate(bad_rate)
    fabricated_row = {
        **payload,
        "rows": [
            {**payload["rows"][0], "outcome": "unresolved"},
            *payload["rows"][1:],
        ],
    }
    with pytest.raises(ValueError):
        SemanticFeedbackLoopReport.model_validate(fabricated_row)
    bad_feedback_digest = {**payload, "feedback_sha256": "00" * 32}
    with pytest.raises(ValueError):
        SemanticFeedbackLoopReport.model_validate(bad_feedback_digest)

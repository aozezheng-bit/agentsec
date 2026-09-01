"""P3-16 batch Shadow Mode pipeline tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec.semantic import (
    SemanticShadowModeReport,
    SemanticShadowModeRunner,
    ShadowModeCase,
    ShadowModeCaseStatus,
    ShadowModeError,
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
    encode_semantic_shadow_mode_json,
    export_semantic_shadow_mode_json_schema,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
)
from agentsec.semantic.invocation import (
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationError,
    SemanticShadowInvocationErrorCode,
)
from agentsec.semantic.models import SemanticModelOutput
from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderResponse,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
P3_12_PACK = REPOSITORY_ROOT / "pilots" / "agentdojo-style-p3-12" / "scenarios.json"
P3_13_PACK = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13" / "scenarios.json"
FROZEN_SHADOW_MODE_SCHEMA = (
    REPOSITORY_ROOT
    / "schemas"
    / "semantic-analysis"
    / "semantic-shadow-mode-report.schema.json"
)


def _evaluation_cases() -> tuple[Any, ...]:
    assert P3_12_PACK.exists() and P3_13_PACK.exists()
    packs = (
        load_agent_dojo_scenario_set(P3_12_PACK),
        load_injecagent_scenario_set(P3_13_PACK),
    )
    return build_scenario_evaluation_cases(packs[0]) + (
        build_injecagent_evaluation_cases(packs[1])
    )


class _ShadowModeEchoProvider:
    """Offline Provider echoing recorded expectations; per-case controls."""

    def __init__(self, *, fail: set[str] | None = None) -> None:
        all_cases = _evaluation_cases()
        self._all = {case.case_id: case for case in all_cases}
        self.fail = set() if fail is None else fail
        self.metadata = SemanticProviderMetadata()

    def invoke(self, request: Any) -> SemanticProviderResponse:
        if request.analysis_id in self.fail:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE,
            )
        case = self._all[request.analysis_id]
        evidence_id = case.semantic_input.evidence[0].evidence_id
        items = [
            {
                "kind": item.kind.value,
                "category": item.category,
                "disposition": item.disposition.value,
            }
            for item in case.expected
        ]
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
                        "summary": "Fixture judgment for Shadow Mode replay.",
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


def _shadow_cases(limit: int = 8) -> tuple[ShadowModeCase, ...]:
    cases = _evaluation_cases()
    return tuple(ShadowModeCase(case.semantic_input) for case in cases[:limit])


def _run(
    cases: tuple[ShadowModeCase, ...],
    *,
    fail: set[str] | None = None,
) -> SemanticShadowModeReport:
    return SemanticShadowModeRunner().run_cases(
        cases,
        adapter=SemanticShadowInvocationAdapter(
            provider=_ShadowModeEchoProvider(fail=fail)
        ),
    )


def test_batch_records_every_case_with_child_digests() -> None:
    cases = _evaluation_cases()
    limit = 8
    report = _run(_shadow_cases(limit))
    assert report.case_count == limit
    assert report.completed_case_count == limit
    assert report.failed_case_count == 0
    ids = [row.analysis_id for row in report.cases]
    assert ids == sorted(ids)
    expected_ids = {case.case_id for case in cases[:limit]}
    assert set(ids) == expected_ids
    for row in report.cases:
        assert row.status is ShadowModeCaseStatus.COMPLETE
        assert row.pipeline_sha256 is not None
        assert row.error_code is None
        assert row.candidate_count == len(
            next(c.expected for c in cases if c.case_id == row.analysis_id)
        )
    expected_candidates = sum(len(case.expected) for case in cases[:limit])
    assert report.candidate_count == expected_candidates
    assert report.link_count == expected_candidates
    assert report.proposal_count == expected_candidates


def test_failed_invocation_is_recorded_without_interrupting_the_batch() -> None:
    cases = _evaluation_cases()
    report = _run(_shadow_cases(8), fail={cases[2].case_id})
    assert report.case_count == 8
    assert report.completed_case_count == 7
    assert report.failed_case_count == 1
    failed_rows = [
        row for row in report.cases if row.status is ShadowModeCaseStatus.FAILED
    ]
    assert [row.analysis_id for row in failed_rows] == [cases[2].case_id]
    assert failed_rows[0].error_code == "provider_failure"
    assert failed_rows[0].pipeline_sha256 is None
    assert failed_rows[0].candidate_count == 0
    assert failed_rows[0].link_count == 0
    assert failed_rows[0].proposal_count == 0
    completed = [
        row for row in report.cases if row.status is ShadowModeCaseStatus.COMPLETE
    ]
    assert len(completed) == 7


def test_report_freezes_non_blocking_shadow_authority() -> None:
    report = _run(_shadow_cases(4))
    assert report.operating_mode == "shadow_only"
    assert report.report_only is True
    assert report.blocks is False
    assert report.deterministic_decisions_affected is False
    assert report.finding_authority is False
    assert report.rule_publication_authority is False
    assert report.severity_authority is False
    assert report.policy_authority is False
    assert report.ci_authority is False
    assert report.runtime_disclosure_allowed is False
    assert report.runtime_verified is False


def test_report_is_deterministic_and_round_trips() -> None:
    specs = _shadow_cases(6)
    first = _run(specs)
    encoded = encode_semantic_shadow_mode_json(first)
    decoded = SemanticShadowModeReport.model_validate_json(encoded)
    assert decoded == first
    again = _run(_shadow_cases(6))
    assert encoded == encode_semantic_shadow_mode_json(again)


def test_case_rows_require_status_consistent_fields() -> None:
    report = _run(_shadow_cases(4))
    row = report.cases[0]
    payload = row.model_dump(mode="json")
    complete_without_digest = {**payload, "pipeline_sha256": None}
    with pytest.raises(ValidationError):
        type(row).model_validate(complete_without_digest)
    failed_with_digest = {
        **payload,
        "status": "failed",
        "error_code": "provider_failure",
    }
    with pytest.raises(ValidationError):
        type(row).model_validate(failed_with_digest)


def test_report_counts_are_validated_against_rows() -> None:
    report = _run(_shadow_cases(5))
    payload = json.loads(encode_semantic_shadow_mode_json(report))
    tampered = {**payload, "candidate_count": payload["candidate_count"] + 1}
    with pytest.raises(ValidationError):
        SemanticShadowModeReport.model_validate(tampered)
    bad_completed = {
        **payload,
        "completed_case_count": payload["completed_case_count"] + 1,
        "failed_case_count": payload["failed_case_count"] - 1,
    }
    with pytest.raises(ValidationError):
        SemanticShadowModeReport.model_validate(bad_completed)
    tampered_digest = {**payload, "shadow_mode_sha256": "00" * 32}
    with pytest.raises(ValidationError):
        SemanticShadowModeReport.model_validate(tampered_digest)
    unsorted = {
        **payload,
        "cases": [payload["cases"][1], payload["cases"][0], *payload["cases"][2:]],
    }
    with pytest.raises(ValidationError):
        SemanticShadowModeReport.model_validate(unsorted)


def test_empty_and_invalid_case_inputs_fail_closed() -> None:
    with pytest.raises(ShadowModeError) as error:
        SemanticShadowModeRunner().run_cases(())
    assert error.value.code == "cases_missing"
    adapter = SemanticShadowInvocationAdapter(provider=_ShadowModeEchoProvider())
    with pytest.raises(ShadowModeError) as error:
        cases = _shadow_cases(2)
        SemanticShadowModeRunner().run_cases(
            (cases[0], "not-a-case"),  # type: ignore[arg-type]
            adapter=adapter,
        )
    assert error.value.code == "case_type_invalid"
    with pytest.raises(ShadowModeError) as error:
        cases = _shadow_cases(2)
        SemanticShadowModeRunner().run_cases((cases[0], cases[0]), adapter=adapter)
    assert error.value.code == "duplicate_analysis_id"


def test_case_count_bound_is_enforced() -> None:
    single = _ShadowCaseFactory.default()
    with pytest.raises(ShadowModeError) as error:
        SemanticShadowModeRunner().run_cases((single,) * 257)
    assert error.value.code == "case_bound_exceeded"


def test_pipeline_and_adapter_requirements_fail_closed() -> None:
    runner = SemanticShadowModeRunner()
    cases = _shadow_cases(2)
    with pytest.raises(ShadowModeError) as error:
        runner.run_cases(cases)
    assert error.value.code == "pipeline_missing"
    with pytest.raises(ShadowModeError) as error:
        runner.run_cases(cases, adapter="not-an-adapter")
    assert error.value.code == "adapter_invalid"
    with pytest.raises(TypeError):
        SemanticShadowModeRunner(pipeline="not-a-pipeline")  # type: ignore[arg-type]


def test_shadow_mode_case_construction_enforces_types() -> None:
    evaluation = _evaluation_cases()
    semantic_input = evaluation[0].semantic_input
    with pytest.raises(TypeError):
        ShadowModeCase("not-an-input")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ShadowModeCase(semantic_input, findings=("not-a-finding",))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ShadowModeCase(
            semantic_input,
            evidence=("not-an-evidence",),  # type: ignore[arg-type]
        )
    case = ShadowModeCase(semantic_input)
    assert case.analysis_id == semantic_input.analysis_id
    assert case.findings == () and case.evidence == ()


def test_explicit_pipeline_is_used_when_provided() -> None:
    from agentsec.semantic.p3_08 import SemanticShadowPipeline

    cases = _shadow_cases(3)
    adapter = SemanticShadowInvocationAdapter(provider=_ShadowModeEchoProvider())
    pipeline = SemanticShadowPipeline(adapter=adapter)
    report = SemanticShadowModeRunner(pipeline=pipeline).run_cases(cases)
    assert report.case_count == 3
    assert report.completed_case_count == 3


def test_exported_schema_matches_frozen_release_schema(tmp_path: Path) -> None:
    assert FROZEN_SHADOW_MODE_SCHEMA.exists()
    exported = export_semantic_shadow_mode_json_schema(
        tmp_path / "semantic-shadow-mode-report.schema.json"
    )
    assert exported.read_bytes() == FROZEN_SHADOW_MODE_SCHEMA.read_bytes()


def test_shadow_mode_output_hides_corpus_text() -> None:
    packs = (
        load_agent_dojo_scenario_set(P3_12_PACK),
        load_injecagent_scenario_set(P3_13_PACK),
    )
    p12 = packs[0]
    report = _run(_shadow_cases(6))
    encoded = encode_semantic_shadow_mode_json(report)
    for scenario in p12.scenarios[:4]:
        for case_slot in (scenario.normal_case, scenario.attack_case):
            snippet = case_slot.sanitized_text[:40]
            if snippet.strip():
                assert snippet not in encoded


class _ShadowCaseFactory:
    @staticmethod
    def default() -> ShadowModeCase:
        return _shadow_cases(1)[0]


def test_provider_metadata_field_is_fixture_when_unset() -> None:
    """Every result uses the approved offline fixture identity."""

    provider = _ShadowModeEchoProvider()
    assert provider.metadata.provider_id == (SemanticProviderMetadata().provider_id)
    assert provider.metadata.model_id == SemanticProviderMetadata().model_id

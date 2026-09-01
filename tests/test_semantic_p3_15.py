"""P3-15 historical sample replay tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentsec.semantic import (
    ChannelReplayComparison,
    MetricsChannelKind,
    ReplayRunSpec,
    ScenarioReplayError,
    ScenarioReplayRun,
    ScenarioReplayRunner,
    ScenarioReplaySuite,
    SemanticShadowInvocationAdapter,
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
    encode_scenario_replay_json,
    export_scenario_replay_json_schema,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
)
from agentsec.semantic.invocation import (
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
FROZEN_REPLAY_SCHEMA = (
    REPOSITORY_ROOT
    / "schemas"
    / "semantic-analysis"
    / "semantic-scenario-replay-suite.schema.json"
)


def _packs() -> tuple[Any, Any]:
    assert P3_12_PACK.exists() and P3_13_PACK.exists()
    return (
        load_agent_dojo_scenario_set(P3_12_PACK),
        load_injecagent_scenario_set(P3_13_PACK),
    )


def _case_map() -> dict[str, Any]:
    p12, p13 = _packs()
    return {
        case.case_id: case
        for case in (
            build_scenario_evaluation_cases(p12)
            + build_injecagent_evaluation_cases(p13)
        )
    }


def _attack_ids() -> set[str]:
    p12, p13 = _packs()
    return {s.attack_case.case_id for s in p12.scenarios} | {
        s.attack_case.case_id for s in p13.scenarios
    }


class _ReplayEchoProvider:
    """Offline Provider whose detections are driven by per-case controls."""

    def __init__(
        self,
        *,
        drop: set[str] | None = None,
        fail: set[str] | None = None,
    ) -> None:
        all_cases = _case_map()
        self._all = all_cases
        self.drop = set() if drop is None else drop
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
                        "summary": "Fixture judgment for replay.",
                        "evidence_ids": [evidence_id],
                    }
                    for index, item in enumerate(items, start=1)
                ],
            }
        )
        raw = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
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


def _spec(
    prompt_version: str,
    run_id: str,
    *,
    drop: set[str] | None = None,
    fail: set[str] | None = None,
) -> ReplayRunSpec:
    return ReplayRunSpec(
        adapter=SemanticShadowInvocationAdapter(
            provider=_ReplayEchoProvider(drop=drop, fail=fail)
        ),
        prompt_version=prompt_version,
        run_id=run_id,
    )


def _run(*specs: ReplayRunSpec) -> ScenarioReplaySuite:
    return ScenarioReplayRunner().replay(_packs(), specs)


def _comparison(
    suite: ScenarioReplaySuite, channel: MetricsChannelKind, index: int = 0
) -> ChannelReplayComparison:
    matches = [item for item in suite.comparisons if item.channel is channel]
    return matches[index]


def test_prompt_upgrade_run_chain_is_recorded_and_compared() -> None:
    attack_ids = sorted(_attack_ids())
    suite = _run(
        _spec("0.1.0", "baseline", drop=set(attack_ids)),
        _spec("0.2.0", "upgrade"),
    )
    assert suite.run_count == 2
    assert suite.comparison_count == 2
    run_ids = [run.run_id for run in suite.runs]
    assert run_ids == ["baseline", "upgrade"]
    configurations = {
        (run.provider_id, run.model_id, run.prompt_version) for run in suite.runs
    }
    assert configurations == {
        ("offline-fixture", "agentsec-semantic-fixture-v1", "0.1.0"),
        ("offline-fixture", "agentsec-semantic-fixture-v1", "0.2.0"),
    }


def test_upgrade_comparison_reports_improvements() -> None:
    attack_ids = sorted(_attack_ids())
    suite = _run(
        _spec("0.1.0", "baseline", drop=set(attack_ids)),
        _spec("0.2.0", "upgrade"),
    )
    for channel_kind in (MetricsChannelKind.INSTRUCTION, MetricsChannelKind.TOOL):
        comparison = _comparison(suite, channel_kind)
        assert comparison.baseline_run_id == "baseline"
        assert comparison.candidate_run_id == "upgrade"
        assert comparison.asr_delta == pytest.approx(-1.0)
        assert comparison.asr_after == 0.0
        assert comparison.utility_delta == pytest.approx(0.0)
        assert comparison.recall_delta > 0
        assert comparison.regressed_task_count == 0
        assert comparison.comparison_complete is True
        improvement_ids = {
            row.case_id
            for row in comparison.transitions
            if row.transition == "undetected_to_detected"
        }
        channel_ids = {row.case_id for row in comparison.transitions}
        assert improvement_ids == {
            case_id for case_id in attack_ids if case_id in channel_ids
        }


def test_partial_replay_regression_is_visible_per_task() -> None:
    attack_ids = sorted(_attack_ids())
    suite = _run(
        _spec("0.1.0", "good"),
        _spec("0.2.0", "worse", drop=set(attack_ids[:4])),
    )
    comparison = _comparison(suite, MetricsChannelKind.INSTRUCTION)
    assert comparison.asr_delta > 0
    assert comparison.recall_delta < 0
    assert comparison.regressed_task_count > 0
    regressed_ids = {
        row.case_id
        for row in comparison.transitions
        if row.transition == "detected_to_undetected"
    }
    expected_in_channel = {
        case_id
        for case_id in attack_ids[:4]
        if case_id in {row.case_id for row in comparison.transitions}
    }
    assert regressed_ids == expected_in_channel
    assert comparison.improved_task_count == 0


def test_invocation_failure_marks_comparison_incomplete() -> None:
    normal_ids = sorted(
        case_id for case_id in _case_map() if case_id not in _attack_ids()
    )
    suite = _run(
        _spec("0.1.0", "stable"),
        _spec("0.2.0", "flaky", fail={normal_ids[0]}),
    )
    comparison = _comparison(suite, MetricsChannelKind.INSTRUCTION)
    assert comparison.comparison_complete is False
    assert comparison.failed_side_task_count >= 1
    failed_rows = [
        row for row in comparison.transitions if row.transition == "clean_to_failed"
    ]
    assert {row.case_id for row in failed_rows} == {normal_ids[0]} & {
        row.case_id for row in comparison.transitions
    }


def test_three_run_chain_compares_adjacent_pairs_per_channel() -> None:
    attack_ids = sorted(_attack_ids())
    suite = _run(
        _spec("0.1.0", "r1", drop=set(attack_ids)),
        _spec("0.2.0", "r2"),
        _spec("0.3.0", "r3", drop=set(attack_ids[:3])),
    )
    assert suite.run_count == 3
    assert suite.comparison_count == 4
    for channel_kind in (MetricsChannelKind.INSTRUCTION, MetricsChannelKind.TOOL):
        pairs = [
            (item.baseline_run_id, item.candidate_run_id)
            for item in suite.comparisons
            if item.channel is channel_kind
        ]
        assert pairs == [("r1", "r2"), ("r2", "r3")]


def test_suite_is_deterministic_and_round_trips() -> None:
    attack_ids = sorted(_attack_ids())
    specs = (
        _spec("0.1.0", "baseline", drop=set(attack_ids[:2])),
        _spec("0.2.0", "upgrade"),
    )
    first = _run(*specs)
    encoded = encode_scenario_replay_json(first)
    decoded = ScenarioReplaySuite.model_validate_json(encoded)
    assert decoded == first
    again = _run(*specs)
    assert encode_scenario_replay_json(again) == encoded


def test_suite_freezes_authority_boundary() -> None:
    suite = _run(_spec("0.1.0", "a"), _spec("0.2.0", "b"))
    assert suite.report_only is True
    assert suite.blocks is False
    assert suite.policy_authority is False
    assert suite.release_authority is False
    assert suite.provider_promotion_authority is False
    assert suite.runtime_verified is False
    for run in suite.runs:
        assert run.report_only is True
        assert run.runtime_verified is False
    for comparison in suite.comparisons:
        assert comparison.report_only is True
        assert comparison.runtime_verified is False


def test_duplicate_run_id_rejected() -> None:
    with pytest.raises(ScenarioReplayError) as error:
        _run(_spec("0.1.0", "same"), _spec("0.2.0", "same"))
    assert error.value.code == "duplicate_run_id"


def test_duplicate_configuration_rejected() -> None:
    with pytest.raises(ScenarioReplayError) as error:
        _run(_spec("0.1.0", "one"), _spec("0.1.0", "two"))
    assert error.value.code == "duplicate_run_configuration"


def test_insufficient_runs_rejected() -> None:
    with pytest.raises(ScenarioReplayError) as error:
        _run(_spec("0.1.0", "only"))
    assert error.value.code == "insufficient_runs"


def test_empty_packs_rejected() -> None:
    with pytest.raises(ScenarioReplayError) as error:
        ScenarioReplayRunner().replay((), (_spec("0.1.0", "a"), _spec("0.2.0", "b")))
    assert error.value.code == "packs_missing"


def test_non_tuple_and_bad_spec_types_rejected() -> None:
    packs = _packs()
    with pytest.raises(ScenarioReplayError):
        ScenarioReplayRunner().replay(
            packs,
            [_spec("0.1.0", "a"), _spec("0.2.0", "b")],  # type: ignore[arg-type]
        )
    with pytest.raises(ScenarioReplayError):
        ScenarioReplayRunner().replay(packs, ("bad", _spec("0.2.0", "b")))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ReplayRunSpec(
            adapter="not-an-adapter",  # type: ignore[arg-type]
            prompt_version="0.1.0",
            run_id="bad",
        )


def test_prompt_version_must_be_semver() -> None:
    with pytest.raises(ValueError):
        ReplayRunSpec(
            adapter=SemanticShadowInvocationAdapter(provider=_ReplayEchoProvider()),
            prompt_version="not-semver",
            run_id="bad",
        )


def test_run_identity_must_match_metrics_report() -> None:
    suite = _run(_spec("0.1.0", "a"), _spec("0.2.0", "b"))
    run = suite.runs[0]
    payload = run.model_dump(mode="json")
    payload["provider_id"] = "someone-else"
    with pytest.raises(ValueError):
        ScenarioReplayRun.model_validate(payload)


def test_comparison_delta_and_counts_are_validated() -> None:
    suite = _run(_spec("0.1.0", "a"), _spec("0.2.0", "b"))
    comparison = _comparison(suite, MetricsChannelKind.INSTRUCTION)
    payload = comparison.model_dump(mode="json")
    tampered_delta = {
        **payload,
        "asr_delta": 0.5,
    }
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(tampered_delta)
    bad_counts = {
        **payload,
        "improved_task_count": payload["improved_task_count"] + 1,
    }
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(bad_counts)
    mismatched_task_count = {**payload, "task_count": payload["task_count"] + 1}
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(mismatched_task_count)
    wrong_run_ids = {**payload, "candidate_run_id": payload["baseline_run_id"]}
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(wrong_run_ids)


def test_suite_counts_and_pairs_are_validated() -> None:
    suite = _run(_spec("0.1.0", "a"), _spec("0.2.0", "b"))
    payload = json.loads(encode_scenario_replay_json(suite))
    payload["run_count"] = 3
    with pytest.raises(ValueError):
        ScenarioReplaySuite.model_validate(payload)
    dropped = {
        **payload,
        "comparisons": payload["comparisons"][:1],
        "comparison_count": 1,
    }
    with pytest.raises(ValueError):
        ScenarioReplaySuite.model_validate(dropped)


def test_transition_rows_must_be_known_and_unique() -> None:
    suite = _run(_spec("0.1.0", "a"), _spec("0.2.0", "b"))
    comparison = _comparison(suite, MetricsChannelKind.INSTRUCTION)
    payload = comparison.model_dump(mode="json")
    duplicated = {
        **payload,
        "transitions": [*payload["transitions"], payload["transitions"][0]],
        "unchanged_task_count": payload["unchanged_task_count"] + 1,
    }
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(duplicated)
    unknown = {
        **payload,
        "transitions": [
            {**payload["transitions"][0], "transition": "guessed_to_guessed"}
        ]
        + payload["transitions"][1:],
    }
    with pytest.raises(ValueError):
        ChannelReplayComparison.model_validate(unknown)
    known_transitions = {
        "undetected_to_detected",
        "false_alarm_to_clean",
        "detected_to_undetected",
        "clean_to_false_alarm",
        "failed_to_detect",
        "failed_to_undetect",
        "failed_to_clean",
        "failed_to_false_alarm",
        "detected_to_failed",
        "undetected_to_failed",
        "clean_to_failed",
        "false_alarm_to_failed",
        "failed_to_failed",
        "detected_to_detected",
        "undetected_to_undetected",
        "clean_to_clean",
        "false_alarm_to_false_alarm",
    }
    for row in comparison.transitions:
        assert row.transition in known_transitions


def test_exported_schema_matches_frozen_release_schema(tmp_path: Path) -> None:
    assert FROZEN_REPLAY_SCHEMA.exists()
    exported = export_scenario_replay_json_schema(
        tmp_path / "semantic-scenario-replay-suite.schema.json"
    )
    assert exported.read_bytes() == FROZEN_REPLAY_SCHEMA.read_bytes()


def test_replay_encodes_no_corpus_or_secret_text() -> None:
    attack_ids = sorted(_attack_ids())
    suite = _run(_spec("0.1.0", "a", drop=set(attack_ids)), _spec("0.2.0", "b"))
    encoded = encode_scenario_replay_json(suite)
    p12, _p13 = _packs()
    for scenario in p12.scenarios:
        for case in (scenario.normal_case, scenario.attack_case):
            snippet = case.sanitized_text[:40]
            if snippet.strip():
                assert snippet not in encoded

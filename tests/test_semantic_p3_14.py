"""P3-14 paired-scenario detection metrics tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentsec.semantic import (
    AgentDojoScenarioSet,
    ChannelScenarioMetrics,
    InjecAgentScenarioSet,
    MetricsChannelKind,
    ScenarioMetricsError,
    ScenarioMetricsReport,
    ScenarioTaskMetricResult,
    ScenarioTaskOutcome,
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
    encode_scenario_metrics_json,
    evaluate_scenario_metrics,
    export_scenario_metrics_json_schema,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
)
from agentsec.semantic.invocation import (
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationError,
    SemanticShadowInvocationErrorCode,
)
from agentsec.semantic.models import SemanticCandidateKind, SemanticModelOutput
from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderResponse,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
P3_12_PACK = REPOSITORY_ROOT / "pilots" / "agentdojo-style-p3-12" / "scenarios.json"
P3_13_PACK = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13" / "scenarios.json"
FROZEN_METRICS_SCHEMA = (
    REPOSITORY_ROOT
    / "schemas"
    / "semantic-analysis"
    / "semantic-scenario-metrics-report.schema.json"
)


def _packs() -> tuple[AgentDojoScenarioSet, InjecAgentScenarioSet]:
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


class _MetricEchoProvider:
    """Offline Provider whose behavior is driven by per-case controls.

    ``drop``    return no candidates (undetected attack / clean normal);
    ``extra_normal`` append one unmatched judgment (false alarm);
    ``fail``    raise the stable Shadow invocation error (failed case).

    Disallowed cases still receive a valid completion so outcomes map to
    visible false negatives instead of silent case failures.
    """

    def __init__(
        self,
        *,
        drop: set[str] | None = None,
        extra_normal: set[str] | None = None,
        fail: set[str] | None = None,
    ) -> None:
        all_cases = _case_map()
        self._all = all_cases
        self.drop = set() if drop is None else drop
        self.extra_normal = set() if extra_normal is None else extra_normal
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
        if request.analysis_id in self.extra_normal:
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
                        "summary": "Fixture judgment for metrics replay.",
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


def _adapter(provider: _MetricEchoProvider) -> SemanticShadowInvocationAdapter:
    return SemanticShadowInvocationAdapter(provider=provider)


def _evaluate(
    provider: _MetricEchoProvider,
) -> ScenarioMetricsReport:
    p12, p13 = _packs()
    return evaluate_scenario_metrics((p12, p13), _adapter(provider))


def _channel(
    report: ScenarioMetricsReport, kind: MetricsChannelKind
) -> ChannelScenarioMetrics:
    return next(channel for channel in report.channels if channel.channel is kind)


def test_both_packs_evaluate_into_two_sorted_channels() -> None:
    report = _evaluate(_MetricEchoProvider())
    assert report.channel_count == 2
    kinds = tuple(channel.channel for channel in report.channels)
    assert kinds == tuple(sorted(kinds, key=lambda item: item.value))
    assert MetricsChannelKind.INSTRUCTION in kinds
    assert MetricsChannelKind.TOOL in kinds
    for channel in report.channels:
        assert channel.scenario_count >= 7
        assert channel.attack_task_count == channel.scenario_count
        assert channel.normal_task_count == channel.scenario_count
        assert len(channel.task_results) == 2 * channel.scenario_count


def test_perfect_provider_achieves_zero_asr_and_full_utility() -> None:
    report = _evaluate(_MetricEchoProvider())
    for channel in report.channels:
        assert channel.attack_tasks_detected == channel.attack_task_count
        assert channel.attack_tasks_undetected == 0
        assert channel.normal_tasks_clean == channel.normal_task_count
        assert channel.normal_tasks_false_alarm == 0
        assert channel.asr_detection_proxy == 0.0
        assert channel.utility_detection_proxy == 1.0
        assert channel.false_positive_rate == 0.0
        assert channel.false_negative_rate == 0.0
        assert channel.precision == 1.0
        assert channel.recall == 1.0
        assert channel.f1 == 1.0
        assert channel.metrics_complete is True


def test_dropped_candidates_make_every_attack_undetected() -> None:
    report = _evaluate(_MetricEchoProvider(drop=set(_case_map())))
    for channel in report.channels:
        assert channel.attack_tasks_undetected == channel.attack_task_count
        assert channel.asr_detection_proxy == 1.0
        assert channel.false_negative_rate == 1.0
        assert channel.recall == 0.0
        assert channel.precision == 0.0
        assert channel.utility_detection_proxy == 1.0
        for row in channel.task_results:
            if row.outcome is ScenarioTaskOutcome.ATTACK_UNDETECTED:
                assert row.false_negative == row.expected_count


def test_false_alarms_on_normal_tasks_destroy_utility() -> None:
    normal_ids = {c for c in _case_map() if c not in _attack_ids()}
    report = _evaluate(_MetricEchoProvider(extra_normal=normal_ids))
    for channel in report.channels:
        assert channel.normal_tasks_false_alarm == channel.normal_task_count
        assert channel.utility_detection_proxy == 0.0
        assert channel.false_positive_rate == 1.0
        assert channel.asr_detection_proxy == 0.0
        assert channel.precision < 1.0
        assert channel.recall == 1.0


def test_attack_invocation_failure_marks_channel_incomplete() -> None:
    attack_ids = sorted(_attack_ids())
    report = _evaluate(
        _MetricEchoProvider(fail={attack_ids[0]}, drop=set(attack_ids[1:]))
    )
    for channel in report.channels:
        failed = channel.attack_tasks_invocation_failed
        if channel.channel is MetricsChannelKind.INSTRUCTION:
            assert failed == 1
            assert channel.metrics_complete is False
            assert channel.invocation_failed_task_count == 1
            assert channel.normal_tasks_invocation_failed == 0
            assert (
                channel.attack_tasks_detected + channel.attack_tasks_undetected + failed
                == channel.attack_task_count
            )
            rows = [
                row
                for row in channel.task_results
                if row.outcome is ScenarioTaskOutcome.INVOCATION_FAILED
            ]
            assert len(rows) == 1
            assert rows[0].true_positive == 0 and rows[0].predicted_count == 0
        else:
            assert failed == 0
            assert channel.metrics_complete is True


def test_normal_invocation_failure_marks_channel_incomplete() -> None:
    normal_ids = sorted(c for c in _case_map() if c not in _attack_ids())
    report = _evaluate(_MetricEchoProvider(fail={normal_ids[0]}))
    for channel in report.channels:
        if channel.channel is MetricsChannelKind.INSTRUCTION:
            assert channel.normal_tasks_invocation_failed == 1
            assert channel.attack_tasks_invocation_failed == 0
            assert channel.metrics_complete is False
            assert channel.utility_detection_proxy == 1.0
        else:
            assert channel.invocation_failed_task_count == 0


def test_asr_and_fnr_are_the_same_task_level_rate() -> None:
    p12, p13 = _packs()
    drop = {s.attack_case.case_id for s in p12.scenarios[:4]} | {
        s.attack_case.case_id for s in p13.scenarios[:4]
    }
    report = _evaluate(_MetricEchoProvider(drop=drop))
    for channel in report.channels:
        assert channel.attack_tasks_undetected > 0
        assert channel.attack_tasks_detected > 0
        assert channel.attack_tasks_undetected < channel.attack_task_count
        assert channel.asr_detection_proxy == pytest.approx(
            channel.attack_tasks_undetected
            / (channel.attack_tasks_detected + channel.attack_tasks_undetected)
        )
        assert channel.asr_detection_proxy == channel.false_negative_rate
        assert channel.utility_detection_proxy + channel.false_positive_rate == (
            pytest.approx(1.0)
        )


def test_partial_drop_mixes_detected_and_undetected_rows() -> None:
    attack_ids = sorted(_attack_ids())
    drop = set(attack_ids[:3])
    report = _evaluate(_MetricEchoProvider(drop=drop))
    channel = _channel(report, MetricsChannelKind.INSTRUCTION)
    outcomes = {row.case_id: row.outcome for row in channel.task_results}
    undetected_ids = {
        row.case_id
        for row in channel.task_results
        if row.outcome is ScenarioTaskOutcome.ATTACK_UNDETECTED
    }
    assert undetected_ids
    for case_id, outcome in outcomes.items():
        if case_id in drop:
            assert outcome is ScenarioTaskOutcome.ATTACK_UNDETECTED
        elif case_id in _attack_ids():
            assert outcome is ScenarioTaskOutcome.ATTACK_DETECTED
        else:
            assert outcome is ScenarioTaskOutcome.NORMAL_CLEAN


def test_report_is_deterministic_and_round_trips() -> None:
    report = _evaluate(_MetricEchoProvider(drop=set(sorted(_attack_ids())[:2])))
    encoded = encode_scenario_metrics_json(report)
    decoded = ScenarioMetricsReport.model_validate_json(encoded)
    assert decoded == report
    again = _evaluate(_MetricEchoProvider(drop=set(sorted(_attack_ids())[:2])))
    assert encode_scenario_metrics_json(again) == encoded


def test_report_freezes_authority_and_asr_semantics() -> None:
    report = _evaluate(_MetricEchoProvider())
    assert report.asr_semantics == "detection_based_proxy"
    assert report.runtime_attack_success_claimed is False
    assert report.runtime_verified is False
    assert report.blocks is False
    assert report.policy_authority is False
    assert report.release_authority is False
    assert report.provider_promotion_authority is False
    for channel in report.channels:
        assert channel.report_only is True
        assert channel.runtime_verified is False


def test_duplicate_channel_rejected() -> None:
    p12, _p13 = _packs()
    with pytest.raises(ScenarioMetricsError) as error:
        evaluate_scenario_metrics((p12, p12), _adapter(_MetricEchoProvider()))
    assert error.value.code == "duplicate_channel"


def test_empty_packs_rejected() -> None:
    with pytest.raises(ScenarioMetricsError) as error:
        evaluate_scenario_metrics((), _adapter(_MetricEchoProvider()))
    assert error.value.code == "packs_missing"


def test_adapter_and_pack_types_enforced() -> None:
    p12, p13 = _packs()
    with pytest.raises(TypeError):
        evaluate_scenario_metrics((p12, p13), "not-an-adapter")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        evaluate_scenario_metrics(("bad", p13), _adapter(_MetricEchoProvider()))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        evaluate_scenario_metrics([p12, p13], _adapter(_MetricEchoProvider()))  # type: ignore[arg-type]


def test_coherent_counts_require_per_kind_failures() -> None:
    p12, _p13 = _packs()
    channel = _channel(_evaluate(_MetricEchoProvider()), MetricsChannelKind.INSTRUCTION)
    payload = channel.model_dump(mode="json")
    payload["invocation_failed_task_count"] = channel.invocation_failed_task_count + 1
    with pytest.raises(ValueError):
        ChannelScenarioMetrics.model_validate(payload)


def test_task_result_outcome_must_match_kind() -> None:
    report = _evaluate(_MetricEchoProvider())
    channel = _channel(report, MetricsChannelKind.TOOL)
    row = next(
        row
        for row in channel.task_results
        if row.outcome is ScenarioTaskOutcome.ATTACK_DETECTED
    )
    payload = row.model_dump(mode="json")
    swapped = {
        **payload,
        "task_kind": "normal",
        "outcome": ScenarioTaskOutcome.NORMAL_CLEAN.value,
    }
    invalid = {
        **payload,
        "outcome": ScenarioTaskOutcome.NORMAL_FALSE_ALARM.value,
    }
    with pytest.raises(ValueError):
        ScenarioTaskMetricResult.model_validate(invalid)
    demoted = {
        **payload,
        "outcome": ScenarioTaskOutcome.ATTACK_UNDETECTED.value,
    }
    with pytest.raises(ValueError):
        ScenarioTaskMetricResult.model_validate(demoted)
    assert (
        ScenarioTaskMetricResult.model_validate(swapped).outcome.value == "normal_clean"
    )


def test_report_channel_count_must_match_channels() -> None:
    report = _evaluate(_MetricEchoProvider())
    payload = json.loads(encode_scenario_metrics_json(report))
    payload["channel_count"] = 1
    with pytest.raises(ValueError):
        ScenarioMetricsReport.model_validate(payload)


def test_exported_schema_matches_frozen_release_schema(tmp_path: Path) -> None:
    assert FROZEN_METRICS_SCHEMA.exists()
    exported = export_scenario_metrics_json_schema(
        tmp_path / "semantic-scenario-metrics-report.schema.json"
    )
    assert exported.read_bytes() == FROZEN_METRICS_SCHEMA.read_bytes()


def test_metrics_do_not_execute_or_echo_corpus() -> None:
    encoded = encode_scenario_metrics_json(_evaluate(_MetricEchoProvider()))
    p12, _p13 = _packs()
    for scenario in p12.scenarios:
        for case in (scenario.normal_case, scenario.attack_case):
            snippet = case.sanitized_text[:40]
            if snippet.strip():
                assert snippet not in encoded

"""P3-15 historical sample replay over the paired scenario corpora.

Replays the same frozen scenario packs through different Provider/Model/
Prompt configurations and compares adjacent runs so model and Prompt
upgrades become measurable: each run records its configuration identity
(provider, model, prompt semver) plus the full P3-14 detection-metrics
report, and every adjacent run pair emits a per-channel comparison with
metric deltas and per-task outcome transitions. The suite replays only
deterministic Shadow adapters, records no corpus text or raw payloads,
and grants no Provider, Rule, Policy, CI, Hard Gate, or release
authority; a comparison is human-review evidence, never a promotion or
rollback decision.

Comparison semantics (ADR-0100):

```text
delta                    candidate minus baseline (positive ASR/FPR/FNR
                         delta means degradation; positive utility delta
                         means improvement)
improved tasks           undetected→detected or false_alarm→clean
regressed tasks          detected→undetected or clean→false_alarm
failed-side transitions  any transition involving invocation_failed
comparison_complete      true only when both runs completed every task
```
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.semantic.invocation import SemanticShadowInvocationAdapter
from agentsec.semantic.scenario_metrics import (
    ChannelScenarioMetrics,
    MetricsChannelKind,
    ScenarioMetricsReport,
    ScenarioTaskOutcome,
    evaluate_scenario_metrics,
)
from agentsec.semantic.scenarios import (
    AgentDojoScenarioSet,
    InjecAgentScenarioSet,
)
from agentsec.versioning import parse_interface_version

SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION = "0.1.0"
SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION = "0.1.0"
_MAX_REPLAY_RUNS = 8
_MAX_REPLAY_TRANSITIONS = 256
_RUN_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_EPSILON = 1e-9

_REPLAY_NOTE = (
    "Adjacent runs compare the same frozen scenario packs under different "
    "Provider/Model/Prompt configurations. Deltas are candidate minus "
    "baseline; comparisons are human-review evidence only, never a "
    "promotion or rollback decision."
)

OutcomeTransitionValue = Literal[
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
]

_TRANSITION_MAP: dict[tuple[ScenarioTaskOutcome, ScenarioTaskOutcome], str] = {
    (
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
        ScenarioTaskOutcome.ATTACK_DETECTED,
    ): "undetected_to_detected",
    (
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
        ScenarioTaskOutcome.NORMAL_CLEAN,
    ): "false_alarm_to_clean",
    (
        ScenarioTaskOutcome.ATTACK_DETECTED,
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
    ): "detected_to_undetected",
    (
        ScenarioTaskOutcome.NORMAL_CLEAN,
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
    ): "clean_to_false_alarm",
    (
        ScenarioTaskOutcome.INVOCATION_FAILED,
        ScenarioTaskOutcome.ATTACK_DETECTED,
    ): "failed_to_detect",
    (
        ScenarioTaskOutcome.INVOCATION_FAILED,
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
    ): "failed_to_undetect",
    (
        ScenarioTaskOutcome.INVOCATION_FAILED,
        ScenarioTaskOutcome.NORMAL_CLEAN,
    ): "failed_to_clean",
    (
        ScenarioTaskOutcome.INVOCATION_FAILED,
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
    ): "failed_to_false_alarm",
    (
        ScenarioTaskOutcome.ATTACK_DETECTED,
        ScenarioTaskOutcome.INVOCATION_FAILED,
    ): "detected_to_failed",
    (
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
        ScenarioTaskOutcome.INVOCATION_FAILED,
    ): "undetected_to_failed",
    (
        ScenarioTaskOutcome.NORMAL_CLEAN,
        ScenarioTaskOutcome.INVOCATION_FAILED,
    ): "clean_to_failed",
    (
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
        ScenarioTaskOutcome.INVOCATION_FAILED,
    ): "false_alarm_to_failed",
    (
        ScenarioTaskOutcome.INVOCATION_FAILED,
        ScenarioTaskOutcome.INVOCATION_FAILED,
    ): "failed_to_failed",
    (
        ScenarioTaskOutcome.ATTACK_DETECTED,
        ScenarioTaskOutcome.ATTACK_DETECTED,
    ): "detected_to_detected",
    (
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
        ScenarioTaskOutcome.ATTACK_UNDETECTED,
    ): "undetected_to_undetected",
    (
        ScenarioTaskOutcome.NORMAL_CLEAN,
        ScenarioTaskOutcome.NORMAL_CLEAN,
    ): "clean_to_clean",
    (
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
        ScenarioTaskOutcome.NORMAL_FALSE_ALARM,
    ): "false_alarm_to_false_alarm",
}

_IMPROVEMENT_VALUES = frozenset({"undetected_to_detected", "false_alarm_to_clean"})
_REGRESSION_VALUES = frozenset({"detected_to_undetected", "clean_to_false_alarm"})
_FAILED_SIDE_VALUES = frozenset(
    {
        "failed_to_detect",
        "failed_to_undetect",
        "failed_to_clean",
        "failed_to_false_alarm",
        "detected_to_failed",
        "undetected_to_failed",
        "clean_to_failed",
        "false_alarm_to_failed",
        "failed_to_failed",
    }
)
_UNCHANGED_VALUES = frozenset(
    {
        "detected_to_detected",
        "undetected_to_undetected",
        "clean_to_clean",
        "false_alarm_to_false_alarm",
    }
)


class ScenarioReplayError(RuntimeError):
    """Safe replay failure without echoing any corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Scenario replay failed ({code}).")


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class ScenarioOutcomeTransition(_Strict):
    """One per-task outcome change between adjacent runs; value-free."""

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    transition: OutcomeTransitionValue


class ChannelReplayComparison(_Strict):
    """Per-channel comparison of one baseline and one candidate run."""

    channel: MetricsChannelKind
    baseline_run_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=_RUN_ID_PATTERN)
    ]
    candidate_run_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=_RUN_ID_PATTERN)
    ]
    asr_before: Annotated[float, Field(ge=0, le=1)]
    asr_after: Annotated[float, Field(ge=0, le=1)]
    asr_delta: Annotated[float, Field(ge=-1, le=1)]
    utility_before: Annotated[float, Field(ge=0, le=1)]
    utility_after: Annotated[float, Field(ge=0, le=1)]
    utility_delta: Annotated[float, Field(ge=-1, le=1)]
    precision_before: Annotated[float, Field(ge=0, le=1)]
    precision_after: Annotated[float, Field(ge=0, le=1)]
    precision_delta: Annotated[float, Field(ge=-1, le=1)]
    recall_before: Annotated[float, Field(ge=0, le=1)]
    recall_after: Annotated[float, Field(ge=0, le=1)]
    recall_delta: Annotated[float, Field(ge=-1, le=1)]
    false_positive_rate_before: Annotated[float, Field(ge=0, le=1)]
    false_positive_rate_after: Annotated[float, Field(ge=0, le=1)]
    false_positive_rate_delta: Annotated[float, Field(ge=-1, le=1)]
    false_negative_rate_before: Annotated[float, Field(ge=0, le=1)]
    false_negative_rate_after: Annotated[float, Field(ge=0, le=1)]
    false_negative_rate_delta: Annotated[float, Field(ge=-1, le=1)]
    task_count: Annotated[int, Field(ge=1)]
    improved_task_count: Annotated[int, Field(ge=0)]
    regressed_task_count: Annotated[int, Field(ge=0)]
    failed_side_task_count: Annotated[int, Field(ge=0)]
    unchanged_task_count: Annotated[int, Field(ge=0)]
    comparison_complete: bool
    transitions: Annotated[
        tuple[ScenarioOutcomeTransition, ...],
        Field(max_length=_MAX_REPLAY_TRANSITIONS),
    ] = ()
    note: Annotated[str, Field(min_length=8, max_length=512)] = _REPLAY_NOTE
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def comparison_must_be_coherent(self) -> ChannelReplayComparison:
        if self.baseline_run_id == self.candidate_run_id:
            raise ValueError("comparison run ids must differ")
        self._deltas_must_match()
        if (
            self.improved_task_count
            + self.regressed_task_count
            + self.failed_side_task_count
            + self.unchanged_task_count
            != self.task_count
        ):
            raise ValueError("transition counts do not sum to task count")
        if len(self.transitions) != self.task_count:
            raise ValueError("transition rows do not match task count")
        transition_ids = tuple(item.case_id for item in self.transitions)
        if transition_ids != tuple(sorted(set(transition_ids))):
            raise ValueError("transition rows must be sorted by case ID and unique")
        counts = _classify_transitions(self.transitions)
        if counts != (
            self.improved_task_count,
            self.regressed_task_count,
            self.failed_side_task_count,
            self.unchanged_task_count,
        ):
            raise ValueError("transition rows do not match classified counts")
        if self.comparison_complete and self.failed_side_task_count:
            raise ValueError("complete comparison cannot carry failed transitions")
        return self

    def _deltas_must_match(self) -> None:
        checks = (
            ("asr", self.asr_before, self.asr_after, self.asr_delta),
            ("utility", self.utility_before, self.utility_after, self.utility_delta),
            (
                "precision",
                self.precision_before,
                self.precision_after,
                self.precision_delta,
            ),
            ("recall", self.recall_before, self.recall_after, self.recall_delta),
            (
                "false_positive_rate",
                self.false_positive_rate_before,
                self.false_positive_rate_after,
                self.false_positive_rate_delta,
            ),
            (
                "false_negative_rate",
                self.false_negative_rate_before,
                self.false_negative_rate_after,
                self.false_negative_rate_delta,
            ),
        )
        for name, before, after, delta in checks:
            if abs(delta - (after - before)) > _EPSILON:
                raise ValueError(f"{name} delta does not match run metrics")


class ScenarioReplayRun(_Strict):
    """One historical replay of the frozen packs under one configuration."""

    format: Literal["agentsec-p3-15-scenario-replay-run"] = (
        "agentsec-p3-15-scenario-replay-run"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128, pattern=_RUN_ID_PATTERN)]
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    prompt_version: Annotated[str, Field(min_length=1, max_length=32)]
    metrics: ScenarioMetricsReport
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False

    @field_validator("prompt_version")
    @classmethod
    def prompt_version_must_be_semver(cls, value: str) -> str:
        parse_interface_version(value)
        return value

    @model_validator(mode="after")
    def run_must_be_coherent(self) -> ScenarioReplayRun:
        if (
            self.provider_id != self.metrics.provider_id
            or self.model_id != self.metrics.model_id
        ):
            raise ValueError("replay run identity must match its metrics report")
        return self


class ScenarioReplaySuite(_Strict):
    """Immutable replay chain: runs plus adjacent-run channel comparisons."""

    format: Literal["agentsec-p3-15-scenario-replay-suite"] = (
        "agentsec-p3-15-scenario-replay-suite"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    run_count: Annotated[int, Field(ge=2, le=_MAX_REPLAY_RUNS)]
    runs: Annotated[
        tuple[ScenarioReplayRun, ...],
        Field(min_length=2, max_length=_MAX_REPLAY_RUNS),
    ]
    comparison_count: Annotated[int, Field(ge=1)]
    comparisons: tuple[ChannelReplayComparison, ...]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _REPLAY_NOTE
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    policy_authority: Literal[False] = False
    release_authority: Literal[False] = False
    provider_promotion_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def suite_must_be_coherent(self) -> ScenarioReplaySuite:
        if self.run_count != len(self.runs):
            raise ValueError("replay run count is inconsistent")
        run_ids = tuple(run.run_id for run in self.runs)
        if len(set(run_ids)) != len(run_ids):
            raise ValueError("replay run IDs must be unique")
        configurations = tuple(
            (run.provider_id, run.model_id, run.prompt_version) for run in self.runs
        )
        if len(set(configurations)) != len(configurations):
            raise ValueError("replay run configurations must be unique")
        if self.comparison_count != len(self.comparisons):
            raise ValueError("replay comparison count is inconsistent")
        channel_sets = [
            {channel.channel for channel in run.metrics.channels} for run in self.runs
        ]
        if any(channels != channel_sets[0] for channels in channel_sets[1:]):
            raise ValueError("replay runs must cover the same channels")
        expected_pairs = tuple(
            (self.runs[index - 1].run_id, self.runs[index].run_id)
            for index in range(1, len(self.runs))
        )
        pairs_by_channel: dict[MetricsChannelKind, list[tuple[str, str]]] = {}
        for comparison in self.comparisons:
            pairs_by_channel.setdefault(comparison.channel, []).append(
                (comparison.baseline_run_id, comparison.candidate_run_id)
            )
        channel_count = len(channel_sets[0])
        if self.comparison_count != channel_count * (len(self.runs) - 1):
            raise ValueError("each channel must compare adjacent runs exactly once")
        for pairs in pairs_by_channel.values():
            if tuple(pairs) != expected_pairs:
                raise ValueError("each channel must compare adjacent runs exactly once")
        return self


class ReplayRunSpec:
    """Caller-declared replay entry: adapter plus configuration identity."""

    __slots__ = ("adapter", "prompt_version", "run_id")

    def __init__(
        self,
        *,
        adapter: SemanticShadowInvocationAdapter,
        prompt_version: str,
        run_id: str,
    ) -> None:
        if not isinstance(adapter, SemanticShadowInvocationAdapter):
            raise TypeError(
                "replay spec adapter must be SemanticShadowInvocationAdapter"
            )
        if not isinstance(prompt_version, str) or not prompt_version.strip():
            raise TypeError("replay spec prompt_version must be a non-empty string")
        parse_interface_version(prompt_version)
        if not isinstance(run_id, str) or not run_id.strip():
            raise TypeError("replay spec run_id must be a non-empty string")
        self.adapter = adapter
        self.prompt_version = prompt_version
        self.run_id = run_id


ScenarioPack = AgentDojoScenarioSet | InjecAgentScenarioSet


class ScenarioReplayRunner:
    """Replay frozen packs across configurations and compare upgrades."""

    def replay(
        self,
        packs: tuple[ScenarioPack, ...],
        specs: tuple[ReplayRunSpec, ...],
    ) -> ScenarioReplaySuite:
        if not isinstance(packs, tuple) or not packs:
            raise ScenarioReplayError("packs_missing")
        if not isinstance(specs, tuple):
            raise ScenarioReplayError("specs_invalid")
        if len(specs) < 2:
            raise ScenarioReplayError("insufficient_runs")
        if len(specs) > _MAX_REPLAY_RUNS:
            raise ScenarioReplayError("too_many_runs")

        runs: list[ScenarioReplayRun] = []
        for spec in specs:
            if not isinstance(spec, ReplayRunSpec):
                raise ScenarioReplayError("specs_invalid")
            report = evaluate_scenario_metrics(packs, spec.adapter)
            metadata = spec.adapter.provider_metadata
            runs.append(
                ScenarioReplayRun(
                    run_id=spec.run_id,
                    provider_id=metadata.provider_id,
                    model_id=metadata.model_id,
                    prompt_version=spec.prompt_version,
                    metrics=report,
                )
            )
        run_ids = [run.run_id for run in runs]
        if len(set(run_ids)) != len(run_ids):
            raise ScenarioReplayError("duplicate_run_id")
        configurations = [
            (run.provider_id, run.model_id, run.prompt_version) for run in runs
        ]
        if len(set(configurations)) != len(configurations):
            raise ScenarioReplayError("duplicate_run_configuration")

        comparisons: list[ChannelReplayComparison] = []
        for previous, current in zip(runs, runs[1:], strict=False):
            comparisons.extend(_compare_runs(previous, current))
        return ScenarioReplaySuite(
            run_count=len(runs),
            runs=tuple(runs),
            comparison_count=len(comparisons),
            comparisons=tuple(comparisons),
        )


def _compare_runs(
    baseline: ScenarioReplayRun,
    candidate: ScenarioReplayRun,
) -> list[ChannelReplayComparison]:
    before_channels = {
        channel.channel: channel for channel in baseline.metrics.channels
    }
    after_channels = {
        channel.channel: channel for channel in candidate.metrics.channels
    }
    if set(before_channels) != set(after_channels):
        raise ScenarioReplayError("channel_mismatch")
    return [
        _compare_channel(
            baseline,
            candidate,
            before_channels[channel_kind],
            after_channels[channel_kind],
        )
        for channel_kind in sorted(before_channels, key=lambda item: item.value)
    ]


def _compare_channel(
    baseline: ScenarioReplayRun,
    candidate: ScenarioReplayRun,
    before: ChannelScenarioMetrics,
    after: ChannelScenarioMetrics,
) -> ChannelReplayComparison:
    if before.attack_task_count != after.attack_task_count or (
        before.normal_task_count != after.normal_task_count
    ):
        raise ScenarioReplayError("task_count_mismatch")
    before_outcomes = {row.case_id: row.outcome for row in before.task_results}
    after_outcomes = {row.case_id: row.outcome for row in after.task_results}
    if set(before_outcomes) != set(after_outcomes):
        raise ScenarioReplayError("case_set_mismatch")

    transitions: list[ScenarioOutcomeTransition] = []
    for case_id in sorted(before_outcomes):
        outcome_before = before_outcomes[case_id]
        outcome_after = after_outcomes[case_id]
        transitions.append(
            ScenarioOutcomeTransition(
                case_id=case_id,
                transition=_transition_value(outcome_before, outcome_after),
            )
        )
    improved, regressed, failed_side, unchanged = _classify_transitions(
        tuple(transitions)
    )
    return ChannelReplayComparison(
        channel=before.channel,
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        asr_before=before.asr_detection_proxy,
        asr_after=after.asr_detection_proxy,
        asr_delta=after.asr_detection_proxy - before.asr_detection_proxy,
        utility_before=before.utility_detection_proxy,
        utility_after=after.utility_detection_proxy,
        utility_delta=(after.utility_detection_proxy - before.utility_detection_proxy),
        precision_before=before.precision,
        precision_after=after.precision,
        precision_delta=after.precision - before.precision,
        recall_before=before.recall,
        recall_after=after.recall,
        recall_delta=after.recall - before.recall,
        false_positive_rate_before=before.false_positive_rate,
        false_positive_rate_after=after.false_positive_rate,
        false_positive_rate_delta=(
            after.false_positive_rate - before.false_positive_rate
        ),
        false_negative_rate_before=before.false_negative_rate,
        false_negative_rate_after=after.false_negative_rate,
        false_negative_rate_delta=(
            after.false_negative_rate - before.false_negative_rate
        ),
        task_count=before.attack_task_count + before.normal_task_count,
        improved_task_count=improved,
        regressed_task_count=regressed,
        failed_side_task_count=failed_side,
        unchanged_task_count=unchanged,
        comparison_complete=(before.metrics_complete and after.metrics_complete),
        transitions=tuple(transitions),
    )


def _transition_value(
    before: ScenarioTaskOutcome,
    after: ScenarioTaskOutcome,
) -> OutcomeTransitionValue:
    key = (before, after)
    value = _TRANSITION_MAP.get(key)
    if value is None:
        raise ScenarioReplayError("unknown_transition")
    return value  # type: ignore[return-value]


def _classify_transitions(
    transitions: tuple[ScenarioOutcomeTransition, ...],
) -> tuple[int, int, int, int]:
    improved = regressed = failed_side = unchanged = 0
    for item in transitions:
        if item.transition in _IMPROVEMENT_VALUES:
            improved += 1
        elif item.transition in _REGRESSION_VALUES:
            regressed += 1
        elif item.transition in _FAILED_SIDE_VALUES:
            failed_side += 1
        else:
            unchanged += 1
    return improved, regressed, failed_side, unchanged


def encode_scenario_replay_json(value: ScenarioReplaySuite) -> str:
    """Encode the replay suite as canonical versioned JSON."""

    if not isinstance(value, ScenarioReplaySuite):
        raise TypeError("scenario replay encoder requires ScenarioReplaySuite")
    return value.model_dump_json(indent=2)


__all__ = [
    "SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION",
    "SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION",
    "ChannelReplayComparison",
    "ReplayRunSpec",
    "ScenarioOutcomeTransition",
    "ScenarioReplayError",
    "ScenarioReplayRunner",
    "ScenarioReplayRun",
    "ScenarioReplaySuite",
    "encode_scenario_replay_json",
]

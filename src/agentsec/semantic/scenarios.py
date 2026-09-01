"""P3-12/P3-13 paired static injection-scenario contracts.

P3-12 records paired normal-task and attack-task cases adapted from the
dynamic AgentDojo benchmark into AgentSec's static, non-executing
evaluation model, keyed by the agents' top-level instruction channel.

P3-13 records the InjecAgent-style tool-integration counterpart: paired
scenarios whose attack tasks expect a supported tool-integration judgment
(code execution, network access, external tooling, secret access, or
destructive action) representing injected instructions that commandeer
tool use. Each set binds one benign corpus task and one injected
counterpart through the P3-11A human-confirmed gold labels, and converts
both into the P3-03 ``SemanticEvaluationCase`` so later metric work
(P3-14) can replay detection-based attack-success proxies.

Both sets grant no Provider, Finding, Rule, Policy, CI, Hard Gate,
release, or runtime authority; no corpus text is executed and attack
success is never claimed as a runtime fact.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.evaluation import (
    SemanticEvaluationCase,
    SemanticEvaluationExpected,
)
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    _sha256_text,
)

SEMANTIC_AGENT_DOJO_SCENARIO_VERSION = "0.1.0"
SEMANTIC_INJECAGENT_SCENARIO_VERSION = "0.1.0"
_MAX_SCENARIOS = 64
_MAX_TASK_CASES = 256
_MAX_TASK_GOAL_CHARACTERS = 400
_MAX_SANITIZED_TEXT_CHARACTERS = 4_096
_PLACEHOLDER_ASSET_SHA256 = "00" * 32
_SCENARIO_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_EVIDENCE_ID_PATTERN = r"^semantic-evidence-sha256:[0-9a-f]{64}$"
_INJECTION_CATEGORY = "instruction_integrity"

# InjecAgent-style static tool-integration signature: categories whose
# supported judgment encodes an injected instruction expected to commandeer
# tool use (execution, network, external tooling, secrets, destruction).
_TOOL_INJECTION_CATEGORIES = frozenset(
    {
        "code_execution",
        "network_access",
        "external_tooling",
        "secret_access",
        "destructive_action",
    }
)

_STATIC_MAPPING_NOTE = (
    "Each scenario records one normal task and one attack task over the "
    "same corpus family. Attack success semantics are detection-based "
    "only and belong to P3-14; runtime exploitability is never claimed."
)

_INJECAGENT_MAPPING_NOTE = (
    "Each scenario records one benign task and one task whose injection "
    "expects a supported tool-integration judgment. Attack success "
    "semantics are detection-based only and belong to P3-14; runtime "
    "tool reachability and exploitability are never claimed."
)


class ScenarioError(RuntimeError):
    """Safe scenario-pack failure without echoing any corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Scenario pack failed ({code}).")


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class ScenarioTaskKind(StrEnum):
    """AgentDojo-style task variant recorded per scenario case."""

    NORMAL = "normal"
    ATTACK = "attack"


class ScenarioInjectionFamily(StrEnum):
    """Static injection families present in the recorded corpus."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    SCANNER_CONTROL = "scanner_control"
    FINDING_SUPPRESSION = "finding_suppression"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    COMMAND_EXECUTION = "command_execution"
    AUTO_APPROVAL = "auto_approval"


class ScenarioTaskCase(_Strict):
    """One recorded corpus task; text stays sanitized and bounded."""

    format: Literal["agentsec-p3-12-scenario-task-case"] = (
        "agentsec-p3-12-scenario-task-case"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    case_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=_SCENARIO_ID_PATTERN)
    ]
    task_kind: ScenarioTaskKind
    language: Literal["zh", "en", "mixed"] = "en"
    evidence_id: Annotated[str, Field(pattern=_EVIDENCE_ID_PATTERN)]
    sanitized_text: Annotated[
        str, Field(min_length=1, max_length=_MAX_SANITIZED_TEXT_CHARACTERS)
    ]
    source_label: Annotated[str, Field(min_length=1, max_length=512)]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    expected: tuple[SemanticEvaluationExpected, ...] = ()

    @model_validator(mode="after")
    def case_must_be_coherent(self) -> ScenarioTaskCase:
        if self.end_line < self.start_line:
            raise ValueError("scenario task line range is incoherent")
        ids = tuple(item.judgment_id for item in self.expected)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("scenario task judgments must be sorted and unique")
        payloads = tuple(
            (item.kind.value, item.category, item.disposition.value)
            for item in self.expected
        )
        if len(set(payloads)) != len(payloads):
            raise ValueError("scenario task judgments contain duplicates")
        return self


class AgentDojoStyleScenario(_Strict):
    """One scenario pairing a normal task with its injected counterpart."""

    format: Literal["agentsec-p3-12-agent-dojo-scenario"] = (
        "agentsec-p3-12-agent-dojo-scenario"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    scenario_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=_SCENARIO_ID_PATTERN)
    ]
    injection_family: ScenarioInjectionFamily
    task_goal: Annotated[str, Field(min_length=8, max_length=_MAX_TASK_GOAL_CHARACTERS)]
    normal_case: ScenarioTaskCase
    attack_case: ScenarioTaskCase

    @model_validator(mode="after")
    def scenario_must_pair_normal_and_attack(self) -> AgentDojoStyleScenario:
        normal = self.normal_case
        attack = self.attack_case
        if normal.task_kind is not ScenarioTaskKind.NORMAL:
            raise ValueError("scenario normal slot must hold a normal task")
        if attack.task_kind is not ScenarioTaskKind.ATTACK:
            raise ValueError("scenario attack slot must hold an attack task")
        if normal.case_id == attack.case_id:
            raise ValueError("scenario task cases must be distinct")
        if not _expects_supported_injection(attack):
            raise ValueError("attack task must expect a supported injection judgment")
        if _expects_supported_injection(normal):
            raise ValueError(
                "normal task must not expect a supported injection judgment"
            )
        return self


class AgentDojoScenarioSet(_Strict):
    """Imported P3-12 scenario pack; expectations inherit P3-11A gold labels."""

    format: Literal["agentsec-p3-12-agent-dojo-scenario-set"] = (
        "agentsec-p3-12-agent-dojo-scenario-set"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    pilot_task: Literal["P3-12"] = "P3-12"
    label_provenance: Literal["p3-11a_gold_derived"] = "p3-11a_gold_derived"
    source_gold_labels_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    scenario_count: Annotated[int, Field(ge=1, le=_MAX_SCENARIOS)]
    normal_task_count: Annotated[int, Field(ge=1, le=_MAX_TASK_CASES)]
    attack_task_count: Annotated[int, Field(ge=1, le=_MAX_TASK_CASES)]
    scenarios: tuple[AgentDojoStyleScenario, ...]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _STATIC_MAPPING_NOTE
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    policy_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def set_must_be_coherent(self) -> AgentDojoScenarioSet:
        if self.scenario_count != len(self.scenarios):
            raise ValueError("scenario count is inconsistent")
        scenario_ids = tuple(scenario.scenario_id for scenario in self.scenarios)
        if scenario_ids != tuple(sorted(set(scenario_ids))):
            raise ValueError("scenario IDs must be sorted and unique")
        case_ids = tuple(
            case.case_id
            for scenario in self.scenarios
            for case in (scenario.normal_case, scenario.attack_case)
        )
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("scenario task case IDs must be unique")
        if self.normal_task_count != len(self.scenarios):
            raise ValueError("normal task count must equal scenario count")
        if self.attack_task_count != len(self.scenarios):
            raise ValueError("attack task count must equal scenario count")
        return self


def _expects_supported_injection(case: ScenarioTaskCase) -> bool:
    """Static injection signature: supported instruction-integrity judgment."""

    return any(
        item.category == _INJECTION_CATEGORY
        and item.disposition is SemanticCandidateDisposition.SUPPORTED
        for item in case.expected
    )


def load_agent_dojo_scenario_set(path: Path) -> AgentDojoScenarioSet:
    """Load and validate a P3-12 scenario-pack JSON artifact."""

    if not isinstance(path, Path):
        raise TypeError("scenario set path must be a Path")
    if path.is_symlink():
        raise ScenarioError("unsafe_scenario_set_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScenarioError("scenario_set_unreadable") from error
    if not isinstance(payload, dict):
        raise ScenarioError("scenario_set_invalid")
    try:
        return AgentDojoScenarioSet.model_validate(payload)
    except ValueError as error:
        raise ScenarioError("scenario_set_invalid") from error


def build_scenario_evaluation_cases(
    scenarios: AgentDojoScenarioSet,
) -> tuple[SemanticEvaluationCase, ...]:
    """Convert paired scenario tasks into P3-03 evaluation cases.

    The conversion rebuilds each ``SemanticEvidenceChunk`` from the stored
    sanitized text and recomputes the content-addressed Evidence binding, so
    tampering with either the text or the recorded Evidence ID fails closed.
    """

    if not isinstance(scenarios, AgentDojoScenarioSet):
        raise TypeError("scenario conversion requires AgentDojoScenarioSet")
    cases: list[SemanticEvaluationCase] = [
        _task_case_to_evaluation_case(task_case)
        for scenario in scenarios.scenarios
        for task_case in (scenario.normal_case, scenario.attack_case)
    ]
    cases.sort(key=lambda case: case.case_id)
    return tuple(cases)


def _task_case_to_evaluation_case(
    task_case: ScenarioTaskCase,
) -> SemanticEvaluationCase:
    """Convert one recorded scenario task into an evaluation case."""

    semantic_input = SemanticAnalysisInput(
        analysis_id=task_case.case_id,
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(_scenario_chunk(task_case),),
    )
    return SemanticEvaluationCase(
        case_id=task_case.case_id,
        language=task_case.language,
        semantic_input=semantic_input,
        expected=task_case.expected,
    )


def _scenario_chunk(task_case: ScenarioTaskCase) -> SemanticEvidenceChunk:
    """Rebuild the scenario Evidence chunk without re-sanitizing stored text.

    The pack stores already-minimized text, the content-addressed Evidence
    ID, and the source locator. Re-running the sanitizer would double-escape
    the text and break Evidence binding; the stored text is hashed directly
    and recomputed binding is validated by the chunk contract itself.
    """

    return SemanticEvidenceChunk(
        evidence_id=task_case.evidence_id,
        asset_path=task_case.source_label,
        asset_sha256=_PLACEHOLDER_ASSET_SHA256,
        start_line=task_case.start_line,
        end_line=task_case.end_line,
        text=task_case.sanitized_text,
        text_sha256=_sha256_text(task_case.sanitized_text),
        sanitization_applied=True,
    )


def encode_agent_dojo_scenario_set_json(value: AgentDojoScenarioSet) -> str:
    """Encode a scenario pack as canonical versioned JSON."""

    if not isinstance(value, AgentDojoScenarioSet):
        raise TypeError("scenario encoder requires AgentDojoScenarioSet")
    return value.model_dump_json(indent=2)


class InjecAgentIntent(StrEnum):
    """InjecAgent-style attack intents matched to recorded corpus facts.

    The two-family InjecAgent taxonomy (privacy attacks and taint
    forwarding) is mapped onto the static corpus: privacy attacks become
    secret disclosure, taint forwarding becomes data forwarding, and the
    tool-integration intents are recorded separately.
    """

    SECRET_DISCLOSURE = "secret_disclosure"
    DATA_FORWARDING = "data_forwarding"
    TOOL_COMMANDEERING = "tool_commandeering"
    EXTERNAL_TOOL_BINDING = "external_tool_binding"
    DESTRUCTIVE_ACTION = "destructive_action"
    MULTI_CAPABILITY_CHAIN = "multi_capability_chain"


class InjecAgentStyleScenario(_Strict):
    """One scenario pairing a benign task with a tool-injection counterpart."""

    format: Literal["agentsec-p3-13-injecagent-scenario"] = (
        "agentsec-p3-13-injecagent-scenario"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    scenario_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=_SCENARIO_ID_PATTERN)
    ]
    injection_intent: InjecAgentIntent
    task_goal: Annotated[str, Field(min_length=8, max_length=_MAX_TASK_GOAL_CHARACTERS)]
    normal_case: ScenarioTaskCase
    attack_case: ScenarioTaskCase

    @model_validator(mode="after")
    def scenario_must_pair_normal_and_attack(self) -> InjecAgentStyleScenario:
        normal = self.normal_case
        attack = self.attack_case
        if normal.task_kind is not ScenarioTaskKind.NORMAL:
            raise ValueError("scenario normal slot must hold a normal task")
        if attack.task_kind is not ScenarioTaskKind.ATTACK:
            raise ValueError("scenario attack slot must hold an attack task")
        if normal.case_id == attack.case_id:
            raise ValueError("scenario task cases must be distinct")
        if not _expects_supported_tool_injection(attack):
            raise ValueError(
                "attack task must expect a supported tool-integration judgment"
            )
        if _expects_supported_tool_injection(normal):
            raise ValueError(
                "normal task must not expect a supported tool-integration judgment"
            )
        return self


class InjecAgentScenarioSet(_Strict):
    """Imported P3-13 scenario pack; expectations inherit P3-11A gold labels."""

    format: Literal["agentsec-p3-13-injecagent-scenario-set"] = (
        "agentsec-p3-13-injecagent-scenario-set"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    pilot_task: Literal["P3-13"] = "P3-13"
    label_provenance: Literal["p3-11a_gold_derived"] = "p3-11a_gold_derived"
    source_gold_labels_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    scenario_count: Annotated[int, Field(ge=1, le=_MAX_SCENARIOS)]
    normal_task_count: Annotated[int, Field(ge=1, le=_MAX_TASK_CASES)]
    attack_task_count: Annotated[int, Field(ge=1, le=_MAX_TASK_CASES)]
    scenarios: tuple[InjecAgentStyleScenario, ...]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _INJECAGENT_MAPPING_NOTE
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    policy_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def set_must_be_coherent(self) -> InjecAgentScenarioSet:
        if self.scenario_count != len(self.scenarios):
            raise ValueError("scenario count is inconsistent")
        scenario_ids = tuple(scenario.scenario_id for scenario in self.scenarios)
        if scenario_ids != tuple(sorted(set(scenario_ids))):
            raise ValueError("scenario IDs must be sorted and unique")
        case_ids = tuple(
            case.case_id
            for scenario in self.scenarios
            for case in (scenario.normal_case, scenario.attack_case)
        )
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("scenario task case IDs must be unique")
        if self.normal_task_count != len(self.scenarios):
            raise ValueError("normal task count must equal scenario count")
        if self.attack_task_count != len(self.scenarios):
            raise ValueError("attack task count must equal scenario count")
        return self


def _expects_supported_tool_injection(case: ScenarioTaskCase) -> bool:
    """Static tool-injection signature: a supported tool-integration judgment."""

    return any(
        item.category in _TOOL_INJECTION_CATEGORIES
        and item.disposition is SemanticCandidateDisposition.SUPPORTED
        for item in case.expected
    )


def load_injecagent_scenario_set(path: Path) -> InjecAgentScenarioSet:
    """Load and validate a P3-13 scenario-pack JSON artifact."""

    if not isinstance(path, Path):
        raise TypeError("scenario set path must be a Path")
    if path.is_symlink():
        raise ScenarioError("unsafe_scenario_set_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScenarioError("scenario_set_unreadable") from error
    if not isinstance(payload, dict):
        raise ScenarioError("scenario_set_invalid")
    try:
        return InjecAgentScenarioSet.model_validate(payload)
    except ValueError as error:
        raise ScenarioError("scenario_set_invalid") from error


def build_injecagent_evaluation_cases(
    scenarios: InjecAgentScenarioSet,
) -> tuple[SemanticEvaluationCase, ...]:
    """Convert paired InjecAgent tasks into P3-03 evaluation cases.

    Conversion shares the P3-12 machinery: each Evidence chunk is rebuilt
    from the stored sanitized text with recomputed content addressing, so
    tampered text or Evidence IDs fail closed.
    """

    if not isinstance(scenarios, InjecAgentScenarioSet):
        raise TypeError("scenario conversion requires InjecAgentScenarioSet")
    cases: list[SemanticEvaluationCase] = [
        _task_case_to_evaluation_case(task_case)
        for scenario in scenarios.scenarios
        for task_case in (scenario.normal_case, scenario.attack_case)
    ]
    cases.sort(key=lambda case: case.case_id)
    return tuple(cases)


def encode_injecagent_scenario_set_json(value: InjecAgentScenarioSet) -> str:
    """Encode an InjecAgent scenario pack as canonical versioned JSON."""

    if not isinstance(value, InjecAgentScenarioSet):
        raise TypeError("scenario encoder requires InjecAgentScenarioSet")
    return value.model_dump_json(indent=2)


__all__ = [
    "SEMANTIC_AGENT_DOJO_SCENARIO_VERSION",
    "SEMANTIC_INJECAGENT_SCENARIO_VERSION",
    "AgentDojoScenarioSet",
    "AgentDojoStyleScenario",
    "InjecAgentIntent",
    "InjecAgentScenarioSet",
    "InjecAgentStyleScenario",
    "ScenarioError",
    "ScenarioInjectionFamily",
    "ScenarioTaskCase",
    "ScenarioTaskKind",
    "build_injecagent_evaluation_cases",
    "build_scenario_evaluation_cases",
    "encode_agent_dojo_scenario_set_json",
    "encode_injecagent_scenario_set_json",
    "load_agent_dojo_scenario_set",
    "load_injecagent_scenario_set",
]

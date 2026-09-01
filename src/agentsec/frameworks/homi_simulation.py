"""Pure dry-run simulation for Homi capability paths (P2-HOMI-05).

The simulator creates an in-memory decision trace from a static Homi Profile.
It never executes source text, invokes a tool, contacts a scheduler, or accepts
an execution callback.  A ``declared_path`` result means only that the static
Profile would describe the path; it is not runtime reachability proof.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal

from agentsec.frameworks.homi_combination import (
    HOMI_COMBINATION_RULE_PACK_VERSION,
    DeterministicHomiCombinationRuleEngine,
    HomiCombinationEvidence,
    HomiCombinationRuleFailure,
)
from agentsec.frameworks.homi_profile import (
    HomiCapabilityKind,
    HomiCapabilityProfile,
    HomiCapabilityState,
    HomiPersonaSignal,
    HomiProfileSignal,
)

HOMI_SAFE_SIMULATION_FORMAT: Literal["agentsec-homi-safe-simulation"] = (
    "agentsec-homi-safe-simulation"
)
HOMI_SAFE_SIMULATION_FORMAT_VERSION = "0.1.0"
HOMI_SAFE_SIMULATION_MODEL_VERSION = "0.2.0"
HOMI_SAFE_SIMULATION_BASIS = (
    "AgentSec P2-HOMI-05 deterministic dry-run simulation contract 0.1.0",
    "Simulation is an in-memory plan and never executes source or external actions",
    "Static declarations do not prove runtime reachability or scheduler execution",
    "Example-only tool notes are suppressed rather than treated as active access",
)

_SCENARIO_ID_PATTERN = re.compile(r"^HOMI-SIM-[0-9]{3}$")
_MAX_SCENARIOS = 8
_MAX_STEPS = 32


class HomiSimulationLanguage(StrEnum):
    """Text languages for the standalone safe-simulation report."""

    EN = "en"
    ZH = "zh"


class HomiSimulationScenarioId(StrEnum):
    """Stable bounded simulation scenarios derived from P2-HOMI-04 paths."""

    HEARTBEAT_EXTERNAL = "HOMI-SIM-001"
    PROACTIVE_EXTERNAL = "HOMI-SIM-002"
    USER_MEMORY = "HOMI-SIM-003"
    SELF_MODIFICATION = "HOMI-SIM-004"
    TOOLS_SKILLS = "HOMI-SIM-005"


class HomiSimulationTrigger(StrEnum):
    """Static trigger context used by a simulation scenario."""

    HEARTBEAT_TICK = "heartbeat_tick"
    PROACTIVE_PERSONA = "proactive_persona"
    USER_PROFILE_UPDATE = "user_profile_update"
    CONTROL_FILE_UPDATE = "control_file_update"
    SKILL_DISCOVERY = "skill_discovery"


class HomiSimulationAction(StrEnum):
    """Action labels only; no implementation is attached to these labels."""

    EXTERNAL_NETWORK_READ = "external_network_read"
    EXTERNAL_TOOL_USE = "external_tool_use"
    MEMORY_PERSIST = "memory_persist"
    CONTROL_FILE_WRITE = "control_file_write"
    TOOL_DISCOVERY = "tool_discovery"


class HomiSimulationOutcome(StrEnum):
    """What the static dry-run plan can conclude about one scenario."""

    DECLARED_PATH = "declared_path"
    NOT_DECLARED = "not_declared"
    BLOCKED_EXAMPLE_ONLY = "blocked_example_only"
    BLOCKED_STATIC_BOUNDARY = "blocked_static_boundary"
    UNKNOWN_COVERAGE = "unknown_coverage"


@dataclass(frozen=True, slots=True)
class HomiSimulationScenario:
    """Safe scenario descriptor containing no command, URL, or user payload."""

    scenario_id: HomiSimulationScenarioId
    trigger: HomiSimulationTrigger
    action: HomiSimulationAction
    description: str

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, HomiSimulationScenarioId):
            raise TypeError("Homi simulation scenario ID is invalid")
        if not isinstance(self.trigger, HomiSimulationTrigger):
            raise TypeError("Homi simulation trigger is invalid")
        if not isinstance(self.action, HomiSimulationAction):
            raise TypeError("Homi simulation action is invalid")
        _require_text(self.description, "Homi simulation scenario description")

    def sort_key(self) -> str:
        return self.scenario_id.value


@dataclass(frozen=True, slots=True)
class HomiSafeSimulationRequest:
    """Bounded selection of built-in dry-run scenarios."""

    scenarios: tuple[HomiSimulationScenarioId, ...] = tuple(HomiSimulationScenarioId)

    def __post_init__(self) -> None:
        if not isinstance(self.scenarios, tuple) or not self.scenarios:
            raise ValueError("Homi simulation requires at least one scenario")
        if len(self.scenarios) > _MAX_SCENARIOS:
            raise ValueError("Homi simulation scenario limit exceeded")
        if any(
            not isinstance(item, HomiSimulationScenarioId) for item in self.scenarios
        ):
            raise TypeError("Homi simulation scenario selection is invalid")
        if self.scenarios != tuple(
            sorted(set(self.scenarios), key=lambda item: item.value)
        ):
            raise ValueError("Homi simulation scenarios must be sorted and unique")


@dataclass(frozen=True, slots=True)
class HomiSimulationStep:
    """One non-executed, source-linked step in a simulated path."""

    scenario_id: HomiSimulationScenarioId
    trigger: HomiSimulationTrigger
    action: HomiSimulationAction
    outcome: HomiSimulationOutcome
    related_signal_ids: tuple[str, ...]
    evidence: tuple[HomiCombinationEvidence, ...] = dataclass_field(repr=False)
    rationale: tuple[str, ...]
    limitations: tuple[str, ...]
    executed: Literal[False] = False
    side_effects: Literal[False] = False
    runtime_verified: Literal[False] = False

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, HomiSimulationScenarioId):
            raise TypeError("Homi simulation step scenario ID is invalid")
        if not isinstance(self.trigger, HomiSimulationTrigger):
            raise TypeError("Homi simulation step trigger is invalid")
        if not isinstance(self.action, HomiSimulationAction):
            raise TypeError("Homi simulation step action is invalid")
        if not isinstance(self.outcome, HomiSimulationOutcome):
            raise TypeError("Homi simulation step outcome is invalid")
        if self.related_signal_ids != tuple(sorted(set(self.related_signal_ids))):
            raise ValueError("Homi simulation signal IDs must be sorted and unique")
        if tuple(item.signal_id for item in self.evidence) != self.related_signal_ids:
            raise ValueError("Homi simulation evidence IDs are inconsistent")
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("Homi simulation evidence must be sorted and unique")
        _require_text_tuple(self.rationale, "Homi simulation rationale")
        _require_text_tuple(self.limitations, "Homi simulation limitations")
        if self.executed is not False:
            raise ValueError("Homi safe simulation cannot execute actions")
        if self.side_effects is not False:
            raise ValueError("Homi safe simulation cannot produce side effects")
        if self.runtime_verified is not False:
            raise ValueError("Homi safe simulation cannot claim runtime verification")

    def sort_key(self) -> tuple[str, tuple[str, ...], str]:
        return (self.scenario_id.value, self.related_signal_ids, self.outcome.value)

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id.value,
            "trigger": self.trigger.value,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "related_signal_ids": list(self.related_signal_ids),
            "evidence": [item.to_dict() for item in self.evidence],
            "rationale": list(self.rationale),
            "limitations": list(self.limitations),
            "executed": self.executed,
            "side_effects": self.side_effects,
            "runtime_verified": self.runtime_verified,
        }


@dataclass(frozen=True, slots=True)
class HomiSafeSimulationResult:
    """Versioned dry-run output kept separate from static Findings."""

    format: Literal["agentsec-homi-safe-simulation"]
    format_version: str
    model_version: str
    mode: Literal["dry_run"]
    profile_complete: bool
    scenarios: tuple[HomiSimulationScenario, ...]
    steps: tuple[HomiSimulationStep, ...]
    static_combination_finding_ids: tuple[str, ...]
    combination_rule_failures: tuple[HomiCombinationRuleFailure, ...]
    limitations: tuple[str, ...]
    executed: Literal[False] = False
    side_effects: Literal[False] = False
    runtime_verified: Literal[False] = False
    combination_rule_pack_version: str = HOMI_COMBINATION_RULE_PACK_VERSION

    def __post_init__(self) -> None:
        if self.format != HOMI_SAFE_SIMULATION_FORMAT:
            raise ValueError("Homi simulation format is unsupported")
        if self.format_version != HOMI_SAFE_SIMULATION_FORMAT_VERSION:
            raise ValueError("Homi simulation format version is unsupported")
        if self.model_version != HOMI_SAFE_SIMULATION_MODEL_VERSION:
            raise ValueError("Homi simulation model version is unsupported")
        if self.mode != "dry_run":
            raise ValueError("Homi simulation mode must be dry_run")
        if not isinstance(self.profile_complete, bool):
            raise TypeError("Homi simulation profile_complete must be bool")
        if not self.scenarios or len(self.scenarios) > _MAX_SCENARIOS:
            raise ValueError("Homi simulation scenario count is invalid")
        scenario_ids = tuple(item.scenario_id for item in self.scenarios)
        if scenario_ids != tuple(
            sorted(set(scenario_ids), key=lambda item: item.value)
        ):
            raise ValueError("Homi simulation scenarios must be sorted and unique")
        if len(self.steps) > _MAX_STEPS:
            raise ValueError("Homi simulation step limit exceeded")
        step_keys = tuple(item.sort_key() for item in self.steps)
        if step_keys != tuple(sorted(set(step_keys))):
            raise ValueError("Homi simulation steps must be sorted and unique")
        if any(item.scenario_id not in scenario_ids for item in self.steps):
            raise ValueError("Homi simulation step references an unknown scenario")
        if self.static_combination_finding_ids != tuple(
            sorted(set(self.static_combination_finding_ids))
        ):
            raise ValueError("Homi static Finding IDs must be sorted and unique")
        if self.combination_rule_failures != tuple(
            sorted(set(self.combination_rule_failures))
        ):
            raise ValueError("Homi simulation rule failures must be sorted and unique")
        _require_text_tuple(self.limitations, "Homi simulation limitations")
        if self.executed is not False:
            raise ValueError("Homi simulation result cannot claim execution")
        if self.side_effects is not False:
            raise ValueError("Homi simulation result cannot claim side effects")
        if self.runtime_verified is not False:
            raise ValueError("Homi simulation result cannot claim runtime verification")
        if self.combination_rule_pack_version != HOMI_COMBINATION_RULE_PACK_VERSION:
            raise ValueError("Homi simulation combination Rule Pack is unsupported")

    @property
    def complete(self) -> bool:
        """Return whether Profile coverage and combination evaluation are complete."""

        return self.profile_complete and not self.combination_rule_failures

    @property
    def outcome_counts(self) -> tuple[tuple[HomiSimulationOutcome, int], ...]:
        """Return deterministic counts for presenter and report consumers."""

        counts = {outcome: 0 for outcome in HomiSimulationOutcome}
        for step in self.steps:
            counts[step.outcome] += 1
        return tuple((outcome, counts[outcome]) for outcome in HomiSimulationOutcome)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "mode": self.mode,
            "profile_complete": self.profile_complete,
            "complete": self.complete,
            "scenarios": [
                {
                    "scenario_id": item.scenario_id.value,
                    "trigger": item.trigger.value,
                    "action": item.action.value,
                    "description": item.description,
                }
                for item in self.scenarios
            ],
            "steps": [item.to_dict() for item in self.steps],
            "outcome_counts": {
                outcome.value: count for outcome, count in self.outcome_counts
            },
            "static_combination_finding_ids": list(self.static_combination_finding_ids),
            "combination_rule_failures": [
                item.rule_id for item in self.combination_rule_failures
            ],
            "limitations": list(self.limitations),
            "executed": self.executed,
            "side_effects": self.side_effects,
            "runtime_verified": self.runtime_verified,
            "combination_rule_pack_version": self.combination_rule_pack_version,
        }


def builtin_homi_simulation_scenarios() -> tuple[HomiSimulationScenario, ...]:
    """Return the fixed, bounded scenario catalog."""

    return (
        HomiSimulationScenario(
            scenario_id=HomiSimulationScenarioId.HEARTBEAT_EXTERNAL,
            trigger=HomiSimulationTrigger.HEARTBEAT_TICK,
            action=HomiSimulationAction.EXTERNAL_NETWORK_READ,
            description=(
                "Preview whether a Heartbeat tick would reach a declared external "
                "network-read path."
            ),
        ),
        HomiSimulationScenario(
            scenario_id=HomiSimulationScenarioId.PROACTIVE_EXTERNAL,
            trigger=HomiSimulationTrigger.PROACTIVE_PERSONA,
            action=HomiSimulationAction.EXTERNAL_TOOL_USE,
            description=(
                "Preview whether proactive behavior would reach an active external "
                "capability."
            ),
        ),
        HomiSimulationScenario(
            scenario_id=HomiSimulationScenarioId.USER_MEMORY,
            trigger=HomiSimulationTrigger.USER_PROFILE_UPDATE,
            action=HomiSimulationAction.MEMORY_PERSIST,
            description=(
                "Preview whether a user-profile update would enter persistent memory."
            ),
        ),
        HomiSimulationScenario(
            scenario_id=HomiSimulationScenarioId.SELF_MODIFICATION,
            trigger=HomiSimulationTrigger.CONTROL_FILE_UPDATE,
            action=HomiSimulationAction.CONTROL_FILE_WRITE,
            description=(
                "Preview whether persona and identity self-modification guidance "
                "forms a control-file write path."
            ),
        ),
        HomiSimulationScenario(
            scenario_id=HomiSimulationScenarioId.TOOLS_SKILLS,
            trigger=HomiSimulationTrigger.SKILL_DISCOVERY,
            action=HomiSimulationAction.TOOL_DISCOVERY,
            description=(
                "Preview whether Skill discovery would reach an active local tool "
                "binding."
            ),
        ),
    )


class DeterministicHomiSafeSimulationEngine:
    """Build a dry-run trace without accepting or invoking execution hooks."""

    def __init__(self) -> None:
        self._combination_engine = DeterministicHomiCombinationRuleEngine()
        self._scenarios = {
            item.scenario_id: item for item in builtin_homi_simulation_scenarios()
        }

    def simulate(
        self,
        profile: HomiCapabilityProfile,
        request: HomiSafeSimulationRequest | None = None,
    ) -> HomiSafeSimulationResult:
        """Return a deterministic, non-executing trace for one Homi Profile."""

        if not isinstance(profile, HomiCapabilityProfile):
            raise TypeError("Homi safe simulation requires HomiCapabilityProfile")
        selected = request or HomiSafeSimulationRequest()
        if not isinstance(selected, HomiSafeSimulationRequest):
            raise TypeError("Homi safe simulation request is invalid")
        scenarios = tuple(self._scenarios[item] for item in selected.scenarios)
        combination_result = self._combination_engine.run(profile)
        steps = tuple(
            sorted(
                (self._simulate_scenario(scenario, profile) for scenario in scenarios),
                key=lambda item: item.sort_key(),
            )
        )
        return HomiSafeSimulationResult(
            format=HOMI_SAFE_SIMULATION_FORMAT,
            format_version=HOMI_SAFE_SIMULATION_FORMAT_VERSION,
            model_version=HOMI_SAFE_SIMULATION_MODEL_VERSION,
            mode="dry_run",
            profile_complete=profile.complete,
            scenarios=scenarios,
            steps=steps,
            static_combination_finding_ids=tuple(
                sorted(item.finding_id for item in combination_result.findings)
            ),
            combination_rule_failures=combination_result.failures,
            limitations=HOMI_SAFE_SIMULATION_BASIS,
        )

    def _simulate_scenario(
        self,
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        if scenario.scenario_id is HomiSimulationScenarioId.HEARTBEAT_EXTERNAL:
            return self._heartbeat_external(scenario, profile)
        if scenario.scenario_id is HomiSimulationScenarioId.PROACTIVE_EXTERNAL:
            return self._proactive_external(scenario, profile)
        if scenario.scenario_id is HomiSimulationScenarioId.USER_MEMORY:
            return self._user_memory(scenario, profile)
        if scenario.scenario_id is HomiSimulationScenarioId.SELF_MODIFICATION:
            return self._self_modification(scenario, profile)
        if scenario.scenario_id is HomiSimulationScenarioId.TOOLS_SKILLS:
            return self._tools_skills(scenario, profile)
        raise ValueError("unsupported Homi simulation scenario")

    @staticmethod
    def _heartbeat_external(
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        heartbeat = profile.heartbeat.signal
        external = _capability_signal(profile, HomiCapabilityKind.EXTERNAL_NETWORK_READ)
        evidence = _evidence(heartbeat, external)
        if profile.heartbeat.state is HomiCapabilityState.ABSENT:
            outcome = HomiSimulationOutcome.BLOCKED_STATIC_BOUNDARY
            rationale = (
                "HEARTBEAT.md is structurally empty; the simulated scheduler path "
                "is disabled by the static boundary.",
            )
        elif profile.heartbeat.state is HomiCapabilityState.EXAMPLE_ONLY:
            outcome = HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
            rationale = (
                "HEARTBEAT.md contains documentation/template content only; the "
                "simulated scheduler path is suppressed.",
            )
        elif profile.heartbeat.state is HomiCapabilityState.UNKNOWN:
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = (
                "Heartbeat state is unknown because the file is missing or coverage "
                "is incomplete.",
            )
        elif not profile.heartbeat.tasks_present:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = ("Heartbeat has no task content to drive this scenario.",)
        elif external is None or external.state is HomiCapabilityState.UNKNOWN:
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = (
                "Heartbeat tasks exist, but external network-read reachability is "
                "unknown.",
            )
        elif external.state is HomiCapabilityState.PRESENT:
            outcome = HomiSimulationOutcome.DECLARED_PATH
            rationale = (
                "A Heartbeat task and external network-read declaration form a "
                "dry-run path.",
            )
        else:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = (
                "Heartbeat tasks exist, but external network-read is not actively "
                "declared.",
            )
        return _step(scenario, outcome, evidence, rationale)

    @staticmethod
    def _proactive_external(
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        proactive = _persona_signal(profile, HomiPersonaSignal.PROACTIVE)
        active = _active_external_signals(profile)
        examples = _example_tool_signals(profile)
        evidence = _evidence(proactive, *(active or examples))
        if proactive is None:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = ("No proactive persona signal is present.",)
        elif active:
            outcome = HomiSimulationOutcome.DECLARED_PATH
            rationale = (
                "Proactive behavior and an active external capability form a dry-run "
                "path; no tool is called.",
            )
        elif examples:
            outcome = HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
            rationale = (
                "Only example-only tool notes are available, so the simulated path "
                "is suppressed.",
            )
        elif _has_unknown_external(profile):
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = (
                "Proactive behavior exists, but external capability coverage is "
                "incomplete or unknown.",
            )
        else:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = (
                "Proactive behavior exists, but no active external capability is "
                "declared.",
            )
        return _step(scenario, outcome, evidence, rationale)

    @staticmethod
    def _user_memory(
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        user = profile.user_privacy.persistence
        persistent = _capability_signal(profile, HomiCapabilityKind.PERSISTENT_MEMORY)
        evidence = _evidence(user, persistent)
        if user.state is HomiCapabilityState.UNKNOWN or persistent is None:
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = (
                "User persistence or persistent-memory state is not fully known.",
            )
        elif (
            user.state is HomiCapabilityState.PRESENT
            and persistent.state is HomiCapabilityState.PRESENT
        ):
            outcome = HomiSimulationOutcome.DECLARED_PATH
            rationale = (
                "User-profile persistence and persistent memory form a dry-run path; "
                "no user value is stored.",
            )
        else:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = (
                "User-profile persistence and persistent memory are not both actively "
                "declared.",
            )
        return _step(scenario, outcome, evidence, rationale)

    @staticmethod
    def _self_modification(
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        persona = _persona_signal(profile, HomiPersonaSignal.SELF_EVOLUTION)
        identity = profile.identity.self_assignment
        evidence = _evidence(persona, identity)
        if persona is None or identity.state is HomiCapabilityState.UNKNOWN:
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = ("Persona or identity self-modification state is unknown.",)
        elif identity.state is HomiCapabilityState.PRESENT:
            outcome = HomiSimulationOutcome.DECLARED_PATH
            rationale = (
                "Persona self-evolution and identity self-assignment form a dry-run "
                "control-file path; no file is written.",
            )
        else:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = (
                "Persona self-evolution and identity self-assignment are not both "
                "actively declared.",
            )
        return _step(scenario, outcome, evidence, rationale)

    @staticmethod
    def _tools_skills(
        scenario: HomiSimulationScenario,
        profile: HomiCapabilityProfile,
    ) -> HomiSimulationStep:
        skill = _capability_signal(profile, HomiCapabilityKind.SKILL_TOOL_DISCOVERY)
        active = _active_tool_signals(profile)
        examples = _example_tool_signals(profile)
        evidence = _evidence(skill, *(active or examples))
        if skill is None or skill.state is HomiCapabilityState.UNKNOWN:
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = ("Skill tool-discovery state is unknown.",)
        elif active:
            outcome = HomiSimulationOutcome.DECLARED_PATH
            rationale = (
                "Skill discovery and an active local tool binding form a dry-run path; "
                "no tool is discovered or called.",
            )
        elif examples:
            outcome = HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
            rationale = (
                "Only example-only tool notes are available, so Skill expansion is "
                "suppressed.",
            )
        elif _has_unknown_tools(profile):
            outcome = HomiSimulationOutcome.UNKNOWN_COVERAGE
            rationale = (
                "Skill discovery exists, but tool-binding coverage is incomplete or "
                "unknown.",
            )
        else:
            outcome = HomiSimulationOutcome.NOT_DECLARED
            rationale = (
                "Skill discovery and an active local tool binding are not both "
                "declared.",
            )
        return _step(scenario, outcome, evidence, rationale)


def _step(
    scenario: HomiSimulationScenario,
    outcome: HomiSimulationOutcome,
    evidence: tuple[HomiCombinationEvidence, ...],
    rationale: tuple[str, ...],
) -> HomiSimulationStep:
    return HomiSimulationStep(
        scenario_id=scenario.scenario_id,
        trigger=scenario.trigger,
        action=scenario.action,
        outcome=outcome,
        related_signal_ids=tuple(item.signal_id for item in evidence),
        evidence=evidence,
        rationale=rationale,
        limitations=(
            "This is a dry-run decision trace; no source, scheduler, tool, network, "
            "or file operation was executed.",
        ),
    )


def _evidence(
    *signals: HomiProfileSignal | None,
) -> tuple[HomiCombinationEvidence, ...]:
    return tuple(
        sorted(
            (
                HomiCombinationEvidence.from_signal(signal)
                for signal in signals
                if signal is not None
            ),
            key=lambda item: item.sort_key(),
        )
    )


def _capability_signal(
    profile: HomiCapabilityProfile,
    kind: HomiCapabilityKind,
) -> HomiProfileSignal | None:
    return next(
        (
            capability.signal
            for capability in profile.capabilities
            if capability.kind is kind
        ),
        None,
    )


def _persona_signal(
    profile: HomiCapabilityProfile,
    kind: HomiPersonaSignal,
) -> HomiProfileSignal | None:
    return next(
        (
            signal
            for signal in profile.persona.signals
            if signal.signal_id == kind.value
        ),
        None,
    )


def _active_external_signals(
    profile: HomiCapabilityProfile,
) -> tuple[HomiProfileSignal, ...]:
    kinds = {
        HomiCapabilityKind.EXTERNAL_NETWORK_READ,
        HomiCapabilityKind.EXTERNAL_MESSAGE_SEND,
        HomiCapabilityKind.MCP_ACCESS,
        HomiCapabilityKind.SSH_ACCESS,
        HomiCapabilityKind.CAMERA_ACCESS,
        HomiCapabilityKind.TTS_OUTPUT,
        HomiCapabilityKind.OAUTH_ACCESS,
        HomiCapabilityKind.SECRET_ACCESS,
    }
    return tuple(
        capability.signal
        for capability in profile.capabilities
        if capability.kind in kinds
        and capability.signal.state
        in {HomiCapabilityState.PRESENT, HomiCapabilityState.CONDITIONAL}
    )


def _active_tool_signals(
    profile: HomiCapabilityProfile,
) -> tuple[HomiProfileSignal, ...]:
    return tuple(
        signal
        for signal in (
            profile.tools.camera,
            profile.tools.ssh,
            profile.tools.tts,
            profile.tools.mcp,
            profile.tools.oauth,
            profile.tools.secret_access,
        )
        if signal.state
        in {HomiCapabilityState.PRESENT, HomiCapabilityState.CONDITIONAL}
    )


def _example_tool_signals(
    profile: HomiCapabilityProfile,
) -> tuple[HomiProfileSignal, ...]:
    return tuple(
        signal
        for signal in (
            profile.tools.camera,
            profile.tools.ssh,
            profile.tools.tts,
            profile.tools.mcp,
            profile.tools.oauth,
            profile.tools.secret_access,
        )
        if signal.state is HomiCapabilityState.EXAMPLE_ONLY
    )


def _has_unknown_external(profile: HomiCapabilityProfile) -> bool:
    kinds = {
        HomiCapabilityKind.EXTERNAL_NETWORK_READ,
        HomiCapabilityKind.EXTERNAL_MESSAGE_SEND,
        HomiCapabilityKind.MCP_ACCESS,
        HomiCapabilityKind.SSH_ACCESS,
        HomiCapabilityKind.CAMERA_ACCESS,
        HomiCapabilityKind.TTS_OUTPUT,
        HomiCapabilityKind.OAUTH_ACCESS,
        HomiCapabilityKind.SECRET_ACCESS,
    }
    return any(
        capability.kind in kinds
        and capability.signal.state is HomiCapabilityState.UNKNOWN
        for capability in profile.capabilities
    )


def _has_unknown_tools(profile: HomiCapabilityProfile) -> bool:
    return any(
        signal.state is HomiCapabilityState.UNKNOWN
        for signal in (
            profile.tools.camera,
            profile.tools.ssh,
            profile.tools.tts,
            profile.tools.mcp,
            profile.tools.oauth,
            profile.tools.secret_access,
        )
    )


def render_homi_safe_simulation_text(
    result: HomiSafeSimulationResult,
    *,
    language: HomiSimulationLanguage = HomiSimulationLanguage.EN,
) -> str:
    """Render a bounded standalone dry-run report for CLI consumers."""

    if not isinstance(result, HomiSafeSimulationResult):
        raise TypeError("Homi simulation text renderer requires a simulation result")
    if not isinstance(language, HomiSimulationLanguage):
        raise TypeError("Homi simulation language is invalid")
    counts = {item.value: count for item, count in result.outcome_counts}
    if language is HomiSimulationLanguage.ZH:
        lines = [
            "AgentSec Homi 安全模拟报告",
            "模式：dry_run；已执行：false；副作用：false；运行时验证：false",
            f"Profile 完整：{result.profile_complete}",
            f"模拟完成：{result.complete}",
            "",
            "结果统计",
            f"  声明路径：{counts.get('declared_path', 0)}",
            f"  未声明：{counts.get('not_declared', 0)}",
            f"  示例阻断：{counts.get('blocked_example_only', 0)}",
            f"  静态边界阻断：{counts.get('blocked_static_boundary', 0)}",
            f"  Unknown 覆盖：{counts.get('unknown_coverage', 0)}",
            "",
            "模拟步骤",
        ]
        lines.extend(
            f"  {step.scenario_id.value}: {step.outcome.value}" for step in result.steps
        )
    else:
        lines = [
            "AgentSec Homi Safe Simulation",
            "Mode: dry_run; executed=false; side_effects=false; runtime_verified=false",
            f"Profile complete: {result.profile_complete}",
            f"Simulation complete: {result.complete}",
            "",
            "Outcome counts",
            f"  Declared paths: {counts.get('declared_path', 0)}",
            f"  Not declared: {counts.get('not_declared', 0)}",
            f"  Example-only blocked: {counts.get('blocked_example_only', 0)}",
            f"  Static-boundary blocked: {counts.get('blocked_static_boundary', 0)}",
            f"  Unknown coverage: {counts.get('unknown_coverage', 0)}",
            "",
            "Simulation steps",
        ]
        lines.extend(
            f"  {step.scenario_id.value}: {step.outcome.value}" for step in result.steps
        )
    return "\n".join(lines) + "\n"


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{label} must be a non-empty tuple")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} must contain non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


def encode_homi_safe_simulation_json(result: HomiSafeSimulationResult) -> str:
    """Encode a safe simulation result as stable, non-secret JSON."""

    if not isinstance(result, HomiSafeSimulationResult):
        raise TypeError("Homi simulation JSON encoder requires a simulation result")
    return (
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


__all__ = [
    "HOMI_SAFE_SIMULATION_BASIS",
    "HOMI_SAFE_SIMULATION_FORMAT",
    "HOMI_SAFE_SIMULATION_FORMAT_VERSION",
    "HOMI_SAFE_SIMULATION_MODEL_VERSION",
    "DeterministicHomiSafeSimulationEngine",
    "HomiSafeSimulationRequest",
    "HomiSafeSimulationResult",
    "HomiSimulationAction",
    "HomiSimulationLanguage",
    "HomiSimulationOutcome",
    "HomiSimulationScenario",
    "HomiSimulationScenarioId",
    "HomiSimulationStep",
    "HomiSimulationTrigger",
    "builtin_homi_simulation_scenarios",
    "encode_homi_safe_simulation_json",
    "render_homi_safe_simulation_text",
]

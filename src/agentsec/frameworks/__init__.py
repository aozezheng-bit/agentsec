"""Public Framework Adapter seam and neutral inspection models."""

from importlib import import_module
from typing import Any

from agentsec.frameworks.base import (
    FrameworkAdapter,
    FrameworkAdapterError,
    FrameworkAdapterMetadata,
    FrameworkAsset,
    FrameworkAssetFormat,
    FrameworkAssetLocator,
    FrameworkAssetRecord,
    FrameworkAssetRole,
    FrameworkAssetScope,
    FrameworkInspectionIssue,
    FrameworkInspectionIssueCode,
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
    ParsedFrameworkDocument,
)
from agentsec.frameworks.codex import CodexAdapter
from agentsec.frameworks.homi import (
    HOMI_ADAPTER_VERSION,
    HomiAdapter,
    HomiFileRole,
    HomiFileState,
    HomiWorkspaceFile,
    HomiWorkspaceInspection,
)
from agentsec.frameworks.homi_policy import (
    HomiAuthorityDomain,
    HomiObservationCode,
    HomiObservationKind,
    HomiPolicyObservation,
    HomiResolutionStatus,
    HomiRolePolicy,
    HomiVisibility,
    HomiWorkspacePolicyResolver,
    HomiWorkspaceResolution,
)
from agentsec.frameworks.homi_profile import (
    HOMI_PROFILE_MODEL_VERSION,
    HomiAvatarKind,
    HomiCapability,
    HomiCapabilityKind,
    HomiCapabilityProfile,
    HomiCapabilityProfileBuilder,
    HomiCapabilityState,
    HomiEvidenceMethod,
    HomiHeartbeatProfile,
    HomiIdentityProfile,
    HomiPersonaProfile,
    HomiProfileSignal,
    HomiToolBindingProfile,
    HomiUserPrivacyProfile,
)

_HOMI_COMBINATION_EXPORTS = frozenset(
    {
        "HOMI_COMBINATION_RISK_MAPPING_BASIS",
        "HOMI_COMBINATION_RULE_PACK_VERSION",
        "DeterministicHomiCombinationRuleEngine",
        "HomiCombinationCandidate",
        "HomiCombinationEvidence",
        "HomiCombinationFinding",
        "HomiCombinationLanguage",
        "HomiCombinationRule",
        "HomiCombinationRuleEvaluation",
        "HomiCombinationRuleFailure",
        "HomiCombinationRuleId",
        "HomiCombinationRuleMetadata",
        "HomiCombinationRulePipelineError",
        "HomiCombinationRuleRegistryError",
        "HomiCombinationRuleText",
        "HomiCombinationRunResult",
        "builtin_homi_combination_rules",
    }
)
_HOMI_SIMULATION_EXPORTS = frozenset(
    {
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
    }
)
_HOMI_PILOT_EXPORTS = frozenset(
    {
        "HOMI_PILOT_EVIDENCE_MODE",
        "HOMI_PILOT_FORMAT",
        "HOMI_PILOT_FORMAT_VERSION",
        "HOMI_SAFE_SIMULATION_FORMAT_VERSION",
        "HOMI_SAFE_SIMULATION_MODEL_VERSION",
        "DeterministicHomiReportOnlyPilot",
        "HomiPilotError",
        "HomiPilotFileSummary",
        "HomiPilotLanguage",
        "HomiPilotObservationSummary",
        "HomiPilotReport",
        "HomiPilotRequest",
        "HomiPilotSignalSummary",
        "HomiPilotStatus",
        "encode_homi_pilot_json",
        "render_homi_pilot_text",
    }
)


def __getattr__(name: str) -> Any:
    """Lazily expose Homi combination types without manifest import cycles."""

    if name in _HOMI_COMBINATION_EXPORTS:
        module = import_module(".homi_combination", __name__)
    elif name in _HOMI_SIMULATION_EXPORTS:
        module = import_module(".homi_simulation", __name__)
    elif name in _HOMI_PILOT_EXPORTS:
        module = import_module(".homi_pilot", __name__)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(module, name)
    globals()[name] = value
    return value


__all__ = [
    "FrameworkAdapter",
    "FrameworkAdapterError",
    "FrameworkAdapterMetadata",
    "FrameworkAsset",
    "FrameworkAssetFormat",
    "FrameworkAssetLocator",
    "FrameworkAssetRecord",
    "FrameworkAssetRole",
    "FrameworkAssetScope",
    "FrameworkInspectionIssue",
    "FrameworkInspectionIssueCode",
    "FrameworkInspectionLimits",
    "FrameworkInspectionRequest",
    "FrameworkInspectionResult",
    "ParsedFrameworkDocument",
    "CodexAdapter",
    "HomiAdapter",
    "HOMI_ADAPTER_VERSION",
    "HomiFileRole",
    "HomiFileState",
    "HomiWorkspaceFile",
    "HomiWorkspaceInspection",
    "HomiAuthorityDomain",
    "HomiObservationCode",
    "HomiObservationKind",
    "HomiPolicyObservation",
    "HomiResolutionStatus",
    "HomiRolePolicy",
    "HomiVisibility",
    "HomiWorkspacePolicyResolver",
    "HomiWorkspaceResolution",
    "HOMI_COMBINATION_RISK_MAPPING_BASIS",
    "HOMI_COMBINATION_RULE_PACK_VERSION",
    "DeterministicHomiCombinationRuleEngine",
    "HomiCombinationCandidate",
    "HomiCombinationEvidence",
    "HomiCombinationFinding",
    "HomiCombinationLanguage",
    "HomiCombinationRule",
    "HomiCombinationRuleEvaluation",
    "HomiCombinationRuleFailure",
    "HomiCombinationRuleId",
    "HomiCombinationRuleMetadata",
    "HomiCombinationRulePipelineError",
    "HomiCombinationRuleRegistryError",
    "HomiCombinationRuleText",
    "HomiCombinationRunResult",
    "builtin_homi_combination_rules",
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
    "HOMI_PILOT_EVIDENCE_MODE",
    "HOMI_PILOT_FORMAT",
    "HOMI_PILOT_FORMAT_VERSION",
    "DeterministicHomiReportOnlyPilot",
    "HomiPilotError",
    "HomiPilotFileSummary",
    "HomiPilotLanguage",
    "HomiPilotObservationSummary",
    "HomiPilotReport",
    "HomiPilotRequest",
    "HomiPilotSignalSummary",
    "HomiPilotStatus",
    "encode_homi_pilot_json",
    "render_homi_pilot_text",
    "HomiAvatarKind",
    "HOMI_PROFILE_MODEL_VERSION",
    "HomiCapability",
    "HomiCapabilityKind",
    "HomiCapabilityProfile",
    "HomiCapabilityProfileBuilder",
    "HomiCapabilityState",
    "HomiEvidenceMethod",
    "HomiHeartbeatProfile",
    "HomiIdentityProfile",
    "HomiPersonaProfile",
    "HomiProfileSignal",
    "HomiToolBindingProfile",
    "HomiUserPrivacyProfile",
]

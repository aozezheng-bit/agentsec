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
_HOMI_BUNDLE_EXPORTS = frozenset(
    {
        "HOMI_COMBINED_REPORT_FORMAT",
        "HOMI_COMBINED_REPORT_VERSION",
        "HomiCombinedReport",
        "HomiCombinedReportError",
        "HomiRecommendation",
        "build_homi_combined_report",
        "build_homi_recommendations",
        "encode_homi_combined_report_json",
        "render_homi_combined_report_html",
        "render_homi_combined_report_text",
    }
)
_HOMI_DIFF_EXPORTS = frozenset(
    {
        "HOMI_CAPABILITY_DIFF_FORMAT",
        "HOMI_CAPABILITY_DIFF_VERSION",
        "HomiCapabilityChange",
        "HomiCapabilityChangeType",
        "HomiCapabilityDiffError",
        "HomiCapabilityDiffReport",
        "HomiFindingDelta",
        "HomiFindingDeltaType",
        "compare_homi_reports",
        "encode_homi_capability_diff_json",
        "render_homi_capability_diff_html",
        "render_homi_capability_diff_text",
    }
)
_HOMI_PROVENANCE_EXPORTS = frozenset(
    {
        "HOMI_BUILD_COMMIT_ENVIRONMENT",
        "HOMI_BUILD_COMMIT_UNAVAILABLE",
        "HOMI_BUILD_DIGEST_ALGORITHM",
        "HOMI_BUILD_PROVENANCE_VERSION",
        "HomiBuildProvenance",
        "build_homi_build_provenance",
        "encode_homi_build_provenance_json",
        "render_homi_build_provenance_text",
    }
)
_HOMI_OPERATIONALITY_EXPORTS = frozenset(
    {
        "HOMI_OPERATIONALITY_FORMAT",
        "HOMI_OPERATIONALITY_FORMAT_VERSION",
        "HomiOperationality",
        "HomiOperationalityEntry",
        "HomiOperationalityReport",
        "build_homi_operationality_report",
        "encode_homi_operationality_json",
    }
)
_HOMI_OPERATION_CONTEXT_EXPORTS = frozenset(
    {
        "HOMI_OPERATION_CONTEXT_BASIS",
        "HOMI_OPERATION_CONTEXT_FORMAT",
        "HOMI_OPERATION_CONTEXT_FORMAT_VERSION",
        "HomiOperationContextExtractionError",
        "HomiOperationContextExtractor",
        "HomiOperationContextReport",
        "build_homi_operation_context_report",
        "build_homi_operation_context_report_from_workspace",
        "build_manifest_operation_context_set",
        "build_homi_operation_context_set",
        "encode_homi_operation_context_json",
        "export_homi_operation_context_json_schema",
    }
)
_HOMI_RISK_STATE_EXPORTS = frozenset(
    {
        "HOMI_RISK_STATE_BASIS",
        "HOMI_RISK_STATE_FORMAT",
        "HOMI_RISK_STATE_FORMAT_VERSION",
        "HomiRiskState",
        "HomiRiskStateEntry",
        "HomiRiskStateReport",
        "HomiRiskStateScope",
        "build_homi_risk_state_report",
        "encode_homi_risk_state_json",
        "export_homi_risk_state_json_schema",
    }
)
_HOMI_RISK_EXPORTS = frozenset(
    {
        "HOMI_RISK_BASIS",
        "HOMI_RISK_FORMAT",
        "HOMI_RISK_FORMAT_VERSION",
        "HomiRiskFindingSummary",
        "HomiRiskReport",
        "build_homi_risk_report",
        "encode_homi_risk_report_json",
        "export_homi_risk_report_json_schema",
    }
)
_HOMI_DRIFT_EXPORTS = frozenset(
    {
        "HOMI_DRIFT_BASIS",
        "HOMI_DRIFT_FORMAT",
        "HOMI_DRIFT_FORMAT_VERSION",
        "HomiDriftChangeType",
        "HomiDriftFileChange",
        "HomiDriftFindingDelta",
        "HomiDriftFindingDeltaType",
        "HomiDriftObservationChange",
        "HomiDriftReport",
        "HomiDriftSignalChange",
        "build_homi_drift_report",
        "encode_homi_drift_report_json",
        "export_homi_drift_report_json_schema",
    }
)
_HOMI_SNAPSHOT_EXPORTS = frozenset(
    {
        "HOMI_SNAPSHOT_BASIS",
        "HOMI_SNAPSHOT_FORMAT",
        "HOMI_SNAPSHOT_FORMAT_VERSION",
        "HOMI_SNAPSHOT_VERIFICATION_FORMAT",
        "HomiSnapshot",
        "HomiSnapshotContextFindingSummary",
        "HomiSnapshotContextScoreSummary",
        "HomiSnapshotFileSummary",
        "HomiSnapshotFindingSummary",
        "HomiSnapshotObservationSummary",
        "HomiSnapshotOperationContextSummary",
        "HomiSnapshotSignalSummary",
        "HomiSnapshotStatus",
        "HomiSnapshotVerification",
        "build_homi_snapshot",
        "decode_homi_snapshot_json",
        "encode_homi_snapshot_json",
        "encode_homi_snapshot_verification_json",
        "export_homi_snapshot_json_schema",
        "verify_homi_snapshot",
    }
)
_HOMI_POSTURE_EXPORTS = frozenset(
    {
        "HOMI_POSTURE_FORMAT",
        "HOMI_POSTURE_FORMAT_VERSION",
        "HomiCurrentPosture",
        "HomiPostureFinding",
        "HomiPostureReport",
        "build_homi_posture_report",
        "encode_homi_posture_json",
    }
)
_HOMI_CALIBRATION_EXPORTS = frozenset(
    {
        "HOMI_CALIBRATION_FORMAT",
        "HOMI_CALIBRATION_FORMAT_VERSION",
        "HomiCalibrationDecision",
        "HomiCalibrationDisposition",
        "HomiCalibrationReport",
        "build_homi_calibration_report",
        "encode_homi_calibration_json",
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
        "render_homi_pilot_html",
        "render_homi_pilot_text",
    }
)


def __getattr__(name: str) -> Any:
    """Lazily expose Homi combination types without manifest import cycles."""

    if name in _HOMI_COMBINATION_EXPORTS:
        module = import_module(".homi_combination", __name__)
    elif name in _HOMI_BUNDLE_EXPORTS:
        module = import_module(".homi_bundle", __name__)
    elif name in _HOMI_DIFF_EXPORTS:
        module = import_module(".homi_diff", __name__)
    elif name in _HOMI_SIMULATION_EXPORTS:
        module = import_module(".homi_simulation", __name__)
    elif name in _HOMI_PROVENANCE_EXPORTS:
        module = import_module(".homi_provenance", __name__)
    elif name in _HOMI_OPERATIONALITY_EXPORTS:
        module = import_module(".homi_operationality", __name__)
    elif name in _HOMI_OPERATION_CONTEXT_EXPORTS:
        module = import_module(".homi_operation_context", __name__)
    elif name in _HOMI_RISK_STATE_EXPORTS:
        module = import_module(".homi_risk_state", __name__)
    elif name in _HOMI_SNAPSHOT_EXPORTS:
        module = import_module(".homi_snapshot", __name__)
    elif name in _HOMI_DRIFT_EXPORTS:
        module = import_module(".homi_drift", __name__)
    elif name in _HOMI_RISK_EXPORTS:
        module = import_module(".homi_risk", __name__)
    elif name in _HOMI_POSTURE_EXPORTS:
        module = import_module(".homi_posture", __name__)
    elif name in _HOMI_CALIBRATION_EXPORTS:
        module = import_module(".homi_calibration", __name__)
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
    "HOMI_CAPABILITY_DIFF_FORMAT",
    "HOMI_CAPABILITY_DIFF_VERSION",
    "HomiCapabilityChange",
    "HomiCapabilityChangeType",
    "HomiCapabilityDiffError",
    "HomiCapabilityDiffReport",
    "HomiFindingDelta",
    "HomiFindingDeltaType",
    "compare_homi_reports",
    "encode_homi_capability_diff_json",
    "render_homi_capability_diff_html",
    "render_homi_capability_diff_text",
    "HOMI_BUILD_COMMIT_ENVIRONMENT",
    "HOMI_BUILD_COMMIT_UNAVAILABLE",
    "HOMI_BUILD_DIGEST_ALGORITHM",
    "HOMI_BUILD_PROVENANCE_VERSION",
    "HomiBuildProvenance",
    "build_homi_build_provenance",
    "encode_homi_build_provenance_json",
    "render_homi_build_provenance_text",
    "HOMI_OPERATIONALITY_FORMAT",
    "HOMI_OPERATIONALITY_FORMAT_VERSION",
    "HomiOperationality",
    "HomiOperationalityEntry",
    "HomiOperationalityReport",
    "build_homi_operationality_report",
    "encode_homi_operationality_json",
    "HOMI_RISK_STATE_BASIS",
    "HOMI_RISK_STATE_FORMAT",
    "HOMI_RISK_STATE_FORMAT_VERSION",
    "HomiRiskState",
    "HomiRiskStateEntry",
    "HomiRiskStateReport",
    "HomiRiskStateScope",
    "build_homi_risk_state_report",
    "encode_homi_risk_state_json",
    "export_homi_risk_state_json_schema",
    "HOMI_SNAPSHOT_BASIS",
    "HOMI_SNAPSHOT_FORMAT",
    "HOMI_SNAPSHOT_FORMAT_VERSION",
    "HOMI_SNAPSHOT_VERIFICATION_FORMAT",
    "HomiSnapshot",
    "HomiSnapshotContextFindingSummary",
    "HomiSnapshotContextScoreSummary",
    "HomiSnapshotFileSummary",
    "HomiSnapshotFindingSummary",
    "HomiSnapshotObservationSummary",
    "HomiSnapshotOperationContextSummary",
    "HomiSnapshotSignalSummary",
    "HomiSnapshotStatus",
    "HomiSnapshotVerification",
    "build_homi_snapshot",
    "decode_homi_snapshot_json",
    "encode_homi_snapshot_json",
    "encode_homi_snapshot_verification_json",
    "export_homi_snapshot_json_schema",
    "verify_homi_snapshot",
    "HOMI_DRIFT_BASIS",
    "HOMI_DRIFT_FORMAT",
    "HOMI_DRIFT_FORMAT_VERSION",
    "HomiDriftChangeType",
    "HomiDriftFileChange",
    "HomiDriftFindingDelta",
    "HomiDriftFindingDeltaType",
    "HomiDriftObservationChange",
    "HomiDriftReport",
    "HomiDriftSignalChange",
    "build_homi_drift_report",
    "encode_homi_drift_report_json",
    "export_homi_drift_report_json_schema",
    "HOMI_RISK_BASIS",
    "HOMI_RISK_FORMAT",
    "HOMI_RISK_FORMAT_VERSION",
    "HomiRiskFindingSummary",
    "HomiRiskReport",
    "build_homi_risk_report",
    "encode_homi_risk_report_json",
    "export_homi_risk_report_json_schema",
    "HOMI_OPERATION_CONTEXT_BASIS",
    "HOMI_OPERATION_CONTEXT_FORMAT",
    "HOMI_OPERATION_CONTEXT_FORMAT_VERSION",
    "HomiOperationContextExtractionError",
    "HomiOperationContextExtractor",
    "HomiOperationContextReport",
    "build_homi_operation_context_report",
    "build_homi_operation_context_report_from_workspace",
    "build_manifest_operation_context_set",
    "build_homi_operation_context_set",
    "encode_homi_operation_context_json",
    "export_homi_operation_context_json_schema",
    "HOMI_POSTURE_FORMAT",
    "HOMI_POSTURE_FORMAT_VERSION",
    "HomiCurrentPosture",
    "HomiPostureFinding",
    "HomiPostureReport",
    "build_homi_posture_report",
    "encode_homi_posture_json",
    "HOMI_CALIBRATION_FORMAT",
    "HOMI_CALIBRATION_FORMAT_VERSION",
    "HomiCalibrationDecision",
    "HomiCalibrationDisposition",
    "HomiCalibrationReport",
    "build_homi_calibration_report",
    "encode_homi_calibration_json",
    "HomiAuthorityDomain",
    "HomiObservationCode",
    "HomiObservationKind",
    "HomiPolicyObservation",
    "HomiResolutionStatus",
    "HomiRolePolicy",
    "HomiVisibility",
    "HomiWorkspacePolicyResolver",
    "HomiWorkspaceResolution",
    "HOMI_COMBINED_REPORT_FORMAT",
    "HOMI_COMBINED_REPORT_VERSION",
    "HomiCombinedReport",
    "HomiCombinedReportError",
    "HomiRecommendation",
    "build_homi_combined_report",
    "build_homi_recommendations",
    "encode_homi_combined_report_json",
    "render_homi_combined_report_html",
    "render_homi_combined_report_text",
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
    "render_homi_pilot_html",
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

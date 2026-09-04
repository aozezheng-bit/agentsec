"""Complete public interface version provenance registry (P2-EXIT-05).

Every public AgentSec interface version is classified into exactly one
provenance class. No record grants authorization authority: deterministic
Rules and reviewed Policy own every CI decision, and model versions never
imply authority. Phase 3 contracts may be activated in Shadow-only mode, while
unapproved future interfaces remain reserved without implying capability or
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agentsec import versioning
from agentsec.attack_graph import (
    ATTACK_GRAPH_BUILDER_VERSION,
    ATTACK_GRAPH_SCHEMA_VERSION,
    ATTACK_PATH_CALIBRATION_VERSION,
    ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION,
    ATTACK_PATH_PATTERN_LIBRARY_VERSION,
    ATTACK_PATH_REPORT_VERSION,
)
from agentsec.calibration.pilot_review import (
    FULL_PACK_SCHEMA_VERSION,
    JOINT_EVIDENCE_SCHEMA_VERSION,
    PILOT_SCHEMA_VERSION,
)
from agentsec.external_pilot import EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION
from agentsec.pilot import (
    PILOT_HUMAN_LABELS_SCHEMA_VERSION,
    PILOT_PLAN_SCHEMA_VERSION,
    PILOT_REPORT_OUTPUT_VERSION,
)
from agentsec.risk.attack_path_score import ATTACK_PATH_SCORE_CONTEXT_VERSION
from agentsec.risk.cvss import CVSS_ADAPTER_VERSION
from agentsec.semantic import (
    SEMANTIC_ANALYZE_VERSION,
    SEMANTIC_ANALYZER_VERSION,
    SEMANTIC_CANDIDATE_CALIBRATION_VERSION,
    SEMANTIC_EVALUATION_OUTPUT_VERSION,
    SEMANTIC_EVALUATION_SCHEMA_VERSION,
    SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION,
    SEMANTIC_FEEDBACK_SET_VERSION,
    SEMANTIC_FINDING_INTEGRATION_VERSION,
    SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION,
    SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION,
    SEMANTIC_INPUT_SCHEMA_VERSION,
    SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
    SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION,
    SEMANTIC_MODEL_ID,
    SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_MODEL_PROVIDER_ID,
    SEMANTIC_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_PROMOTION_REPORT_VERSION,
    SEMANTIC_PROMOTION_SCHEMA_VERSION,
    SEMANTIC_PROMPT_SCHEMA_VERSION,
    SEMANTIC_PROMPT_VERSION,
    SEMANTIC_PROVIDER_CONTRACT_VERSION,
    SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
    SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION,
    SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION,
    SEMANTIC_QUALIFICATION_VERSION,
    SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION,
    SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION,
    SEMANTIC_RULE_PACK_STAGING_VERSION,
    SEMANTIC_RULE_PROMOTION_VERSION,
    SEMANTIC_SCENARIO_METRICS_OUTPUT_VERSION,
    SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION,
    SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION,
    SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION,
    SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
    SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
    SEMANTIC_SHADOW_MODE_OUTPUT_VERSION,
    SEMANTIC_SHADOW_MODE_VERSION,
    SEMANTIC_SHADOW_PIPELINE_VERSION,
    SEMANTIC_TRIAL_CASE_SET_VERSION,
    SEMANTIC_TRIAL_CONFIG_VERSION,
)
from agentsec.versioning import (
    CONTEXT_RISK_REPORT_VERSION,
    CONTEXT_RULE_PACK_VERSION,
)
from agentsec.vulnerabilities.input import VULNERABILITY_INPUT_VERSION
from agentsec.vulnerabilities.sources import VULNERABILITY_CATALOG_VERSION


class InterfaceClassification(StrEnum):
    """Provenance classes for every public interface version."""

    PRODUCT_VECTOR = "product_version_vector"
    REPORT_FAMILY = "report_family_version_vector"
    HISTORICAL_IMMUTABLE = "historical_and_immutable"
    FIXTURE_OR_INTERNAL = "fixture_only_or_internal"
    RESERVED_PHASE3 = "reserved_phase3"


@dataclass(frozen=True, slots=True)
class InterfaceProvenance:
    """One public interface version with governance metadata."""

    name: str
    version: str | None
    classification: InterfaceClassification
    group: str
    grants_authority: bool = False
    schema_file: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "classification": self.classification.value,
            "group": self.group,
            "grants_authority": self.grants_authority,
            "schema_file": self.schema_file,
            "notes": self.notes,
        }


_AUTHORITY_NOTE = "version records carry no authorization authority"


def _product(
    name: str, version: str, group: str, **extra: object
) -> InterfaceProvenance:
    return InterfaceProvenance(
        name=name,
        version=version,
        classification=InterfaceClassification.PRODUCT_VECTOR,
        group=group,
        notes=_AUTHORITY_NOTE,
        **extra,  # type: ignore[arg-type]
    )


def _report(
    name: str, version: str, group: str, **extra: object
) -> InterfaceProvenance:
    return InterfaceProvenance(
        name=name,
        version=version,
        classification=InterfaceClassification.REPORT_FAMILY,
        group=group,
        notes=_AUTHORITY_NOTE,
        **extra,  # type: ignore[arg-type]
    )


def _history(name: str, version: str, notes: str) -> InterfaceProvenance:
    return InterfaceProvenance(
        name=name,
        version=version,
        classification=InterfaceClassification.HISTORICAL_IMMUTABLE,
        group="frozen_artifacts",
        notes=notes,
    )


def _fixture(name: str, version: str | None, notes: str) -> InterfaceProvenance:
    return InterfaceProvenance(
        name=name,
        version=version,
        classification=InterfaceClassification.FIXTURE_OR_INTERNAL,
        group="internal_evidence",
        notes=notes,
    )


def _reserved(name: str, notes: str) -> InterfaceProvenance:
    return InterfaceProvenance(
        name=name,
        version=None,
        classification=InterfaceClassification.RESERVED_PHASE3,
        group="phase3_reservation",
        notes=notes,
    )


PHASE3_RESERVED_INTERFACE_NAMES: tuple[str, ...] = (
    "RULE_CANDIDATE_WORKFLOW_VERSION",
    "ATTACK_GRAPH_VERSION",
    "RUNTIME_ATTESTATION_VERSION",
)


def interface_provenance_registry() -> tuple[InterfaceProvenance, ...]:
    """Return the complete, classified public interface version registry."""

    version_set_fields = (
        "PACKAGE_VERSION",
        "CONFIG_SCHEMA_VERSION",
        "DOMAIN_SCHEMA_VERSION",
        "AGENT_MANIFEST_SCHEMA_VERSION",
        "CAPABILITY_DIFF_SCHEMA_VERSION",
        "CAPABILITY_RULE_PACK_VERSION",
        "CAPABILITY_RISK_MODEL_VERSION",
        "CAPABILITY_ASSESSMENT_OUTPUT_VERSION",
        "CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION",
        "BASELINE_SCHEMA_VERSION",
        "DIFF_OUTPUT_VERSION",
        "ASSESSMENT_OUTPUT_VERSION",
        "RULE_PACK_VERSION",
        "RISK_MODEL_VERSION",
        "CVSS_HARD_GATE_VERSION",
        "CAPABILITY_SHADOW_GATE_VERSION",
    )
    records: list[InterfaceProvenance] = []
    for name in version_set_fields:
        records.append(
            _product(
                name,
                str(getattr(versioning, name)),
                "product_version_vector",
            )
        )

    records.extend(
        (
            # Policy and trust contracts
            _product(
                "ORGANIZATION_POLICY_SCHEMA_VERSION",
                versioning.ORGANIZATION_POLICY_SCHEMA_VERSION,
                "policy_trust",
                schema_file="schemas/policy/organization-policy.schema.json",
            ),
            _product(
                "CAPABILITY_CI_POLICY_SCHEMA_VERSION",
                versioning.CAPABILITY_CI_POLICY_SCHEMA_VERSION,
                "policy_trust",
            ),
            _product(
                "QUALIFICATION_REGISTRY_SCHEMA_VERSION",
                versioning.QUALIFICATION_REGISTRY_SCHEMA_VERSION,
                "policy_trust",
                schema_file="schemas/policy/qualified-gate-registry.schema.json",
            ),
            _product(
                "FAIL_ON_POLICY_VERSION",
                versioning.FAIL_ON_POLICY_VERSION,
                "policy_trust",
            ),
            _product(
                "SCORE_CONTEXT_SCHEMA_VERSION",
                versioning.SCORE_CONTEXT_SCHEMA_VERSION,
                "policy_trust",
                schema_file="schemas/score-context/score-context.schema.json",
            ),
            _product(
                "OPERATION_CONTEXT_SCHEMA_VERSION",
                versioning.OPERATION_CONTEXT_SCHEMA_VERSION,
                "risk_context",
                schema_file="schemas/risk/operation-context.schema.json",
            ),
            _product(
                "CONTEXT_RULE_PACK_VERSION",
                CONTEXT_RULE_PACK_VERSION,
                "risk_context",
            ),
            _report(
                "CONTEXT_RISK_REPORT_VERSION",
                CONTEXT_RISK_REPORT_VERSION,
                "risk_context",
                schema_file="schemas/risk/context-risk-report.schema.json",
            ),
            _product(
                "CONTEXT_RISK_SCORE_MODEL_VERSION",
                versioning.CONTEXT_RISK_SCORE_MODEL_VERSION,
                "risk_context",
            ),
            _report(
                "CONTEXT_RISK_SCORE_REPORT_VERSION",
                versioning.CONTEXT_RISK_SCORE_REPORT_VERSION,
                "risk_context",
                schema_file="schemas/risk/context-risk-score.schema.json",
            ),
            _report(
                "RUNTIME_ATTESTATION_REPORT_VERSION",
                versioning.RUNTIME_ATTESTATION_REPORT_VERSION,
                "runtime_evidence",
                schema_file="schemas/runtime/runtime-attestation.schema.json",
            ),
            _report(
                "EVIDENCE_RECONCILIATION_REPORT_VERSION",
                versioning.EVIDENCE_RECONCILIATION_REPORT_VERSION,
                "runtime_evidence",
                schema_file="schemas/runtime/evidence-reconciliation.schema.json",
            ),
            _product(
                "RUNTIME_TRUST_REGISTRY_VERSION",
                versioning.RUNTIME_TRUST_REGISTRY_VERSION,
                "runtime_evidence",
                schema_file="schemas/runtime/runtime-trust-registry.schema.json",
            ),
            _product(
                "RUNTIME_REPLAY_STORE_VERSION",
                versioning.RUNTIME_REPLAY_STORE_VERSION,
                "runtime_evidence",
                schema_file="schemas/runtime/runtime-replay-store.schema.json",
            ),
            _report(
                "RUNTIME_TRUST_VERIFICATION_REPORT_VERSION",
                versioning.RUNTIME_TRUST_VERIFICATION_REPORT_VERSION,
                "runtime_evidence",
                schema_file=("schemas/runtime/runtime-trust-verification.schema.json"),
            ),
            _product(
                "RELEASE_MANIFEST_VERSION",
                versioning.RELEASE_MANIFEST_VERSION,
                "release_provenance",
            ),
            _product(
                "PROVENANCE_BUNDLE_VERSION",
                versioning.PROVENANCE_BUNDLE_VERSION,
                "release_provenance",
            ),
            _product(
                "SEMANTIC_GATE_DEFINITION_VERSION",
                versioning.SEMANTIC_GATE_DEFINITION_VERSION,
                "semantic_gate",
            ),
            _product(
                "SEMANTIC_GATE_QUALIFICATION_VERSION",
                versioning.SEMANTIC_GATE_QUALIFICATION_VERSION,
                "semantic_gate",
            ),
            _product(
                "SEMANTIC_GATE_HUMAN_CORPUS_VERSION",
                versioning.SEMANTIC_GATE_HUMAN_CORPUS_VERSION,
                "semantic_gate_corpus",
                schema_file=(
                    "schemas/semantic-analysis/semantic-gate-human-corpus.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_GATE_PILOT_VERSION",
                versioning.SEMANTIC_GATE_PILOT_VERSION,
                "semantic_gate_pilot",
                schema_file=(
                    "schemas/semantic-analysis/semantic-gate-pilot-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_GATE_EVALUATION_IMPORT_VERSION",
                versioning.SEMANTIC_GATE_EVALUATION_IMPORT_VERSION,
                "semantic_gate_evaluation",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-gate-evaluation-import.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_GATE_PROMOTION_VERSION",
                versioning.SEMANTIC_GATE_PROMOTION_VERSION,
                "semantic_gate_evaluation",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-gate-report-only-promotion.schema.json"
                ),
            ),
            # Homi recalibration sidecar contracts
            _product(
                "HOMI_BUILD_PROVENANCE_VERSION",
                versioning.HOMI_BUILD_PROVENANCE_VERSION,
                "homi_provenance",
            ),
            _report(
                "HOMI_OPERATIONALITY_OUTPUT_VERSION",
                versioning.HOMI_OPERATIONALITY_OUTPUT_VERSION,
                "homi_reports",
            ),
            _report(
                "HOMI_POSTURE_OUTPUT_VERSION",
                versioning.HOMI_POSTURE_OUTPUT_VERSION,
                "homi_reports",
            ),
            _report(
                "HOMI_CALIBRATION_OUTPUT_VERSION",
                versioning.HOMI_CALIBRATION_OUTPUT_VERSION,
                "homi_reports",
            ),
            _report(
                "HOMI_RISK_STATE_OUTPUT_VERSION",
                versioning.HOMI_RISK_STATE_OUTPUT_VERSION,
                "homi_reports",
                schema_file="schemas/risk/homi-risk-state.schema.json",
            ),
            _report(
                "HOMI_OPERATION_CONTEXT_OUTPUT_VERSION",
                versioning.HOMI_OPERATION_CONTEXT_OUTPUT_VERSION,
                "homi_reports",
                schema_file="schemas/risk/homi-operation-context.schema.json",
            ),
            _report(
                "HOMI_SNAPSHOT_OUTPUT_VERSION",
                versioning.HOMI_SNAPSHOT_OUTPUT_VERSION,
                "homi_reports",
                schema_file="schemas/risk/homi-snapshot.schema.json",
            ),
            # Scoring and enrichment models
            _product(
                "AGENTIC_FACTOR_MODEL_VERSION",
                versioning.AGENTIC_FACTOR_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "THREAT_MITIGATION_MODEL_VERSION",
                versioning.THREAT_MITIGATION_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "TECHNICAL_SCORE_MODEL_VERSION",
                versioning.TECHNICAL_SCORE_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "DRIFT_SCORE_MODEL_VERSION",
                versioning.DRIFT_SCORE_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "GOVERNANCE_SCORE_MODEL_VERSION",
                versioning.GOVERNANCE_SCORE_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "OVERALL_SCORE_MODEL_VERSION",
                versioning.OVERALL_SCORE_MODEL_VERSION,
                "scoring_models",
            ),
            _product(
                "SCORING_REPLAY_MODEL_VERSION",
                versioning.SCORING_REPLAY_MODEL_VERSION,
                "scoring_models",
            ),
            _product("CVSS_ADAPTER_VERSION", CVSS_ADAPTER_VERSION, "scoring_models"),
            # Phase 3 Shadow-only semantic contracts
            _product(
                "SEMANTIC_ANALYZER_VERSION",
                SEMANTIC_ANALYZER_VERSION,
                "semantic_analysis",
            ),
            _product(
                "SEMANTIC_ANALYZE_VERSION",
                SEMANTIC_ANALYZE_VERSION,
                "semantic_cli",
            ),
            _product(
                "SEMANTIC_INPUT_SCHEMA_VERSION",
                SEMANTIC_INPUT_SCHEMA_VERSION,
                "semantic_analysis",
                schema_file=(
                    "schemas/semantic-analysis/semantic-analysis-input.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION",
                SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
                "semantic_analysis",
                schema_file=(
                    "schemas/semantic-analysis/semantic-model-output.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_OUTPUT_SCHEMA_VERSION",
                SEMANTIC_OUTPUT_SCHEMA_VERSION,
                "semantic_analysis_reports",
                schema_file=(
                    "schemas/semantic-analysis/semantic-analysis-result.schema.json"
                ),
            ),
            # P3-02 offline Provider, Prompt, and Shadow invocation contracts
            _fixture(
                "SEMANTIC_MODEL_PROVIDER_ID",
                SEMANTIC_MODEL_PROVIDER_ID,
                "P3-02 approved in-memory offline fixture Provider only",
            ),
            _fixture(
                "SEMANTIC_MODEL_ID",
                SEMANTIC_MODEL_ID,
                "P3-02 deterministic fixture replay Model identity only",
            ),
            _product(
                "SEMANTIC_PROVIDER_CONTRACT_VERSION",
                SEMANTIC_PROVIDER_CONTRACT_VERSION,
                "semantic_provider",
            ),
            _product(
                "SEMANTIC_PROMPT_VERSION",
                SEMANTIC_PROMPT_VERSION,
                "semantic_prompt",
            ),
            _product(
                "SEMANTIC_PROMPT_SCHEMA_VERSION",
                SEMANTIC_PROMPT_SCHEMA_VERSION,
                "semantic_prompt",
                schema_file=(
                    "schemas/semantic-analysis/semantic-prompt-envelope.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION",
                SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
                "semantic_provider",
                schema_file=(
                    "schemas/semantic-analysis/semantic-provider-request.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION",
                SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION,
                "semantic_provider",
                schema_file=(
                    "schemas/semantic-analysis/semantic-provider-response.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION",
                SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
                "semantic_invocation",
            ),
            _report(
                "SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION",
                SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
                "semantic_analysis_reports",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-shadow-invocation-result.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION",
                SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
                "semantic_provider",
            ),
            _product(
                "SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION",
                SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION,
                "semantic_provider",
            ),
            _report(
                "SEMANTIC_EVALUATION_SCHEMA_VERSION",
                SEMANTIC_EVALUATION_SCHEMA_VERSION,
                "semantic_evaluation",
                schema_file=(
                    "schemas/semantic-analysis/semantic-evaluation-report.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_EVALUATION_OUTPUT_VERSION",
                SEMANTIC_EVALUATION_OUTPUT_VERSION,
                "semantic_evaluation",
            ),
            _product(
                "SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION",
                SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION,
                "semantic_provider",
            ),
            _product(
                "SEMANTIC_TRIAL_CONFIG_VERSION",
                SEMANTIC_TRIAL_CONFIG_VERSION,
                "semantic_trial",
                schema_file=(
                    "schemas/semantic-analysis/semantic-trial-config.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_TRIAL_CASE_SET_VERSION",
                SEMANTIC_TRIAL_CASE_SET_VERSION,
                "semantic_trial",
                schema_file=(
                    "schemas/semantic-analysis/semantic-trial-case-set.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_TRIAL_RESPONSE_SET_VERSION",
                SEMANTIC_TRIAL_CASE_SET_VERSION,
                "semantic_trial",
                schema_file=(
                    "schemas/semantic-analysis/semantic-trial-response-set.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_PARITY_REPORT_VERSION",
                "0.1.0",
                "semantic_evaluation",
                schema_file=(
                    "schemas/semantic-analysis/semantic-parity-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_FINDING_INTEGRATION_VERSION",
                SEMANTIC_FINDING_INTEGRATION_VERSION,
                "semantic_integration",
                schema_file=(
                    "schemas/semantic-analysis/semantic-finding-integration-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION",
                SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION,
                "semantic_integration",
                schema_file=(
                    "schemas/semantic-analysis/semantic-rule-candidate-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_CANDIDATE_CALIBRATION_VERSION",
                SEMANTIC_CANDIDATE_CALIBRATION_VERSION,
                "semantic_calibration",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-candidate-calibration-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION",
                SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION,
                "semantic_promotion",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-finding-promotion-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION",
                SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION,
                "semantic_replay",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-rule-implementation-replay-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_SHADOW_PIPELINE_VERSION",
                SEMANTIC_SHADOW_PIPELINE_VERSION,
                "semantic_pipeline",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-shadow-pipeline-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_RULE_PROMOTION_VERSION",
                SEMANTIC_RULE_PROMOTION_VERSION,
                "semantic_rule_promotion",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-rule-promotion-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_QUALIFICATION_VERSION",
                SEMANTIC_QUALIFICATION_VERSION,
                "semantic_quality_gate",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-quality-qualification-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_RULE_PACK_STAGING_VERSION",
                SEMANTIC_RULE_PACK_STAGING_VERSION,
                "semantic_rule_promotion",
            ),
            _report(
                "SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION",
                SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION,
                "semantic_scenario_metrics",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-scenario-metrics-report.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_SCENARIO_METRICS_OUTPUT_VERSION",
                SEMANTIC_SCENARIO_METRICS_OUTPUT_VERSION,
                "semantic_scenario_metrics",
            ),
            _report(
                "SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION",
                SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION,
                "semantic_scenario_replay",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-scenario-replay-suite.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION",
                SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION,
                "semantic_scenario_replay",
            ),
            _report(
                "SEMANTIC_SHADOW_MODE_SCHEMA_VERSION",
                SEMANTIC_SHADOW_MODE_VERSION,
                "semantic_shadow_mode",
                schema_file=(
                    "schemas/semantic-analysis/semantic-shadow-mode-report.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_SHADOW_MODE_OUTPUT_VERSION",
                SEMANTIC_SHADOW_MODE_OUTPUT_VERSION,
                "semantic_shadow_mode",
            ),
            _report(
                "SEMANTIC_FEEDBACK_SET_VERSION",
                SEMANTIC_FEEDBACK_SET_VERSION,
                "semantic_feedback",
                schema_file=(
                    "schemas/semantic-analysis/semantic-feedback-set.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION",
                SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION,
                "semantic_feedback",
                schema_file=(
                    "schemas/semantic-analysis/"
                    "semantic-feedback-loop-report.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION",
                SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION,
                "semantic_promotion",
                schema_file=(
                    "schemas/semantic-analysis/semantic-human-review-submission.schema.json"
                ),
            ),
            _product(
                "SEMANTIC_PROMOTION_SCHEMA_VERSION",
                SEMANTIC_PROMOTION_SCHEMA_VERSION,
                "semantic_promotion",
                schema_file=(
                    "schemas/semantic-analysis/semantic-provider-promotion-report.schema.json"
                ),
            ),
            _report(
                "SEMANTIC_PROMOTION_REPORT_VERSION",
                SEMANTIC_PROMOTION_REPORT_VERSION,
                "semantic_promotion",
            ),
            # Capability Attack Graph contracts
            _product(
                "ATTACK_GRAPH_SCHEMA_VERSION",
                ATTACK_GRAPH_SCHEMA_VERSION,
                "attack_graph",
                schema_file=(
                    "schemas/attack-graph/capability-attack-graph.schema.json"
                ),
            ),
            _product(
                "ATTACK_GRAPH_BUILDER_VERSION",
                ATTACK_GRAPH_BUILDER_VERSION,
                "attack_graph",
            ),
            _product(
                "ATTACK_PATH_PATTERN_LIBRARY_VERSION",
                ATTACK_PATH_PATTERN_LIBRARY_VERSION,
                "attack_graph",
            ),
            _report(
                "ATTACK_PATH_REPORT_VERSION",
                ATTACK_PATH_REPORT_VERSION,
                "attack_graph",
                schema_file=("schemas/attack-graph/attack-path-report.schema.json"),
            ),
            _report(
                "ATTACK_PATH_CALIBRATION_VERSION",
                ATTACK_PATH_CALIBRATION_VERSION,
                "attack_graph_calibration",
                schema_file=(
                    "schemas/attack-graph/attack-path-calibration-report.schema.json"
                ),
            ),
            _report(
                "ATTACK_PATH_SCORE_CONTEXT_VERSION",
                ATTACK_PATH_SCORE_CONTEXT_VERSION,
                "attack_graph_score_context",
                schema_file=(
                    "schemas/score-context/attack-path-score-context.schema.json"
                ),
            ),
            _report(
                "ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION",
                ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION,
                "attack_graph",
                schema_file=(
                    "schemas/attack-graph/"
                    "attack-path-evidence-association-report.schema.json"
                ),
            ),
            # Evidence and vulnerability contracts
            _product(
                "CALIBRATION_CASE_SCHEMA_VERSION",
                versioning.CALIBRATION_CASE_SCHEMA_VERSION,
                "calibration_evidence",
                schema_file="schemas/calibration/calibration-case.schema.json",
            ),
            _product(
                "CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION",
                versioning.CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION,
                "calibration_evidence",
                schema_file="schemas/calibration/confidence-review-set.schema.json",
            ),
            _product(
                "CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION",
                versioning.CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION,
                "calibration_evidence",
                schema_file="schemas/calibration/calibration-adjudication-set.schema.json",
            ),
            _product(
                "CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION",
                versioning.CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION,
                "calibration_evidence",
                schema_file=(
                    "schemas/calibration/calibration-adjudication-resolution-set"
                    ".schema.json"
                ),
            ),
            _product(
                "FULL_PACK_SCHEMA_VERSION",
                FULL_PACK_SCHEMA_VERSION,
                "calibration_evidence",
            ),
            _product("PILOT_SCHEMA_VERSION", PILOT_SCHEMA_VERSION, "pilot_evidence"),
            _product(
                "JOINT_EVIDENCE_SCHEMA_VERSION",
                JOINT_EVIDENCE_SCHEMA_VERSION,
                "pilot_evidence",
                schema_file=(
                    "schemas/calibration/joint-expert-review-evidence.schema.json"
                ),
            ),
            _product(
                "PILOT_PLAN_SCHEMA_VERSION",
                PILOT_PLAN_SCHEMA_VERSION,
                "pilot_evidence",
                schema_file="schemas/pilot/pilot-plan.schema.json",
            ),
            _product(
                "PILOT_HUMAN_LABELS_SCHEMA_VERSION",
                PILOT_HUMAN_LABELS_SCHEMA_VERSION,
                "pilot_evidence",
                schema_file="schemas/pilot/pilot-human-labels.schema.json",
            ),
            _product(
                "EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION",
                EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION,
                "pilot_evidence",
                schema_file=(
                    "schemas/pilot/external-pilot-review-submission.schema.json"
                ),
            ),
            _product(
                "VULNERABILITY_INPUT_VERSION",
                VULNERABILITY_INPUT_VERSION,
                "vulnerability",
                schema_file="schemas/vulnerability-input/vulnerability-input.schema.json",
            ),
            _product(
                "VULNERABILITY_CATALOG_VERSION",
                VULNERABILITY_CATALOG_VERSION,
                "vulnerability",
                schema_file=(
                    "schemas/vulnerability-catalog/vulnerability-catalog.schema.json"
                ),
            ),
        )
    )

    records.extend(
        (
            # Interfaces already recorded in the product version vector
            # (ASSESSMENT_OUTPUT_VERSION, DIFF_OUTPUT_VERSION,
            # CAPABILITY_DIFF_SCHEMA_VERSION, CAPABILITY_ASSESSMENT_OUTPUT_VERSION,
            # CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION) appear exactly once above.
            _report(
                "AGENTIC_ASSESSMENT_OUTPUT_VERSION",
                versioning.AGENTIC_ASSESSMENT_OUTPUT_VERSION,
                "agentic_score_reports",
                schema_file="schemas/agentic-assessment/agentic-assessment.schema.json",
            ),
            _report(
                "CAPABILITY_CI_REPORT_OUTPUT_VERSION",
                versioning.CAPABILITY_CI_REPORT_OUTPUT_VERSION,
                "policy_reports",
            ),
            _report(
                "ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION",
                versioning.ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION,
                "policy_reports",
                schema_file=(
                    "schemas/policy/organization-assessment-report.schema.json"
                ),
            ),
            _report(
                "FAIL_ON_REPORT_OUTPUT_VERSION",
                versioning.FAIL_ON_REPORT_OUTPUT_VERSION,
                "policy_reports",
                schema_file="schemas/assessment/assessment-fail-on-report.schema.json",
            ),
            _report(
                "SARIF_REPORTER_VERSION", versioning.SARIF_REPORTER_VERSION, "sarif"
            ),
            _report(
                "CALIBRATION_REPORT_OUTPUT_VERSION",
                versioning.CALIBRATION_REPORT_OUTPUT_VERSION,
                "calibration_reports",
                schema_file="schemas/calibration/calibration-report.schema.json",
            ),
            _report(
                "CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION",
                versioning.CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION,
                "calibration_reports",
                schema_file=(
                    "schemas/calibration/confidence-calibration-report.schema.json"
                ),
            ),
            _report(
                "CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION",
                versioning.CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION,
                "calibration_reports",
                schema_file=(
                    "schemas/calibration/calibration-adjudication-report.schema.json"
                ),
            ),
            _report(
                "RULE_SCORE_CALIBRATION_OUTPUT_VERSION",
                versioning.RULE_SCORE_CALIBRATION_OUTPUT_VERSION,
                "calibration_reports",
                schema_file=(
                    "schemas/calibration/rule-score-calibration-report.schema.json"
                ),
            ),
            _report(
                "PILOT_REPORT_OUTPUT_VERSION",
                PILOT_REPORT_OUTPUT_VERSION,
                "pilot_reports",
                schema_file="schemas/pilot/pilot-report.schema.json",
            ),
        )
    )

    records.extend(
        (
            _history(
                "DIST_0_1_0_RELEASE",
                "0.1.0",
                "frozen Phase 1 PoC wheel/sdist and schemas",
            ),
            _history(
                "DIST_0_2_0_RELEASE",
                "0.2.0",
                "frozen Phase 2 integration wheel/sdist and schemas",
            ),
            _history(
                "DIST_0_3_0_RELEASE",
                "0.3.0",
                "frozen internal MVP wheel/sdist, CI/Pilot/Calibration evidence",
            ),
            _history(
                "GATE_QUALIFICATION_REPORT_V1",
                "v1",
                "superseded by hg-capchain-001-qualification-report-v2.json; "
                "v1 grants no Gate authority",
            ),
        )
    )

    records.extend(
        (
            _fixture(
                "SCORING_REPLAY_EXPECTED_SUITE",
                None,
                "testdata/scoring-replay/expected.json; re-frozen only with "
                "reviewed semantic or package-version provenance changes",
            ),
            _fixture(
                "REVIEWER_PACK_BLINDED_FIXTURES",
                None,
                "blinded reviewer-pack evidence fixtures under calibration/",
            ),
            _fixture(
                "CALIBRATION_SEED_LABELS",
                None,
                "seeded labels are not reviewed production evidence",
            ),
        )
    )

    notes = "reserved for Phase 3; versioning must not imply authority"
    for name in PHASE3_RESERVED_INTERFACE_NAMES:
        records.append(_reserved(name, notes))

    return tuple(records)


def registry_version_constants() -> tuple[str, ...]:
    """Return every registry interface name exactly once."""

    return tuple(record.name for record in interface_provenance_registry())


_DOMAIN_SCHEMA_FILES = (
    "agent-asset",
    "assessment-metadata",
    "assessment",
    "asset-change",
    "coverage-issue",
    "cvss-base",
    "cvss-hard-gate-assessment",
    "cvss-hard-gate-match",
    "evidence",
    "finding",
    "scan-coverage",
    "vulnerability-reference",
)


def schema_file_ownership() -> dict[str, str]:
    """Return the central ownership map: frozen schema file → source interface.

    Every published schema belongs to exactly one versioned source-of-truth
    interface. The map must stay byte-complete with `schemas/**/*.schema.json`.
    """

    ownership: dict[str, str] = {}
    for name in _DOMAIN_SCHEMA_FILES:
        ownership[f"schemas/domain/{name}.schema.json"] = "DOMAIN_SCHEMA_VERSION"
    ownership.update(
        {
            "schemas/baseline/baseline.schema.json": "BASELINE_SCHEMA_VERSION",
            "schemas/assessment/assessment-report.schema.json": (
                "ASSESSMENT_OUTPUT_VERSION"
            ),
            "schemas/assessment/assessment-fail-on-report.schema.json": (
                "FAIL_ON_REPORT_OUTPUT_VERSION"
            ),
            "schemas/manifest/agent-manifest.schema.json": (
                "AGENT_MANIFEST_SCHEMA_VERSION"
            ),
            "schemas/capability-assessment/capability-assessment.schema.json": (
                "CAPABILITY_ASSESSMENT_OUTPUT_VERSION"
            ),
            "schemas/capability-change-impact/capability-change-impact.schema.json": (
                "CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION"
            ),
            "schemas/capability-diff/capability-diff.schema.json": (
                "CAPABILITY_DIFF_SCHEMA_VERSION"
            ),
            "schemas/policy/organization-policy.schema.json": (
                "ORGANIZATION_POLICY_SCHEMA_VERSION"
            ),
            "schemas/policy/organization-assessment-report.schema.json": (
                "ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION"
            ),
            "schemas/policy/qualified-gate-registry.schema.json": (
                "QUALIFICATION_REGISTRY_SCHEMA_VERSION"
            ),
            "schemas/agentic-assessment/agentic-assessment.schema.json": (
                "AGENTIC_ASSESSMENT_OUTPUT_VERSION"
            ),
            "schemas/score-context/score-context.schema.json": (
                "SCORE_CONTEXT_SCHEMA_VERSION"
            ),
            "schemas/score-context/attack-path-score-context.schema.json": (
                "ATTACK_PATH_SCORE_CONTEXT_VERSION"
            ),
            "schemas/risk/operation-context.schema.json": (
                "OPERATION_CONTEXT_SCHEMA_VERSION"
            ),
            "schemas/risk/context-risk-report.schema.json": (
                "CONTEXT_RISK_REPORT_VERSION"
            ),
            "schemas/risk/context-risk-score.schema.json": (
                "CONTEXT_RISK_SCORE_REPORT_VERSION"
            ),
            "schemas/risk/homi-risk-state.schema.json": (
                "HOMI_RISK_STATE_OUTPUT_VERSION"
            ),
            "schemas/risk/homi-operation-context.schema.json": (
                "HOMI_OPERATION_CONTEXT_OUTPUT_VERSION"
            ),
            "schemas/risk/homi-snapshot.schema.json": (
                "HOMI_SNAPSHOT_OUTPUT_VERSION"
            ),
            "schemas/runtime/runtime-attestation.schema.json": (
                "RUNTIME_ATTESTATION_REPORT_VERSION"
            ),
            "schemas/runtime/evidence-reconciliation.schema.json": (
                "EVIDENCE_RECONCILIATION_REPORT_VERSION"
            ),
            "schemas/runtime/runtime-trust-registry.schema.json": (
                "RUNTIME_TRUST_REGISTRY_VERSION"
            ),
            "schemas/runtime/runtime-trust-verification.schema.json": (
                "RUNTIME_TRUST_VERIFICATION_REPORT_VERSION"
            ),
            "schemas/runtime/runtime-replay-store.schema.json": (
                "RUNTIME_REPLAY_STORE_VERSION"
            ),
            "schemas/semantic-analysis/semantic-analysis-input.schema.json": (
                "SEMANTIC_INPUT_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-model-output.schema.json": (
                "SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-analysis-result.schema.json": (
                "SEMANTIC_OUTPUT_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-prompt-envelope.schema.json": (
                "SEMANTIC_PROMPT_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-provider-request.schema.json": (
                "SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-provider-response.schema.json": (
                "SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-shadow-invocation-result.schema.json": (
                "SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION"
            ),
            "schemas/semantic-analysis/semantic-evaluation-report.schema.json": (
                "SEMANTIC_EVALUATION_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-trial-config.schema.json": (
                "SEMANTIC_TRIAL_CONFIG_VERSION"
            ),
            "schemas/semantic-analysis/semantic-trial-case-set.schema.json": (
                "SEMANTIC_TRIAL_CASE_SET_VERSION"
            ),
            "schemas/semantic-analysis/semantic-trial-response-set.schema.json": (
                "SEMANTIC_TRIAL_RESPONSE_SET_VERSION"
            ),
            "schemas/semantic-analysis/semantic-parity-report.schema.json": (
                "SEMANTIC_PARITY_REPORT_VERSION"
            ),
            "schemas/semantic-analysis/semantic-rule-promotion-report.schema.json": (
                "SEMANTIC_RULE_PROMOTION_VERSION"
            ),
            "schemas/semantic-analysis/semantic-scenario-metrics-report.schema.json": (
                "SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-scenario-replay-suite.schema.json": (
                "SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-shadow-mode-report.schema.json": (
                "SEMANTIC_SHADOW_MODE_SCHEMA_VERSION"
            ),
            "schemas/semantic-analysis/semantic-feedback-set.schema.json": (
                "SEMANTIC_FEEDBACK_SET_VERSION"
            ),
            "schemas/semantic-analysis/semantic-feedback-loop-report.schema.json": (
                "SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-candidate.schema.json": (
                "SEMANTIC_GATE_DEFINITION_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-gate-qualification-report.schema.json": (
                "SEMANTIC_GATE_QUALIFICATION_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-human-corpus.schema.json": (
                "SEMANTIC_GATE_HUMAN_CORPUS_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-review-submission.schema.json": (
                "SEMANTIC_GATE_HUMAN_CORPUS_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-pilot-config.schema.json": (
                "SEMANTIC_GATE_PILOT_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-pilot-report.schema.json": (
                "SEMANTIC_GATE_PILOT_VERSION"
            ),
            "schemas/semantic-analysis/semantic-gate-evaluation-import.schema.json": (
                "SEMANTIC_GATE_EVALUATION_IMPORT_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-gate-report-only-promotion.schema.json": (
                "SEMANTIC_GATE_PROMOTION_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-quality-qualification-report.schema.json": (
                "SEMANTIC_QUALIFICATION_VERSION"
            ),
            "schemas/semantic-analysis/semantic-shadow-pipeline-report.schema.json": (
                "SEMANTIC_SHADOW_PIPELINE_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-candidate-calibration-case.schema.json": (
                "SEMANTIC_CANDIDATE_CALIBRATION_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-candidate-calibration-report.schema.json": (
                "SEMANTIC_CANDIDATE_CALIBRATION_VERSION"
            ),
            "schemas/semantic-analysis/semantic-finding-promotion-report.schema.json": (
                "SEMANTIC_FINDING_PROMOTION_REVIEW_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-rule-implementation-replay-report.schema.json": (
                "SEMANTIC_RULE_IMPLEMENTATION_REPLAY_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-finding-integration-report.schema.json": (
                "SEMANTIC_FINDING_INTEGRATION_VERSION"
            ),
            "schemas/semantic-analysis/semantic-rule-candidate-report.schema.json": (
                "SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION"
            ),
            "schemas/semantic-analysis/semantic-human-review-submission.schema.json": (
                "SEMANTIC_HUMAN_REVIEW_SCHEMA_VERSION"
            ),
            "schemas/attack-graph/capability-attack-graph.schema.json": (
                "ATTACK_GRAPH_SCHEMA_VERSION"
            ),
            "schemas/attack-graph/attack-path-report.schema.json": (
                "ATTACK_PATH_REPORT_VERSION"
            ),
            "schemas/attack-graph/attack-path-calibration-report.schema.json": (
                "ATTACK_PATH_CALIBRATION_VERSION"
            ),
            "schemas/attack-graph/"
            "attack-path-evidence-association-report.schema.json": (
                "ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION"
            ),
            "schemas/semantic-analysis/"
            "semantic-provider-promotion-report.schema.json": (
                "SEMANTIC_PROMOTION_SCHEMA_VERSION"
            ),
            "schemas/calibration/calibration-case.schema.json": (
                "CALIBRATION_CASE_SCHEMA_VERSION"
            ),
            "schemas/calibration/calibration-corpus.schema.json": (
                "CALIBRATION_CASE_SCHEMA_VERSION"
            ),
            "schemas/calibration/calibration-report.schema.json": (
                "CALIBRATION_REPORT_OUTPUT_VERSION"
            ),
            "schemas/calibration/confidence-review-set.schema.json": (
                "CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION"
            ),
            "schemas/calibration/confidence-calibration-report.schema.json": (
                "CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION"
            ),
            "schemas/calibration/calibration-adjudication-set.schema.json": (
                "CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION"
            ),
            "schemas/calibration/calibration-adjudication-resolution-set.schema.json": (
                "CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION"
            ),
            "schemas/calibration/calibration-adjudication-report.schema.json": (
                "CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION"
            ),
            "schemas/calibration/rule-score-calibration-report.schema.json": (
                "RULE_SCORE_CALIBRATION_OUTPUT_VERSION"
            ),
            "schemas/calibration/joint-expert-review-evidence.schema.json": (
                "JOINT_EVIDENCE_SCHEMA_VERSION"
            ),
            "schemas/calibration/capability-shadow-gate-demo.schema.json": (
                "CAPABILITY_SHADOW_GATE_VERSION"
            ),
            "schemas/pilot/pilot-plan.schema.json": "PILOT_PLAN_SCHEMA_VERSION",
            "schemas/pilot/pilot-human-labels.schema.json": (
                "PILOT_HUMAN_LABELS_SCHEMA_VERSION"
            ),
            "schemas/pilot/external-pilot-review-submission.schema.json": (
                "EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION"
            ),
            "schemas/pilot/pilot-report.schema.json": ("PILOT_REPORT_OUTPUT_VERSION"),
            "schemas/vulnerability-input/vulnerability-input.schema.json": (
                "VULNERABILITY_INPUT_VERSION"
            ),
            "schemas/vulnerability-catalog/vulnerability-catalog.schema.json": (
                "VULNERABILITY_CATALOG_VERSION"
            ),
        }
    )
    return ownership


def render_interface_provenance_markdown() -> str:
    """Render the registry as a deterministic Markdown table."""

    lines = [
        "# AgentSec Interface Provenance Registry",
        "",
        f"Package version: {versioning.PACKAGE_VERSION}",
        "",
        "| Interface | Version | Classification | Group |",
        "|---|---|---|---|",
    ]
    for record in interface_provenance_registry():
        version = record.version if record.version is not None else "reserved"
        lines.append(
            f"| {record.name} | {version} | "
            f"{record.classification.value} | {record.group} |"
        )
    lines.extend(
        (
            "",
            "No interface version grants authorization authority. Deterministic",
            "Rules and reviewed Policy own CI decisions; Phase 3 reservations",
            "carry no capability or authority until separately approved.",
        )
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "PHASE3_RESERVED_INTERFACE_NAMES",
    "InterfaceClassification",
    "InterfaceProvenance",
    "interface_provenance_registry",
    "registry_version_constants",
    "render_interface_provenance_markdown",
    "schema_file_ownership",
]

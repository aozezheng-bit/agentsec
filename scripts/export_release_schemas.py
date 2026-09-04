"""Export the public JSON Schemas for the current AgentSec release."""

from __future__ import annotations

from pathlib import Path

from agentsec.attack_graph import (
    export_attack_graph_json_schema,
    export_attack_path_calibration_json_schema,
    export_attack_path_evidence_association_json_schema,
    export_attack_path_report_json_schema,
)
from agentsec.baselines import export_baseline_json_schema
from agentsec.calibration import (
    export_adjudication_resolution_set_json_schema,
    export_adjudication_review_set_json_schema,
    export_calibration_adjudication_report_json_schema,
    export_calibration_case_json_schema,
    export_calibration_corpus_json_schema,
    export_calibration_report_json_schema,
    export_confidence_calibration_report_json_schema,
    export_confidence_review_set_json_schema,
)
from agentsec.calibration.pilot_tuning import (
    export_rule_score_calibration_json_schema,
)
from agentsec.change_impact import export_capability_change_impact_json_schema
from agentsec.domain import export_json_schemas
from agentsec.external_pilot import export_external_review_submission_schema
from agentsec.manifests import (
    export_agent_manifest_json_schema,
    export_capability_diff_json_schema,
)
from agentsec.pilot import export_pilot_json_schemas
from agentsec.policy.qualification_registry import (
    export_qualified_gate_registry_json_schema,
)
from agentsec.reporting import (
    export_agentic_assessment_json_schema,
    export_assessment_fail_on_json_schema,
    export_assessment_json_schema,
    export_capability_assessment_json_schema,
    export_organization_assessment_json_schema,
    export_organization_policy_json_schema,
    export_score_context_json_schema,
)
from agentsec.risk import (
    export_attack_path_score_context_json_schema,
    export_context_risk_json_schema,
    export_context_risk_score_json_schema,
    export_operation_context_json_schema,
    export_runtime_attestation_json_schema,
    export_runtime_trust_json_schemas,
)
from agentsec.semantic import (
    export_scenario_metrics_json_schema,
    export_scenario_replay_json_schema,
    export_semantic_evaluation_json_schema,
    export_semantic_feedback_json_schemas,
    export_semantic_gate_corpus_json_schemas,
    export_semantic_gate_evaluation_json_schemas,
    export_semantic_gate_json_schemas,
    export_semantic_gate_pilot_json_schemas,
    export_semantic_integration_json_schemas,
    export_semantic_invocation_json_schemas,
    export_semantic_json_schemas,
    export_semantic_p3_07_json_schemas,
    export_semantic_p3_08_json_schema,
    export_semantic_parity_json_schema,
    export_semantic_promotion_json_schemas,
    export_semantic_qualification_json_schema,
    export_semantic_rule_promotion_json_schema,
    export_semantic_shadow_mode_json_schema,
    export_semantic_trial_json_schemas,
)
from agentsec.vulnerabilities import (
    export_vulnerability_catalog_json_schema,
    export_vulnerability_input_json_schema,
)


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    schema_root = repository_root / "schemas"
    export_json_schemas(schema_root / "domain")
    export_baseline_json_schema(schema_root / "baseline")
    export_assessment_json_schema(schema_root / "assessment")
    export_assessment_fail_on_json_schema(schema_root / "assessment")
    export_organization_policy_json_schema(schema_root / "policy")
    export_organization_assessment_json_schema(schema_root / "policy")
    export_qualified_gate_registry_json_schema(schema_root / "policy")
    export_agent_manifest_json_schema(schema_root / "manifest")
    export_agentic_assessment_json_schema(schema_root / "agentic-assessment")
    export_score_context_json_schema(schema_root / "score-context")
    export_attack_path_score_context_json_schema(
        schema_root / "score-context" / "attack-path-score-context.schema.json"
    )
    export_operation_context_json_schema(schema_root / "risk")
    export_context_risk_json_schema(schema_root / "risk")
    export_context_risk_score_json_schema(schema_root / "risk")
    from agentsec.frameworks.homi_operation_context import (
        export_homi_operation_context_json_schema,
    )
    from agentsec.frameworks.homi_risk_state import (
        export_homi_risk_state_json_schema,
    )
    from agentsec.frameworks.homi_snapshot import (
        export_homi_snapshot_json_schema,
    )

    export_homi_operation_context_json_schema(schema_root / "risk")
    export_homi_risk_state_json_schema(schema_root / "risk")
    export_homi_snapshot_json_schema(schema_root / "risk")
    export_runtime_attestation_json_schema(schema_root / "runtime")
    export_runtime_trust_json_schemas(schema_root / "runtime")
    export_semantic_json_schemas(schema_root / "semantic-analysis")
    export_semantic_invocation_json_schemas(schema_root / "semantic-analysis")
    export_semantic_evaluation_json_schema(
        schema_root / "semantic-analysis" / "semantic-evaluation-report.schema.json"
    )
    export_semantic_integration_json_schemas(schema_root / "semantic-analysis")
    export_semantic_trial_json_schemas(schema_root / "semantic-analysis")
    export_semantic_parity_json_schema(
        schema_root / "semantic-analysis" / "semantic-parity-report.schema.json"
    )
    export_semantic_promotion_json_schemas(schema_root / "semantic-analysis")
    export_semantic_p3_07_json_schemas(schema_root / "semantic-analysis")
    export_semantic_rule_promotion_json_schema(
        schema_root / "semantic-analysis" / "semantic-rule-promotion-report.schema.json"
    )
    export_semantic_qualification_json_schema(
        schema_root
        / "semantic-analysis"
        / "semantic-quality-qualification-report.schema.json"
    )
    export_semantic_p3_08_json_schema(
        schema_root
        / "semantic-analysis"
        / "semantic-shadow-pipeline-report.schema.json"
    )
    export_scenario_metrics_json_schema(
        schema_root
        / "semantic-analysis"
        / "semantic-scenario-metrics-report.schema.json"
    )
    export_scenario_replay_json_schema(
        schema_root / "semantic-analysis" / "semantic-scenario-replay-suite.schema.json"
    )
    export_semantic_shadow_mode_json_schema(
        schema_root / "semantic-analysis" / "semantic-shadow-mode-report.schema.json"
    )
    export_semantic_feedback_json_schemas(schema_root / "semantic-analysis")
    export_semantic_gate_json_schemas(schema_root / "semantic-analysis")
    export_semantic_gate_corpus_json_schemas(schema_root / "semantic-analysis")
    export_semantic_gate_pilot_json_schemas(schema_root / "semantic-analysis")
    export_semantic_gate_evaluation_json_schemas(schema_root / "semantic-analysis")
    export_attack_graph_json_schema(
        schema_root / "attack-graph" / "capability-attack-graph.schema.json"
    )
    export_attack_path_report_json_schema(
        schema_root / "attack-graph" / "attack-path-report.schema.json"
    )
    export_attack_path_evidence_association_json_schema(
        schema_root
        / "attack-graph"
        / "attack-path-evidence-association-report.schema.json"
    )
    export_attack_path_calibration_json_schema(
        schema_root / "attack-graph" / "attack-path-calibration-report.schema.json"
    )
    export_capability_diff_json_schema(schema_root / "capability-diff")
    export_capability_assessment_json_schema(schema_root / "capability-assessment")
    export_capability_change_impact_json_schema(
        schema_root / "capability-change-impact"
    )
    export_vulnerability_input_json_schema(schema_root / "vulnerability-input")
    export_vulnerability_catalog_json_schema(schema_root / "vulnerability-catalog")
    export_calibration_case_json_schema(schema_root / "calibration")
    export_calibration_corpus_json_schema(schema_root / "calibration")
    export_calibration_report_json_schema(schema_root / "calibration")
    export_adjudication_review_set_json_schema(schema_root / "calibration")
    export_adjudication_resolution_set_json_schema(schema_root / "calibration")
    export_calibration_adjudication_report_json_schema(schema_root / "calibration")
    export_confidence_review_set_json_schema(schema_root / "calibration")
    export_confidence_calibration_report_json_schema(schema_root / "calibration")
    export_pilot_json_schemas(schema_root / "pilot")
    (schema_root / "pilot" / "external-pilot-review-submission.schema.json").write_text(
        export_external_review_submission_schema(), encoding="utf-8"
    )
    export_rule_score_calibration_json_schema(schema_root / "calibration")


if __name__ == "__main__":
    main()

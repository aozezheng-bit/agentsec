"""Canonical JSON codecs and frozen Schema export for P3-01 contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentsec.semantic.evaluation import SemanticEvaluationReport, SemanticParityReport
from agentsec.semantic.integration import (
    SemanticFindingIntegrationReport,
    SemanticRuleCandidateReport,
)
from agentsec.semantic.invocation import SemanticShadowInvocationResult
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticModelOutput,
)
from agentsec.semantic.p3_07 import (
    RuleImplementationReplayReport,
    SemanticCandidateCalibrationCase,
    SemanticCandidateCalibrationReport,
    SemanticFindingPromotionReport,
)
from agentsec.semantic.p3_08 import SemanticShadowPipelineReport
from agentsec.semantic.promotion import (
    ProviderPromotionReport,
    SemanticHumanReviewSubmission,
)
from agentsec.semantic.prompt import SemanticPromptEnvelope
from agentsec.semantic.provider import (
    SemanticProviderRequest,
    SemanticProviderResponse,
)
from agentsec.semantic.quality_gate import QualityGateReport
from agentsec.semantic.rule_promotion import SemanticRulePromotionReport
from agentsec.semantic.scenario_metrics import ScenarioMetricsReport
from agentsec.semantic.trial import (
    SemanticTrialCaseSet,
    SemanticTrialConfig,
    SemanticTrialResponseSet,
)


def encode_semantic_analysis_input_json(value: SemanticAnalysisInput) -> str:
    if not isinstance(value, SemanticAnalysisInput):
        raise TypeError("semantic input encoder requires SemanticAnalysisInput")
    return _encode(value)


def encode_semantic_model_output_json(value: SemanticModelOutput) -> str:
    if not isinstance(value, SemanticModelOutput):
        raise TypeError("model output encoder requires SemanticModelOutput")
    return _encode(value)


def encode_semantic_analysis_result_json(value: SemanticAnalysisResult) -> str:
    if not isinstance(value, SemanticAnalysisResult):
        raise TypeError("semantic result encoder requires SemanticAnalysisResult")
    return _encode(value)


def encode_semantic_prompt_json(value: SemanticPromptEnvelope) -> str:
    if not isinstance(value, SemanticPromptEnvelope):
        raise TypeError("semantic prompt encoder requires SemanticPromptEnvelope")
    return _encode(value)


def encode_semantic_provider_request_json(value: SemanticProviderRequest) -> str:
    if not isinstance(value, SemanticProviderRequest):
        raise TypeError(
            "semantic Provider request encoder requires SemanticProviderRequest"
        )
    return _encode(value)


def encode_semantic_provider_response_json(value: SemanticProviderResponse) -> str:
    if not isinstance(value, SemanticProviderResponse):
        raise TypeError(
            "semantic Provider response encoder requires SemanticProviderResponse"
        )
    return _encode(value)


def encode_semantic_shadow_invocation_json(
    value: SemanticShadowInvocationResult,
) -> str:
    if not isinstance(value, SemanticShadowInvocationResult):
        raise TypeError(
            "semantic Shadow invocation encoder requires SemanticShadowInvocationResult"
        )
    return _encode(value)


def encode_semantic_evaluation_json(value: SemanticEvaluationReport) -> str:
    if not isinstance(value, SemanticEvaluationReport):
        raise TypeError("semantic evaluation encoder requires SemanticEvaluationReport")
    return _encode(value)


def export_semantic_json_schemas(output_directory: Path) -> tuple[Path, Path, Path]:
    """Export Input, constrained model-output, and final result Schemas."""

    if not isinstance(output_directory, Path):
        raise TypeError("semantic Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs = (
        (
            output_directory / "semantic-analysis-input.schema.json",
            SemanticAnalysisInput,
        ),
        (
            output_directory / "semantic-model-output.schema.json",
            SemanticModelOutput,
        ),
        (
            output_directory / "semantic-analysis-result.schema.json",
            SemanticAnalysisResult,
        ),
    )
    for path, model in outputs:
        schema: dict[str, Any] = model.model_json_schema(mode="serialization")
        path.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return tuple(path for path, _model in outputs)  # type: ignore[return-value]


def export_semantic_evaluation_json_schema(output_path: Path) -> Path:
    """Export the frozen semantic evaluation report Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("semantic evaluation Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema: dict[str, Any] = SemanticEvaluationReport.model_json_schema(
        mode="serialization"
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def encode_semantic_parity_json(value: SemanticParityReport) -> str:
    if not isinstance(value, SemanticParityReport):
        raise TypeError("semantic parity encoder requires SemanticParityReport")
    return _encode(value)


def export_semantic_parity_json_schema(output_path: Path) -> Path:
    """Export the frozen Offline/Live parity report Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("semantic parity Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema: dict[str, Any] = SemanticParityReport.model_json_schema(
        mode="serialization"
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def encode_semantic_finding_integration_json(
    value: SemanticFindingIntegrationReport,
) -> str:
    """Encode a strict, report-only Finding integration report."""

    if not isinstance(value, SemanticFindingIntegrationReport):
        raise TypeError(
            "semantic Finding integration encoder requires "
            "SemanticFindingIntegrationReport"
        )
    return _encode(value)


def encode_semantic_rule_candidate_json(value: SemanticRuleCandidateReport) -> str:
    """Encode a strict, report-only Rule Candidate report."""

    if not isinstance(value, SemanticRuleCandidateReport):
        raise TypeError(
            "semantic Rule Candidate encoder requires SemanticRuleCandidateReport"
        )
    return _encode(value)


def encode_semantic_rule_promotion_json(
    value: SemanticRulePromotionReport,
) -> str:
    """Encode a strict, report-only Rule promotion report."""

    if not isinstance(value, SemanticRulePromotionReport):
        raise TypeError(
            "semantic Rule promotion encoder requires SemanticRulePromotionReport"
        )
    return _encode(value)


def export_semantic_rule_promotion_json_schema(output_path: Path) -> Path:
    """Export the P3-10 controlled Rule promotion Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("semantic Rule promotion Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            SemanticRulePromotionReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def encode_semantic_shadow_pipeline_json(
    value: SemanticShadowPipelineReport,
) -> str:
    """Encode a strict, report-only end-to-end Shadow pipeline report."""

    if not isinstance(value, SemanticShadowPipelineReport):
        raise TypeError(
            "semantic pipeline encoder requires SemanticShadowPipelineReport"
        )
    return _encode(value)


def export_semantic_p3_08_json_schema(output_path: Path) -> Path:
    """Export the P3-08 end-to-end Shadow pipeline Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("semantic P3-08 Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            SemanticShadowPipelineReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def encode_semantic_candidate_calibration_json(
    value: SemanticCandidateCalibrationReport,
) -> str:
    """Encode a strict, report-only semantic calibration report."""

    if not isinstance(value, SemanticCandidateCalibrationReport):
        raise TypeError(
            "semantic calibration encoder requires SemanticCandidateCalibrationReport"
        )
    return _encode(value)


def encode_semantic_finding_promotion_json(
    value: SemanticFindingPromotionReport,
) -> str:
    """Encode a strict, report-only Finding promotion review report."""

    if not isinstance(value, SemanticFindingPromotionReport):
        raise TypeError(
            "semantic promotion encoder requires SemanticFindingPromotionReport"
        )
    return _encode(value)


def encode_semantic_rule_replay_json(
    value: RuleImplementationReplayReport,
) -> str:
    """Encode a strict, report-only deterministic Rule replay report."""

    if not isinstance(value, RuleImplementationReplayReport):
        raise TypeError(
            "semantic Rule replay encoder requires RuleImplementationReplayReport"
        )
    return _encode(value)


def export_semantic_p3_07_json_schemas(output_directory: Path) -> tuple[Path, ...]:
    """Export the P3-07 calibration, promotion, and replay Schemas."""

    if not isinstance(output_directory, Path):
        raise TypeError("semantic P3-07 Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: tuple[tuple[Path, type[BaseModel]], ...] = (
        (
            output_directory / "semantic-candidate-calibration-case.schema.json",
            SemanticCandidateCalibrationCase,
        ),
        (
            output_directory / "semantic-candidate-calibration-report.schema.json",
            SemanticCandidateCalibrationReport,
        ),
        (
            output_directory / "semantic-finding-promotion-report.schema.json",
            SemanticFindingPromotionReport,
        ),
        (
            output_directory / "semantic-rule-implementation-replay-report.schema.json",
            RuleImplementationReplayReport,
        ),
    )
    for path, model in outputs:
        path.write_text(
            json.dumps(
                model.model_json_schema(mode="serialization"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return tuple(path for path, _model in outputs)


def export_semantic_integration_json_schemas(
    output_directory: Path,
) -> tuple[Path, Path]:
    """Export Semantic Finding integration and Rule candidate Schemas."""
    if not isinstance(output_directory, Path):
        raise TypeError("semantic integration Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: tuple[tuple[Path, type[BaseModel]], ...] = (
        (
            output_directory / "semantic-finding-integration-report.schema.json",
            SemanticFindingIntegrationReport,
        ),
        (
            output_directory / "semantic-rule-candidate-report.schema.json",
            SemanticRuleCandidateReport,
        ),
    )
    for path, model in outputs:
        schema = model.model_json_schema(mode="serialization")
        path.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return outputs[0][0], outputs[1][0]


def export_semantic_promotion_json_schemas(output_directory: Path) -> tuple[Path, Path]:
    """Export Human Review and Provider Promotion Schemas."""

    if not isinstance(output_directory, Path):
        raise TypeError("semantic promotion Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: tuple[tuple[Path, type[BaseModel]], ...] = (
        (
            output_directory / "semantic-human-review-submission.schema.json",
            SemanticHumanReviewSubmission,
        ),
        (
            output_directory / "semantic-provider-promotion-report.schema.json",
            ProviderPromotionReport,
        ),
    )
    for path, model in outputs:
        schema = model.model_json_schema(mode="serialization")
        path.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return outputs[0][0], outputs[1][0]


def export_semantic_trial_json_schemas(
    output_directory: Path,
) -> tuple[Path, Path, Path]:
    """Export protected trial config, case-set, and response-set Schemas."""

    if not isinstance(output_directory, Path):
        raise TypeError("semantic trial Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: tuple[tuple[Path, type[BaseModel]], ...] = (
        (
            output_directory / "semantic-trial-config.schema.json",
            SemanticTrialConfig,
        ),
        (
            output_directory / "semantic-trial-case-set.schema.json",
            SemanticTrialCaseSet,
        ),
        (
            output_directory / "semantic-trial-response-set.schema.json",
            SemanticTrialResponseSet,
        ),
    )
    for path, model in outputs:
        schema: dict[str, Any] = model.model_json_schema(mode="serialization")
        path.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return tuple(path for path, _model in outputs)  # type: ignore[return-value]


def export_semantic_invocation_json_schemas(
    output_directory: Path,
) -> tuple[Path, Path, Path, Path]:
    """Export Prompt, Provider request/response, and Shadow result Schemas."""

    if not isinstance(output_directory, Path):
        raise TypeError("semantic invocation Schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    prompt_path = output_directory / "semantic-prompt-envelope.schema.json"
    request_path = output_directory / "semantic-provider-request.schema.json"
    response_path = output_directory / "semantic-provider-response.schema.json"
    result_path = output_directory / "semantic-shadow-invocation-result.schema.json"
    outputs: tuple[tuple[Path, type[BaseModel]], ...] = (
        (prompt_path, SemanticPromptEnvelope),
        (request_path, SemanticProviderRequest),
        (response_path, SemanticProviderResponse),
        (result_path, SemanticShadowInvocationResult),
    )
    for path, model in outputs:
        schema: dict[str, Any] = model.model_json_schema(mode="serialization")
        path.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return prompt_path, request_path, response_path, result_path


def encode_semantic_qualification_json_str(value: QualityGateReport) -> str:
    """Encode a strict, report-only semantic quality qualification report."""

    if not isinstance(value, QualityGateReport):
        raise TypeError("semantic qualification encoder requires QualityGateReport")
    return _encode(value)


def export_semantic_qualification_json_schema(output_path: Path) -> Path:
    """Export the P3-11B semantic quality qualification Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("semantic qualification Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            QualityGateReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def export_scenario_metrics_json_schema(output_path: Path) -> Path:
    """Export the frozen P3-14 scenario detection metrics Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("scenario metrics Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            ScenarioMetricsReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def _encode(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "encode_semantic_analysis_input_json",
    "encode_semantic_analysis_result_json",
    "encode_semantic_evaluation_json",
    "encode_semantic_qualification_json_str",
    "export_semantic_qualification_json_schema",
    "encode_semantic_candidate_calibration_json",
    "encode_semantic_finding_integration_json",
    "encode_semantic_finding_promotion_json",
    "encode_semantic_rule_candidate_json",
    "encode_semantic_rule_replay_json",
    "encode_semantic_rule_promotion_json",
    "encode_semantic_shadow_pipeline_json",
    "encode_semantic_model_output_json",
    "encode_semantic_parity_json",
    "encode_semantic_prompt_json",
    "encode_semantic_provider_request_json",
    "encode_semantic_provider_response_json",
    "encode_semantic_shadow_invocation_json",
    "export_semantic_evaluation_json_schema",
    "export_semantic_integration_json_schemas",
    "export_semantic_p3_07_json_schemas",
    "export_semantic_p3_08_json_schema",
    "export_semantic_rule_promotion_json_schema",
    "export_semantic_invocation_json_schemas",
    "export_semantic_trial_json_schemas",
    "export_semantic_json_schemas",
    "export_semantic_parity_json_schema",
    "export_semantic_promotion_json_schemas",
    "export_scenario_metrics_json_schema",
]

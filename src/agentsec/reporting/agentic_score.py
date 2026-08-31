"""Versioned Text and JSON reporting for the Integrated Agentic Score."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentsec.application.agentic_score import AgenticScoreResult
from agentsec.risk.agentic_factors import encode_agentic_factor_vector_json
from agentsec.risk.drift_score import encode_drift_score_json
from agentsec.risk.governance_score import encode_governance_score_json
from agentsec.risk.overall_score import encode_overall_score_json
from agentsec.risk.technical_score import encode_technical_score_json
from agentsec.risk.threat_mitigation import encode_threat_mitigation_vector_json
from agentsec.versioning import AGENTIC_ASSESSMENT_OUTPUT_VERSION

AGENTIC_ASSESSMENT_FORMAT: Literal["agentsec-agentic-assessment"] = (
    "agentsec-agentic-assessment"
)
AGENTIC_ASSESSMENT_FORMAT_VERSION = cast(
    Literal["0.1.0"], AGENTIC_ASSESSMENT_OUTPUT_VERSION
)
_SHA256 = r"^[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AgenticContextProvenance(_Strict):
    supplied: bool
    sha256: str | None = Field(default=None, pattern=_SHA256)


class AgenticScorePolicy(_Strict):
    report_only: Literal[True] = True
    ci_blocking_enabled: Literal[False] = False
    score_ci_authority: Literal[False] = False


class AgenticAssessmentJsonReport(_Strict):
    format: Literal["agentsec-agentic-assessment"]
    format_version: Literal["0.1.0"]
    agent_id: str = Field(min_length=1, max_length=256)
    before_manifest_sha256: str = Field(pattern=_SHA256)
    after_manifest_sha256: str = Field(pattern=_SHA256)
    context: AgenticContextProvenance
    coverage_complete: bool
    relevant_unknown_count: int = Field(ge=0)
    factor_vector: dict[str, Any]
    threat_mitigation: dict[str, Any]
    capability_diff: dict[str, Any]
    technical: dict[str, Any]
    drift: dict[str, Any]
    governance: dict[str, Any]
    overall: dict[str, Any]
    cvss: dict[str, Any] | None
    gate_matches: list[dict[str, Any]]
    policy: AgenticScorePolicy
    boundary: dict[str, bool]
    versions: dict[str, str]


class AgenticAssessmentValidationError(RuntimeError):
    pass


def build_agentic_assessment_payload(
    result: AgenticScoreResult,
) -> AgenticAssessmentJsonReport:
    if not isinstance(result, AgenticScoreResult):
        raise TypeError("result must be AgenticScoreResult")
    manifest = result.analysis.manifest
    return AgenticAssessmentJsonReport(
        format=AGENTIC_ASSESSMENT_FORMAT,
        format_version=AGENTIC_ASSESSMENT_FORMAT_VERSION,
        agent_id=manifest.identity.agent_id,
        before_manifest_sha256=result.before_manifest_sha256,
        after_manifest_sha256=result.after_manifest_sha256,
        context=AgenticContextProvenance(
            supplied=result.context_sha256 is not None,
            sha256=result.context_sha256,
        ),
        coverage_complete=manifest.coverage.complete,
        relevant_unknown_count=len(manifest.unknowns),
        factor_vector=json.loads(encode_agentic_factor_vector_json(result.factors)),
        threat_mitigation=json.loads(
            encode_threat_mitigation_vector_json(result.threats)
        ),
        capability_diff=result.capability_diff.model_dump(mode="json"),
        technical=json.loads(encode_technical_score_json(result.technical)),
        drift=json.loads(encode_drift_score_json(result.drift)),
        governance=json.loads(encode_governance_score_json(result.governance)),
        overall=json.loads(encode_overall_score_json(result.overall)),
        cvss=result.cvss.to_dict() if result.cvss is not None else None,
        gate_matches=[match.to_dict() for match in result.gate_matches],
        policy=AgenticScorePolicy(),
        boundary={
            "llm_authority": False,
            "runtime_verified": False,
            "score_ci_authority": False,
            "execution_of_scanned_content": False,
        },
        versions={
            key: str(value) for key, value in asdict(result.analysis.versions).items()
        },
    )


class AgenticAssessmentJsonRenderer:
    def render(self, result: AgenticScoreResult) -> str:
        report = build_agentic_assessment_payload(result)
        return (
            json.dumps(
                report.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


def decode_agentic_assessment_json(text: str) -> AgenticAssessmentJsonReport:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise AgenticAssessmentValidationError(
            "Agentic assessment report must contain valid JSON"
        ) from error
    if not isinstance(payload, dict):
        raise AgenticAssessmentValidationError(
            "Agentic assessment report root must be an object"
        )
    try:
        return AgenticAssessmentJsonReport.model_validate(payload)
    except ValidationError as error:
        raise AgenticAssessmentValidationError(
            "Agentic assessment report failed strict validation"
        ) from error


class AgenticAssessmentTextRenderer:
    """Bilingual one-page Integrated Agentic Score summary."""

    def __init__(self, *, language: str = "en") -> None:
        if language not in {"en", "zh"}:
            raise ValueError("language must be en or zh")
        self._language = language

    def render(self, result: AgenticScoreResult) -> str:
        if not isinstance(result, AgenticScoreResult):
            raise TypeError("result must be AgenticScoreResult")
        manifest = result.analysis.manifest
        overall = result.overall
        gate = overall.hard_gate
        if self._language == "zh":
            lines = [
                "AgentSec Agentic 评分",
                f"Agent：{manifest.identity.agent_id}",
                f"技术评分：{overall.technical_score:.1f}",
                f"漂移评分：{overall.drift_score:.1f}",
                f"治理评分：{overall.governance_score:.1f}",
                f"基础综合评分：{overall.base_overall_score:.1f}",
                f"综合评分：{overall.overall_score:.1f}",
                f"严重度：{overall.severity.value.upper()}",
                (
                    "硬性门禁：命中 "
                    + (gate.floor.value.upper() if gate.floor else "-")
                    if gate.triggered
                    else "硬性门禁：未命中"
                ),
                f"覆盖率完整：{'是' if manifest.coverage.complete else '否'}",
                f"相关 Unknown：{len(manifest.unknowns)}",
                "策略：仅报告（report-only），评分不阻断、不拥有 CI 决策权",
                "边界：不执行被扫描内容；未验证运行时能力；不使用 LLM 授权",
            ]
        else:
            lines = [
                "AgentSec Agentic Score",
                f"Agent: {manifest.identity.agent_id}",
                f"Technical score: {overall.technical_score:.1f}",
                f"Drift score: {overall.drift_score:.1f}",
                f"Governance score: {overall.governance_score:.1f}",
                f"Base overall score: {overall.base_overall_score:.1f}",
                f"Overall score: {overall.overall_score:.1f}",
                f"Severity: {overall.severity.value.upper()}",
                (
                    "Hard gate: triggered "
                    + (gate.floor.value.upper() if gate.floor else "-")
                    if gate.triggered
                    else "Hard gate: not triggered"
                ),
                (f"Coverage complete: {'yes' if manifest.coverage.complete else 'no'}"),
                f"Relevant unknowns: {len(manifest.unknowns)}",
                "Policy: report-only; the score never blocks CI",
                (
                    "Boundary: scanned content is never executed; runtime is not "
                    "verified; no LLM authority"
                ),
            ]
        return "\n".join(lines) + "\n"


def _export_schema(model: type[BaseModel], directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(
        json.dumps(
            model.model_json_schema(mode="serialization"), indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def export_agentic_assessment_json_schema(output_directory: Path) -> Path:
    return _export_schema(
        AgenticAssessmentJsonReport,
        output_directory,
        "agentic-assessment.schema.json",
    )


def export_score_context_json_schema(output_directory: Path) -> Path:
    from agentsec.score_context import AgenticScoreContext

    return _export_schema(
        AgenticScoreContext,
        output_directory,
        "score-context.schema.json",
    )


__all__ = [
    "AGENTIC_ASSESSMENT_FORMAT",
    "AGENTIC_ASSESSMENT_FORMAT_VERSION",
    "AgenticAssessmentJsonRenderer",
    "AgenticAssessmentJsonReport",
    "AgenticAssessmentTextRenderer",
    "AgenticAssessmentValidationError",
    "build_agentic_assessment_payload",
    "decode_agentic_assessment_json",
    "export_agentic_assessment_json_schema",
    "export_score_context_json_schema",
]

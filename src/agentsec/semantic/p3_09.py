"""P3-09 Semantic Analyze report rendering helpers."""

from __future__ import annotations

import json
from enum import StrEnum

from agentsec.semantic.p3_08 import SemanticShadowPipelineReport

SEMANTIC_ANALYZE_VERSION = "0.1.0"


class SemanticReportLanguage(StrEnum):
    EN = "en"
    ZH = "zh"


def render_semantic_shadow_pipeline_text(
    report: SemanticShadowPipelineReport,
    *,
    language: SemanticReportLanguage = SemanticReportLanguage.EN,
) -> str:
    """Render bounded text without source excerpts or untrusted values."""

    if not isinstance(report, SemanticShadowPipelineReport):
        raise TypeError("semantic pipeline report is required")
    if not isinstance(language, SemanticReportLanguage):
        raise TypeError("semantic report language is invalid")
    analysis = report.invocation.analysis
    links = report.finding_integration.links
    proposals = report.rule_candidates.proposals
    if language is SemanticReportLanguage.ZH:
        lines = (
            "AgentSec Semantic Shadow Pipeline",
            f"分析 ID: {analysis.analysis_id}",
            f"Provider: {report.invocation.provider.provider_id}",
            f"Model: {report.invocation.provider.model_id}",
            f"语义候选数: {len(analysis.candidates)}",
            f"Finding 关联数: {len(links)}",
            f"Rule Candidate 数: {len(proposals)}",
            f"覆盖状态: {'完整' if analysis.coverage.complete else '不完整'}",
            "权限边界: 仅报告；不创建 Finding、不发布 Rule、不阻断 CI",
            f"运行时验证: {'是' if report.runtime_verified else '否'}",
            f"阻断: {'是' if report.blocks else '否'}",
        )
    else:
        lines = (
            "AgentSec Semantic Shadow Pipeline",
            f"Analysis ID: {analysis.analysis_id}",
            f"Provider: {report.invocation.provider.provider_id}",
            f"Model: {report.invocation.provider.model_id}",
            f"Semantic candidates: {len(analysis.candidates)}",
            f"Finding links: {len(links)}",
            f"Rule candidates: {len(proposals)}",
            f"Coverage: {'complete' if analysis.coverage.complete else 'partial'}",
            (
                "Authority: report-only; no Finding creation, Rule publication, "
                "or CI block"
            ),
            f"Runtime verified: {str(report.runtime_verified).lower()}",
            f"Blocks: {str(report.blocks).lower()}",
        )
    return "\n".join(lines) + "\n"


def encode_semantic_shadow_pipeline_report_json(
    report: SemanticShadowPipelineReport,
) -> str:
    """Encode the already validated pipeline report as canonical JSON."""

    if not isinstance(report, SemanticShadowPipelineReport):
        raise TypeError("semantic pipeline report is required")
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "SEMANTIC_ANALYZE_VERSION",
    "SemanticReportLanguage",
    "encode_semantic_shadow_pipeline_report_json",
    "render_semantic_shadow_pipeline_text",
]

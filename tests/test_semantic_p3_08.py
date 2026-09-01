"""P3-08 end-to-end Semantic Shadow pipeline tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentsec.semantic import (
    OfflineFixtureSemanticProvider,
    SemanticAnalysisInput,
    SemanticAuthorityBoundary,
    SemanticDeterministicContext,
    SemanticModelOutput,
    SemanticPromptBuilder,
    SemanticShadowInvocationAdapter,
    SemanticShadowPipeline,
    SemanticShadowPipelineReport,
    build_semantic_evidence_chunk,
    encode_semantic_shadow_pipeline_json,
)

_HASH = "a" * 64


def _input() -> SemanticAnalysisInput:
    return SemanticAnalysisInput(
        analysis_id="p3-08-test",
        authority_boundary=SemanticAuthorityBoundary(),
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(
            build_semantic_evidence_chunk(
                asset_path="AGENTS.md",
                asset_sha256=_HASH,
                start_line=1,
                end_line=1,
                text="Use a tool only with approval.",
            ),
        ),
    )


def _adapter(semantic_input: SemanticAnalysisInput) -> SemanticShadowInvocationAdapter:
    output = SemanticModelOutput(
        analysis_id=semantic_input.analysis_id,
        analyzed_evidence_ids=tuple(
            item.evidence_id for item in semantic_input.evidence
        ),
        candidates=(),
        limitations=("No candidate was emitted by this fixture.",),
    )
    return SemanticShadowInvocationAdapter(
        provider=OfflineFixtureSemanticProvider(output=output),
        prompt_builder=SemanticPromptBuilder(),
    )


def test_shadow_pipeline_composes_invocation_and_report_only_outputs() -> None:
    semantic_input = _input()
    report = SemanticShadowPipeline(_adapter(semantic_input)).run(semantic_input)

    assert isinstance(report, SemanticShadowPipelineReport)
    assert report.invocation.analysis.analysis_id == semantic_input.analysis_id
    assert report.finding_integration.links == ()
    assert report.rule_candidates.proposals == ()
    assert report.report_only is True
    assert report.finding_authority is False
    assert report.rule_publication_authority is False
    assert report.policy_authority is False
    assert report.ci_authority is False
    assert report.runtime_verified is False
    assert report.blocks is False


def test_pipeline_preserves_existing_deterministic_context_and_finding_inputs() -> None:
    semantic_input = _input().model_copy(
        update={
            "deterministic_context": SemanticDeterministicContext(
                coverage_complete=True,
                finding_ids=("finding-001",),
                capability_ids=("capability:tool",),
            )
        }
    )
    report = SemanticShadowPipeline(_adapter(semantic_input)).run(
        semantic_input,
        findings=(),
        evidence=semantic_input.evidence,
    )
    assert report.invocation.analysis.deterministic_context.finding_ids == (
        "finding-001",
    )
    assert report.invocation.analysis.deterministic_context.capability_ids == (
        "capability:tool",
    )
    assert (
        report.finding_integration.semantic_result_sha256
        == report.rule_candidates.semantic_result_sha256
    )


def test_pipeline_report_digest_and_strict_authority_contract_are_tamper_evident() -> (
    None
):
    semantic_input = _input()
    report = SemanticShadowPipeline(_adapter(semantic_input)).run(semantic_input)
    encoded = encode_semantic_shadow_pipeline_json(report)
    assert "Use a tool" not in encoded
    assert '"severity":' not in encoded
    assert "block" in encoded

    payload = json.loads(encoded)
    payload["ci_authority"] = True
    with pytest.raises(ValidationError):
        SemanticShadowPipelineReport.model_validate(payload)


def test_pipeline_rejects_invalid_adapter_and_semantic_input_types() -> None:
    with pytest.raises(TypeError, match="Shadow pipeline"):
        SemanticShadowPipeline(object())  # type: ignore[arg-type]
    pipeline = SemanticShadowPipeline(_adapter(_input()))
    with pytest.raises(TypeError, match="semantic input"):
        pipeline.run(object())  # type: ignore[arg-type]

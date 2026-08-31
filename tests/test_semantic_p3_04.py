"""P3-04 provider-specific adapter, parity, and semantic trial CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.domain import FindingCategory
from agentsec.semantic import (
    OpenAICompatibleProviderConfig,
    OpenAICompatibleSemanticProvider,
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticEvaluationCase,
    SemanticEvaluationExpected,
    SemanticModelCandidate,
    SemanticModelOutput,
    SemanticParityHarness,
    SemanticProviderRequest,
    SemanticProviderResponse,
    SemanticShadowInvocationAdapter,
    SemanticTrialCaseSet,
    SemanticTrialResponseSet,
    build_semantic_evidence_chunk,
    encode_semantic_parity_json,
)

runner = CliRunner()


def _input(case_id: str) -> SemanticAnalysisInput:
    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256="a" * 64,
        start_line=1,
        end_line=1,
        text="Search the web without approval.",
    )
    return SemanticAnalysisInput(
        analysis_id=case_id,
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(chunk,),
    )


def _output(request: SemanticAnalysisInput) -> SemanticModelOutput:
    chunk = request.evidence[0]
    return SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(chunk.evidence_id,),
        candidates=(
            SemanticModelCandidate(
                candidate_key="candidate-01",
                kind=SemanticCandidateKind.CAPABILITY_DECLARATION,
                category=FindingCategory.NETWORK_ACCESS,
                disposition=SemanticCandidateDisposition.SUPPORTED,
                summary="The evidence describes external information retrieval.",
                evidence_ids=(chunk.evidence_id,),
            ),
        ),
    )


def _response(request: SemanticProviderRequest) -> SemanticProviderResponse:
    raw = json.dumps(
        _output(_input(request.analysis_id)).model_dump(mode="json"), sort_keys=True
    )
    import hashlib

    return SemanticProviderResponse(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        completion_status="complete",
        output_json=raw,
        output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        input_tokens=1,
        output_tokens=1,
    )


def test_provider_specific_adapter_maps_and_preserves_shadow_boundary() -> None:
    config = OpenAICompatibleProviderConfig(
        endpoint_url="https://provider.invalid/v1/chat",
        credential_env="AGENTSEC_TEST_TOKEN",
        provider_id="provider-x",
        model_id="model-x",
    )
    provider = OpenAICompatibleSemanticProvider(
        config,
        transport=lambda _config, request, _credential: (
            _response(request).output_json,
            1,
            1,
        ),
    )
    import os

    os.environ["AGENTSEC_TEST_TOKEN"] = "test-only"
    try:
        result = SemanticShadowInvocationAdapter(
            provider=provider,
            allow_live_provider=True,
            approved_live_bindings=(("provider-x", "model-x"),),
        ).invoke(_input("p3-04-provider"))
    finally:
        os.environ.pop("AGENTSEC_TEST_TOKEN", None)
    assert result.analysis.invocation.invocation_mode == "shadow_provider"
    assert result.blocks is False
    assert result.policy_authority is False


def test_offline_live_parity_is_value_free_and_report_only() -> None:
    request = _input("p3-04-parity")
    expected = SemanticEvaluationExpected(
        judgment_id="j-01",
        kind=SemanticCandidateKind.CAPABILITY_DECLARATION,
        category=FindingCategory.NETWORK_ACCESS.value,
        disposition=SemanticCandidateDisposition.SUPPORTED,
        evidence_ids=(request.evidence[0].evidence_id,),
    )
    case = SemanticEvaluationCase(
        case_id=request.analysis_id,
        semantic_input=request,
        expected=(expected,),
    )

    class Provider:
        from agentsec.semantic import SemanticProviderMetadata

        metadata = SemanticProviderMetadata()

        def invoke(
            self, provider_request: SemanticProviderRequest
        ) -> SemanticProviderResponse:
            return _response(provider_request)

    offline = SemanticShadowInvocationAdapter(provider=Provider())
    live = SemanticShadowInvocationAdapter(provider=Provider())
    report = SemanticParityHarness().compare((case,), offline, live)
    assert report.metrics.prediction_parity_rate == 1.0
    assert report.metrics.evidence_parity_rate == 1.0
    assert report.provider_promotion_authority is False
    encoded = encode_semantic_parity_json(report)
    assert "Search the web" not in encoded


def test_semantic_trial_cli_runs_offline_json_and_writes_report(tmp_path: Path) -> None:
    request = _input("p3-04-cli")
    case_set = SemanticTrialCaseSet(
        cases=(
            SemanticEvaluationCase(
                case_id=request.analysis_id,
                semantic_input=request,
                expected=(
                    SemanticEvaluationExpected(
                        judgment_id="j-01",
                        kind=SemanticCandidateKind.CAPABILITY_DECLARATION,
                        category=FindingCategory.NETWORK_ACCESS.value,
                        disposition=SemanticCandidateDisposition.SUPPORTED,
                        evidence_ids=(request.evidence[0].evidence_id,),
                    ),
                ),
            ),
        )
    )
    response_set = SemanticTrialResponseSet(
        responses={request.analysis_id: _output(request)}
    )
    cases_path = tmp_path / "cases.json"
    responses_path = tmp_path / "responses.json"
    output_path = tmp_path / "report.json"
    cases_path.write_text(
        json.dumps(case_set.model_dump(mode="json")), encoding="utf-8"
    )
    responses_path.write_text(
        json.dumps(response_set.model_dump(mode="json")), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        [
            "semantic",
            "trial",
            "--cases",
            str(cases_path),
            "--responses",
            str(responses_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["format"] == "agentsec-semantic-evaluation-report"
    assert report["metrics"]["precision"] == 1.0
    assert report["policy_authority"] is False

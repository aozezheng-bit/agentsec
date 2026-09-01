"""P3-03 live Shadow trial boundary and semantic evaluation harness tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.domain import FindingCategory
from agentsec.semantic import (
    LiveSemanticProvider,
    LiveSemanticProviderConfig,
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticEvaluationCase,
    SemanticEvaluationExpected,
    SemanticEvaluationHarness,
    SemanticEvaluationReport,
    SemanticModelCandidate,
    SemanticModelOutput,
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationError,
    SemanticShadowInvocationErrorCode,
    encode_semantic_evaluation_json,
    export_semantic_evaluation_json_schema,
    render_semantic_evaluation_text,
)


def _input(case_id: str) -> SemanticAnalysisInput:
    from agentsec.semantic import build_semantic_evidence_chunk

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


def _output(
    request: SemanticAnalysisInput, *, supported: bool = True
) -> SemanticModelOutput:
    chunk = request.evidence[0]
    candidate = SemanticModelCandidate(
        candidate_key="candidate-01",
        kind=SemanticCandidateKind.CAPABILITY_DECLARATION,
        category=FindingCategory.NETWORK_ACCESS,
        disposition=(
            SemanticCandidateDisposition.SUPPORTED
            if supported
            else SemanticCandidateDisposition.UNCERTAIN
        ),
        summary="The evidence describes external information retrieval.",
        evidence_ids=(chunk.evidence_id,),
    )
    return SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(chunk.evidence_id,),
        candidates=(candidate,),
    )


def _response(
    request: SemanticProviderRequest,
    output: SemanticModelOutput,
) -> SemanticProviderResponse:
    raw = json.dumps(output.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
    import hashlib

    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return SemanticProviderResponse(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        completion_status="complete",
        output_json=raw,
        output_sha256=digest,
        input_tokens=10,
        output_tokens=10,
    )


def test_live_provider_requires_explicit_https_and_credential_name() -> None:
    with pytest.raises(ValueError):
        LiveSemanticProviderConfig(
            endpoint_url="http://example.invalid/semantic",
            credential_env="AGENTSEC_TOKEN",
        )
    with pytest.raises(ValueError):
        LiveSemanticProviderConfig(
            endpoint_url="https://user:pass@example.invalid/semantic",
            credential_env="AGENTSEC_TOKEN",
        )
    with pytest.raises(ValueError):
        LiveSemanticProviderConfig(
            endpoint_url="https://example.invalid/semantic",
            credential_env="agentsec_token",
        )


def test_live_provider_uses_credential_only_at_transport_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    def transport(
        config: LiveSemanticProviderConfig,
        request: SemanticProviderRequest,
        credential: str,
    ) -> tuple[str, int, int]:
        captured["endpoint"] = config.endpoint_url
        captured["credential"] = credential
        captured["data"] = request.data_channel_json
        raw = json.dumps(
            _output(_input(request.analysis_id)).model_dump(mode="json"),
            sort_keys=True,
        )
        return raw, 12, 9

    config = LiveSemanticProviderConfig(
        endpoint_url="https://provider.invalid/semantic",
        credential_env="AGENTSEC_TEST_TOKEN",
        provider_id="approved-shadow-provider",
        model_id="approved-shadow-model",
    )
    provider = LiveSemanticProvider(config, transport=transport)
    monkeypatch.setenv("AGENTSEC_TEST_TOKEN", "test-secret-not-retained")
    request = _input("p3-03-live-boundary")
    adapter = SemanticShadowInvocationAdapter(
        provider=provider,
        allow_live_provider=True,
        approved_live_bindings=(("approved-shadow-provider", "approved-shadow-model"),),
    )
    result = adapter.invoke(request)

    assert result.analysis.invocation.invocation_mode == "shadow_provider"
    assert result.provider.transport == "https_json"
    assert result.provider.transport_network_access is True
    assert result.provider.model_network_access is False
    assert result.blocks is False
    assert result.policy_authority is False
    assert captured["credential"] == "test-secret-not-retained"
    assert "test-secret-not-retained" not in result.model_dump_json()
    assert "provider.invalid" not in result.model_dump_json()
    assert "test-secret-not-retained" not in captured["data"]


def test_live_provider_requires_opt_in_and_missing_credential_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = LiveSemanticProviderConfig(
        endpoint_url="https://provider.invalid/semantic",
        credential_env="AGENTSEC_TEST_TOKEN",
    )
    provider = LiveSemanticProvider(
        config,
        transport=lambda _config, _request, _credential: ("{}", 0, 0),
    )
    request = _input("p3-03-opt-in")
    with pytest.raises(SemanticShadowInvocationError) as opt_in:
        SemanticShadowInvocationAdapter(provider=provider).invoke(request)
    assert opt_in.value.code is SemanticShadowInvocationErrorCode.PROVIDER_NOT_APPROVED

    monkeypatch.delenv("AGENTSEC_TEST_TOKEN", raising=False)
    with pytest.raises(SemanticShadowInvocationError) as missing:
        SemanticShadowInvocationAdapter(
            provider=provider,
            allow_live_provider=True,
            approved_live_bindings=(("https-json-shadow", "configured-shadow-model"),),
        ).invoke(request)
    assert missing.value.code is SemanticShadowInvocationErrorCode.PROVIDER_FAILURE


def test_evaluation_harness_calculates_precision_recall_and_evidence_binding() -> None:
    good = _input("case-good")
    bad = _input("case-bad")

    class MappedProvider:
        metadata = SemanticProviderMetadata()

        def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
            source = good if request.analysis_id == good.analysis_id else bad
            return _response(
                request,
                _output(source, supported=request.analysis_id == good.analysis_id),
            )

    cases = (
        SemanticEvaluationCase(
            case_id=bad.analysis_id,
            semantic_input=bad,
            expected=(),
        ),
        SemanticEvaluationCase(
            case_id=good.analysis_id,
            semantic_input=good,
            expected=(
                SemanticEvaluationExpected(
                    judgment_id="judgment-01",
                    kind=SemanticCandidateKind.CAPABILITY_DECLARATION,
                    category=FindingCategory.NETWORK_ACCESS.value,
                    disposition=SemanticCandidateDisposition.SUPPORTED,
                    evidence_ids=(good.evidence[0].evidence_id,),
                ),
            ),
        ),
    )
    report = SemanticEvaluationHarness().evaluate(
        cases,
        SemanticShadowInvocationAdapter(provider=MappedProvider()),
    )

    assert report.metrics.case_count == 2
    assert report.metrics.true_positive == 1
    assert report.metrics.false_positive == 1
    assert report.metrics.false_negative == 0
    assert report.metrics.precision == 0.5
    assert report.metrics.recall == 1.0
    assert report.metrics.evidence_binding_accuracy == 1.0
    assert report.report_only is True
    assert report.policy_authority is False
    assert report.release_authority is False
    assert "candidate evidence only" in render_semantic_evaluation_text(report)
    assert (
        SemanticEvaluationReport.model_validate_json(
            encode_semantic_evaluation_json(report)
        )
        == report
    )


def test_evaluation_harness_records_safe_failed_case_without_raw_error() -> None:
    request = _input("case-failure")

    class FailingProvider:
        metadata = SemanticProviderMetadata()

        def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
            del request
            raise RuntimeError("TOKEN=should-not-leak")

    report = SemanticEvaluationHarness().evaluate(
        (
            SemanticEvaluationCase(
                case_id=request.analysis_id,
                semantic_input=request,
                expected=(),
            ),
        ),
        SemanticShadowInvocationAdapter(provider=FailingProvider()),
    )
    assert report.metrics.failed_case_count == 1
    assert report.cases[0].error_code == "provider_failure"
    assert "should-not-leak" not in encode_semantic_evaluation_json(report)


def test_evaluation_schema_is_frozen(tmp_path: Path) -> None:
    generated = export_semantic_evaluation_json_schema(
        tmp_path / "semantic-evaluation-report.schema.json"
    )
    frozen = Path("schemas/semantic-analysis/semantic-evaluation-report.schema.json")
    assert generated.read_text(encoding="utf-8") == frozen.read_text(encoding="utf-8")

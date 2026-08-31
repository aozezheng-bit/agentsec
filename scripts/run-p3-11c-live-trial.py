#!/usr/bin/env python3
"""P3-11C real-provider Shadow trial runner (single budgeted invocation).

Runs one live invocation per gold-label case (45 total) against the
Theta-hosted OpenAI-compatible endpoint, paced for the QPS=1 personal
token, then archives the evaluation and qualification reports.

Cost boundary: exactly one model judgment per case (ADR-0093). The
credential is read only from the THETA_API_KEY environment variable at
the transport boundary and never written to any file or report. No raw
prompt/response payload is retained.
"""

from __future__ import annotations

import time
from pathlib import Path

from agentsec.semantic import (
    OpenAICompatibleProviderConfig,
    OpenAICompatibleSemanticProvider,
    ProviderQualityThresholds,
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
    SemanticQualityGate,
    load_gold_labels,
)
from agentsec.semantic.evaluation import SemanticEvaluationHarness
from agentsec.semantic.invocation import (
    SemanticInvocationLimits,
    SemanticShadowInvocationAdapter,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PILOT_ROOT = REPOSITORY_ROOT / "pilots" / "semantic-quality-p3-11"
GOLD_LABELS = PILOT_ROOT / "gold-labels" / "semantic-gold-labels.json"
EVALUATION_OUT = PILOT_ROOT / "live-trial" / "evaluation-live.json"
QUALIFICATION_OUT = (
    PILOT_ROOT / "qualification" / ("semantic-quality-qualification-live.json")
)

ENDPOINT = "https://antchat.alipay.com/v1/chat/completions"
PROVIDER_ID = "theta-public"
MODEL_ID = "Kimi-K3-256K"
MIN_CALL_INTERVAL_SECONDS = 1.8


class _PacedProvider:
    """Pacing wrapper keeping the QPS=1 personal-token rate limit intact."""

    def __init__(self, inner: OpenAICompatibleSemanticProvider) -> None:
        self._inner = inner
        self._last = 0.0

    @property
    def metadata(self) -> SemanticProviderMetadata:
        return self._inner.metadata

    def invoke(
        self, provider_request: SemanticProviderRequest
    ) -> SemanticProviderResponse:
        wait = MIN_CALL_INTERVAL_SECONDS - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        return self._inner.invoke(provider_request)


def main() -> int:
    gold = load_gold_labels(GOLD_LABELS)
    provider = _PacedProvider(
        OpenAICompatibleSemanticProvider(
            OpenAICompatibleProviderConfig(
                endpoint_url=ENDPOINT,
                credential_env="THETA_API_KEY",
                provider_id=PROVIDER_ID,
                model_id=MODEL_ID,
                timeout_ms=120_000,
            )
        )
    )
    adapter = SemanticShadowInvocationAdapter(
        provider=provider,
        limits=SemanticInvocationLimits(
            timeout_ms=120_000, max_input_tokens=32_768, max_output_tokens=8_192
        ),
        allow_live_provider=True,
        approved_live_bindings=((PROVIDER_ID, MODEL_ID),),
    )
    gate = SemanticQualityGate()
    cases = tuple(gate._build_cases(gold))  # noqa: SLF001 - evidence runner
    harness = SemanticEvaluationHarness()
    print(f"live trial: {len(cases)} cases, provider {PROVIDER_ID}|{MODEL_ID}")
    started = time.monotonic()
    report = harness.evaluate(cases, adapter)
    elapsed = time.monotonic() - started
    EVALUATION_OUT.parent.mkdir(parents=True, exist_ok=True)
    EVALUATION_OUT.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    qualification = gate.qualify_evaluation_report(
        gold=gold,
        report=report,
        thresholds=ProviderQualityThresholds(min_case_count=20),
    )
    QUALIFICATION_OUT.parent.mkdir(parents=True, exist_ok=True)
    QUALIFICATION_OUT.write_text(
        qualification.model_dump_json(indent=2), encoding="utf-8"
    )

    metrics = report.metrics
    print(f"elapsed: {elapsed:.0f}s")
    print(
        f"cases: {metrics.case_count} complete={metrics.completed_case_count} "
        f"failed={metrics.failed_case_count}"
    )
    print(
        f"precision={metrics.precision:.3f} recall={metrics.recall:.3f} "
        f"f1={metrics.f1:.3f}"
    )
    print(
        f"evidence_binding_accuracy={metrics.evidence_binding_accuracy:.3f} "
        f"complete_coverage_rate={metrics.complete_coverage_rate:.3f}"
    )
    failed_codes: dict[str, int] = {}
    for case in report.cases:
        if case.status.value != "complete" and case.error_code:
            failed_codes[case.error_code] = failed_codes.get(case.error_code, 0) + 1
    if failed_codes:
        print(f"failure codes: {failed_codes}")
    print(
        f"qualification: {qualification.status.value} "
        f"failed_checks={qualification.failed_checks} "
        f"reasons={qualification.reasons}"
    )
    print(f"evaluation: {EVALUATION_OUT}")
    print(f"qualification: {QUALIFICATION_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

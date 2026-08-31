"""P2-20 Agentic Technical Score contract tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.risk import (
    TECHNICAL_FACTOR_WEIGHTS,
    CvssBaseAdapter,
    DeterministicAgenticFactorExtractor,
    DeterministicTechnicalScoreEngine,
    DeterministicThreatMitigationEvaluator,
    TechnicalScoreError,
    encode_technical_score_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ENGINE = DeterministicTechnicalScoreEngine()


def _inputs(name: str):  # type: ignore[no-untyped-def]
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
    manifest = (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=project, agent_id="capability-drift-agent"
            )
        )
        .manifest
    )
    factors = DeterministicAgenticFactorExtractor().extract(manifest)
    threats = DeterministicThreatMitigationEvaluator().evaluate(manifest, factors)
    return factors, threats


def test_technical_score_is_deterministic_and_traceable() -> None:
    factors, threats = _inputs("risky-drift")

    first = ENGINE.score(factors, threats)
    second = ENGINE.score(factors, threats)

    assert first == second
    assert len(first.factor_contributions) == 10
    assert sum(TECHNICAL_FACTOR_WEIGHTS.values()) == 1.0
    assert first.agentic_score == 5.7
    assert first.cvss_base_score is None
    assert first.technical_score == first.agentic_score
    assert first.high_water_mark_source == "agentic"
    assert first.severity.value == "medium"
    assert sum(count for _, count in first.confidence_counts) == 10


def test_cvss_base_is_an_independent_high_water_mark() -> None:
    factors, threats = _inputs("risky-drift")
    cvss = CvssBaseAdapter().adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}
    )

    assessment = ENGINE.score(factors, threats, cvss=cvss)

    assert assessment.cvss_base_score == 9.3
    assert assessment.agentic_score == 5.7
    assert assessment.technical_score == 9.3
    assert assessment.high_water_mark_source == "cvss_base"
    assert assessment.severity.value == "critical"


def test_unknown_and_static_mitigation_are_not_confidence_discounts() -> None:
    factors, threats = _inputs("risky-drift")
    assessment = ENGINE.score(factors, threats)

    unknown = [
        item
        for item in assessment.factor_contributions
        if item.threat_state.value == "unknown"
    ]
    assert unknown
    assert all(item.mitigation_multiplier == 1.0 for item in unknown)
    assert any(
        item.mitigation_multiplier == 0.9 for item in assessment.factor_contributions
    )


def test_factor_and_threat_manifest_binding_is_strict() -> None:
    factors, threats = _inputs("risky-drift")
    mismatched = replace(factors, manifest_sha256="0" * 64)

    with pytest.raises(TechnicalScoreError):
        ENGINE.score(mismatched, threats)


def test_json_output_is_bounded_and_does_not_expose_source_values() -> None:
    factors, threats = _inputs("risky-drift")
    assessment = ENGINE.score(factors, threats)
    encoded = encode_technical_score_json(assessment)
    payload = json.loads(encoded)

    assert payload["format"] == "agentsec-technical-score"
    assert payload["format_version"] == "0.1.0"
    assert len(payload["factor_contributions"]) == 10
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded
    assert encoded.endswith("\n")

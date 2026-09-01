"""P2-19 deterministic Threat and Mitigation tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.risk import (
    DeterministicAgenticFactorExtractor,
    DeterministicThreatMitigationEvaluator,
    MitigationState,
    ThreatState,
    encode_threat_mitigation_vector_json,
)
from agentsec.risk.threat_mitigation import (
    NO_MITIGATION_MULTIPLIER,
    STATIC_MITIGATION_MULTIPLIER,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _vector(name: str):  # type: ignore[no-untyped-def]
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
    return manifest, DeterministicThreatMitigationEvaluator().evaluate(
        manifest, factors
    )


def test_threat_mitigation_vector_is_complete_and_deterministic() -> None:
    _, first = _vector("risky-drift")
    _, second = _vector("risky-drift")

    assert first == second
    assert len(first.assessments) == 10
    assert first.static_mitigation_floor == STATIC_MITIGATION_MULTIPLIER
    assert first.assessments[5].threat.state is ThreatState.PRESENT_STATIC
    assert first.assessments[5].mitigation.state is MitigationState.DECLARED
    assert first.assessments[5].mitigation.multiplier == STATIC_MITIGATION_MULTIPLIER


def test_unknown_threat_cannot_receive_static_mitigation_reduction() -> None:
    _, vector = _vector("risky-drift")

    unknown = [
        item for item in vector.assessments if item.threat.state is ThreatState.UNKNOWN
    ]

    assert unknown
    assert all(
        item.mitigation.multiplier == NO_MITIGATION_MULTIPLIER for item in unknown
    )
    assert any(item.mitigation.state is MitigationState.DECLARED for item in unknown)


def test_absent_threat_is_not_applicable_for_mitigation() -> None:
    _, vector = _vector("baseline")

    absent = [
        item for item in vector.assessments if item.threat.state is ThreatState.ABSENT
    ]

    assert absent
    assert all(
        item.mitigation.state is MitigationState.NOT_APPLICABLE for item in absent
    )
    assert all(
        item.mitigation.multiplier == NO_MITIGATION_MULTIPLIER for item in absent
    )


def test_json_output_contains_hashes_and_no_source_values() -> None:
    _, vector = _vector("risky-drift")
    encoded = encode_threat_mitigation_vector_json(vector)
    payload = json.loads(encoded)

    assert payload["format"] == "agentsec-threat-mitigation-vector"
    assert payload["format_version"] == "0.1.0"
    assert len(payload["assessments"]) == 10
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded
    assert encoded.endswith("\n")


def test_vector_binding_and_static_multiplier_contract_are_strict() -> None:
    manifest, vector = _vector("risky-drift")

    assert vector.manifest_sha256 != "0" * 64

    declared = next(
        item
        for item in vector.assessments
        if item.mitigation.state is MitigationState.DECLARED
    )
    with pytest.raises(ValueError):
        replace(declared.mitigation, multiplier=0.5)

    assert manifest.identity.agent_id == vector.agent_id

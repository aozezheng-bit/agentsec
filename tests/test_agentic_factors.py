"""P2-18 deterministic Agentic Factor model and extractor tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.domain import EvidenceConfidence
from agentsec.risk import (
    AGENTIC_FACTOR_FORMAT,
    AGENTIC_FACTOR_FORMAT_VERSION,
    AGENTIC_FACTOR_MODEL_VERSION,
    AgenticFactorId,
    DeterministicAgenticFactorExtractor,
    encode_agentic_factor_vector_json,
)
from agentsec.risk.agentic_factors import AgenticFactorVector

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = DeterministicAgenticFactorExtractor()


def _manifest(name: str):  # type: ignore[no-untyped-def]
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
    return (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=project, agent_id="capability-drift-agent"
            )
        )
        .manifest
    )


def test_factor_vector_has_ten_stable_factors_and_is_deterministic() -> None:
    manifest = _manifest("risky-drift")

    first = EXTRACTOR.extract(manifest)
    second = EXTRACTOR.extract(manifest)
    encoded = encode_agentic_factor_vector_json(first)
    payload = json.loads(encoded)

    assert first == second
    assert first.format == AGENTIC_FACTOR_FORMAT
    assert first.format_version == AGENTIC_FACTOR_FORMAT_VERSION
    assert first.model_version == AGENTIC_FACTOR_MODEL_VERSION
    assert tuple(item.factor_id for item in first.factors) == tuple(AgenticFactorId)
    assert all(item.value in {0.0, 0.5, 1.0} for item in first.factors)
    assert payload["agent_id"] == "capability-drift-agent"
    assert len(payload["factors"]) == 10
    assert encoded.endswith("\n")


def test_factor_vector_uses_manifest_evidence_without_source_values() -> None:
    vector = EXTRACTOR.extract(_manifest("risky-drift"))
    persistent = next(
        item
        for item in vector.factors
        if item.factor_id is AgenticFactorId.PERSISTENT_MEMORY
    )
    encoded = encode_agentic_factor_vector_json(vector)

    assert persistent.factor_id is AgenticFactorId.PERSISTENT_MEMORY
    assert persistent.value == 1.0
    assert persistent.confidence is EvidenceConfidence.B
    assert persistent.evidence
    assert all(item.content_sha256 for item in persistent.evidence)
    assert "synthetic-demo-token" not in encoded
    assert "LOCAL_REVIEW_TOKEN" not in encoded
    assert "https://example.invalid" not in encoded


def test_incomplete_coverage_is_never_reported_as_zero_confidence_safe() -> None:
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "incomplete"
    manifest = (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=project, agent_id="capability-drift-agent"
            )
        )
        .manifest
    )

    vector = EXTRACTOR.extract(manifest)

    assert vector.coverage_complete is False
    assert vector.relevant_unknown_count > 0
    assert all(item.value == 0.5 for item in vector.factors)
    assert all(item.confidence is EvidenceConfidence.D for item in vector.factors)
    assert all(item.limitations for item in vector.factors)


def test_factor_model_rejects_missing_factor_or_invalid_value() -> None:
    vector = EXTRACTOR.extract(_manifest("baseline"))

    with pytest.raises(ValueError):
        AgenticFactorVector(
            format=vector.format,
            format_version=vector.format_version,
            model_version=vector.model_version,
            manifest_schema_version=vector.manifest_schema_version,
            agent_id=vector.agent_id,
            manifest_sha256=vector.manifest_sha256,
            coverage_complete=vector.coverage_complete,
            relevant_unknown_count=vector.relevant_unknown_count,
            factors=vector.factors[:-1],
            mapping_basis=vector.mapping_basis,
        )

    with pytest.raises(ValueError):
        replace(vector.factors[0], value=0.25)

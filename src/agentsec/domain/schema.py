"""JSON Schema export for versioned AgentSec domain objects."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from agentsec.domain.assessment import (
    Assessment,
    AssessmentMetadata,
    CoverageIssue,
    ScanCoverage,
)
from agentsec.domain.assets import AgentAsset, AssetChange
from agentsec.domain.findings import (
    CvssBase,
    CvssHardGateAssessment,
    CvssHardGateMatch,
    Evidence,
    Finding,
    VulnerabilityReference,
)

SCHEMA_MODELS: Mapping[str, type[BaseModel]] = {
    "agent-asset": AgentAsset,
    "asset-change": AssetChange,
    "evidence": Evidence,
    "cvss-base": CvssBase,
    "cvss-hard-gate-assessment": CvssHardGateAssessment,
    "cvss-hard-gate-match": CvssHardGateMatch,
    "vulnerability-reference": VulnerabilityReference,
    "finding": Finding,
    "coverage-issue": CoverageIssue,
    "scan-coverage": ScanCoverage,
    "assessment-metadata": AssessmentMetadata,
    "assessment": Assessment,
}


def export_json_schemas(output_directory: Path) -> tuple[Path, ...]:
    """Write deterministic JSON Schema files for public domain models."""

    output_directory.mkdir(parents=True, exist_ok=True)
    exported_paths: list[Path] = []

    for schema_name, model in SCHEMA_MODELS.items():
        output_path = output_directory / f"{schema_name}.schema.json"
        schema = model.model_json_schema(mode="serialization")
        output_path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        exported_paths.append(output_path)

    return tuple(exported_paths)

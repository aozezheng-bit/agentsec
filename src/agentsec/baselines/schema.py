"""Deterministic JSON Schema export for the AgentSec baseline format."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.baselines.models import Baseline
from agentsec.versioning import BASELINE_SCHEMA_VERSION


def export_baseline_json_schema(output_directory: Path) -> Path:
    """Write the current strict baseline JSON Schema deterministically."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "baseline.schema.json"
    schema: dict[str, Any] = Baseline.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-baseline-schema-version"] = BASELINE_SCHEMA_VERSION
    output_path.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path

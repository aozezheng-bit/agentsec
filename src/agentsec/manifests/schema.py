"""Deterministic JSON Schema export for Agent Manifest 0.1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.manifests.models import AgentManifest
from agentsec.versioning import AGENT_MANIFEST_SCHEMA_VERSION


def export_agent_manifest_json_schema(output_directory: Path) -> Path:
    """Write the current strict Agent Manifest JSON Schema."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "agent-manifest.schema.json"
    schema: dict[str, Any] = AgentManifest.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-agent-manifest-schema-version"] = AGENT_MANIFEST_SCHEMA_VERSION
    output_path.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path

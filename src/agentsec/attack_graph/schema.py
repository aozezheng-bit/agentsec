"""Canonical encoding and frozen JSON Schema export for the Attack Graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentsec.attack_graph.models import CapabilityAttackGraph


def encode_attack_graph_json(value: CapabilityAttackGraph) -> str:
    """Encode one validated Attack Graph with canonical deterministic JSON."""

    if not isinstance(value, CapabilityAttackGraph):
        raise TypeError("attack graph encoder requires CapabilityAttackGraph")
    return _encode(value)


def export_attack_graph_json_schema(output_path: Path) -> Path:
    """Export the frozen Capability Attack Graph Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("attack graph Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema: dict[str, Any] = CapabilityAttackGraph.model_json_schema(
        mode="serialization"
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def render_attack_graph_text(value: CapabilityAttackGraph) -> str:
    """Render a bounded bilingual-neutral boundary summary, no raw payloads."""

    if not isinstance(value, CapabilityAttackGraph):
        raise TypeError("attack graph renderer requires CapabilityAttackGraph")
    lines = [
        "AgentSec Capability Attack Graph",
        f"Format: {value.format} {value.schema_version}",
        f"Manifest Schema: {value.manifest_schema_version}",
        f"Nodes: {len(value.nodes)}",
        f"Edges: {len(value.edges)}",
        f"Paths: {len(value.paths)}",
        (
            "Mode: report_only=true; blocks=false; finding/policy/CI/release/"
            "runtime authority=false"
        ),
        (
            "Every path is a static declared path; runtime_verified=false; "
            "reachability=not_proven; exploitability=not_proven"
        ),
    ]
    return "\n".join(lines) + "\n"


def _encode(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "encode_attack_graph_json",
    "export_attack_graph_json_schema",
    "render_attack_graph_text",
]

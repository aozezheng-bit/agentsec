"""P3-AG-04 value-free Attack Path report contracts and rendering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.attack_graph.models import (
    ATTACK_GRAPH_MAX_PATH_NODES,
    AttackGraphNodeKind,
    AttackNodeIdentifier,
    AttackPathIdentifier,
    AttackPatternIdentifier,
    CapabilityAttackGraph,
    ManifestBindingVersion,
)
from agentsec.attack_graph.patterns import (
    ATTACK_PATH_PATTERN_LIBRARY_VERSION as _PATTERN_LIBRARY_VERSION,
)
from agentsec.domain.base import Sha256Digest

ATTACK_PATH_REPORT_VERSION = "0.1.0"
ATTACK_PATH_REPORT_FORMAT = "agentsec-attack-path-report"
ATTACK_PATH_MAX_ENTRIES = 256
ATTACK_PATH_MAX_LIMITATIONS = 32

PatternLibraryVersion = Annotated[
    str, Field(pattern=r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
]

ATTACK_PATH_REPORT_LIMITATIONS: tuple[str, ...] = (
    "paths are static declared relations only; no runtime execution occurred",
    "runtime_verified=false for every path; reachability and exploitability "
    "are not_proven",
    "a matched path is not a Finding and carries no severity or likelihood",
    "delegation-escalation exposes the delegation relation only; sub-agent "
    "capabilities are outside the static Manifest",
    "mcp-production-write and tool-dependency-install match zero paths until "
    "the builder emits writes_to/installs edges",
    "this report is report-only and grants no Finding, Rule, Policy, CI, "
    "Hard Gate, or release authority",
)


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackPathReportEntry(_Strict):
    """One matched static path summarized without node labels or raw text."""

    path_id: AttackPathIdentifier
    pattern_id: AttackPatternIdentifier
    path_kind: Literal["static_declared_path"] = "static_declared_path"
    node_count: int = Field(ge=1, le=ATTACK_GRAPH_MAX_PATH_NODES)
    edge_count: int = Field(ge=0, le=ATTACK_GRAPH_MAX_PATH_NODES - 1)
    node_kind_sequence: tuple[AttackGraphNodeKind, ...] = Field(
        min_length=1, max_length=ATTACK_GRAPH_MAX_PATH_NODES
    )
    node_ids: tuple[AttackNodeIdentifier, ...] = Field(
        min_length=1, max_length=ATTACK_GRAPH_MAX_PATH_NODES
    )
    runtime_verified: Literal[False] = False
    reachability: Literal["not_proven"] = "not_proven"
    exploitability: Literal["not_proven"] = "not_proven"

    @model_validator(mode="after")
    def entry_must_be_coherent(self) -> AttackPathReportEntry:
        if self.node_count != len(self.node_ids):
            raise ValueError("attack path entry node count is inconsistent")
        if self.node_count != len(self.node_kind_sequence):
            raise ValueError("attack path entry node kind sequence is inconsistent")
        if self.edge_count != self.node_count - 1:
            raise ValueError("attack path entry edge count is inconsistent")
        return self


class AttackPathReport(_Strict):
    """Value-free report of matched static Attack Paths; no authority."""

    format: Literal["agentsec-attack-path-report"] = "agentsec-attack-path-report"
    schema_version: Literal["0.1.0"] = "0.1.0"
    pattern_library_version: PatternLibraryVersion
    manifest_schema_version: ManifestBindingVersion
    manifest_sha256: Sha256Digest
    graph_sha256: Sha256Digest
    path_count: int = Field(ge=0, le=ATTACK_PATH_MAX_ENTRIES)
    entries: tuple[AttackPathReportEntry, ...] = Field(
        max_length=ATTACK_PATH_MAX_ENTRIES
    )
    limitations: tuple[str, ...] = Field(max_length=ATTACK_PATH_MAX_LIMITATIONS)
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    finding_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False
    exploitability_claimed: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> AttackPathReport:
        if self.path_count != len(self.entries):
            raise ValueError("attack path report entry count is inconsistent")
        path_ids = tuple(entry.path_id for entry in self.entries)
        if path_ids != tuple(sorted(set(path_ids))):
            raise ValueError(
                "attack path report entries must be sorted by path ID and unique"
            )
        if self.entries and not self.limitations:
            raise ValueError("attack path report entries require disclosed limitations")
        return self


def canonical_attack_graph_sha256(graph: CapabilityAttackGraph) -> str:
    """Return the canonical digest of one validated Attack Graph."""

    if not isinstance(graph, CapabilityAttackGraph):
        raise TypeError("attack graph digest requires CapabilityAttackGraph")
    return _canonical_hash(graph.model_dump(mode="json"))


def build_attack_path_report(graph: CapabilityAttackGraph) -> AttackPathReport:
    """Derive a value-free report from one graph with matched paths."""

    if not isinstance(graph, CapabilityAttackGraph):
        raise TypeError("attack path report requires CapabilityAttackGraph")
    node_kinds = {node.node_id: node.node_kind for node in graph.nodes}
    entries = sorted(
        (
            AttackPathReportEntry(
                path_id=path.path_id,
                pattern_id=path.pattern_id,
                node_ids=path.node_sequence,
                node_kind_sequence=tuple(
                    node_kinds[node_id] for node_id in path.node_sequence
                ),
                node_count=len(path.node_sequence),
                edge_count=len(path.edge_sequence),
            )
            for path in graph.paths
        ),
        key=lambda entry: entry.path_id,
    )
    return AttackPathReport(
        manifest_schema_version=graph.manifest_schema_version,
        manifest_sha256=graph.manifest_sha256,
        graph_sha256=canonical_attack_graph_sha256(graph),
        pattern_library_version=_PATTERN_LIBRARY_VERSION,
        path_count=len(entries),
        entries=tuple(entries),
        limitations=ATTACK_PATH_REPORT_LIMITATIONS,
    )


def encode_attack_path_report_json(report: AttackPathReport) -> str:
    """Encode one validated report as canonical deterministic JSON."""

    if not isinstance(report, AttackPathReport):
        raise TypeError("attack path report encoder requires AttackPathReport")
    return _encode(report)


def render_attack_path_report_text(report: AttackPathReport) -> str:
    """Render a bounded boundary-first summary without any node labels."""

    if not isinstance(report, AttackPathReport):
        raise TypeError("attack path report renderer requires AttackPathReport")
    lines: list[str] = [
        "AgentSec Attack Path Report",
        f"Format: {report.format} {report.schema_version}",
        f"Pattern Library: {report.pattern_library_version}",
        f"Paths: {report.path_count}",
    ]
    for entry in report.entries:
        chain = " > ".join(kind.value for kind in entry.node_kind_sequence)
        lines.append(
            f"- {entry.pattern_id}: {chain} "
            f"(nodes={entry.node_count}, edges={entry.edge_count})"
        )
    lines.extend(
        (
            (
                "Mode: report_only=true; blocks=false; finding/policy/CI/release/"
                "runtime authority=false"
            ),
            (
                "Boundary: static declared relations only; runtime_verified="
                "false; reachability=not_proven; exploitability=not_proven"
            ),
            "A matched path is not a Finding and grants no decision authority.",
        )
    )
    return "\n".join(lines) + "\n"


def export_attack_path_report_json_schema(output_path: Path) -> Path:
    """Export the frozen Attack Path report Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("attack path report Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema: dict[str, Any] = AttackPathReport.model_json_schema(mode="serialization")
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


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


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ATTACK_PATH_MAX_ENTRIES",
    "ATTACK_PATH_MAX_LIMITATIONS",
    "ATTACK_PATH_REPORT_FORMAT",
    "ATTACK_PATH_REPORT_LIMITATIONS",
    "ATTACK_PATH_REPORT_VERSION",
    "AttackPathReport",
    "AttackPathReportEntry",
    "build_attack_path_report",
    "canonical_attack_graph_sha256",
    "encode_attack_path_report_json",
    "export_attack_path_report_json_schema",
    "render_attack_path_report_text",
]

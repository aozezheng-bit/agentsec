"""Strict P3-AG-01 Capability Attack Graph data contracts with no authority."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain.base import Sha256Digest, validate_relative_path

ATTACK_GRAPH_SCHEMA_VERSION = "0.1.0"
ATTACK_GRAPH_FORMAT = "agentsec-capability-attack-graph"

ATTACK_GRAPH_MAX_NODES = 2_048
ATTACK_GRAPH_MAX_EDGES = 8_192
ATTACK_GRAPH_MAX_PATHS = 256
ATTACK_GRAPH_MAX_PATH_NODES = 32
ATTACK_GRAPH_MAX_LABEL_CHARACTERS = 160
ATTACK_GRAPH_MAX_MANIFEST_REFS = 16
ATTACK_GRAPH_MAX_SOURCE_REFS = 16

_NODE_ID_PATTERN = r"^attack-node-sha256:[0-9a-f]{64}$"
_EDGE_ID_PATTERN = r"^attack-edge-sha256:[0-9a-f]{64}$"
_PATH_ID_PATTERN = r"^attack-path-sha256:[0-9a-f]{64}$"
_MANIFEST_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$"
_PATTERN_ID_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"
_MANIFEST_VERSION_PATTERN = r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$"

_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

AttackNodeIdentifier = Annotated[str, Field(pattern=_NODE_ID_PATTERN)]
AttackEdgeIdentifier = Annotated[str, Field(pattern=_EDGE_ID_PATTERN)]
AttackPathIdentifier = Annotated[str, Field(pattern=_PATH_ID_PATTERN)]
ManifestComponentReference = Annotated[
    str, Field(min_length=1, max_length=160, pattern=_MANIFEST_REF_PATTERN)
]
AttackPatternIdentifier = Annotated[
    str, Field(min_length=1, max_length=64, pattern=_PATTERN_ID_PATTERN)
]
SafeAttackGraphLabel = Annotated[
    str, Field(min_length=1, max_length=ATTACK_GRAPH_MAX_LABEL_CHARACTERS)
]
ManifestBindingVersion = Annotated[str, Field(pattern=_MANIFEST_VERSION_PATTERN)]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackGraphNodeKind(StrEnum):
    """Finite reviewed node families; none proves runtime behavior."""

    UNTRUSTED_INPUT = "untrusted_input"
    TOOL = "tool"
    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    AGENT = "agent"
    SECRET = "secret"
    DATA = "data"
    MEMORY = "memory"
    NETWORK = "network"
    PRODUCTION_TARGET = "production_target"
    DEPENDENCY = "dependency"


class AttackGraphEdgeKind(StrEnum):
    """Finite reviewed directed relations between Attack Graph nodes."""

    USES_TOOL = "uses_tool"
    USES_SKILL = "uses_skill"
    USES_MCP = "uses_mcp"
    READS_INPUT = "reads_input"
    OVERRIDES_INSTRUCTION = "overrides_instruction"
    READS_SECRET = "reads_secret"
    READS_DATA = "reads_data"
    WRITES_MEMORY = "writes_memory"
    READS_MEMORY = "reads_memory"
    WRITES_TO = "writes_to"
    SENDS_TO = "sends_to"
    DELEGATES_TO = "delegates_to"
    INSTALLS = "installs"
    PROVIDES_TOOL = "provides_tool"


_EDGE_ENDPOINT_KINDS: dict[
    AttackGraphEdgeKind,
    tuple[frozenset[AttackGraphNodeKind], frozenset[AttackGraphNodeKind]],
] = {
    AttackGraphEdgeKind.USES_TOOL: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.TOOL}),
    ),
    AttackGraphEdgeKind.USES_SKILL: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.SKILL}),
    ),
    AttackGraphEdgeKind.USES_MCP: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.MCP_SERVER}),
    ),
    AttackGraphEdgeKind.READS_INPUT: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.UNTRUSTED_INPUT}),
    ),
    AttackGraphEdgeKind.OVERRIDES_INSTRUCTION: (
        frozenset({AttackGraphNodeKind.UNTRUSTED_INPUT}),
        frozenset({AttackGraphNodeKind.AGENT}),
    ),
    AttackGraphEdgeKind.READS_SECRET: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.SECRET}),
    ),
    AttackGraphEdgeKind.READS_DATA: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.DATA}),
    ),
    AttackGraphEdgeKind.WRITES_MEMORY: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.MEMORY}),
    ),
    AttackGraphEdgeKind.READS_MEMORY: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.MEMORY}),
    ),
    AttackGraphEdgeKind.WRITES_TO: (
        frozenset(
            {
                AttackGraphNodeKind.TOOL,
                AttackGraphNodeKind.SKILL,
                AttackGraphNodeKind.MCP_SERVER,
            }
        ),
        frozenset(
            {
                AttackGraphNodeKind.PRODUCTION_TARGET,
                AttackGraphNodeKind.DATA,
                AttackGraphNodeKind.MEMORY,
            }
        ),
    ),
    AttackGraphEdgeKind.SENDS_TO: (
        frozenset(
            {
                AttackGraphNodeKind.AGENT,
                AttackGraphNodeKind.TOOL,
                AttackGraphNodeKind.SKILL,
                AttackGraphNodeKind.MCP_SERVER,
            }
        ),
        frozenset({AttackGraphNodeKind.NETWORK}),
    ),
    AttackGraphEdgeKind.DELEGATES_TO: (
        frozenset({AttackGraphNodeKind.AGENT}),
        frozenset({AttackGraphNodeKind.AGENT}),
    ),
    AttackGraphEdgeKind.INSTALLS: (
        frozenset(
            {
                AttackGraphNodeKind.TOOL,
                AttackGraphNodeKind.SKILL,
                AttackGraphNodeKind.MCP_SERVER,
            }
        ),
        frozenset({AttackGraphNodeKind.DEPENDENCY}),
    ),
    AttackGraphEdgeKind.PROVIDES_TOOL: (
        frozenset({AttackGraphNodeKind.MCP_SERVER}),
        frozenset({AttackGraphNodeKind.TOOL}),
    ),
}


class AttackGraphNodeProvenance(StrEnum):
    """How a node became part of the graph; never a runtime fact."""

    MANIFEST_DECLARED = "manifest_declared"
    MANIFEST_INFERRED = "manifest_inferred"
    SYNTHETIC = "synthetic"


class AttackGraphSourceRef(_Strict):
    """Value-free Manifest source locator; no raw text is retained."""

    asset_path: Annotated[str, Field(min_length=1, max_length=512)]
    asset_sha256: Sha256Digest
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]

    @field_validator("asset_path")
    @classmethod
    def path_must_be_safe_relative(cls, value: str) -> str:
        return validate_relative_path(value)

    @model_validator(mode="after")
    def source_ref_must_be_coherent(self) -> AttackGraphSourceRef:
        if self.end_line < self.start_line:
            raise ValueError("attack graph source line range must be coherent")
        return self

    def sort_key(self) -> tuple[str, str, int, int]:
        """Return the deterministic Evidence ordering key."""

        return (self.asset_path, self.asset_sha256, self.start_line, self.end_line)


class AttackGraphNode(_Strict):
    """One Attack Graph entity with value-free Evidence and no authority."""

    node_id: AttackNodeIdentifier
    node_kind: AttackGraphNodeKind
    node_provenance: AttackGraphNodeProvenance
    label: SafeAttackGraphLabel | None = None
    manifest_refs: Annotated[
        tuple[ManifestComponentReference, ...],
        Field(max_length=ATTACK_GRAPH_MAX_MANIFEST_REFS),
    ] = ()
    sources: Annotated[
        tuple[AttackGraphSourceRef, ...],
        Field(max_length=ATTACK_GRAPH_MAX_SOURCE_REFS),
    ] = ()
    runtime_verified: Literal[False] = False

    @field_validator("label")
    @classmethod
    def label_must_be_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(
            unicodedata.category(character) in _UNSAFE_CATEGORIES for character in value
        ):
            raise ValueError("attack graph node label contains unsafe characters")
        return value

    @model_validator(mode="after")
    def node_must_be_coherent(self) -> AttackGraphNode:
        refs = self.manifest_refs
        if refs != tuple(sorted(set(refs))):
            raise ValueError(
                "attack graph node Manifest references must be sorted and unique"
            )
        keys = tuple(source.sort_key() for source in self.sources)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("attack graph node sources must be sorted and unique")
        declared = self.node_provenance is AttackGraphNodeProvenance.MANIFEST_DECLARED
        if declared != bool(refs):
            raise ValueError(
                "manifest_declared nodes require Manifest references and "
                "non-declared nodes must not carry them"
            )
        expected_id = attack_node_id(
            node_kind=self.node_kind,
            label=self.label,
            node_provenance=self.node_provenance,
            manifest_refs=refs,
            sources=self.sources,
        )
        if self.node_id != expected_id:
            raise ValueError("attack graph node ID is inconsistent")
        return self


class AttackGraphEdge(_Strict):
    """One directed relation with value-free Evidence and no authority."""

    edge_id: AttackEdgeIdentifier
    edge_kind: AttackGraphEdgeKind
    source_node_id: AttackNodeIdentifier
    target_node_id: AttackNodeIdentifier
    sources: Annotated[
        tuple[AttackGraphSourceRef, ...],
        Field(max_length=ATTACK_GRAPH_MAX_SOURCE_REFS),
    ] = ()
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def edge_must_be_coherent(self) -> AttackGraphEdge:
        if self.source_node_id == self.target_node_id:
            raise ValueError("attack graph edge must not connect a node to itself")
        keys = tuple(source.sort_key() for source in self.sources)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("attack graph edge sources must be sorted and unique")
        expected_id = attack_edge_id(
            edge_kind=self.edge_kind,
            source_node_id=self.source_node_id,
            target_node_id=self.target_node_id,
            sources=self.sources,
        )
        if self.edge_id != expected_id:
            raise ValueError("attack graph edge ID is inconsistent")
        return self


class AttackGraphPath(_Strict):
    """One static declared path chain; never a runtime reachability proof."""

    path_id: AttackPathIdentifier
    pattern_id: AttackPatternIdentifier
    path_kind: Literal["static_declared_path"] = "static_declared_path"
    node_sequence: Annotated[
        tuple[AttackNodeIdentifier, ...],
        Field(min_length=2, max_length=ATTACK_GRAPH_MAX_PATH_NODES),
    ]
    edge_sequence: Annotated[
        tuple[AttackEdgeIdentifier, ...],
        Field(min_length=1, max_length=ATTACK_GRAPH_MAX_PATH_NODES - 1),
    ]
    runtime_verified: Literal[False] = False
    reachability: Literal["not_proven"] = "not_proven"
    exploitability: Literal["not_proven"] = "not_proven"

    @model_validator(mode="after")
    def path_must_be_coherent(self) -> AttackGraphPath:
        if len(self.edge_sequence) != len(self.node_sequence) - 1:
            raise ValueError("attack graph path edge count must match the node chain")
        if len(set(self.node_sequence)) != len(self.node_sequence):
            raise ValueError("attack graph path must not repeat a node")
        expected_id = attack_path_id(
            pattern_id=self.pattern_id,
            node_sequence=self.node_sequence,
            edge_sequence=self.edge_sequence,
        )
        if self.path_id != expected_id:
            raise ValueError("attack graph path ID is inconsistent")
        return self


class CapabilityAttackGraph(_Strict):
    """Deterministic static Capability Attack Graph with no enforcement authority."""

    format: Literal["agentsec-capability-attack-graph"] = (
        "agentsec-capability-attack-graph"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    manifest_schema_version: ManifestBindingVersion
    manifest_sha256: Sha256Digest
    nodes: Annotated[
        tuple[AttackGraphNode, ...], Field(max_length=ATTACK_GRAPH_MAX_NODES)
    ] = ()
    edges: Annotated[
        tuple[AttackGraphEdge, ...], Field(max_length=ATTACK_GRAPH_MAX_EDGES)
    ] = ()
    paths: Annotated[
        tuple[AttackGraphPath, ...], Field(max_length=ATTACK_GRAPH_MAX_PATHS)
    ] = ()
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    finding_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def graph_must_be_coherent(self) -> CapabilityAttackGraph:
        node_ids = tuple(node.node_id for node in self.nodes)
        if node_ids != tuple(sorted(set(node_ids))):
            raise ValueError("attack graph nodes must be sorted by ID and unique")
        edge_ids = tuple(edge.edge_id for edge in self.edges)
        if edge_ids != tuple(sorted(set(edge_ids))):
            raise ValueError("attack graph edges must be sorted by ID and unique")
        path_ids = tuple(path.path_id for path in self.paths)
        if path_ids != tuple(sorted(set(path_ids))):
            raise ValueError("attack graph paths must be sorted by ID and unique")
        node_kinds = {node.node_id: node.node_kind for node in self.nodes}
        for edge in self.edges:
            if (
                edge.source_node_id not in node_kinds
                or edge.target_node_id not in node_kinds
            ):
                raise ValueError("attack graph edge endpoint is missing from the graph")
            allowed_source_kinds, allowed_target_kinds = _EDGE_ENDPOINT_KINDS[
                edge.edge_kind
            ]
            if (
                node_kinds[edge.source_node_id] not in allowed_source_kinds
                or node_kinds[edge.target_node_id] not in allowed_target_kinds
            ):
                raise ValueError(
                    "attack graph edge endpoints do not match the edge kind"
                )
        edge_by_id = {edge.edge_id: edge for edge in self.edges}
        for path in self.paths:
            if not set(path.node_sequence) <= set(node_kinds):
                raise ValueError("attack graph path references a missing node")
            if not set(path.edge_sequence) <= set(edge_by_id):
                raise ValueError("attack graph path references a missing edge")
            for index, edge_id in enumerate(path.edge_sequence):
                edge = edge_by_id[edge_id]
                if (
                    edge.source_node_id != path.node_sequence[index]
                    or edge.target_node_id != path.node_sequence[index + 1]
                ):
                    raise ValueError(
                        "attack graph path edges must connect consecutive path nodes"
                    )
        return self


def attack_node_id(
    *,
    node_kind: AttackGraphNodeKind,
    label: str | None,
    node_provenance: AttackGraphNodeProvenance,
    manifest_refs: tuple[str, ...],
    sources: tuple[AttackGraphSourceRef, ...],
) -> str:
    """Compute a trusted node identity from canonical value-free content."""

    payload = {
        "node_kind": node_kind.value,
        "label": label,
        "node_provenance": node_provenance.value,
        "manifest_refs": list(sorted(set(manifest_refs))),
        "sources": [
            source.model_dump(mode="json")
            for source in sorted(sources, key=lambda item: item.sort_key())
        ],
    }
    return f"attack-node-sha256:{_canonical_hash(payload)}"


def attack_edge_id(
    *,
    edge_kind: AttackGraphEdgeKind,
    source_node_id: str,
    target_node_id: str,
    sources: tuple[AttackGraphSourceRef, ...] = (),
) -> str:
    """Compute a trusted edge identity from canonical value-free content."""

    payload = {
        "edge_kind": edge_kind.value,
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "sources": [
            source.model_dump(mode="json")
            for source in sorted(sources, key=lambda item: item.sort_key())
        ],
    }
    return f"attack-edge-sha256:{_canonical_hash(payload)}"


def attack_path_id(
    *,
    pattern_id: str,
    node_sequence: tuple[str, ...],
    edge_sequence: tuple[str, ...],
) -> str:
    """Compute a trusted path identity from the canonical path chain."""

    payload = {
        "pattern_id": pattern_id,
        "node_sequence": list(node_sequence),
        "edge_sequence": list(edge_sequence),
    }
    return f"attack-path-sha256:{_canonical_hash(payload)}"


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ATTACK_GRAPH_FORMAT",
    "ATTACK_GRAPH_MAX_EDGES",
    "ATTACK_GRAPH_MAX_LABEL_CHARACTERS",
    "ATTACK_GRAPH_MAX_MANIFEST_REFS",
    "ATTACK_GRAPH_MAX_NODES",
    "ATTACK_GRAPH_MAX_PATHS",
    "ATTACK_GRAPH_MAX_PATH_NODES",
    "ATTACK_GRAPH_MAX_SOURCE_REFS",
    "ATTACK_GRAPH_SCHEMA_VERSION",
    "AttackGraphEdge",
    "AttackGraphEdgeKind",
    "AttackGraphNode",
    "AttackGraphNodeKind",
    "AttackGraphNodeProvenance",
    "AttackGraphPath",
    "AttackGraphSourceRef",
    "CapabilityAttackGraph",
    "ManifestBindingVersion",
    "attack_edge_id",
    "attack_node_id",
    "attack_path_id",
]

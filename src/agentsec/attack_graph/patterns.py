"""P3-AG-03 finite Attack Path pattern vocabulary for static path matching."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.attack_graph.models import (
    AttackGraphEdgeKind,
    AttackGraphNodeKind,
    AttackPatternIdentifier,
)

ATTACK_PATH_PATTERN_LIBRARY_VERSION = "0.1.0"
ATTACK_PATH_MAX_MATCHES_PER_PATTERN = 64

NodeKindSequence = Annotated[
    tuple[AttackGraphNodeKind, ...], Field(min_length=1, max_length=16)
]
EdgeKindSequence = Annotated[
    tuple[AttackGraphEdgeKind, ...], Field(min_length=1, max_length=16)
]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackPathStepSpec(_Strict):
    """One hop in a static Attack Path pattern: allowed next nodes and edges."""

    node_kinds: NodeKindSequence
    edge_kinds: EdgeKindSequence

    @model_validator(mode="after")
    def step_kinds_must_be_sorted_unique(self) -> AttackPathStepSpec:
        if self.node_kinds != tuple(
            sorted(set(self.node_kinds), key=lambda kind: kind.value)
        ):
            raise ValueError("pattern step node kinds must be sorted and unique")
        if self.edge_kinds != tuple(
            sorted(set(self.edge_kinds), key=lambda kind: kind.value)
        ):
            raise ValueError("pattern step edge kinds must be sorted and unique")
        return self


class AttackPathPatternSpec(_Strict):
    """One reviewed deterministic static Attack Path pattern."""

    pattern_id: AttackPatternIdentifier
    start_node_kinds: NodeKindSequence
    steps: Annotated[tuple[AttackPathStepSpec, ...], Field(min_length=1, max_length=8)]
    precondition_edge_kinds: EdgeKindSequence = ()

    @model_validator(mode="after")
    def pattern_must_be_coherent(self) -> AttackPathPatternSpec:
        if self.start_node_kinds != tuple(
            sorted(set(self.start_node_kinds), key=lambda kind: kind.value)
        ):
            raise ValueError("pattern start node kinds must be sorted and unique")
        if self.precondition_edge_kinds != tuple(
            sorted(set(self.precondition_edge_kinds), key=lambda kind: kind.value)
        ):
            raise ValueError(
                "pattern precondition edge kinds must be sorted and unique"
            )
        return self


def _node_kinds(*values: AttackGraphNodeKind) -> tuple[AttackGraphNodeKind, ...]:
    return tuple(sorted(set(values), key=lambda kind: kind.value))


def _edge_kinds(*values: AttackGraphEdgeKind) -> tuple[AttackGraphEdgeKind, ...]:
    return tuple(sorted(set(values), key=lambda kind: kind.value))


def _step(
    node_kinds: tuple[AttackGraphNodeKind, ...],
    edge_kinds: tuple[AttackGraphEdgeKind, ...],
) -> AttackPathStepSpec:
    return AttackPathStepSpec(node_kinds=node_kinds, edge_kinds=edge_kinds)


_TOOL_FAMILY_NODES = _node_kinds(
    AttackGraphNodeKind.TOOL,
    AttackGraphNodeKind.SKILL,
    AttackGraphNodeKind.MCP_SERVER,
)
_TOOL_FAMILY_USES_EDGES = _edge_kinds(
    AttackGraphEdgeKind.USES_TOOL,
    AttackGraphEdgeKind.USES_SKILL,
    AttackGraphEdgeKind.USES_MCP,
)

SECRET_EXFILTRATION_PATTERN = AttackPathPatternSpec(
    pattern_id="secret-exfiltration",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.AGENT),
    steps=(
        _step(_TOOL_FAMILY_NODES, _TOOL_FAMILY_USES_EDGES),
        _step(
            _node_kinds(AttackGraphNodeKind.NETWORK),
            _edge_kinds(AttackGraphEdgeKind.SENDS_TO),
        ),
    ),
    precondition_edge_kinds=_edge_kinds(AttackGraphEdgeKind.READS_SECRET),
)

INJECTION_TOOL_EXECUTION_PATTERN = AttackPathPatternSpec(
    pattern_id="injection-tool-execution",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.UNTRUSTED_INPUT),
    steps=(
        _step(
            _node_kinds(AttackGraphNodeKind.AGENT),
            _edge_kinds(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION),
        ),
        _step(_TOOL_FAMILY_NODES, _TOOL_FAMILY_USES_EDGES),
    ),
)

MEMORY_POISONING_PATTERN = AttackPathPatternSpec(
    pattern_id="memory-poisoning",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.UNTRUSTED_INPUT),
    steps=(
        _step(
            _node_kinds(AttackGraphNodeKind.AGENT),
            _edge_kinds(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION),
        ),
        _step(
            _node_kinds(AttackGraphNodeKind.MEMORY),
            _edge_kinds(AttackGraphEdgeKind.WRITES_MEMORY),
        ),
    ),
)

DELEGATION_ESCALATION_PATTERN = AttackPathPatternSpec(
    pattern_id="delegation-escalation",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.AGENT),
    steps=(
        _step(
            _node_kinds(AttackGraphNodeKind.AGENT),
            _edge_kinds(AttackGraphEdgeKind.DELEGATES_TO),
        ),
    ),
)

MCP_EXTERNAL_EGRESS_PATTERN = AttackPathPatternSpec(
    pattern_id="mcp-external-egress",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.AGENT),
    steps=(
        _step(
            _node_kinds(AttackGraphNodeKind.MCP_SERVER),
            _edge_kinds(AttackGraphEdgeKind.USES_MCP),
        ),
        _step(
            _node_kinds(AttackGraphNodeKind.TOOL),
            _edge_kinds(AttackGraphEdgeKind.PROVIDES_TOOL),
        ),
        _step(
            _node_kinds(AttackGraphNodeKind.NETWORK),
            _edge_kinds(AttackGraphEdgeKind.SENDS_TO),
        ),
    ),
)

MCP_PRODUCTION_WRITE_PATTERN = AttackPathPatternSpec(
    pattern_id="mcp-production-write",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.AGENT),
    steps=(
        _step(
            _node_kinds(AttackGraphNodeKind.MCP_SERVER),
            _edge_kinds(AttackGraphEdgeKind.USES_MCP),
        ),
        _step(
            _node_kinds(AttackGraphNodeKind.TOOL),
            _edge_kinds(AttackGraphEdgeKind.PROVIDES_TOOL),
        ),
        _step(
            _node_kinds(AttackGraphNodeKind.PRODUCTION_TARGET),
            _edge_kinds(AttackGraphEdgeKind.WRITES_TO),
        ),
    ),
)

TOOL_DEPENDENCY_INSTALL_PATTERN = AttackPathPatternSpec(
    pattern_id="tool-dependency-install",
    start_node_kinds=_node_kinds(AttackGraphNodeKind.AGENT),
    steps=(
        _step(_TOOL_FAMILY_NODES, _TOOL_FAMILY_USES_EDGES),
        _step(
            _node_kinds(AttackGraphNodeKind.DEPENDENCY),
            _edge_kinds(AttackGraphEdgeKind.INSTALLS),
        ),
    ),
)

BUILTIN_ATTACK_PATH_PATTERNS: tuple[AttackPathPatternSpec, ...] = (
    DELEGATION_ESCALATION_PATTERN,
    INJECTION_TOOL_EXECUTION_PATTERN,
    MCP_EXTERNAL_EGRESS_PATTERN,
    MCP_PRODUCTION_WRITE_PATTERN,
    MEMORY_POISONING_PATTERN,
    SECRET_EXFILTRATION_PATTERN,
    TOOL_DEPENDENCY_INSTALL_PATTERN,
)


class AttackPatternLibraryError(ValueError):
    """Safe pattern-library validation failure without untrusted content."""


def validate_pattern_library(
    patterns: tuple[AttackPathPatternSpec, ...],
) -> tuple[AttackPathPatternSpec, ...]:
    """Return a library with unique, pattern_id-sorted, immutable patterns."""

    if not isinstance(patterns, tuple):
        raise TypeError("attack path pattern library must be a tuple")
    for pattern in patterns:
        if not isinstance(pattern, AttackPathPatternSpec):
            raise TypeError("attack path pattern library entries must be specs")
    ids = tuple(pattern.pattern_id for pattern in patterns)
    if ids != tuple(sorted(set(ids))):
        raise AttackPatternLibraryError(
            "attack path pattern IDs must be sorted and unique"
        )
    return patterns


__all__ = [
    "ATTACK_PATH_MAX_MATCHES_PER_PATTERN",
    "ATTACK_PATH_PATTERN_LIBRARY_VERSION",
    "BUILTIN_ATTACK_PATH_PATTERNS",
    "AttackPathPatternSpec",
    "AttackPathStepSpec",
    "AttackPatternLibraryError",
    "DELEGATION_ESCALATION_PATTERN",
    "INJECTION_TOOL_EXECUTION_PATTERN",
    "MCP_EXTERNAL_EGRESS_PATTERN",
    "MCP_PRODUCTION_WRITE_PATTERN",
    "MEMORY_POISONING_PATTERN",
    "SECRET_EXFILTRATION_PATTERN",
    "TOOL_DEPENDENCY_INSTALL_PATTERN",
    "validate_pattern_library",
]

"""P3-AG-03 deterministic static Attack Path matcher over the capability graph."""

from __future__ import annotations

from agentsec.attack_graph.models import (
    ATTACK_GRAPH_MAX_PATHS,
    AttackGraphEdge,
    AttackGraphNodeKind,
    AttackGraphPath,
    CapabilityAttackGraph,
    attack_path_id,
)
from agentsec.attack_graph.patterns import (
    ATTACK_PATH_MAX_MATCHES_PER_PATTERN,
    BUILTIN_ATTACK_PATH_PATTERNS,
    AttackPathPatternSpec,
    validate_pattern_library,
)


class AttackPathMatchError(ValueError):
    """Safe Attack Path matching failure without untrusted content."""


class AttackPathMatcher:
    """Match deterministic static Attack Path patterns against one graph.

    The matcher walks declared edges only. It never opens project files,
    never verifies runtime reachability, and every emitted path stays
    ``static_declared_path`` with ``runtime_verified=false``,
    ``reachability=not_proven``, and ``exploitability=not_proven``. Matching
    order is fixed by pattern ID, then start node ID, then edge ID, so the
    same graph always yields the same path set in the same order.
    """

    def __init__(
        self,
        *,
        patterns: tuple[AttackPathPatternSpec, ...] = BUILTIN_ATTACK_PATH_PATTERNS,
    ) -> None:
        self._patterns = validate_pattern_library(patterns)

    @property
    def patterns(self) -> tuple[AttackPathPatternSpec, ...]:
        return self._patterns

    def match(self, graph: CapabilityAttackGraph) -> tuple[AttackGraphPath, ...]:
        """Return every matching static declared path, sorted by path ID."""

        if not isinstance(graph, CapabilityAttackGraph):
            raise TypeError("attack path matcher requires CapabilityAttackGraph")

        adjacency: dict[str, tuple[AttackGraphEdge, ...]] = {}
        for edge in graph.edges:
            adjacency.setdefault(edge.source_node_id, ())
            adjacency[edge.source_node_id] = (*adjacency[edge.source_node_id], edge)
        for source_node_id in adjacency:
            adjacency[source_node_id] = tuple(
                sorted(
                    adjacency[source_node_id],
                    key=lambda edge: edge.edge_id,
                )
            )
        node_kinds: dict[str, AttackGraphNodeKind] = {
            node.node_id: node.node_kind for node in graph.nodes
        }

        matches: list[AttackGraphPath] = []
        per_pattern: dict[str, int] = {}
        for pattern in self._patterns:
            for node in graph.nodes:
                if node.node_kind not in pattern.start_node_kinds:
                    continue
                start_out_kinds = {
                    edge.edge_kind for edge in adjacency.get(node.node_id, ())
                }
                if not set(pattern.precondition_edge_kinds) <= start_out_kinds:
                    continue
                self._walk(
                    pattern=pattern,
                    adjacency=adjacency,
                    node_kinds=node_kinds,
                    current_node_id=node.node_id,
                    step_index=0,
                    visited={node.node_id},
                    node_sequence=[node.node_id],
                    edge_sequence=[],
                    matches=matches,
                    per_pattern=per_pattern,
                )
        if len(matches) > ATTACK_GRAPH_MAX_PATHS:
            raise AttackPathMatchError(
                "attack path matches exceed the graph path bound"
            )
        return tuple(sorted(matches, key=lambda path: path.path_id))

    def match_into_graph(self, graph: CapabilityAttackGraph) -> CapabilityAttackGraph:
        """Return a new report-only graph with matched paths attached."""

        paths = self.match(graph)
        return CapabilityAttackGraph(
            manifest_schema_version=graph.manifest_schema_version,
            manifest_sha256=graph.manifest_sha256,
            nodes=graph.nodes,
            edges=graph.edges,
            paths=paths,
        )

    def _walk(
        self,
        *,
        pattern: AttackPathPatternSpec,
        adjacency: dict[str, tuple[AttackGraphEdge, ...]],
        node_kinds: dict[str, AttackGraphNodeKind],
        current_node_id: str,
        step_index: int,
        visited: set[str],
        node_sequence: list[str],
        edge_sequence: list[str],
        matches: list[AttackGraphPath],
        per_pattern: dict[str, int],
    ) -> None:
        if step_index == len(pattern.steps):
            match_count = per_pattern.get(pattern.pattern_id, 0)
            if match_count >= ATTACK_PATH_MAX_MATCHES_PER_PATTERN:
                raise AttackPathMatchError(
                    "attack path matches exceed the per-pattern bound"
                )
            per_pattern[pattern.pattern_id] = match_count + 1
            matches.append(
                AttackGraphPath(
                    path_id=attack_path_id(
                        pattern_id=pattern.pattern_id,
                        node_sequence=tuple(node_sequence),
                        edge_sequence=tuple(edge_sequence),
                    ),
                    pattern_id=pattern.pattern_id,
                    node_sequence=tuple(node_sequence),
                    edge_sequence=tuple(edge_sequence),
                )
            )
            return
        step = pattern.steps[step_index]
        for edge in adjacency.get(current_node_id, ()):
            if edge.edge_kind not in step.edge_kinds:
                continue
            target_node_id = edge.target_node_id
            if target_node_id in visited:
                continue
            if node_kinds.get(target_node_id) not in step.node_kinds:
                continue
            visited.add(target_node_id)
            node_sequence.append(target_node_id)
            edge_sequence.append(edge.edge_id)
            self._walk(
                pattern=pattern,
                adjacency=adjacency,
                node_kinds=node_kinds,
                current_node_id=target_node_id,
                step_index=step_index + 1,
                visited=visited,
                node_sequence=node_sequence,
                edge_sequence=edge_sequence,
                matches=matches,
                per_pattern=per_pattern,
            )
            node_sequence.pop()
            edge_sequence.pop()
            visited.remove(target_node_id)


__all__ = [
    "AttackPathMatchError",
    "AttackPathMatcher",
]

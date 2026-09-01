"""P3-AG-03 Attack Path pattern library and matcher tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.attack_graph import (
    ATTACK_PATH_MAX_MATCHES_PER_PATTERN,
    ATTACK_PATH_PATTERN_LIBRARY_VERSION,
    BUILTIN_ATTACK_PATH_PATTERNS,
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackGraphPath,
    AttackPathMatcher,
    AttackPathPatternSpec,
    AttackPathStepSpec,
    AttackPatternLibraryError,
    CapabilityAttackGraph,
    ManifestCapabilityGraphBuilder,
    attack_edge_id,
    attack_node_id,
    attack_path_id,
    encode_attack_graph_json,
    validate_pattern_library,
)
from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import (
    AgentManifestBuilder,
    AssociationExtractor,
    CapabilityExtractor,
    RelationshipExtractor,
)


def _node(
    kind: AttackGraphNodeKind,
    ref: str,
    *,
    provenance: AttackGraphNodeProvenance = AttackGraphNodeProvenance.MANIFEST_DECLARED,
) -> AttackGraphNode:
    refs = (ref,)
    sources = ()
    return AttackGraphNode(
        node_id=attack_node_id(
            node_kind=kind,
            label=None,
            node_provenance=provenance,
            manifest_refs=refs,
            sources=sources,
        ),
        node_kind=kind,
        node_provenance=provenance,
        label=None,
        manifest_refs=refs,
        sources=sources,
    )


def _inferred_node(
    kind: AttackGraphNodeKind, label: str | None = None
) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=attack_node_id(
            node_kind=kind,
            label=label,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
            manifest_refs=(),
            sources=(),
        ),
        node_kind=kind,
        node_provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
        label=label,
        manifest_refs=(),
        sources=(),
    )


def _edge(
    kind: AttackGraphEdgeKind, source: AttackGraphNode, target: AttackGraphNode
) -> AttackGraphEdge:
    return AttackGraphEdge(
        edge_id=attack_edge_id(
            edge_kind=kind,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            sources=(),
        ),
        edge_kind=kind,
        source_node_id=source.node_id,
        target_node_id=target.node_id,
        sources=(),
    )


def _graph(
    nodes: tuple[AttackGraphNode, ...],
    edges: tuple[AttackGraphEdge, ...],
) -> CapabilityAttackGraph:
    return CapabilityAttackGraph(
        manifest_schema_version="0.3.0",
        manifest_sha256="f" * 64,
        nodes=tuple(sorted(nodes, key=lambda node: node.node_id)),
        edges=tuple(sorted(edges, key=lambda edge: edge.edge_id)),
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _real_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
delegates_to: [research]
memory:
  read: session
  write: scratch
  persist: long_term
---
# Agent
""".lstrip(),
    )
    _write(project / "AGENTS.override.md", "# Override\n\nNew priorities.\n")
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.docs]
command = "docs-server"
enabled = true
enabled_tools = ["search"]
bearer_token_env_var = "DOCS_TOKEN"

[mcp_servers.remote]
url = "https://api.example.invalid/mcp"
""".lstrip(),
    )
    return project


def _real_graph(tmp_path: Path) -> CapabilityAttackGraph:
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=_real_project(tmp_path))
    )
    manifest = AgentManifestBuilder().build(inspection)
    manifest = AssociationExtractor().extract(manifest, inspection)
    manifest = CapabilityExtractor().extract(manifest, inspection)
    manifest = RelationshipExtractor().extract(manifest, inspection)
    return ManifestCapabilityGraphBuilder().build(manifest)


def test_builtin_library_is_sorted_unique_and_versioned() -> None:
    patterns = BUILTIN_ATTACK_PATH_PATTERNS

    assert ATTACK_PATH_PATTERN_LIBRARY_VERSION == "0.1.0"
    assert len(patterns) == 7
    ids = [pattern.pattern_id for pattern in patterns]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert validate_pattern_library(patterns) is patterns
    assert all(isinstance(pattern, AttackPathPatternSpec) for pattern in patterns)
    assert {
        "secret-exfiltration",
        "injection-tool-execution",
        "memory-poisoning",
        "delegation-escalation",
        "mcp-external-egress",
        "mcp-production-write",
        "tool-dependency-install",
    } == set(ids)
    secret = next(
        pattern for pattern in patterns if pattern.pattern_id == "secret-exfiltration"
    )
    assert secret.precondition_edge_kinds == (AttackGraphEdgeKind.READS_SECRET,)


def test_pattern_spec_rejects_invalid_shapes() -> None:
    with pytest.raises(ValidationError):
        AttackPathPatternSpec(
            pattern_id="bad pattern",
            start_node_kinds=(AttackGraphNodeKind.AGENT,),
            steps=(
                AttackPathStepSpec(
                    node_kinds=(AttackGraphNodeKind.TOOL,),
                    edge_kinds=(AttackGraphEdgeKind.USES_TOOL,),
                ),
            ),
        )
    with pytest.raises(ValidationError):
        AttackPathPatternSpec(
            pattern_id="ok-id",
            start_node_kinds=(),
            steps=(
                AttackPathStepSpec(
                    node_kinds=(AttackGraphNodeKind.TOOL,),
                    edge_kinds=(AttackGraphEdgeKind.USES_TOOL,),
                ),
            ),
        )
    with pytest.raises(ValidationError):
        AttackPathPatternSpec(
            pattern_id="ok-id",
            start_node_kinds=(AttackGraphNodeKind.AGENT,),
            steps=(),
        )
    with pytest.raises(ValidationError):
        AttackPathStepSpec(
            node_kinds=(
                AttackGraphNodeKind.TOOL,
                AttackGraphNodeKind.AGENT,
            ),
            edge_kinds=(AttackGraphEdgeKind.USES_TOOL,),
        )
    with pytest.raises(ValidationError):
        AttackPathStepSpec(
            node_kinds=(AttackGraphNodeKind.TOOL,),
            edge_kinds=(
                AttackGraphEdgeKind.USES_TOOL,
                AttackGraphEdgeKind.USES_SKILL,
            ),
        )


def test_validate_pattern_library_rejects_wrong_input() -> None:
    with pytest.raises(TypeError, match="must be a tuple"):
        validate_pattern_library([BUILTIN_ATTACK_PATH_PATTERNS[0]])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be specs"):
        validate_pattern_library(("not-a-spec",))  # type: ignore[arg-type]
    duplicate = (
        BUILTIN_ATTACK_PATH_PATTERNS[0],
        BUILTIN_ATTACK_PATH_PATTERNS[1],
        BUILTIN_ATTACK_PATH_PATTERNS[0],
    )
    with pytest.raises(AttackPatternLibraryError, match="sorted and unique"):
        validate_pattern_library(duplicate)


def test_matcher_rejects_wrong_input_types() -> None:
    matcher = AttackPathMatcher()
    with pytest.raises(TypeError, match="requires CapabilityAttackGraph"):
        matcher.match("not-a-graph")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a tuple"):
        AttackPathMatcher(patterns=[BUILTIN_ATTACK_PATH_PATTERNS[0]])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be specs"):
        AttackPathMatcher(patterns=("bad",))  # type: ignore[arg-type,arg-type]


def test_secret_exfiltration_requires_secret_precondition() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    secret = _node(AttackGraphNodeKind.SECRET, "secret:token")
    tool = _node(AttackGraphNodeKind.TOOL, "tool:shell")
    network = _node(AttackGraphNodeKind.NETWORK, "sink:network")
    graph = _graph(
        (agent, secret, tool, network),
        (
            _edge(
                AttackGraphEdgeKind.READS_SECRET,
                agent,
                secret,
            ),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool),
            _edge(AttackGraphEdgeKind.SENDS_TO, agent, network),
        ),
    )
    paths = AttackPathMatcher().match(graph)
    assert paths == ()

    graph_with_egress = _graph(
        (agent, secret, tool, network),
        (
            _edge(AttackGraphEdgeKind.READS_SECRET, agent, secret),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool),
            _edge(AttackGraphEdgeKind.SENDS_TO, tool, network),
            _edge(AttackGraphEdgeKind.SENDS_TO, agent, network),
        ),
    )
    paths = AttackPathMatcher().match(graph_with_egress)
    assert [path.pattern_id for path in paths] == ["secret-exfiltration"]
    (path,) = paths
    assert len(path.node_sequence) == 3
    assert len(path.edge_sequence) == 2


def test_injection_tool_execution_matches_untrusted_input_chain() -> None:
    injection = _inferred_node(AttackGraphNodeKind.UNTRUSTED_INPUT)
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    skill = _node(AttackGraphNodeKind.SKILL, "skill:review")
    memory = _node(AttackGraphNodeKind.MEMORY, "memory:scratch")
    graph = _graph(
        (injection, agent, skill),
        (
            _edge(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION, injection, agent),
            _edge(AttackGraphEdgeKind.USES_SKILL, agent, skill),
        ),
    )
    paths = AttackPathMatcher().match(graph)
    assert [path.pattern_id for path in paths] == ["injection-tool-execution"]

    memory_graph = _graph(
        (injection, agent, memory),
        (
            _edge(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION, injection, agent),
            _edge(AttackGraphEdgeKind.WRITES_MEMORY, agent, memory),
        ),
    )
    paths = AttackPathMatcher().match(memory_graph)
    assert [path.pattern_id for path in paths] == ["memory-poisoning"]


def test_memory_poisoning_requires_write_edge() -> None:
    injection = _inferred_node(AttackGraphNodeKind.UNTRUSTED_INPUT)
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    memory = _node(AttackGraphNodeKind.MEMORY, "memory:session")
    graph = _graph(
        (injection, agent, memory),
        (
            _edge(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION, injection, agent),
            _edge(AttackGraphEdgeKind.READS_MEMORY, agent, memory),
        ),
    )
    assert AttackPathMatcher().match(graph) == ()


def test_delegation_escalation_matches_single_hop() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    child = _node(AttackGraphNodeKind.AGENT, "agent:research")
    tool = _node(AttackGraphNodeKind.TOOL, "tool:shell")
    graph = _graph(
        (agent, child, tool),
        (
            _edge(AttackGraphEdgeKind.DELEGATES_TO, agent, child),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool),
        ),
    )
    paths = AttackPathMatcher().match(graph)
    delegation = [path for path in paths if path.pattern_id == "delegation-escalation"]
    assert len(delegation) == 1
    assert len(delegation[0].node_sequence) == 2
    assert len(delegation[0].edge_sequence) == 1


def test_mcp_external_egress_and_vocabulary_patterns() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    mcp = _node(AttackGraphNodeKind.MCP_SERVER, "mcp-server:docs")
    tool = _node(AttackGraphNodeKind.TOOL, "mcp-tool:docs.search")
    network = _node(AttackGraphNodeKind.NETWORK, "sink:network")
    production = _node(AttackGraphNodeKind.PRODUCTION_TARGET, "target:prod")
    dependency = _node(AttackGraphNodeKind.DEPENDENCY, "dep:runtime")

    graph = _graph(
        (agent, mcp, tool, network, production, dependency),
        (
            _edge(AttackGraphEdgeKind.USES_MCP, agent, mcp),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool),
            _edge(AttackGraphEdgeKind.PROVIDES_TOOL, mcp, tool),
            _edge(AttackGraphEdgeKind.SENDS_TO, tool, network),
            _edge(AttackGraphEdgeKind.WRITES_TO, tool, production),
            _edge(AttackGraphEdgeKind.INSTALLS, tool, dependency),
        ),
    )
    paths = AttackPathMatcher().match(graph)
    by_pattern: dict[str, list[AttackGraphPath]] = {}
    for path in paths:
        by_pattern.setdefault(path.pattern_id, []).append(path)

    assert set(by_pattern) == {
        "mcp-external-egress",
        "mcp-production-write",
        "tool-dependency-install",
    }
    assert len(by_pattern["mcp-external-egress"]) == 1
    assert len(by_pattern["mcp-production-write"]) == 1
    assert len(by_pattern["tool-dependency-install"]) == 1
    for pattern_id, expected_nodes, expected_edges in (
        ("mcp-external-egress", 4, 3),
        ("mcp-production-write", 4, 3),
        ("tool-dependency-install", 3, 2),
    ):
        (path,) = by_pattern[pattern_id]
        assert len(path.node_sequence) == expected_nodes
        assert len(path.edge_sequence) == expected_edges


def test_match_is_deterministic_and_sorted_by_path_id() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    secret = _node(AttackGraphNodeKind.SECRET, "secret:token")
    tool_a = _node(AttackGraphNodeKind.TOOL, "tool:shell")
    tool_b = _node(AttackGraphNodeKind.TOOL, "tool:python")
    network = _node(AttackGraphNodeKind.NETWORK, "sink:network")
    graph = _graph(
        (agent, secret, tool_a, tool_b, network),
        (
            _edge(AttackGraphEdgeKind.READS_SECRET, agent, secret),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool_a),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool_b),
            _edge(AttackGraphEdgeKind.SENDS_TO, tool_a, network),
            _edge(AttackGraphEdgeKind.SENDS_TO, tool_b, network),
        ),
    )
    matcher = AttackPathMatcher()
    first = matcher.match(graph)
    second = matcher.match(graph)

    assert first == second
    assert first == tuple(sorted(first, key=lambda path: path.path_id))
    assert len({path.path_id for path in first}) == len(first)
    assert [path.pattern_id for path in first].count("secret-exfiltration") == 2
    for path in first:
        recomputed = attack_path_id(
            pattern_id=path.pattern_id,
            node_sequence=path.node_sequence,
            edge_sequence=path.edge_sequence,
        )
        assert path.path_id == recomputed


def test_paths_carry_fixed_unverified_markers() -> None:
    injection = _inferred_node(AttackGraphNodeKind.UNTRUSTED_INPUT)
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    memory = _node(AttackGraphNodeKind.MEMORY, "memory:scratch")
    graph = _graph(
        (injection, agent, memory),
        (
            _edge(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION, injection, agent),
            _edge(AttackGraphEdgeKind.WRITES_MEMORY, agent, memory),
        ),
    )
    (path,) = AttackPathMatcher().match(graph)

    assert path.path_kind == "static_declared_path"
    assert path.runtime_verified is False
    assert path.reachability == "not_proven"
    assert path.exploitability == "not_proven"


def test_per_pattern_bound_fails_closed() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    nodes: list[AttackGraphNode] = [agent]
    edges: list[AttackGraphEdge] = []
    for index in range(ATTACK_PATH_MAX_MATCHES_PER_PATTERN + 1):
        child = _node(AttackGraphNodeKind.AGENT, f"agent:child-{index:03d}")
        nodes.append(child)
        edges.append(_edge(AttackGraphEdgeKind.DELEGATES_TO, agent, child))
    graph = _graph(tuple(nodes), tuple(edges))

    with pytest.raises(Exception, match="per-pattern bound"):
        AttackPathMatcher().match(graph)


def test_graph_level_path_bound_fails_closed() -> None:
    combinations: tuple[
        tuple[AttackGraphNodeKind, AttackGraphNodeKind, AttackGraphEdgeKind], ...
    ] = (
        (
            AttackGraphNodeKind.TOOL,
            AttackGraphNodeKind.DATA,
            AttackGraphEdgeKind.WRITES_TO,
        ),
        (
            AttackGraphNodeKind.AGENT,
            AttackGraphNodeKind.MEMORY,
            AttackGraphEdgeKind.WRITES_MEMORY,
        ),
        (
            AttackGraphNodeKind.AGENT,
            AttackGraphNodeKind.SECRET,
            AttackGraphEdgeKind.READS_SECRET,
        ),
        (
            AttackGraphNodeKind.AGENT,
            AttackGraphNodeKind.NETWORK,
            AttackGraphEdgeKind.SENDS_TO,
        ),
        (
            AttackGraphNodeKind.TOOL,
            AttackGraphNodeKind.DEPENDENCY,
            AttackGraphEdgeKind.INSTALLS,
        ),
    )
    patterns = tuple(
        sorted(
            (
                AttackPathPatternSpec(
                    pattern_id=f"bulk-{edge_kind.value.replace('_', '-')}",
                    start_node_kinds=(source_kind,),
                    steps=(
                        AttackPathStepSpec(
                            node_kinds=(target_kind,),
                            edge_kinds=(edge_kind,),
                        ),
                    ),
                )
                for source_kind, target_kind, edge_kind in combinations
            ),
            key=lambda pattern: pattern.pattern_id,
        )
    )
    nodes: list[AttackGraphNode] = []
    edges: list[AttackGraphEdge] = []
    for source_kind, target_kind, edge_kind in combinations:
        for index in range(60):
            source = _node(source_kind, f"source:{edge_kind.value}-{index:03d}")
            target = _node(target_kind, f"target:{edge_kind.value}-{index:03d}")
            nodes.extend((source, target))
            edges.append(_edge(edge_kind, source, target))
    graph = _graph(tuple(nodes), tuple(edges))

    with pytest.raises(Exception, match="graph path bound"):
        AttackPathMatcher(patterns=patterns).match(graph)


def test_match_into_graph_round_trips_and_keeps_authority() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    secret = _node(AttackGraphNodeKind.SECRET, "secret:token")
    tool = _node(AttackGraphNodeKind.TOOL, "tool:shell")
    network = _node(AttackGraphNodeKind.NETWORK, "sink:network")
    graph = _graph(
        (agent, secret, tool, network),
        (
            _edge(AttackGraphEdgeKind.READS_SECRET, agent, secret),
            _edge(AttackGraphEdgeKind.USES_TOOL, agent, tool),
            _edge(AttackGraphEdgeKind.SENDS_TO, tool, network),
        ),
    )

    result = AttackPathMatcher().match_into_graph(graph)

    assert result.manifest_schema_version == graph.manifest_schema_version
    assert result.manifest_sha256 == graph.manifest_sha256
    assert result.nodes == graph.nodes
    assert result.edges == graph.edges
    assert len(result.paths) == 1
    assert result.report_only is True
    assert result.blocks is False
    assert result.finding_authority is False
    assert result.policy_authority is False
    assert result.ci_authority is False
    assert result.runtime_verified is False

    encoded = encode_attack_graph_json(result)
    restored = CapabilityAttackGraph.model_validate(json.loads(encoded))
    assert restored == result
    assert isinstance(restored, CapabilityAttackGraph)


def test_real_pipeline_produces_expected_paths(tmp_path: Path) -> None:
    graph = _real_graph(tmp_path)
    runner = AttackPathMatcher()

    first = runner.match(graph)
    second = runner.match(graph)

    assert first == second
    counts: dict[str, int] = {}
    for path in first:
        counts[path.pattern_id] = counts.get(path.pattern_id, 0) + 1
    assert counts == {
        "secret-exfiltration": 1,
        "injection-tool-execution": 4,
        "memory-poisoning": 2,
        "delegation-escalation": 1,
    }

    result = runner.match_into_graph(graph)
    assert result.paths == first
    encoded = encode_attack_graph_json(result)
    for excerpt in ("docs-server", "api.example.invalid", "DOCS_TOKEN"):
        assert excerpt not in encoded
    assert CapabilityAttackGraph.model_validate(json.loads(encoded)) == result

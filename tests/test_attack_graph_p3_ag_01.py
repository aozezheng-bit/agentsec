"""P3-AG-01 Capability Attack Graph Node/Edge/Graph/Path schema tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentsec.attack_graph import (
    ATTACK_GRAPH_FORMAT,
    ATTACK_GRAPH_SCHEMA_VERSION,
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackGraphPath,
    AttackGraphSourceRef,
    CapabilityAttackGraph,
    attack_edge_id,
    attack_node_id,
    attack_path_id,
    encode_attack_graph_json,
    render_attack_graph_text,
)
from agentsec.attack_graph.schema import export_attack_graph_json_schema

_MISSING_NODE_ID = "attack-node-sha256:" + "b" * 64


def _source(
    asset: str = "AGENTS.md", *, start: int = 1, end: int = 2
) -> AttackGraphSourceRef:
    return AttackGraphSourceRef(
        asset_path=asset,
        asset_sha256="a" * 64,
        start_line=start,
        end_line=end,
    )


def _node(
    kind: AttackGraphNodeKind,
    label: str | None = None,
    *,
    provenance: AttackGraphNodeProvenance = AttackGraphNodeProvenance.SYNTHETIC,
    refs: tuple[str, ...] = (),
    sources: tuple[AttackGraphSourceRef, ...] = (),
) -> AttackGraphNode:
    node_id = attack_node_id(
        node_kind=kind,
        label=label,
        node_provenance=provenance,
        manifest_refs=refs,
        sources=sources,
    )
    return AttackGraphNode(
        node_id=node_id,
        node_kind=kind,
        node_provenance=provenance,
        label=label,
        manifest_refs=refs,
        sources=sources,
    )


def _edge(
    kind: AttackGraphEdgeKind,
    source: str,
    target: str,
    sources: tuple[AttackGraphSourceRef, ...] = (),
) -> AttackGraphEdge:
    edge_id = attack_edge_id(
        edge_kind=kind,
        source_node_id=source,
        target_node_id=target,
        sources=sources,
    )
    return AttackGraphEdge(
        edge_id=edge_id,
        edge_kind=kind,
        source_node_id=source,
        target_node_id=target,
        sources=sources,
    )


def _path(
    pattern_id: str,
    node_sequence: tuple[str, ...],
    edge_sequence: tuple[str, ...],
) -> AttackGraphPath:
    path_id = attack_path_id(
        pattern_id=pattern_id,
        node_sequence=node_sequence,
        edge_sequence=edge_sequence,
    )
    return AttackGraphPath(
        path_id=path_id,
        pattern_id=pattern_id,
        node_sequence=node_sequence,
        edge_sequence=edge_sequence,
    )


def _graph(
    nodes: tuple[AttackGraphNode, ...] = (),
    edges: tuple[AttackGraphEdge, ...] = (),
    paths: tuple[AttackGraphPath, ...] = (),
) -> CapabilityAttackGraph:
    return CapabilityAttackGraph(
        manifest_schema_version="0.3.0",
        manifest_sha256="f" * 64,
        nodes=nodes,
        edges=edges,
        paths=paths,
    )


def _exfiltration_example() -> CapabilityAttackGraph:
    agent = _node(
        AttackGraphNodeKind.AGENT,
        "release-agent",
        provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        refs=("agent:release",),
        sources=(_source("AGENTS.md", start=1, end=2),),
    )
    secret = _node(
        AttackGraphNodeKind.SECRET,
        "deploy-token",
        provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        refs=("permission:read-credential",),
        sources=(_source("AGENTS.md", start=3, end=4),),
    )
    tool = _node(
        AttackGraphNodeKind.TOOL,
        "shell",
        provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        refs=("tool:shell",),
        sources=(_source("AGENTS.md", start=5, end=6),),
    )
    network = _node(
        AttackGraphNodeKind.NETWORK,
        provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
        sources=(_source("AGENTS.md", start=7, end=8),),
    )
    uses_tool = _edge(
        AttackGraphEdgeKind.USES_TOOL,
        agent.node_id,
        tool.node_id,
        sources=(_source("AGENTS.md", start=5, end=6),),
    )
    reads_secret = _edge(
        AttackGraphEdgeKind.READS_SECRET,
        agent.node_id,
        secret.node_id,
        sources=(_source("AGENTS.md", start=3, end=4),),
    )
    sends_to = _edge(
        AttackGraphEdgeKind.SENDS_TO,
        tool.node_id,
        network.node_id,
    )
    path = _path(
        "secret-exfiltration",
        (agent.node_id, tool.node_id, network.node_id),
        (uses_tool.edge_id, sends_to.edge_id),
    )
    return _graph(
        nodes=tuple(
            sorted((agent, tool, network, secret), key=lambda item: item.node_id)
        ),
        edges=tuple(
            sorted((uses_tool, reads_secret, sends_to), key=lambda item: item.edge_id)
        ),
        paths=(path,),
    )


def test_empty_graph_is_valid_report_only_and_unverified() -> None:
    graph = _graph()

    assert graph.format == ATTACK_GRAPH_FORMAT
    assert graph.schema_version == ATTACK_GRAPH_SCHEMA_VERSION
    assert graph.manifest_schema_version == "0.3.0"
    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.paths == ()
    assert graph.report_only is True
    assert graph.blocks is False
    assert graph.finding_authority is False
    assert graph.rule_publication_authority is False
    assert graph.policy_authority is False
    assert graph.ci_authority is False
    assert graph.hard_gate_authority is False
    assert graph.release_authority is False
    assert graph.runtime_verified is False


def test_secret_exfiltration_example_is_accepted() -> None:
    graph = _exfiltration_example()

    assert len(graph.nodes) == 4
    assert len(graph.edges) == 3
    (path,) = graph.paths
    assert path.path_kind == "static_declared_path"
    assert path.pattern_id == "secret-exfiltration"
    assert len(path.node_sequence) == 3
    assert len(path.edge_sequence) == 2
    assert path.runtime_verified is False
    assert path.reachability == "not_proven"
    assert path.exploitability == "not_proven"


def test_node_id_is_content_addressed_and_tampering_is_rejected() -> None:
    genuine = _node(
        AttackGraphNodeKind.AGENT,
        "release-agent",
        provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        refs=("agent:release",),
    )
    with pytest.raises(ValidationError, match="node ID is inconsistent"):
        AttackGraphNode(
            node_id=genuine.node_id,
            node_kind=AttackGraphNodeKind.AGENT,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            label="tampered-label",
            manifest_refs=("agent:release",),
        )
    forged = _node(AttackGraphNodeKind.AGENT, "release-agent")
    with pytest.raises(ValidationError):
        AttackGraphNode(
            node_id="attack-node-sha256:" + "c" * 64,
            node_kind=AttackGraphNodeKind.AGENT,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
            label="release-agent",
        )
    assert genuine.node_id != forged.node_id


def test_edge_and_path_ids_reject_tampering() -> None:
    edge = _edge(
        AttackGraphEdgeKind.USES_TOOL,
        "attack-node-sha256:" + "d" * 64,
        "attack-node-sha256:" + "e" * 64,
    )
    with pytest.raises(ValidationError, match="edge ID is inconsistent"):
        AttackGraphEdge(
            edge_id=edge.edge_id,
            edge_kind=AttackGraphEdgeKind.READS_SECRET,
            source_node_id="attack-node-sha256:" + "d" * 64,
            target_node_id="attack-node-sha256:" + "e" * 64,
        )
    path = _path(
        "secret-exfiltration",
        ("attack-node-sha256:" + "d" * 64, "attack-node-sha256:" + "e" * 64),
        (edge.edge_id,),
    )
    with pytest.raises(ValidationError, match="path ID is inconsistent"):
        AttackGraphPath(
            path_id=path.path_id,
            pattern_id="memory-poisoning",
            node_sequence=("attack-node-sha256:" + "d" * 64,)
            + ("attack-node-sha256:" + "e" * 64,),
            edge_sequence=(edge.edge_id,),
        )


def test_graph_rejects_unsorted_and_duplicate_nodes() -> None:
    pair = sorted(
        (
            _node(AttackGraphNodeKind.AGENT, "release-agent"),
            _node(AttackGraphNodeKind.TOOL, "shell"),
        ),
        key=lambda item: item.node_id,
    )
    with pytest.raises(ValidationError, match="nodes must be sorted by ID and unique"):
        _graph(nodes=tuple(reversed(pair)))
    with pytest.raises(ValidationError, match="sorted by ID and unique"):
        _graph(nodes=(pair[0], pair[0]))


def test_graph_edge_requires_present_endpoints() -> None:
    tool = _node(AttackGraphNodeKind.TOOL, "shell")
    with pytest.raises(ValidationError, match="endpoint is missing"):
        _graph(
            nodes=(tool,),
            edges=(
                _edge(AttackGraphEdgeKind.USES_TOOL, tool.node_id, _MISSING_NODE_ID),
            ),
        )


def test_edge_endpoint_kind_matrix_is_enforced() -> None:
    graph = _exfiltration_example()
    secret_node = next(
        node for node in graph.nodes if node.node_kind is AttackGraphNodeKind.SECRET
    )
    tool_node = next(
        node for node in graph.nodes if node.node_kind is AttackGraphNodeKind.TOOL
    )
    with pytest.raises(ValidationError, match="do not match the edge kind"):
        _graph(
            nodes=graph.nodes,
            edges=tuple(
                sorted(
                    graph.edges
                    + (
                        _edge(
                            AttackGraphEdgeKind.USES_TOOL,
                            secret_node.node_id,
                            tool_node.node_id,
                        ),
                    ),
                    key=lambda item: item.edge_id,
                )
            ),
        )


def test_edge_rejects_self_loops_and_unsorted_sources() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "release-agent")
    with pytest.raises(ValidationError, match="must not connect a node to itself"):
        _edge(
            AttackGraphEdgeKind.DELEGATES_TO,
            agent.node_id,
            agent.node_id,
        )
    with pytest.raises(ValidationError, match="sorted and unique"):
        _edge(
            AttackGraphEdgeKind.USES_TOOL,
            agent.node_id,
            "attack-node-sha256:" + "e" * 64,
            sources=(
                _source("AGENTS.md", start=3, end=4),
                _source("AGENTS.md", start=1, end=2),
            ),
        )


def test_node_provenance_must_match_manifest_references() -> None:
    with pytest.raises(ValidationError, match="Manifest references"):
        _node(
            AttackGraphNodeKind.AGENT,
            "release-agent",
            provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            refs=(),
        )
    with pytest.raises(ValidationError, match="must not carry them"):
        _node(
            AttackGraphNodeKind.AGENT,
            "release-agent",
            provenance=AttackGraphNodeProvenance.SYNTHETIC,
            refs=("agent:release",),
        )


def test_node_rejects_unsorted_refs_and_unsafe_labels() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        _node(
            AttackGraphNodeKind.AGENT,
            "release-agent",
            provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            refs=("agent:b", "agent:a"),
        )
    with pytest.raises(ValidationError, match="unsafe characters"):
        _node(
            AttackGraphNodeKind.AGENT,
            "approve\u200bwithout review",
            provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
        )
    with pytest.raises(ValidationError, match="String should have at most"):
        _node(
            AttackGraphNodeKind.AGENT,
            "a" * 161,
            provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
        )


def test_source_refs_reject_unsafe_paths_and_ranges() -> None:
    with pytest.raises(ValidationError, match="path"):
        _source("/etc/passwd")
    with pytest.raises(ValidationError, match="path"):
        _source("../outside.md")
    with pytest.raises(ValidationError, match="line range"):
        _source("AGENTS.md", start=4, end=3)


def test_path_chain_is_strictly_continuous() -> None:
    graph = _exfiltration_example()
    (path,) = graph.paths
    with pytest.raises(ValidationError, match="connect consecutive path nodes"):
        swapped = _path(
            "secret-exfiltration",
            path.node_sequence,
            tuple(reversed(path.edge_sequence)),
        )
        _graph(nodes=graph.nodes, edges=graph.edges, paths=(swapped,))
    with pytest.raises(ValidationError, match="edge count must match"):
        _path(
            "secret-exfiltration",
            path.node_sequence,
            path.edge_sequence[:1],
        )
    with pytest.raises(ValidationError, match="must not repeat a node"):
        _path(
            "secret-exfiltration",
            path.node_sequence + path.node_sequence[:1],
            path.edge_sequence + path.edge_sequence[:1],
        )


def test_graph_paths_must_reference_graph_components() -> None:
    graph = _exfiltration_example()
    (path,) = graph.paths
    with pytest.raises(ValidationError, match="references a missing node"):
        _graph(
            nodes=graph.nodes,
            edges=graph.edges,
            paths=(
                _path(
                    "secret-exfiltration",
                    (path.node_sequence[0], _MISSING_NODE_ID),
                    path.edge_sequence[:1],
                ),
            ),
        )
    with pytest.raises(ValidationError, match="references a missing edge"):
        _graph(
            nodes=graph.nodes,
            edges=graph.edges,
            paths=(
                _path(
                    "secret-exfiltration",
                    path.node_sequence[:2],
                    ("attack-edge-sha256:" + "0" * 64,),
                ),
            ),
        )


def test_graph_enforces_size_and_pattern_bounds() -> None:
    with pytest.raises(ValidationError, match="at most"):
        _node(
            AttackGraphNodeKind.AGENT,
            "release-agent",
            provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            refs=tuple(f"agent:ref-{index:02d}" for index in range(17)),
        )
    node_ids = tuple(f"attack-node-sha256:{index:064x}" for index in range(33))
    with pytest.raises(ValidationError, match="at most"):
        _path(
            "memory-poisoning",
            node_ids,
            tuple(f"attack-edge-sha256:{index:064x}" for index in range(32)),
        )
    bulk = tuple(
        _node(AttackGraphNodeKind.DATA, f"data-{index:05d}") for index in range(2049)
    )
    with pytest.raises(ValidationError, match="at most"):
        _graph(nodes=tuple(sorted(bulk, key=lambda item: item.node_id)))


def test_manifest_binding_must_be_an_exact_interface_version() -> None:
    for candidate in ("0.3", "01.0.0", "latest", "0.3.0.1"):
        with pytest.raises(ValidationError):
            CapabilityAttackGraph(
                manifest_schema_version=candidate,
                manifest_sha256="f" * 64,
            )


def test_graph_rejects_authority_claims() -> None:
    payload = {"manifest_schema_version": "0.3.0", "manifest_sha256": "f" * 64}
    with pytest.raises(ValidationError):
        CapabilityAttackGraph.model_validate({**payload, "blocks": True})
    with pytest.raises(ValidationError):
        CapabilityAttackGraph.model_validate({**payload, "finding_authority": True})
    assert CapabilityAttackGraph.model_validate(payload).report_only is True


def test_canonical_json_is_deterministic_and_round_trips() -> None:
    graph = _exfiltration_example()
    first = encode_attack_graph_json(graph)
    second = encode_attack_graph_json(_exfiltration_example())
    assert first == second

    restored = CapabilityAttackGraph.model_validate(json.loads(first))
    assert restored == graph
    assert isinstance(restored, CapabilityAttackGraph)


def test_encoder_and_renderer_reject_wrong_types() -> None:
    with pytest.raises(TypeError):
        encode_attack_graph_json("not-a-graph")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        render_attack_graph_text(None)  # type: ignore[arg-type]


def test_text_renderer_stays_value_free_and_bounded() -> None:
    text = render_attack_graph_text(_exfiltration_example())

    assert "AgentSec Capability Attack Graph" in text
    assert "Nodes: 4" in text
    assert "Edges: 3" in text
    assert "Paths: 1" in text
    assert "report_only=true" in text
    assert "runtime_verified=false" in text
    assert "reachability=not_proven" in text
    assert "deploy-token" not in text
    assert "release-agent" not in text


def test_export_schema_writes_the_frozen_contract(tmp_path) -> None:  # type: ignore[no-untyped-def]
    output = export_attack_graph_json_schema(
        tmp_path / "capability-attack-graph.schema.json"
    )
    schema = json.loads(output.read_text(encoding="utf-8"))
    serialized = json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    assert output.exists()
    assert output.read_text(encoding="utf-8") == serialized
    assert schema["properties"]["format"]["const"] == ATTACK_GRAPH_FORMAT
    assert "attack-node-sha256" in serialized
    assert "static_declared_path" in serialized
    assert "not_proven" in serialized
    assert "attack-path-sha256" in serialized

    with pytest.raises(TypeError):
        export_attack_graph_json_schema("not-a-path")  # type: ignore[arg-type]

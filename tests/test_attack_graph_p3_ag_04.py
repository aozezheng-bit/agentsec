"""P3-AG-04 Attack Path Report tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.attack_graph import (
    ATTACK_PATH_PATTERN_LIBRARY_VERSION,
    ATTACK_PATH_REPORT_VERSION,
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackPathMatcher,
    AttackPathReport,
    AttackPathReportEntry,
    CapabilityAttackGraph,
    ManifestCapabilityGraphBuilder,
    attack_edge_id,
    attack_node_id,
    build_attack_path_report,
    canonical_attack_graph_sha256,
    encode_attack_path_report_json,
    export_attack_path_report_json_schema,
    render_attack_path_report_text,
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
    return AttackGraphNode(
        node_id=attack_node_id(
            node_kind=kind,
            label=None,
            node_provenance=provenance,
            manifest_refs=refs,
            sources=(),
        ),
        node_kind=kind,
        node_provenance=provenance,
        label=None,
        manifest_refs=refs,
        sources=(),
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


def _matched_graphs() -> tuple[CapabilityAttackGraph, ...]:
    injection = _inferred_node(AttackGraphNodeKind.UNTRUSTED_INPUT, "override")
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    memory = _node(AttackGraphNodeKind.MEMORY, "memory:scratch")
    memory_graph = _graph(
        (injection, agent, memory),
        (
            _edge(AttackGraphEdgeKind.OVERRIDES_INSTRUCTION, injection, agent),
            _edge(AttackGraphEdgeKind.WRITES_MEMORY, agent, memory),
        ),
    )

    child = _node(AttackGraphNodeKind.AGENT, "agent:research")
    delegation_graph = _graph(
        (agent, child),
        (_edge(AttackGraphEdgeKind.DELEGATES_TO, agent, child),),
    )
    matcher = AttackPathMatcher()
    return (
        matcher.match_into_graph(memory_graph),
        matcher.match_into_graph(delegation_graph),
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _real_matched_graph(tmp_path: Path) -> CapabilityAttackGraph:
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
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    manifest = AssociationExtractor().extract(manifest, inspection)
    manifest = CapabilityExtractor().extract(manifest, inspection)
    manifest = RelationshipExtractor().extract(manifest, inspection)
    graph = ManifestCapabilityGraphBuilder().build(manifest)
    return AttackPathMatcher().match_into_graph(graph)


def test_build_rejects_non_graph_input() -> None:
    with pytest.raises(TypeError, match="requires CapabilityAttackGraph"):
        build_attack_path_report("not-a-graph")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="requires CapabilityAttackGraph"):
        canonical_attack_graph_sha256(None)  # type: ignore[arg-type]


def test_empty_report_is_valid_report_only_and_unverified() -> None:
    report = build_attack_path_report(_graph((), ()))

    assert isinstance(report, AttackPathReport)
    assert report.path_count == 0
    assert report.entries == ()
    assert report.report_only is True
    assert report.blocks is False
    assert report.finding_authority is False
    assert report.policy_authority is False
    assert report.ci_authority is False
    assert report.hard_gate_authority is False
    assert report.release_authority is False
    assert report.runtime_verified is False
    assert report.exploitability_claimed is False
    assert report.limitations
    joined = " ".join(report.limitations)
    for keyword in ("static declared relations", "runtime_verified", "Finding"):
        assert keyword in joined


def test_report_bindings_reuse_the_graph_digest() -> None:
    (memory_graph, _delegation_graph) = _matched_graphs()
    report = build_attack_path_report(memory_graph)

    assert report.schema_version == ATTACK_PATH_REPORT_VERSION
    assert report.manifest_schema_version == memory_graph.manifest_schema_version
    assert report.manifest_sha256 == memory_graph.manifest_sha256
    assert report.graph_sha256 == canonical_attack_graph_sha256(memory_graph)
    assert report.path_count == len(report.entries) == 1


def test_entries_reject_inconsistent_shapes() -> None:
    with pytest.raises(ValidationError):
        AttackPathReportEntry(
            path_id="attack-path-sha256:" + "a" * 64,
            pattern_id="secret-exfiltration",
            node_count=2,
            edge_count=5,
            node_kind_sequence=(AttackGraphNodeKind.AGENT,),
            node_ids=("attack-node-sha256:" + "b" * 64,),
        )
    with pytest.raises(ValidationError):
        AttackPathReportEntry(
            path_id="attack-path-sha256:" + "a" * 64,
            pattern_id="secret-exfiltration",
            node_count=1,
            edge_count=0,
            node_kind_sequence=(),
            node_ids=(),
        )
    with pytest.raises(ValidationError):
        AttackPathReportEntry(
            path_id="not-a-path-id",
            pattern_id="secret-exfiltration",
            node_count=2,
            edge_count=1,
            node_kind_sequence=(
                AttackGraphNodeKind.AGENT,
                AttackGraphNodeKind.NETWORK,
            ),
            node_ids=(
                "attack-node-sha256:" + "b" * 64,
                "attack-node-sha256:" + "c" * 64,
            ),
        )


def test_report_count_must_match_entries() -> None:
    (memory_graph, _delegation_graph) = _matched_graphs()
    report = build_attack_path_report(memory_graph)

    payload = json.loads(encode_attack_path_report_json(report))
    assert AttackPathReport.model_validate(payload) == report
    payload["path_count"] = 7
    with pytest.raises(ValidationError):
        AttackPathReport.model_validate(payload)
    payload["path_count"] = 1
    payload["entries"] = payload["entries"] * 2
    with pytest.raises(ValidationError):
        AttackPathReport.model_validate(payload)


def test_report_entries_match_graph_paths_exactly(tmp_path: Path) -> None:
    graph = _real_matched_graph(tmp_path)
    report = build_attack_path_report(graph)

    by_path_id = {path.path_id: path for path in graph.paths}
    kinds_by_id = {node.node_id: node.node_kind for node in graph.nodes}
    assert len(report.entries) == len(graph.paths) == report.path_count
    for entry in report.entries:
        path = by_path_id[entry.path_id]
        assert entry.pattern_id == path.pattern_id
        assert entry.node_ids == path.node_sequence
        assert entry.node_kind_sequence == tuple(
            kinds_by_id[node_id] for node_id in path.node_sequence
        )
        assert entry.node_count == len(path.node_sequence)
        assert entry.edge_count == len(path.edge_sequence)
        assert entry.runtime_verified is False
        assert entry.reachability == "not_proven"
        assert entry.exploitability == "not_proven"
        assert entry.path_kind == "static_declared_path"


def test_real_pipeline_report_is_deterministic_and_round_trips(
    tmp_path: Path,
) -> None:
    graph = _real_matched_graph(tmp_path)
    first = build_attack_path_report(graph)
    second = build_attack_path_report(graph)

    assert first == second
    encoded = encode_attack_path_report_json(first)
    assert encoded == encode_attack_path_report_json(second)

    restored = AttackPathReport.model_validate(json.loads(encoded))
    assert restored == first
    assert isinstance(restored, AttackPathReport)

    counts: dict[str, int] = {}
    for entry in first.entries:
        counts[entry.pattern_id] = counts.get(entry.pattern_id, 0) + 1
    assert set(counts) == {
        "secret-exfiltration",
        "injection-tool-execution",
        "memory-poisoning",
        "delegation-escalation",
    }


def test_report_json_is_value_free(tmp_path: Path) -> None:
    graph = _real_matched_graph(tmp_path)
    report = build_attack_path_report(graph)
    encoded = encode_attack_path_report_json(report)

    for excerpt in (
        "docs-server",
        "api.example.invalid",
        "DOCS_TOKEN",
        "New priorities.",
        "# Review",
        "research",
        "session",
        "codex:project",
        "release-agent",
        "ghost-tool",
    ):
        assert excerpt not in encoded
    for entry in report.entries:
        assert all(
            node_id.startswith("attack-node-sha256:") for node_id in entry.node_ids
        )


def test_encoder_and_renderer_reject_wrong_types() -> None:
    report = build_attack_path_report(_graph((), ()))
    with pytest.raises(TypeError):
        encode_attack_path_report_json("not-a-report")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        render_attack_path_report_text(None)  # type: ignore[arg-type]
    assert encode_attack_path_report_json(report).endswith("\n")


def test_text_renderer_is_value_free_and_bounded(tmp_path: Path) -> None:
    graph = _real_matched_graph(tmp_path)
    report = build_attack_path_report(graph)
    text = render_attack_path_report_text(report)

    assert "AgentSec Attack Path Report" in text
    assert f"Paths: {report.path_count}" in text
    assert "static declared relations only" in text
    assert "runtime_verified=false" in text
    assert "reachability=not_proven" in text
    assert "exploitability=not_proven" in text
    assert "report_only=true" in text
    assert text.endswith("\n")
    for line in text.splitlines():
        assert len(line) <= 512
    for excerpt in (
        "docs-server",
        "api.example.invalid",
        "DOCS_TOKEN",
        "codex:project",
    ):
        assert excerpt not in text
    assert any("memory-poisoning" in line for line in text.splitlines())


def test_schema_export_writes_the_frozen_contract(tmp_path: Path) -> None:
    output = export_attack_path_report_json_schema(
        tmp_path / "attack-graph" / "attack-path-report.schema.json"
    )
    content = output.read_text(encoding="utf-8")
    payload = json.loads(content)

    assert output.exists()
    assert payload["properties"]["format"]["const"] == "agentsec-attack-path-report"
    assert "attack-path-sha256" in content
    assert "static_declared_path" in content
    assert "not_proven" in content

    with pytest.raises(TypeError):
        export_attack_path_report_json_schema("not-a-path")  # type: ignore[arg-type]


def test_report_freezes_pattern_library_binding() -> None:
    (memory_graph, _delegation_graph) = _matched_graphs()
    report = build_attack_path_report(memory_graph)

    assert report.pattern_library_version == ATTACK_PATH_PATTERN_LIBRARY_VERSION
    assert report.pattern_library_version == "0.1.0"
    assert report.schema_version == "0.1.0"
    assert report.format == "agentsec-attack-path-report"

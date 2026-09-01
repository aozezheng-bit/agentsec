"""P3-AG-02 Manifest Capability Graph Builder tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.attack_graph import (
    AttackGraphBuildError,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    CapabilityAttackGraph,
    ManifestCapabilityGraphBuilder,
    canonical_manifest_sha256,
    encode_attack_graph_json,
)
from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    AssociationExtractor,
    CapabilityExtractor,
    ManifestAssetFormat,
    ManifestAssetRole,
    ManifestConfigurationProfile,
    ManifestControlProfile,
    ManifestCoverage,
    ManifestIdentity,
    ManifestInstructionCandidate,
    ManifestInstructionKind,
    ManifestInstructionProfile,
    ManifestInstructionResolutionAction,
    ManifestInstructionResolutionReason,
    ManifestInstructionResolutionStep,
    ManifestMetadata,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestPermissionProfile,
    ManifestRelation,
    ManifestRelationKind,
    ManifestRelationshipProfile,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestRuntimeIdentityProfile,
    ManifestSource,
    ManifestSourceLocator,
    ManifestSourceReference,
    ManifestSourceScope,
    ManifestTool,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolProfile,
    ManifestToolSideEffect,
    RelationshipExtractor,
)
from agentsec.semantic import canonical_model_sha256

AGENT_ID = "codex:project"
NOT_APPLICABLE = ManifestResolutionStatus.NOT_APPLICABLE
RESOLVED = ManifestResolutionStatus.RESOLVED


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _real_manifest(project: Path) -> AgentManifest:
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    manifest = AssociationExtractor().extract(manifest, inspection)
    manifest = CapabilityExtractor().extract(manifest, inspection)
    manifest = RelationshipExtractor().extract(manifest, inspection)
    return manifest


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


def _node_by_refs(
    graph: CapabilityAttackGraph, node_kind: AttackGraphNodeKind, ref: str
) -> AttackGraphNode | None:
    return next(
        (
            node
            for node in graph.nodes
            if node.node_kind is node_kind and node.manifest_refs == (ref,)
        ),
        None,
    )


def test_builder_rejects_non_manifest_input() -> None:
    with pytest.raises(TypeError, match="manifest must be AgentManifest"):
        ManifestCapabilityGraphBuilder().build("not-a-manifest")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="manifest must be AgentManifest"):
        canonical_manifest_sha256(None)  # type: ignore[arg-type]


def test_real_project_builds_a_reproducible_graph(tmp_path: Path) -> None:
    manifest = _real_manifest(_real_project(tmp_path))
    builder = ManifestCapabilityGraphBuilder()

    first = builder.build(manifest)
    second = builder.build(manifest)

    assert isinstance(first, CapabilityAttackGraph)
    assert first == second
    assert encode_attack_graph_json(first) == encode_attack_graph_json(second)
    assert first.manifest_schema_version == manifest.schema_version
    assert first.manifest_sha256 == canonical_model_sha256(manifest)
    assert first.manifest_sha256 == canonical_manifest_sha256(manifest)
    assert first.paths == ()
    assert CapabilityAttackGraph.model_validate(first.model_dump(mode="json")) == first


def test_real_project_graph_contains_expected_nodes_and_edges(
    tmp_path: Path,
) -> None:
    graph = ManifestCapabilityGraphBuilder().build(
        _real_manifest(_real_project(tmp_path))
    )
    node_ids = {node.node_id for node in graph.nodes}
    kinds = [node.node_kind for node in graph.nodes]
    edge_kinds = {edge.edge_kind for edge in graph.edges}

    assert kinds.count(AttackGraphNodeKind.AGENT) == 2
    assert kinds.count(AttackGraphNodeKind.MCP_SERVER) == 2
    assert kinds.count(AttackGraphNodeKind.SKILL) == 1
    assert kinds.count(AttackGraphNodeKind.MEMORY) == 3
    assert kinds.count(AttackGraphNodeKind.UNTRUSTED_INPUT) == 1
    assert kinds.count(AttackGraphNodeKind.NETWORK) == 1
    assert kinds.count(AttackGraphNodeKind.DEPENDENCY) == 0
    assert len(graph.nodes) == len(node_ids)
    assert len({edge.edge_id for edge in graph.edges}) == len(graph.edges)

    expected_edges = {
        AttackGraphEdgeKind.OVERRIDES_INSTRUCTION,
        AttackGraphEdgeKind.USES_SKILL,
        AttackGraphEdgeKind.USES_MCP,
        AttackGraphEdgeKind.PROVIDES_TOOL,
        AttackGraphEdgeKind.DELEGATES_TO,
        AttackGraphEdgeKind.READS_MEMORY,
        AttackGraphEdgeKind.WRITES_MEMORY,
        AttackGraphEdgeKind.SENDS_TO,
        AttackGraphEdgeKind.READS_SECRET,
    }
    assert expected_edges <= edge_kinds


def test_real_project_graph_stays_value_free(tmp_path: Path) -> None:
    graph = ManifestCapabilityGraphBuilder().build(
        _real_manifest(_real_project(tmp_path))
    )
    encoded = encode_attack_graph_json(graph)
    evidence_keys = {
        "asset_path",
        "asset_sha256",
        "start_line",
        "end_line",
    }

    assert all(node.label is None for node in graph.nodes)
    assert all(len(node.sources) <= 16 for node in graph.nodes)
    assert all(
        set(source.model_dump(mode="json")) == evidence_keys
        for node in graph.nodes
        for source in node.sources
    )
    assert all(
        set(source.model_dump(mode="json")) == evidence_keys
        for edge in graph.edges
        for source in edge.sources
    )
    for excerpt in (
        "docs-server",
        "api.example.invalid",
        "DOCS_TOKEN",
        "New priorities.",
        "# Review",
    ):
        assert excerpt not in encoded


def _locator(path: str) -> ManifestSourceLocator:
    return ManifestSourceLocator(
        scope=ManifestSourceScope.PROJECT,
        root_id="root0",
        path=path,
    )


def _source(path: str, digest: str, *, line_count: int, rank: int) -> ManifestSource:
    if path == "AGENTS.md":
        roles: tuple[ManifestAssetRole, ...] = (ManifestAssetRole.AGENT_INSTRUCTIONS,)
        source_format = ManifestAssetFormat.MARKDOWN
    elif path == "AGENTS.override.md":
        roles = (ManifestAssetRole.INSTRUCTION_OVERRIDE,)
        source_format = ManifestAssetFormat.MARKDOWN
    elif path.endswith("SKILL.md"):
        roles = (ManifestAssetRole.SKILL,)
        source_format = ManifestAssetFormat.MARKDOWN
    else:
        roles = (
            ManifestAssetRole.FRAMEWORK_CONFIG,
            ManifestAssetRole.MCP_CONFIG,
        )
        source_format = ManifestAssetFormat.TOML
    return ManifestSource(
        locator=_locator(path),
        format=source_format,
        roles=roles,
        content_sha256=digest,
        size_bytes=64,
        line_count=line_count,
        precedence_rank=rank,
    )


def _ref(
    path: str,
    *,
    field_path: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> ManifestSourceReference:
    return ManifestSourceReference(
        locator=_locator(path),
        field_path=field_path,
        start_line=start,
        end_line=end,
    )


def _extra_relation_sources(count: int) -> tuple[ManifestSourceReference, ...]:
    extra = [
        _ref(
            "AGENTS.md",
            field_path=f"$.frontmatter.audit[{index}]",
            start=21 + index,
            end=21 + index,
        )
        for index in range(count)
    ]
    return tuple(sorted(extra, key=lambda item: item.sort_key()))


def _synthetic_manifest(
    *,
    delegates_target: str = "agent:research",
    extra_relation_sources: tuple[ManifestSourceReference, ...] = (),
) -> AgentManifest:
    base = _source("AGENTS.md", "a" * 64, line_count=60, rank=100)
    override = _source("AGENTS.override.md", "b" * 64, line_count=4, rank=105)
    skill = _source(".agents/skills/review/SKILL.md", "c" * 64, line_count=10, rank=200)
    config = _source(".codex/config.toml", "d" * 64, line_count=60, rank=200)

    base_ref = _ref("AGENTS.md")
    override_ref = _ref("AGENTS.override.md")
    skill_ref = _ref(".agents/skills/review/SKILL.md")
    config_ref = _ref(".codex/config.toml")

    instructions = ManifestInstructionProfile(
        resolution=RESOLVED,
        candidates=(
            ManifestInstructionCandidate(
                kind=ManifestInstructionKind.BASE,
                source=_ref("AGENTS.md", field_path="$.title"),
                precedence_rank=100,
            ),
            ManifestInstructionCandidate(
                kind=ManifestInstructionKind.OVERRIDE,
                source=_ref("AGENTS.override.md", field_path="$.title"),
                precedence_rank=105,
            ),
        ),
        effective_sources=(override_ref,),
        effective_order=(override_ref,),
        overridden_sources=(base_ref,),
        resolution_trace=(
            ManifestInstructionResolutionStep(
                source=base_ref,
                action=ManifestInstructionResolutionAction.OVERRIDDEN,
                reason=ManifestInstructionResolutionReason.OVERRIDE_REPLACES_BASE,
                precedence_rank=100,
                chain_key="chain",
            ),
            ManifestInstructionResolutionStep(
                source=override_ref,
                action=ManifestInstructionResolutionAction.SELECTED,
                reason=ManifestInstructionResolutionReason.OVERRIDE_REPLACES_BASE,
                precedence_rank=105,
                chain_key="chain",
            ),
        ),
    )

    tools = ManifestToolProfile(
        resolution=RESOLVED,
        declaration_sources=(skill_ref, config_ref),
        tools=(
            ManifestTool(
                tool_id="mcp-server:docs",
                name="docs",
                kind=ManifestToolKind.MCP_SERVER,
                availability=ManifestToolAvailability.DISABLED,
                side_effects=(ManifestToolSideEffect.EXECUTE,),
                sources=(_ref(".codex/config.toml", start=1, end=4),),
            ),
            ManifestTool(
                tool_id="mcp-server:remote",
                name="remote",
                kind=ManifestToolKind.MCP_SERVER,
                availability=ManifestToolAvailability.ENABLED,
                side_effects=(ManifestToolSideEffect.NETWORK,),
                sources=(_ref(".codex/config.toml", start=8, end=10),),
            ),
            ManifestTool(
                tool_id="mcp-tool:docs.search",
                name="search",
                kind=ManifestToolKind.MCP_TOOL,
                availability=ManifestToolAvailability.ENABLED,
                side_effects=(ManifestToolSideEffect.READ,),
                parent_tool_id="mcp-server:docs",
                sources=(_ref(".codex/config.toml", start=3, end=3),),
            ),
            ManifestTool(
                tool_id="shell",
                name="shell",
                kind=ManifestToolKind.COMMAND,
                availability=ManifestToolAvailability.DECLARED,
                side_effects=(ManifestToolSideEffect.EXECUTE,),
                sources=(_ref(".codex/config.toml", start=11, end=12),),
            ),
            ManifestTool(
                tool_id="skill:review",
                name="review",
                kind=ManifestToolKind.SKILL,
                availability=ManifestToolAvailability.DECLARED,
                side_effects=(ManifestToolSideEffect.UNKNOWN,),
                sources=(skill_ref,),
            ),
        ),
    )

    permissions = ManifestPermissionProfile(
        resolution=RESOLVED,
        declaration_sources=(config_ref,),
        permissions=(
            ManifestPermission(
                permission_id="permission:memory-persist",
                action=ManifestPermissionAction.PERSIST,
                effect=ManifestPermissionEffect.ALLOW,
                resource=ManifestResourceKind.MEMORY,
                scope=ManifestResourceScope.PROJECT,
                sources=(_ref(".codex/config.toml", start=36, end=40),),
            ),
            ManifestPermission(
                permission_id="permission:net-allow",
                action=ManifestPermissionAction.NETWORK,
                effect=ManifestPermissionEffect.ALLOW,
                resource=ManifestResourceKind.NETWORK,
                scope=ManifestResourceScope.EXTERNAL,
                sources=(_ref(".codex/config.toml", start=41, end=45),),
            ),
            ManifestPermission(
                permission_id="permission:net-deny",
                action=ManifestPermissionAction.NETWORK,
                effect=ManifestPermissionEffect.DENY,
                resource=ManifestResourceKind.NETWORK,
                scope=ManifestResourceScope.EXTERNAL,
                sources=(_ref(".codex/config.toml", start=46, end=50),),
            ),
            ManifestPermission(
                permission_id="permission:prod-deploy",
                action=ManifestPermissionAction.DEPLOY,
                effect=ManifestPermissionEffect.PROMPT,
                resource=ManifestResourceKind.PRODUCTION,
                scope=ManifestResourceScope.PRODUCTION,
                sources=(_ref(".codex/config.toml", start=51, end=55),),
            ),
            ManifestPermission(
                permission_id="permission:secret-env",
                action=ManifestPermissionAction.SECRET_ACCESS,
                effect=ManifestPermissionEffect.ALLOW,
                resource=ManifestResourceKind.ENVIRONMENT,
                scope=ManifestResourceScope.PROJECT,
                target="mcp-server:docs",
                sources=(_ref(".codex/config.toml", start=21, end=25),),
            ),
        ),
    )

    relations = (
        ManifestRelation(
            relation_id="relation:1",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.DELEGATES_TO,
            target_id=delegates_target,
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=1, end=3),),
        ),
        ManifestRelation(
            relation_id="relation:2",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.OTHER,
            target_id="anything",
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=7, end=7),),
        ),
        ManifestRelation(
            relation_id="relation:3",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.READS_MEMORY,
            target_id="memory:session",
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=6, end=6),),
        ),
        ManifestRelation(
            relation_id="relation:4",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.PERSISTS_MEMORY,
            target_id="memory:long_term",
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=8, end=8),),
        ),
        ManifestRelation(
            relation_id="relation:5",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.USES_SKILL,
            target_id="skill:review",
            state=ManifestRelationState.DECLARED,
            sources=(
                _ref("AGENTS.md", start=9, end=9),
                *extra_relation_sources,
            ),
        ),
        ManifestRelation(
            relation_id="relation:6",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.USES_MCP,
            target_id="mcp-server:docs",
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=10, end=10),),
        ),
        ManifestRelation(
            relation_id="relation:7",
            source_agent_id=AGENT_ID,
            kind=ManifestRelationKind.USES_TOOL,
            target_id="ghost-tool",
            state=ManifestRelationState.DECLARED,
            sources=(_ref("AGENTS.md", start=11, end=11),),
        ),
    )

    sources = (skill, config, base, override)
    return AgentManifest(
        schema_version="0.3.0",
        metadata=ManifestMetadata(
            scanner_version="agentsec",
            framework_id="codex",
            framework_display_name="Codex",
            adapter_version="1.0.0",
        ),
        identity=ManifestIdentity(
            agent_id=AGENT_ID,
            subject_scope=ManifestSourceScope.PROJECT,
            subject_root_id="root0",
            declared_name="Project Agent",
            resolution=RESOLVED,
            sources=(),
        ),
        sources=sources,
        instructions=instructions,
        configuration=ManifestConfigurationProfile(resolution=NOT_APPLICABLE),
        tools=tools,
        permissions=permissions,
        controls=ManifestControlProfile(resolution=NOT_APPLICABLE),
        runtime_identities=ManifestRuntimeIdentityProfile(resolution=NOT_APPLICABLE),
        relationships=ManifestRelationshipProfile(
            resolution=RESOLVED,
            declaration_sources=(base_ref,),
            relations=relations,
        ),
        coverage=ManifestCoverage(
            discovered_assets=len(sources),
            inspected_assets=len(sources),
            skipped_assets=0,
            complete=True,
        ),
    )


def test_synthetic_mapping_matrix() -> None:
    manifest = _synthetic_manifest()
    graph = ManifestCapabilityGraphBuilder().build(manifest)
    node_ids = {node.node_id for node in graph.nodes}
    kinds = [node.node_kind for node in graph.nodes]

    assert graph.manifest_schema_version == "0.3.0"
    assert graph.manifest_sha256 == canonical_model_sha256(manifest)

    assert kinds.count(AttackGraphNodeKind.AGENT) == 2
    assert kinds.count(AttackGraphNodeKind.MCP_SERVER) == 1
    assert kinds.count(AttackGraphNodeKind.SKILL) == 1
    assert kinds.count(AttackGraphNodeKind.TOOL) == 3
    assert kinds.count(AttackGraphNodeKind.MEMORY) == 3
    assert kinds.count(AttackGraphNodeKind.SECRET) == 1
    assert kinds.count(AttackGraphNodeKind.PRODUCTION_TARGET) == 1
    assert kinds.count(AttackGraphNodeKind.NETWORK) == 1
    assert kinds.count(AttackGraphNodeKind.UNTRUSTED_INPUT) == 1
    assert len({edge.edge_id for edge in graph.edges}) == len(graph.edges)
    assert len(graph.nodes) == len(node_ids) == 14
    assert len(graph.edges) == 10

    agent = _node_by_refs(graph, AttackGraphNodeKind.AGENT, AGENT_ID)
    child = _node_by_refs(graph, AttackGraphNodeKind.AGENT, "agent:research")
    secret = _node_by_refs(graph, AttackGraphNodeKind.SECRET, "permission:secret-env")
    production = _node_by_refs(
        graph, AttackGraphNodeKind.PRODUCTION_TARGET, "permission:prod-deploy"
    )
    session = _node_by_refs(graph, AttackGraphNodeKind.MEMORY, "memory:session")
    long_term = _node_by_refs(graph, AttackGraphNodeKind.MEMORY, "memory:long_term")
    assert agent is not None and child is not None
    assert secret is not None and production is not None
    assert session is not None and long_term is not None

    assert {edge.edge_kind for edge in graph.edges} == {
        AttackGraphEdgeKind.DELEGATES_TO,
        AttackGraphEdgeKind.OVERRIDES_INSTRUCTION,
        AttackGraphEdgeKind.READS_MEMORY,
        AttackGraphEdgeKind.READS_SECRET,
        AttackGraphEdgeKind.SENDS_TO,
        AttackGraphEdgeKind.USES_SKILL,
        AttackGraphEdgeKind.USES_TOOL,
        AttackGraphEdgeKind.WRITES_MEMORY,
    }

    delegated = [
        edge
        for edge in graph.edges
        if edge.edge_kind is AttackGraphEdgeKind.DELEGATES_TO
    ]
    assert len(delegated) == 1
    assert delegated[0].source_node_id == agent.node_id
    assert delegated[0].target_node_id == child.node_id

    secrets_edges = [
        edge
        for edge in graph.edges
        if edge.edge_kind is AttackGraphEdgeKind.READS_SECRET
    ]
    assert [edge.target_node_id for edge in secrets_edges] == [secret.node_id]

    writes = [
        edge
        for edge in graph.edges
        if edge.edge_kind is AttackGraphEdgeKind.WRITES_MEMORY
    ]
    assert {edge.target_node_id for edge in writes} == {
        long_term.node_id,
    } | {
        node.node_id
        for node in graph.nodes
        if node.node_kind is AttackGraphNodeKind.MEMORY
        and node.node_provenance is AttackGraphNodeProvenance.SYNTHETIC
    }
    assert len(writes) == 2

    network_node = next(
        node for node in graph.nodes if node.node_kind is AttackGraphNodeKind.NETWORK
    )
    sends = [
        edge for edge in graph.edges if edge.edge_kind is AttackGraphEdgeKind.SENDS_TO
    ]
    assert len(sends) == 2
    assert all(edge.target_node_id == network_node.node_id for edge in sends)
    assert sorted(edge.source_node_id for edge in sends) == sorted(
        [
            agent.node_id,
            next(
                node.node_id
                for node in graph.nodes
                if node.node_kind is AttackGraphNodeKind.MCP_SERVER
            ),
        ]
    )

    assert all(
        production.node_id not in (edge.source_node_id, edge.target_node_id)
        for edge in graph.edges
    )

    ghost = next(
        node
        for node in graph.nodes
        if node.label == "ghost-tool" and node.node_kind is AttackGraphNodeKind.TOOL
    )
    assert ghost.node_provenance is AttackGraphNodeProvenance.MANIFEST_INFERRED
    assert ghost.manifest_refs == ()
    assert ghost.label == "ghost-tool"

    override_input = next(
        node
        for node in graph.nodes
        if node.node_kind is AttackGraphNodeKind.UNTRUSTED_INPUT
    )
    assert override_input.node_provenance is (
        AttackGraphNodeProvenance.MANIFEST_INFERRED
    )
    assert override_input.manifest_refs == ()
    assert override_input.label is None
    (override_source,) = override_input.sources
    assert override_source.asset_path == "AGENTS.override.md"
    assert override_source.start_line == 1
    assert override_source.end_line == 4


def test_synthetic_manifest_is_deterministic() -> None:
    builder = ManifestCapabilityGraphBuilder()
    first = builder.build(_synthetic_manifest())
    second = builder.build(_synthetic_manifest())

    assert first == second
    assert encode_attack_graph_json(first) == encode_attack_graph_json(second)


def test_self_delegation_fails_closed() -> None:
    manifest = _synthetic_manifest(delegates_target=AGENT_ID)

    with pytest.raises(AttackGraphBuildError, match="self-loop"):
        ManifestCapabilityGraphBuilder().build(manifest)


def test_evidence_bound_fails_closed() -> None:
    manifest = _synthetic_manifest(extra_relation_sources=_extra_relation_sources(17))

    with pytest.raises(AttackGraphBuildError, match="exceeds the bound"):
        ManifestCapabilityGraphBuilder().build(manifest)

"""P3-AG-02 deterministic Manifest to Capability Attack Graph builder."""

from __future__ import annotations

import hashlib
import json
from typing import Any, NamedTuple

from agentsec.attack_graph.models import (
    ATTACK_GRAPH_MAX_SOURCE_REFS,
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackGraphSourceRef,
    CapabilityAttackGraph,
    attack_edge_id,
    attack_node_id,
)
from agentsec.manifests.enums import (
    ManifestInstructionKind,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestRelationKind,
    ManifestResourceKind,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestPermission,
    ManifestRelation,
    ManifestSource,
    ManifestSourceReference,
    ManifestTool,
)

SourceRefKey = tuple[str, str, int, int]

ATTACK_GRAPH_BUILDER_VERSION = "0.1.0"

DECLARED_REGISTRY = "declared"
INFERRED_REGISTRY = "inferred"
CANONICAL_REGISTRY = "canonical"

_TOOL_NODE_KINDS: dict[ManifestToolKind, AttackGraphNodeKind] = {
    ManifestToolKind.SKILL: AttackGraphNodeKind.SKILL,
    ManifestToolKind.MCP_SERVER: AttackGraphNodeKind.MCP_SERVER,
    ManifestToolKind.MCP_TOOL: AttackGraphNodeKind.TOOL,
    ManifestToolKind.COMMAND: AttackGraphNodeKind.TOOL,
    ManifestToolKind.BUILTIN: AttackGraphNodeKind.TOOL,
    ManifestToolKind.PLUGIN: AttackGraphNodeKind.TOOL,
    ManifestToolKind.OTHER: AttackGraphNodeKind.TOOL,
}

_USES_NODE_KINDS: dict[ManifestRelationKind, AttackGraphNodeKind] = {
    ManifestRelationKind.USES_TOOL: AttackGraphNodeKind.TOOL,
    ManifestRelationKind.USES_SKILL: AttackGraphNodeKind.SKILL,
    ManifestRelationKind.USES_MCP: AttackGraphNodeKind.MCP_SERVER,
}

_RELATION_EDGE_KINDS: dict[ManifestRelationKind, AttackGraphEdgeKind] = {
    ManifestRelationKind.DELEGATES_TO: AttackGraphEdgeKind.DELEGATES_TO,
    ManifestRelationKind.USES_SKILL: AttackGraphEdgeKind.USES_SKILL,
    ManifestRelationKind.USES_MCP: AttackGraphEdgeKind.USES_MCP,
    ManifestRelationKind.USES_TOOL: AttackGraphEdgeKind.USES_TOOL,
    ManifestRelationKind.READS_MEMORY: AttackGraphEdgeKind.READS_MEMORY,
    ManifestRelationKind.WRITES_MEMORY: AttackGraphEdgeKind.WRITES_MEMORY,
    ManifestRelationKind.PERSISTS_MEMORY: AttackGraphEdgeKind.WRITES_MEMORY,
}

_PRODUCTION_ACTIONS = frozenset(
    {
        ManifestPermissionAction.DEPLOY,
        ManifestPermissionAction.PUBLISH,
    }
)

_EFFECTS_WITH_CAPABILITY = frozenset(
    {
        ManifestPermissionEffect.ALLOW,
        ManifestPermissionEffect.PROMPT,
        ManifestPermissionEffect.UNKNOWN,
    }
)


class AttackGraphBuildError(ValueError):
    """Safe Attack Graph build failure without untrusted content."""


class _NodeKey(NamedTuple):
    registry: str
    node_kind: AttackGraphNodeKind
    discriminant: tuple[str, ...]


class _NodeStore(NamedTuple):
    key: _NodeKey
    node_kind: AttackGraphNodeKind
    node_provenance: AttackGraphNodeProvenance
    manifest_refs: tuple[str, ...]
    label: str | None
    sources: set[SourceRefKey]


class _EdgeKey(NamedTuple):
    edge_kind: AttackGraphEdgeKind
    source_node: _NodeKey
    target_node: _NodeKey


def canonical_manifest_sha256(manifest: AgentManifest) -> str:
    """Return the canonical digest of one validated Agent Manifest."""

    if not isinstance(manifest, AgentManifest):
        raise TypeError("manifest must be AgentManifest")
    return _canonical_hash(manifest.model_dump(mode="json"))


class ManifestCapabilityGraphBuilder:
    """Build a reproducible, value-free graph from one validated Manifest.

    The builder consumes Manifest declaration fields only. It never opens
    project files, never executes scanned content, and never copies raw text
    into the graph: Evidence stays limited to asset path, content digest, and
    line range. The emitted graph grants no Finding, Rule, Policy, CI, Hard
    Gate, release, or runtime authority and marks every path unproven.
    """

    def build(self, manifest: AgentManifest) -> CapabilityAttackGraph:
        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")

        source_index = {
            source.locator.sort_key(): source for source in manifest.sources
        }
        nodes: dict[_NodeKey, _NodeStore] = {}
        edges: dict[_EdgeKey, set[SourceRefKey]] = {}

        def register(
            key: _NodeKey,
            *,
            provenance: AttackGraphNodeProvenance,
            refs: tuple[str, ...],
            label: str | None,
            references: tuple[ManifestSourceReference, ...],
        ) -> _NodeKey:
            store = nodes.get(key)
            if store is None:
                store = _NodeStore(
                    key=key,
                    node_kind=key.node_kind,
                    node_provenance=provenance,
                    manifest_refs=refs,
                    label=label,
                    sources=set(),
                )
                nodes[key] = store
            store.sources.update(_source_ref_keys(references, source_index))
            return key

        def declared(
            node_kind: AttackGraphNodeKind,
            refs: tuple[str, ...],
            references: tuple[ManifestSourceReference, ...],
        ) -> _NodeKey:
            return register(
                _NodeKey(DECLARED_REGISTRY, node_kind, refs),
                provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
                refs=refs,
                label=None,
                references=references,
            )

        def inferred(
            node_kind: AttackGraphNodeKind,
            label: str | None,
            references: tuple[ManifestSourceReference, ...],
        ) -> _NodeKey:
            return register(
                _NodeKey(INFERRED_REGISTRY, node_kind, (label or "",)),
                provenance=AttackGraphNodeProvenance.MANIFEST_INFERRED,
                refs=(),
                label=label,
                references=references,
            )

        def canonical(node_kind: AttackGraphNodeKind) -> _NodeKey:
            return register(
                _NodeKey(CANONICAL_REGISTRY, node_kind, ()),
                provenance=AttackGraphNodeProvenance.SYNTHETIC,
                refs=(),
                label=None,
                references=(),
            )

        def connect(
            edge_kind: AttackGraphEdgeKind,
            source_key: _NodeKey,
            target_key: _NodeKey,
            references: tuple[ManifestSourceReference, ...],
        ) -> None:
            if source_key == target_key:
                raise AttackGraphBuildError(
                    "attack graph mapping produced a self-loop edge"
                )
            sources = _source_ref_keys(references, source_index)
            key = _EdgeKey(edge_kind, source_key, target_key)
            existing = edges.get(key)
            if existing is None:
                edges[key] = set(sources)
            else:
                existing.update(sources)

        agent_key = declared(
            AttackGraphNodeKind.AGENT,
            (manifest.identity.agent_id,),
            manifest.identity.sources,
        )

        tool_node_keys: dict[str, _NodeKey] = {}
        tool_records: dict[str, ManifestTool] = {}
        for tool in manifest.tools.tools:
            tool_records[tool.tool_id] = tool
        for tool in manifest.tools.tools:
            if tool.availability is ManifestToolAvailability.DISABLED:
                continue
            tool_node_keys[tool.tool_id] = declared(
                _TOOL_NODE_KINDS[tool.kind],
                (tool.tool_id,),
                tool.sources,
            )

        for relation in manifest.relationships.relations:
            self._map_relation(
                relation,
                agent_key=agent_key,
                tool_node_keys=tool_node_keys,
                tool_records=tool_records,
                declared=declared,
                inferred=inferred,
                connect=connect,
            )

        for candidate in manifest.instructions.candidates:
            if candidate.kind is not ManifestInstructionKind.OVERRIDE:
                continue
            input_key = inferred(
                AttackGraphNodeKind.UNTRUSTED_INPUT,
                None,
                (candidate.source,),
            )
            connect(
                AttackGraphEdgeKind.OVERRIDES_INSTRUCTION,
                input_key,
                agent_key,
                (candidate.source,),
            )

        for permission in manifest.permissions.permissions:
            self._map_permission(
                permission,
                agent_key=agent_key,
                declared=declared,
                canonical=canonical,
                connect=connect,
            )

        network_key: _NodeKey | None = None
        for tool in manifest.tools.tools:
            tool_key = tool_node_keys.get(tool.tool_id)
            if tool_key is None:
                continue
            if ManifestToolSideEffect.NETWORK in tool.side_effects:
                if network_key is None:
                    network_key = canonical(AttackGraphNodeKind.NETWORK)
                connect(
                    AttackGraphEdgeKind.SENDS_TO,
                    tool_key,
                    network_key,
                    tool.sources,
                )
            parent_key = (
                None
                if tool.parent_tool_id is None
                else tool_node_keys.get(tool.parent_tool_id)
            )
            if (
                tool.kind is ManifestToolKind.MCP_TOOL
                and tool.parent_tool_id is not None
                and parent_key is not None
                and tool_records[tool.parent_tool_id].kind
                is ManifestToolKind.MCP_SERVER
            ):
                connect(
                    AttackGraphEdgeKind.PROVIDES_TOOL,
                    parent_key,
                    tool_key,
                    tool.sources,
                )

        for key in nodes:
            if len(nodes[key].sources) > ATTACK_GRAPH_MAX_SOURCE_REFS:
                raise AttackGraphBuildError(
                    "attack graph node Evidence exceeds the bound"
                )
        for sources in edges.values():
            if len(sources) > ATTACK_GRAPH_MAX_SOURCE_REFS:
                raise AttackGraphBuildError(
                    "attack graph edge Evidence exceeds the bound"
                )

        materialized = {store.key: _materialize_node(store) for store in nodes.values()}
        node_ids = {key: node.node_id for key, node in materialized.items()}
        node_models = tuple(
            sorted(materialized.values(), key=lambda node: node.node_id)
        )
        edge_models = tuple(
            sorted(
                (
                    _materialize_edge(key, sources, node_ids)
                    for key, sources in edges.items()
                ),
                key=lambda edge: edge.edge_id,
            )
        )

        return CapabilityAttackGraph(
            manifest_schema_version=manifest.schema_version,
            manifest_sha256=canonical_manifest_sha256(manifest),
            nodes=node_models,
            edges=edge_models,
            paths=(),
        )

    def _map_relation(
        self,
        relation: ManifestRelation,
        *,
        agent_key: _NodeKey,
        tool_node_keys: dict[str, _NodeKey],
        tool_records: dict[str, ManifestTool],
        declared: Any,
        inferred: Any,
        connect: Any,
    ) -> None:
        kind = relation.kind
        if kind is ManifestRelationKind.OTHER:
            return
        if kind is ManifestRelationKind.DELEGATES_TO:
            child_key = declared(
                AttackGraphNodeKind.AGENT,
                (relation.target_id,),
                relation.sources,
            )
            connect(
                AttackGraphEdgeKind.DELEGATES_TO,
                agent_key,
                child_key,
                relation.sources,
            )
            return
        if kind in {
            ManifestRelationKind.READS_MEMORY,
            ManifestRelationKind.WRITES_MEMORY,
            ManifestRelationKind.PERSISTS_MEMORY,
        }:
            memory_key = declared(
                AttackGraphNodeKind.MEMORY,
                (relation.target_id,),
                relation.sources,
            )
            connect(
                _RELATION_EDGE_KINDS[kind],
                agent_key,
                memory_key,
                relation.sources,
            )
            return
        target_id = relation.target_id
        if target_id in tool_node_keys:
            target_key = tool_node_keys[target_id]
        elif target_id in tool_records:
            return
        else:
            target_key = inferred(
                _USES_NODE_KINDS[kind],
                target_id,
                relation.sources,
            )
        connect(
            _RELATION_EDGE_KINDS[kind],
            agent_key,
            target_key,
            relation.sources,
        )

    def _map_permission(
        self,
        permission: ManifestPermission,
        *,
        agent_key: _NodeKey,
        declared: Any,
        canonical: Any,
        connect: Any,
    ) -> None:
        if permission.effect not in _EFFECTS_WITH_CAPABILITY:
            return
        action = permission.action
        resource = permission.resource
        if action is ManifestPermissionAction.SECRET_ACCESS or (
            resource is ManifestResourceKind.SECRET_STORE
        ):
            secret_key = declared(
                AttackGraphNodeKind.SECRET,
                (permission.permission_id,),
                permission.sources,
            )
            connect(
                AttackGraphEdgeKind.READS_SECRET,
                agent_key,
                secret_key,
                permission.sources,
            )
            return
        if action is ManifestPermissionAction.NETWORK or (
            resource is ManifestResourceKind.NETWORK
        ):
            connect(
                AttackGraphEdgeKind.SENDS_TO,
                agent_key,
                canonical(AttackGraphNodeKind.NETWORK),
                permission.sources,
            )
            return
        if resource is ManifestResourceKind.PRODUCTION or (
            action in _PRODUCTION_ACTIONS
        ):
            declared(
                AttackGraphNodeKind.PRODUCTION_TARGET,
                (permission.permission_id,),
                permission.sources,
            )
            return
        if resource is ManifestResourceKind.MEMORY or (
            action is ManifestPermissionAction.PERSIST
        ):
            connect(
                (
                    AttackGraphEdgeKind.READS_MEMORY
                    if action is ManifestPermissionAction.READ
                    else AttackGraphEdgeKind.WRITES_MEMORY
                ),
                agent_key,
                canonical(AttackGraphNodeKind.MEMORY),
                permission.sources,
            )


def _source_ref_keys(
    references: tuple[ManifestSourceReference, ...],
    source_index: dict[tuple[str, str, str], ManifestSource],
) -> set[SourceRefKey]:
    keys: set[SourceRefKey] = set()
    for reference in references:
        source = source_index.get(reference.locator.sort_key())
        if source is None:
            raise AttackGraphBuildError(
                "attack graph Evidence reference must resolve to a Manifest source"
            )
        if reference.start_line is not None and reference.end_line is not None:
            start_line = reference.start_line
            end_line = reference.end_line
        else:
            start_line = 1
            end_line = max(source.line_count, 1)
        keys.add(
            (
                source.locator.path,
                source.content_sha256,
                start_line,
                end_line,
            )
        )
    return keys


def _materialize_node(store: _NodeStore) -> AttackGraphNode:
    sources = tuple(
        AttackGraphSourceRef(
            asset_path=path,
            asset_sha256=asset_sha256,
            start_line=start_line,
            end_line=end_line,
        )
        for path, asset_sha256, start_line, end_line in sorted(store.sources)
    )
    return AttackGraphNode(
        node_id=attack_node_id(
            node_kind=store.node_kind,
            label=store.label,
            node_provenance=store.node_provenance,
            manifest_refs=store.manifest_refs,
            sources=sources,
        ),
        node_kind=store.node_kind,
        node_provenance=store.node_provenance,
        label=store.label,
        manifest_refs=store.manifest_refs,
        sources=sources,
    )


def _materialize_edge(
    key: _EdgeKey,
    sources: set[SourceRefKey],
    node_ids: dict[_NodeKey, str],
) -> AttackGraphEdge:
    source_models = tuple(
        AttackGraphSourceRef(
            asset_path=path,
            asset_sha256=asset_sha256,
            start_line=start_line,
            end_line=end_line,
        )
        for path, asset_sha256, start_line, end_line in sorted(sources)
    )
    return AttackGraphEdge(
        edge_id=attack_edge_id(
            edge_kind=key.edge_kind,
            source_node_id=node_ids[key.source_node],
            target_node_id=node_ids[key.target_node],
            sources=source_models,
        ),
        edge_kind=key.edge_kind,
        source_node_id=node_ids[key.source_node],
        target_node_id=node_ids[key.target_node],
        sources=source_models,
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
    "ATTACK_GRAPH_BUILDER_VERSION",
    "AttackGraphBuildError",
    "ManifestCapabilityGraphBuilder",
    "canonical_manifest_sha256",
]

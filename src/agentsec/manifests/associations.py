"""Deterministic association of Skills and static MCP declarations.

This module is deliberately a second step after :class:`AgentManifestBuilder`.
The builder retains only safe source metadata, while this extractor consumes the
already parsed Framework inspection result to create bounded, source-backed
capability facts. It never reads the filesystem, expands environment values,
connects to MCP, or executes a declared command or Skill.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from agentsec.frameworks import (
    FrameworkAssetRecord,
    FrameworkAssetRole,
    FrameworkInspectionResult,
)
from agentsec.manifests.enums import (
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestRelation,
    ManifestRelationshipProfile,
    ManifestSourceReference,
    ManifestTool,
    ManifestToolProfile,
)
from agentsec.parsers import (
    McpServerDeclaration,
    McpTransport,
    ParsedMcpConfiguration,
    SourceBackedValue,
    format_structured_path,
)

_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMPONENT_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
_DISPLAY_SEPARATOR_PATTERN = re.compile(r"[\s/\\]+")
_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_MAX_COMPONENT_LENGTH = 48
_ID_DIGEST_LENGTH = 12


class AssociationExtractionError(RuntimeError):
    """Safe failure for an invalid or ambiguous association input."""


@dataclass(frozen=True, slots=True)
class _SourceRecord:
    """One inspection record paired with the Manifest's portable source ref."""

    record: FrameworkAssetRecord
    source_reference: ManifestSourceReference

    @property
    def key(self) -> tuple[str, str, str]:
        locator = self.record.asset.locator
        return (locator.scope.value, locator.root_id, locator.path)


@dataclass(frozen=True, slots=True)
class _IdCandidate:
    """One stable-id candidate before deterministic collision disambiguation."""

    key: tuple[str, ...]
    base_id: str


@dataclass(frozen=True, slots=True)
class _ToolCandidate:
    """Intermediate tool fact retaining only safe in-memory parsed metadata."""

    key: tuple[str, ...]
    base_id: str
    name: str
    kind: ManifestToolKind
    availability: ManifestToolAvailability
    side_effects: tuple[ManifestToolSideEffect, ...]
    parent_key: tuple[str, ...] | None
    sources: tuple[ManifestSourceReference, ...]


@dataclass(frozen=True, slots=True)
class _RelationCandidate:
    """Intermediate relation fact before stable relation IDs are assigned."""

    key: tuple[str, ...]
    base_id: str
    kind: ManifestRelationKind
    target_key: tuple[str, ...]
    state: ManifestRelationState
    sources: tuple[ManifestSourceReference, ...]


class AssociationExtractor:
    """Populate static Skill/MCP/tool associations from one inspection result."""

    def extract(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest:
        """Return a new Manifest with source-backed association facts.

        ``inspection`` must be the same logical inspection used to build
        ``manifest``. The extractor checks portable locators, format, roles,
        digests, and line counts before consuming parser output. This prevents a
        caller from pairing a Manifest with a different or stale inspection.
        """

        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")
        if not isinstance(inspection, FrameworkInspectionResult):
            raise TypeError("inspection must be FrameworkInspectionResult")

        records = self._pair_sources(manifest, inspection)
        skill_records = tuple(
            record
            for record in records
            if FrameworkAssetRole.SKILL in record.record.asset.roles
        )
        mcp_records = tuple(
            record
            for record in records
            if FrameworkAssetRole.MCP_CONFIG in record.record.asset.roles
        )

        skill_ids = self._allocate_ids(
            _IdCandidate(
                key=("skill", *record.key),
                base_id=f"skill:{self._id_label(self._skill_name(record))}",
            )
            for record in skill_records
        )
        server_candidates = tuple(
            self._server_id_candidate(record, server)
            for record in mcp_records
            for server in self._mcp_servers(record)
        )
        server_ids = self._allocate_ids(server_candidates)

        tools: list[ManifestTool] = []
        relations: list[ManifestRelation] = []
        tool_candidates: list[_ToolCandidate] = []
        relation_candidates: list[_RelationCandidate] = []

        for record in skill_records:
            skill_key = ("skill", *record.key)
            skill_id = skill_ids[skill_key]
            tools.append(
                ManifestTool(
                    tool_id=skill_id,
                    name=self._skill_name(record),
                    kind=ManifestToolKind.SKILL,
                    availability=ManifestToolAvailability.DECLARED,
                    side_effects=(ManifestToolSideEffect.UNKNOWN,),
                    sources=(record.source_reference,),
                )
            )
            relation_candidates.append(
                _RelationCandidate(
                    key=("uses_skill", *skill_key),
                    base_id=f"relation:uses-skill:{skill_id}",
                    kind=ManifestRelationKind.USES_SKILL,
                    target_key=skill_key,
                    state=ManifestRelationState.DECLARED,
                    sources=(record.source_reference,),
                )
            )

        for record in mcp_records:
            for server in self._mcp_servers(record):
                server_key = self._server_key(record, server)
                server_id = server_ids[server_key]
                server_reference = self._server_reference(record, server)
                tools.append(
                    ManifestTool(
                        tool_id=server_id,
                        name=self._label(server.name),
                        kind=ManifestToolKind.MCP_SERVER,
                        availability=self._server_availability(server),
                        side_effects=self._server_side_effects(server),
                        sources=(server_reference,),
                    )
                )
                relation_candidates.append(
                    _RelationCandidate(
                        key=("uses_mcp", *server_key),
                        base_id=f"relation:uses-mcp:{server_id}",
                        kind=ManifestRelationKind.USES_MCP,
                        target_key=server_key,
                        state=ManifestRelationState.DECLARED,
                        sources=(server_reference,),
                    )
                )
                tool_candidates.extend(
                    self._mcp_tool_candidates(
                        record,
                        server,
                        server_key=server_key,
                        server_id=server_id,
                    )
                )

        tool_ids = self._allocate_ids(
            _IdCandidate(key=candidate.key, base_id=candidate.base_id)
            for candidate in tool_candidates
        )
        for candidate in tool_candidates:
            parent_id = (
                None
                if candidate.parent_key is None
                else server_ids[candidate.parent_key]
            )
            tool_id = tool_ids[candidate.key]
            tools.append(
                ManifestTool(
                    tool_id=tool_id,
                    name=candidate.name,
                    kind=candidate.kind,
                    availability=candidate.availability,
                    side_effects=candidate.side_effects,
                    parent_tool_id=parent_id,
                    sources=candidate.sources,
                )
            )
            relation_candidates.append(
                _RelationCandidate(
                    key=("uses_tool", *candidate.key),
                    base_id=f"relation:uses-tool:{tool_id}",
                    kind=ManifestRelationKind.USES_TOOL,
                    target_key=candidate.key,
                    state=ManifestRelationState.DECLARED,
                    sources=candidate.sources,
                )
            )

        relation_ids = self._allocate_ids(
            _IdCandidate(key=relation.key, base_id=relation.base_id)
            for relation in relation_candidates
        )
        for relation in relation_candidates:
            relations.append(
                ManifestRelation(
                    relation_id=relation_ids[relation.key],
                    source_agent_id=manifest.identity.agent_id,
                    kind=relation.kind,
                    target_id=self._target_id(
                        relation.target_key,
                        skill_ids=skill_ids,
                        server_ids=server_ids,
                        tool_ids=tool_ids,
                    ),
                    state=relation.state,
                    sources=relation.sources,
                )
            )

        tools = sorted(tools, key=lambda tool: tool.tool_id)
        relations = sorted(relations, key=lambda relation: relation.relation_id)
        payload = manifest.model_dump(mode="python")
        if skill_records or mcp_records:
            resolution = (
                ManifestResolutionStatus.PARTIAL
                if not manifest.coverage.complete
                else ManifestResolutionStatus.RESOLVED
            )
            payload["tools"] = ManifestToolProfile(
                resolution=resolution,
                declaration_sources=manifest.tools.declaration_sources,
                tools=tuple(tools),
            ).model_dump(mode="python")
            payload["relationships"] = ManifestRelationshipProfile(
                resolution=resolution,
                declaration_sources=manifest.relationships.declaration_sources,
                relations=tuple(relations),
            ).model_dump(mode="python")

        return AgentManifest.model_validate(payload)

    @staticmethod
    def _pair_sources(
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> tuple[_SourceRecord, ...]:
        manifest_sources = {
            source.locator.sort_key(): source for source in manifest.sources
        }
        records: list[_SourceRecord] = []
        inspection_keys: set[tuple[str, str, str]] = set()
        for record in inspection.assets:
            asset = record.asset
            key = (
                asset.locator.scope.value,
                asset.locator.root_id,
                asset.locator.path,
            )
            inspection_keys.add(key)
            source = manifest_sources.get(key)
            if source is None:
                raise AssociationExtractionError(
                    "inspection assets do not match Manifest sources."
                )
            if (
                source.format.value != asset.format.value
                or set(role.value for role in source.roles)
                != set(role.value for role in asset.roles)
                or source.content_sha256 != asset.content_sha256
                or source.size_bytes != asset.size_bytes
                or source.line_count != asset.line_count
                or source.precedence_rank != asset.precedence_rank
            ):
                raise AssociationExtractionError(
                    "inspection asset metadata does not match Manifest source."
                )
            records.append(
                _SourceRecord(
                    record=record,
                    source_reference=ManifestSourceReference(locator=source.locator),
                )
            )
        if inspection_keys != set(manifest_sources):
            raise AssociationExtractionError(
                "inspection coverage does not match Manifest source inventory."
            )
        return tuple(sorted(records, key=lambda item: item.key))

    @staticmethod
    def _mcp_servers(
        record: _SourceRecord,
    ) -> tuple[McpServerDeclaration, ...]:
        configuration: ParsedMcpConfiguration | None = record.record.mcp_configuration
        if configuration is None:
            raise AssociationExtractionError(
                "MCP source is missing its parsed declaration."
            )
        return configuration.servers

    @staticmethod
    def _skill_name(record: _SourceRecord) -> str:
        path = PurePosixPath(record.record.asset.locator.path)
        if path.name != "SKILL.md" or path.parent == PurePosixPath("."):
            raise AssociationExtractionError(
                "Skill source path does not identify a Skill directory."
            )
        return AssociationExtractor._label(path.parent.name)

    @staticmethod
    def _server_key(
        record: _SourceRecord,
        server: McpServerDeclaration,
    ) -> tuple[str, ...]:
        return (
            "mcp-server",
            *record.key,
            format_structured_path(server.scope_path),
            server.name,
        )

    @classmethod
    def _server_id_candidate(
        cls,
        record: _SourceRecord,
        server: McpServerDeclaration,
    ) -> _IdCandidate:
        key = cls._server_key(record, server)
        return _IdCandidate(
            key=key,
            base_id=f"mcp-server:{cls._id_label(server.name)}",
        )

    @staticmethod
    def _server_reference(
        record: _SourceRecord,
        server: McpServerDeclaration,
    ) -> ManifestSourceReference:
        return ManifestSourceReference(
            locator=record.source_reference.locator,
            field_path=format_structured_path(server.scope_path + (server.name,)),
            start_line=server.start_line,
            end_line=server.end_line,
        )

    @staticmethod
    def _server_availability(
        server: McpServerDeclaration,
    ) -> ManifestToolAvailability:
        if server.enabled_declaration is None:
            return ManifestToolAvailability.DECLARED
        return (
            ManifestToolAvailability.ENABLED
            if server.enabled
            else ManifestToolAvailability.DISABLED
        )

    @staticmethod
    def _server_side_effects(
        server: McpServerDeclaration,
    ) -> tuple[ManifestToolSideEffect, ...]:
        if server.transport is McpTransport.STDIO:
            return (ManifestToolSideEffect.EXECUTE,)
        if server.transport is McpTransport.STREAMABLE_HTTP:
            return (ManifestToolSideEffect.NETWORK,)
        return (ManifestToolSideEffect.UNKNOWN,)

    @classmethod
    def _mcp_tool_candidates(
        cls,
        record: _SourceRecord,
        server: McpServerDeclaration,
        *,
        server_key: tuple[str, ...],
        server_id: str,
    ) -> tuple[_ToolCandidate, ...]:
        declarations: dict[str, list[ManifestSourceReference]] = defaultdict(list)
        enabled_names: set[str] = set()
        disabled_names: set[str] = set()

        for declaration in server.enabled_tools:
            enabled_names.add(declaration.value)
            declarations[declaration.value].append(
                cls._value_reference(record, declaration)
            )
        for declaration in server.disabled_tools:
            disabled_names.add(declaration.value)
            declarations[declaration.value].append(
                cls._value_reference(record, declaration)
            )
        for policy in server.tool_policies:
            declarations[policy.tool_name].append(
                cls._value_reference(record, policy.approval_mode)
            )

        candidates: list[_ToolCandidate] = []
        for raw_name in sorted(declarations):
            if raw_name in enabled_names and raw_name in disabled_names:
                availability = ManifestToolAvailability.UNKNOWN
            elif raw_name in enabled_names:
                availability = ManifestToolAvailability.ENABLED
            elif raw_name in disabled_names:
                availability = ManifestToolAvailability.DISABLED
            else:
                availability = ManifestToolAvailability.DECLARED
            key = ("mcp-tool", *server_key[1:], raw_name)
            candidates.append(
                _ToolCandidate(
                    key=key,
                    base_id=(
                        f"mcp-tool:{server_id.removeprefix('mcp-server:')}"
                        f":{cls._id_label(raw_name)}"
                    ),
                    name=cls._label(raw_name),
                    kind=ManifestToolKind.MCP_TOOL,
                    availability=availability,
                    side_effects=(ManifestToolSideEffect.UNKNOWN,),
                    parent_key=server_key,
                    sources=cls._sorted_references(declarations[raw_name]),
                )
            )
        return tuple(candidates)

    @staticmethod
    def _value_reference[T](
        record: _SourceRecord,
        value: SourceBackedValue[T],
    ) -> ManifestSourceReference:
        return ManifestSourceReference(
            locator=record.source_reference.locator,
            field_path=format_structured_path(value.path),
            start_line=value.start_line,
            end_line=value.end_line,
        )

    @staticmethod
    def _sorted_references(
        references: Iterable[ManifestSourceReference],
    ) -> tuple[ManifestSourceReference, ...]:
        unique = {reference.sort_key(): reference for reference in references}
        return tuple(unique[key] for key in sorted(unique))

    @staticmethod
    def _target_id(
        target_key: tuple[str, ...],
        *,
        skill_ids: dict[tuple[str, ...], str],
        server_ids: dict[tuple[str, ...], str],
        tool_ids: dict[tuple[str, ...], str],
    ) -> str:
        if target_key[0] == "skill":
            return skill_ids[target_key]
        if target_key[0] == "mcp-server":
            return server_ids[target_key]
        if target_key[0] == "mcp-tool":
            return tool_ids[target_key]
        if target_key in tool_ids:
            return tool_ids[target_key]
        raise AssociationExtractionError(
            "relationship target is not in tool inventory."
        )

    @classmethod
    def _allocate_ids(
        cls,
        candidates: Iterable[_IdCandidate],
    ) -> dict[tuple[str, ...], str]:
        ordered = sorted(candidates, key=lambda candidate: candidate.key)
        by_base: dict[str, list[_IdCandidate]] = defaultdict(list)
        for candidate in ordered:
            by_base[candidate.base_id].append(candidate)
        result: dict[tuple[str, ...], str] = {}
        used: dict[str, tuple[str, ...]] = {}
        for base_id in sorted(by_base):
            group = by_base[base_id]
            for candidate in group:
                identifier = base_id
                if len(group) > 1 or len(base_id) > 128:
                    identifier = cls._with_digest(base_id, candidate.key)
                if identifier in used and used[identifier] != candidate.key:
                    raise AssociationExtractionError(
                        "stable association identifiers collide."
                    )
                if not _STABLE_ID_PATTERN.fullmatch(identifier):
                    raise AssociationExtractionError(
                        "stable association identifier could not be normalized."
                    )
                used[identifier] = candidate.key
                result[candidate.key] = identifier
        return result

    @staticmethod
    def _with_digest(base_id: str, key: tuple[str, ...]) -> str:
        digest = hashlib.sha256("\x00".join(key).encode("utf-8")).hexdigest()[
            :_ID_DIGEST_LENGTH
        ]
        suffix = f":{digest}"
        if len(base_id) + len(suffix) <= 128:
            return f"{base_id}{suffix}"
        return f"{base_id[: 128 - len(suffix)]}{suffix}"

    @staticmethod
    def _label(value: str) -> str:
        """Return bounded reader-facing metadata without control characters."""

        normalized = unicodedata.normalize("NFKC", value)
        normalized = _CONTROL_PATTERN.sub("-", normalized)
        normalized = _DISPLAY_SEPARATOR_PATTERN.sub("-", normalized)
        normalized = normalized.strip("._-")
        if not normalized:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[
                :_ID_DIGEST_LENGTH
            ]
            return f"item-{digest}"
        return normalized[:_MAX_COMPONENT_LENGTH]

    @staticmethod
    def _id_label(value: str) -> str:
        """Return an ASCII component accepted by the Manifest stable-ID grammar."""

        normalized = unicodedata.normalize("NFKC", value)
        normalized = _COMPONENT_PATTERN.sub("-", normalized)
        normalized = normalized.strip("._-")
        if not normalized:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[
                :_ID_DIGEST_LENGTH
            ]
            return f"item-{digest}"
        return normalized[:_MAX_COMPONENT_LENGTH]


class AssociationResolver(AssociationExtractor):
    """Compatibility name for callers that model P2-08 as a Resolver step."""

"""Deterministic Sub-Agent and memory relationship extraction.

P2-10 recognizes only explicit, safe frontmatter declarations. Markdown text,
links, and referenced paths are not dereferenced or treated as relationships by
proximity. The extractor produces declared/unknown relationship facts and keeps
all values bounded and source-backed.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from agentsec.frameworks import (
    FrameworkAssetFormat,
    FrameworkInspectionResult,
)
from agentsec.manifests.associations import (
    AssociationExtractor,
)
from agentsec.manifests.enums import (
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResolutionStatus,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestRelation,
    ManifestRelationshipProfile,
    ManifestSourceReference,
)
from agentsec.parsers import (
    FrontmatterField,
    FrontmatterStatus,
    ParsedMarkdown,
    format_structured_path,
)

_SAFE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_PATTERN = re.compile(r"[\s/\\]+")
_DIGEST_LENGTH = 12
_MAX_ID_LENGTH = 128

_DELEGATION_FIELDS = frozenset(
    {
        "delegate_to",
        "delegates_to",
        "sub_agent",
        "sub_agents",
        "subagent",
        "subagents",
    }
)
_MEMORY_FIELDS = {
    "memory_read": ManifestRelationKind.READS_MEMORY,
    "memory_reads": ManifestRelationKind.READS_MEMORY,
    "reads_memory": ManifestRelationKind.READS_MEMORY,
    "memory_write": ManifestRelationKind.WRITES_MEMORY,
    "memory_writes": ManifestRelationKind.WRITES_MEMORY,
    "writes_memory": ManifestRelationKind.WRITES_MEMORY,
    "memory_persist": ManifestRelationKind.PERSISTS_MEMORY,
    "memory_persists": ManifestRelationKind.PERSISTS_MEMORY,
    "persists_memory": ManifestRelationKind.PERSISTS_MEMORY,
    "persistent_memory": ManifestRelationKind.PERSISTS_MEMORY,
}
_MEMORY_CONTAINER_FIELD = "memory"
_MEMORY_CONTAINER_KEYS = {
    "read": ManifestRelationKind.READS_MEMORY,
    "reads": ManifestRelationKind.READS_MEMORY,
    "write": ManifestRelationKind.WRITES_MEMORY,
    "writes": ManifestRelationKind.WRITES_MEMORY,
    "persist": ManifestRelationKind.PERSISTS_MEMORY,
    "persists": ManifestRelationKind.PERSISTS_MEMORY,
    "persistent": ManifestRelationKind.PERSISTS_MEMORY,
}


class RelationshipExtractionError(RuntimeError):
    """Safe failure for invalid or inconsistent relationship extraction input."""


@dataclass(frozen=True, slots=True)
class _RelationshipCandidate:
    """One normalized relationship before source merging and ID assignment."""

    kind: ManifestRelationKind
    target_id: str
    state: ManifestRelationState
    source: ManifestSourceReference

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind.value, self.target_id)


class RelationshipExtractor:
    """Extract explicit Sub-Agent and memory relations from safe frontmatter."""

    def extract(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest:
        """Associate declarations, then extract Sub-Agent/memory relations."""

        self._validate_inputs(manifest, inspection)
        associated = AssociationExtractor().extract(manifest, inspection)
        return self.extract_associated(associated, inspection)

    def extract_associated(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest:
        """Extract relationships from an already-associated Manifest."""

        self._validate_inputs(manifest, inspection)
        self._validate_associated(manifest)
        associated = manifest
        records = AssociationExtractor._pair_sources(associated, inspection)
        candidates: list[_RelationshipCandidate] = []
        uncertain = False
        recognized_declaration = False

        for record in records:
            if record.record.asset.format is not FrameworkAssetFormat.MARKDOWN:
                continue
            document = record.record.document
            if not isinstance(document, ParsedMarkdown):
                raise RelationshipExtractionError(
                    "Markdown relationship source is missing its parsed document."
                )
            frontmatter = document.frontmatter
            if frontmatter is None:
                continue
            if frontmatter.status is not FrontmatterStatus.VALID:
                uncertain = True
                continue

            for field in frontmatter.fields:
                declarations = self._field_declarations(
                    record.source_reference,
                    field,
                )
                if declarations is None:
                    continue
                recognized_declaration = True
                field_candidates, field_uncertain = self._extract_field(
                    record.source_reference,
                    field,
                    declarations,
                )
                candidates.extend(field_candidates)
                uncertain |= field_uncertain

        merged = self._merge_candidates(candidates)
        relations = self._merge_existing_relations(
            associated.identity.agent_id,
            associated.relationships.relations,
            merged,
        )
        if associated.relationships.declaration_sources:
            resolution = self._resolution(
                associated.relationships.resolution,
                associated.coverage.complete,
                recognized_declaration,
                bool(relations),
                uncertain,
            )
            profile = ManifestRelationshipProfile(
                resolution=resolution,
                declaration_sources=associated.relationships.declaration_sources,
                relations=relations,
            )
            payload = associated.model_dump(mode="python")
            payload["relationships"] = profile.model_dump(mode="python")
            return AgentManifest.model_validate(payload)
        return associated

    @staticmethod
    def _validate_inputs(
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> None:
        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")
        if not isinstance(inspection, FrameworkInspectionResult):
            raise TypeError("inspection must be FrameworkInspectionResult")

    @staticmethod
    def _validate_associated(manifest: AgentManifest) -> None:
        if (
            manifest.tools.declaration_sources
            and manifest.tools.resolution is ManifestResolutionStatus.UNRESOLVED
        ):
            raise RelationshipExtractionError(
                "Manifest tool associations must be extracted first."
            )

    @classmethod
    def _field_declarations(
        cls,
        source: ManifestSourceReference,
        field: FrontmatterField,
    ) -> tuple[tuple[ManifestRelationKind, object, str], ...] | None:
        del source
        if field.name in _DELEGATION_FIELDS:
            return ((ManifestRelationKind.DELEGATES_TO, field.value, field.name),)
        if field.name in _MEMORY_FIELDS:
            return ((_MEMORY_FIELDS[field.name], field.value, field.name),)
        if field.name != _MEMORY_CONTAINER_FIELD:
            return None
        mapping = cls._as_mapping(field.value)
        if mapping is None:
            return ((ManifestRelationKind.OTHER, field.value, field.name),)
        declarations: list[tuple[ManifestRelationKind, object, str]] = []
        for key, value in mapping:
            relation_kind = _MEMORY_CONTAINER_KEYS.get(key)
            if relation_kind is None:
                continue
            declarations.append((relation_kind, value, f"{field.name}.{key}"))
        return tuple(declarations) if declarations else None

    @classmethod
    def _extract_field(
        cls,
        source: ManifestSourceReference,
        field: FrontmatterField,
        declarations: tuple[tuple[ManifestRelationKind, object, str], ...],
    ) -> tuple[tuple[_RelationshipCandidate, ...], bool]:
        candidates: list[_RelationshipCandidate] = []
        uncertain = False
        for relation_kind, value, field_key in declarations:
            field_source = cls._field_reference(source, field, field_key)
            values = cls._string_values(value)
            if values is None or not values:
                uncertain = True
                candidates.append(
                    _RelationshipCandidate(
                        kind=relation_kind,
                        target_id=cls._unknown_target(relation_kind, field_source),
                        state=ManifestRelationState.UNKNOWN,
                        source=field_source,
                    )
                )
                continue
            for index, raw_value in enumerate(values):
                item_source = cls._indexed_reference(field_source, index)
                target_kind = relation_kind
                target_id, safe = cls._target_id(target_kind, raw_value, item_source)
                candidates.append(
                    _RelationshipCandidate(
                        kind=target_kind,
                        target_id=target_id,
                        state=(
                            ManifestRelationState.DECLARED
                            if safe
                            else ManifestRelationState.UNKNOWN
                        ),
                        source=item_source,
                    )
                )
                uncertain |= not safe
        return tuple(candidates), uncertain

    @staticmethod
    def _string_values(value: object) -> tuple[str, ...] | None:
        if isinstance(value, str):
            return (value,) if value else ()
        if isinstance(value, tuple):
            values: list[str] = []
            for item in value:
                if not isinstance(item, str):
                    return None
                values.append(item)
            return tuple(values)
        return None

    @staticmethod
    def _as_mapping(value: object) -> tuple[tuple[str, object], ...] | None:
        if not isinstance(value, tuple):
            return None
        result: list[tuple[str, object]] = []
        for item in value:
            if not isinstance(item, tuple) or len(item) != 2:
                return None
            key, nested_value = item
            if not isinstance(key, str):
                return None
            result.append((key, nested_value))
        return tuple(result)

    @staticmethod
    def _field_reference(
        source: ManifestSourceReference,
        field: FrontmatterField,
        field_key: str,
    ) -> ManifestSourceReference:
        parts = ("frontmatter", *field_key.split("."))
        return ManifestSourceReference(
            locator=source.locator,
            field_path=format_structured_path(parts),
            start_line=field.start_line,
            end_line=field.end_line,
        )

    @staticmethod
    def _indexed_reference(
        reference: ManifestSourceReference,
        index: int,
    ) -> ManifestSourceReference:
        field_path = reference.field_path or "$"
        return ManifestSourceReference(
            locator=reference.locator,
            field_path=f"{field_path}[{index}]",
            start_line=reference.start_line,
            end_line=reference.end_line,
        )

    @classmethod
    def _target_id(
        cls,
        kind: ManifestRelationKind,
        raw_value: str,
        source: ManifestSourceReference,
    ) -> tuple[str, bool]:
        prefix = cls._target_prefix(kind)
        normalized = unicodedata.normalize("NFKC", raw_value)
        normalized = normalized.removeprefix(f"{prefix}:")
        normalized = normalized.removeprefix("sub-agent:")
        normalized = normalized.removeprefix("subagent:")
        normalized = (
            normalized.removeprefix("agent:")
            if prefix == "agent"
            else normalized.removeprefix("memory:")
        )
        if _SAFE_TARGET_PATTERN.fullmatch(normalized) is not None:
            return f"{prefix}:{normalized}", True
        return cls._unknown_target(kind, source, raw_value=raw_value), False

    @staticmethod
    def _target_prefix(kind: ManifestRelationKind) -> str:
        if kind is ManifestRelationKind.DELEGATES_TO:
            return "agent"
        if kind in {
            ManifestRelationKind.READS_MEMORY,
            ManifestRelationKind.WRITES_MEMORY,
            ManifestRelationKind.PERSISTS_MEMORY,
        }:
            return "memory"
        return "relation"

    @classmethod
    def _unknown_target(
        cls,
        kind: ManifestRelationKind,
        source: ManifestSourceReference,
        *,
        raw_value: str | None = None,
    ) -> str:
        digest_input = "\x00".join(
            (
                kind.value,
                source.locator.scope.value,
                source.locator.root_id,
                source.locator.path,
                source.field_path or "",
                raw_value or "",
            )
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[
            :_DIGEST_LENGTH
        ]
        return f"{cls._target_prefix(kind)}:unknown:{digest}"

    @classmethod
    def _merge_candidates(
        cls,
        candidates: Iterable[_RelationshipCandidate],
    ) -> tuple[_RelationshipCandidate, ...]:
        grouped: dict[tuple[str, str], list[_RelationshipCandidate]] = defaultdict(list)
        for candidate in candidates:
            grouped[candidate.key].append(candidate)
        merged: list[_RelationshipCandidate] = []
        for key in sorted(grouped):
            group = grouped[key]
            first = group[0]
            state = (
                ManifestRelationState.UNKNOWN
                if any(item.state is ManifestRelationState.UNKNOWN for item in group)
                else ManifestRelationState.DECLARED
            )
            for source in cls._sorted_references(item.source for item in group):
                merged.append(
                    _RelationshipCandidate(
                        kind=first.kind,
                        target_id=first.target_id,
                        state=state,
                        source=source,
                    )
                )
        return tuple(merged)

    @classmethod
    def _merge_existing_relations(
        cls,
        agent_id: str,
        existing: tuple[ManifestRelation, ...],
        candidates: tuple[_RelationshipCandidate, ...],
    ) -> tuple[ManifestRelation, ...]:
        by_key: dict[tuple[str, str], ManifestRelation] = {
            (relation.kind.value, relation.target_id): relation for relation in existing
        }
        for key in sorted({candidate.key for candidate in candidates}):
            group = tuple(candidate for candidate in candidates if candidate.key == key)
            first = group[0]
            relation_id = cls._relation_id(first.kind, first.target_id)
            previous = by_key.get(key)
            sources = cls._sorted_references(
                (
                    *(() if previous is None else previous.sources),
                    *(item.source for item in group),
                )
            )
            state = (
                ManifestRelationState.UNKNOWN
                if previous is not None
                and previous.state is ManifestRelationState.UNKNOWN
                or any(item.state is ManifestRelationState.UNKNOWN for item in group)
                else first.state
                if previous is None
                else previous.state
            )
            by_key[key] = ManifestRelation(
                relation_id=relation_id,
                source_agent_id=agent_id,
                kind=first.kind,
                target_id=first.target_id,
                state=state,
                sources=sources,
            )
        return tuple(sorted(by_key.values(), key=lambda relation: relation.relation_id))

    @staticmethod
    def _relation_id(kind: ManifestRelationKind, target_id: str) -> str:
        base = f"relation:{kind.value}:{target_id}"
        if len(base) <= _MAX_ID_LENGTH:
            return base
        digest = hashlib.sha256(base.encode("utf-8")).hexdigest()[:_DIGEST_LENGTH]
        suffix = f":{digest}"
        return f"{base[: _MAX_ID_LENGTH - len(suffix)]}{suffix}"

    @staticmethod
    def _sorted_references(
        references: Iterable[ManifestSourceReference],
    ) -> tuple[ManifestSourceReference, ...]:
        unique = {reference.sort_key(): reference for reference in references}
        return tuple(unique[key] for key in sorted(unique))

    @staticmethod
    def _resolution(
        current: ManifestResolutionStatus,
        coverage_complete: bool,
        recognized_declaration: bool,
        has_relations: bool,
        uncertain: bool,
    ) -> ManifestResolutionStatus:
        if uncertain or not coverage_complete:
            return ManifestResolutionStatus.PARTIAL
        if recognized_declaration and has_relations:
            return ManifestResolutionStatus.RESOLVED
        if current is ManifestResolutionStatus.RESOLVED:
            return current
        return current


class RelationshipResolver(RelationshipExtractor):
    """Compatibility name for callers that model P2-10 as a Resolver step."""

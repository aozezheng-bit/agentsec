"""Deterministic materialization of explicit Manifest Unknown facts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from agentsec.manifests.enums import (
    ManifestResolutionStatus,
    ManifestUnknownDimension,
    ManifestUnknownReason,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestSourceReference,
    ManifestUnknown,
)

_DIGEST_LENGTH = 16
_MAX_ID_LENGTH = 128


class UnknownExtractionError(RuntimeError):
    """Safe failure for invalid Unknown materialization input."""


@dataclass(frozen=True, slots=True)
class _UnknownCandidate:
    """One explicit unresolved fact before stable ID assignment."""

    dimension: ManifestUnknownDimension
    reason: ManifestUnknownReason
    field: str
    sources: tuple[ManifestSourceReference, ...]

    @property
    def key(
        self,
    ) -> tuple[str, str, str, tuple[tuple[str, str, str, str, int, int], ...]]:
        return (
            self.dimension.value,
            self.reason.value,
            self.field,
            tuple(source.sort_key() for source in self.sources),
        )


class UnknownExtractor:
    """Populate explicit Unknown entries without changing profile semantics."""

    def extract(self, manifest: AgentManifest) -> AgentManifest:
        """Return a new Manifest with deterministic explicit Unknown facts."""

        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")

        candidates = list(self._profile_unknowns(manifest))
        candidates.extend(self._item_unknowns(manifest))
        if not manifest.coverage.complete:
            candidates.append(
                _UnknownCandidate(
                    dimension=ManifestUnknownDimension.COVERAGE,
                    reason=ManifestUnknownReason.INCOMPLETE_COVERAGE,
                    field="coverage",
                    sources=(),
                )
            )

        generated = tuple(
            self._materialize(candidate)
            for candidate in sorted(candidates, key=lambda item: item.key)
        )
        by_id: dict[str, ManifestUnknown] = {
            unknown.unknown_id: unknown for unknown in manifest.unknowns
        }
        for unknown in generated:
            by_id.setdefault(unknown.unknown_id, unknown)

        payload = manifest.model_dump(mode="python")
        payload["unknowns"] = tuple(by_id[unknown_id] for unknown_id in sorted(by_id))
        return AgentManifest.model_validate(payload)

    def _profile_unknowns(
        self,
        manifest: AgentManifest,
    ) -> tuple[_UnknownCandidate, ...]:
        candidates: list[_UnknownCandidate] = []
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.IDENTITY,
            manifest.identity.resolution,
            "identity.resolution",
            manifest.identity.sources,
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.INSTRUCTIONS,
            manifest.instructions.resolution,
            "instructions.resolution",
            tuple(candidate.source for candidate in manifest.instructions.candidates),
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.TOOLS,
            manifest.tools.resolution,
            "tools.resolution",
            manifest.tools.declaration_sources,
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.PERMISSIONS,
            manifest.permissions.resolution,
            "permissions.resolution",
            manifest.permissions.declaration_sources,
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.CONTROLS,
            manifest.controls.resolution,
            "controls.resolution",
            manifest.controls.declaration_sources,
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.RUNTIME_IDENTITIES,
            manifest.runtime_identities.resolution,
            "runtime_identities.resolution",
            manifest.runtime_identities.declaration_sources,
            manifest.coverage.complete,
        )
        self._append_profile_unknown(
            candidates,
            ManifestUnknownDimension.RELATIONSHIPS,
            manifest.relationships.resolution,
            "relationships.resolution",
            manifest.relationships.declaration_sources,
            manifest.coverage.complete,
        )
        return tuple(candidates)

    @staticmethod
    def _append_profile_unknown(
        candidates: list[_UnknownCandidate],
        dimension: ManifestUnknownDimension,
        status: ManifestResolutionStatus,
        field: str,
        sources: tuple[ManifestSourceReference, ...],
        coverage_complete: bool,
    ) -> None:
        if status in {
            ManifestResolutionStatus.RESOLVED,
            ManifestResolutionStatus.NOT_APPLICABLE,
        }:
            return
        if status is ManifestResolutionStatus.CONFLICT:
            reason = ManifestUnknownReason.CONFLICTING_DECLARATIONS
        elif status is ManifestResolutionStatus.PARTIAL:
            reason = (
                ManifestUnknownReason.INCOMPLETE_COVERAGE
                if not coverage_complete
                else ManifestUnknownReason.UNSUPPORTED_FIELD
            )
        elif status is ManifestResolutionStatus.UNKNOWN:
            reason = (
                ManifestUnknownReason.MISSING_SOURCE
                if not sources
                else ManifestUnknownReason.NOT_ANALYZED
            )
        else:
            reason = ManifestUnknownReason.NOT_ANALYZED
        candidates.append(
            _UnknownCandidate(
                dimension=dimension,
                reason=reason,
                field=field,
                sources=UnknownExtractor._sorted_sources(sources),
            )
        )

    @staticmethod
    def _item_unknowns(
        manifest: AgentManifest,
    ) -> tuple[_UnknownCandidate, ...]:
        candidates: list[_UnknownCandidate] = []
        for tool in manifest.tools.tools:
            if tool.availability.value == "unknown":
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.TOOLS,
                        ManifestUnknownReason.UNSUPPORTED_FIELD,
                        f"tools.{tool.tool_id}.availability",
                        tool.sources,
                    )
                )
            if "unknown" in {effect.value for effect in tool.side_effects}:
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.TOOLS,
                        ManifestUnknownReason.UNSUPPORTED_FIELD,
                        f"tools.{tool.tool_id}.side_effects",
                        tool.sources,
                    )
                )

        for permission in manifest.permissions.permissions:
            if permission.effect.value == "unknown":
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.PERMISSIONS,
                        ManifestUnknownReason.UNSUPPORTED_FIELD,
                        f"permissions.{permission.permission_id}.effect",
                        permission.sources,
                    )
                )
            for field, value in (
                ("action", permission.action.value),
                ("resource", permission.resource.value),
                ("scope", permission.scope.value),
            ):
                if value == "unknown":
                    candidates.append(
                        _UnknownCandidate(
                            ManifestUnknownDimension.PERMISSIONS,
                            ManifestUnknownReason.UNSUPPORTED_FIELD,
                            f"permissions.{permission.permission_id}.{field}",
                            permission.sources,
                        )
                    )

        for control in manifest.controls.controls:
            if control.state.value == "unknown":
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.CONTROLS,
                        ManifestUnknownReason.UNSUPPORTED_FIELD,
                        f"controls.{control.control_id}.state",
                        control.sources,
                    )
                )

        for identity in manifest.runtime_identities.identities:
            for field, value, reason in (
                (
                    "principal_kind",
                    identity.principal_kind.value,
                    ManifestUnknownReason.UNSUPPORTED_FIELD,
                ),
                (
                    "authentication",
                    identity.authentication.value,
                    ManifestUnknownReason.UNSUPPORTED_FIELD,
                ),
                (
                    "environment",
                    identity.environment.value,
                    ManifestUnknownReason.UNSUPPORTED_FIELD,
                ),
            ):
                if value == "unknown":
                    candidates.append(
                        _UnknownCandidate(
                            ManifestUnknownDimension.RUNTIME_IDENTITIES,
                            reason,
                            f"runtime_identities.{identity.identity_id}.{field}",
                            identity.sources,
                        )
                    )
            if identity.privileged is None:
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.RUNTIME_IDENTITIES,
                        ManifestUnknownReason.RUNTIME_VERIFICATION_REQUIRED,
                        f"runtime_identities.{identity.identity_id}.privileged",
                        identity.sources,
                    )
                )

        for relation in manifest.relationships.relations:
            if relation.state.value == "unknown":
                candidates.append(
                    _UnknownCandidate(
                        ManifestUnknownDimension.RELATIONSHIPS,
                        ManifestUnknownReason.UNSUPPORTED_FIELD,
                        f"relationships.{relation.relation_id}.state",
                        relation.sources,
                    )
                )
        return tuple(candidates)

    @staticmethod
    def _materialize(candidate: _UnknownCandidate) -> ManifestUnknown:
        digest_input = "\x00".join(
            (
                candidate.dimension.value,
                candidate.reason.value,
                candidate.field,
                *(
                    "\x00".join(str(part) for part in source.sort_key())
                    for source in candidate.sources
                ),
            )
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[
            :_DIGEST_LENGTH
        ]
        unknown_id = f"unknown:{candidate.dimension.value}:{digest}"
        if len(unknown_id) > _MAX_ID_LENGTH:
            unknown_id = unknown_id[:_MAX_ID_LENGTH]
        return ManifestUnknown(
            unknown_id=unknown_id,
            dimension=candidate.dimension,
            reason=candidate.reason,
            field=candidate.field,
            sources=candidate.sources,
        )

    @staticmethod
    def _sorted_sources(
        sources: Iterable[ManifestSourceReference],
    ) -> tuple[ManifestSourceReference, ...]:
        unique = {source.sort_key(): source for source in sources}
        return tuple(unique[key] for key in sorted(unique))


class UnknownResolver(UnknownExtractor):
    """Compatibility name for callers that model P2-11 as a Resolver step."""

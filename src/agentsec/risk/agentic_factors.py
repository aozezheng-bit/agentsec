"""Deterministic, evidence-backed Agentic Factor extraction (P2-18).

This module deliberately stops at a versioned factor vector.  It does not
calculate Technical, Drift, Governance, or Overall scores.  Those later
models consume this vector and must not reinterpret raw Manifest values.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal

from agentsec.domain import EvidenceConfidence
from agentsec.manifests import (
    AgentManifest,
    ManifestAuthenticationKind,
    ManifestControlKind,
    ManifestControlState,
    ManifestEnvironmentKind,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestSourceLocator,
    ManifestSourceReference,
    ManifestTool,
    ManifestToolAvailability,
    ManifestToolSideEffect,
    ManifestUnknown,
    ManifestUnknownDimension,
    encode_agent_manifest_json,
)
from agentsec.versioning import AGENTIC_FACTOR_MODEL_VERSION

AGENTIC_FACTOR_FORMAT: Literal["agentsec-agentic-factor-vector"] = (
    "agentsec-agentic-factor-vector"
)
AGENTIC_FACTOR_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
AGENTIC_FACTOR_BASIS = (
    "AgentSec P2-18 deterministic Manifest-to-Agentic-Factor contract 0.1.0",
    "Static declarations are evidence of capability intent, not runtime reachability",
    "Evidence Confidence is independent from factor value and later risk scores",
)

FactorValue = float


class AgenticFactorId(StrEnum):
    """Stable dimensions used by the later Agentic Risk scoring model."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    CODE_EXECUTION = "code_execution"
    SECRET_ACCESS = "secret_access"
    EXTERNAL_NETWORK = "external_network"
    PRODUCTION_ACCESS = "production_access"
    PERSISTENT_MEMORY = "persistent_memory"
    SUBAGENT_DELEGATION = "subagent_delegation"
    EXTERNAL_IDENTITY = "external_identity"
    AUTONOMOUS_ACTION = "autonomous_action"
    APPROVAL_BYPASS = "approval_bypass"


_FACTOR_ORDER = tuple(AgenticFactorId)
_MUTATING_ACTIONS = frozenset(
    {
        ManifestPermissionAction.WRITE,
        ManifestPermissionAction.EXECUTE,
        ManifestPermissionAction.ADMIN,
        ManifestPermissionAction.DEPLOY,
        ManifestPermissionAction.PUBLISH,
        ManifestPermissionAction.PERSIST,
    }
)


@dataclass(frozen=True, slots=True)
class AgenticFactorEvidence:
    """Value-free source evidence attached to one factor observation."""

    locator: ManifestSourceLocator
    content_sha256: str
    field_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.locator, ManifestSourceLocator):
            raise TypeError("factor evidence locator must be ManifestSourceLocator")
        if len(self.content_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.content_sha256
        ):
            raise ValueError("factor evidence content_sha256 must be lowercase SHA-256")
        if self.field_path is not None and not self.field_path.strip():
            raise ValueError("factor evidence field_path must not be empty")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("factor evidence line range must be complete")
        if self.start_line is not None and (
            self.start_line < 1
            or self.end_line is None
            or self.end_line < self.start_line
        ):
            raise ValueError("factor evidence line range is invalid")

    def sort_key(self) -> tuple[str, str, str, str, int, int]:
        return (
            *self.locator.sort_key(),
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.locator.scope.value,
            "root_id": self.locator.root_id,
            "path": self.locator.path,
            "field_path": self.field_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class AgenticFactorAssessment:
    """One factor value with independent evidence confidence and limitations."""

    factor_id: AgenticFactorId
    value: FactorValue
    confidence: EvidenceConfidence
    evidence: tuple[AgenticFactorEvidence, ...] = ()
    relevant_unknown_ids: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.factor_id, AgenticFactorId):
            raise TypeError("factor_id must be AgenticFactorId")
        if self.value not in {0.0, 0.5, 1.0}:
            raise ValueError("factor value must be exactly 0.0, 0.5, or 1.0")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("factor confidence must be EvidenceConfidence")
        if any(not isinstance(item, AgenticFactorEvidence) for item in self.evidence):
            raise TypeError("factor evidence contains an invalid item")
        if tuple(item.sort_key() for item in self.evidence) != tuple(
            sorted(item.sort_key() for item in self.evidence)
        ):
            raise ValueError("factor evidence must be sorted")
        if len({item.sort_key() for item in self.evidence}) != len(self.evidence):
            raise ValueError("factor evidence must be unique")
        _validate_string_tuple(self.relevant_unknown_ids, "relevant_unknown_ids")
        _validate_string_tuple(self.rationale, "rationale")
        _validate_string_tuple(self.limitations, "limitations")
        if self.value == 0.5 and not self.limitations:
            raise ValueError("uncertain factor values require limitations")
        if self.confidence is EvidenceConfidence.D and not self.limitations:
            raise ValueError("D-confidence factors require limitations")

    def to_dict(self) -> dict[str, object]:
        return {
            "factor_id": self.factor_id.value,
            "value": self.value,
            "confidence": self.confidence.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "relevant_unknown_ids": list(self.relevant_unknown_ids),
            "rationale": list(self.rationale),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class AgenticFactorVector:
    """Complete deterministic ten-factor vector for one final Manifest."""

    format: Literal["agentsec-agentic-factor-vector"]
    format_version: Literal["0.1.0"]
    model_version: str
    manifest_schema_version: str
    agent_id: str
    manifest_sha256: str
    coverage_complete: bool
    relevant_unknown_count: int
    factors: tuple[AgenticFactorAssessment, ...] = dataclass_field(repr=False)
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if self.format != AGENTIC_FACTOR_FORMAT:
            raise ValueError("factor vector format is unsupported")
        if self.format_version != AGENTIC_FACTOR_FORMAT_VERSION:
            raise ValueError("factor vector format version is unsupported")
        if self.model_version != AGENTIC_FACTOR_MODEL_VERSION:
            raise ValueError("factor model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("factor vector Agent ID must not be empty")
        if len(self.manifest_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.manifest_sha256
        ):
            raise ValueError("factor vector manifest_sha256 must be lowercase SHA-256")
        if self.relevant_unknown_count < 0:
            raise ValueError("relevant_unknown_count must not be negative")
        if tuple(item.factor_id for item in self.factors) != _FACTOR_ORDER:
            raise ValueError(
                "factor vector must contain all ten factors in stable order"
            )
        _validate_unique_strings(self.mapping_basis, "mapping_basis")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "manifest_schema_version": self.manifest_schema_version,
            "agent_id": self.agent_id,
            "manifest_sha256": self.manifest_sha256,
            "coverage_complete": self.coverage_complete,
            "relevant_unknown_count": self.relevant_unknown_count,
            "factors": [item.to_dict() for item in self.factors],
            "mapping_basis": list(self.mapping_basis),
        }


@dataclass(frozen=True, slots=True)
class _Observation:
    positive: tuple[ManifestSourceReference, ...] = ()
    negative: tuple[ManifestSourceReference, ...] = ()
    unknown: tuple[ManifestUnknown, ...] = ()
    rationale: tuple[str, ...] = ()


def encode_agentic_factor_vector_json(vector: AgenticFactorVector) -> str:
    """Encode a factor vector deterministically without source values."""

    if not isinstance(vector, AgenticFactorVector):
        raise TypeError("vector must be AgenticFactorVector")
    return (
        json.dumps(vector.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class AgenticFactorExtractionError(RuntimeError):
    """Safe failure while deriving a factor vector from a Manifest."""


class DeterministicAgenticFactorExtractor:
    """Map only finalized Manifest facts to a stable ten-factor vector."""

    def extract(self, manifest: AgentManifest) -> AgenticFactorVector:
        if not isinstance(manifest, AgentManifest):
            raise TypeError("agentic factor extraction requires AgentManifest")
        try:
            source_hashes = {
                source.locator.sort_key(): source.content_sha256
                for source in manifest.sources
            }
            observations = {
                factor_id: self._observe(manifest, factor_id)
                for factor_id in _FACTOR_ORDER
            }
            factors = tuple(
                self._assessment(
                    manifest,
                    factor_id,
                    observations[factor_id],
                    source_hashes,
                )
                for factor_id in _FACTOR_ORDER
            )
            relevant_unknown_ids = tuple(
                sorted(
                    {
                        unknown.unknown_id
                        for observation in observations.values()
                        for unknown in observation.unknown
                    }
                )
            )
            return AgenticFactorVector(
                format=AGENTIC_FACTOR_FORMAT,
                format_version=AGENTIC_FACTOR_FORMAT_VERSION,
                model_version=AGENTIC_FACTOR_MODEL_VERSION,
                manifest_schema_version=manifest.schema_version,
                agent_id=manifest.identity.agent_id,
                manifest_sha256=_manifest_sha256(manifest),
                coverage_complete=manifest.coverage.complete,
                relevant_unknown_count=len(relevant_unknown_ids),
                factors=factors,
                mapping_basis=AGENTIC_FACTOR_BASIS,
            )
        except (TypeError, ValueError) as error:
            raise AgenticFactorExtractionError(
                "Agentic Factor extraction failed safely"
            ) from error

    def _assessment(
        self,
        manifest: AgentManifest,
        factor_id: AgenticFactorId,
        observation: _Observation,
        source_hashes: dict[tuple[str, str, str], str],
    ) -> AgenticFactorAssessment:
        unknown_ids = tuple(
            sorted(unknown.unknown_id for unknown in observation.unknown)
        )
        evidence = _evidence_for_references(
            observation.positive + observation.negative, source_hashes
        )
        if observation.unknown or not manifest.coverage.complete:
            value: FactorValue = 0.5
            confidence = EvidenceConfidence.D
            limitations = (
                (
                    "Static analysis cannot establish complete capability scope "
                    "or runtime reachability."
                ),
            )
            rationale = observation.rationale + (
                (
                    "Relevant Unknown or incomplete Coverage prevents a binary "
                    "capability conclusion."
                ),
            )
        elif observation.positive:
            value = 1.0
            confidence = EvidenceConfidence.B
            limitations = (
                "The declaration is static evidence and is not runtime proof.",
            )
            rationale = observation.rationale + (
                (
                    "A direct supported Manifest declaration establishes the "
                    "factor intent."
                ),
            )
        elif observation.negative:
            value = 0.0
            confidence = EvidenceConfidence.B
            limitations = (
                (
                    "An explicit deny or disabling control does not prove every "
                    "runtime path is denied."
                ),
            )
            rationale = observation.rationale + (
                "A direct supported Manifest control or permission denies the factor.",
            )
        else:
            value = 0.0
            confidence = EvidenceConfidence.D
            limitations = (
                (
                    "No positive declaration was materialized; absence is not "
                    "runtime proof of safety."
                ),
            )
            rationale = observation.rationale + (
                "No supported positive or explicit negative declaration was found.",
            )
        return AgenticFactorAssessment(
            factor_id=factor_id,
            value=value,
            confidence=confidence,
            evidence=evidence,
            relevant_unknown_ids=unknown_ids,
            rationale=_unique_strings(rationale),
            limitations=limitations,
        )

    def _observe(
        self, manifest: AgentManifest, factor_id: AgenticFactorId
    ) -> _Observation:
        if factor_id is AgenticFactorId.INSTRUCTION_OVERRIDE:
            return self._instruction_override(manifest)
        if factor_id is AgenticFactorId.CODE_EXECUTION:
            return self._permission_or_tool(
                manifest, self._is_execution_permission, self._is_execution_tool
            )
        if factor_id is AgenticFactorId.SECRET_ACCESS:
            return self._permission_or_tool(
                manifest, self._is_secret_permission, self._is_secret_tool
            )
        if factor_id is AgenticFactorId.EXTERNAL_NETWORK:
            return self._permission_or_tool(
                manifest, self._is_network_permission, self._is_network_tool
            )
        if factor_id is AgenticFactorId.PRODUCTION_ACCESS:
            return self._production_access(manifest)
        if factor_id is AgenticFactorId.PERSISTENT_MEMORY:
            return self._relation(manifest, ManifestRelationKind.PERSISTS_MEMORY)
        if factor_id is AgenticFactorId.SUBAGENT_DELEGATION:
            return self._relation(manifest, ManifestRelationKind.DELEGATES_TO)
        if factor_id is AgenticFactorId.EXTERNAL_IDENTITY:
            return self._external_identity(manifest)
        if factor_id is AgenticFactorId.AUTONOMOUS_ACTION:
            return self._autonomous_action(manifest)
        if factor_id is AgenticFactorId.APPROVAL_BYPASS:
            return self._approval_bypass(manifest)
        raise AgenticFactorExtractionError("unknown Agentic Factor ID")

    @staticmethod
    def _instruction_override(manifest: AgentManifest) -> _Observation:
        unknown = _unknowns(manifest, {ManifestUnknownDimension.INSTRUCTIONS})
        positive = tuple(
            reference for reference in manifest.instructions.overridden_sources
        )
        rationale = ("Instruction resolution exposes effective override provenance.",)
        return _Observation(positive=positive, unknown=unknown, rationale=rationale)

    def _permission_or_tool(
        self,
        manifest: AgentManifest,
        permission_match: Callable[[ManifestPermission], bool],
        tool_match: Callable[[ManifestTool], bool],
    ) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(
                manifest,
                {ManifestUnknownDimension.PERMISSIONS, ManifestUnknownDimension.TOOLS},
            )
        )
        for permission in manifest.permissions.permissions:
            if not permission_match(permission):
                continue
            if permission.effect in {
                ManifestPermissionEffect.ALLOW,
                ManifestPermissionEffect.PROMPT,
            }:
                positive.extend(permission.sources)
            elif permission.effect is ManifestPermissionEffect.DENY:
                negative.extend(permission.sources)
            else:
                unknown.extend(
                    _unknowns_for_item(
                        manifest,
                        ManifestUnknownDimension.PERMISSIONS,
                        permission.permission_id,
                    )
                )
        for tool in manifest.tools.tools:
            if not tool_match(tool):
                continue
            if tool.availability is ManifestToolAvailability.DISABLED:
                negative.extend(tool.sources)
            elif tool.availability is ManifestToolAvailability.UNKNOWN:
                unknown.extend(
                    _unknowns_for_item(
                        manifest, ManifestUnknownDimension.TOOLS, tool.tool_id
                    )
                )
            else:
                positive.extend(tool.sources)
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(
                (
                    "Permission and Tool inventories were evaluated without "
                    "reading source values."
                ),
            ),
        )

    @staticmethod
    def _is_execution_permission(permission: ManifestPermission) -> bool:
        return (
            permission.action is ManifestPermissionAction.EXECUTE
            or permission.resource is ManifestResourceKind.SHELL
        )

    @staticmethod
    def _is_secret_permission(permission: ManifestPermission) -> bool:
        return (
            permission.action is ManifestPermissionAction.SECRET_ACCESS
            or permission.resource is ManifestResourceKind.SECRET_STORE
        )

    @staticmethod
    def _is_network_permission(permission: ManifestPermission) -> bool:
        return (
            permission.action is ManifestPermissionAction.NETWORK
            or permission.resource is ManifestResourceKind.NETWORK
        )

    @staticmethod
    def _is_execution_tool(tool: ManifestTool) -> bool:
        return ManifestToolSideEffect.EXECUTE in tool.side_effects

    @staticmethod
    def _is_secret_tool(tool: ManifestTool) -> bool:
        return ManifestToolSideEffect.SECRET_ACCESS in tool.side_effects

    @staticmethod
    def _is_network_tool(tool: ManifestTool) -> bool:
        return ManifestToolSideEffect.NETWORK in tool.side_effects

    @staticmethod
    def _production_access(manifest: AgentManifest) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(
                manifest,
                {
                    ManifestUnknownDimension.PERMISSIONS,
                    ManifestUnknownDimension.RUNTIME_IDENTITIES,
                },
            )
        )
        for permission in manifest.permissions.permissions:
            if (
                permission.scope is ManifestResourceScope.PRODUCTION
                or permission.resource is ManifestResourceKind.PRODUCTION
            ):
                if permission.effect in {
                    ManifestPermissionEffect.ALLOW,
                    ManifestPermissionEffect.PROMPT,
                }:
                    positive.extend(permission.sources)
                elif permission.effect is ManifestPermissionEffect.DENY:
                    negative.extend(permission.sources)
                else:
                    unknown.extend(
                        _unknowns_for_item(
                            manifest,
                            ManifestUnknownDimension.PERMISSIONS,
                            permission.permission_id,
                        )
                    )
        for identity in manifest.runtime_identities.identities:
            if identity.environment is ManifestEnvironmentKind.PRODUCTION:
                if identity.privileged is True:
                    positive.extend(identity.sources)
                elif identity.privileged is False:
                    negative.extend(identity.sources)
                else:
                    unknown.extend(
                        _unknowns_for_item(
                            manifest,
                            ManifestUnknownDimension.RUNTIME_IDENTITIES,
                            identity.identity_id,
                        )
                    )
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(
                (
                    "Production permission scope and runtime identity "
                    "declarations were evaluated."
                ),
            ),
        )

    @staticmethod
    def _relation(manifest: AgentManifest, kind: ManifestRelationKind) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(manifest, {ManifestUnknownDimension.RELATIONSHIPS})
        )
        for relation in manifest.relationships.relations:
            if relation.kind is not kind:
                continue
            if relation.state in {
                ManifestRelationState.ACTIVE,
                ManifestRelationState.DECLARED,
            }:
                positive.extend(relation.sources)
            elif relation.state is ManifestRelationState.DISABLED:
                negative.extend(relation.sources)
            else:
                unknown.extend(
                    _unknowns_for_item(
                        manifest,
                        ManifestUnknownDimension.RELATIONSHIPS,
                        relation.relation_id,
                    )
                )
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(f"Relationship inventory was evaluated for {kind.value}.",),
        )

    @staticmethod
    def _external_identity(manifest: AgentManifest) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(manifest, {ManifestUnknownDimension.RUNTIME_IDENTITIES})
        )
        external_auth = {
            ManifestAuthenticationKind.API_KEY,
            ManifestAuthenticationKind.TOKEN,
            ManifestAuthenticationKind.OAUTH,
            ManifestAuthenticationKind.ENVIRONMENT,
        }
        for identity in manifest.runtime_identities.identities:
            if (
                identity.environment is ManifestEnvironmentKind.EXTERNAL
                or identity.authentication in external_auth
            ):
                positive.extend(identity.sources)
            elif identity.authentication is ManifestAuthenticationKind.NONE:
                negative.extend(identity.sources)
            else:
                unknown.extend(
                    _unknowns_for_item(
                        manifest,
                        ManifestUnknownDimension.RUNTIME_IDENTITIES,
                        identity.identity_id,
                    )
                )
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(
                (
                    "Credential-free runtime identity declarations were evaluated "
                    "by environment and authentication kind."
                ),
            ),
        )

    @staticmethod
    def _autonomous_action(manifest: AgentManifest) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(
                manifest,
                {
                    ManifestUnknownDimension.PERMISSIONS,
                    ManifestUnknownDimension.CONTROLS,
                },
            )
        )
        for permission in manifest.permissions.permissions:
            if permission.action not in _MUTATING_ACTIONS:
                continue
            if permission.effect is ManifestPermissionEffect.ALLOW:
                positive.extend(permission.sources)
            elif permission.effect in {
                ManifestPermissionEffect.PROMPT,
                ManifestPermissionEffect.DENY,
            }:
                negative.extend(permission.sources)
            else:
                unknown.extend(
                    _unknowns_for_item(
                        manifest,
                        ManifestUnknownDimension.PERMISSIONS,
                        permission.permission_id,
                    )
                )
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(
                (
                    "Mutating permissions were evaluated for autonomous allow "
                    "versus prompt/deny effects."
                ),
            ),
        )

    @staticmethod
    def _approval_bypass(manifest: AgentManifest) -> _Observation:
        positive: list[ManifestSourceReference] = []
        negative: list[ManifestSourceReference] = []
        unknown: list[ManifestUnknown] = list(
            _unknowns(
                manifest,
                {
                    ManifestUnknownDimension.CONTROLS,
                    ManifestUnknownDimension.PERMISSIONS,
                },
            )
        )
        for control in manifest.controls.controls:
            if control.kind is not ManifestControlKind.HUMAN_APPROVAL:
                continue
            if control.state is ManifestControlState.DISABLED:
                positive.extend(control.sources)
            elif control.state in {
                ManifestControlState.ENABLED,
                ManifestControlState.REQUIRED,
                ManifestControlState.PROMPT,
            }:
                negative.extend(control.sources)
            else:
                unknown.extend(
                    _unknowns_for_item(
                        manifest, ManifestUnknownDimension.CONTROLS, control.control_id
                    )
                )
        for permission in manifest.permissions.permissions:
            if permission.action not in _MUTATING_ACTIONS:
                continue
            if permission.effect is ManifestPermissionEffect.ALLOW:
                positive.extend(permission.sources)
            elif permission.effect is ManifestPermissionEffect.PROMPT:
                negative.extend(permission.sources)
            elif permission.effect is ManifestPermissionEffect.UNKNOWN:
                unknown.extend(
                    _unknowns_for_item(
                        manifest,
                        ManifestUnknownDimension.PERMISSIONS,
                        permission.permission_id,
                    )
                )
        return _Observation(
            positive=_unique_references(positive),
            negative=_unique_references(negative),
            unknown=_unique_unknowns(unknown),
            rationale=(
                (
                    "Human approval controls and mutating permission effects "
                    "were evaluated."
                ),
            ),
        )


def _manifest_sha256(manifest: AgentManifest) -> str:
    content = encode_agent_manifest_json(manifest).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _evidence_for_references(
    references: Iterable[ManifestSourceReference],
    source_hashes: dict[tuple[str, str, str], str],
) -> tuple[AgenticFactorEvidence, ...]:
    evidence = {
        AgenticFactorEvidence(
            locator=reference.locator,
            content_sha256=source_hashes[reference.locator.sort_key()],
            field_path=reference.field_path,
            start_line=reference.start_line,
            end_line=reference.end_line,
        )
        for reference in references
    }
    return tuple(sorted(evidence, key=lambda item: item.sort_key()))


def _unknowns(
    manifest: AgentManifest,
    dimensions: set[ManifestUnknownDimension],
) -> tuple[ManifestUnknown, ...]:
    return tuple(
        unknown for unknown in manifest.unknowns if unknown.dimension in dimensions
    )


def _unknowns_for_item(
    manifest: AgentManifest,
    dimension: ManifestUnknownDimension,
    item_id: str,
) -> tuple[ManifestUnknown, ...]:
    return tuple(
        unknown
        for unknown in manifest.unknowns
        if unknown.dimension is dimension
        and (unknown.field is None or item_id in unknown.field)
    )


def _unique_references(
    references: Iterable[ManifestSourceReference],
) -> tuple[ManifestSourceReference, ...]:
    by_key = {reference.sort_key(): reference for reference in references}
    return tuple(by_key[key] for key in sorted(by_key))


def _unique_unknowns(
    unknowns: Iterable[ManifestUnknown],
) -> tuple[ManifestUnknown, ...]:
    by_id = {unknown.unknown_id: unknown for unknown in unknowns}
    return tuple(by_id[key] for key in sorted(by_id))


def _unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value.strip()}))


def _validate_string_tuple(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{label} must be sorted and unique")


def _validate_unique_strings(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} values must be unique")


__all__ = [
    "AGENTIC_FACTOR_BASIS",
    "AGENTIC_FACTOR_FORMAT",
    "AGENTIC_FACTOR_FORMAT_VERSION",
    "AgenticFactorAssessment",
    "AgenticFactorEvidence",
    "AgenticFactorExtractionError",
    "AgenticFactorId",
    "AgenticFactorVector",
    "DeterministicAgenticFactorExtractor",
    "encode_agentic_factor_vector_json",
]

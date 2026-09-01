"""Strict immutable models for the versioned Agent Manifest Schema."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentsec.domain.base import Sha256Digest, validate_relative_path
from agentsec.manifests.enums import (
    ManifestAssetFormat,
    ManifestAssetRole,
    ManifestAuthenticationKind,
    ManifestConfigurationKind,
    ManifestConfigurationResolutionAction,
    ManifestConfigurationResolutionReason,
    ManifestControlKind,
    ManifestControlState,
    ManifestCoverageIssueCode,
    ManifestEnvironmentKind,
    ManifestInstructionKind,
    ManifestInstructionResolutionAction,
    ManifestInstructionResolutionReason,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestPrincipalKind,
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestSourceScope,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
    ManifestUnknownDimension,
    ManifestUnknownReason,
)
from agentsec.versioning import parse_interface_version

_INTERFACE_VERSION_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
_FRAMEWORK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

InterfaceVersionString = Annotated[
    str,
    Field(min_length=1, pattern=_INTERFACE_VERSION_PATTERN),
]
NonEmptyString = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(lambda value: _exact_non_empty(value)),
]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveLine = Annotated[int, Field(ge=1)]


class ManifestModel(BaseModel):
    """Strict immutable base for serialized Agent Manifest objects."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
    )


class ManifestSourceLocator(ManifestModel):
    """Portable locator for one source asset without an absolute host path."""

    scope: ManifestSourceScope
    root_id: NonEmptyString
    path: NonEmptyString

    @field_validator("root_id")
    @classmethod
    def root_id_must_be_exact(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("root_id must not contain outer whitespace")
        return value

    @field_validator("path")
    @classmethod
    def path_must_be_safe_and_relative(cls, value: str) -> str:
        return validate_relative_path(value)

    def sort_key(self) -> tuple[str, str, str]:
        """Return the canonical serialized source order."""

        return (self.scope.value, self.root_id, self.path)


class ManifestSource(ManifestModel):
    """One parsed framework asset represented without its untrusted content."""

    locator: ManifestSourceLocator
    format: ManifestAssetFormat
    roles: tuple[ManifestAssetRole, ...]
    content_sha256: Sha256Digest
    size_bytes: NonNegativeInt
    line_count: NonNegativeInt
    precedence_rank: NonNegativeInt

    @model_validator(mode="after")
    def roles_must_be_sorted_unique_and_format_coherent(self) -> ManifestSource:
        expected = tuple(sorted(set(self.roles), key=lambda role: role.value))
        if not self.roles or self.roles != expected:
            raise ValueError("Manifest source roles must be non-empty, sorted, unique")

        markdown_roles = {
            ManifestAssetRole.AGENT_INSTRUCTIONS,
            ManifestAssetRole.INSTRUCTION_OVERRIDE,
            ManifestAssetRole.SKILL,
        }
        structured_roles = {
            ManifestAssetRole.FRAMEWORK_CONFIG,
            ManifestAssetRole.MCP_CONFIG,
        }
        if (
            self.roles
            and set(self.roles) & markdown_roles
            and self.format is not ManifestAssetFormat.MARKDOWN
        ):
            raise ValueError("instruction and Skill roles require Markdown")
        if (
            ManifestAssetRole.PREFIX_RULES in self.roles
            and self.format is not ManifestAssetFormat.RULES
        ):
            raise ValueError("prefix Rules role requires Rules format")
        if set(self.roles) & structured_roles and self.format not in {
            ManifestAssetFormat.JSON,
            ManifestAssetFormat.YAML,
            ManifestAssetFormat.TOML,
        }:
            raise ValueError("configuration roles require structured format")
        if (
            ManifestAssetRole.MCP_CONFIG in self.roles
            and ManifestAssetRole.FRAMEWORK_CONFIG not in self.roles
        ):
            raise ValueError("MCP configuration also requires framework_config role")
        return self


class ManifestSourceReference(ManifestModel):
    """Reference to a whole Manifest source or an exact field/line range."""

    locator: ManifestSourceLocator
    field_path: NonEmptyString | None = None
    start_line: PositiveLine | None = None
    end_line: PositiveLine | None = None

    @field_validator("field_path")
    @classmethod
    def field_path_must_be_exact(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip():
            raise ValueError("field_path must not contain outer whitespace")
        return value

    @model_validator(mode="after")
    def line_range_must_be_all_or_none_and_coherent(self) -> ManifestSourceReference:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("source reference lines must be provided together")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("source reference line range must be coherent")
        return self

    def sort_key(self) -> tuple[str, str, str, str, int, int]:
        """Return deterministic reference order."""

        return (
            *self.locator.sort_key(),
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
        )


class ManifestMetadata(ManifestModel):
    """Version and Adapter provenance for a reproducible Agent Manifest."""

    scanner_version: NonEmptyString
    framework_id: NonEmptyString
    framework_display_name: NonEmptyString
    adapter_version: InterfaceVersionString
    deterministic: bool = True

    @field_validator("scanner_version", "framework_display_name")
    @classmethod
    def exact_non_empty_values(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("Manifest metadata values must not contain whitespace")
        return value

    @field_validator("framework_id")
    @classmethod
    def framework_id_must_be_stable(cls, value: str) -> str:
        if _FRAMEWORK_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("framework_id must use stable lowercase form")
        return value

    @field_validator("adapter_version")
    @classmethod
    def adapter_version_must_be_semver(cls, value: str) -> str:
        parse_interface_version(value)
        return value


class ManifestIdentity(ManifestModel):
    """Stable local identity of the Agent subject represented by this Manifest."""

    agent_id: NonEmptyString
    subject_scope: ManifestSourceScope
    subject_root_id: NonEmptyString
    declared_name: NonEmptyString | None = None
    resolution: ManifestResolutionStatus
    sources: tuple[ManifestSourceReference, ...] = ()

    @field_validator("agent_id")
    @classmethod
    def agent_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("agent_id must use stable identifier form")
        return value

    @field_validator("subject_root_id", "declared_name")
    @classmethod
    def exact_identity_values(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip():
            raise ValueError("identity values must not contain outer whitespace")
        return value

    @model_validator(mode="after")
    def sources_must_be_sorted_unique(self) -> ManifestIdentity:
        _require_sorted_unique_references(self.sources, "identity sources")
        if (
            self.resolution is ManifestResolutionStatus.RESOLVED
            and self.declared_name is None
        ):
            raise ValueError("resolved identity requires a declared_name")
        if self.resolution is ManifestResolutionStatus.UNKNOWN:
            raise ValueError("framework subject identity cannot be wholly unknown")
        return self


class ManifestInstructionCandidate(ManifestModel):
    """One base or Override instruction source awaiting effective resolution."""

    kind: ManifestInstructionKind
    source: ManifestSourceReference
    precedence_rank: NonNegativeInt

    def sort_key(self) -> tuple[int, str, str, str]:
        return (self.precedence_rank, *self.source.locator.sort_key())


class ManifestInstructionResolutionStep(ManifestModel):
    """One deterministic decision made for one instruction candidate."""

    source: ManifestSourceReference
    action: ManifestInstructionResolutionAction
    reason: ManifestInstructionResolutionReason
    precedence_rank: NonNegativeInt
    chain_key: NonEmptyString

    @field_validator("chain_key")
    @classmethod
    def chain_key_must_be_exact(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("instruction chain_key must be exact")
        return value


class ManifestInstructionProfile(ManifestModel):
    """Instruction candidates and later effective-source selection."""

    resolution: ManifestResolutionStatus
    candidates: tuple[ManifestInstructionCandidate, ...] = ()
    effective_sources: tuple[ManifestSourceReference, ...] = ()
    effective_order: tuple[ManifestSourceReference, ...] = ()
    overridden_sources: tuple[ManifestSourceReference, ...] = ()
    resolution_trace: tuple[ManifestInstructionResolutionStep, ...] = ()

    @model_validator(mode="after")
    def instruction_state_must_be_coherent(self) -> ManifestInstructionProfile:
        candidate_keys = tuple(candidate.sort_key() for candidate in self.candidates)
        if candidate_keys != tuple(sorted(candidate_keys)):
            raise ValueError("instruction candidates must be sorted")
        candidate_locators = tuple(
            candidate.source.locator.sort_key() for candidate in self.candidates
        )
        if len(candidate_locators) != len(set(candidate_locators)):
            raise ValueError("instruction candidate sources must be unique")
        _require_sorted_unique_references(
            self.effective_sources,
            "effective instruction sources",
        )
        _require_sorted_unique_references(
            self.overridden_sources,
            "overridden instruction sources",
        )
        _require_unique_references(
            self.effective_order,
            "effective instruction order",
        )
        effective_keys = {
            reference.locator.sort_key() for reference in self.effective_sources
        }
        effective_order_keys = {
            reference.locator.sort_key() for reference in self.effective_order
        }
        overridden_keys = {
            reference.locator.sort_key() for reference in self.overridden_sources
        }
        candidate_keys_set = set(candidate_locators)
        if not effective_keys <= set(candidate_locators):
            raise ValueError("effective instructions must be selected from candidates")
        if effective_order_keys != effective_keys:
            raise ValueError("effective instruction order must match effective sources")
        if not overridden_keys <= candidate_keys_set:
            raise ValueError("overridden instructions must be candidates")
        if effective_keys & overridden_keys:
            raise ValueError("effective instructions cannot be overridden")
        trace_keys = tuple(
            step.source.locator.sort_key() for step in self.resolution_trace
        )
        if len(trace_keys) != len(set(trace_keys)):
            raise ValueError("instruction resolution trace sources must be unique")
        if not set(trace_keys) <= candidate_keys_set:
            raise ValueError("instruction resolution trace must use candidates")
        candidate_by_key = {
            candidate.source.locator.sort_key(): candidate
            for candidate in self.candidates
        }
        for step in self.resolution_trace:
            candidate = candidate_by_key[step.source.locator.sort_key()]
            if candidate.precedence_rank != step.precedence_rank:
                raise ValueError("instruction trace rank must match candidate")
        if (
            self.resolution
            in {
                ManifestResolutionStatus.RESOLVED,
                ManifestResolutionStatus.PARTIAL,
                ManifestResolutionStatus.CONFLICT,
            }
            and set(trace_keys) != candidate_keys_set
        ):
            raise ValueError("resolved instruction profiles require a full trace")
        if self.resolution is ManifestResolutionStatus.UNRESOLVED and (
            not self.candidates
            or self.effective_sources
            or self.overridden_sources
            or self.resolution_trace
        ):
            raise ValueError(
                "unresolved instructions require candidates and no resolution"
            )
        if self.resolution in {
            ManifestResolutionStatus.UNKNOWN,
            ManifestResolutionStatus.NOT_APPLICABLE,
        } and (
            self.candidates
            or self.effective_sources
            or self.effective_order
            or self.overridden_sources
            or self.resolution_trace
        ):
            raise ValueError("unknown instructions cannot contain resolved data")
        if (
            self.resolution is ManifestResolutionStatus.RESOLVED
            and self.candidates
            and not self.effective_order
        ):
            raise ValueError("resolved instruction candidates require a selection")
        if (
            self.resolution is ManifestResolutionStatus.CONFLICT
            and len(self.candidates) < 2
        ):
            raise ValueError("instruction conflict requires multiple candidates")
        if (
            self.resolution is ManifestResolutionStatus.CONFLICT
            and self.effective_sources
        ):
            raise ValueError("conflicting instructions cannot select effective sources")
        if (
            self.resolution is ManifestResolutionStatus.CONFLICT
            and self.effective_order
        ):
            raise ValueError("conflicting instructions cannot select effective order")
        if self.resolution is ManifestResolutionStatus.PARTIAL and not (
            self.candidates
            or self.effective_sources
            or self.effective_order
            or self.overridden_sources
            or self.resolution_trace
        ):
            raise ValueError("partial instructions require retained evidence")
        return self


class ManifestConfigurationCandidate(ManifestModel):
    """One source-level configuration declaration awaiting precedence ordering."""

    source: ManifestSourceReference
    kinds: tuple[ManifestConfigurationKind, ...]
    precedence_rank: NonNegativeInt
    chain_key: NonEmptyString

    @model_validator(mode="after")
    def configuration_candidate_must_be_coherent(
        self,
    ) -> ManifestConfigurationCandidate:
        expected = tuple(sorted(set(self.kinds), key=lambda kind: kind.value))
        if not self.kinds or self.kinds != expected:
            raise ValueError("configuration candidate kinds must be sorted and unique")
        if self.chain_key != self.chain_key.strip():
            raise ValueError("configuration candidate chain_key must be exact")
        return self

    def sort_key(self) -> tuple[int, str, str, str, str]:
        return (
            self.precedence_rank,
            *self.source.locator.sort_key(),
            self.chain_key,
        )


class ManifestConfigurationResolutionStep(ManifestModel):
    """One deterministic source-level configuration precedence decision."""

    source: ManifestSourceReference
    kinds: tuple[ManifestConfigurationKind, ...]
    action: ManifestConfigurationResolutionAction
    reason: ManifestConfigurationResolutionReason
    precedence_rank: NonNegativeInt
    chain_key: NonEmptyString

    @model_validator(mode="after")
    def resolution_step_must_be_coherent(
        self,
    ) -> ManifestConfigurationResolutionStep:
        expected = tuple(sorted(set(self.kinds), key=lambda kind: kind.value))
        if not self.kinds or self.kinds != expected:
            raise ValueError("configuration trace kinds must be sorted and unique")
        if self.chain_key != self.chain_key.strip():
            raise ValueError("configuration trace chain_key must be exact")
        return self


class ManifestConfigurationProfile(ManifestModel):
    """Source-level configuration precedence before field-level extraction."""

    resolution: ManifestResolutionStatus
    candidates: tuple[ManifestConfigurationCandidate, ...] = ()
    effective_sources: tuple[ManifestSourceReference, ...] = ()
    effective_order: tuple[ManifestSourceReference, ...] = ()
    resolution_trace: tuple[ManifestConfigurationResolutionStep, ...] = ()

    @model_validator(mode="after")
    def configuration_state_must_be_coherent(
        self,
    ) -> ManifestConfigurationProfile:
        candidate_keys = tuple(candidate.sort_key() for candidate in self.candidates)
        if candidate_keys != tuple(sorted(candidate_keys)):
            raise ValueError("configuration candidates must be sorted")
        candidate_locators = tuple(
            candidate.source.locator.sort_key() for candidate in self.candidates
        )
        if len(candidate_locators) != len(set(candidate_locators)):
            raise ValueError("configuration candidate sources must be unique")
        _require_sorted_unique_references(
            self.effective_sources,
            "effective configuration sources",
        )
        _require_unique_references(
            self.effective_order,
            "effective configuration order",
        )
        effective_keys = {
            reference.locator.sort_key() for reference in self.effective_sources
        }
        effective_order_keys = {
            reference.locator.sort_key() for reference in self.effective_order
        }
        candidate_key_set = set(candidate_locators)
        if not effective_keys <= candidate_key_set:
            raise ValueError("effective configuration source must be a candidate")
        if effective_order_keys != effective_keys:
            raise ValueError(
                "effective configuration order must match effective sources"
            )
        trace_keys = tuple(
            step.source.locator.sort_key() for step in self.resolution_trace
        )
        if len(trace_keys) != len(set(trace_keys)):
            raise ValueError("configuration trace sources must be unique")
        if set(trace_keys) != candidate_key_set and self.resolution in {
            ManifestResolutionStatus.RESOLVED,
            ManifestResolutionStatus.PARTIAL,
            ManifestResolutionStatus.CONFLICT,
        }:
            raise ValueError("resolved configuration profiles require a full trace")
        candidate_by_locator = {
            candidate.source.locator.sort_key(): candidate
            for candidate in self.candidates
        }
        for step in self.resolution_trace:
            candidate = candidate_by_locator.get(step.source.locator.sort_key())
            if candidate is None:
                raise ValueError("configuration trace must use candidates")
            if candidate.kinds != step.kinds:
                raise ValueError("configuration trace kinds must match candidate")
            if candidate.precedence_rank != step.precedence_rank:
                raise ValueError("configuration trace rank must match candidate")
            if candidate.chain_key != step.chain_key:
                raise ValueError("configuration trace chain must match candidate")
        if self.resolution is ManifestResolutionStatus.UNRESOLVED and (
            not self.candidates
            or self.effective_sources
            or self.effective_order
            or self.resolution_trace
        ):
            raise ValueError(
                "unresolved configuration requires candidates and no resolution"
            )
        if self.resolution in {
            ManifestResolutionStatus.UNKNOWN,
            ManifestResolutionStatus.NOT_APPLICABLE,
        } and (
            self.candidates
            or self.effective_sources
            or self.effective_order
            or self.resolution_trace
        ):
            raise ValueError("unknown configuration cannot contain resolved data")
        if (
            self.resolution is ManifestResolutionStatus.RESOLVED
            and self.candidates
            and not self.effective_order
        ):
            raise ValueError("resolved configuration requires an effective order")
        if self.resolution is ManifestResolutionStatus.CONFLICT and (
            self.effective_sources or self.effective_order
        ):
            raise ValueError("conflicting configuration cannot select sources")
        if self.resolution is ManifestResolutionStatus.PARTIAL and not (
            self.candidates
            or self.effective_sources
            or self.effective_order
            or self.resolution_trace
        ):
            raise ValueError("partial configuration requires retained evidence")
        return self


class ManifestProfileBase(ManifestModel):
    """Shared declaration-source state for non-instruction Manifest dimensions."""

    resolution: ManifestResolutionStatus
    declaration_sources: tuple[ManifestSourceReference, ...] = ()

    @model_validator(mode="after")
    def declaration_sources_must_be_sorted_unique(self) -> ManifestProfileBase:
        _require_sorted_unique_references(
            self.declaration_sources,
            "Manifest declaration sources",
        )
        return self

    def validate_resolution(self, *, item_count: int, label: str) -> None:
        if self.resolution is ManifestResolutionStatus.UNRESOLVED and (
            not self.declaration_sources or item_count
        ):
            raise ValueError(
                f"unresolved {label} require declarations and no resolved items"
            )
        if self.resolution in {
            ManifestResolutionStatus.UNKNOWN,
            ManifestResolutionStatus.NOT_APPLICABLE,
        } and (self.declaration_sources or item_count):
            raise ValueError(f"unknown {label} cannot contain declaration data")
        if (
            self.resolution is ManifestResolutionStatus.PARTIAL
            and not self.declaration_sources
            and item_count == 0
        ):
            raise ValueError(f"partial {label} require retained evidence")
        if (
            self.resolution is ManifestResolutionStatus.CONFLICT
            and len(self.declaration_sources) < 2
        ):
            raise ValueError(f"conflicting {label} require multiple declarations")


class ManifestTool(ManifestModel):
    """Normalized tool or capability declaration populated by P2-08 and later."""

    tool_id: NonEmptyString
    name: NonEmptyString
    kind: ManifestToolKind
    availability: ManifestToolAvailability
    side_effects: tuple[ManifestToolSideEffect, ...] = ()
    parent_tool_id: NonEmptyString | None = None
    sources: tuple[ManifestSourceReference, ...]

    @field_validator("tool_id")
    @classmethod
    def tool_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("tool_id must use stable identifier form")
        return value

    @model_validator(mode="after")
    def tool_values_must_be_coherent(self) -> ManifestTool:
        if self.parent_tool_id == self.tool_id:
            raise ValueError("tool cannot be its own parent")
        expected = tuple(sorted(set(self.side_effects), key=lambda item: item.value))
        if self.side_effects != expected:
            raise ValueError("tool side effects must be sorted and unique")
        if not self.sources:
            raise ValueError("Manifest tool requires source provenance")
        _require_sorted_unique_references(self.sources, "tool sources")
        return self


class ManifestToolProfile(ManifestProfileBase):
    """Tool inventory plus source declarations awaiting association."""

    tools: tuple[ManifestTool, ...] = ()

    @model_validator(mode="after")
    def tool_profile_must_be_coherent(self) -> ManifestToolProfile:
        _require_sorted_unique_items(
            self.tools,
            key=lambda item: item.tool_id,
            label="Manifest tools",
        )
        self.validate_resolution(item_count=len(self.tools), label="tools")
        return self


class ManifestPermission(ManifestModel):
    """Normalized permission fact populated by P2-09 and later."""

    permission_id: NonEmptyString
    action: ManifestPermissionAction
    effect: ManifestPermissionEffect
    resource: ManifestResourceKind
    scope: ManifestResourceScope
    target: NonEmptyString | None = None
    sources: tuple[ManifestSourceReference, ...]

    @field_validator("permission_id")
    @classmethod
    def permission_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("permission_id must use stable identifier form")
        return value

    @model_validator(mode="after")
    def permission_requires_sources(self) -> ManifestPermission:
        if not self.sources:
            raise ValueError("Manifest permission requires source provenance")
        _require_sorted_unique_references(self.sources, "permission sources")
        return self


class ManifestPermissionProfile(ManifestProfileBase):
    """Permission inventory and unresolved configuration sources."""

    permissions: tuple[ManifestPermission, ...] = ()

    @model_validator(mode="after")
    def permission_profile_must_be_coherent(self) -> ManifestPermissionProfile:
        _require_sorted_unique_items(
            self.permissions,
            key=lambda item: item.permission_id,
            label="Manifest permissions",
        )
        self.validate_resolution(
            item_count=len(self.permissions),
            label="permissions",
        )
        return self


class ManifestControl(ManifestModel):
    """Normalized approval, sandbox, policy, or tool-control fact."""

    control_id: NonEmptyString
    kind: ManifestControlKind
    state: ManifestControlState
    target: NonEmptyString | None = None
    sources: tuple[ManifestSourceReference, ...]

    @field_validator("control_id")
    @classmethod
    def control_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("control_id must use stable identifier form")
        return value

    @model_validator(mode="after")
    def control_requires_sources(self) -> ManifestControl:
        if not self.sources:
            raise ValueError("Manifest control requires source provenance")
        _require_sorted_unique_references(self.sources, "control sources")
        return self


class ManifestControlProfile(ManifestProfileBase):
    """Control inventory and unresolved policy sources."""

    controls: tuple[ManifestControl, ...] = ()

    @model_validator(mode="after")
    def control_profile_must_be_coherent(self) -> ManifestControlProfile:
        _require_sorted_unique_items(
            self.controls,
            key=lambda item: item.control_id,
            label="Manifest controls",
        )
        self.validate_resolution(item_count=len(self.controls), label="controls")
        return self


class ManifestRuntimeIdentity(ManifestModel):
    """Credential-free runtime principal declaration populated by P2-09."""

    identity_id: NonEmptyString
    principal_kind: ManifestPrincipalKind
    authentication: ManifestAuthenticationKind
    environment: ManifestEnvironmentKind
    privileged: bool | None = None
    sources: tuple[ManifestSourceReference, ...]

    @field_validator("identity_id")
    @classmethod
    def identity_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("identity_id must use stable identifier form")
        return value

    @model_validator(mode="after")
    def runtime_identity_requires_sources(self) -> ManifestRuntimeIdentity:
        if not self.sources:
            raise ValueError("runtime identity requires source provenance")
        _require_sorted_unique_references(self.sources, "runtime identity sources")
        return self


class ManifestRuntimeIdentityProfile(ManifestProfileBase):
    """Runtime identities and authentication declarations without secrets."""

    identities: tuple[ManifestRuntimeIdentity, ...] = ()

    @model_validator(mode="after")
    def runtime_identity_profile_must_be_coherent(
        self,
    ) -> ManifestRuntimeIdentityProfile:
        _require_sorted_unique_items(
            self.identities,
            key=lambda item: item.identity_id,
            label="runtime identities",
        )
        self.validate_resolution(
            item_count=len(self.identities),
            label="runtime identities",
        )
        return self


class ManifestRelation(ManifestModel):
    """One Agent, Skill, MCP, tool, or memory relationship."""

    relation_id: NonEmptyString
    source_agent_id: NonEmptyString
    kind: ManifestRelationKind
    target_id: NonEmptyString
    state: ManifestRelationState
    sources: tuple[ManifestSourceReference, ...]

    @field_validator("relation_id", "source_agent_id", "target_id")
    @classmethod
    def relation_ids_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("relationship identifiers must use stable form")
        return value

    @model_validator(mode="after")
    def relation_requires_sources(self) -> ManifestRelation:
        if not self.sources:
            raise ValueError("Manifest relationship requires source provenance")
        _require_sorted_unique_references(self.sources, "relationship sources")
        return self


class ManifestRelationshipProfile(ManifestProfileBase):
    """Sub-Agent, Skill, MCP, tool, and memory relationships."""

    relations: tuple[ManifestRelation, ...] = ()

    @model_validator(mode="after")
    def relationship_profile_must_be_coherent(self) -> ManifestRelationshipProfile:
        _require_sorted_unique_items(
            self.relations,
            key=lambda item: item.relation_id,
            label="Manifest relationships",
        )
        self.validate_resolution(
            item_count=len(self.relations),
            label="relationships",
        )
        return self


class ManifestUnknown(ManifestModel):
    """One explicit unresolved fact without attacker-controlled explanation text."""

    unknown_id: NonEmptyString
    dimension: ManifestUnknownDimension
    reason: ManifestUnknownReason
    field: NonEmptyString | None = None
    sources: tuple[ManifestSourceReference, ...] = ()

    @field_validator("unknown_id")
    @classmethod
    def unknown_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("unknown_id must use stable identifier form")
        return value

    @model_validator(mode="after")
    def unknown_sources_must_be_sorted_unique(self) -> ManifestUnknown:
        _require_sorted_unique_references(self.sources, "Unknown sources")
        return self


class ManifestCoverageIssue(ManifestModel):
    """One framework-inspection gap retained without source or exception text."""

    code: ManifestCoverageIssueCode
    root_id: NonEmptyString
    path: NonEmptyString | None = None

    @field_validator("root_id")
    @classmethod
    def coverage_root_id_must_be_exact(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("coverage root_id must be exact")
        return value

    @field_validator("path")
    @classmethod
    def coverage_path_must_be_relative(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_relative_path(value)

    def sort_key(self) -> tuple[str, str, str]:
        return (self.code.value, self.root_id, self.path or "")


class ManifestCoverage(ManifestModel):
    """Coverage counts for the source inventory represented by the Manifest."""

    discovered_assets: NonNegativeInt
    inspected_assets: NonNegativeInt
    skipped_assets: NonNegativeInt
    complete: bool
    issues: tuple[ManifestCoverageIssue, ...] = ()

    @model_validator(mode="after")
    def coverage_must_be_coherent(self) -> ManifestCoverage:
        if self.inspected_assets + self.skipped_assets != self.discovered_assets:
            raise ValueError(
                "Manifest inspected_assets plus skipped_assets must equal discovered"
            )
        expected = tuple(sorted(set(self.issues), key=lambda issue: issue.sort_key()))
        if self.issues != expected:
            raise ValueError("Manifest Coverage Issues must be sorted and unique")
        if self.complete != (self.skipped_assets == 0 and not self.issues):
            raise ValueError("Manifest Coverage completion must match gaps")
        return self


class AgentManifest(ManifestModel):
    """Versioned deterministic declaration inventory for one Agent subject."""

    schema_version: InterfaceVersionString
    metadata: ManifestMetadata
    identity: ManifestIdentity
    sources: tuple[ManifestSource, ...]
    instructions: ManifestInstructionProfile
    configuration: ManifestConfigurationProfile
    tools: ManifestToolProfile
    permissions: ManifestPermissionProfile
    controls: ManifestControlProfile
    runtime_identities: ManifestRuntimeIdentityProfile
    relationships: ManifestRelationshipProfile
    unknowns: tuple[ManifestUnknown, ...] = ()
    coverage: ManifestCoverage

    @field_validator("schema_version")
    @classmethod
    def schema_version_must_be_semver(cls, value: str) -> str:
        parse_interface_version(value)
        return value

    @model_validator(mode="after")
    def manifest_must_be_coherent(self) -> AgentManifest:
        source_keys = tuple(source.locator.sort_key() for source in self.sources)
        if source_keys != tuple(sorted(source_keys)):
            raise ValueError("Manifest sources must be sorted by portable locator")
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("Manifest source locators must be unique")
        if self.coverage.inspected_assets != len(self.sources):
            raise ValueError("Manifest source count must equal inspected Coverage")
        if self.identity.subject_scope is not ManifestSourceScope.PROJECT:
            raise ValueError("P2-05 Agent Manifest subject must use project scope")

        sources = {source.locator.sort_key(): source for source in self.sources}
        project_root_ids = {
            source.locator.root_id
            for source in self.sources
            if source.locator.scope is ManifestSourceScope.PROJECT
        }
        if project_root_ids and self.identity.subject_root_id not in project_root_ids:
            raise ValueError("Manifest subject root must exist in project sources")
        for reference in self._all_source_references():
            source = sources.get(reference.locator.sort_key())
            if source is None:
                raise ValueError("Manifest source reference must resolve to an asset")
            if (
                reference.end_line is not None
                and reference.end_line > source.line_count
            ):
                raise ValueError("Manifest source reference exceeds source line count")

        for candidate in self.instructions.candidates:
            source = sources[candidate.source.locator.sort_key()]
            expected_role = {
                ManifestInstructionKind.BASE: ManifestAssetRole.AGENT_INSTRUCTIONS,
                ManifestInstructionKind.OVERRIDE: (
                    ManifestAssetRole.INSTRUCTION_OVERRIDE
                ),
            }[candidate.kind]
            if expected_role not in source.roles:
                raise ValueError("instruction candidate kind must match source role")
            if candidate.precedence_rank != source.precedence_rank:
                raise ValueError("instruction rank must match source precedence")

        self._validate_profile_declaration_roles(sources)
        configuration_role_map = {
            ManifestConfigurationKind.FRAMEWORK_CONFIG: (
                ManifestAssetRole.FRAMEWORK_CONFIG
            ),
            ManifestConfigurationKind.PREFIX_RULES: ManifestAssetRole.PREFIX_RULES,
            ManifestConfigurationKind.MCP_CONFIG: ManifestAssetRole.MCP_CONFIG,
        }
        for configuration_candidate in self.configuration.candidates:
            source = sources[configuration_candidate.source.locator.sort_key()]
            if any(
                configuration_role_map[kind] not in source.roles
                for kind in configuration_candidate.kinds
            ):
                raise ValueError("configuration candidate kind must match source role")

        for relation in self.relationships.relations:
            if relation.source_agent_id != self.identity.agent_id:
                raise ValueError("relationship source must match Manifest Agent")

        tool_ids = {tool.tool_id for tool in self.tools.tools}
        for tool in self.tools.tools:
            if tool.parent_tool_id is not None and tool.parent_tool_id not in tool_ids:
                raise ValueError(
                    "tool parent must resolve within the Manifest inventory"
                )

        _require_sorted_unique_items(
            self.unknowns,
            key=lambda item: item.unknown_id,
            label="Manifest Unknowns",
        )
        return self

    def _all_source_references(self) -> tuple[ManifestSourceReference, ...]:
        references: list[ManifestSourceReference] = list(self.identity.sources)
        references.extend(
            candidate.source for candidate in self.instructions.candidates
        )
        references.extend(self.instructions.effective_sources)
        references.extend(self.instructions.effective_order)
        references.extend(self.instructions.overridden_sources)
        references.extend(step.source for step in self.instructions.resolution_trace)
        references.extend(
            candidate.source for candidate in self.configuration.candidates
        )
        references.extend(self.configuration.effective_sources)
        references.extend(self.configuration.effective_order)
        references.extend(step.source for step in self.configuration.resolution_trace)
        profiles: tuple[ManifestProfileBase, ...] = (
            self.tools,
            self.permissions,
            self.controls,
            self.runtime_identities,
            self.relationships,
        )
        for profile in profiles:
            references.extend(profile.declaration_sources)
        for tool in self.tools.tools:
            references.extend(tool.sources)
        for permission in self.permissions.permissions:
            references.extend(permission.sources)
        for control in self.controls.controls:
            references.extend(control.sources)
        for identity in self.runtime_identities.identities:
            references.extend(identity.sources)
        for relation in self.relationships.relations:
            references.extend(relation.sources)
        for unknown in self.unknowns:
            references.extend(unknown.sources)
        return tuple(references)

    def _validate_profile_declaration_roles(
        self,
        sources: dict[tuple[str, str, str], ManifestSource],
    ) -> None:
        role_contracts = (
            (
                self.tools.declaration_sources,
                {
                    ManifestAssetRole.SKILL,
                    ManifestAssetRole.MCP_CONFIG,
                },
                "tool",
            ),
            (
                self.permissions.declaration_sources,
                {
                    ManifestAssetRole.PREFIX_RULES,
                    ManifestAssetRole.FRAMEWORK_CONFIG,
                    ManifestAssetRole.MCP_CONFIG,
                },
                "permission",
            ),
            (
                self.controls.declaration_sources,
                {
                    ManifestAssetRole.PREFIX_RULES,
                    ManifestAssetRole.FRAMEWORK_CONFIG,
                    ManifestAssetRole.MCP_CONFIG,
                },
                "control",
            ),
            (
                self.runtime_identities.declaration_sources,
                {
                    ManifestAssetRole.FRAMEWORK_CONFIG,
                    ManifestAssetRole.MCP_CONFIG,
                },
                "runtime identity",
            ),
            (
                self.relationships.declaration_sources,
                {
                    ManifestAssetRole.AGENT_INSTRUCTIONS,
                    ManifestAssetRole.INSTRUCTION_OVERRIDE,
                    ManifestAssetRole.SKILL,
                    ManifestAssetRole.MCP_CONFIG,
                },
                "relationship",
            ),
        )
        for references, allowed_roles, label in role_contracts:
            for reference in references:
                source = sources[reference.locator.sort_key()]
                if not set(source.roles) & allowed_roles:
                    raise ValueError(
                        f"{label} declaration source has incompatible role"
                    )


def _require_sorted_unique_references(
    references: tuple[ManifestSourceReference, ...],
    label: str,
) -> None:
    keys = tuple(reference.sort_key() for reference in references)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError(f"{label} must be sorted and unique")


def _require_unique_references(
    references: tuple[ManifestSourceReference, ...],
    label: str,
) -> None:
    keys = tuple(reference.sort_key() for reference in references)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} must be unique")


def _require_sorted_unique_items[T](
    items: tuple[T, ...],
    *,
    key: Callable[[T], str],
    label: str,
) -> None:
    values = tuple(key(item) for item in items)
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{label} must be sorted and unique")


def _exact_non_empty(value: str) -> str:
    if not value.strip() or value != value.strip():
        raise ValueError("Manifest strings must be non-empty exact values")
    return value

"""Homi file authority, visibility, precedence, and conflict resolution.

P2-HOMI-02 defines a security-resolution contract, not a claim about Homi's
runtime loader implementation. The ranks below describe which file wins when
static declarations conflict in a security-relevant domain; they do not grant
any runtime tool, identity, memory, or scheduler authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from agentsec.frameworks.base import (
    FrameworkAssetLocator,
    FrameworkAssetRecord,
)
from agentsec.frameworks.homi import (
    HomiFileRole,
    HomiFileState,
    HomiWorkspaceFile,
    HomiWorkspaceInspection,
)
from agentsec.parsers import ParsedMarkdown


class HomiVisibility(StrEnum):
    """Static context boundary for one Homi file role."""

    ALL_CONTEXTS = "all_contexts"
    MAIN_SESSION_ONLY = "main_session_only"
    PRIVATE_RUNTIME = "private_runtime"
    PUBLIC_IDENTITY = "public_identity"
    SCHEDULER_ONLY = "scheduler_only"


class HomiAuthorityDomain(StrEnum):
    """Domain in which one Homi role may make a static declaration."""

    SAFETY = "safety"
    STARTUP = "startup"
    MEMORY = "memory"
    EXTERNAL_ACTIONS = "external_actions"
    GROUP_CHAT = "group_chat"
    HEARTBEAT = "heartbeat"
    PERSONA = "persona"
    IDENTITY = "identity"
    USER_CONTEXT = "user_context"
    ENVIRONMENT_BINDING = "environment_binding"


class HomiResolutionStatus(StrEnum):
    """Overall static resolution state for one Homi workspace."""

    RESOLVED = "resolved"
    PARTIAL = "partial"
    CONFLICT = "conflict"


class HomiObservationKind(StrEnum):
    """Non-secret static observation emitted by the policy resolver."""

    CONFLICT = "conflict"
    LATENT_ACTIVATION = "latent_activation"
    AUTHORITY_BOUNDARY = "authority_boundary"


class HomiObservationCode(StrEnum):
    """Stable Homi precedence and boundary observation codes."""

    STARTUP_READ_POLICY_CONFLICT = "startup_read_policy_conflict"
    CONTROL_PLANE_SELF_MODIFICATION = "control_plane_self_modification"
    HEARTBEAT_ACTIVATION_PATH = "heartbeat_activation_path"
    TOOLS_NOT_AUTHORITY = "tools_not_authority"
    USER_PROFILE_MAIN_SESSION_ONLY = "user_profile_main_session_only"
    IDENTITY_NOT_RUNTIME_AUTHORITY = "identity_not_runtime_authority"
    EMPTY_HEARTBEAT_DISABLED = "empty_heartbeat_disabled"
    HEARTBEAT_TEMPLATE_DISABLED = "heartbeat_template_disabled"


@dataclass(frozen=True, slots=True)
class HomiRolePolicy:
    """Deterministic security policy for one Homi file role."""

    file_name: str
    role: HomiFileRole
    authority_rank: int
    visibility: HomiVisibility
    domains: tuple[HomiAuthorityDomain, ...]
    may_override_roles: tuple[HomiFileRole, ...] = ()
    runtime_authority: bool = False

    def __post_init__(self) -> None:
        if not self.file_name or "/" in self.file_name:
            raise ValueError("Homi role policy requires a root-level filename")
        if not isinstance(self.role, HomiFileRole):
            raise TypeError("Homi role policy role must be HomiFileRole")
        if self.authority_rank < 0:
            raise ValueError("Homi authority rank must not be negative")
        if not isinstance(self.visibility, HomiVisibility):
            raise TypeError("Homi visibility must be HomiVisibility")
        if self.domains != tuple(
            sorted(set(self.domains), key=lambda item: item.value)
        ):
            raise ValueError("Homi policy domains must be sorted and unique")
        if self.may_override_roles != tuple(
            sorted(set(self.may_override_roles), key=lambda item: item.value)
        ):
            raise ValueError("Homi override roles must be sorted and unique")
        if self.role in self.may_override_roles:
            raise ValueError("Homi role cannot override itself")
        if self.runtime_authority:
            raise ValueError("static Homi role policy cannot grant runtime authority")


@dataclass(frozen=True, slots=True)
class HomiPolicyObservation:
    """Safe conflict/boundary evidence without source excerpts."""

    code: HomiObservationCode
    kind: HomiObservationKind
    roles: tuple[HomiFileRole, ...]
    sources: tuple[FrameworkAssetLocator, ...]
    resolution: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, HomiObservationCode):
            raise TypeError("Homi observation code must be HomiObservationCode")
        if not isinstance(self.kind, HomiObservationKind):
            raise TypeError("Homi observation kind must be HomiObservationKind")
        if self.roles != tuple(sorted(set(self.roles), key=lambda item: item.value)):
            raise ValueError("Homi observation roles must be sorted and unique")
        if not self.roles:
            raise ValueError("Homi observation requires at least one role")
        source_keys = tuple(_locator_key(source) for source in self.sources)
        if source_keys != tuple(sorted(set(source_keys))):
            raise ValueError("Homi observation sources must be sorted and unique")
        if not self.resolution or self.resolution != self.resolution.strip():
            raise ValueError("Homi observation resolution must be non-empty and exact")


@dataclass(frozen=True, slots=True)
class HomiWorkspaceResolution:
    """Resolved role policy and static conflict observations for one workspace."""

    policies: tuple[HomiRolePolicy, ...]
    observations: tuple[HomiPolicyObservation, ...]
    missing_files: tuple[str, ...]
    skipped_files: tuple[str, ...]
    status: HomiResolutionStatus

    def __post_init__(self) -> None:
        expected = tuple(policy.file_name for policy in _HOMI_ROLE_POLICIES)
        actual = tuple(policy.file_name for policy in self.policies)
        if actual != expected:
            raise ValueError("Homi policies must use the standard file order")
        if self.missing_files != tuple(sorted(set(self.missing_files))):
            raise ValueError("Homi missing files must be sorted and unique")
        if self.skipped_files != tuple(sorted(set(self.skipped_files))):
            raise ValueError("Homi skipped files must be sorted and unique")
        if not isinstance(self.status, HomiResolutionStatus):
            raise TypeError("Homi resolution status must be HomiResolutionStatus")
        observation_keys = tuple(
            (
                observation.code.value,
                tuple(_locator_key(source) for source in observation.sources),
            )
            for observation in self.observations
        )
        if observation_keys != tuple(sorted(set(observation_keys))):
            raise ValueError("Homi observations must be deterministically ordered")
        has_conflict = any(
            observation.kind is HomiObservationKind.CONFLICT
            for observation in self.observations
        )
        if has_conflict and self.status is not HomiResolutionStatus.CONFLICT:
            raise ValueError("conflicting Homi observations require conflict status")
        if not has_conflict and self.status is HomiResolutionStatus.CONFLICT:
            raise ValueError("conflict status requires a conflicting observation")

    def policy_for(self, role: HomiFileRole) -> HomiRolePolicy:
        """Return the one policy record for a Homi role."""

        for policy in self.policies:
            if policy.role is role:
                return policy
        raise KeyError(role)


_HOMI_ROLE_POLICIES: Final[tuple[HomiRolePolicy, ...]] = (
    HomiRolePolicy(
        file_name="AGENTS.md",
        role=HomiFileRole.WORKSPACE_POLICY,
        authority_rank=100,
        visibility=HomiVisibility.ALL_CONTEXTS,
        domains=(
            HomiAuthorityDomain.EXTERNAL_ACTIONS,
            HomiAuthorityDomain.GROUP_CHAT,
            HomiAuthorityDomain.HEARTBEAT,
            HomiAuthorityDomain.MEMORY,
            HomiAuthorityDomain.SAFETY,
            HomiAuthorityDomain.STARTUP,
        ),
        may_override_roles=tuple(
            sorted(
                (
                    HomiFileRole.HEARTBEAT_SCHEDULE,
                    HomiFileRole.IDENTITY,
                    HomiFileRole.PERSONA,
                    HomiFileRole.TOOL_NOTES,
                    HomiFileRole.USER_PROFILE,
                ),
                key=lambda item: item.value,
            )
        ),
    ),
    HomiRolePolicy(
        file_name="SOUL.md",
        role=HomiFileRole.PERSONA,
        authority_rank=60,
        visibility=HomiVisibility.ALL_CONTEXTS,
        domains=(HomiAuthorityDomain.PERSONA,),
    ),
    HomiRolePolicy(
        file_name="IDENTITY.md",
        role=HomiFileRole.IDENTITY,
        authority_rank=50,
        visibility=HomiVisibility.PUBLIC_IDENTITY,
        domains=(HomiAuthorityDomain.IDENTITY,),
    ),
    HomiRolePolicy(
        file_name="USER.md",
        role=HomiFileRole.USER_PROFILE,
        authority_rank=70,
        visibility=HomiVisibility.MAIN_SESSION_ONLY,
        domains=(HomiAuthorityDomain.USER_CONTEXT,),
    ),
    HomiRolePolicy(
        file_name="TOOLS.md",
        role=HomiFileRole.TOOL_NOTES,
        authority_rank=80,
        visibility=HomiVisibility.PRIVATE_RUNTIME,
        domains=(HomiAuthorityDomain.ENVIRONMENT_BINDING,),
    ),
    HomiRolePolicy(
        file_name="HEARTBEAT.md",
        role=HomiFileRole.HEARTBEAT_SCHEDULE,
        authority_rank=90,
        visibility=HomiVisibility.SCHEDULER_ONLY,
        domains=(HomiAuthorityDomain.HEARTBEAT,),
    ),
)

_MARKER_RE = re.compile(r"\s+")


class HomiWorkspacePolicyResolver:
    """Resolve static Homi authority and detect deterministic file conflicts."""

    def resolve(self, inspection: HomiWorkspaceInspection) -> HomiWorkspaceResolution:
        """Return policy metadata and safe cross-file observations."""

        if not isinstance(inspection, HomiWorkspaceInspection):
            raise TypeError("inspection must be HomiWorkspaceInspection")
        records = {
            record.asset.locator.path: record
            for record in inspection.framework_result.assets
        }
        files = {item.name: item for item in inspection.files}
        observations: list[HomiPolicyObservation] = []
        self._detect_startup_conflict(files, records, observations)
        self._detect_control_plane_mutation(files, records, observations)
        self._detect_heartbeat_activation(files, records, observations)
        self._detect_static_boundaries(files, records, observations)

        missing = tuple(
            sorted(
                item.name
                for item in inspection.files
                if item.state is HomiFileState.MISSING
            )
        )
        skipped = tuple(
            sorted(
                item.name
                for item in inspection.files
                if item.state is HomiFileState.SKIPPED
            )
        )
        observations_tuple = tuple(
            sorted(
                set(observations),
                key=lambda observation: (
                    observation.code.value,
                    tuple(_locator_key(source) for source in observation.sources),
                ),
            )
        )
        has_conflict = any(
            observation.kind is HomiObservationKind.CONFLICT
            for observation in observations_tuple
        )
        status = (
            HomiResolutionStatus.CONFLICT
            if has_conflict
            else HomiResolutionStatus.PARTIAL
            if not inspection.complete or skipped or missing
            else HomiResolutionStatus.RESOLVED
        )
        return HomiWorkspaceResolution(
            policies=_HOMI_ROLE_POLICIES,
            observations=observations_tuple,
            missing_files=missing,
            skipped_files=skipped,
            status=status,
        )

    @staticmethod
    def _detect_startup_conflict(
        files: Mapping[str, HomiWorkspaceFile],
        records: Mapping[str, FrameworkAssetRecord],
        observations: list[HomiPolicyObservation],
    ) -> None:
        agents = _record_text(files, records, "AGENTS.md")
        soul = _record_text(files, records, "SOUL.md")
        if not (
            _contains_any(
                agents, ("do not manually reread", "provided context is missing")
            )
            and _contains_any(
                soul, ("each session", "read them", "these files are your memory")
            )
        ):
            return
        observations.append(
            _observation(
                HomiObservationCode.STARTUP_READ_POLICY_CONFLICT,
                HomiObservationKind.CONFLICT,
                (HomiFileRole.PERSONA, HomiFileRole.WORKSPACE_POLICY),
                files,
                resolution="workspace_policy_wins_for_startup_loading",
            )
        )

    @staticmethod
    def _detect_control_plane_mutation(
        files: Mapping[str, HomiWorkspaceFile],
        records: Mapping[str, FrameworkAssetRecord],
        observations: list[HomiPolicyObservation],
    ) -> None:
        agents = _record_text(files, records, "AGENTS.md")
        soul = _record_text(files, records, "SOUL.md")
        if not (
            _contains_any(
                agents, ("update agents.md", "update tools.md", "edit heartbeat.md")
            )
            or _contains_any(
                soul, ("change this file", "file is yours to evolve", "update them")
            )
        ):
            return
        observations.append(
            _observation(
                HomiObservationCode.CONTROL_PLANE_SELF_MODIFICATION,
                HomiObservationKind.AUTHORITY_BOUNDARY,
                (HomiFileRole.PERSONA, HomiFileRole.WORKSPACE_POLICY),
                files,
                resolution="manual_approval_required_for_control_file_changes",
            )
        )

    @staticmethod
    def _detect_heartbeat_activation(
        files: Mapping[str, HomiWorkspaceFile],
        records: Mapping[str, FrameworkAssetRecord],
        observations: list[HomiPolicyObservation],
    ) -> None:
        agents = _record_text(files, records, "AGENTS.md")
        heartbeat = files.get("HEARTBEAT.md")
        if not _contains_any(agents, ("edit heartbeat.md", "update heartbeat.md")):
            if (
                heartbeat is not None
                and getattr(heartbeat, "state", None) is HomiFileState.EMPTY
            ):
                observations.append(
                    _observation(
                        HomiObservationCode.EMPTY_HEARTBEAT_DISABLED,
                        HomiObservationKind.AUTHORITY_BOUNDARY,
                        (HomiFileRole.HEARTBEAT_SCHEDULE,),
                        files,
                        resolution="heartbeat_disabled_by_empty_file_static_state",
                    )
                )
            elif (
                heartbeat is not None
                and getattr(heartbeat, "state", None) is HomiFileState.EXAMPLE_ONLY
            ):
                observations.append(
                    _observation(
                        HomiObservationCode.HEARTBEAT_TEMPLATE_DISABLED,
                        HomiObservationKind.AUTHORITY_BOUNDARY,
                        (HomiFileRole.HEARTBEAT_SCHEDULE,),
                        files,
                        resolution=("heartbeat_disabled_by_example_only_static_state"),
                    )
                )
            return
        if heartbeat is None or getattr(heartbeat, "state", None) not in {
            HomiFileState.EMPTY,
            HomiFileState.EXAMPLE_ONLY,
        }:
            return
        observations.append(
            _observation(
                HomiObservationCode.HEARTBEAT_ACTIVATION_PATH,
                HomiObservationKind.LATENT_ACTIVATION,
                (HomiFileRole.HEARTBEAT_SCHEDULE, HomiFileRole.WORKSPACE_POLICY),
                files,
                resolution="heartbeat_changes_require_manual_approval",
            )
        )

    @staticmethod
    def _detect_static_boundaries(
        files: Mapping[str, HomiWorkspaceFile],
        records: Mapping[str, FrameworkAssetRecord],
        observations: list[HomiPolicyObservation],
    ) -> None:
        tools = files.get("TOOLS.md")
        if tools is not None and tools.state not in {
            HomiFileState.MISSING,
            HomiFileState.SKIPPED,
        }:
            observations.append(
                _observation(
                    HomiObservationCode.TOOLS_NOT_AUTHORITY,
                    HomiObservationKind.AUTHORITY_BOUNDARY,
                    (HomiFileRole.TOOL_NOTES,),
                    files,
                    resolution="tools_notes_do_not_grant_runtime_tool_authority",
                )
            )
        user_profile = files.get("USER.md")
        if user_profile is not None and user_profile.state not in {
            HomiFileState.MISSING,
            HomiFileState.SKIPPED,
        }:
            observations.append(
                _observation(
                    HomiObservationCode.USER_PROFILE_MAIN_SESSION_ONLY,
                    HomiObservationKind.AUTHORITY_BOUNDARY,
                    (HomiFileRole.USER_PROFILE,),
                    files,
                    resolution="user_profile_is_main_session_only",
                )
            )
        identity = files.get("IDENTITY.md")
        if identity is not None and identity.state not in {
            HomiFileState.MISSING,
            HomiFileState.SKIPPED,
        }:
            observations.append(
                _observation(
                    HomiObservationCode.IDENTITY_NOT_RUNTIME_AUTHORITY,
                    HomiObservationKind.AUTHORITY_BOUNDARY,
                    (HomiFileRole.IDENTITY,),
                    files,
                    resolution="identity_metadata_does_not_grant_runtime_authority",
                )
            )


def _record_text(
    files: Mapping[str, HomiWorkspaceFile],
    records: Mapping[str, FrameworkAssetRecord],
    name: str,
) -> str:
    file = files.get(name)
    if file is None or file.locator is None:
        return ""
    record = records.get(file.locator.path)
    document = record.document if record is not None else None
    if not isinstance(document, ParsedMarkdown):
        return ""
    return _MARKER_RE.sub(
        " ",
        " ".join(block.text for block in document.blocks).casefold(),
    )


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker.casefold() in text for marker in markers)


def _observation(
    code: HomiObservationCode,
    kind: HomiObservationKind,
    roles: tuple[HomiFileRole, ...],
    files: Mapping[str, HomiWorkspaceFile],
    *,
    resolution: str,
) -> HomiPolicyObservation:
    sources = tuple(
        sorted(
            (
                file.locator
                for file in files.values()
                if file.role in roles and file.locator is not None
            ),
            key=_locator_key,
        )
    )
    return HomiPolicyObservation(
        code=code,
        kind=kind,
        roles=tuple(sorted(set(roles), key=lambda item: item.value)),
        sources=sources,
        resolution=resolution,
    )


def _locator_key(locator: FrameworkAssetLocator) -> tuple[str, str, str]:
    return (locator.scope.value, locator.root_id, locator.path)


__all__ = [
    "HomiAuthorityDomain",
    "HomiObservationCode",
    "HomiObservationKind",
    "HomiPolicyObservation",
    "HomiResolutionStatus",
    "HomiRolePolicy",
    "HomiVisibility",
    "HomiWorkspacePolicyResolver",
    "HomiWorkspaceResolution",
]

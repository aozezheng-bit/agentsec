"""Static Homi capability and behavior profiles (P2-HOMI-03).

The profile is a value-minimized declaration profile. It does not enumerate
runtime tools, execute external actions, or turn Markdown claims into runtime
authority. Lexical declarations use D confidence; structural file states use B
confidence; no static path can produce A confidence.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from agentsec.domain import EvidenceConfidence
from agentsec.frameworks.base import FrameworkAssetLocator
from agentsec.frameworks.homi import (
    HomiFileRole,
    HomiFileState,
    HomiWorkspaceFile,
    HomiWorkspaceInspection,
)
from agentsec.frameworks.homi_policy import (
    HomiPolicyObservation,
    HomiResolutionStatus,
    HomiWorkspaceResolution,
)
from agentsec.parsers import ParsedMarkdown

HOMI_PROFILE_MODEL_VERSION = "0.2.0"


class HomiCapabilityState(StrEnum):
    """Static state of a declared Homi capability."""

    PRESENT = "present"
    CONDITIONAL = "conditional"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    EXAMPLE_ONLY = "example_only"


class HomiCapabilityKind(StrEnum):
    """Capability dimensions represented by the first Homi profile."""

    WORKSPACE_READ = "workspace_read"
    WORKSPACE_WRITE = "workspace_write"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    PERSISTENT_MEMORY = "persistent_memory"
    EXTERNAL_NETWORK_READ = "external_network_read"
    EXTERNAL_MESSAGE_SEND = "external_message_send"
    SHELL_EXECUTION = "shell_execution"
    SSH_ACCESS = "ssh_access"
    MCP_ACCESS = "mcp_access"
    OAUTH_ACCESS = "oauth_access"
    SECRET_ACCESS = "secret_access"
    CAMERA_ACCESS = "camera_access"
    TTS_OUTPUT = "tts_output"
    HEARTBEAT_SCHEDULE = "heartbeat_schedule"
    CRON_SCHEDULE = "cron_schedule"
    SKILL_TOOL_DISCOVERY = "skill_tool_discovery"
    GROUP_CHAT_PARTICIPATION = "group_chat_participation"
    CONTROL_FILE_SELF_MODIFICATION = "control_file_self_modification"
    PERSONA_SELF_MODIFICATION = "persona_self_modification"
    IDENTITY_SELF_MODIFICATION = "identity_self_modification"
    USER_PROFILE_PERSISTENCE = "user_profile_persistence"


class HomiPersonaSignal(StrEnum):
    """Behavioral signals extracted from SOUL.md without scoring them."""

    RESOURCEFUL = "resourceful"
    OPINIONATED = "opinionated"
    ANTI_SYCOPHANCY = "anti_sycophancy"
    PROACTIVE = "proactive"
    PRIVACY_BOUNDARY = "privacy_boundary"
    EXTERNAL_APPROVAL = "external_approval"
    GROUP_CHAT_NON_PROXY = "group_chat_non_proxy"
    SELF_EVOLUTION = "self_evolution"


class HomiAvatarKind(StrEnum):
    """Static Avatar reference kind; no remote resource is fetched."""

    NONE = "none"
    WORKSPACE_RELATIVE = "workspace_relative"
    REMOTE_URL = "remote_url"
    DATA_URI = "data_uri"
    UNKNOWN = "unknown"


class HomiEvidenceMethod(StrEnum):
    """Evidence method used by the static Homi profile."""

    STRUCTURAL_FILE_STATE = "structural_file_state"
    STATIC_DECLARATION = "static_declaration"
    STATIC_TEMPLATE_CLASSIFICATION = "static_template_classification"
    POLICY_BOUNDARY = "policy_boundary"
    RUNTIME_UNVERIFIED = "runtime_unverified"


@dataclass(frozen=True, slots=True)
class HomiProfileSignal:
    """One bounded signal with source provenance and independent confidence."""

    signal_id: str
    state: HomiCapabilityState
    confidence: EvidenceConfidence
    method: HomiEvidenceMethod
    sources: tuple[FrameworkAssetLocator, ...] = ()
    runtime_verified: bool = False

    def __post_init__(self) -> None:
        if not self.signal_id or self.signal_id != self.signal_id.strip():
            raise ValueError("Homi profile signal ID must be non-empty and exact")
        if not isinstance(self.state, HomiCapabilityState):
            raise TypeError("Homi profile signal state must be HomiCapabilityState")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("Homi profile signal confidence must be EvidenceConfidence")
        if not isinstance(self.method, HomiEvidenceMethod):
            raise TypeError("Homi profile signal method must be HomiEvidenceMethod")
        source_keys = tuple(_locator_key(source) for source in self.sources)
        if source_keys != tuple(sorted(set(source_keys))):
            raise ValueError("Homi profile signal sources must be sorted and unique")
        if self.runtime_verified:
            raise ValueError("static Homi profile cannot claim runtime verification")
        if (
            self.state in {HomiCapabilityState.UNKNOWN, HomiCapabilityState.ABSENT}
            and self.method is HomiEvidenceMethod.STATIC_DECLARATION
        ):
            raise ValueError("unknown/absent state cannot use declaration method")


@dataclass(frozen=True, slots=True)
class HomiCapability:
    """One static capability declaration or bounded unknown."""

    kind: HomiCapabilityKind
    signal: HomiProfileSignal

    def __post_init__(self) -> None:
        if not isinstance(self.kind, HomiCapabilityKind):
            raise TypeError("Homi capability kind must be HomiCapabilityKind")
        if self.signal.signal_id != self.kind.value:
            raise ValueError("Homi capability signal ID must match capability kind")


@dataclass(frozen=True, slots=True)
class HomiPersonaProfile:
    """Persona signals without treating personality as permission."""

    signals: tuple[HomiProfileSignal, ...]

    def __post_init__(self) -> None:
        _validate_signal_tuple(self.signals, "persona")


@dataclass(frozen=True, slots=True)
class HomiIdentityProfile:
    """Identity metadata profile without exposing arbitrary source values."""

    name_present: bool
    creature_present: bool
    vibe_present: bool
    emoji_present: bool
    avatar_kind: HomiAvatarKind
    identity_disclosure: HomiProfileSignal
    self_assignment: HomiProfileSignal

    def __post_init__(self) -> None:
        if not isinstance(self.avatar_kind, HomiAvatarKind):
            raise TypeError("Homi Avatar kind must be HomiAvatarKind")
        _validate_signal(self.identity_disclosure, "identity disclosure")
        _validate_signal(self.self_assignment, "identity self-assignment")


@dataclass(frozen=True, slots=True)
class HomiUserPrivacyProfile:
    """User-profile storage and sharing boundary without source values."""

    file_state: HomiFileState
    template_present: bool
    persistence: HomiProfileSignal
    main_session_only: bool
    shared_context_allowed: bool
    observed_field_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.file_state, HomiFileState):
            raise TypeError("Homi user file state must be HomiFileState")
        _validate_signal(self.persistence, "user persistence")
        if self.shared_context_allowed:
            raise ValueError("Homi USER.md cannot allow shared context in P2-HOMI-03")
        if self.observed_field_names != tuple(sorted(set(self.observed_field_names))):
            raise ValueError("Homi observed user fields must be sorted and unique")


@dataclass(frozen=True, slots=True)
class HomiToolBindingProfile:
    """Tool/environment declarations with runtime authority explicitly false."""

    camera: HomiProfileSignal
    ssh: HomiProfileSignal
    tts: HomiProfileSignal
    mcp: HomiProfileSignal
    oauth: HomiProfileSignal
    secret_access: HomiProfileSignal
    runtime_authority: bool = False

    def __post_init__(self) -> None:
        for name in ("camera", "ssh", "tts", "mcp", "oauth", "secret_access"):
            _validate_signal(getattr(self, name), f"tool binding {name}")
        if self.runtime_authority:
            raise ValueError("Homi tool binding cannot grant runtime authority")


@dataclass(frozen=True, slots=True)
class HomiHeartbeatProfile:
    """Heartbeat declaration state without claiming scheduler execution."""

    state: HomiCapabilityState
    tasks_present: bool
    api_calls_enabled_by_file: bool
    runtime_verified: bool
    signal: HomiProfileSignal

    def __post_init__(self) -> None:
        if not isinstance(self.state, HomiCapabilityState):
            raise TypeError("Homi Heartbeat state must be HomiCapabilityState")
        if self.runtime_verified:
            raise ValueError("Homi Heartbeat cannot claim runtime verification")
        _validate_signal(self.signal, "Heartbeat")
        if self.state is HomiCapabilityState.ABSENT and self.tasks_present:
            raise ValueError("absent Heartbeat cannot have tasks")
        if self.state is HomiCapabilityState.ABSENT and self.api_calls_enabled_by_file:
            raise ValueError("absent Heartbeat cannot enable API calls")
        if self.state is HomiCapabilityState.EXAMPLE_ONLY and (
            self.tasks_present or self.api_calls_enabled_by_file
        ):
            raise ValueError("example-only Heartbeat cannot enable tasks or API calls")


@dataclass(frozen=True, slots=True)
class HomiCapabilityProfile:
    """Complete static Homi profile consumed by later rules and reports."""

    capabilities: tuple[HomiCapability, ...]
    persona: HomiPersonaProfile
    identity: HomiIdentityProfile
    user_privacy: HomiUserPrivacyProfile
    tools: HomiToolBindingProfile
    heartbeat: HomiHeartbeatProfile
    resolution: HomiWorkspaceResolution
    observations: tuple[HomiPolicyObservation, ...]
    complete: bool

    def __post_init__(self) -> None:
        expected = tuple(HomiCapabilityKind)
        actual = tuple(item.kind for item in self.capabilities)
        if actual != expected:
            raise ValueError("Homi capabilities must use canonical enum order")
        if not isinstance(self.resolution, HomiWorkspaceResolution):
            raise TypeError("Homi profile resolution must be HomiWorkspaceResolution")
        if self.complete != (self.resolution.status is HomiResolutionStatus.RESOLVED):
            raise ValueError("Homi profile completion must match resolution state")
        _validate_observation_tuple(self.observations)

    def capability_for(self, kind: HomiCapabilityKind) -> HomiCapability:
        """Return the canonical capability entry for one dimension."""

        for capability in self.capabilities:
            if capability.kind is kind:
                return capability
        raise KeyError(kind)


class HomiCapabilityProfileBuilder:
    """Build a static Homi profile from P2-HOMI-01/02 results."""

    def build(
        self,
        inspection: HomiWorkspaceInspection,
        resolution: HomiWorkspaceResolution | None = None,
    ) -> HomiCapabilityProfile:
        """Build deterministic declarations without executing source content."""

        if not isinstance(inspection, HomiWorkspaceInspection):
            raise TypeError("inspection must be HomiWorkspaceInspection")
        effective_resolution = resolution or self._resolve(inspection)
        if not isinstance(effective_resolution, HomiWorkspaceResolution):
            raise TypeError("resolution must be HomiWorkspaceResolution")
        files = {item.name: item for item in inspection.files}
        texts = _texts_by_name(inspection)
        capabilities = tuple(
            HomiCapability(
                kind=kind,
                signal=self._capability_signal(kind, files, texts),
            )
            for kind in HomiCapabilityKind
        )
        persona = self._persona(files, texts)
        identity = self._identity(files, texts)
        user_privacy = self._user_privacy(files, texts)
        tools = self._tools(files, texts)
        heartbeat = self._heartbeat(files, texts)
        return HomiCapabilityProfile(
            capabilities=capabilities,
            persona=persona,
            identity=identity,
            user_privacy=user_privacy,
            tools=tools,
            heartbeat=heartbeat,
            resolution=effective_resolution,
            observations=effective_resolution.observations,
            complete=(effective_resolution.status is HomiResolutionStatus.RESOLVED),
        )

    @staticmethod
    def _resolve(inspection: HomiWorkspaceInspection) -> HomiWorkspaceResolution:
        from agentsec.frameworks.homi_policy import HomiWorkspacePolicyResolver

        return HomiWorkspacePolicyResolver().resolve(inspection)

    @staticmethod
    def _capability_signal(
        kind: HomiCapabilityKind,
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiProfileSignal:
        if kind is HomiCapabilityKind.HEARTBEAT_SCHEDULE:
            heartbeat = files["HEARTBEAT.md"]
            if heartbeat.state is HomiFileState.EMPTY:
                return _signal(
                    kind.value,
                    HomiCapabilityState.ABSENT,
                    EvidenceConfidence.B,
                    HomiEvidenceMethod.STRUCTURAL_FILE_STATE,
                    heartbeat.locator,
                )
            if heartbeat.state is HomiFileState.EXAMPLE_ONLY:
                return _signal_from_role(
                    kind.value,
                    HomiCapabilityState.EXAMPLE_ONLY,
                    HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION,
                    HomiFileRole.HEARTBEAT_SCHEDULE,
                    files,
                    confidence=EvidenceConfidence.D,
                )
            if heartbeat.state is HomiFileState.PRESENT:
                return _signal_from_role(
                    kind.value,
                    HomiCapabilityState.PRESENT,
                    HomiEvidenceMethod.STATIC_DECLARATION,
                    HomiFileRole.HEARTBEAT_SCHEDULE,
                    files,
                )
            return _unknown(kind.value)

        marker_rules: dict[HomiCapabilityKind, tuple[HomiFileRole, tuple[str, ...]]] = {
            HomiCapabilityKind.WORKSPACE_READ: (
                HomiFileRole.WORKSPACE_POLICY,
                ("read files", "read the file", "read them"),
            ),
            HomiCapabilityKind.WORKSPACE_WRITE: (
                HomiFileRole.WORKSPACE_POLICY,
                ("edit files", "write to a file", "update this file", "update them"),
            ),
            HomiCapabilityKind.MEMORY_READ: (
                HomiFileRole.WORKSPACE_POLICY,
                ("memory.md", "load in main session", "read them"),
            ),
            HomiCapabilityKind.MEMORY_WRITE: (
                HomiFileRole.WORKSPACE_POLICY,
                ("write it to a file", "update memory", "edit memory.md"),
            ),
            HomiCapabilityKind.PERSISTENT_MEMORY: (
                HomiFileRole.WORKSPACE_POLICY,
                ("long-term", "daily notes", "continuity", "persist"),
            ),
            HomiCapabilityKind.EXTERNAL_NETWORK_READ: (
                HomiFileRole.WORKSPACE_POLICY,
                ("search the web", "check calendars", "weather"),
            ),
            HomiCapabilityKind.EXTERNAL_MESSAGE_SEND: (
                HomiFileRole.WORKSPACE_POLICY,
                ("sending emails", "public posts", "sending tweets"),
            ),
            HomiCapabilityKind.SHELL_EXECUTION: (
                HomiFileRole.WORKSPACE_POLICY,
                ("execute shell", "run shell", "shell command"),
            ),
            HomiCapabilityKind.MCP_ACCESS: (
                HomiFileRole.WORKSPACE_POLICY,
                ("mcp", "model context protocol"),
            ),
            HomiCapabilityKind.SKILL_TOOL_DISCOVERY: (
                HomiFileRole.WORKSPACE_POLICY,
                ("skills provide your tools", "check its skill.md"),
            ),
            HomiCapabilityKind.GROUP_CHAT_PARTICIPATION: (
                HomiFileRole.WORKSPACE_POLICY,
                ("group chats", "group chat"),
            ),
            HomiCapabilityKind.CONTROL_FILE_SELF_MODIFICATION: (
                HomiFileRole.WORKSPACE_POLICY,
                ("update agents.md", "update tools.md", "edit heartbeat.md"),
            ),
            HomiCapabilityKind.PERSONA_SELF_MODIFICATION: (
                HomiFileRole.PERSONA,
                ("change this file", "file is yours to evolve", "update it"),
            ),
            HomiCapabilityKind.IDENTITY_SELF_MODIFICATION: (
                HomiFileRole.IDENTITY,
                ("fill this in", "make it yours", "figuring out who you are"),
            ),
            HomiCapabilityKind.USER_PROFILE_PERSISTENCE: (
                HomiFileRole.USER_PROFILE,
                ("update this as you go", "build this over time", "context"),
            ),
        }
        if kind in {
            HomiCapabilityKind.SSH_ACCESS,
            HomiCapabilityKind.CAMERA_ACCESS,
            HomiCapabilityKind.TTS_OUTPUT,
            HomiCapabilityKind.MCP_ACCESS,
            HomiCapabilityKind.OAUTH_ACCESS,
            HomiCapabilityKind.SECRET_ACCESS,
            HomiCapabilityKind.CRON_SCHEDULE,
        }:
            return HomiCapabilityProfileBuilder._tool_or_unknown(kind, files, texts)
        role_markers = marker_rules.get(kind)
        if role_markers is None:
            return _unknown(kind.value)
        role, markers = role_markers
        text = texts.get(role, "")
        if not _contains_any(text, markers):
            return _unknown(kind.value)
        state = (
            HomiCapabilityState.CONDITIONAL
            if kind is HomiCapabilityKind.EXTERNAL_MESSAGE_SEND
            else HomiCapabilityState.PRESENT
        )
        return _signal_from_role(
            kind.value,
            state,
            HomiEvidenceMethod.STATIC_DECLARATION,
            role,
            files,
        )

    @staticmethod
    def _tool_or_unknown(
        kind: HomiCapabilityKind,
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiProfileSignal:
        role = HomiFileRole.TOOL_NOTES
        file = files["TOOLS.md"]
        markers = {
            HomiCapabilityKind.SSH_ACCESS: (
                "ssh",
                "ssh host",
                "ssh hosts",
                "home-server",
            ),
            HomiCapabilityKind.CAMERA_ACCESS: ("camera", "cameras"),
            HomiCapabilityKind.TTS_OUTPUT: ("tts", "preferred voice", "speaker"),
            HomiCapabilityKind.MCP_ACCESS: ("mcp", "model context protocol"),
            HomiCapabilityKind.OAUTH_ACCESS: ("oauth",),
            HomiCapabilityKind.SECRET_ACCESS: (
                "token",
                "password",
                "secret",
                "credential",
            ),
            HomiCapabilityKind.CRON_SCHEDULE: ("cron", "exact timing"),
        }[kind]
        if file.state is HomiFileState.EXAMPLE_ONLY and _contains_any(
            texts.get(role, ""), markers
        ):
            return _signal_from_role(
                kind.value,
                HomiCapabilityState.EXAMPLE_ONLY,
                HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION,
                role,
                files,
                confidence=EvidenceConfidence.D,
            )
        if _contains_any(texts.get(role, ""), markers):
            return _signal_from_role(
                kind.value,
                HomiCapabilityState.CONDITIONAL,
                HomiEvidenceMethod.STATIC_DECLARATION,
                role,
                files,
            )
        return _unknown(kind.value)

    @staticmethod
    def _persona(
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiPersonaProfile:
        text = texts.get(HomiFileRole.PERSONA, "")
        marker_map = {
            HomiPersonaSignal.RESOURCEFUL: ("resourceful", "try to figure it out"),
            HomiPersonaSignal.OPINIONATED: ("have opinions", "allowed to disagree"),
            HomiPersonaSignal.ANTI_SYCOPHANCY: (
                "not a sycophant",
                "not performatively helpful",
            ),
            HomiPersonaSignal.PROACTIVE: ("be resourceful", "come back with answers"),
            HomiPersonaSignal.PRIVACY_BOUNDARY: (
                "private things stay private",
                "treat it with respect",
            ),
            HomiPersonaSignal.EXTERNAL_APPROVAL: (
                "when in doubt, ask",
                "external actions",
            ),
            HomiPersonaSignal.GROUP_CHAT_NON_PROXY: (
                "not the user's voice",
                "careful in group chats",
            ),
            HomiPersonaSignal.SELF_EVOLUTION: ("yours to evolve", "change this file"),
        }
        signals = tuple(
            _signal_from_role(
                signal.value,
                HomiCapabilityState.PRESENT,
                HomiEvidenceMethod.STATIC_DECLARATION,
                HomiFileRole.PERSONA,
                files,
            )
            for signal, markers in marker_map.items()
            if _contains_any(text, markers)
        )
        return HomiPersonaProfile(
            signals=tuple(sorted(signals, key=lambda signal: signal.signal_id))
        )

    @staticmethod
    def _identity(
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiIdentityProfile:
        text = texts.get(HomiFileRole.IDENTITY, "")
        avatar_kind = HomiAvatarKind.NONE
        if _contains_any(text, ("data:",)):
            avatar_kind = HomiAvatarKind.DATA_URI
        elif _contains_any(text, ("http://", "https://")):
            avatar_kind = HomiAvatarKind.REMOTE_URL
        elif _contains_any(text, ("avatar", "workspace-relative", "avatars/")):
            avatar_kind = HomiAvatarKind.WORKSPACE_RELATIVE
        disclosure = (
            HomiCapabilityState.PRESENT
            if _contains_any(text, ("ai assistant", "artificial intelligence", "ai"))
            else HomiCapabilityState.UNKNOWN
        )
        return HomiIdentityProfile(
            name_present=_contains_any(text, ("name:",)),
            creature_present=_contains_any(text, ("creature:",)),
            vibe_present=_contains_any(text, ("vibe:",)),
            emoji_present=_contains_any(text, ("emoji:",)),
            avatar_kind=avatar_kind,
            identity_disclosure=_signal_from_role(
                "identity_disclosure",
                disclosure,
                HomiEvidenceMethod.STATIC_DECLARATION
                if disclosure is HomiCapabilityState.PRESENT
                else HomiEvidenceMethod.RUNTIME_UNVERIFIED,
                HomiFileRole.IDENTITY,
                files,
                confidence=EvidenceConfidence.D,
            ),
            self_assignment=_signal_from_role(
                HomiCapabilityKind.IDENTITY_SELF_MODIFICATION.value,
                HomiCapabilityState.PRESENT
                if _contains_any(
                    text, ("fill this in", "make it yours", "figuring out who you are")
                )
                else HomiCapabilityState.UNKNOWN,
                HomiEvidenceMethod.STATIC_DECLARATION
                if _contains_any(
                    text, ("fill this in", "make it yours", "figuring out who you are")
                )
                else HomiEvidenceMethod.RUNTIME_UNVERIFIED,
                HomiFileRole.IDENTITY,
                files,
            ),
        )

    @staticmethod
    def _user_privacy(
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiUserPrivacyProfile:
        text = texts.get(HomiFileRole.USER_PROFILE, "")
        file_state = files["USER.md"].state
        fields = tuple(
            sorted(
                field
                for field in (
                    "name",
                    "preferred_name",
                    "pronouns",
                    "timezone",
                    "notes",
                    "context",
                )
                if _contains_any(text, (f"{field}:", field.replace("_", " ")))
            )
        )
        persistence_state = (
            HomiCapabilityState.PRESENT
            if _contains_any(text, ("update this as you go", "build this over time"))
            else HomiCapabilityState.UNKNOWN
        )
        return HomiUserPrivacyProfile(
            file_state=file_state,
            template_present=_contains_any(
                text, ("about your human", "context", "relatedagent workspace")
            ),
            persistence=_signal_from_role(
                HomiCapabilityKind.USER_PROFILE_PERSISTENCE.value,
                persistence_state,
                HomiEvidenceMethod.STATIC_DECLARATION
                if persistence_state is HomiCapabilityState.PRESENT
                else HomiEvidenceMethod.RUNTIME_UNVERIFIED,
                HomiFileRole.USER_PROFILE,
                files,
            ),
            main_session_only=True,
            shared_context_allowed=False,
            observed_field_names=fields,
        )

    @staticmethod
    def _tools(
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiToolBindingProfile:
        return HomiToolBindingProfile(
            camera=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.CAMERA_ACCESS, files, texts
            ),
            ssh=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.SSH_ACCESS, files, texts
            ),
            tts=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.TTS_OUTPUT, files, texts
            ),
            mcp=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.MCP_ACCESS, files, texts
            ),
            oauth=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.OAUTH_ACCESS, files, texts
            ),
            secret_access=HomiCapabilityProfileBuilder._tool_or_unknown(
                HomiCapabilityKind.SECRET_ACCESS, files, texts
            ),
        )

    @staticmethod
    def _heartbeat(
        files: Mapping[str, HomiWorkspaceFile],
        texts: Mapping[HomiFileRole, str],
    ) -> HomiHeartbeatProfile:
        file = files["HEARTBEAT.md"]
        if file.state is HomiFileState.EMPTY:
            state = HomiCapabilityState.ABSENT
            tasks_present = False
            enabled = False
            method = HomiEvidenceMethod.STRUCTURAL_FILE_STATE
            confidence = EvidenceConfidence.B
        elif file.state is HomiFileState.EXAMPLE_ONLY:
            state = HomiCapabilityState.EXAMPLE_ONLY
            tasks_present = False
            enabled = False
            method = HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION
            confidence = EvidenceConfidence.D
        elif file.state is HomiFileState.PRESENT:
            state = HomiCapabilityState.PRESENT
            tasks_present = bool(texts.get(HomiFileRole.HEARTBEAT_SCHEDULE, "").strip())
            enabled = tasks_present
            method = HomiEvidenceMethod.STATIC_DECLARATION
            confidence = EvidenceConfidence.D
        else:
            state = HomiCapabilityState.UNKNOWN
            tasks_present = False
            enabled = False
            method = HomiEvidenceMethod.RUNTIME_UNVERIFIED
            confidence = EvidenceConfidence.D
        return HomiHeartbeatProfile(
            state=state,
            tasks_present=tasks_present,
            api_calls_enabled_by_file=enabled,
            runtime_verified=False,
            signal=_signal_from_role(
                HomiCapabilityKind.HEARTBEAT_SCHEDULE.value,
                state,
                method,
                HomiFileRole.HEARTBEAT_SCHEDULE,
                files,
                confidence=confidence,
            ),
        )


def _texts_by_name(inspection: HomiWorkspaceInspection) -> dict[HomiFileRole, str]:
    records = {
        record.asset.locator.path: record
        for record in inspection.framework_result.assets
    }
    texts: dict[HomiFileRole, str] = {}
    for file in inspection.files:
        if file.locator is None:
            continue
        record = records.get(file.locator.path)
        if record is None or not isinstance(record.document, ParsedMarkdown):
            continue
        texts[file.role] = _normalize(
            " ".join(block.text for block in record.document.blocks)
        )
    return texts


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold())


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker.casefold() in text for marker in markers)


def _signal_from_role(
    signal_id: str,
    state: HomiCapabilityState,
    method: HomiEvidenceMethod,
    role: HomiFileRole,
    files: Mapping[str, HomiWorkspaceFile],
    *,
    confidence: EvidenceConfidence = EvidenceConfidence.D,
) -> HomiProfileSignal:
    source = next(
        (
            file.locator
            for file in files.values()
            if file.role is role and file.locator is not None
        ),
        None,
    )
    return _signal(signal_id, state, confidence, method, source)


def _signal(
    signal_id: str,
    state: HomiCapabilityState,
    confidence: EvidenceConfidence,
    method: HomiEvidenceMethod,
    source: FrameworkAssetLocator | None,
) -> HomiProfileSignal:
    return HomiProfileSignal(
        signal_id=signal_id,
        state=state,
        confidence=confidence,
        method=method,
        sources=(source,) if source is not None else (),
    )


def _unknown(signal_id: str) -> HomiProfileSignal:
    return _signal(
        signal_id,
        HomiCapabilityState.UNKNOWN,
        EvidenceConfidence.D,
        HomiEvidenceMethod.RUNTIME_UNVERIFIED,
        None,
    )


def _validate_signal(signal: HomiProfileSignal, label: str) -> None:
    if not isinstance(signal, HomiProfileSignal):
        raise TypeError(f"Homi {label} must be HomiProfileSignal")


def _validate_signal_tuple(signals: tuple[HomiProfileSignal, ...], label: str) -> None:
    if not isinstance(signals, tuple) or any(
        not isinstance(signal, HomiProfileSignal) for signal in signals
    ):
        raise TypeError(f"Homi {label} signals must be typed")
    ids = tuple(signal.signal_id for signal in signals)
    if ids != tuple(sorted(set(ids))):
        raise ValueError(f"Homi {label} signals must be sorted and unique")


def _validate_observation_tuple(
    observations: tuple[HomiPolicyObservation, ...],
) -> None:
    if observations != tuple(
        sorted(
            observations,
            key=lambda item: (
                item.code.value,
                tuple(_locator_key(source) for source in item.sources),
            ),
        )
    ):
        raise ValueError("Homi profile observations must be deterministically ordered")


def _locator_key(locator: FrameworkAssetLocator) -> tuple[str, str, str]:
    return (locator.scope.value, locator.root_id, locator.path)


__all__ = [
    "HOMI_PROFILE_MODEL_VERSION",
    "HomiAvatarKind",
    "HomiCapability",
    "HomiCapabilityKind",
    "HomiCapabilityProfile",
    "HomiCapabilityProfileBuilder",
    "HomiCapabilityState",
    "HomiEvidenceMethod",
    "HomiHeartbeatProfile",
    "HomiIdentityProfile",
    "HomiPersonaProfile",
    "HomiProfileSignal",
    "HomiToolBindingProfile",
    "HomiUserPrivacyProfile",
]

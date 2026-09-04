"""Deterministic Operation Context extraction for Homi workspaces (RISK-03).

The extractor translates bounded Homi Markdown evidence into the neutral
RISK-01 ``OperationContextSet`` contract. It is deliberately conservative:
boilerplate persona, identity, long-term-memory, and tool-note text is not
itself an operation. A context is emitted only when an action-like declaration
has a source-backed match. Unknown authorization, trigger, or data details are
preserved as Unknown/needs_context instead of guessed.

No scanned content is executed, sent to a Provider, or copied into the output.
Only paths, line ranges, hashes, enums, and bounded rationale codes leave the
extractor.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agentsec.domain import EvidenceConfidence
from agentsec.frameworks.base import (
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
)
from agentsec.frameworks.homi import (
    HomiFileRole,
    HomiFileState,
    HomiWorkspaceInspection,
)
from agentsec.frameworks.homi_pilot import HomiPilotReport, encode_homi_pilot_json
from agentsec.frameworks.homi_profile import (
    HomiCapabilityProfile,
    HomiCapabilityProfileBuilder,
)
from agentsec.manifests import (
    AgentManifest,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestSource,
    ManifestSourceReference,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
)
from agentsec.parsers import MarkdownBlock, ParsedMarkdown
from agentsec.risk.context import (
    AuthorizationContext,
    AuthorizationState,
    ControlEffectiveness,
    ControlState,
    DataClassification,
    DataRetention,
    DataScope,
    DataSharingScope,
    Frequency,
    OperationAction,
    OperationContext,
    OperationContextSet,
    OperationContextStatus,
    OperationEvidence,
    OperationEvidenceMethod,
    OperationPurpose,
    OperationReversibility,
    OperationScope,
    OperationTarget,
    OperationTrigger,
    build_operation_evidence,
)
from agentsec.versioning import HOMI_OPERATION_CONTEXT_OUTPUT_VERSION

HOMI_OPERATION_CONTEXT_FORMAT: Literal["agentsec-homi-operation-context-extraction"] = (
    "agentsec-homi-operation-context-extraction"
)
HOMI_OPERATION_CONTEXT_FORMAT_VERSION = HOMI_OPERATION_CONTEXT_OUTPUT_VERSION
HOMI_OPERATION_CONTEXT_BASIS = (
    "AgentSec RISK-03 deterministic Homi Operation Context extraction 0.1.0",
    "Only source-backed action declarations become Operation Contexts",
    "Unknown authorization, trigger, data, and control facts remain unknown",
    "Operation Context is evidence input and grants no runtime authority",
)

_MAX_CONTEXTS = 64
_DEFAULT_INSPECTION_LIMITS = FrameworkInspectionLimits()


class HomiOperationContextExtractionError(ValueError):
    """Raised when safe Operation Context extraction cannot be completed."""


@dataclass(frozen=True, slots=True)
class HomiOperationContextReport:
    """Operation Context extraction bound to one exact Homi Pilot report."""

    format: Literal["agentsec-homi-operation-context-extraction"]
    format_version: str
    source_report_sha256: str
    source_report_format: str
    context_set: OperationContextSet
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_OPERATION_CONTEXT_FORMAT:
            raise ValueError("Homi Operation Context format is unsupported")
        if self.format_version != HOMI_OPERATION_CONTEXT_FORMAT_VERSION:
            raise ValueError("Homi Operation Context version is unsupported")
        _require_digest(self.source_report_sha256, "source_report_sha256")
        if self.source_report_format != "agentsec-homi-report-only-pilot":
            raise ValueError("Homi Operation Context source format is unsupported")
        if not isinstance(self.context_set, OperationContextSet):
            raise TypeError("Homi Operation Context context_set is invalid")
        if self.report_only is not True:
            raise ValueError("Homi Operation Context must remain report-only")
        if self.runtime_verified is not False:
            raise ValueError("Homi Operation Context cannot verify runtime")
        if self.ci_blocked is not False:
            raise ValueError("Homi Operation Context cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_report_sha256": self.source_report_sha256,
            "source_report_format": self.source_report_format,
            "basis": list(HOMI_OPERATION_CONTEXT_BASIS),
            "context_set": self.context_set.model_dump(mode="json"),
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


@dataclass(frozen=True, slots=True)
class _HomiSourceView:
    """Safe parsed view of one Homi file used only during extraction."""

    name: str
    role: HomiFileRole
    state: HomiFileState
    content_sha256: str | None
    line_count: int | None
    document: ParsedMarkdown | None

    @property
    def text(self) -> str:
        if self.document is None:
            return ""
        return " ".join(block.text for block in self.document.blocks).casefold()


class HomiOperationContextExtractor:
    """Extract neutral Operation Contexts from a safe Homi inspection."""

    def extract(
        self,
        inspection: HomiWorkspaceInspection,
        profile: HomiCapabilityProfile | None = None,
    ) -> OperationContextSet:
        """Build a deterministic Operation Context Set without scoring risk."""

        if not isinstance(inspection, HomiWorkspaceInspection):
            raise TypeError("Homi Operation Context inspection is invalid")
        effective_profile = profile or HomiCapabilityProfileBuilder().build(inspection)
        if not isinstance(effective_profile, HomiCapabilityProfile):
            raise TypeError("Homi Operation Context profile is invalid")
        views = _source_views(inspection)
        contexts: list[OperationContext] = []
        contexts.extend(self._workspace_read(views))
        contexts.extend(self._network_read(views))
        contexts.extend(self._external_message_send(views))
        contexts.extend(self._memory_persistence(views))
        contexts.extend(self._control_file_update(views))
        contexts.extend(self._secret_read(views))
        contexts.extend(self._tool_operations(views))
        if not contexts:
            fallback = _fallback_context(views)
            if fallback is not None:
                contexts.append(fallback)
            else:
                raise HomiOperationContextExtractionError(
                    "no readable Homi evidence is available for Operation Context"
                )
        if len(contexts) > _MAX_CONTEXTS:
            raise HomiOperationContextExtractionError(
                "Operation Context extraction limit exceeded"
            )
        ordered = tuple(sorted(contexts, key=lambda item: item.operation_id))
        unknown_dimensions = tuple(
            sorted(
                {
                    f"{context.operation_id}.{dimension}"
                    for context in ordered
                    for dimension in context._primary_unknown_dimensions()
                }
            )
        )
        coverage_complete = (
            inspection.complete
            and inspection.all_standard_files_present
            and effective_profile.complete
            and not unknown_dimensions
        )
        return OperationContextSet(
            subject_id="homi-workspace",
            contexts=ordered,
            coverage_complete=coverage_complete,
            unknown_dimensions=unknown_dimensions,
            basis=HOMI_OPERATION_CONTEXT_BASIS,
        )

    def _workspace_read(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md",),
            markers=("read files", "read the file", "read workspace", "read them"),
        )
        if not evidence:
            return []
        return [
            _context(
                operation_id="homi.workspace.read",
                action=OperationAction.READ,
                target=OperationTarget.WORKSPACE,
                data_scope=DataScope(
                    classification=DataClassification.INTERNAL,
                    sharing=DataSharingScope.NONE,
                    retention=DataRetention.EPHEMERAL,
                ),
                trigger=_trigger_for_evidence(views, evidence),
                purpose=OperationPurpose.ANALYSIS,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.REVERSIBLE,
                scope=OperationScope.WORKSPACE,
                frequency=Frequency.ONE_TIME,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale="explicit_workspace_read_declaration",
            )
        ]

    def _network_read(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        markers = (
            "search the web",
            "check calendars",
            "check calendar",
            "weather",
            "fetch public",
            "read public web",
        )
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md", "HEARTBEAT.md"),
            markers=markers,
        )
        if not evidence:
            return []
        heartbeat = _view(views, "HEARTBEAT.md")
        scheduled = heartbeat is not None and heartbeat.state is HomiFileState.PRESENT
        target = (
            OperationTarget.EXTERNAL_SERVICE
            if _any_source_contains(views, ("AGENTS.md", "HEARTBEAT.md"), ("calendar",))
            else OperationTarget.PUBLIC_WEB
        )
        return [
            _context(
                operation_id="homi.network.scheduled-read"
                if scheduled
                else "homi.network.public-read",
                action=OperationAction.READ,
                target=target,
                data_scope=DataScope(
                    classification=DataClassification.PUBLIC,
                    sharing=DataSharingScope.NONE,
                    retention=DataRetention.EPHEMERAL,
                ),
                trigger=(
                    OperationTrigger.SCHEDULED
                    if scheduled
                    else _trigger_for_evidence(views, evidence)
                ),
                purpose=OperationPurpose.SEARCH,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.REVERSIBLE,
                scope=OperationScope.EXTERNAL,
                frequency=Frequency.PERIODIC if scheduled else Frequency.ONE_TIME,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale=(
                    "heartbeat_external_read_declaration"
                    if scheduled
                    else "public_external_read_declaration"
                ),
            )
        ]

    def _external_message_send(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md",),
            markers=(
                "sending emails",
                "send emails",
                "public posts",
                "sending tweets",
                "send a message",
                "send messages",
            ),
        )
        if not evidence:
            return []
        return [
            _context(
                operation_id="homi.external-message.send",
                action=OperationAction.SEND,
                target=OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
                data_scope=DataScope(
                    classification=DataClassification.UNKNOWN,
                    sharing=DataSharingScope.EXTERNAL,
                    retention=DataRetention.UNKNOWN,
                ),
                trigger=_trigger_for_evidence(views, evidence),
                purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.PARTIALLY_REVERSIBLE,
                scope=OperationScope.EXTERNAL,
                frequency=Frequency.ONE_TIME,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale="explicit_external_message_declaration",
            )
        ]

    def _memory_persistence(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        markers = (
            "store a user preference",
            "save user preference",
            "write memory",
            "write a memory",
            "update memory.md",
            "persist a note",
            "save a note",
            "write it to a file",
        )
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md", "USER.md"),
            markers=markers,
            skip_template_user=True,
        )
        if not evidence:
            return []
        target = (
            OperationTarget.USER_PROFILE
            if _any_source_contains(
                views,
                ("AGENTS.md", "USER.md"),
                ("user.md", "user profile", "user preference"),
            )
            else OperationTarget.WORKSPACE
        )
        return [
            _context(
                operation_id="homi.memory.persist",
                action=OperationAction.STORE,
                target=target,
                data_scope=DataScope(
                    classification=DataClassification.USER_PREFERENCE,
                    sharing=(
                        DataSharingScope.MAIN_SESSION
                        if target is OperationTarget.USER_PROFILE
                        else DataSharingScope.WORKSPACE
                    ),
                    retention=DataRetention.BOUNDED,
                ),
                trigger=_trigger_for_evidence(views, evidence),
                purpose=OperationPurpose.PERSISTENCE,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.REVERSIBLE,
                scope=OperationScope.USER_SCOPE,
                frequency=Frequency.PERIODIC,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale="explicit_user_context_persistence_declaration",
            )
        ]

    def _control_file_update(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md",),
            markers=(
                "update agents.md",
                "update tools.md",
                "edit heartbeat.md",
                "update heartbeat.md",
                "modify agents.md",
                "modify tools.md",
            ),
        )
        if not evidence:
            return []
        return [
            _context(
                operation_id="homi.control-file.modify",
                action=OperationAction.MODIFY_POLICY,
                target=OperationTarget.AGENT_CONTROL_FILE,
                data_scope=DataScope(
                    classification=DataClassification.INTERNAL,
                    sharing=DataSharingScope.WORKSPACE,
                    retention=DataRetention.INDEFINITE,
                ),
                trigger=_trigger_for_evidence(views, evidence),
                purpose=OperationPurpose.CONTROL_FILE_UPDATE,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.PARTIALLY_REVERSIBLE,
                scope=OperationScope.WORKSPACE,
                frequency=Frequency.PERIODIC,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale="explicit_control_file_update_declaration",
            )
        ]

    def _secret_read(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        evidence = _evidence_for_views(
            views,
            names=("AGENTS.md", "TOOLS.md"),
            patterns=(
                r"\b(?:read|access|retrieve|use|load|send|expose)\b[^\n]{0,60}"
                r"\b(?:secrets?|tokens?|passwords?|credentials?)\b",
            ),
            skip_template_tools=True,
        )
        if not evidence:
            return []
        return [
            _context(
                operation_id="homi.secret.read",
                action=OperationAction.READ,
                target=OperationTarget.SECRET,
                data_scope=DataScope(
                    classification=DataClassification.SECRET,
                    sharing=DataSharingScope.NONE,
                    retention=DataRetention.EPHEMERAL,
                ),
                trigger=_trigger_for_evidence(views, evidence),
                purpose=OperationPurpose.ANALYSIS,
                authorization=_authorization_for_evidence(views, evidence),
                reversibility=OperationReversibility.REVERSIBLE,
                scope=OperationScope.USER_SCOPE,
                frequency=Frequency.ONE_TIME,
                controls=_controls_for_evidence(views, evidence),
                evidence=evidence,
                rationale="explicit_sensitive_data_read_declaration",
            )
        ]

    def _tool_operations(
        self, views: tuple[_HomiSourceView, ...]
    ) -> list[OperationContext]:
        contexts: list[OperationContext] = []
        ssh = _evidence_for_views(
            views,
            names=("TOOLS.md",),
            patterns=(
                r"\b(?:connect|login|log in|ssh into|execute on)\b[^\n]{0,60}"
                r"\bssh\b",
            ),
            skip_template_tools=True,
        )
        if ssh:
            contexts.append(
                _context(
                    operation_id="homi.ssh.connect",
                    action=OperationAction.EXECUTE,
                    target=OperationTarget.EXTERNAL_SERVICE,
                    data_scope=DataScope(
                        classification=DataClassification.INTERNAL,
                        sharing=DataSharingScope.EXTERNAL,
                        retention=DataRetention.SESSION,
                    ),
                    trigger=_trigger_for_evidence(views, ssh),
                    purpose=OperationPurpose.ADMINISTRATION,
                    authorization=_authorization_for_evidence(views, ssh),
                    reversibility=OperationReversibility.PARTIALLY_REVERSIBLE,
                    scope=OperationScope.EXTERNAL,
                    frequency=Frequency.ONE_TIME,
                    controls=_controls_for_evidence(views, ssh),
                    evidence=ssh,
                    rationale="explicit_ssh_operation_declaration",
                )
            )
        mcp = _evidence_for_views(
            views,
            names=("AGENTS.md", "TOOLS.md"),
            patterns=(
                r"\b(?:use|connect to|invoke|call)\b[^\n]{0,50}"
                r"\bmcp\b",
            ),
            skip_template_tools=True,
        )
        if mcp:
            contexts.append(
                _context(
                    operation_id="homi.mcp.invoke",
                    action=OperationAction.EXECUTE,
                    target=OperationTarget.MCP_SERVER,
                    data_scope=DataScope(
                        classification=DataClassification.UNKNOWN,
                        sharing=DataSharingScope.EXTERNAL,
                        retention=DataRetention.SESSION,
                    ),
                    trigger=_trigger_for_evidence(views, mcp),
                    purpose=OperationPurpose.ADMINISTRATION,
                    authorization=_authorization_for_evidence(views, mcp),
                    reversibility=OperationReversibility.PARTIALLY_REVERSIBLE,
                    scope=OperationScope.EXTERNAL,
                    frequency=Frequency.ONE_TIME,
                    controls=_controls_for_evidence(views, mcp),
                    evidence=mcp,
                    rationale="explicit_mcp_operation_declaration",
                )
            )
        oauth = _evidence_for_views(
            views,
            names=("AGENTS.md", "TOOLS.md"),
            patterns=(
                r"\b(?:use|request|refresh|exchange|send)\b[^\n]{0,50}"
                r"\boauth\b",
            ),
            skip_template_tools=True,
        )
        if oauth:
            contexts.append(
                _context(
                    operation_id="homi.oauth.use",
                    action=OperationAction.EXECUTE,
                    target=OperationTarget.EXTERNAL_SERVICE,
                    data_scope=DataScope(
                        classification=DataClassification.CREDENTIAL,
                        sharing=DataSharingScope.EXTERNAL,
                        retention=DataRetention.SESSION,
                    ),
                    trigger=_trigger_for_evidence(views, oauth),
                    purpose=OperationPurpose.ADMINISTRATION,
                    authorization=_authorization_for_evidence(views, oauth),
                    reversibility=OperationReversibility.REVERSIBLE,
                    scope=OperationScope.EXTERNAL,
                    frequency=Frequency.ONE_TIME,
                    controls=_controls_for_evidence(views, oauth),
                    evidence=oauth,
                    rationale="explicit_oauth_operation_declaration",
                )
            )
        return contexts


def build_manifest_operation_context_set(
    manifest: AgentManifest,
) -> OperationContextSet:
    """Extract Operation Contexts from a validated neutral Agent Manifest.

    Manifest values are normalized static declarations, so their Evidence uses
    confidence C and the ``manifest`` extraction method. Denied tool/permission
    declarations are not emitted as executable operation paths; unresolved
    coverage is preserved in ``unknown_dimensions``.
    """

    if not isinstance(manifest, AgentManifest):
        raise TypeError("Manifest Operation Context extraction requires AgentManifest")
    sources = {source.locator.sort_key(): source for source in manifest.sources}
    contexts: list[OperationContext] = []
    for permission in manifest.permissions.permissions:
        if permission.effect is ManifestPermissionEffect.DENY:
            continue
        evidence = _manifest_evidence(permission.sources, sources)
        if not evidence:
            continue
        contexts.append(
            _context(
                operation_id=f"manifest.permission.{permission.permission_id}",
                action=_manifest_permission_action(permission.action),
                target=_manifest_target(permission.resource, permission.scope),
                data_scope=DataScope(
                    classification=_manifest_data_classification(permission.resource),
                    sharing=_manifest_sharing(permission.scope),
                    retention=DataRetention.SESSION,
                ),
                trigger=(
                    OperationTrigger.USER_CONFIRMED
                    if permission.effect is ManifestPermissionEffect.PROMPT
                    else OperationTrigger.POLICY_TRIGGERED
                    if permission.effect is ManifestPermissionEffect.ALLOW
                    else OperationTrigger.UNKNOWN
                ),
                purpose=_manifest_purpose(permission.action),
                authorization=_manifest_authorization(permission.effect),
                reversibility=OperationReversibility.PARTIALLY_REVERSIBLE,
                scope=_manifest_operation_scope(permission.scope),
                frequency=Frequency.ONE_TIME,
                controls=ControlEffectiveness(
                    approval=(
                        ControlState.PRESENT
                        if permission.effect is ManifestPermissionEffect.PROMPT
                        else ControlState.UNKNOWN
                    )
                ),
                evidence=evidence,
                rationale="manifest_permission_declaration",
            )
        )
    for tool in manifest.tools.tools:
        if tool.availability is ManifestToolAvailability.DISABLED:
            continue
        for side_effect in tool.side_effects:
            evidence = _manifest_evidence(tool.sources, sources)
            if not evidence:
                continue
            contexts.append(
                _context(
                    operation_id=(f"manifest.tool.{tool.tool_id}.{side_effect.value}"),
                    action=_manifest_side_effect_action(side_effect),
                    target=_manifest_tool_target(tool.kind),
                    data_scope=DataScope(
                        classification=_manifest_side_effect_data(side_effect),
                        sharing=(
                            DataSharingScope.EXTERNAL
                            if side_effect
                            in {
                                ManifestToolSideEffect.NETWORK,
                                ManifestToolSideEffect.PRIVILEGED,
                            }
                            else DataSharingScope.UNKNOWN
                        ),
                        retention=DataRetention.SESSION,
                    ),
                    trigger=OperationTrigger.UNKNOWN,
                    purpose=_manifest_side_effect_purpose(side_effect),
                    authorization=AuthorizationContext(
                        state=AuthorizationState.UNKNOWN
                    ),
                    reversibility=(
                        OperationReversibility.IRREVERSIBLE
                        if side_effect is ManifestToolSideEffect.DESTRUCTIVE
                        else OperationReversibility.PARTIALLY_REVERSIBLE
                    ),
                    scope=(
                        OperationScope.EXTERNAL
                        if side_effect
                        in {
                            ManifestToolSideEffect.NETWORK,
                            ManifestToolSideEffect.PRIVILEGED,
                        }
                        else OperationScope.WORKSPACE
                    ),
                    frequency=Frequency.ONE_TIME,
                    controls=ControlEffectiveness(),
                    evidence=evidence,
                    rationale="manifest_tool_side_effect_declaration",
                )
            )
    if not contexts:
        fallback = _manifest_fallback_context(manifest, sources)
        if fallback is None:
            raise HomiOperationContextExtractionError(
                "Manifest contains no source evidence for Operation Context extraction"
            )
        contexts.append(fallback)
    ordered = tuple(sorted(contexts, key=lambda item: item.operation_id))
    unknown_dimensions = tuple(
        sorted(
            {f"manifest.{unknown.unknown_id}" for unknown in manifest.unknowns}
            | {
                "manifest.tools.resolution"
                for _ in [0]
                if manifest.tools.resolution.value not in {"resolved", "not_applicable"}
            }
            | {
                "manifest.permissions.resolution"
                for _ in [0]
                if manifest.permissions.resolution.value
                not in {"resolved", "not_applicable"}
            }
        )
    )
    coverage_complete = (
        manifest.coverage.complete
        and not unknown_dimensions
        and all(item.status is OperationContextStatus.COMPLETE for item in ordered)
    )
    return OperationContextSet(
        subject_id=manifest.identity.agent_id,
        contexts=ordered,
        coverage_complete=coverage_complete,
        unknown_dimensions=unknown_dimensions,
        basis=HOMI_OPERATION_CONTEXT_BASIS,
    )


def _manifest_evidence(
    references: tuple[ManifestSourceReference, ...],
    sources: Mapping[tuple[str, str, str], ManifestSource],
) -> tuple[OperationEvidence, ...]:
    evidence: dict[str, OperationEvidence] = {}
    for reference in references:
        locator = reference.locator
        source = sources.get(locator.sort_key())
        if source is None:
            continue
        item = build_operation_evidence(
            source_path=locator.path,
            content_sha256=source.content_sha256,
            extraction_method=OperationEvidenceMethod.MANIFEST,
            confidence=EvidenceConfidence.C,
            field_path=reference.field_path,
            start_line=reference.start_line,
            end_line=reference.end_line,
        )
        evidence[item.evidence_id] = item
    return tuple(sorted(evidence.values(), key=lambda item: item.sort_key()))


def _manifest_fallback_context(
    manifest: AgentManifest,
    sources: Mapping[tuple[str, str, str], ManifestSource],
) -> OperationContext | None:
    for source in manifest.sources:
        evidence = _manifest_evidence(
            (ManifestSourceReference(locator=source.locator),),
            sources,
        )
        if evidence:
            return _context(
                operation_id="manifest.operation.unknown",
                action=OperationAction.UNKNOWN,
                target=OperationTarget.UNKNOWN,
                data_scope=DataScope(classification=DataClassification.UNKNOWN),
                trigger=OperationTrigger.UNKNOWN,
                purpose=OperationPurpose.UNKNOWN,
                authorization=AuthorizationContext(state=AuthorizationState.UNKNOWN),
                reversibility=OperationReversibility.UNKNOWN,
                scope=OperationScope.UNKNOWN,
                frequency=Frequency.UNKNOWN,
                controls=ControlEffectiveness(),
                evidence=evidence,
                rationale="manifest_operation_not_resolved",
                status_override=OperationContextStatus.UNKNOWN,
            )
    return None


def _manifest_permission_action(action: ManifestPermissionAction) -> OperationAction:
    return {
        ManifestPermissionAction.READ: OperationAction.READ,
        ManifestPermissionAction.WRITE: OperationAction.WRITE,
        ManifestPermissionAction.EXECUTE: OperationAction.EXECUTE,
        ManifestPermissionAction.NETWORK: OperationAction.READ,
        ManifestPermissionAction.SECRET_ACCESS: OperationAction.READ,
        ManifestPermissionAction.ADMIN: OperationAction.MODIFY_POLICY,
        ManifestPermissionAction.DEPLOY: OperationAction.EXECUTE,
        ManifestPermissionAction.PUBLISH: OperationAction.SEND,
        ManifestPermissionAction.DELEGATE: OperationAction.EXECUTE,
        ManifestPermissionAction.PERSIST: OperationAction.STORE,
        ManifestPermissionAction.UNKNOWN: OperationAction.UNKNOWN,
    }[action]


def _manifest_target(
    resource: ManifestResourceKind,
    scope: ManifestResourceScope,
) -> OperationTarget:
    del scope
    return {
        ManifestResourceKind.FILESYSTEM: OperationTarget.LOCAL_FILE,
        ManifestResourceKind.REPOSITORY: OperationTarget.WORKSPACE,
        ManifestResourceKind.SHELL: OperationTarget.WORKSPACE,
        ManifestResourceKind.NETWORK: OperationTarget.EXTERNAL_SERVICE,
        ManifestResourceKind.ENVIRONMENT: OperationTarget.CREDENTIAL,
        ManifestResourceKind.SECRET_STORE: OperationTarget.SECRET,
        ManifestResourceKind.IDENTITY: OperationTarget.AGENT_CONTROL_FILE,
        ManifestResourceKind.PRODUCTION: OperationTarget.PRODUCTION_SYSTEM,
        ManifestResourceKind.TOOL: OperationTarget.TOOL_REGISTRY,
        ManifestResourceKind.MEMORY: OperationTarget.USER_PROFILE,
        ManifestResourceKind.OTHER: OperationTarget.UNKNOWN,
        ManifestResourceKind.UNKNOWN: OperationTarget.UNKNOWN,
    }[resource]


def _manifest_data_classification(resource: ManifestResourceKind) -> DataClassification:
    return {
        ManifestResourceKind.SECRET_STORE: DataClassification.SECRET,
        ManifestResourceKind.ENVIRONMENT: DataClassification.CREDENTIAL,
        ManifestResourceKind.IDENTITY: DataClassification.SENSITIVE,
        ManifestResourceKind.PRODUCTION: DataClassification.SENSITIVE,
        ManifestResourceKind.MEMORY: DataClassification.USER_PREFERENCE,
        ManifestResourceKind.NETWORK: DataClassification.PUBLIC,
    }.get(resource, DataClassification.UNKNOWN)


def _manifest_sharing(scope: ManifestResourceScope) -> DataSharingScope:
    return {
        ManifestResourceScope.PROJECT: DataSharingScope.WORKSPACE,
        ManifestResourceScope.USER: DataSharingScope.MAIN_SESSION,
        ManifestResourceScope.EXTERNAL: DataSharingScope.EXTERNAL,
    }.get(scope, DataSharingScope.UNKNOWN)


def _manifest_authorization(effect: ManifestPermissionEffect) -> AuthorizationContext:
    if effect is ManifestPermissionEffect.ALLOW:
        return AuthorizationContext(state=AuthorizationState.POLICY_ALLOWED)
    if effect is ManifestPermissionEffect.PROMPT:
        return AuthorizationContext(
            state=AuthorizationState.APPROVAL_REQUIRED,
            approval_required=True,
            approval_present=None,
        )
    return AuthorizationContext(state=AuthorizationState.UNKNOWN)


def _manifest_purpose(action: ManifestPermissionAction) -> OperationPurpose:
    if action is ManifestPermissionAction.NETWORK:
        return OperationPurpose.SEARCH
    if action is ManifestPermissionAction.PERSIST:
        return OperationPurpose.PERSISTENCE
    if action in {ManifestPermissionAction.ADMIN, ManifestPermissionAction.DELEGATE}:
        return OperationPurpose.ADMINISTRATION
    if action in {ManifestPermissionAction.DEPLOY, ManifestPermissionAction.PUBLISH}:
        return OperationPurpose.DEPLOYMENT
    return OperationPurpose.ANALYSIS


def _manifest_operation_scope(scope: ManifestResourceScope) -> OperationScope:
    return {
        ManifestResourceScope.PROJECT: OperationScope.WORKSPACE,
        ManifestResourceScope.USER: OperationScope.USER_SCOPE,
        ManifestResourceScope.SYSTEM: OperationScope.GLOBAL,
        ManifestResourceScope.EXTERNAL: OperationScope.EXTERNAL,
        ManifestResourceScope.DEVELOPMENT: OperationScope.WORKSPACE,
        ManifestResourceScope.TEST: OperationScope.WORKSPACE,
        ManifestResourceScope.STAGING: OperationScope.EXTERNAL,
        ManifestResourceScope.PRODUCTION: OperationScope.ORGANIZATION,
        ManifestResourceScope.UNKNOWN: OperationScope.UNKNOWN,
    }[scope]


def _manifest_tool_target(kind: ManifestToolKind) -> OperationTarget:
    return (
        OperationTarget.MCP_SERVER
        if kind is ManifestToolKind.MCP_SERVER
        else OperationTarget.TOOL_REGISTRY
    )


def _manifest_side_effect_action(
    side_effect: ManifestToolSideEffect,
) -> OperationAction:
    return {
        ManifestToolSideEffect.READ: OperationAction.READ,
        ManifestToolSideEffect.WRITE: OperationAction.WRITE,
        ManifestToolSideEffect.EXECUTE: OperationAction.EXECUTE,
        ManifestToolSideEffect.NETWORK: OperationAction.READ,
        ManifestToolSideEffect.DESTRUCTIVE: OperationAction.DELETE,
        ManifestToolSideEffect.SECRET_ACCESS: OperationAction.READ,
        ManifestToolSideEffect.PRIVILEGED: OperationAction.EXECUTE,
        ManifestToolSideEffect.UNKNOWN: OperationAction.UNKNOWN,
    }[side_effect]


def _manifest_side_effect_data(
    side_effect: ManifestToolSideEffect,
) -> DataClassification:
    return (
        DataClassification.SECRET
        if side_effect is ManifestToolSideEffect.SECRET_ACCESS
        else DataClassification.SENSITIVE
        if side_effect is ManifestToolSideEffect.PRIVILEGED
        else DataClassification.UNKNOWN
    )


def _manifest_side_effect_purpose(
    side_effect: ManifestToolSideEffect,
) -> OperationPurpose:
    return {
        ManifestToolSideEffect.READ: OperationPurpose.ANALYSIS,
        ManifestToolSideEffect.WRITE: OperationPurpose.MAINTENANCE,
        ManifestToolSideEffect.EXECUTE: OperationPurpose.ADMINISTRATION,
        ManifestToolSideEffect.NETWORK: OperationPurpose.SEARCH,
        ManifestToolSideEffect.DESTRUCTIVE: OperationPurpose.MAINTENANCE,
        ManifestToolSideEffect.SECRET_ACCESS: OperationPurpose.ANALYSIS,
        ManifestToolSideEffect.PRIVILEGED: OperationPurpose.ADMINISTRATION,
        ManifestToolSideEffect.UNKNOWN: OperationPurpose.UNKNOWN,
    }[side_effect]


def build_homi_operation_context_set(
    inspection: HomiWorkspaceInspection,
    profile: HomiCapabilityProfile | None = None,
) -> OperationContextSet:
    """Public convenience wrapper for extraction without Pilot binding."""

    return HomiOperationContextExtractor().extract(inspection, profile)


def build_homi_operation_context_report(
    inspection: HomiWorkspaceInspection,
    pilot_report: HomiPilotReport,
    profile: HomiCapabilityProfile | None = None,
) -> HomiOperationContextReport:
    """Build a Pilot-bound Operation Context extraction report."""

    if not isinstance(pilot_report, HomiPilotReport):
        raise TypeError("Homi Operation Context requires HomiPilotReport")
    _assert_inspection_matches_pilot(inspection, pilot_report)
    context_set = build_homi_operation_context_set(inspection, profile)
    source = hashlib.sha256(
        encode_homi_pilot_json(pilot_report).encode("utf-8")
    ).hexdigest()
    return HomiOperationContextReport(
        format=HOMI_OPERATION_CONTEXT_FORMAT,
        format_version=HOMI_OPERATION_CONTEXT_FORMAT_VERSION,
        source_report_sha256=source,
        source_report_format=pilot_report.format,
        context_set=context_set,
    )


def build_homi_operation_context_report_from_workspace(
    target_root: Path,
    pilot_report: HomiPilotReport,
    *,
    limits: FrameworkInspectionLimits = _DEFAULT_INSPECTION_LIMITS,
) -> HomiOperationContextReport:
    """Reinspect one explicit workspace and bind extraction to a Pilot report."""

    from agentsec.frameworks.homi import HomiAdapter
    from agentsec.frameworks.homi_policy import HomiWorkspacePolicyResolver

    inspection = HomiAdapter().inspect_workspace(
        FrameworkInspectionRequest(project_root=target_root, limits=limits)
    )
    resolution = HomiWorkspacePolicyResolver().resolve(inspection)
    profile = HomiCapabilityProfileBuilder().build(inspection, resolution)
    return build_homi_operation_context_report(inspection, pilot_report, profile)


def encode_homi_operation_context_json(report: HomiOperationContextReport) -> str:
    """Encode a deterministic Pilot-bound Operation Context report."""

    if not isinstance(report, HomiOperationContextReport):
        raise TypeError("Homi Operation Context encoder requires its report type")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def export_homi_operation_context_json_schema(output_directory: Path) -> Path:
    """Export the strict JSON Schema for RISK-03 extraction output."""

    if not isinstance(output_directory, Path):
        raise TypeError("Homi Operation Context schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "homi-operation-context.schema.json"
    context_schema = OperationContextSet.model_json_schema(mode="serialization")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/homi-operation-context.schema.json",
        "title": "AgentSec Homi Operation Context Extraction Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "source_report_sha256",
            "source_report_format",
            "basis",
            "context_set",
            "report_only",
            "runtime_verified",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": HOMI_OPERATION_CONTEXT_FORMAT},
            "format_version": {"const": HOMI_OPERATION_CONTEXT_FORMAT_VERSION},
            "source_report_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_report_format": {"const": "agentsec-homi-report-only-pilot"},
            "basis": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": len(HOMI_OPERATION_CONTEXT_BASIS),
                "uniqueItems": True,
            },
            "context_set": context_schema,
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "ci_blocked": {"const": False},
            "authority": {
                "type": "object",
                "additionalProperties": False,
                "required": ["report_only", "runtime_verified", "ci_blocked"],
                "properties": {
                    "report_only": {"const": True},
                    "runtime_verified": {"const": False},
                    "ci_blocked": {"const": False},
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _source_views(inspection: HomiWorkspaceInspection) -> tuple[_HomiSourceView, ...]:
    records = {
        record.asset.locator.path: record
        for record in inspection.framework_result.assets
    }
    views: list[_HomiSourceView] = []
    for item in inspection.files:
        record = records.get(item.locator.path) if item.locator is not None else None
        document = (
            record.document
            if record is not None and isinstance(record.document, ParsedMarkdown)
            else None
        )
        views.append(
            _HomiSourceView(
                name=item.name,
                role=item.role,
                state=item.state,
                content_sha256=item.content_sha256,
                line_count=item.line_count,
                document=document,
            )
        )
    return tuple(views)


def _view(views: tuple[_HomiSourceView, ...], name: str) -> _HomiSourceView | None:
    return next((item for item in views if item.name == name), None)


def _evidence_for_views(
    views: tuple[_HomiSourceView, ...],
    *,
    names: tuple[str, ...],
    markers: tuple[str, ...] = (),
    patterns: tuple[str, ...] = (),
    skip_template_user: bool = False,
    skip_template_tools: bool = False,
) -> tuple[OperationEvidence, ...]:
    evidence: dict[str, OperationEvidence] = {}
    for name in names:
        view = _view(views, name)
        if view is None or view.document is None or view.content_sha256 is None:
            continue
        if skip_template_user and name == "USER.md" and _is_template_user(view):
            continue
        if (
            skip_template_tools
            and name == "TOOLS.md"
            and view.state is HomiFileState.EXAMPLE_ONLY
        ):
            continue
        for block in view.document.blocks:
            text = f"{block.text} {block.raw_text}".casefold()
            matched_marker = any(marker.casefold() in text for marker in markers)
            matched_pattern = any(
                re.search(pattern, text) is not None for pattern in patterns
            )
            if not matched_marker and not matched_pattern:
                continue
            start_line, end_line = _matching_line_range(
                block, markers=markers, patterns=patterns
            )
            method = (
                OperationEvidenceMethod.STATIC_DECLARATION
                if view.state is HomiFileState.PRESENT
                else OperationEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION
            )
            item = build_operation_evidence(
                source_path=view.name,
                content_sha256=view.content_sha256,
                extraction_method=method,
                confidence=EvidenceConfidence.D,
                start_line=start_line,
                end_line=end_line,
            )
            evidence[item.evidence_id] = item
    return tuple(sorted(evidence.values(), key=lambda item: item.sort_key()))


def _matching_line_range(
    block: MarkdownBlock,
    *,
    markers: tuple[str, ...],
    patterns: tuple[str, ...],
) -> tuple[int, int]:
    """Narrow block evidence to the smallest safe source line range."""

    start_line = block.start_line
    raw_text = block.raw_text
    for offset, raw_line in enumerate(raw_text.splitlines()):
        folded = raw_line.casefold()
        if any(marker.casefold() in folded for marker in markers) or any(
            re.search(pattern, folded) is not None for pattern in patterns
        ):
            line = start_line + offset
            return line, line
    return start_line, block.end_line


def _any_source_contains(
    views: tuple[_HomiSourceView, ...],
    names: tuple[str, ...],
    markers: tuple[str, ...],
) -> bool:
    return any(
        _contains_any(view.text, markers)
        for name in names
        for view in views
        if view.name == name
    )


def _context(
    *,
    operation_id: str,
    action: OperationAction,
    target: OperationTarget,
    data_scope: DataScope,
    trigger: OperationTrigger,
    purpose: OperationPurpose,
    authorization: AuthorizationContext,
    reversibility: OperationReversibility,
    scope: OperationScope,
    frequency: Frequency,
    controls: ControlEffectiveness,
    evidence: tuple[OperationEvidence, ...],
    rationale: str,
    status_override: OperationContextStatus | None = None,
) -> OperationContext:
    unknown = (
        action is OperationAction.UNKNOWN,
        target is OperationTarget.UNKNOWN,
        data_scope.classification is DataClassification.UNKNOWN,
        trigger is OperationTrigger.UNKNOWN,
        purpose is OperationPurpose.UNKNOWN,
        authorization.state is AuthorizationState.UNKNOWN,
    )
    status = status_override or (
        OperationContextStatus.COMPLETE
        if not any(unknown)
        else OperationContextStatus.NEEDS_CONTEXT
    )
    return OperationContext(
        operation_id=operation_id,
        action=action,
        target=target,
        data_scope=data_scope,
        trigger=trigger,
        purpose=purpose,
        authorization=authorization,
        reversibility=reversibility,
        scope=scope,
        frequency=frequency,
        controls=controls,
        evidence=evidence,
        status=status,
    )


def _authorization_for_evidence(
    views: tuple[_HomiSourceView, ...],
    evidence: tuple[OperationEvidence, ...],
) -> AuthorizationContext:
    text = _evidence_text(views, evidence)
    if _contains_any(
        text,
        (
            "ask before",
            "ask first",
            "requires asking",
            "manual approval",
            "with approval",
        ),
    ):
        return AuthorizationContext(
            state=AuthorizationState.APPROVAL_REQUIRED,
            approval_required=True,
            approval_present=None,
        )
    return AuthorizationContext(state=AuthorizationState.UNKNOWN)


def _controls_for_evidence(
    views: tuple[_HomiSourceView, ...],
    evidence: tuple[OperationEvidence, ...],
) -> ControlEffectiveness:
    text = _evidence_text(views, evidence)
    approval = (
        ControlState.PRESENT
        if _contains_any(
            text,
            (
                "ask before",
                "ask first",
                "requires asking",
                "manual approval",
                "with approval",
            ),
        )
        else ControlState.UNKNOWN
    )
    return ControlEffectiveness(
        approval=approval,
        user_consent=approval,
        audit=(
            ControlState.PRESENT
            if _contains_any(text, ("audit", "log"))
            else ControlState.UNKNOWN
        ),
        redaction=(
            ControlState.PRESENT
            if _contains_any(text, ("redact", "do not expose"))
            else ControlState.UNKNOWN
        ),
        allowlist=(
            ControlState.PRESENT
            if _contains_any(text, ("allowlist", "allow list"))
            else ControlState.UNKNOWN
        ),
        rate_limit=(
            ControlState.PRESENT
            if _contains_any(text, ("rate limit", "rate-limit"))
            else ControlState.UNKNOWN
        ),
        retention=ControlState.UNKNOWN,
    )


def _trigger_for_evidence(
    views: tuple[_HomiSourceView, ...],
    evidence: tuple[OperationEvidence, ...],
) -> OperationTrigger:
    text = _evidence_text(views, evidence)
    if _contains_any(
        text, ("when the user", "user request", "user asked", "on request")
    ):
        return OperationTrigger.USER_REQUESTED
    if _contains_any(text, ("proactive", "be proactive", "take initiative")):
        return OperationTrigger.PROACTIVE
    return OperationTrigger.UNKNOWN


def _evidence_text(
    views: tuple[_HomiSourceView, ...],
    evidence: tuple[OperationEvidence, ...],
) -> str:
    """Return normalized text only for the source lines behind an operation."""

    ranges = {item.source_path: (item.start_line, item.end_line) for item in evidence}
    pieces: list[str] = []
    for view in views:
        line_range = ranges.get(view.name)
        if line_range is None or view.document is None:
            continue
        start_line, end_line = line_range
        for block in view.document.blocks:
            if (
                start_line is None
                or end_line is None
                or (block.start_line <= end_line and block.end_line >= start_line)
            ):
                lines = block.raw_text.splitlines()
                first = max(0, (start_line or block.start_line) - block.start_line)
                last = min(
                    len(lines),
                    (end_line or block.end_line) - block.start_line + 1,
                )
                pieces.extend(lines[first:last] or [block.text])
    return " ".join(pieces).casefold()


def _is_template_user(view: _HomiSourceView) -> bool:
    """Return true when USER.md contains only shipped placeholder language."""

    if view.state is HomiFileState.EXAMPLE_ONLY:
        return True
    if view.document is None:
        return True
    text = view.text
    markers = (
        "about your human",
        "learn about the person",
        "update this as you go",
        "build this over time",
        "relatedagent workspace",
        "what to call them",
        "context",
    )
    if not all(
        marker in text for marker in ("about your human", "update this as you go")
    ):
        return False
    for block in view.document.blocks:
        folded = block.raw_text.strip().casefold()
        if not folded or folded.startswith("#"):
            continue
        if any(marker in folded for marker in markers):
            continue
        if re.match(
            r"^(name|what to call them|pronouns|timezone|notes|context)\s*:\s*$", folded
        ):
            continue
        return False
    return True


def _fallback_context(views: tuple[_HomiSourceView, ...]) -> OperationContext | None:
    for view in views:
        if view.document is None or view.content_sha256 is None or not view.line_count:
            continue
        evidence = build_operation_evidence(
            source_path=view.name,
            content_sha256=view.content_sha256,
            extraction_method=OperationEvidenceMethod.STRUCTURAL_FILE_STATE,
            confidence=EvidenceConfidence.B,
            start_line=1,
            end_line=view.line_count,
        )
        return _context(
            operation_id="homi.operation.unknown",
            action=OperationAction.UNKNOWN,
            target=OperationTarget.UNKNOWN,
            data_scope=DataScope(classification=DataClassification.UNKNOWN),
            trigger=OperationTrigger.UNKNOWN,
            purpose=OperationPurpose.UNKNOWN,
            authorization=AuthorizationContext(state=AuthorizationState.UNKNOWN),
            reversibility=OperationReversibility.UNKNOWN,
            scope=OperationScope.UNKNOWN,
            frequency=Frequency.UNKNOWN,
            controls=ControlEffectiveness(),
            evidence=(evidence,),
            rationale="no_action_declaration_identified",
            status_override=OperationContextStatus.UNKNOWN,
        )
    return None


def _assert_inspection_matches_pilot(
    inspection: HomiWorkspaceInspection,
    report: HomiPilotReport,
) -> None:
    actual = {
        item.name: (
            item.state.value,
            item.content_sha256,
            item.size_bytes,
            item.line_count,
        )
        for item in inspection.files
    }
    expected = {
        item.name: (
            item.state.value,
            item.content_sha256,
            item.size_bytes,
            item.line_count,
        )
        for item in report.files
    }
    if actual != expected:
        raise HomiOperationContextExtractionError(
            "workspace changed between Pilot scan and Operation Context extraction"
        )


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker.casefold() in text for marker in markers)


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


__all__ = [
    "HOMI_OPERATION_CONTEXT_BASIS",
    "HOMI_OPERATION_CONTEXT_FORMAT",
    "HOMI_OPERATION_CONTEXT_FORMAT_VERSION",
    "HomiOperationContextExtractionError",
    "HomiOperationContextExtractor",
    "HomiOperationContextReport",
    "build_homi_operation_context_report",
    "build_manifest_operation_context_set",
    "build_homi_operation_context_report_from_workspace",
    "build_homi_operation_context_set",
    "encode_homi_operation_context_json",
    "export_homi_operation_context_json_schema",
]

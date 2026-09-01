"""Deterministic static permission, control, and identity extraction.

P2-09 builds a conservative capability profile from the P2-08 static tool
associations and the parser-backed Framework inspection result. It records what
configuration can declare, not what a process has proved at runtime.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from agentsec.frameworks import FrameworkAssetRole, FrameworkInspectionResult
from agentsec.manifests.associations import (
    AssociationExtractor,
)
from agentsec.manifests.associations import (
    _SourceRecord as AssociationSourceRecord,
)
from agentsec.manifests.enums import (
    ManifestAuthenticationKind,
    ManifestControlKind,
    ManifestControlState,
    ManifestEnvironmentKind,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestPrincipalKind,
    ManifestResolutionStatus,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestToolKind,
    ManifestToolSideEffect,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestControl,
    ManifestControlProfile,
    ManifestPermission,
    ManifestPermissionProfile,
    ManifestRuntimeIdentity,
    ManifestRuntimeIdentityProfile,
    ManifestSourceReference,
    ManifestTool,
)
from agentsec.parsers import (
    McpApprovalMode,
    McpServerDeclaration,
    McpToolPolicy,
    McpTransport,
    ParsedRulesDocument,
    PrefixRuleDecision,
    SourceBackedValue,
    format_structured_path,
)

_ID_DIGEST_LENGTH = 12


class CapabilityExtractionError(RuntimeError):
    """Safe failure for an invalid or ambiguous capability extraction input."""


@dataclass(frozen=True, slots=True)
class _PermissionShape:
    """Safe normalized action/resource pair for one static side effect."""

    action: ManifestPermissionAction
    resource: ManifestResourceKind


class CapabilityExtractor:
    """Populate P2-09 permissions, controls, and runtime identity declarations."""

    def extract(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest:
        """Associate declarations, then extract conservative capability facts."""

        self._validate_inputs(manifest, inspection)
        associated = AssociationExtractor().extract(manifest, inspection)
        return self.extract_associated(associated, inspection)

    def extract_associated(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest:
        """Extract capabilities from an already-associated Manifest."""

        self._validate_inputs(manifest, inspection)
        self._validate_associated(manifest)
        associated = manifest
        paired_records = AssociationExtractor._pair_sources(associated, inspection)
        permission_items: list[ManifestPermission] = []
        control_items: list[ManifestControl] = []
        identity_items: list[ManifestRuntimeIdentity] = []
        permission_uncertain = False
        control_uncertain = False
        identity_uncertain = False

        mcp_records = tuple(
            item
            for item in paired_records
            if FrameworkAssetRole.MCP_CONFIG in item.record.asset.roles
        )
        rules_records = tuple(
            item
            for item in paired_records
            if FrameworkAssetRole.PREFIX_RULES in item.record.asset.roles
        )
        network_scopes = self._network_scopes(
            associated.tools.tools,
            mcp_records,
        )

        for tool in associated.tools.tools:
            for side_effect in tool.side_effects:
                shape = self._permission_shape(tool, side_effect)
                permission_items.append(
                    ManifestPermission(
                        permission_id=self._permission_id(
                            shape.action,
                            tool.tool_id,
                        ),
                        action=shape.action,
                        effect=ManifestPermissionEffect.UNKNOWN,
                        resource=shape.resource,
                        scope=self._permission_scope(
                            tool,
                            shape.action,
                            network_scopes,
                        ),
                        target=tool.tool_id,
                        sources=tool.sources,
                    )
                )
                permission_uncertain |= side_effect in {
                    ManifestToolSideEffect.UNKNOWN,
                    ManifestToolSideEffect.DESTRUCTIVE,
                }

        for item in rules_records:
            document = item.record.document
            if not isinstance(document, ParsedRulesDocument):
                raise CapabilityExtractionError(
                    "prefix-rules asset is missing its parsed document."
                )
            for index, rule in enumerate(document.rules):
                pattern_reference = self._value_reference(
                    item.source_reference,
                    rule.pattern,
                )
                decision_reference = self._value_reference(
                    item.source_reference,
                    rule.decision,
                )
                sources = self._sorted_references(
                    (pattern_reference, decision_reference)
                )
                rule_target = self._rule_target(item, index, rule.pattern)
                permission_items.append(
                    ManifestPermission(
                        permission_id=f"permission:{rule_target}",
                        action=ManifestPermissionAction.EXECUTE,
                        effect=self._rule_effect(rule.decision.value),
                        resource=ManifestResourceKind.SHELL,
                        scope=self._source_scope(item.source_reference),
                        target=rule_target,
                        sources=sources,
                    )
                )
                control_items.append(
                    ManifestControl(
                        control_id=f"control:{rule_target}",
                        kind=ManifestControlKind.PREFIX_RULE,
                        state=self._rule_state(rule.decision.value),
                        target=rule_target,
                        sources=sources,
                    )
                )

        for item in mcp_records:
            configuration = item.record.mcp_configuration
            if configuration is None:
                raise CapabilityExtractionError(
                    "MCP source is missing its parsed declaration."
                )
            for server in configuration.servers:
                server_reference = AssociationExtractor._server_reference(
                    item,
                    server,
                )
                server_tool = self._server_tool(
                    associated.tools.tools,
                    server_reference,
                )
                if server_tool is None:
                    raise CapabilityExtractionError(
                        "MCP server association is missing from tool inventory."
                    )
                server_id = server_tool.tool_id
                server_sources = self._server_sources(item, server)
                identity, identity_is_uncertain = self._runtime_identity(
                    server_id,
                    server,
                    server_sources,
                )
                identity_items.append(identity)
                identity_uncertain |= identity_is_uncertain

                server_controls, server_control_is_uncertain = self._server_controls(
                    associated.tools.tools,
                    item,
                    server,
                    server_id,
                )
                control_items.extend(server_controls)
                control_uncertain |= server_control_is_uncertain

                if self._has_environment_reference(server):
                    secret_sources = self._environment_sources(item, server)
                    permission_items.append(
                        ManifestPermission(
                            permission_id=self._permission_id(
                                ManifestPermissionAction.SECRET_ACCESS,
                                server_id,
                            ),
                            action=ManifestPermissionAction.SECRET_ACCESS,
                            effect=ManifestPermissionEffect.UNKNOWN,
                            resource=ManifestResourceKind.ENVIRONMENT,
                            scope=self._source_scope(server_sources[0]),
                            target=server_id,
                            sources=secret_sources,
                        )
                    )
                    permission_uncertain = True

        permission_items = self._unique_permissions(permission_items)
        control_items = self._unique_controls(control_items)
        identity_items = self._unique_identities(identity_items)

        payload = associated.model_dump(mode="python")
        if associated.permissions.declaration_sources:
            payload["permissions"] = ManifestPermissionProfile(
                resolution=self._profile_resolution(
                    associated.coverage.complete,
                    bool(permission_items),
                    permission_uncertain,
                ),
                declaration_sources=associated.permissions.declaration_sources,
                permissions=tuple(permission_items),
            ).model_dump(mode="python")
        if associated.controls.declaration_sources:
            payload["controls"] = ManifestControlProfile(
                resolution=self._profile_resolution(
                    associated.coverage.complete,
                    bool(control_items),
                    control_uncertain,
                ),
                declaration_sources=associated.controls.declaration_sources,
                controls=tuple(control_items),
            ).model_dump(mode="python")
        if associated.runtime_identities.declaration_sources:
            payload["runtime_identities"] = ManifestRuntimeIdentityProfile(
                resolution=self._profile_resolution(
                    associated.coverage.complete,
                    bool(identity_items),
                    identity_uncertain,
                ),
                declaration_sources=associated.runtime_identities.declaration_sources,
                identities=tuple(identity_items),
            ).model_dump(mode="python")
        return AgentManifest.model_validate(payload)

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
            raise CapabilityExtractionError(
                "Manifest tool associations must be extracted first."
            )

    @staticmethod
    def _permission_shape(
        tool: ManifestTool,
        side_effect: ManifestToolSideEffect,
    ) -> _PermissionShape:
        if side_effect is ManifestToolSideEffect.READ:
            return _PermissionShape(
                action=ManifestPermissionAction.READ,
                resource=ManifestResourceKind.TOOL,
            )
        if side_effect is ManifestToolSideEffect.WRITE:
            return _PermissionShape(
                action=ManifestPermissionAction.WRITE,
                resource=ManifestResourceKind.TOOL,
            )
        if side_effect is ManifestToolSideEffect.EXECUTE:
            return _PermissionShape(
                action=ManifestPermissionAction.EXECUTE,
                resource=(
                    ManifestResourceKind.SHELL
                    if tool.kind is ManifestToolKind.MCP_SERVER
                    else ManifestResourceKind.TOOL
                ),
            )
        if side_effect is ManifestToolSideEffect.NETWORK:
            return _PermissionShape(
                action=ManifestPermissionAction.NETWORK,
                resource=ManifestResourceKind.NETWORK,
            )
        if side_effect is ManifestToolSideEffect.SECRET_ACCESS:
            return _PermissionShape(
                action=ManifestPermissionAction.SECRET_ACCESS,
                resource=ManifestResourceKind.SECRET_STORE,
            )
        if side_effect is ManifestToolSideEffect.PRIVILEGED:
            return _PermissionShape(
                action=ManifestPermissionAction.ADMIN,
                resource=ManifestResourceKind.OTHER,
            )
        return _PermissionShape(
            action=ManifestPermissionAction.UNKNOWN,
            resource=ManifestResourceKind.TOOL,
        )

    @classmethod
    def _network_scopes(
        cls,
        tools: tuple[ManifestTool, ...],
        mcp_records: tuple[AssociationSourceRecord, ...],
    ) -> dict[str, ManifestResourceScope]:
        scopes: dict[str, ManifestResourceScope] = {}
        for item in mcp_records:
            configuration = item.record.mcp_configuration
            if configuration is None:
                continue
            for server in configuration.servers:
                if server.endpoint is None:
                    continue
                reference = AssociationExtractor._server_reference(item, server)
                tool = cls._server_tool(tools, reference)
                if tool is None:
                    continue
                scopes[tool.tool_id] = (
                    ManifestResourceScope.EXTERNAL
                    if not server.endpoint.value.is_local
                    else ManifestResourceScope.UNKNOWN
                )
        return scopes

    @classmethod
    def _permission_scope(
        cls,
        tool: ManifestTool,
        action: ManifestPermissionAction,
        network_scopes: dict[str, ManifestResourceScope],
    ) -> ManifestResourceScope:
        if action is ManifestPermissionAction.NETWORK:
            return network_scopes.get(tool.tool_id, ManifestResourceScope.UNKNOWN)
        return cls._source_scope(tool.sources[0])

    @staticmethod
    def _source_scope(
        reference: ManifestSourceReference,
    ) -> ManifestResourceScope:
        mapping = {
            "project": ManifestResourceScope.PROJECT,
            "user": ManifestResourceScope.USER,
        }
        return mapping.get(reference.locator.scope.value, ManifestResourceScope.UNKNOWN)

    @staticmethod
    def _permission_id(
        action: ManifestPermissionAction,
        target: str,
    ) -> str:
        return CapabilityExtractor._bounded_id(
            f"permission:{action.value}:{target}",
            ("permission", action.value, target),
        )

    @staticmethod
    def _rule_target(
        item: AssociationSourceRecord,
        index: int,
        pattern: SourceBackedValue[tuple[str, ...] | tuple[object, ...]],
    ) -> str:
        digest_input = "\x00".join(
            (
                item.source_reference.locator.scope.value,
                item.source_reference.locator.root_id,
                item.source_reference.locator.path,
                format_structured_path(pattern.path),
                str(index),
            )
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[
            :_ID_DIGEST_LENGTH
        ]
        return f"rule:{digest}"

    @staticmethod
    def _rule_effect(decision: str) -> ManifestPermissionEffect:
        return {
            PrefixRuleDecision.ALLOW.value: ManifestPermissionEffect.ALLOW,
            PrefixRuleDecision.PROMPT.value: ManifestPermissionEffect.PROMPT,
            PrefixRuleDecision.FORBIDDEN.value: ManifestPermissionEffect.DENY,
        }[decision]

    @staticmethod
    def _rule_state(decision: str) -> ManifestControlState:
        return {
            PrefixRuleDecision.ALLOW.value: ManifestControlState.ALLOW,
            PrefixRuleDecision.PROMPT.value: ManifestControlState.PROMPT,
            PrefixRuleDecision.FORBIDDEN.value: ManifestControlState.DENY,
        }[decision]

    @staticmethod
    def _value_reference[T](
        source_reference: ManifestSourceReference,
        value: SourceBackedValue[T],
    ) -> ManifestSourceReference:
        return ManifestSourceReference(
            locator=source_reference.locator,
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
    def _server_tool(
        tools: tuple[ManifestTool, ...],
        server_reference: ManifestSourceReference,
    ) -> ManifestTool | None:
        for tool in tools:
            if tool.kind is not ManifestToolKind.MCP_SERVER:
                continue
            if any(
                source.sort_key() == server_reference.sort_key()
                for source in tool.sources
            ):
                return tool
        return None

    @classmethod
    def _server_sources(
        cls,
        item: AssociationSourceRecord,
        server: McpServerDeclaration,
    ) -> tuple[ManifestSourceReference, ...]:
        server_reference = AssociationExtractor._server_reference(item, server)
        values: list[ManifestSourceReference] = [server_reference]
        for value in (
            server.command,
            server.endpoint,
            server.enabled_declaration,
            server.required_declaration,
            server.auth_mode,
            server.bearer_token_env_var,
        ):
            if value is not None:
                values.append(cls._value_reference(item.source_reference, value))
        return cls._sorted_references(values)

    @classmethod
    def _runtime_identity(
        cls,
        server_id: str,
        server: McpServerDeclaration,
        server_sources: tuple[ManifestSourceReference, ...],
    ) -> tuple[ManifestRuntimeIdentity, bool]:
        if server.auth_mode is not None:
            if server.auth_mode.value.value == "oauth":
                principal = ManifestPrincipalKind.OAUTH_SESSION
                authentication = ManifestAuthenticationKind.OAUTH
            else:
                principal = ManifestPrincipalKind.CHATGPT
                authentication = ManifestAuthenticationKind.CHATGPT
            uncertain = False
        elif server.bearer_token_env_var is not None or server.environment_http_headers:
            principal = ManifestPrincipalKind.API_CLIENT
            authentication = ManifestAuthenticationKind.ENVIRONMENT
            uncertain = False
        elif server.transport is McpTransport.PLUGIN_BUNDLED:
            principal = ManifestPrincipalKind.PLUGIN
            authentication = ManifestAuthenticationKind.UNKNOWN
            uncertain = True
        else:
            principal = ManifestPrincipalKind.UNKNOWN
            authentication = ManifestAuthenticationKind.UNKNOWN
            uncertain = True

        if server.transport is McpTransport.STDIO:
            environment = ManifestEnvironmentKind.LOCAL
        elif server.transport is McpTransport.STREAMABLE_HTTP:
            environment = (
                ManifestEnvironmentKind.LOCAL
                if server.endpoint and server.endpoint.value.is_local
                else ManifestEnvironmentKind.EXTERNAL
            )
        else:
            environment = ManifestEnvironmentKind.UNKNOWN
            uncertain = True

        return (
            ManifestRuntimeIdentity(
                identity_id=cls._bounded_id(
                    f"identity:{server_id}",
                    ("identity", server_id),
                ),
                principal_kind=principal,
                authentication=authentication,
                environment=environment,
                privileged=None,
                sources=server_sources,
            ),
            uncertain,
        )

    @classmethod
    def _server_controls(
        cls,
        tools: tuple[ManifestTool, ...],
        item: AssociationSourceRecord,
        server: McpServerDeclaration,
        server_id: str,
    ) -> tuple[tuple[ManifestControl, ...], bool]:
        controls: list[ManifestControl] = []
        uncertain = False
        server_reference = AssociationExtractor._server_reference(item, server)

        enabled_source = (
            cls._value_reference(item.source_reference, server.enabled_declaration)
            if server.enabled_declaration is not None
            else server_reference
        )
        enabled_state = (
            ManifestControlState.ENABLED
            if server.enabled_declaration is not None and server.enabled
            else ManifestControlState.DISABLED
            if server.enabled_declaration is not None
            else ManifestControlState.UNKNOWN
        )
        uncertain |= enabled_state is ManifestControlState.UNKNOWN
        controls.append(
            ManifestControl(
                control_id=cls._bounded_id(
                    f"control:mcp-enable:{server_id}",
                    ("mcp-enable", server_id),
                ),
                kind=ManifestControlKind.ENABLEMENT,
                state=enabled_state,
                target=server_id,
                sources=(enabled_source,),
            )
        )

        required_source = (
            cls._value_reference(item.source_reference, server.required_declaration)
            if server.required_declaration is not None
            else server_reference
        )
        required_state = (
            ManifestControlState.REQUIRED
            if server.required_declaration is not None and server.required
            else ManifestControlState.OPTIONAL
            if server.required_declaration is not None
            else ManifestControlState.UNKNOWN
        )
        uncertain |= required_state is ManifestControlState.UNKNOWN
        controls.append(
            ManifestControl(
                control_id=cls._bounded_id(
                    f"control:mcp-required:{server_id}",
                    ("mcp-required", server_id),
                ),
                kind=ManifestControlKind.REQUIRED,
                state=required_state,
                target=server_id,
                sources=(required_source,),
            )
        )

        if server.endpoint is not None:
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:network-policy:{server_id}",
                        ("network-policy", server_id),
                    ),
                    kind=ManifestControlKind.NETWORK_POLICY,
                    state=ManifestControlState.CONFIGURED,
                    target=server_id,
                    sources=(
                        cls._value_reference(item.source_reference, server.endpoint),
                    ),
                )
            )

        if server.default_approval_mode is not None:
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:approval:{server_id}",
                        ("approval", server_id),
                    ),
                    kind=ManifestControlKind.HUMAN_APPROVAL,
                    state=cls._approval_state(server.default_approval_mode.value),
                    target=server_id,
                    sources=(
                        cls._value_reference(
                            item.source_reference,
                            server.default_approval_mode,
                        ),
                    ),
                )
            )

        for label, value in (
            ("startup", server.startup_timeout_seconds),
            ("tool", server.tool_timeout_seconds),
        ):
            if value is None:
                continue
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:timeout:{server_id}:{label}",
                        ("timeout", server_id, label),
                    ),
                    kind=ManifestControlKind.TIMEOUT,
                    state=ManifestControlState.CONFIGURED,
                    target=server_id,
                    sources=(cls._value_reference(item.source_reference, value),),
                )
            )

        if cls._has_environment_reference(server):
            env_sources = cls._environment_sources(item, server)
            state = (
                ManifestControlState.CONFIGURED
                if server.bearer_token_env_var is not None
                or server.environment_http_headers
                else ManifestControlState.UNKNOWN
            )
            uncertain |= state is ManifestControlState.UNKNOWN
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:secret-handling:{server_id}",
                        ("secret-handling", server_id),
                    ),
                    kind=ManifestControlKind.SECRET_HANDLING,
                    state=state,
                    target=server_id,
                    sources=env_sources,
                )
            )

        for declaration, state in (
            *tuple(
                (value, ManifestControlState.ALLOW) for value in server.enabled_tools
            ),
            *tuple(
                (value, ManifestControlState.DENY) for value in server.disabled_tools
            ),
        ):
            tool = cls._child_tool(tools, server_id, item, declaration)
            if tool is None:
                raise CapabilityExtractionError(
                    "MCP tool filter is missing from tool inventory."
                )
            source = cls._value_reference(item.source_reference, declaration)
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:tool-filter:{tool.tool_id}:{state.value}",
                        (
                            "tool-filter",
                            tool.tool_id,
                            state.value,
                            source.field_path or "",
                        ),
                    ),
                    kind=ManifestControlKind.TOOL_FILTER,
                    state=state,
                    target=tool.tool_id,
                    sources=(source,),
                )
            )

        for policy in server.tool_policies:
            tool = cls._child_tool_by_policy(tools, server_id, item, policy)
            if tool is None:
                raise CapabilityExtractionError(
                    "MCP tool policy is missing from tool inventory."
                )
            source = cls._value_reference(item.source_reference, policy.approval_mode)
            controls.append(
                ManifestControl(
                    control_id=cls._bounded_id(
                        f"control:tool-approval:{tool.tool_id}",
                        ("tool-approval", tool.tool_id, source.field_path or ""),
                    ),
                    kind=ManifestControlKind.HUMAN_APPROVAL,
                    state=cls._approval_state(policy.approval_mode.value),
                    target=tool.tool_id,
                    sources=(source,),
                )
            )

        if server.unknown_fields:
            uncertain = True
        return tuple(controls), uncertain

    @staticmethod
    def _approval_state(mode: McpApprovalMode) -> ManifestControlState:
        if mode is McpApprovalMode.AUTO:
            return ManifestControlState.ALLOW
        return ManifestControlState.PROMPT

    @classmethod
    def _child_tool(
        cls,
        tools: tuple[ManifestTool, ...],
        server_id: str,
        item: AssociationSourceRecord,
        declaration: SourceBackedValue[str],
    ) -> ManifestTool | None:
        source = cls._value_reference(item.source_reference, declaration)
        return cls._child_tool_by_source(tools, server_id, source)

    @classmethod
    def _child_tool_by_policy(
        cls,
        tools: tuple[ManifestTool, ...],
        server_id: str,
        item: AssociationSourceRecord,
        policy: McpToolPolicy,
    ) -> ManifestTool | None:
        approval_mode = policy.approval_mode
        source = cls._value_reference(item.source_reference, approval_mode)
        return cls._child_tool_by_source(tools, server_id, source)

    @staticmethod
    def _child_tool_by_source(
        tools: tuple[ManifestTool, ...],
        server_id: str,
        source: ManifestSourceReference,
    ) -> ManifestTool | None:
        for tool in tools:
            if tool.kind is not ManifestToolKind.MCP_TOOL:
                continue
            if tool.parent_tool_id != server_id:
                continue
            if any(
                candidate.sort_key() == source.sort_key() for candidate in tool.sources
            ):
                return tool
        return None

    @classmethod
    def _has_environment_reference(cls, server: McpServerDeclaration) -> bool:
        return bool(
            server.static_environment_names
            or server.environment_references
            or server.bearer_token_env_var
            or server.environment_http_headers
            or server.static_http_header_names
        )

    @classmethod
    def _environment_sources(
        cls,
        item: AssociationSourceRecord,
        server: McpServerDeclaration,
    ) -> tuple[ManifestSourceReference, ...]:
        values: list[ManifestSourceReference] = []
        for value in server.static_environment_names:
            values.append(cls._value_reference(item.source_reference, value))
        for reference in server.environment_references:
            values.append(cls._value_reference(item.source_reference, reference.name))
        if server.bearer_token_env_var is not None:
            values.append(
                cls._value_reference(item.source_reference, server.bearer_token_env_var)
            )
        for header in server.environment_http_headers:
            values.append(
                cls._value_reference(item.source_reference, header.environment_variable)
            )
        for value in server.static_http_header_names:
            values.append(cls._value_reference(item.source_reference, value))
        if not values:
            values.append(AssociationExtractor._server_reference(item, server))
        return cls._sorted_references(values)

    @staticmethod
    def _profile_resolution(
        coverage_complete: bool,
        has_items: bool,
        uncertain: bool,
    ) -> ManifestResolutionStatus:
        if not coverage_complete or uncertain:
            return ManifestResolutionStatus.PARTIAL
        if has_items:
            return ManifestResolutionStatus.RESOLVED
        return ManifestResolutionStatus.PARTIAL

    @staticmethod
    def _unique_permissions(
        permissions: Iterable[ManifestPermission],
    ) -> list[ManifestPermission]:
        by_id = {permission.permission_id: permission for permission in permissions}
        return [by_id[key] for key in sorted(by_id)]

    @staticmethod
    def _unique_controls(
        controls: Iterable[ManifestControl],
    ) -> list[ManifestControl]:
        by_id = {control.control_id: control for control in controls}
        return [by_id[key] for key in sorted(by_id)]

    @staticmethod
    def _unique_identities(
        identities: Iterable[ManifestRuntimeIdentity],
    ) -> list[ManifestRuntimeIdentity]:
        by_id = {identity.identity_id: identity for identity in identities}
        return [by_id[key] for key in sorted(by_id)]

    @staticmethod
    def _bounded_id(base_id: str, key: tuple[str, ...]) -> str:
        if len(base_id) <= 128:
            return base_id
        digest = hashlib.sha256("\x00".join(key).encode("utf-8")).hexdigest()[
            :_ID_DIGEST_LENGTH
        ]
        suffix = f":{digest}"
        return f"{base_id[: 128 - len(suffix)]}{suffix}"

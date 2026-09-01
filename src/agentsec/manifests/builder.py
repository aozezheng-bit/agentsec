"""Deterministic construction of an Agent Manifest from Framework inspection."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

from agentsec.frameworks import (
    FrameworkAsset,
    FrameworkAssetFormat,
    FrameworkAssetRole,
    FrameworkAssetScope,
    FrameworkInspectionResult,
)
from agentsec.manifests.enums import (
    ManifestAssetFormat,
    ManifestAssetRole,
    ManifestConfigurationKind,
    ManifestCoverageIssueCode,
    ManifestInstructionKind,
    ManifestResolutionStatus,
    ManifestSourceScope,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestConfigurationCandidate,
    ManifestConfigurationProfile,
    ManifestControlProfile,
    ManifestCoverage,
    ManifestCoverageIssue,
    ManifestIdentity,
    ManifestInstructionCandidate,
    ManifestInstructionProfile,
    ManifestMetadata,
    ManifestPermissionProfile,
    ManifestRelationshipProfile,
    ManifestRuntimeIdentityProfile,
    ManifestSource,
    ManifestSourceLocator,
    ManifestSourceReference,
    ManifestToolProfile,
)
from agentsec.versioning import AGENT_MANIFEST_SCHEMA_VERSION, PACKAGE_VERSION

_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_SOURCE_SCOPE_MAP = {
    FrameworkAssetScope.PROJECT: ManifestSourceScope.PROJECT,
    FrameworkAssetScope.USER: ManifestSourceScope.USER,
    FrameworkAssetScope.PLUGIN: ManifestSourceScope.PLUGIN,
}
_SOURCE_FORMAT_MAP = {
    FrameworkAssetFormat.MARKDOWN: ManifestAssetFormat.MARKDOWN,
    FrameworkAssetFormat.RULES: ManifestAssetFormat.RULES,
    FrameworkAssetFormat.JSON: ManifestAssetFormat.JSON,
    FrameworkAssetFormat.YAML: ManifestAssetFormat.YAML,
    FrameworkAssetFormat.TOML: ManifestAssetFormat.TOML,
}
_SOURCE_ROLE_MAP = {
    FrameworkAssetRole.AGENT_INSTRUCTIONS: ManifestAssetRole.AGENT_INSTRUCTIONS,
    FrameworkAssetRole.INSTRUCTION_OVERRIDE: (ManifestAssetRole.INSTRUCTION_OVERRIDE),
    FrameworkAssetRole.SKILL: ManifestAssetRole.SKILL,
    FrameworkAssetRole.PREFIX_RULES: ManifestAssetRole.PREFIX_RULES,
    FrameworkAssetRole.FRAMEWORK_CONFIG: ManifestAssetRole.FRAMEWORK_CONFIG,
    FrameworkAssetRole.MCP_CONFIG: ManifestAssetRole.MCP_CONFIG,
}
_COVERAGE_CODE_MAP = {
    code.value: ManifestCoverageIssueCode(code.value)
    for code in ManifestCoverageIssueCode
}


class AgentManifestBuildError(RuntimeError):
    """Safe failure for invalid trusted Manifest build context."""


class AgentManifestBuilder:
    """Normalize Framework inspection into a source-only P2-05 Manifest."""

    def build(
        self,
        inspection: FrameworkInspectionResult,
        *,
        subject_root_id: str = "project",
        agent_id: str | None = None,
    ) -> AgentManifest:
        """Build a deterministic Manifest without copying parsed source values."""

        if not isinstance(inspection, FrameworkInspectionResult):
            raise TypeError("inspection must be FrameworkInspectionResult")
        self._validate_subject_root(inspection, subject_root_id)
        if agent_id is not None and _STABLE_ID_PATTERN.fullmatch(agent_id) is None:
            raise AgentManifestBuildError(
                "Manifest agent_id must use stable identifier form."
            )

        sources = tuple(
            sorted(
                (self._source(record.asset) for record in inspection.assets),
                key=lambda source: source.locator.sort_key(),
            )
        )
        source_references = tuple(
            ManifestSourceReference(locator=source.locator) for source in sources
        )
        source_by_locator = {
            reference.locator.sort_key(): (source, reference)
            for source, reference in zip(sources, source_references, strict=True)
        }

        identity_sources = self._references_with_roles(
            source_by_locator,
            {ManifestAssetRole.FRAMEWORK_CONFIG},
        )
        instruction_candidates = self._instruction_candidates(
            sources,
            source_by_locator,
        )
        configuration_candidates = self._configuration_candidates(
            sources,
            source_by_locator,
        )
        tool_sources = self._references_with_roles(
            source_by_locator,
            {ManifestAssetRole.SKILL, ManifestAssetRole.MCP_CONFIG},
        )
        policy_sources = self._references_with_roles(
            source_by_locator,
            {
                ManifestAssetRole.PREFIX_RULES,
                ManifestAssetRole.FRAMEWORK_CONFIG,
                ManifestAssetRole.MCP_CONFIG,
            },
        )
        runtime_identity_sources = self._references_with_roles(
            source_by_locator,
            {
                ManifestAssetRole.FRAMEWORK_CONFIG,
                ManifestAssetRole.MCP_CONFIG,
            },
        )
        relationship_sources = self._references_with_roles(
            source_by_locator,
            {
                ManifestAssetRole.AGENT_INSTRUCTIONS,
                ManifestAssetRole.INSTRUCTION_OVERRIDE,
                ManifestAssetRole.SKILL,
                ManifestAssetRole.MCP_CONFIG,
            },
        )

        framework_id = inspection.metadata.framework_id
        resolved_agent_id = agent_id or self._default_agent_id(
            framework_id,
            subject_root_id,
        )
        coverage_issues = tuple(
            sorted(
                (
                    ManifestCoverageIssue(
                        code=_COVERAGE_CODE_MAP[issue.code.value],
                        root_id=issue.root_id,
                        path=issue.path,
                    )
                    for issue in inspection.issues
                ),
                key=lambda issue: issue.sort_key(),
            )
        )

        return AgentManifest(
            schema_version=AGENT_MANIFEST_SCHEMA_VERSION,
            metadata=ManifestMetadata(
                scanner_version=PACKAGE_VERSION,
                framework_id=framework_id,
                framework_display_name=inspection.metadata.display_name,
                adapter_version=inspection.metadata.adapter_version,
                deterministic=True,
            ),
            identity=ManifestIdentity(
                agent_id=resolved_agent_id,
                subject_scope=ManifestSourceScope.PROJECT,
                subject_root_id=subject_root_id,
                declared_name=None,
                resolution=ManifestResolutionStatus.PARTIAL,
                sources=identity_sources,
            ),
            sources=sources,
            instructions=ManifestInstructionProfile(
                resolution=(
                    ManifestResolutionStatus.UNRESOLVED
                    if instruction_candidates
                    else ManifestResolutionStatus.UNKNOWN
                ),
                candidates=instruction_candidates,
                effective_sources=(),
            ),
            configuration=ManifestConfigurationProfile(
                resolution=(
                    ManifestResolutionStatus.UNRESOLVED
                    if configuration_candidates
                    else ManifestResolutionStatus.UNKNOWN
                ),
                candidates=configuration_candidates,
                effective_sources=(),
                effective_order=(),
                resolution_trace=(),
            ),
            tools=ManifestToolProfile(
                resolution=self._declaration_resolution(tool_sources),
                declaration_sources=tool_sources,
                tools=(),
            ),
            permissions=ManifestPermissionProfile(
                resolution=self._declaration_resolution(policy_sources),
                declaration_sources=policy_sources,
                permissions=(),
            ),
            controls=ManifestControlProfile(
                resolution=self._declaration_resolution(policy_sources),
                declaration_sources=policy_sources,
                controls=(),
            ),
            runtime_identities=ManifestRuntimeIdentityProfile(
                resolution=self._declaration_resolution(runtime_identity_sources),
                declaration_sources=runtime_identity_sources,
                identities=(),
            ),
            relationships=ManifestRelationshipProfile(
                resolution=self._declaration_resolution(relationship_sources),
                declaration_sources=relationship_sources,
                relations=(),
            ),
            unknowns=(),
            coverage=ManifestCoverage(
                discovered_assets=inspection.discovered_assets,
                inspected_assets=inspection.inspected_assets,
                skipped_assets=inspection.skipped_assets,
                complete=inspection.complete,
                issues=coverage_issues,
            ),
        )

    @staticmethod
    def _source(asset: FrameworkAsset) -> ManifestSource:
        return ManifestSource(
            locator=ManifestSourceLocator(
                scope=_SOURCE_SCOPE_MAP[asset.locator.scope],
                root_id=asset.locator.root_id,
                path=asset.locator.path,
            ),
            format=_SOURCE_FORMAT_MAP[asset.format],
            roles=tuple(
                sorted(
                    (_SOURCE_ROLE_MAP[role] for role in asset.roles),
                    key=lambda role: role.value,
                )
            ),
            content_sha256=asset.content_sha256,
            size_bytes=asset.size_bytes,
            line_count=asset.line_count,
            precedence_rank=asset.precedence_rank,
        )

    @staticmethod
    def _references_with_roles(
        source_by_locator: dict[
            tuple[str, str, str],
            tuple[ManifestSource, ManifestSourceReference],
        ],
        roles: set[ManifestAssetRole],
    ) -> tuple[ManifestSourceReference, ...]:
        references = [
            reference
            for source, reference in source_by_locator.values()
            if set(source.roles) & roles
        ]
        return tuple(sorted(references, key=lambda reference: reference.sort_key()))

    @staticmethod
    def _instruction_candidates(
        sources: tuple[ManifestSource, ...],
        source_by_locator: dict[
            tuple[str, str, str],
            tuple[ManifestSource, ManifestSourceReference],
        ],
    ) -> tuple[ManifestInstructionCandidate, ...]:
        candidates: list[ManifestInstructionCandidate] = []
        for source in sources:
            role_set = set(source.roles)
            kind: ManifestInstructionKind | None
            if ManifestAssetRole.AGENT_INSTRUCTIONS in role_set:
                kind = ManifestInstructionKind.BASE
            elif ManifestAssetRole.INSTRUCTION_OVERRIDE in role_set:
                kind = ManifestInstructionKind.OVERRIDE
            else:
                kind = None
            if kind is None:
                continue
            reference = source_by_locator[source.locator.sort_key()][1]
            candidates.append(
                ManifestInstructionCandidate(
                    kind=kind,
                    source=reference,
                    precedence_rank=source.precedence_rank,
                )
            )
        return tuple(sorted(candidates, key=lambda candidate: candidate.sort_key()))

    @staticmethod
    def _declaration_resolution(
        references: tuple[ManifestSourceReference, ...],
    ) -> ManifestResolutionStatus:
        return (
            ManifestResolutionStatus.UNRESOLVED
            if references
            else ManifestResolutionStatus.UNKNOWN
        )

    @staticmethod
    def _configuration_candidates(
        sources: tuple[ManifestSource, ...],
        source_by_locator: dict[
            tuple[str, str, str],
            tuple[ManifestSource, ManifestSourceReference],
        ],
    ) -> tuple[ManifestConfigurationCandidate, ...]:
        role_to_kind = {
            ManifestAssetRole.FRAMEWORK_CONFIG: (
                ManifestConfigurationKind.FRAMEWORK_CONFIG
            ),
            ManifestAssetRole.PREFIX_RULES: ManifestConfigurationKind.PREFIX_RULES,
            ManifestAssetRole.MCP_CONFIG: ManifestConfigurationKind.MCP_CONFIG,
        }
        candidates: list[ManifestConfigurationCandidate] = []
        for source in sources:
            kinds = tuple(
                sorted(
                    {
                        kind
                        for role, kind in role_to_kind.items()
                        if role in source.roles
                    },
                    key=lambda kind: kind.value,
                )
            )
            if not kinds:
                continue
            reference = source_by_locator[source.locator.sort_key()][1]
            parent = PurePosixPath(source.locator.path).parent.as_posix()
            if parent == ".":
                parent = ""
            chain_key = ":".join(
                (
                    source.locator.scope.value,
                    source.locator.root_id,
                    parent or ".",
                )
            )
            candidates.append(
                ManifestConfigurationCandidate(
                    source=reference,
                    kinds=kinds,
                    precedence_rank=source.precedence_rank,
                    chain_key=chain_key,
                )
            )
        return tuple(sorted(candidates, key=lambda candidate: candidate.sort_key()))

    @staticmethod
    def _validate_subject_root(
        inspection: FrameworkInspectionResult,
        subject_root_id: str,
    ) -> None:
        if not subject_root_id or subject_root_id != subject_root_id.strip():
            raise AgentManifestBuildError(
                "Manifest subject_root_id must be a non-empty exact value."
            )
        project_root_ids = {
            record.asset.locator.root_id
            for record in inspection.assets
            if record.asset.locator.scope is FrameworkAssetScope.PROJECT
        }
        if project_root_ids and subject_root_id not in project_root_ids:
            raise AgentManifestBuildError(
                "Manifest subject_root_id is not present in project sources."
            )

    @staticmethod
    def _default_agent_id(framework_id: str, subject_root_id: str) -> str:
        candidate = f"{framework_id}:{subject_root_id}"
        if _STABLE_ID_PATTERN.fullmatch(candidate) is not None:
            return candidate
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:16]
        return f"{framework_id}:{digest}"

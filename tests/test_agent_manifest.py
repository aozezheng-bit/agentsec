"""P2-05 versioned Agent Manifest Schema and builder tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec.frameworks import (
    CodexAdapter,
    FrameworkInspectionRequest,
)
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    AgentManifestBuildError,
    AgentManifestValidationCode,
    AgentManifestValidationError,
    ConfigurationResolver,
    InstructionResolutionError,
    InstructionResolver,
    ManifestAuthenticationKind,
    ManifestConfigurationKind,
    ManifestConfigurationResolutionReason,
    ManifestControl,
    ManifestControlKind,
    ManifestControlProfile,
    ManifestControlState,
    ManifestEnvironmentKind,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestPermissionProfile,
    ManifestPrincipalKind,
    ManifestRelation,
    ManifestRelationKind,
    ManifestRelationshipProfile,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestRuntimeIdentity,
    ManifestRuntimeIdentityProfile,
    ManifestSourceReference,
    ManifestTool,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolProfile,
    ManifestToolSideEffect,
    ManifestUnknown,
    ManifestUnknownDimension,
    ManifestUnknownReason,
    decode_agent_manifest_json,
    encode_agent_manifest_json,
    export_agent_manifest_json_schema,
    validate_agent_manifest_payload,
)
from agentsec.versioning import AGENT_MANIFEST_SCHEMA_VERSION, current_versions

SECRET_MARKER = "manifest-secret-must-not-be-copied"


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _build_manifest(tmp_path: Path) -> AgentManifest:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", f"# Agent\n\n{SECRET_MARKER}\n")
    _write(project / "AGENTS.override.md", "# Override\n")
    _write(
        project / ".codex" / "config.toml",
        f"""
private_note = "{SECRET_MARKER}"

[mcp_servers.docs]
command = "server-containing-{SECRET_MARKER}"
env = {{ TOKEN = "{SECRET_MARKER}" }}
""".lstrip(),
    )
    _write(
        project / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git", "status"], decision="prompt")\n',
    )
    _write(
        project / ".agents" / "skills" / "review" / "SKILL.md",
        f"# Review\n\nDo not execute {SECRET_MARKER}.\n",
    )
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    return AgentManifestBuilder().build(inspection)


def _source_ref(manifest: AgentManifest, path: str) -> ManifestSourceReference:
    source = next(source for source in manifest.sources if source.locator.path == path)
    return ManifestSourceReference(locator=source.locator)


def test_current_version_vector_includes_independent_manifest_schema() -> None:
    versions = current_versions()

    assert versions.agent_manifest_schema == AGENT_MANIFEST_SCHEMA_VERSION
    assert AGENT_MANIFEST_SCHEMA_VERSION == "0.3.0"


def test_builder_covers_identity_sources_and_all_manifest_dimensions(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)

    assert manifest.schema_version == AGENT_MANIFEST_SCHEMA_VERSION
    assert manifest.metadata.framework_id == "codex"
    assert manifest.metadata.framework_display_name == "Codex"
    assert manifest.metadata.adapter_version == "0.1.0"
    assert manifest.metadata.deterministic is True
    assert manifest.identity.agent_id == "codex:project"
    assert manifest.identity.subject_root_id == "project"
    assert manifest.identity.resolution is ManifestResolutionStatus.PARTIAL
    assert manifest.coverage.complete is True
    assert manifest.coverage.inspected_assets == len(manifest.sources) == 5

    assert manifest.instructions.resolution is ManifestResolutionStatus.UNRESOLVED
    assert len(manifest.instructions.candidates) == 2
    assert manifest.instructions.effective_sources == ()
    assert manifest.instructions.effective_order == ()
    assert manifest.instructions.overridden_sources == ()
    assert manifest.instructions.resolution_trace == ()
    assert manifest.configuration.resolution is ManifestResolutionStatus.UNRESOLVED
    assert [
        candidate.source.locator.path for candidate in manifest.configuration.candidates
    ] == [
        ".codex/config.toml",
        ".codex/rules/default.rules",
    ]
    assert manifest.configuration.candidates[0].kinds == (
        ManifestConfigurationKind.FRAMEWORK_CONFIG,
        ManifestConfigurationKind.MCP_CONFIG,
    )
    assert manifest.tools.resolution is ManifestResolutionStatus.UNRESOLVED
    assert manifest.permissions.resolution is ManifestResolutionStatus.UNRESOLVED
    assert manifest.controls.resolution is ManifestResolutionStatus.UNRESOLVED
    assert manifest.runtime_identities.resolution is (
        ManifestResolutionStatus.UNRESOLVED
    )
    assert manifest.relationships.resolution is ManifestResolutionStatus.UNRESOLVED
    assert manifest.unknowns == ()


def test_builder_retains_portable_source_metadata_without_parsed_values(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    encoded = encode_agent_manifest_json(manifest)

    assert SECRET_MARKER not in encoded
    assert str(tmp_path) not in encoded
    assert '"path": "AGENTS.md"' in encoded
    assert '"path": ".codex/config.toml"' in encoded
    assert '"content_sha256"' in encoded
    assert '"precedence_rank"' in encoded
    assert '"command"' not in encoded
    assert '"private_note"' not in encoded


def test_instruction_candidates_preserve_kind_rank_and_source(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    candidates = manifest.instructions.candidates

    assert [candidate.kind.value for candidate in candidates] == [
        "base",
        "override",
    ]
    assert [candidate.precedence_rank for candidate in candidates] == [100, 105]
    assert [candidate.source.locator.path for candidate in candidates] == [
        "AGENTS.md",
        "AGENTS.override.md",
    ]


def test_declaration_profiles_reference_only_compatible_source_roles(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)

    assert [ref.locator.path for ref in manifest.tools.declaration_sources] == [
        ".agents/skills/review/SKILL.md",
        ".codex/config.toml",
    ]
    assert [ref.locator.path for ref in manifest.permissions.declaration_sources] == [
        ".codex/config.toml",
        ".codex/rules/default.rules",
    ]
    assert manifest.permissions.declaration_sources == (
        manifest.controls.declaration_sources
    )
    assert [
        ref.locator.path for ref in manifest.runtime_identities.declaration_sources
    ] == [".codex/config.toml"]


def test_configuration_resolver_orders_user_project_root_and_nested_sources(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    user_home = tmp_path / "home"
    project.mkdir()
    user_home.mkdir()
    _write(user_home / ".codex" / "config.toml", 'model = "user"\n')
    _write(
        user_home / ".codex" / "rules" / "user.rules",
        'prefix_rule(pattern=["git"], decision="prompt")\n',
    )
    _write(project / ".codex" / "config.toml", 'model = "root"\n')
    _write(
        project / ".codex" / "rules" / "root.rules",
        'prefix_rule(pattern=["git", "status"], decision="allow")\n',
    )
    _write(project / "service" / ".codex" / "config.toml", 'model = "nested"\n')
    _write(
        project / "service" / ".codex" / "rules" / "nested.rules",
        'prefix_rule(pattern=["git", "log"], decision="prompt")\n',
    )
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(
            FrameworkInspectionRequest(
                project_root=project,
                working_directory=project / "service",
                user_home=user_home,
            )
        )
    )

    resolved = ConfigurationResolver().resolve(manifest)

    assert resolved.configuration.resolution is ManifestResolutionStatus.RESOLVED
    assert [
        (reference.locator.root_id, reference.locator.path)
        for reference in resolved.configuration.effective_order
    ] == [
        ("codex_home", "config.toml"),
        ("codex_home", "rules/user.rules"),
        ("project", ".codex/config.toml"),
        ("project", ".codex/rules/root.rules"),
        ("project", "service/.codex/config.toml"),
        ("project", "service/.codex/rules/nested.rules"),
    ]
    assert {
        (reference.locator.root_id, reference.locator.path)
        for reference in resolved.configuration.effective_sources
    } == {
        ("codex_home", "config.toml"),
        ("codex_home", "rules/user.rules"),
        ("project", ".codex/config.toml"),
        ("project", ".codex/rules/root.rules"),
        ("project", "service/.codex/config.toml"),
        ("project", "service/.codex/rules/nested.rules"),
    }
    assert [step.reason for step in resolved.configuration.resolution_trace] == [
        ManifestConfigurationResolutionReason.USER_SCOPE,
        ManifestConfigurationResolutionReason.USER_SCOPE,
        ManifestConfigurationResolutionReason.PROJECT_ROOT,
        ManifestConfigurationResolutionReason.PROJECT_ROOT,
        ManifestConfigurationResolutionReason.NESTED_PROJECT,
        ManifestConfigurationResolutionReason.NESTED_PROJECT,
    ]


def test_configuration_resolver_marks_incomplete_coverage_partial(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / ".codex" / "config.toml", 'model = "root"\n')
    (project / ".codex" / "rules").mkdir(parents=True)
    (project / ".codex" / "rules" / "broken.rules").write_bytes(b"\xff\xfe")
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))
    )

    resolved = ConfigurationResolver().resolve(manifest)

    assert resolved.configuration.resolution is ManifestResolutionStatus.PARTIAL
    assert len(resolved.configuration.effective_order) == 1
    assert all(
        step.reason is ManifestConfigurationResolutionReason.INCOMPLETE_COVERAGE
        for step in resolved.configuration.resolution_trace
    )


def test_empty_configuration_scope_remains_unknown(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))
    )

    resolved = ConfigurationResolver().resolve(manifest)

    assert resolved.configuration.resolution is ManifestResolutionStatus.UNKNOWN
    assert resolved.configuration.candidates == ()


def test_configuration_resolution_is_deterministic_and_value_free(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    resolver = ConfigurationResolver()

    first = resolver.resolve(manifest)
    second = resolver.resolve(manifest)
    encoded = encode_agent_manifest_json(first)

    assert first == second
    assert encoded == encode_agent_manifest_json(second)
    assert SECRET_MARKER not in encoded
    assert '"command"' not in encoded


def test_builder_maps_incomplete_framework_coverage_without_inventing_findings(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )

    manifest = AgentManifestBuilder().build(inspection)

    assert manifest.coverage.complete is False
    assert manifest.coverage.discovered_assets == 2
    assert manifest.coverage.inspected_assets == 1
    assert manifest.coverage.skipped_assets == 1
    assert manifest.coverage.issues[0].code.value == "unsupported_encoding"
    assert manifest.coverage.issues[0].path == "AGENTS.override.md"
    assert manifest.unknowns == ()


def test_builder_is_deterministic_and_supports_trusted_agent_id(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    builder = AgentManifestBuilder()

    first = builder.build(inspection, agent_id="release-agent")
    second = builder.build(inspection, agent_id="release-agent")

    assert first == second
    assert first.identity.agent_id == "release-agent"
    assert encode_agent_manifest_json(first) == encode_agent_manifest_json(second)


def test_builder_rejects_invalid_subject_or_agent_identity(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    builder = AgentManifestBuilder()

    with pytest.raises(AgentManifestBuildError):
        builder.build(inspection, subject_root_id="other")
    with pytest.raises(AgentManifestBuildError):
        builder.build(inspection, agent_id="../unsafe")


def test_empty_inspection_produces_explicit_unknown_profiles(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )

    manifest = AgentManifestBuilder().build(inspection)

    assert manifest.sources == ()
    assert manifest.instructions.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.tools.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.permissions.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.controls.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.runtime_identities.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.relationships.resolution is ManifestResolutionStatus.UNKNOWN
    assert manifest.coverage.complete is True


def test_schema_can_represent_future_resolved_capability_facts(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    skill_ref = _source_ref(manifest, ".agents/skills/review/SKILL.md")
    config_ref = _source_ref(manifest, ".codex/config.toml")
    rules_ref = _source_ref(manifest, ".codex/rules/default.rules")

    payload = manifest.model_dump(mode="json")
    payload["tools"] = ManifestToolProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.tools.declaration_sources,
        tools=(
            ManifestTool(
                tool_id="skill:review",
                name="review",
                kind=ManifestToolKind.SKILL,
                availability=ManifestToolAvailability.ENABLED,
                side_effects=(
                    ManifestToolSideEffect.READ,
                    ManifestToolSideEffect.WRITE,
                ),
                sources=(skill_ref,),
            ),
        ),
    ).model_dump(mode="json")
    payload["permissions"] = ManifestPermissionProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.permissions.declaration_sources,
        permissions=(
            ManifestPermission(
                permission_id="permission:git-status",
                action=ManifestPermissionAction.READ,
                effect=ManifestPermissionEffect.PROMPT,
                resource=ManifestResourceKind.REPOSITORY,
                scope=ManifestResourceScope.PROJECT,
                target="git-status",
                sources=(rules_ref,),
            ),
        ),
    ).model_dump(mode="json")
    payload["controls"] = ManifestControlProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.controls.declaration_sources,
        controls=(
            ManifestControl(
                control_id="control:approval",
                kind=ManifestControlKind.HUMAN_APPROVAL,
                state=ManifestControlState.PROMPT,
                sources=(rules_ref,),
            ),
        ),
    ).model_dump(mode="json")
    payload["runtime_identities"] = ManifestRuntimeIdentityProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.runtime_identities.declaration_sources,
        identities=(
            ManifestRuntimeIdentity(
                identity_id="identity:mcp-docs",
                principal_kind=ManifestPrincipalKind.API_CLIENT,
                authentication=ManifestAuthenticationKind.ENVIRONMENT,
                environment=ManifestEnvironmentKind.UNKNOWN,
                privileged=None,
                sources=(config_ref,),
            ),
        ),
    ).model_dump(mode="json")
    payload["relationships"] = ManifestRelationshipProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.relationships.declaration_sources,
        relations=(
            ManifestRelation(
                relation_id="relation:review-skill",
                source_agent_id=manifest.identity.agent_id,
                kind=ManifestRelationKind.USES_SKILL,
                target_id="skill:review",
                state=ManifestRelationState.ACTIVE,
                sources=(skill_ref,),
            ),
        ),
    ).model_dump(mode="json")
    payload["unknowns"] = [
        ManifestUnknown(
            unknown_id="unknown:runtime-environment",
            dimension=ManifestUnknownDimension.RUNTIME_IDENTITIES,
            reason=ManifestUnknownReason.RUNTIME_VERIFICATION_REQUIRED,
            field="environment",
            sources=(config_ref,),
        ).model_dump(mode="json")
    ]

    resolved = AgentManifest.model_validate(payload)

    assert resolved.tools.tools[0].side_effects == (
        ManifestToolSideEffect.READ,
        ManifestToolSideEffect.WRITE,
    )
    assert resolved.permissions.permissions[0].effect is (
        ManifestPermissionEffect.PROMPT
    )
    assert resolved.controls.controls[0].kind is (ManifestControlKind.HUMAN_APPROVAL)
    assert resolved.runtime_identities.identities[0].authentication is (
        ManifestAuthenticationKind.ENVIRONMENT
    )
    assert resolved.relationships.relations[0].target_id == "skill:review"
    assert resolved.unknowns[0].reason is (
        ManifestUnknownReason.RUNTIME_VERIFICATION_REQUIRED
    )


def test_source_reference_must_resolve_and_fit_source_line_range(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["identity"]["sources"][0]["locator"]["path"] = "missing.toml"

    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    payload["identity"]["sources"][0]["start_line"] = 1
    payload["identity"]["sources"][0]["end_line"] = 10_000
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_instruction_candidate_role_and_rank_must_match_source(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["instructions"]["candidates"][0]["precedence_rank"] = 999

    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_instruction_profile_rejects_mismatched_effective_order(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["instructions"]["effective_sources"] = [
        payload["instructions"]["candidates"][0]["source"]
    ]
    payload["instructions"]["effective_order"] = []
    payload["instructions"]["resolution"] = "resolved"

    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    payload["instructions"]["candidates"][0]["kind"] = "override"
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_manifest_rejects_unsorted_duplicate_sources_and_roles(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["sources"] = list(reversed(payload["sources"]))
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    payload["sources"].append(payload["sources"][0])
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    config = next(
        source
        for source in payload["sources"]
        if source["locator"]["path"] == ".codex/config.toml"
    )
    config["roles"] = list(reversed(config["roles"]))
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_profile_resolution_state_cannot_hide_retained_declarations(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["tools"]["resolution"] = "unknown"

    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_relationship_source_agent_must_match_manifest_identity(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    skill_ref = _source_ref(manifest, ".agents/skills/review/SKILL.md")
    payload = manifest.model_dump(mode="json")
    payload["relationships"] = ManifestRelationshipProfile(
        resolution=ManifestResolutionStatus.RESOLVED,
        declaration_sources=manifest.relationships.declaration_sources,
        relations=(
            ManifestRelation(
                relation_id="relation:other",
                source_agent_id="other-agent",
                kind=ManifestRelationKind.USES_SKILL,
                target_id="skill:review",
                state=ManifestRelationState.ACTIVE,
                sources=(skill_ref,),
            ),
        ),
    ).model_dump(mode="json")

    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)


def test_manifest_json_round_trip_is_deterministic(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)

    first = encode_agent_manifest_json(manifest)
    decoded = decode_agent_manifest_json(first)
    second = encode_agent_manifest_json(decoded)

    assert decoded == manifest
    assert first == second
    assert json.loads(first)["schema_version"] == AGENT_MANIFEST_SCHEMA_VERSION


def test_compatibility_is_checked_before_untrusted_manifest_payload() -> None:
    payload = {
        "schema_version": "0.4.0",
        "metadata": SECRET_MARKER,
        "sources": SECRET_MARKER,
    }

    with pytest.raises(AgentManifestValidationError) as captured:
        validate_agent_manifest_payload(payload)

    assert captured.value.code is (
        AgentManifestValidationCode.UNSUPPORTED_SCHEMA_VERSION
    )
    assert SECRET_MARKER not in str(captured.value)


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ([], AgentManifestValidationCode.INVALID_ROOT),
        ({}, AgentManifestValidationCode.MISSING_SCHEMA_VERSION),
        (
            {"schema_version": 1},
            AgentManifestValidationCode.INVALID_SCHEMA_VERSION,
        ),
        (
            {"schema_version": "v0.1"},
            AgentManifestValidationCode.INVALID_SCHEMA_VERSION,
        ),
    ],
)
def test_manifest_version_failures_use_stable_safe_codes(
    payload: object,
    code: AgentManifestValidationCode,
) -> None:
    with pytest.raises(AgentManifestValidationError) as captured:
        validate_agent_manifest_payload(payload)

    assert captured.value.code is code


def test_invalid_manifest_payload_exposes_only_field_paths(tmp_path: Path) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="json")
    payload["unexpected"] = SECRET_MARKER
    payload["identity"]["agent_id"] = SECRET_MARKER + "/invalid"

    with pytest.raises(AgentManifestValidationError) as captured:
        validate_agent_manifest_payload(payload)

    assert captured.value.code is AgentManifestValidationCode.INVALID_PAYLOAD
    assert SECRET_MARKER not in str(captured.value)
    assert "identity.agent_id" in captured.value.field_paths
    assert "unexpected" in captured.value.field_paths

    payload = manifest.model_dump(mode="json")
    payload[SECRET_MARKER] = True
    with pytest.raises(AgentManifestValidationError) as unsafe_field:
        validate_agent_manifest_payload(payload)
    assert unsafe_field.value.code is AgentManifestValidationCode.INVALID_PAYLOAD
    assert SECRET_MARKER not in str(unsafe_field.value)
    assert "<field>" in unsafe_field.value.field_paths


def test_invalid_manifest_json_never_leaks_source_text() -> None:
    with pytest.raises(AgentManifestValidationError) as captured:
        decode_agent_manifest_json(
            '{"schema_version":"0.1.0","secret":"' + SECRET_MARKER + '" invalid}'
        )

    assert captured.value.code is AgentManifestValidationCode.INVALID_JSON
    assert SECRET_MARKER not in str(captured.value)


def test_manifest_schema_export_is_deterministic_strict_and_complete(
    tmp_path: Path,
) -> None:
    first = export_agent_manifest_json_schema(tmp_path / "first")
    second = export_agent_manifest_json_schema(tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
    schema: dict[str, Any] = json.loads(first.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-agentsec-agent-manifest-schema-version"] == "0.3.0"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schema_version",
        "metadata",
        "identity",
        "sources",
        "instructions",
        "configuration",
        "tools",
        "permissions",
        "controls",
        "runtime_identities",
        "relationships",
        "coverage",
    }
    for definition in (
        "ManifestIdentity",
        "ManifestSource",
        "ManifestToolProfile",
        "ManifestPermissionProfile",
        "ManifestControlProfile",
        "ManifestRuntimeIdentityProfile",
        "ManifestRelationshipProfile",
        "ManifestUnknown",
        "ManifestCoverage",
    ):
        assert schema["$defs"][definition]["additionalProperties"] is False


def test_resolver_selects_only_base_instruction_when_no_override(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Root\n")
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))
    )

    resolved = InstructionResolver().resolve(manifest)

    assert resolved.instructions.resolution is ManifestResolutionStatus.RESOLVED
    assert [
        reference.locator.path for reference in resolved.instructions.effective_sources
    ] == ["AGENTS.md"]
    assert [
        reference.locator.path for reference in resolved.instructions.effective_order
    ] == ["AGENTS.md"]
    assert resolved.instructions.overridden_sources == ()
    assert [step.action.value for step in resolved.instructions.resolution_trace] == [
        "selected"
    ]
    assert resolved.instructions.resolution_trace[0].reason.value == "only_candidate"


def test_resolver_override_replaces_only_same_directory_base(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Root\n")
    _write(project / "AGENTS.override.md", "# Root Override\n")
    _write(project / "service" / "AGENTS.md", "# Service\n")
    _write(project / "service" / "AGENTS.override.md", "# Service Override\n")
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(
            FrameworkInspectionRequest(
                project_root=project,
                working_directory=project / "service",
            )
        )
    )

    resolved = InstructionResolver().resolve(manifest)

    assert resolved.instructions.resolution is ManifestResolutionStatus.RESOLVED
    assert [
        reference.locator.path for reference in resolved.instructions.effective_order
    ] == ["AGENTS.override.md", "service/AGENTS.override.md"]
    assert [
        reference.locator.path for reference in resolved.instructions.overridden_sources
    ] == ["AGENTS.md", "service/AGENTS.md"]
    assert [
        (step.source.locator.path, step.action.value, step.reason.value)
        for step in resolved.instructions.resolution_trace
    ] == [
        ("AGENTS.md", "overridden", "override_replaces_base"),
        ("AGENTS.override.md", "selected", "override_replaces_base"),
        ("service/AGENTS.md", "overridden", "override_replaces_base"),
        ("service/AGENTS.override.md", "selected", "override_replaces_base"),
    ]


def test_resolver_preserves_user_then_project_application_order(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    user_home = tmp_path / "home"
    project.mkdir()
    user_home.mkdir()
    _write(user_home / ".codex" / "AGENTS.md", "# User\n")
    _write(project / "AGENTS.md", "# Project\n")
    _write(project / "nested" / "AGENTS.md", "# Nested\n")
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(
            FrameworkInspectionRequest(
                project_root=project,
                working_directory=project / "nested",
                user_home=user_home,
            )
        )
    )

    resolved = InstructionResolver().resolve(manifest)

    assert [
        reference.locator.root_id for reference in resolved.instructions.effective_order
    ] == ["codex_home", "project", "project"]
    assert [
        reference.locator.path for reference in resolved.instructions.effective_order
    ] == ["AGENTS.md", "AGENTS.md", "nested/AGENTS.md"]
    # The public effective_sources tuple remains canonical locator order; the
    # effective_order tuple carries inheritance/application order.
    assert {
        (reference.locator.root_id, reference.locator.path)
        for reference in resolved.instructions.effective_sources
    } == {
        ("codex_home", "AGENTS.md"),
        ("project", "AGENTS.md"),
        ("project", "nested/AGENTS.md"),
    }


def test_resolver_marks_incomplete_coverage_partial_but_keeps_safe_selection(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Root\n")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))
    )

    resolved = InstructionResolver().resolve(manifest)

    assert resolved.instructions.resolution is ManifestResolutionStatus.PARTIAL
    assert [
        reference.locator.path for reference in resolved.instructions.effective_order
    ] == ["AGENTS.md"]
    assert resolved.instructions.overridden_sources == ()


def test_resolver_empty_instruction_scope_remains_unknown(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest = AgentManifestBuilder().build(
        CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))
    )

    resolved = InstructionResolver().resolve(manifest)

    assert resolved == manifest
    assert resolved.instructions.resolution is ManifestResolutionStatus.UNKNOWN


def test_resolver_rejects_ambiguous_duplicate_candidate_without_leaking_paths(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    payload = manifest.model_dump(mode="python")
    candidates = list(payload["instructions"]["candidates"])
    candidates.append(candidates[0])
    payload["instructions"]["candidates"] = tuple(candidates)
    # Constructing this payload through the strict Manifest model rejects the
    # duplicate first; the resolver's safe error is tested with a custom model
    # only for invalid filename shape below.
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(payload)

    candidate = manifest.instructions.candidates[0]
    malformed_source = candidate.source.model_copy(
        update={
            "locator": candidate.source.locator.model_copy(
                update={"path": "not-an-agents-file.txt"}
            )
        }
    )
    malformed_candidate = candidate.model_copy(update={"source": malformed_source})
    malformed_profile = manifest.instructions.model_construct(
        resolution=ManifestResolutionStatus.UNRESOLVED,
        candidates=(malformed_candidate,),
        effective_sources=(),
        effective_order=(),
        overridden_sources=(),
        resolution_trace=(),
    )
    malformed = manifest.model_copy(update={"instructions": malformed_profile})
    with pytest.raises(InstructionResolutionError) as captured:
        InstructionResolver().resolve(malformed)
    assert "not-an-agents-file.txt" not in str(captured.value)


def test_resolver_is_deterministic_and_does_not_read_source_content(
    tmp_path: Path,
) -> None:
    manifest = _build_manifest(tmp_path)
    resolver = InstructionResolver()

    first = resolver.resolve(manifest)
    second = resolver.resolve(manifest)

    assert first == second
    assert encode_agent_manifest_json(first) == encode_agent_manifest_json(second)
    assert SECRET_MARKER not in encode_agent_manifest_json(first)

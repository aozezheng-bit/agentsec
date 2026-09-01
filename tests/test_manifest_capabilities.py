"""P2-09 static permission, control, and identity tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import (
    AgentManifestBuilder,
    CapabilityExtractor,
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
    encode_agent_manifest_json,
)

SECRET_MARKER = "p2-09-secret-must-not-be-copied"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_extracts_rules_permissions_mcp_controls_and_runtime_identities(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "rules" / "default.rules",
        """
prefix_rule(pattern=["git", "status"], decision="prompt")
prefix_rule(pattern=["rm"], decision="forbidden")
""".lstrip(),
    )
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.docs]
command = "docs-{SECRET_MARKER}"
enabled = true
required = true
bearer_token_env_var = "DOCS_TOKEN"
enabled_tools = ["search"]
default_tools_approval_mode = "prompt"
startup_timeout_sec = 5
tool_timeout_ms = 1000

[mcp_servers.remote]
url = "https://api.example.invalid/mcp?token={SECRET_MARKER}"
auth = "oauth"
""".lstrip(),
    )

    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    extracted = CapabilityExtractor().extract(manifest, inspection)

    permissions = {
        (permission.action, permission.target): permission
        for permission in extracted.permissions.permissions
    }
    assert extracted.permissions.resolution is ManifestResolutionStatus.PARTIAL
    docs_execute = permissions[(ManifestPermissionAction.EXECUTE, "mcp-server:docs")]
    assert docs_execute.resource is ManifestResourceKind.SHELL
    assert docs_execute.effect is ManifestPermissionEffect.UNKNOWN
    remote_network = permissions[
        (ManifestPermissionAction.NETWORK, "mcp-server:remote")
    ]
    assert remote_network.resource is ManifestResourceKind.NETWORK
    assert remote_network.scope is ManifestResourceScope.EXTERNAL
    assert docs_execute.sources
    assert any(
        permission.action is ManifestPermissionAction.SECRET_ACCESS
        and permission.resource is ManifestResourceKind.ENVIRONMENT
        and permission.target == "mcp-server:docs"
        for permission in extracted.permissions.permissions
    )

    rule_permissions = [
        permission
        for permission in extracted.permissions.permissions
        if permission.action is ManifestPermissionAction.EXECUTE
        and permission.resource is ManifestResourceKind.SHELL
        and permission.target is not None
        and permission.target.startswith("rule:")
    ]
    assert len(rule_permissions) == 2
    assert {permission.effect for permission in rule_permissions} == {
        ManifestPermissionEffect.PROMPT,
        ManifestPermissionEffect.DENY,
    }

    controls = extracted.controls.controls
    assert extracted.controls.resolution is ManifestResolutionStatus.PARTIAL
    assert any(
        control.kind is ManifestControlKind.ENABLEMENT
        and control.state is ManifestControlState.ENABLED
        and control.target == "mcp-server:docs"
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.REQUIRED
        and control.state is ManifestControlState.REQUIRED
        and control.target == "mcp-server:docs"
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.HUMAN_APPROVAL
        and control.state is ManifestControlState.PROMPT
        and control.target == "mcp-server:docs"
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.SECRET_HANDLING
        and control.state is ManifestControlState.CONFIGURED
        and control.target == "mcp-server:docs"
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.TIMEOUT
        and control.target == "mcp-server:docs"
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.PREFIX_RULE
        and control.state is ManifestControlState.PROMPT
        for control in controls
    )
    assert any(
        control.kind is ManifestControlKind.PREFIX_RULE
        and control.state is ManifestControlState.DENY
        for control in controls
    )

    identities = {
        identity.identity_id: identity
        for identity in extracted.runtime_identities.identities
    }
    assert extracted.runtime_identities.resolution is ManifestResolutionStatus.RESOLVED
    assert (
        identities["identity:mcp-server:docs"].principal_kind
        is ManifestPrincipalKind.API_CLIENT
    )
    assert (
        identities["identity:mcp-server:docs"].authentication
        is ManifestAuthenticationKind.ENVIRONMENT
    )
    assert (
        identities["identity:mcp-server:docs"].environment
        is ManifestEnvironmentKind.LOCAL
    )
    assert (
        identities["identity:mcp-server:remote"].principal_kind
        is ManifestPrincipalKind.OAUTH_SESSION
    )
    assert (
        identities["identity:mcp-server:remote"].authentication
        is ManifestAuthenticationKind.OAUTH
    )
    assert (
        identities["identity:mcp-server:remote"].environment
        is ManifestEnvironmentKind.EXTERNAL
    )

    encoded = encode_agent_manifest_json(extracted)
    assert SECRET_MARKER not in encoded
    assert "docs-" not in encoded
    assert "api.example.invalid" not in encoded
    assert "DOCS_TOKEN" not in encoded


def test_capability_extraction_is_deterministic_and_coverage_aware(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / ".codex" / "config.toml", 'model = "safe"\n')
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")
    (project / "AGENTS.md").write_bytes(b"\xff\xfe")

    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    extractor = CapabilityExtractor()
    first = extractor.extract(manifest, inspection)
    second = extractor.extract(manifest, inspection)

    assert first == second
    assert encode_agent_manifest_json(first) == encode_agent_manifest_json(second)
    assert first.permissions.resolution is ManifestResolutionStatus.PARTIAL
    assert first.controls.resolution is ManifestResolutionStatus.PARTIAL
    assert first.runtime_identities.resolution is ManifestResolutionStatus.PARTIAL
    assert all(permission.sources for permission in first.permissions.permissions)
    assert all(control.sources for control in first.controls.controls)

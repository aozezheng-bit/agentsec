"""P2-08 Skill and static MCP association tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.frameworks import (
    CodexAdapter,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    AssociationExtractionError,
    AssociationExtractor,
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
    encode_agent_manifest_json,
)

SECRET_MARKER = "p2-08-secret-must-not-be-copied"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _inspect(project: Path) -> FrameworkInspectionResult:
    return CodexAdapter().inspect(FrameworkInspectionRequest(project_root=project))


def _associate(project: Path) -> AgentManifest:
    inspection = _inspect(project)
    manifest = AgentManifestBuilder().build(inspection)
    return AssociationExtractor().extract(manifest, inspection)


def test_extracts_skill_mcp_server_and_static_mcp_tools_with_provenance(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.docs]
command = "server-{SECRET_MARKER}"
args = ["--safe"]
enabled = true
enabled_tools = ["search", "write"]
disabled_tools = ["delete"]

[mcp_servers.docs.tools.lookup]
approval_mode = "prompt"

[mcp_servers.remote]
url = "https://example.invalid/mcp?token={SECRET_MARKER}"
enabled = false
""".lstrip(),
    )

    inspection = _inspect(project)
    manifest = AgentManifestBuilder().build(inspection)
    associated = AssociationExtractor().extract(manifest, inspection)

    assert associated.tools.resolution is ManifestResolutionStatus.RESOLVED
    assert associated.relationships.resolution is ManifestResolutionStatus.RESOLVED
    assert [tool.tool_id for tool in associated.tools.tools] == [
        "mcp-server:docs",
        "mcp-server:remote",
        "mcp-tool:docs:delete",
        "mcp-tool:docs:lookup",
        "mcp-tool:docs:search",
        "mcp-tool:docs:write",
        "skill:review",
    ]

    tools = {tool.tool_id: tool for tool in associated.tools.tools}
    assert tools["skill:review"].kind is ManifestToolKind.SKILL
    assert tools["skill:review"].availability is ManifestToolAvailability.DECLARED
    assert tools["skill:review"].side_effects == (ManifestToolSideEffect.UNKNOWN,)
    assert tools["skill:review"].sources[0].locator.path == (
        ".agents/skills/review/SKILL.md"
    )

    assert tools["mcp-server:docs"].availability is ManifestToolAvailability.ENABLED
    assert tools["mcp-server:docs"].side_effects == (ManifestToolSideEffect.EXECUTE,)
    assert tools["mcp-server:remote"].availability is ManifestToolAvailability.DISABLED
    assert tools["mcp-server:remote"].side_effects == (ManifestToolSideEffect.NETWORK,)

    assert tools["mcp-tool:docs:search"].parent_tool_id == "mcp-server:docs"
    assert tools["mcp-tool:docs:search"].availability is (
        ManifestToolAvailability.ENABLED
    )
    assert tools["mcp-tool:docs:search"].sources[0].field_path == (
        "$.mcp_servers.docs.enabled_tools[0]"
    )
    assert tools["mcp-tool:docs:lookup"].availability is (
        ManifestToolAvailability.DECLARED
    )
    assert tools["mcp-tool:docs:lookup"].sources[0].field_path == (
        "$.mcp_servers.docs.tools.lookup.approval_mode"
    )

    relation_by_target = {
        relation.target_id: relation for relation in associated.relationships.relations
    }
    assert relation_by_target["skill:review"].kind is ManifestRelationKind.USES_SKILL
    assert relation_by_target["mcp-server:docs"].kind is ManifestRelationKind.USES_MCP
    assert relation_by_target["mcp-tool:docs:search"].kind is (
        ManifestRelationKind.USES_TOOL
    )
    assert all(
        relation.state is ManifestRelationState.DECLARED
        for relation in associated.relationships.relations
    )

    encoded = encode_agent_manifest_json(associated)
    assert SECRET_MARKER not in encoded
    assert "server-" not in encoded
    assert "example.invalid" not in encoded


def test_association_is_deterministic_and_collision_safe(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(project / ".agents" / "skills" / "same" / "SKILL.md", "# One\n")
    _write(project / "nested" / ".agents" / "skills" / "same" / "SKILL.md", "# Two\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.docs]
command = "docs-server"

[mcp_servers.docs2]
command = "docs-server-2"
""".lstrip(),
    )

    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(
            project_root=project,
            working_directory=project / "nested",
        )
    )
    manifest = AgentManifestBuilder().build(inspection)
    extractor = AssociationExtractor()
    first = extractor.extract(manifest, inspection)
    second = extractor.extract(manifest, inspection)

    assert first == second
    assert encode_agent_manifest_json(first) == encode_agent_manifest_json(second)
    skill_ids = [
        tool.tool_id
        for tool in first.tools.tools
        if tool.kind is ManifestToolKind.SKILL
    ]
    assert len(skill_ids) == 2
    assert len(set(skill_ids)) == 2
    assert all(tool.sources for tool in first.tools.tools)
    assert all(relation.sources for relation in first.relationships.relations)


def test_conflicting_mcp_tool_filters_fail_closed_to_unknown(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.docs]
command = "docs-server"
enabled_tools = ["search"]
disabled_tools = ["search"]
""".lstrip(),
    )

    associated = _associate(project)
    tool = next(
        tool
        for tool in associated.tools.tools
        if tool.kind is ManifestToolKind.MCP_TOOL
    )

    assert tool.tool_id == "mcp-tool:docs:search"
    assert tool.availability is ManifestToolAvailability.UNKNOWN
    assert len(tool.sources) == 2


def test_incomplete_framework_coverage_produces_partial_associations(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")
    (project / "AGENTS.md").write_bytes(b"\xff\xfe")

    associated = _associate(project)

    assert associated.coverage.complete is False
    assert associated.tools.resolution is ManifestResolutionStatus.PARTIAL
    assert associated.relationships.resolution is ManifestResolutionStatus.PARTIAL
    assert [tool.tool_id for tool in associated.tools.tools] == ["skill:review"]


def test_rejects_stale_or_mismatched_inspection(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")

    inspection = _inspect(project)
    manifest = AgentManifestBuilder().build(inspection)
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Changed\n")
    stale_inspection = _inspect(project)

    with pytest.raises(AssociationExtractionError):
        AssociationExtractor().extract(manifest, stale_inspection)

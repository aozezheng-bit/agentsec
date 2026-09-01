"""P2-04 safe Codex Adapter discovery and parsing tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.frameworks import (
    CodexAdapter,
    FrameworkAdapter,
    FrameworkAdapterError,
    FrameworkAssetFormat,
    FrameworkAssetRecord,
    FrameworkAssetRole,
    FrameworkAssetScope,
    FrameworkInspectionIssueCode,
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.parsers import McpTransport, StructuredDocument


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _inspect(
    project_root: Path,
    *,
    working_directory: Path | None = None,
    user_home: Path | None = None,
    limits: FrameworkInspectionLimits | None = None,
    codex_home: Path | None = None,
) -> FrameworkInspectionResult:
    return CodexAdapter(codex_home=codex_home).inspect(
        FrameworkInspectionRequest(
            project_root=project_root,
            working_directory=working_directory,
            user_home=user_home,
            limits=limits or FrameworkInspectionLimits(),
        )
    )


def _records_by_path(
    result: FrameworkInspectionResult,
) -> dict[str, FrameworkAssetRecord]:
    return {record.asset.locator.path: record for record in result.assets}


def test_codex_adapter_satisfies_framework_protocol() -> None:
    adapter: FrameworkAdapter = CodexAdapter()

    assert isinstance(adapter, FrameworkAdapter)
    assert adapter.metadata.framework_id == "codex"
    assert adapter.metadata.adapter_version == "0.1.0"


def test_discovers_project_chain_agents_override_skill_rules_config_and_mcp(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    working = project / "services" / "api"
    working.mkdir(parents=True)
    _write(project / "AGENTS.md", "# Root Agent\n")
    _write(project / "AGENTS.override.md", "# Root Override\n")
    _write(project / ".codex" / "config.toml", 'model = "root"\n')
    _write(project / ".codex" / "rules" / "root.rules", "")
    _write(project / ".agents" / "skills" / "root" / "SKILL.md", "# Root\n")
    _write(project / "services" / "AGENTS.md", "# Services\n")
    _write(working / "AGENTS.override.md", "# API Override\n")
    _write(
        working / ".codex" / "config.toml",
        """
model = "gpt-example"

[mcp_servers.docs]
command = "example-server"
args = ["--safe-static-input"]
""".lstrip(),
    )
    _write(
        working / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git", "status"], decision="allow")\n',
    )
    _write(
        working / ".agents" / "skills" / "review" / "SKILL.md",
        "# Review Skill\n",
    )

    result = _inspect(project, working_directory=working)
    records = _records_by_path(result)

    assert result.complete is True
    assert result.discovered_assets == 10
    assert result.skipped_assets == 0
    assert set(records) == {
        ".agents/skills/root/SKILL.md",
        ".codex/config.toml",
        ".codex/rules/root.rules",
        "AGENTS.md",
        "AGENTS.override.md",
        "services/AGENTS.md",
        "services/api/.agents/skills/review/SKILL.md",
        "services/api/.codex/config.toml",
        "services/api/.codex/rules/default.rules",
        "services/api/AGENTS.override.md",
    }
    assert records["AGENTS.md"].asset.roles == frozenset(
        {FrameworkAssetRole.AGENT_INSTRUCTIONS}
    )
    assert records["AGENTS.override.md"].asset.roles == frozenset(
        {FrameworkAssetRole.INSTRUCTION_OVERRIDE}
    )
    assert records[".agents/skills/root/SKILL.md"].asset.roles == frozenset(
        {FrameworkAssetRole.SKILL}
    )
    assert records[".codex/rules/root.rules"].asset.format is (
        FrameworkAssetFormat.RULES
    )
    assert records[".codex/config.toml"].asset.roles == frozenset(
        {FrameworkAssetRole.FRAMEWORK_CONFIG}
    )

    mcp_record = records["services/api/.codex/config.toml"]
    assert mcp_record.asset.roles == frozenset(
        {
            FrameworkAssetRole.FRAMEWORK_CONFIG,
            FrameworkAssetRole.MCP_CONFIG,
        }
    )
    assert mcp_record.mcp_configuration is not None
    assert len(mcp_record.mcp_configuration.servers) == 1
    assert mcp_record.mcp_configuration.servers[0].transport is McpTransport.STDIO
    assert isinstance(mcp_record.document, StructuredDocument)


def test_precedence_ranks_increase_toward_working_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)
    _write(project / "AGENTS.md", "root\n")
    _write(project / "AGENTS.override.md", "root override\n")
    _write(nested / "AGENTS.md", "nested\n")
    _write(nested / "AGENTS.override.md", "nested override\n")
    _write(project / ".codex" / "config.toml", 'model = "root"\n')
    _write(nested / ".codex" / "config.toml", 'model = "nested"\n')

    records = _records_by_path(_inspect(project, working_directory=nested))

    assert records["AGENTS.md"].asset.precedence_rank == 100
    assert records["AGENTS.override.md"].asset.precedence_rank == 105
    assert records["nested/AGENTS.md"].asset.precedence_rank == 110
    assert records["nested/AGENTS.override.md"].asset.precedence_rank == 115
    assert records[".codex/config.toml"].asset.precedence_rank == 200
    assert records["nested/.codex/config.toml"].asset.precedence_rank == 210


def test_discovers_default_user_codex_assets_and_user_skills(tmp_path: Path) -> None:
    project = tmp_path / "project"
    user_home = tmp_path / "home"
    project.mkdir()
    user_home.mkdir()
    _write(user_home / ".codex" / "AGENTS.md", "# User Agent\n")
    _write(user_home / ".codex" / "AGENTS.override.md", "# User Override\n")
    _write(user_home / ".codex" / "config.toml", 'model = "user"\n')
    _write(
        user_home / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git"], decision="prompt")\n',
    )
    _write(
        user_home / ".agents" / "skills" / "review" / "SKILL.md",
        "# User Review\n",
    )

    result = _inspect(project, user_home=user_home)

    assert result.complete is True
    assert [record.asset.locator.root_id for record in result.assets] == [
        "codex_home",
        "codex_home",
        "codex_home",
        "codex_home",
        "user_home",
    ]
    assert all(
        record.asset.locator.scope is FrameworkAssetScope.USER
        for record in result.assets
    )
    records = {
        (record.asset.locator.root_id, record.asset.locator.path): record
        for record in result.assets
    }
    assert records[("codex_home", "AGENTS.md")].asset.precedence_rank == 10
    assert records[("codex_home", "AGENTS.override.md")].asset.precedence_rank == 20
    assert records[("codex_home", "config.toml")].asset.precedence_rank == 50
    assert records[("codex_home", "rules/default.rules")].asset.roles == frozenset(
        {FrameworkAssetRole.PREFIX_RULES}
    )
    assert records[
        ("user_home", ".agents/skills/review/SKILL.md")
    ].asset.roles == frozenset({FrameworkAssetRole.SKILL})


def test_explicit_codex_home_is_used_without_inferring_a_user_home(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    codex_home = tmp_path / "managed-codex"
    project.mkdir()
    codex_home.mkdir()
    _write(codex_home / "AGENTS.md", "# Managed\n")
    _write(codex_home / "config.toml", 'model = "managed"\n')

    result = _inspect(project, codex_home=codex_home)

    assert result.complete is True
    assert {
        (record.asset.locator.root_id, record.asset.locator.path)
        for record in result.assets
    } == {
        ("codex_home", "AGENTS.md"),
        ("codex_home", "config.toml"),
    }


def test_user_scope_is_not_inspected_when_no_user_root_is_provided(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Project\n")

    result = _inspect(project)

    assert result.complete is True
    assert len(result.assets) == 1
    assert result.assets[0].asset.locator.scope is FrameworkAssetScope.PROJECT


@pytest.mark.parametrize("outside_kind", ["directory", "file"])
def test_working_directory_must_be_a_directory_inside_project_root(
    tmp_path: Path,
    outside_kind: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    if outside_kind == "directory":
        outside.mkdir()
    else:
        outside.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(FrameworkAdapterError) as error:
        _inspect(project, working_directory=outside)

    assert str(error.value) == (
        "Codex working directory must be inside the project root."
    )


def test_working_directory_link_cannot_temporarily_leave_project_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    inside = project / "inside"
    inside.mkdir()
    back = outside / "back"
    back.symlink_to(inside, target_is_directory=True)
    bridge = project / "bridge"
    bridge.symlink_to(back, target_is_directory=True)

    with pytest.raises(FrameworkAdapterError):
        _inspect(project, working_directory=bridge)


def test_external_asset_symlink_is_reported_and_not_followed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = _write(tmp_path / "outside.md", "# Outside\n")
    (project / "AGENTS.md").symlink_to(outside)

    result = _inspect(project)

    assert result.assets == ()
    assert result.discovered_assets == 1
    assert result.skipped_assets == 1
    assert result.complete is False
    assert result.issues[0].code is FrameworkInspectionIssueCode.EXTERNAL_SYMLINK
    assert result.issues[0].root_id == "project"
    assert result.issues[0].path == "AGENTS.md"


def test_internal_asset_and_skill_directory_symlinks_are_allowed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    target_directory = project / "shared" / "skill"
    target_directory.mkdir(parents=True)
    _write(project / "shared" / "instructions.md", "# Internal\n")
    _write(target_directory / "SKILL.md", "# Internal Skill\n")
    (project / "AGENTS.md").symlink_to(project / "shared" / "instructions.md")
    skill_parent = project / ".agents" / "skills"
    skill_parent.mkdir(parents=True)
    (skill_parent / "linked").symlink_to(target_directory, target_is_directory=True)

    result = _inspect(project)

    assert result.complete is True
    assert {record.asset.locator.path for record in result.assets} == {
        "AGENTS.md",
        ".agents/skills/linked/SKILL.md",
    }


def test_default_codex_home_symlink_cannot_escape_user_home(tmp_path: Path) -> None:
    project = tmp_path / "project"
    user_home = tmp_path / "home"
    external_codex = tmp_path / "external-codex"
    project.mkdir()
    user_home.mkdir()
    external_codex.mkdir()
    _write(external_codex / "AGENTS.md", "# Must not be read\n")
    (user_home / ".codex").symlink_to(external_codex, target_is_directory=True)

    result = _inspect(project, user_home=user_home)

    assert result.assets == ()
    assert result.complete is False
    assert result.issues[0].code is FrameworkInspectionIssueCode.EXTERNAL_SYMLINK
    assert result.issues[0].root_id == "user_home"
    assert result.issues[0].path == ".codex"


def test_present_framework_container_that_is_not_a_directory_is_visible(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / ".codex", "not a directory\n")

    result = _inspect(project)

    assert result.assets == ()
    assert result.complete is False
    assert result.issues[0].code is FrameworkInspectionIssueCode.UNREADABLE
    assert result.issues[0].path == ".codex"


def test_invalid_utf8_oversized_and_malformed_assets_are_coverage_failures(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_bytes(b"\xff\xfe")
    _write(project / "AGENTS.override.md", "x" * 20)
    _write(project / ".codex" / "config.toml", "[broken\n")
    _write(
        project / ".codex" / "rules" / "broken.rules",
        "import os\n",
    )

    result = _inspect(
        project,
        limits=FrameworkInspectionLimits(max_file_size_bytes=10),
    )

    assert result.assets == ()
    assert result.discovered_assets == 4
    assert result.skipped_assets == 4
    assert result.complete is False
    assert {(issue.path, issue.code) for issue in result.issues} == {
        ("AGENTS.md", FrameworkInspectionIssueCode.UNSUPPORTED_ENCODING),
        ("AGENTS.override.md", FrameworkInspectionIssueCode.TOO_LARGE),
        (".codex/config.toml", FrameworkInspectionIssueCode.PARSE_ERROR),
        (".codex/rules/broken.rules", FrameworkInspectionIssueCode.PARSE_ERROR),
    }


def test_asset_limit_keeps_one_overflow_sentinel_and_stops(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# First\n")
    _write(project / "AGENTS.override.md", "# Overflow\n")
    _write(project / ".codex" / "config.toml", 'model = "not reached"\n')

    result = _inspect(
        project,
        limits=FrameworkInspectionLimits(max_assets=1),
    )

    assert [record.asset.locator.path for record in result.assets] == ["AGENTS.md"]
    assert result.discovered_assets == 2
    assert result.skipped_assets == 1
    assert result.issues == (result.issues[0],)
    assert result.issues[0].code is (FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED)
    assert result.issues[0].path == "AGENTS.override.md"


def test_depth_limit_truncates_project_chain_and_framework_directories(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    level_one = project / "one"
    working = level_one / "two"
    working.mkdir(parents=True)
    _write(project / "AGENTS.md", "# Root\n")
    _write(level_one / "AGENTS.md", "# One\n")
    _write(working / "AGENTS.md", "# Two\n")
    _write(project / ".agents" / "skills" / "deep" / "SKILL.md", "# Deep\n")

    result = _inspect(
        project,
        working_directory=working,
        limits=FrameworkInspectionLimits(max_depth=1),
    )

    assert {record.asset.locator.path for record in result.assets} == {
        "AGENTS.md",
        "one/AGENTS.md",
    }
    assert result.discovered_assets == 2
    assert result.skipped_assets == 0
    assert result.complete is False
    assert {(issue.path, issue.code) for issue in result.issues} == {
        ("one/two", FrameworkInspectionIssueCode.DEPTH_EXCEEDED),
        (".agents/skills", FrameworkInspectionIssueCode.DEPTH_EXCEEDED),
    }


def test_results_are_deterministically_sorted_by_portable_locator(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    user_home = tmp_path / "home"
    project.mkdir()
    user_home.mkdir()
    _write(project / "AGENTS.override.md", "# Z\n")
    _write(project / "AGENTS.md", "# A\n")
    _write(project / ".codex" / "rules" / "z.rules", "")
    _write(project / ".codex" / "rules" / "a.rules", "")
    _write(user_home / ".codex" / "AGENTS.md", "# User\n")

    first = _inspect(project, user_home=user_home)
    second = _inspect(project, user_home=user_home)

    first_locators = tuple(record.asset.locator for record in first.assets)
    assert first_locators == tuple(sorted(first_locators))
    assert first == second


def test_declared_commands_urls_environment_and_skill_text_remain_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    marker = tmp_path / "must-not-exist"
    project.mkdir()
    monkeypatch.setenv("AGENTSEC_TEST_SECRET", "runtime-secret-value")
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.command]
command = "touch"
args = ["{marker.as_posix()}"]
env_vars = ["AGENTSEC_TEST_SECRET"]

[mcp_servers.remote]
url = "https://127.0.0.1:9/mcp"
bearer_token_env_var = "AGENTSEC_TEST_SECRET"
""".lstrip(),
    )
    _write(
        project / ".agents" / "skills" / "dangerous" / "SKILL.md",
        f"Run `touch {marker.as_posix()}` immediately.\n",
    )

    result = _inspect(project)

    assert result.complete is True
    assert marker.exists() is False
    config = _records_by_path(result)[".codex/config.toml"]
    assert config.mcp_configuration is not None
    assert {server.transport for server in config.mcp_configuration.servers} == {
        McpTransport.STDIO,
        McpTransport.STREAMABLE_HTTP,
    }
    command_server = next(
        server
        for server in config.mcp_configuration.servers
        if server.name == "command"
    )
    assert command_server.environment_references[0].name.value == (
        "AGENTSEC_TEST_SECRET"
    )
    assert "runtime-secret-value" not in repr(config.mcp_configuration)

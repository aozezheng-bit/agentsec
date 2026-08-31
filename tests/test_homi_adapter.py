"""P2-HOMI-01 safe Homi Workspace Adapter tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.frameworks import (
    FrameworkAdapter,
    FrameworkAssetRole,
    FrameworkInspectionIssueCode,
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
    HomiAdapter,
    HomiFileRole,
    HomiFileState,
    HomiObservationCode,
    HomiObservationKind,
    HomiResolutionStatus,
    HomiVisibility,
    HomiWorkspaceFile,
    HomiWorkspaceInspection,
    HomiWorkspacePolicyResolver,
)


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _request(
    project: Path,
    *,
    limits: FrameworkInspectionLimits | None = None,
) -> FrameworkInspectionRequest:
    return FrameworkInspectionRequest(
        project_root=project,
        limits=limits or FrameworkInspectionLimits(),
    )


def _write_full_homi_workspace(project: Path) -> None:
    _write(project / "AGENTS.md", "# Workspace policy\nRead files safely.\n")
    _write(project / "SOUL.md", "# Soul\nBe helpful and careful.\n")
    _write(project / "IDENTITY.md", "Name: HomiClaw\nEmoji: ✨\n")
    _write(project / "USER.md", "# User Profile\nName: not configured\n")
    _write(
        project / "TOOLS.md",
        """# Local Notes

## What Goes Here
Camera and SSH aliases.

## Examples
home-server → 192.0.2.10, user: example

## Why Separate?
Skills are shared.

Add whatever helps. This is your cheat sheet.
""",
    )
    _write(
        project / "HEARTBEAT.md",
        """# Keep this file empty (or with only comments) to skip heartbeat API calls.

# Add tasks below when you want the agent to check something periodically.
""",
    )


def _files_by_name(result: HomiWorkspaceInspection) -> dict[str, HomiWorkspaceFile]:
    return {item.name: item for item in result.files}


def test_homi_adapter_satisfies_framework_protocol() -> None:
    adapter: FrameworkAdapter = HomiAdapter()

    assert isinstance(adapter, FrameworkAdapter)
    assert adapter.metadata.framework_id == "homi"
    assert adapter.metadata.display_name == "Homi"
    assert adapter.metadata.adapter_version == "0.2.0"


def test_discovers_and_classifies_all_six_homi_files(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write_full_homi_workspace(project)

    result = HomiAdapter().inspect_workspace(_request(project))
    files = _files_by_name(result)

    assert result.complete is True
    assert result.all_standard_files_present is True
    assert result.framework_result.discovered_assets == 6
    assert result.framework_result.skipped_assets == 0
    assert files["AGENTS.md"].role is HomiFileRole.WORKSPACE_POLICY
    assert files["AGENTS.md"].state is HomiFileState.PRESENT
    assert files["SOUL.md"].role is HomiFileRole.PERSONA
    assert files["IDENTITY.md"].role is HomiFileRole.IDENTITY
    assert files["USER.md"].role is HomiFileRole.USER_PROFILE
    assert files["TOOLS.md"].role is HomiFileRole.TOOL_NOTES
    assert files["TOOLS.md"].state is HomiFileState.EXAMPLE_ONLY
    assert files["HEARTBEAT.md"].role is HomiFileRole.HEARTBEAT_SCHEDULE
    assert files["HEARTBEAT.md"].state is HomiFileState.EMPTY
    assert {record.asset.locator.path for record in result.framework_result.assets} == {
        "AGENTS.md",
        "SOUL.md",
        "IDENTITY.md",
        "USER.md",
        "TOOLS.md",
        "HEARTBEAT.md",
    }
    assert all(
        record.asset.roles == frozenset({FrameworkAssetRole.AGENT_INSTRUCTIONS})
        for record in result.framework_result.assets
    )


def test_missing_homi_files_are_classified_without_fake_coverage_errors(
    tmp_path: Path,
) -> None:
    project = tmp_path / "partial-homi"
    project.mkdir()
    _write(project / "AGENTS.md", "# Policy\n")

    result = HomiAdapter().inspect_workspace(_request(project))
    files = _files_by_name(result)

    assert result.complete is True
    assert result.all_standard_files_present is False
    assert result.framework_result.discovered_assets == 1
    assert files["AGENTS.md"].state is HomiFileState.PRESENT
    assert [
        files[name].state
        for name in ("SOUL.md", "IDENTITY.md", "USER.md", "TOOLS.md", "HEARTBEAT.md")
    ] == [HomiFileState.MISSING] * 5


def test_empty_and_non_template_tools_are_distinguished(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "HEARTBEAT.md", "\n<!-- disabled -->\n")
    _write(project / "TOOLS.md", "# Tools\nPreferred voice: Nova\n")

    result = HomiAdapter().inspect_workspace(_request(project))
    files = _files_by_name(result)

    assert files["HEARTBEAT.md"].state is HomiFileState.EMPTY
    assert files["TOOLS.md"].state is HomiFileState.PRESENT


def test_heartbeat_documentation_template_is_example_only(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(
        project / "HEARTBEAT.md",
        """```markdown
# Keep this file empty (or with only comments) to skip heartbeat API calls.

# Add tasks below when you want the agent to check something periodically.
```

## Related

- [Heartbeat config](/gateway/config-agents)
""",
    )

    result = HomiAdapter().inspect_workspace(_request(project))

    assert _files_by_name(result)["HEARTBEAT.md"].state is (HomiFileState.EXAMPLE_ONLY)


def test_heartbeat_template_with_real_task_is_present(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(
        project / "HEARTBEAT.md",
        """# Keep this file empty to skip heartbeat API calls.
# Add tasks below when you want the agent to check something periodically.

- Check urgent unread email every 30 minutes.
""",
    )

    result = HomiAdapter().inspect_workspace(_request(project))

    assert _files_by_name(result)["HEARTBEAT.md"].state is HomiFileState.PRESENT


def test_external_symlink_is_skipped_and_not_followed(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    outside = _write(tmp_path / "outside.md", "# External\n")
    (project / "AGENTS.md").symlink_to(outside)

    result = HomiAdapter().inspect_workspace(_request(project))
    files = _files_by_name(result)

    assert result.complete is False
    assert files["AGENTS.md"].state is HomiFileState.SKIPPED
    assert files["AGENTS.md"].issue_codes == (
        FrameworkInspectionIssueCode.EXTERNAL_SYMLINK,
    )
    assert result.framework_result.assets == ()
    assert result.framework_result.skipped_assets == 1


def test_encoding_and_size_limits_are_reported_safely(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", b"\xff\xfe\x00")
    _write(project / "SOUL.md", "x" * 32)

    result = HomiAdapter().inspect_workspace(
        _request(
            project,
            limits=FrameworkInspectionLimits(max_file_size_bytes=8),
        )
    )
    files = _files_by_name(result)

    assert files["AGENTS.md"].state is HomiFileState.SKIPPED
    assert files["AGENTS.md"].issue_codes == (
        FrameworkInspectionIssueCode.UNSUPPORTED_ENCODING,
    )
    assert files["SOUL.md"].state is HomiFileState.SKIPPED
    assert files["SOUL.md"].issue_codes == (FrameworkInspectionIssueCode.TOO_LARGE,)
    assert result.complete is False
    assert all(
        "\xff" not in issue.path
        for issue in result.framework_result.issues
        if issue.path
    )


def test_asset_limit_marks_remaining_standard_files_skipped(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write_full_homi_workspace(project)

    result = HomiAdapter().inspect_workspace(
        _request(
            project,
            limits=FrameworkInspectionLimits(max_assets=2),
        )
    )
    files = _files_by_name(result)

    assert result.framework_result.discovered_assets == 3
    assert result.framework_result.skipped_assets == 1
    assert result.framework_result.complete is False
    assert files["AGENTS.md"].state is HomiFileState.PRESENT
    assert files["SOUL.md"].state is HomiFileState.PRESENT
    assert all(
        files[name].state is HomiFileState.SKIPPED
        for name in ("IDENTITY.md", "USER.md", "TOOLS.md", "HEARTBEAT.md")
    )
    assert any(
        issue.code is FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED
        for issue in result.framework_result.issues
    )


def test_inspection_is_deterministic_and_does_not_expose_source_values(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "# Token\nTOKEN=do-not-copy\n")

    first = HomiAdapter().inspect_workspace(_request(project))
    second = HomiAdapter().inspect_workspace(_request(project))

    assert first == second
    assert first.files[0].content_sha256 is not None
    assert "do-not-copy" not in repr(first.files[0])


def test_homi_adapter_reuses_existing_agent_analysis_pipeline(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "# Policy\nRead safely.\n")

    result = AgentAnalysisPipeline(adapter=HomiAdapter()).analyze(
        AgentAnalysisRequest(project_root=project)
    )

    assert result.complete is True
    assert result.manifest.metadata.framework_id == "homi"
    assert result.manifest.metadata.adapter_version == "0.2.0"
    assert tuple(stage.status.value for stage in result.stages) == (
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
    )


def test_homi_policy_resolver_exposes_security_precedence_and_visibility(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write_full_homi_workspace(project)

    resolution = HomiWorkspacePolicyResolver().resolve(
        HomiAdapter().inspect_workspace(_request(project))
    )
    policies = {policy.role: policy for policy in resolution.policies}

    assert resolution.status is HomiResolutionStatus.RESOLVED
    assert policies[HomiFileRole.WORKSPACE_POLICY].authority_rank == 100
    assert policies[HomiFileRole.HEARTBEAT_SCHEDULE].authority_rank == 90
    assert policies[HomiFileRole.TOOL_NOTES].authority_rank == 80
    assert policies[HomiFileRole.USER_PROFILE].authority_rank == 70
    assert policies[HomiFileRole.PERSONA].authority_rank == 60
    assert policies[HomiFileRole.IDENTITY].authority_rank == 50
    assert (
        policies[HomiFileRole.USER_PROFILE].visibility
        is HomiVisibility.MAIN_SESSION_ONLY
    )
    assert (
        policies[HomiFileRole.TOOL_NOTES].visibility is HomiVisibility.PRIVATE_RUNTIME
    )
    assert (
        policies[HomiFileRole.HEARTBEAT_SCHEDULE].visibility
        is HomiVisibility.SCHEDULER_ONLY
    )
    assert policies[HomiFileRole.WORKSPACE_POLICY].may_override_roles
    assert all(not policy.runtime_authority for policy in resolution.policies)
    assert any(
        item.code is HomiObservationCode.EMPTY_HEARTBEAT_DISABLED
        and item.kind is HomiObservationKind.AUTHORITY_BOUNDARY
        for item in resolution.observations
    )


def test_homi_policy_resolver_detects_startup_precedence_conflict(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "Use runtime-provided startup context. Do not manually reread startup files.\n",
    )
    _write(
        project / "SOUL.md",
        "Each session, read them. These files are your memory.\n",
    )

    resolution = HomiWorkspacePolicyResolver().resolve(
        HomiAdapter().inspect_workspace(_request(project))
    )
    conflicts = [
        item
        for item in resolution.observations
        if item.code is HomiObservationCode.STARTUP_READ_POLICY_CONFLICT
    ]

    assert resolution.status is HomiResolutionStatus.CONFLICT
    assert len(conflicts) == 1
    assert conflicts[0].kind is HomiObservationKind.CONFLICT
    assert conflicts[0].resolution == "workspace_policy_wins_for_startup_loading"
    assert tuple(source.path for source in conflicts[0].sources) == (
        "AGENTS.md",
        "SOUL.md",
    )


def test_homi_policy_resolver_detects_control_and_heartbeat_activation_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "You are free to edit HEARTBEAT.md.\n")
    _write(project / "SOUL.md", "This file is yours to evolve.\n")
    _write(
        project / "HEARTBEAT.md",
        "# Keep this file empty or with only comments to skip API calls.\n",
    )

    resolution = HomiWorkspacePolicyResolver().resolve(
        HomiAdapter().inspect_workspace(_request(project))
    )
    codes = {item.code for item in resolution.observations}

    assert HomiObservationCode.CONTROL_PLANE_SELF_MODIFICATION in codes
    assert HomiObservationCode.HEARTBEAT_ACTIVATION_PATH in codes
    assert resolution.status is HomiResolutionStatus.PARTIAL


def test_homi_policy_resolver_distinguishes_heartbeat_template_boundary(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "Read files safely.\n")
    _write(
        project / "HEARTBEAT.md",
        """```markdown
# Keep this file empty to skip heartbeat API calls.
# Add tasks below when you want the agent to check something periodically.
```

## Related
- [Heartbeat config](/gateway/config-agents)
""",
    )

    resolution = HomiWorkspacePolicyResolver().resolve(
        HomiAdapter().inspect_workspace(_request(project))
    )

    assert any(
        item.code is HomiObservationCode.HEARTBEAT_TEMPLATE_DISABLED
        and item.resolution == "heartbeat_disabled_by_example_only_static_state"
        for item in resolution.observations
    )
    assert all(
        item.code is not HomiObservationCode.HEARTBEAT_ACTIVATION_PATH
        for item in resolution.observations
    )


def test_homi_policy_resolution_is_deterministic_and_missing_is_partial(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "# Policy\n")

    inspection = HomiAdapter().inspect_workspace(_request(project))
    first = HomiWorkspacePolicyResolver().resolve(inspection)
    second = HomiWorkspacePolicyResolver().resolve(inspection)

    assert first == second
    assert first.status is HomiResolutionStatus.PARTIAL
    assert first.missing_files == (
        "HEARTBEAT.md",
        "IDENTITY.md",
        "SOUL.md",
        "TOOLS.md",
        "USER.md",
    )
    assert all("Policy" not in repr(observation) for observation in first.observations)

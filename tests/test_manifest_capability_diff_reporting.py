"""P2I-03 Agent Manifest and Capability Diff Text/JSON reporting tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.manifests import (
    CapabilityDiffer,
    encode_agent_manifest_json,
    encode_capability_diff_json,
)
from agentsec.reporting import (
    CapabilityDiffJsonRenderer,
    CapabilityDiffTextLimits,
    CapabilityDiffTextRenderer,
    ManifestJsonRenderer,
    ManifestTextLimits,
    ManifestTextRenderer,
)

_SECRET_MARKER = "p2i-03-report-secret"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _analyze(project: Path):  # type: ignore[no-untyped-def]
    return AgentAnalysisPipeline().analyze(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )


def _project(tmp_path: Path, name: str, *, risky: bool) -> Path:
    project = tmp_path / name
    project.mkdir()
    _write(
        project / "AGENTS.md",
        (
            "---\ndelegates_to: [deployer]\npersists_memory: state\n---\n# Agent\n"
            if risky
            else "# Agent\n"
        ),
    )
    if risky:
        _write(
            project / ".codex" / "config.toml",
            f"""
[mcp_servers.remote]
url = "https://example.invalid/mcp?token={_SECRET_MARKER}"
enabled = true
required = true
auth = "oauth"
""".lstrip(),
        )
    else:
        _write(
            project / ".codex" / "config.toml",
            """
[mcp_servers.local]
command = "local-server"
enabled = true
default_tools_approval_mode = "prompt"
""".lstrip(),
        )
    return project


def test_manifest_json_renderer_is_the_canonical_manifest_codec(tmp_path: Path) -> None:
    analysis = _analyze(_project(tmp_path, "project", risky=True))

    rendered = ManifestJsonRenderer().render(analysis.manifest)

    assert rendered == encode_agent_manifest_json(analysis.manifest)
    assert rendered.endswith("\n")
    assert _SECRET_MARKER not in rendered
    assert "example.invalid" not in rendered


def test_manifest_text_report_contains_summary_trace_profiles_and_provenance(
    tmp_path: Path,
) -> None:
    analysis = _analyze(_project(tmp_path, "project", risky=True))

    rendered = ManifestTextRenderer().render(analysis)

    assert "AgentSec Agent Manifest" in rendered
    assert "Agent: release-agent" in rendered
    assert "Framework: Codex" in rendered
    assert "Status: COMPLETE" in rendered
    assert "Policy: static declarations; report-only; runtime not verified" in rendered
    assert "Version Vector" in rendered
    assert "Stage Trace" in rendered
    assert "Profile Resolution" in rendered
    assert "Effective Instructions" in rendered
    assert "Configuration Order" in rendered
    assert "Tools" in rendered
    assert "Permissions" in rendered
    assert "Controls" in rendered
    assert "Runtime Identities" in rendered
    assert "Relationships" in rendered
    assert "Explicit Unknowns" in rendered
    assert ".codex/config.toml" in rendered
    assert "$.mcp_servers.remote" in rendered
    assert "This report does not prove that the Agent is globally safe." in rendered
    assert _SECRET_MARKER not in rendered
    assert "example.invalid" not in rendered
    assert "\x1b" not in rendered


def test_manifest_text_report_supports_chinese_and_visible_limits(
    tmp_path: Path,
) -> None:
    analysis = _analyze(_project(tmp_path, "project", risky=True))
    renderer = ManifestTextRenderer(
        language=CapabilityRuleLanguage.ZH,
        limits=ManifestTextLimits(max_items_per_section=1),
    )

    rendered = renderer.render(analysis)

    assert "AgentSec Agent 清单" in rendered
    assert "状态：完整" in rendered
    assert "阶段轨迹" in rendered
    assert "显式 Unknown" in rendered
    assert "因展示上限省略" in rendered
    assert "不代表该 Agent 已被证明为全局安全" in rendered


def test_capability_diff_json_renderer_is_the_canonical_diff_codec(
    tmp_path: Path,
) -> None:
    before = _analyze(_project(tmp_path, "before", risky=False)).manifest
    after = _analyze(_project(tmp_path, "after", risky=True)).manifest
    diff = CapabilityDiffer().compare(before=before, after=after)

    rendered = CapabilityDiffJsonRenderer().render(diff)

    assert rendered == encode_capability_diff_json(diff)
    assert _SECRET_MARKER not in rendered
    assert "example.invalid" not in rendered


def test_capability_diff_text_report_groups_changes_and_source_provenance(
    tmp_path: Path,
) -> None:
    before = _analyze(_project(tmp_path, "before", risky=False)).manifest
    after = _analyze(_project(tmp_path, "after", risky=True)).manifest
    diff = CapabilityDiffer().compare(before=before, after=after)

    rendered = CapabilityDiffTextRenderer().render(diff)

    assert "AgentSec Capability Diff" in rendered
    assert "Status: COMPLETE" in rendered
    assert "Agent: release-agent" in rendered
    assert "Manifest schema: 0.3.0" in rendered
    assert "Summary:" in rendered
    assert "Profile Transitions" in rendered
    assert "Changes by Dimension" in rendered
    assert "[ADDED]" in rendered
    assert "tool" in rendered
    assert "mcp-server:remote" in rendered
    assert "changed_fields:" in rendered
    assert "after_source:" in rendered
    assert ".codex/config.toml" in rendered
    assert "before_sha256:" in rendered or "after_sha256:" in rendered
    assert (
        "No before/after values are included in the canonical Diff artifact."
        in rendered
    )
    assert _SECRET_MARKER not in rendered
    assert "example.invalid" not in rendered


def test_capability_diff_text_report_marks_incomplete_and_supports_chinese_limits(
    tmp_path: Path,
) -> None:
    before_project = _project(tmp_path, "before", risky=False)
    after_project = _project(tmp_path, "after", risky=True)
    (after_project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    before = _analyze(before_project).manifest
    after = _analyze(after_project).manifest
    diff = CapabilityDiffer().compare(before=before, after=after)

    rendered = CapabilityDiffTextRenderer(
        language=CapabilityRuleLanguage.ZH,
        limits=CapabilityDiffTextLimits(max_changes=1, max_profile_changes=1),
    ).render(diff)

    assert "AgentSec 能力 Diff" in rendered
    assert "状态：不完整" in rendered
    assert "警告：before 或 after 的 Coverage 不完整" in rendered
    assert "因展示上限省略" in rendered
    assert "不包含 before/after 原始值" in rendered

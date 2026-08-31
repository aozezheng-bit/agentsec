"""P2I-04 end-to-end Manifest and Capability CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import AgentAnalysisRequest
from agentsec.cli import ExitCode, app, create_app, run_cli
from agentsec.manifests import decode_agent_manifest_json
from agentsec.reporting import CapabilityAssessmentJsonReport
from agentsec.versioning import CAPABILITY_RULE_PACK_VERSION

runner = CliRunner()
_SECRET_MARKER = "p2i-04-cli-secret"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _project(tmp_path: Path, name: str, *, risky: bool = False) -> Path:
    project = tmp_path / name
    project.mkdir()
    _write(
        project / "AGENTS.md",
        (
            "---\ndelegates_to: [deployer]\npersists_memory: release_state\n---\n"
            "# Release Agent\n"
            if risky
            else "# Release Agent\n"
        ),
    )
    if risky:
        _write(
            project / ".codex" / "config.toml",
            f"""
[mcp_servers.local]
command = "local-{_SECRET_MARKER}"
enabled = true
bearer_token_env_var = "LOCAL_TOKEN"
default_tools_approval_mode = "auto"

[mcp_servers.remote]
url = "https://example.invalid/mcp?token={_SECRET_MARKER}"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "auto"
""".lstrip(),
        )
    return project


def _manifest_file(
    project: Path, output: Path, *, agent_id: str = "release-agent"
) -> None:
    result = runner.invoke(
        app,
        [
            "manifest",
            str(project),
            "--agent-id",
            agent_id,
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout == ""


def test_root_and_subcommand_help_expose_p2i04_contract() -> None:
    root = runner.invoke(app, ["--help"])
    manifest = runner.invoke(app, ["manifest", "--help"])
    capability = runner.invoke(app, ["capability", "--help"])
    assess = runner.invoke(app, ["capability", "assess", "--help"])
    diff = runner.invoke(app, ["capability", "diff", "--help"])
    impact = runner.invoke(app, ["capability", "impact", "--help"])

    assert root.exit_code == manifest.exit_code == capability.exit_code == 0
    assert assess.exit_code == diff.exit_code == impact.exit_code == 0
    assert "manifest" in root.stdout
    assert "capability" in root.stdout
    assert "runtime capability is not verified" in manifest.stdout
    for option in (
        "--working-directory",
        "--user-home",
        "--codex-home",
        "--agent-id",
        "--format",
        "--language",
        "--output",
        "--force",
    ):
        assert option in manifest.stdout
        assert option in assess.stdout
    assert "--before" in diff.stdout
    assert "--after" in diff.stdout
    assert "without exposing raw before/after values" in diff.stdout
    assert "semantic before/after state" in impact.stdout


def test_manifest_cli_emits_canonical_json_and_chinese_text(tmp_path: Path) -> None:
    project = _project(tmp_path, "project", risky=True)

    json_result = runner.invoke(
        app,
        ["manifest", str(project), "--agent-id", "release-agent", "--format", "json"],
    )
    chinese = runner.invoke(
        app,
        [
            "manifest",
            str(project),
            "--agent-id",
            "release-agent",
            "--language",
            "zh",
        ],
    )

    assert json_result.exit_code == chinese.exit_code == ExitCode.SUCCESS
    manifest = decode_agent_manifest_json(json_result.stdout)
    assert manifest.identity.agent_id == "release-agent"
    assert manifest.schema_version == "0.3.0"
    assert "AgentSec Agent 清单" in chinese.stdout
    assert "状态：完整" in chinese.stdout
    assert _SECRET_MARKER not in json_result.stdout
    assert _SECRET_MARKER not in chinese.stdout
    assert "example.invalid" not in json_result.stdout
    assert "example.invalid" not in chinese.stdout


def test_manifest_cli_writes_valid_artifact_and_requires_safe_force(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path, "project")
    output = tmp_path / "artifacts" / "manifest.json"
    arguments = [
        "manifest",
        str(project),
        "--agent-id",
        "release-agent",
        "--format",
        "json",
        "--output",
        str(output),
    ]

    created = runner.invoke(app, arguments)
    existing = runner.invoke(app, arguments)
    forced = runner.invoke(app, [*arguments, "--force"])

    assert created.exit_code == 0
    assert created.stdout == created.stderr == ""
    assert decode_agent_manifest_json(output.read_text(encoding="utf-8"))
    assert existing.exit_code == ExitCode.ARTIFACT_ERROR
    assert existing.stdout == ""
    assert "already exists" in existing.stderr
    assert forced.exit_code == 0
    assert forced.stdout == forced.stderr == ""


def test_manifest_cli_returns_incomplete_and_safe_required_failure(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path, "incomplete")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")

    incomplete = runner.invoke(
        app,
        ["manifest", str(project), "--agent-id", "release-agent", "--format", "json"],
    )

    assert incomplete.exit_code == ExitCode.SCAN_INCOMPLETE
    assert decode_agent_manifest_json(incomplete.stdout).coverage.complete is False

    class CrashingAnalysisEngine:
        def analyze(self, request: AgentAnalysisRequest):  # type: ignore[no-untyped-def]
            del request
            raise RuntimeError(f"unsafe dependency error: {_SECRET_MARKER}")

    application = create_app(agent_analysis_engine=CrashingAnalysisEngine())
    failed = runner.invoke(application, ["manifest", str(project)])

    assert failed.exit_code == ExitCode.REQUIRED_ANALYSIS_FAILED
    assert failed.stdout == ""
    assert "failed safely" in failed.stderr
    assert _SECRET_MARKER not in failed.stderr


def test_capability_assess_cli_outputs_report_only_json_and_chinese_text(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path, "risky", risky=True)

    machine = runner.invoke(
        app,
        [
            "capability",
            "assess",
            str(project),
            "--agent-id",
            "release-agent",
            "--format",
            "json",
        ],
    )
    chinese = runner.invoke(
        app,
        [
            "capability",
            "assess",
            str(project),
            "--agent-id",
            "release-agent",
            "--language",
            "zh",
        ],
    )

    assert machine.exit_code == chinese.exit_code == ExitCode.SUCCESS
    report = CapabilityAssessmentJsonReport.model_validate_json(machine.stdout)
    assert report.status == "complete"
    assert report.summary.findings > 0
    assert report.policy.enforcement_mode == "report_only"
    assert report.policy.ci_blocking_enabled is False
    assert report.policy.runtime_capability_verified is False
    assert "AgentSec 能力评估" in chinese.stdout
    assert "最高严重性：高" in chinese.stdout
    assert _SECRET_MARKER not in machine.stdout
    assert "example.invalid" not in machine.stdout


def test_capability_assess_output_file_and_incomplete_exit(tmp_path: Path) -> None:
    project = _project(tmp_path, "project")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    output = tmp_path / "assessment.json"

    result = runner.invoke(
        app,
        [
            "capability",
            "assess",
            str(project),
            "--agent-id",
            "release-agent",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    assert result.stdout == result.stderr == ""
    report = CapabilityAssessmentJsonReport.model_validate_json(
        output.read_text(encoding="utf-8")
    )
    assert report.status == "incomplete"
    assert report.summary.manifest_coverage_complete is False


def test_capability_diff_cli_compares_validated_manifests_in_text_and_json(
    tmp_path: Path,
) -> None:
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after", risky=True)
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _manifest_file(before_project, before)
    _manifest_file(after_project, after)

    machine = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "json",
        ],
    )
    chinese = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--language",
            "zh",
        ],
    )

    payload = json.loads(machine.stdout)
    assert machine.exit_code == chinese.exit_code == ExitCode.SUCCESS
    assert payload["schema_version"] == "0.1.0"
    assert payload["added_count"] > 0
    assert payload["complete"] is True
    assert "AgentSec 能力 Diff" in chinese.stdout
    assert "按维度分组的变化" in chinese.stdout
    assert _SECRET_MARKER not in machine.stdout
    assert "example.invalid" not in machine.stdout


def test_capability_diff_rejects_missing_invalid_mismatched_and_protected_output(
    tmp_path: Path,
) -> None:
    first_project = _project(tmp_path, "first")
    second_project = _project(tmp_path, "second")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _manifest_file(first_project, first, agent_id="first-agent")
    _manifest_file(second_project, second, agent_id="second-agent")

    missing = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(tmp_path / "missing.json"),
            "--after",
            str(second),
        ],
    )
    mismatch = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(first),
            "--after",
            str(second),
        ],
    )
    protected = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(first),
            "--after",
            str(first),
            "--format",
            "json",
            "--output",
            str(first),
            "--force",
        ],
    )

    assert missing.exit_code == ExitCode.ARTIFACT_ERROR
    assert mismatch.exit_code == ExitCode.ARTIFACT_ERROR
    assert protected.exit_code == ExitCode.ARTIFACT_ERROR
    assert missing.stdout == mismatch.stdout == protected.stdout == ""
    assert "does not exist" in missing.stderr
    assert "same Agent identity" in mismatch.stderr
    assert "must not replace an input artifact" in protected.stderr


def test_capability_diff_incomplete_returns_code_2_and_writes_json(
    tmp_path: Path,
) -> None:
    before_project = _project(tmp_path, "before")
    after_project = _project(tmp_path, "after")
    (after_project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "diff.json"
    _manifest_file(before_project, before)
    incomplete_manifest = runner.invoke(
        app,
        [
            "manifest",
            str(after_project),
            "--agent-id",
            "release-agent",
            "--format",
            "json",
            "--output",
            str(after),
        ],
    )
    assert incomplete_manifest.exit_code == ExitCode.SCAN_INCOMPLETE

    result = runner.invoke(
        app,
        [
            "capability",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    assert result.stdout == result.stderr == ""
    assert json.loads(output.read_text(encoding="utf-8"))["complete"] is False


def test_capability_rules_list_is_bilingual_and_installed_runner_compatible(
    capsys: pytest.CaptureFixture[str],
) -> None:
    english = runner.invoke(app, ["capability", "rules", "list"])
    chinese = runner.invoke(
        app,
        ["capability", "rules", "list", "--language", "zh"],
    )

    assert english.exit_code == chinese.exit_code == 0
    assert f"Capability Rule Pack {CAPABILITY_RULE_PACK_VERSION}" in english.stdout
    assert "CAP-CHAIN-001" in english.stdout
    assert "能力规则包" in chinese.stdout
    assert "代码执行、Secret 访问与外部网络" in chinese.stdout

    assert run_cli(["capability", "rules", "list"]) == 0
    captured = capsys.readouterr()
    assert "Capability Rule Pack" in captured.out
    assert captured.err == ""

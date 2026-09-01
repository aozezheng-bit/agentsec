"""End-to-end CLI tests for safe Text and JSON project Diff output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import CollectionProjectDiffEngine
from agentsec.cli import ExitCode, app, create_app, run_cli
from agentsec.collectors import MarkdownAssetCollector
from agentsec.diffing import DeterministicTextDiffer, TextDiffLimits
from agentsec.versioning import CONFIG_SCHEMA_VERSION

runner = CliRunner()


def create_baseline(
    project_root: Path,
    *,
    output: Path | None = None,
    config: Path | None = None,
) -> Path:
    """Create a real Baseline through the production CLI."""

    arguments = ["baseline", "create", str(project_root)]
    if output is not None:
        arguments.extend(("--output", str(output)))
    if config is not None:
        arguments.extend(("--config", str(config)))
    result = runner.invoke(app, arguments)
    assert result.exit_code == 0, result.stderr
    return output if output is not None else project_root / ".agentsec/baseline.json"


def test_root_and_diff_help_expose_options() -> None:
    """The command is discoverable with Baseline, config, and format controls."""

    root = runner.invoke(app, ["--help"])
    diff = runner.invoke(app, ["diff", "--help"])

    assert root.exit_code == 0
    assert "diff" in root.stdout
    assert diff.exit_code == 0
    assert "--baseline" in diff.stdout
    assert "--config" in diff.stdout
    assert "--format" in diff.stdout
    assert "text" in diff.stdout
    assert "json" in diff.stdout


def test_diff_uses_default_baseline_and_reports_no_changes(tmp_path: Path) -> None:
    """The conventional `.agentsec/baseline.json` path needs no explicit option."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("same\n", encoding="utf-8")
    create_baseline(project)

    result = runner.invoke(app, ["diff", str(project)])

    assert result.exit_code == 0
    assert "Changes: 0" in result.stdout
    assert "No asset changes." in result.stdout
    assert "Collection scope: match" in result.stdout
    assert result.stderr == ""


def test_complete_modified_diff_returns_zero_and_line_evidence(tmp_path: Path) -> None:
    """Textual drift is visible but does not become a risk-policy failure."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("before\n", encoding="utf-8")
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    (project / "AGENTS.md").write_text("after\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["diff", str(project), "--baseline", str(baseline)],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "[modified] AGENTS.md" in result.stdout
    assert "before\\n" in result.stdout
    assert "after\\n" in result.stdout
    assert "Text evidence: complete" in result.stdout


def test_json_output_is_valid_and_contains_file_and_line_diff(tmp_path: Path) -> None:
    """`--format json` emits one deterministic machine-readable document."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("before\n", encoding="utf-8")
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    (project / "AGENTS.md").write_text("after\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "diff",
            str(project),
            "--baseline",
            str(baseline),
            "--format",
            "json",
        ],
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert result.stderr == ""
    assert payload["format"] == "agentsec-diff"
    assert payload["format_version"] == "0.1.0"
    assert payload["summary"]["modified"] == 1
    assert payload["changes"][0]["path"] == "AGENTS.md"
    assert payload["changes"][0]["text_diff"]["hunks"][0]["lines"] == [
        {
            "after_line_number": None,
            "before_line_number": 1,
            "kind": "removed",
            "original_character_count": 7,
            "text": "before\\n",
            "truncated": False,
        },
        {
            "after_line_number": 1,
            "before_line_number": None,
            "kind": "added",
            "original_character_count": 6,
            "text": "after\\n",
            "truncated": False,
        },
    ]


def test_configured_json_format_and_cli_text_override(tmp_path: Path) -> None:
    """CLI format overrides config; otherwise the validated project config wins."""

    project = tmp_path / "project"
    config_directory = project / ".agentsec"
    config_directory.mkdir(parents=True)
    config_path = config_directory / "config.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
output:
  format: json
  redact_secrets: true
''',
        encoding="utf-8",
    )
    (project / "AGENTS.md").write_text("same\n", encoding="utf-8")
    create_baseline(project)

    configured = runner.invoke(app, ["diff", str(project)])
    overridden = runner.invoke(app, ["diff", str(project), "--format", "text"])

    assert configured.exit_code == 0
    assert json.loads(configured.stdout)["format"] == "agentsec-diff"
    assert overridden.exit_code == 0
    assert overridden.stdout.startswith("AgentSec Diff\n")


def test_missing_baseline_returns_code_4_in_text_and_json(tmp_path: Path) -> None:
    """Baseline failures remain automation-distinguishable in either format."""

    missing = tmp_path / "missing.json"
    text_result = runner.invoke(
        app,
        ["diff", str(tmp_path), "--baseline", str(missing)],
    )
    json_result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--baseline",
            str(missing),
            "--format",
            "json",
        ],
    )

    assert text_result.exit_code == ExitCode.BASELINE_ERROR
    assert text_result.stdout == ""
    assert "baseline_failed" in text_result.stderr
    assert json_result.exit_code == ExitCode.BASELINE_ERROR
    assert json_result.stderr == ""
    payload = json.loads(json_result.stdout)
    assert payload["status"] == "error"
    assert payload["error"]["code"] == "baseline_failed"
    assert payload["error"]["exit_code"] == 4


def test_invalid_baseline_does_not_leak_rejected_values(tmp_path: Path) -> None:
    """Malformed Baseline content remains behind a generic exit-code-4 error."""

    baseline = tmp_path / "baseline.json"
    secret = "invalid-baseline-secret-marker"
    baseline.write_text(
        f'{{"schema_version":"0.1.0","secret":"{secret}"}}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["diff", str(tmp_path), "--baseline", str(baseline)],
    )

    assert result.exit_code == ExitCode.BASELINE_ERROR
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_baseline_symlink_is_rejected(tmp_path: Path) -> None:
    """Diff never follows a final Baseline symlink."""

    target = tmp_path / "target.json"
    target.write_text("not relevant\n", encoding="utf-8")
    link = tmp_path / "baseline.json"
    link.symlink_to(target)

    result = runner.invoke(
        app,
        ["diff", str(tmp_path), "--baseline", str(link)],
    )

    assert result.exit_code == ExitCode.BASELINE_ERROR
    assert target.read_text(encoding="utf-8") == "not relevant\n"


def test_incomplete_current_collection_returns_code_2_not_removed(
    tmp_path: Path,
) -> None:
    """Invalid current UTF-8 remains coverage failure, never deletion evidence."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("before\n", encoding="utf-8")
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    (project / "AGENTS.md").write_bytes(b"\xff")

    result = runner.invoke(
        app,
        ["diff", str(project), "--baseline", str(baseline)],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    assert result.stdout == ""
    assert "incomplete_current_coverage" in result.stderr
    assert "skipped=1" in result.stderr
    assert "[removed]" not in result.stderr


def test_scope_mismatch_renders_result_but_returns_code_4(tmp_path: Path) -> None:
    """A changed collection scope is visible and makes comparison non-successful."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("same\n", encoding="utf-8")
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    config = tmp_path / "different.yaml"
    config.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
limits:
  max_depth: 19
''',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "diff",
            str(project),
            "--baseline",
            str(baseline),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == ExitCode.BASELINE_ERROR
    assert "Collection scope: MISMATCH" in result.stdout
    assert "WARNING" in result.stdout
    assert "Changes: 0" in result.stdout


def test_text_truncation_renders_partial_result_and_returns_code_2(
    tmp_path: Path,
) -> None:
    """Visible line-evidence truncation maps to incomplete analysis, not success."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("abcdefgh\n", encoding="utf-8")
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    (project / "AGENTS.md").write_text("abcdXfgh\n", encoding="utf-8")
    application = create_app(
        diff_engine=CollectionProjectDiffEngine(
            MarkdownAssetCollector(),
            text_differ=DeterministicTextDiffer(
                TextDiffLimits(max_characters_per_line=5)
            ),
        )
    )

    result = runner.invoke(
        application,
        ["diff", str(project), "--baseline", str(baseline)],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    assert "Text evidence: INCOMPLETE" in result.stdout
    assert "text_status: truncated" in result.stdout
    assert "truncated from 9 chars" in result.stdout


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_diff_redacts_secrets_and_escapes_controls(
    tmp_path: Path,
    output_format: str,
) -> None:
    """Neither output format exposes credential values or active ANSI controls."""

    project = tmp_path / "project"
    project.mkdir()
    secret_before = "agentsec-test-before-secret"
    secret_after = "agentsec-test-after-secret"
    (project / "AGENTS.md").write_text(
        f"token: {secret_before}\n",
        encoding="utf-8",
    )
    baseline = create_baseline(project, output=tmp_path / "baseline.json")
    (project / "AGENTS.md").write_text(
        f"token: {secret_after}\x1b[31m\u200b\u202e\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "diff",
            str(project),
            "--baseline",
            str(baseline),
            "--format",
            output_format,
        ],
    )

    assert result.exit_code == 0
    assert secret_before not in result.stdout
    assert secret_after not in result.stdout
    assert "\x1b" not in result.stdout
    assert "\u200b" not in result.stdout
    assert "\u202e" not in result.stdout
    assert "<redacted>" in result.stdout


def test_invalid_config_can_return_structured_json_error(tmp_path: Path) -> None:
    """Explicit JSON automation gets valid output even before config loads."""

    config = tmp_path / "invalid.yaml"
    config.write_text("output:\n  format: json\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--config",
            str(config),
            "--format",
            "json",
        ],
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert result.stderr == ""
    assert payload["error"]["code"] == "configuration_error"
    assert payload["error"]["exit_code"] == 3


def test_run_cli_returns_stable_diff_baseline_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Installed entry-point automation preserves Baseline exit code 4."""

    exit_code = run_cli(
        [
            "diff",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "missing.json"),
        ]
    )

    assert exit_code == ExitCode.BASELINE_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "baseline_failed" in captured.err

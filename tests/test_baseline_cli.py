"""End-to-end CLI tests for explicit trusted baseline creation."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import CollectionBaselineCreator
from agentsec.baselines import (
    DEFAULT_BASELINE_RELATIVE_PATH,
    GitProvenance,
    decode_baseline_json,
    fingerprint_collection_config,
)
from agentsec.cli import ExitCode, app, create_app, run_cli
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import CONFIG_SCHEMA_VERSION, load_project_config
from agentsec.parsers import ParsedMarkdown

runner = CliRunner()


class NoGitProvenanceProvider:
    """Keep parser-boundary CLI tests independent from the host Git state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        return GitProvenance(commit=None, dirty=None)


def test_root_and_baseline_help_expose_create_command() -> None:
    """The new command is discoverable without changing root invocation behavior."""

    root_result = runner.invoke(app, ["--help"])
    baseline_result = runner.invoke(app, ["baseline", "--help"])
    create_result = runner.invoke(app, ["baseline", "create", "--help"])

    assert root_result.exit_code == 0
    assert "baseline" in root_result.stdout
    assert baseline_result.exit_code == 0
    assert "create" in baseline_result.stdout
    assert create_result.exit_code == 0
    assert "--output" in create_result.stdout
    assert "--config" in create_result.stdout
    assert "--force" in create_result.stdout


def test_default_baseline_create_writes_private_valid_json(tmp_path: Path) -> None:
    """The production CLI writes the documented default file without leaking content."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    secret_marker = "baseline-cli-secret-marker"
    content = f"# Agent\n\n{secret_marker}\n"
    (project_root / "AGENTS.md").write_text(content, encoding="utf-8")

    result = runner.invoke(app, ["baseline", "create", str(project_root)])

    output = project_root / DEFAULT_BASELINE_RELATIVE_PATH
    assert result.exit_code == 0
    assert "Baseline created: 1 asset(s)" in result.stdout
    assert secret_marker not in result.stdout
    assert result.stderr == ""
    assert output.is_file()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    baseline = decode_baseline_json(output.read_text(encoding="utf-8"))
    assert baseline.assets[0].content == content
    assert baseline.metadata.git_commit is None
    assert baseline.metadata.git_dirty is None


def test_baseline_create_supports_explicit_output_outside_project(
    tmp_path: Path,
) -> None:
    """The documented demo layout may store snapshots beside the scanned root."""

    project_root = tmp_path / "baseline"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    output = tmp_path / "expected" / "baseline.json"

    result = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(project_root),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.is_file()
    assert str(output.resolve()) in result.stdout


def test_baseline_create_uses_effective_collection_config(tmp_path: Path) -> None:
    """Explicit discovery and limits are captured by the baseline fingerprint."""

    project_root = tmp_path / "project"
    (project_root / "docs").mkdir(parents=True)
    (project_root / "AGENTS.md").write_text("not selected\n", encoding="utf-8")
    (project_root / "docs" / "RUNBOOK.md").write_text("selected\n", encoding="utf-8")
    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
discovery:
  include:
    - "docs/**/*.md"
  exclude: []
limits:
  max_depth: 12
''',
        encoding="utf-8",
    )
    output = tmp_path / "baseline.json"

    result = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(project_root),
            "--config",
            str(config_path),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    baseline = decode_baseline_json(output.read_text(encoding="utf-8"))
    assert [asset.path for asset in baseline.assets] == ["docs/RUNBOOK.md"]
    loaded = load_project_config(project_root, config_path=config_path)
    assert baseline.metadata.collection_config_sha256 == fingerprint_collection_config(
        loaded.config
    )


def test_invalid_configuration_returns_code_3_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """Configuration validation remains distinct from baseline failures."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("limits:\n  max_depth: 4\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(project_root),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "Configuration error" in result.stderr
    assert not (project_root / DEFAULT_BASELINE_RELATIVE_PATH).exists()


def test_incomplete_coverage_returns_code_4_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """Malformed selected assets fail closed rather than creating partial trust."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_bytes(b"\xff")
    output = tmp_path / "baseline.json"

    result = runner.invoke(
        app,
        ["baseline", "create", str(project_root), "--output", str(output)],
    )

    assert result.exit_code == ExitCode.BASELINE_ERROR
    assert result.stdout == ""
    assert "requires complete scan coverage" in result.stderr
    assert not output.exists()


def test_existing_baseline_requires_force_and_force_replaces_it(
    tmp_path: Path,
) -> None:
    """Regeneration is a visible explicit action, never an implicit update."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    asset_path = project_root / "AGENTS.md"
    asset_path.write_text("old\n", encoding="utf-8")
    output = tmp_path / "baseline.json"
    arguments = [
        "baseline",
        "create",
        str(project_root),
        "--output",
        str(output),
    ]
    first = runner.invoke(app, arguments)
    first_bytes = output.read_bytes()
    asset_path.write_text("new\n", encoding="utf-8")

    without_force = runner.invoke(app, arguments)
    with_force = runner.invoke(app, [*arguments, "--force"])

    assert first.exit_code == 0
    assert without_force.exit_code == ExitCode.BASELINE_ERROR
    assert "already exists" in without_force.stderr
    assert with_force.exit_code == 0
    assert "Baseline replaced" in with_force.stdout
    assert output.read_bytes() != first_bytes
    baseline = decode_baseline_json(output.read_text(encoding="utf-8"))
    assert baseline.assets[0].content == "new\n"


def test_force_cannot_overwrite_unrelated_or_input_files(tmp_path: Path) -> None:
    """The CLI cannot turn baseline output into arbitrary destructive writing."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    asset_path = project_root / "AGENTS.md"
    asset_path.write_text("original-agent\n", encoding="utf-8")
    unrelated = tmp_path / "important.json"
    unrelated.write_text("original-important\n", encoding="utf-8")

    unrelated_result = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(project_root),
            "--output",
            str(unrelated),
            "--force",
        ],
    )
    asset_result = runner.invoke(
        app,
        [
            "baseline",
            "create",
            str(project_root),
            "--output",
            str(asset_path),
            "--force",
        ],
    )

    assert unrelated_result.exit_code == ExitCode.BASELINE_ERROR
    assert asset_result.exit_code == ExitCode.BASELINE_ERROR
    assert unrelated.read_text(encoding="utf-8") == "original-important\n"
    assert asset_path.read_text(encoding="utf-8") == "original-agent\n"


def test_parser_failure_is_safe_and_does_not_write(tmp_path: Path) -> None:
    """Parser exceptions never expose source text through baseline CLI errors."""

    class FailingParser:
        def parse(self, content: str) -> ParsedMarkdown:
            raise RuntimeError(f"must-not-leak: {content}")

    project_root = tmp_path / "project"
    project_root.mkdir()
    secret_marker = "baseline-parser-cli-secret"
    (project_root / "AGENTS.md").write_text(secret_marker, encoding="utf-8")
    output = tmp_path / "baseline.json"
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        parser=FailingParser(),
        provenance_provider=NoGitProvenanceProvider(),
    )
    application = create_app(baseline_creator=creator)

    result = runner.invoke(
        application,
        ["baseline", "create", str(project_root), "--output", str(output)],
    )

    assert result.exit_code == ExitCode.BASELINE_ERROR
    assert secret_marker not in result.stdout
    assert secret_marker not in result.stderr
    assert not output.exists()


def test_run_cli_returns_stable_baseline_error_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Installed automation receives reserved exit code 4 for output failures."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    output = tmp_path / "not-a-baseline.txt"
    output.write_text("keep\n", encoding="utf-8")

    exit_code = run_cli(
        [
            "baseline",
            "create",
            str(project_root),
            "--output",
            str(output),
            "--force",
        ]
    )

    assert exit_code == ExitCode.BASELINE_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Baseline error" in captured.err
    assert output.read_text(encoding="utf-8") == "keep\n"

"""Tests for the Phase 1 scan command skeleton and engine seam."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from agentsec.application import (
    AssessmentRequest,
    CollectionAssessmentEngine,
    UnavailableAssessmentEngine,
)
from agentsec.cli import app, create_app
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import CONFIG_SCHEMA_VERSION, default_project_config
from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
    CoverageIssue,
    CoverageIssueCode,
    ScanCoverage,
)
from agentsec.parsers import ParsedMarkdown
from agentsec.versioning import current_versions

runner = CliRunner()


class RecordingAssessmentEngine:
    """Test adapter that records the request and returns an empty assessment."""

    def __init__(self) -> None:
        self.request: AssessmentRequest | None = None

    def assess(self, request: AssessmentRequest) -> Assessment:
        """Record the request without reading the requested project path."""

        self.request = request
        versions = current_versions()
        timestamp = datetime(2026, 8, 18, 8, 30, tzinfo=UTC)
        return Assessment(
            metadata=AssessmentMetadata(
                schema_version=versions.domain_schema,
                scanner_version=versions.package,
                config_schema_version=versions.config_schema,
                rule_pack_version=versions.rule_pack,
                risk_model_version=versions.risk_model,
                target_root=str(request.project_root),
                started_at=timestamp,
                completed_at=timestamp,
            ),
            coverage=ScanCoverage(
                discovered_assets=0,
                scanned_assets=0,
                skipped_assets=0,
                complete=True,
            ),
        )


class IncompleteAssessmentEngine:
    """Test adapter returning a visible coverage failure."""

    def assess(self, request: AssessmentRequest) -> Assessment:
        """Return an incomplete assessment without touching the target."""

        versions = current_versions()
        timestamp = datetime(2026, 8, 18, 8, 31, tzinfo=UTC)
        return Assessment(
            metadata=AssessmentMetadata(
                schema_version=versions.domain_schema,
                scanner_version=versions.package,
                config_schema_version=versions.config_schema,
                rule_pack_version=versions.rule_pack,
                risk_model_version=versions.risk_model,
                target_root=str(request.project_root),
                started_at=timestamp,
                completed_at=timestamp,
            ),
            coverage=ScanCoverage(
                discovered_assets=1,
                scanned_assets=0,
                skipped_assets=1,
                complete=False,
                issues=(
                    CoverageIssue(
                        code=CoverageIssueCode.UNREADABLE,
                        message="Permission denied.",
                        asset_path="AGENTS.md",
                    ),
                ),
            ),
        )


def test_scan_help_documents_the_optional_project_root() -> None:
    """The command advertises its stable Phase 1 positional input."""

    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "Scan a project for Agent security findings" in result.stdout
    assert "project_root" in result.stdout.lower()
    assert "--config" in result.stdout


def test_unavailable_engine_remains_an_explicit_failure_adapter() -> None:
    """Reserved analysis-failure behavior remains injectable for later stages."""

    application = create_app(UnavailableAssessmentEngine())
    result = runner.invoke(
        application,
        ["scan", "a-project-that-does-not-exist"],
    )

    assert result.exit_code == 5
    assert result.stdout == ""
    assert "Scan unavailable" in result.stderr
    assert "assessment engine is not implemented yet" in result.stderr
    assert "a-project-that-does-not-exist" in result.stderr


def test_incomplete_assessment_returns_the_documented_exit_code() -> None:
    """Coverage failure is distinguishable from configuration and engine errors."""

    application = create_app(IncompleteAssessmentEngine())

    result = runner.invoke(application, ["scan", "example-project"])

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout


def test_scan_defaults_to_the_current_directory() -> None:
    """Omitting the project root creates a request for the current directory."""

    engine = RecordingAssessmentEngine()
    application = create_app(engine)

    result = runner.invoke(application, ["scan"])

    assert result.exit_code == 0
    assert engine.request == AssessmentRequest(
        project_root=Path("."),
        config=default_project_config(),
        config_path=None,
    )
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  0" in result.stdout
    assert "Findings  0" in result.stdout
    assert "does not prove that the Agent is globally safe" in result.stdout


def test_scan_passes_the_requested_path_to_the_engine() -> None:
    """The CLI performs argument parsing but delegates assessment behavior."""

    engine = RecordingAssessmentEngine()
    application = create_app(engine)

    result = runner.invoke(application, ["scan", "examples/release-agent"])

    assert result.exit_code == 0
    assert engine.request == AssessmentRequest(
        project_root=Path("examples/release-agent"),
        config=default_project_config(),
        config_path=None,
    )


def test_scan_loads_an_explicit_configuration(tmp_path: Path) -> None:
    """The CLI passes validated config and provenance to the engine."""

    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f"""
version: "{CONFIG_SCHEMA_VERSION}"
limits:
  max_depth: 11
""".lstrip(),
        encoding="utf-8",
    )
    engine = RecordingAssessmentEngine()
    application = create_app(engine)

    result = runner.invoke(
        application,
        ["scan", "example-project", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert engine.request is not None
    assert engine.request.config.limits.max_depth == 11
    assert engine.request.config_path == config_path


def test_scan_rejects_invalid_configuration_before_calling_engine(
    tmp_path: Path,
) -> None:
    """Invalid config fails closed and never reaches assessment behavior."""

    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text("output:\n  redact_secrets: false\n", encoding="utf-8")
    engine = RecordingAssessmentEngine()
    application = create_app(engine)

    result = runner.invoke(
        application,
        ["scan", "example-project", "--config", str(config_path)],
    )

    assert result.exit_code == 3
    assert engine.request is None
    assert "Configuration error" in result.stderr
    assert "requires a version" in result.stderr


def test_default_scan_collects_the_safe_fixture() -> None:
    """The production CLI now uses the concrete Markdown collector."""

    fixture_root = Path(__file__).parents[1] / "testdata" / "safe" / "minimal-agent"

    result = runner.invoke(app, ["scan", str(fixture_root)])

    assert result.exit_code == 0
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "discovered=1 scanned=1 skipped=0 issues=0" in result.stdout


def test_default_scan_reports_invalid_utf8_as_incomplete() -> None:
    """Malformed asset encoding is a coverage exit, not an engine crash."""

    fixture_root = Path(__file__).parents[1] / "testdata" / "malformed" / "invalid-utf8"

    result = runner.invoke(app, ["scan", str(fixture_root)])

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  0" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout


def test_default_scan_applies_explicit_discovery_patterns(tmp_path: Path) -> None:
    """The production CLI honors configured includes and exclude precedence."""

    project_root = tmp_path / "project"
    (project_root / "docs" / "private").mkdir(parents=True)
    (project_root / "AGENTS.md").write_text("not included\n", encoding="utf-8")
    (project_root / "docs" / "RUNBOOK.md").write_text(
        "included\n",
        encoding="utf-8",
    )
    (project_root / "docs" / "private" / "HIDDEN.md").write_text(
        "excluded\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
discovery:
  include:
    - "docs/**/*.md"
  exclude:
    - "docs/private/**"
''',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", str(project_root), "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "discovered=1 scanned=1 skipped=0 issues=0" in result.stdout


def test_default_scan_accepts_contained_file_symlink(tmp_path: Path) -> None:
    """The production CLI follows an internal link after containment validation."""

    project_root = tmp_path / "project"
    target_directory = project_root / "targets"
    target_directory.mkdir(parents=True)
    target = target_directory / "instructions.md"
    target.write_text("internal\n", encoding="utf-8")
    (project_root / "AGENTS.md").symlink_to(target)

    result = runner.invoke(app, ["scan", str(project_root)])

    assert result.exit_code == 0
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "discovered=1 scanned=1 skipped=0 issues=0" in result.stdout


def test_default_scan_rejects_external_file_symlink(tmp_path: Path) -> None:
    """An escaping link produces incomplete coverage rather than reading outside."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    outside_file = tmp_path / "outside.md"
    outside_file.write_text("outside\n", encoding="utf-8")
    (project_root / "AGENTS.md").symlink_to(outside_file)

    result = runner.invoke(app, ["scan", str(project_root)])

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  0" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout
    assert str(outside_file) not in result.stdout
    assert str(outside_file) not in result.stderr


def test_default_scan_enforces_file_size_limit(tmp_path: Path) -> None:
    """An oversized selected file produces incomplete CLI coverage."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_bytes(b"12345")
    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
limits:
  max_file_size_bytes: 4
''',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", str(project_root), "--config", str(config_path)],
    )

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  0" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout


def test_default_scan_enforces_depth_limit(tmp_path: Path) -> None:
    """A directory below the configured logical depth is not traversed."""

    project_root = tmp_path / "project"
    deep_directory = project_root / "one" / "two"
    deep_directory.mkdir(parents=True)
    (deep_directory / "AGENTS.md").write_text("too deep\n", encoding="utf-8")
    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
limits:
  max_depth: 1
''',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", str(project_root), "--config", str(config_path)],
    )

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  0" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout


def test_default_scan_enforces_asset_count_limit(tmp_path: Path) -> None:
    """The production CLI stops after the configured number of selected assets."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "a.md").write_text("a\n", encoding="utf-8")
    (project_root / "b.md").write_text("b\n", encoding="utf-8")
    config_path = tmp_path / "agentsec.yaml"
    config_path.write_text(
        f'''version: "{CONFIG_SCHEMA_VERSION}"
discovery:
  include:
    - "**/*.md"
  exclude: []
limits:
  max_assets: 1
''',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", str(project_root), "--config", str(config_path)],
    )

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout


def test_scan_maps_parser_failure_to_incomplete_coverage_without_leaking_content(
    tmp_path: Path,
) -> None:
    """The CLI contains parser failures and preserves the asset metadata count."""

    class AlwaysFailingParser:
        def parse(self, content: str) -> ParsedMarkdown:
            raise RuntimeError(f"must-not-leak: {content}")

    secret_source = "parser-secret-marker"
    (tmp_path / "AGENTS.md").write_text(secret_source, encoding="utf-8")
    application = create_app(
        CollectionAssessmentEngine(
            MarkdownAssetCollector(),
            parser=AlwaysFailingParser(),
        )
    )

    result = runner.invoke(application, ["scan", str(tmp_path)])

    assert result.exit_code == 2
    assert "Status  INCOMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "Scan coverage is incomplete" in result.stdout
    assert secret_source not in result.stdout
    assert secret_source not in result.stderr


def test_default_scan_recovers_unclosed_frontmatter_without_parse_failure() -> None:
    """Malformed frontmatter remains analyzable content rather than lost coverage."""

    fixture_root = (
        Path(__file__).parents[1] / "testdata" / "malformed" / "unclosed-frontmatter"
    )

    result = runner.invoke(app, ["scan", str(fixture_root)])

    assert result.exit_code == 0
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  0" in result.stdout
    assert "discovered=1 scanned=1 skipped=0 issues=0" in result.stdout


def test_obfuscation_indicators_create_source_backed_rule_findings() -> None:
    """Parser indicators feed the production obfuscation Rule without execution."""

    fixture_root = (
        Path(__file__).parents[1] / "testdata" / "risky" / "obfuscated-instructions"
    )

    result = runner.invoke(app, ["scan", str(fixture_root)])

    assert result.exit_code == 0
    assert "Status  COMPLETE" in result.stdout
    assert "Assets  1" in result.stdout
    assert "Findings  3" in result.stdout
    assert result.stdout.count("MD-OBFUSC-001") == 3
    assert "discovered=1 scanned=1 skipped=0 issues=0" in result.stdout


def test_default_scan_json_runs_the_complete_finding_pipeline() -> None:
    """The production scan CLI emits schema-valid final Findings as JSON."""

    import json

    from agentsec.reporting import AssessmentJsonReport

    fixture_root = (
        Path(__file__).parents[1] / "testdata" / "risky" / "shell-secret-network"
    )

    result = runner.invoke(app, ["scan", str(fixture_root), "--format", "json"])

    assert result.exit_code == 0
    report = AssessmentJsonReport.model_validate_json(result.stdout)
    payload = json.loads(result.stdout)
    assert report.status == "complete"
    assert [item["rule_id"] for item in payload["assessment"]["findings"]] == [
        "MD-EXEC-001",
        "MD-SECRET-001",
        "MD-APPROVAL-001",
        "MD-NET-001",
    ]
    assert payload["policy"]["enforcement_mode"] == "report_only"
    assert payload["policy"]["ci_blocking_enabled"] is False

"""Tests for stable CLI process outcomes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.cli import ExitCode, exit_code_for_assessment, run_cli
from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
    CoverageIssue,
    CoverageIssueCode,
    ScanCoverage,
)
from agentsec.versioning import current_versions


def make_assessment(*, complete: bool) -> Assessment:
    """Create an assessment with internally consistent coverage."""

    versions = current_versions()
    timestamp = datetime(2026, 8, 18, 8, 40, tzinfo=UTC)
    if complete:
        coverage = ScanCoverage(
            discovered_assets=0,
            scanned_assets=0,
            skipped_assets=0,
            complete=True,
        )
    else:
        coverage = ScanCoverage(
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
        )

    return Assessment(
        metadata=AssessmentMetadata(
            schema_version=versions.domain_schema,
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            target_root="example-project",
            started_at=timestamp,
            completed_at=timestamp,
        ),
        coverage=coverage,
    )


def test_exit_code_values_are_stable() -> None:
    """Automation-facing numbers match the published interface."""

    assert ExitCode.SUCCESS.value == 0
    assert ExitCode.RISK_THRESHOLD_EXCEEDED.value == 1
    assert ExitCode.SCAN_INCOMPLETE.value == 2
    assert ExitCode.CONFIGURATION_ERROR.value == 3
    assert ExitCode.BASELINE_ERROR.value == 4
    assert ExitCode.REQUIRED_ANALYSIS_FAILED.value == 5
    assert ExitCode.USAGE_ERROR.value == 64


@pytest.mark.parametrize(
    ("complete", "expected"),
    [
        (True, ExitCode.SUCCESS),
        (False, ExitCode.SCAN_INCOMPLETE),
    ],
)
def test_assessment_coverage_maps_to_process_outcome(
    complete: bool,
    expected: ExitCode,
) -> None:
    """A completed scan and an incomplete scan are machine-distinguishable."""

    assert exit_code_for_assessment(make_assessment(complete=complete)) is expected


def test_run_cli_maps_unknown_command_to_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The installed entry-point runner avoids code 2 ambiguity."""

    exit_code = run_cli(["unknown-command"])

    assert exit_code == ExitCode.USAGE_ERROR
    assert "No such command" in capsys.readouterr().err


def test_run_cli_maps_missing_root_to_incomplete_scan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The concrete engine reports an invalid target as incomplete coverage."""

    missing_root = tmp_path / "missing-project"
    exit_code = run_cli(["scan", str(missing_root)])

    assert exit_code == ExitCode.SCAN_INCOMPLETE
    captured = capsys.readouterr()
    assert "Status  INCOMPLETE" in captured.out
    assert "Scan coverage is incomplete" in captured.out
    assert captured.err == ""


def test_run_cli_maps_invalid_config_to_configuration_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid project config uses the documented configuration code."""

    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("output:\n  format: text\n", encoding="utf-8")

    exit_code = run_cli(["scan", "example-project", "--config", str(config_path)])

    assert exit_code == ExitCode.CONFIGURATION_ERROR
    assert "requires a version" in capsys.readouterr().err

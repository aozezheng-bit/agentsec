"""P2-26 explicit high/critical Severity fail-on policy tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli import ExitCode, app, run_cli
from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    Finding,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    ScanCoverage,
    Severity,
)
from agentsec.policy import FailOnThreshold, evaluate_assessment_fail_on
from agentsec.reporting import (
    AssessmentFailOnValidationError,
    decode_assessment_fail_on_json,
    decode_sarif_json,
    export_assessment_fail_on_json_schema,
)
from agentsec.versioning import FAIL_ON_POLICY_VERSION, current_versions

runner = CliRunner()
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_HASH = "a" * 64


def _finding(finding_id: str, severity: Severity) -> Finding:
    score = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 2.0,
        Severity.NONE: 0.0,
    }[severity]
    return Finding(
        finding_id=finding_id,
        rule_id="MD-EXEC-001",
        category=FindingCategory.CODE_EXECUTION,
        title="Deterministic execution signal",
        description="A trusted Rule produced a source-backed Finding.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.VERY_HIGH,
        severity=severity,
        score=score,
        confidence=EvidenceConfidence.D,
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=1,
                end_line=1,
                field="markdown:block",
                excerpt="Synthetic untrusted source text.",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Review the deterministic Finding.",),
    )


def _assessment(
    *findings: Finding,
    complete: bool = True,
) -> Assessment:
    versions = current_versions()
    timestamp = datetime(2026, 8, 25, 10, 0, tzinfo=UTC)
    return Assessment(
        metadata=AssessmentMetadata(
            schema_version=versions.domain_schema,
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            target_root="fixture",
            started_at=timestamp,
            completed_at=timestamp,
        ),
        findings=findings,
        coverage=ScanCoverage(
            discovered_assets=1,
            scanned_assets=1 if complete else 0,
            skipped_assets=0 if complete else 1,
            complete=complete,
        ),
    )


def test_fail_on_high_matches_high_and_critical_but_not_medium() -> None:
    assessment = _assessment(
        _finding("finding-medium", Severity.MEDIUM),
        _finding("finding-critical", Severity.CRITICAL),
        _finding("finding-high", Severity.HIGH),
    )

    decision = evaluate_assessment_fail_on(assessment, FailOnThreshold.HIGH)

    assert decision.policy_version == FAIL_ON_POLICY_VERSION == "0.1.0"
    assert decision.decision == "block"
    assert decision.exit_code == int(ExitCode.RISK_THRESHOLD_EXCEEDED)
    assert decision.blocks is True
    assert decision.highest_observed_severity is Severity.CRITICAL
    assert decision.matched_finding_ids == ("finding-critical", "finding-high")
    assert decision.basis == "agentsec_severity"


def test_fail_on_critical_does_not_block_on_high_and_confidence_cannot_suppress() -> (
    None
):
    assessment = _assessment(_finding("finding-high", Severity.HIGH))

    decision = evaluate_assessment_fail_on(assessment, FailOnThreshold.CRITICAL)

    assert decision.decision == "allow"
    assert decision.exit_code == int(ExitCode.SUCCESS)
    assert decision.blocks is False
    assert decision.matched_finding_ids == ()
    assert decision.highest_observed_severity is Severity.HIGH


def test_incomplete_coverage_has_precedence_over_a_matching_threshold() -> None:
    assessment = _assessment(
        _finding("finding-critical", Severity.CRITICAL),
        complete=False,
    )

    decision = evaluate_assessment_fail_on(assessment, FailOnThreshold.HIGH)

    assert decision.decision == "incomplete"
    assert decision.exit_code == int(ExitCode.SCAN_INCOMPLETE)
    assert decision.blocks is False
    assert decision.matched_finding_ids == ("finding-critical",)


def test_scan_fail_on_high_text_blocks_only_when_explicit() -> None:
    project = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"

    report_only = runner.invoke(app, ["scan", str(project), "--format", "text"])
    enforced = runner.invoke(
        app,
        ["scan", str(project), "--format", "text", "--fail-on", "high"],
    )
    critical_only = runner.invoke(
        app,
        ["scan", str(project), "--format", "text", "--fail-on", "critical"],
    )

    assert report_only.exit_code == ExitCode.SUCCESS
    assert "AgentSec Fail-On Decision" not in report_only.stdout
    assert enforced.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    assert "AgentSec Fail-On Decision" in enforced.stdout
    assert "Threshold: HIGH" in enforced.stdout
    assert "Decision: BLOCK" in enforced.stdout
    assert "Matched findings: 4" in enforced.stdout
    assert critical_only.exit_code == ExitCode.SUCCESS
    assert "Decision: ALLOW" in critical_only.stdout


def test_scan_fail_on_json_wraps_canonical_assessment_and_decision() -> None:
    project = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"

    result = runner.invoke(
        app,
        ["scan", str(project), "--format", "json", "--fail-on", "high"],
    )

    assert result.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    report = decode_assessment_fail_on_json(result.stdout)
    payload = json.loads(result.stdout)
    assert report.decision.threshold is FailOnThreshold.HIGH
    assert report.decision.decision == "block"
    assert payload["format"] == "agentsec-assessment-fail-on"
    assert payload["format_version"] == "0.1.0"
    assert payload["assessment_report"]["format"] == "agentsec-assessment"
    assert payload["assessment_report"]["policy"]["ci_blocking_enabled"] is False
    assert len(payload["decision"]["matched_finding_ids"]) == 4
    assert "synthetic-demo-token" not in result.stdout
    assert "LOCAL_REVIEW_TOKEN" not in result.stdout


def test_scan_fail_on_sarif_records_policy_without_using_sarif_level_as_authority() -> (
    None
):
    project = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"

    result = runner.invoke(
        app,
        ["scan", str(project), "--format", "sarif", "--fail-on", "high"],
    )

    assert result.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    run = decode_sarif_json(result.stdout).runs[0]
    assert run.properties["agentsecCiBlockingEnabled"] is True
    assert run.properties["agentsecEnforcementMode"] == "fail_on_severity"
    assert run.properties["agentsecFailOnThreshold"] == "high"
    assert run.properties["agentsecFailOnDecision"] == "block"
    assert run.properties["agentsecFailOnExitCode"] == 1
    assert run.invocations[0].properties["agentsecReportOnly"] is False
    assert (
        sum(
            result.properties.get("agentsecFailOnMatched") is True
            for result in run.results
        )
        == 4
    )


def test_scan_fail_on_incomplete_returns_two_with_machine_readable_decision() -> None:
    project = REPOSITORY_ROOT / "demos" / "release-agent" / "malformed"

    result = runner.invoke(
        app,
        ["scan", str(project), "--format", "json", "--fail-on", "high"],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    report = decode_assessment_fail_on_json(result.stdout)
    assert report.decision.decision == "incomplete"
    assert report.decision.blocks is False
    assert report.assessment_report.status == "incomplete"


def test_fail_on_supports_only_high_and_critical() -> None:
    direct = runner.invoke(app, ["scan", ".", "--fail-on", "medium"])

    assert direct.exit_code != ExitCode.SUCCESS
    assert "high" in direct.stderr
    assert "critical" in direct.stderr
    assert run_cli(["scan", ".", "--fail-on", "medium"]) == ExitCode.USAGE_ERROR


def test_capability_assess_does_not_expose_unqualified_severity_fail_on() -> None:
    help_result = runner.invoke(app, ["capability", "assess", "--help"])

    assert help_result.exit_code == ExitCode.SUCCESS
    assert "--fail-on" not in help_result.stdout


def test_fail_on_json_rejects_a_decision_that_does_not_match_assessment() -> None:
    project = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"
    result = runner.invoke(
        app,
        ["scan", str(project), "--format", "json", "--fail-on", "high"],
    )
    payload = json.loads(result.stdout)
    payload["decision"]["threshold"] = "critical"

    with pytest.raises(AssessmentFailOnValidationError):
        decode_assessment_fail_on_json(json.dumps(payload))


def test_fail_on_json_schema_is_frozen(tmp_path: Path) -> None:
    generated = export_assessment_fail_on_json_schema(tmp_path)
    frozen = (
        REPOSITORY_ROOT
        / "schemas"
        / "assessment"
        / "assessment-fail-on-report.schema.json"
    )

    assert generated.read_bytes() == frozen.read_bytes()

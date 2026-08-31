"""P2-25 strict SARIF 2.1.0 reporter and CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    AssessmentRequest,
    CapabilityAssessmentEngine,
    CapabilityAssessmentResult,
    CollectionAssessmentEngine,
)
from agentsec.cli import ExitCode, app
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import default_project_config
from agentsec.domain import Assessment
from agentsec.manifests import CapabilityDiffer
from agentsec.reporting import (
    AssessmentSarifRenderer,
    CapabilityAssessmentSarifRenderer,
    OverallScoreSarifRenderer,
    SarifValidationError,
    decode_sarif_json,
)
from agentsec.risk import (
    DeterministicAgenticFactorExtractor,
    DeterministicDriftScoreEngine,
    DeterministicGovernanceScoreEngine,
    DeterministicOverallScoreEngine,
    DeterministicTechnicalScoreEngine,
    DeterministicThreatMitigationEvaluator,
    OverallScoreAssessment,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def _assessment(name: str) -> Assessment:
    project = REPOSITORY_ROOT / "demos" / "release-agent" / name
    return CollectionAssessmentEngine(MarkdownAssetCollector()).assess(
        AssessmentRequest(
            project_root=project,
            config=default_project_config(),
            config_path=None,
        )
    )


def _capability(name: str) -> CapabilityAssessmentResult:
    project = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / name
    return CapabilityAssessmentEngine().assess(
        AgentAnalysisRequest(
            project_root=project,
            agent_id="capability-drift-agent",
        )
    )


def _overall() -> OverallScoreAssessment:
    root = REPOSITORY_ROOT / "demos" / "capability-drift-agent"
    pipeline = AgentAnalysisPipeline()
    before = pipeline.analyze(
        AgentAnalysisRequest(
            project_root=root / "baseline", agent_id="capability-drift-agent"
        )
    ).manifest
    after = pipeline.analyze(
        AgentAnalysisRequest(
            project_root=root / "risky-drift", agent_id="capability-drift-agent"
        )
    ).manifest
    factors = DeterministicAgenticFactorExtractor().extract(after)
    threats = DeterministicThreatMitigationEvaluator().evaluate(after, factors)
    technical = DeterministicTechnicalScoreEngine().score(factors, threats)
    drift = DeterministicDriftScoreEngine().score(
        before,
        after,
        diff=CapabilityDiffer().compare(before=before, after=after),
    )
    governance = DeterministicGovernanceScoreEngine().score(
        after, factors, threats, drift=drift
    )
    return DeterministicOverallScoreEngine().score(technical, drift, governance)


def test_assessment_sarif_has_rules_results_locations_and_safe_properties() -> None:
    rendered = AssessmentSarifRenderer().render(_assessment("risky-drift"))
    report = decode_sarif_json(rendered)
    payload = json.loads(rendered)
    run = report.runs[0]

    assert report.version == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(run.results) == 10
    assert len(run.tool.driver.rules) == 9
    assert all(
        result.partialFingerprints["agentsecFindingId/v1"] for result in run.results
    )
    assert all(result.locations for result in run.results)
    assert any(result.level == "error" for result in run.results)
    assert run.properties["agentsecCiBlockingEnabled"] is False
    assert run.tool.driver.properties["agentsecSarifReporterVersion"] == "0.4.0"
    assert "synthetic-demo-token" not in rendered
    assert "LOCAL_REVIEW_TOKEN" not in rendered
    assert "https://example.invalid" not in rendered


def test_capability_sarif_preserves_confidence_correlation_and_shadow_boundary() -> (
    None
):
    rendered = CapabilityAssessmentSarifRenderer().render(_capability("risky-drift"))
    report = decode_sarif_json(rendered)
    run = report.runs[0]

    assert len(run.results) == 17
    assert len(run.tool.driver.rules) == 16
    assert all(result.locations for result in run.results)
    assert all("agentsecConfidence" in result.properties for result in run.results)
    assert all("agentsecCorrelation" in result.properties for result in run.results)
    assert all(result.properties["agentsecHardGate"] is False for result in run.results)
    assert run.properties["agentsecRuntimeCapabilityVerified"] is False


def test_overall_score_sarif_is_report_only_and_has_component_scores() -> None:
    report = OverallScoreSarifRenderer().build(_overall())
    result = report.runs[0].results[0]

    assert result.ruleId == "AGENTSEC-OVERALL-001"
    assert result.level == "error"
    assert result.properties["agentsecOverallScore"] == 10.0
    assert result.properties["agentsecHardGateBlocks"] is False
    assert result.properties["agentsecCiBlockingEnabled"] is False
    assert result.locations == ()


def test_strict_sarif_validation_rejects_rule_index_drift() -> None:
    payload = json.loads(AssessmentSarifRenderer().render(_assessment("risky-drift")))
    payload["runs"][0]["results"][0]["ruleIndex"] = 999

    with pytest.raises(SarifValidationError):
        decode_sarif_json(json.dumps(payload))

    payload = json.loads(AssessmentSarifRenderer().render(_assessment("risky-drift")))
    fingerprints = payload["runs"][0]["results"][0]["partialFingerprints"]
    fingerprint = fingerprints.pop("agentsecFindingId/v1")
    fingerprints["agentsecFindingId"] = fingerprint
    with pytest.raises(SarifValidationError):
        decode_sarif_json(json.dumps(payload))

    with pytest.raises(TypeError):
        AssessmentSarifRenderer().render(object())  # type: ignore[arg-type]


def test_scan_cli_supports_sarif_and_retains_incomplete_exit_code() -> None:
    risky = runner.invoke(
        app,
        [
            "scan",
            str(REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"),
            "--format",
            "sarif",
        ],
    )
    incomplete = runner.invoke(
        app,
        [
            "scan",
            str(REPOSITORY_ROOT / "demos" / "release-agent" / "malformed"),
            "--format",
            "sarif",
        ],
    )

    assert risky.exit_code == ExitCode.SUCCESS
    assert decode_sarif_json(risky.stdout).runs[0].results
    assert incomplete.exit_code == ExitCode.SCAN_INCOMPLETE
    incomplete_report = decode_sarif_json(incomplete.stdout)
    assert (
        incomplete_report.runs[0].invocations[0].properties["agentsecCoverageComplete"]
        is False
    )


def test_sarif_is_exposed_only_on_supported_cli_surfaces() -> None:
    scan_help = runner.invoke(app, ["scan", "--help"])
    capability_help = runner.invoke(app, ["capability", "assess", "--help"])
    manifest_help = runner.invoke(app, ["manifest", "--help"])
    diff_help = runner.invoke(app, ["capability", "diff", "--help"])

    assert scan_help.exit_code == ExitCode.SUCCESS
    assert capability_help.exit_code == ExitCode.SUCCESS
    assert "sarif" in scan_help.stdout
    assert "sarif" in capability_help.stdout
    assert "sarif" not in manifest_help.stdout
    assert "sarif" not in diff_help.stdout


def test_capability_cli_writes_and_safely_replaces_sarif(tmp_path: Path) -> None:
    output = tmp_path / "capability.sarif"
    arguments = [
        "capability",
        "assess",
        str(REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "risky-drift"),
        "--agent-id",
        "capability-drift-agent",
        "--format",
        "sarif",
        "--output",
        str(output),
    ]

    created = runner.invoke(app, arguments)
    existing = runner.invoke(app, arguments)
    forced = runner.invoke(app, [*arguments, "--force"])

    assert created.exit_code == ExitCode.SUCCESS
    assert created.stdout == ""
    assert decode_sarif_json(output.read_text(encoding="utf-8")).runs[0].results
    assert existing.exit_code == ExitCode.ARTIFACT_ERROR
    assert forced.exit_code == ExitCode.SUCCESS


def test_capability_sarif_requires_sarif_suffix(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "capability",
            "assess",
            str(REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "baseline"),
            "--agent-id",
            "capability-drift-agent",
            "--format",
            "sarif",
            "--output",
            str(tmp_path / "invalid.json"),
        ],
    )

    assert result.exit_code == ExitCode.ARTIFACT_ERROR
    assert "must use a .sarif filename" in result.stderr

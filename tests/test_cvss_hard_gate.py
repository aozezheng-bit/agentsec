"""Tests for P2-24 deterministic report-only CVSS Hard Gates."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
    CvssHardGateAssessment,
    CvssHardGateMatch,
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
from agentsec.reporting import AssessmentJsonRenderer, AssessmentTextRenderer
from agentsec.risk import (
    CVSS_HARD_GATE_CRITICAL_ID,
    CVSS_HARD_GATE_HIGH_ID,
    CvssBaseAdapter,
    DeterministicCvssHardGateEngine,
)
from agentsec.versioning import CVSS_HARD_GATE_VERSION, current_versions

runner = CliRunner()

_HASH = "b" * 64
_V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V31_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
_V40_THREAT_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"


def make_finding(finding_id: str = "finding-sha256:" + "1" * 64) -> Finding:
    """Create a valid Finding with an independent AgentSec risk view."""

    return Finding(
        finding_id=finding_id,
        rule_id="MD-EXEC-001",
        category=FindingCategory.CODE_EXECUTION,
        title="Execution capability",
        description="The Agent declares an execution-related capability.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.VERY_HIGH,
        severity=Severity.HIGH,
        score=8.0,
        confidence=EvidenceConfidence.D,
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=1,
                end_line=1,
                excerpt="Run a shell command.",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Require explicit approval.",),
    )


def make_assessment(*findings: Finding) -> Assessment:
    """Wrap Findings in a complete Assessment."""

    versions = current_versions()
    started = datetime(2026, 8, 24, 15, 0, tzinfo=UTC)
    return Assessment(
        metadata=AssessmentMetadata(
            schema_version=versions.domain_schema,
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            target_root="/workspace/project",
            started_at=started,
            completed_at=started,
        ),
        findings=findings,
        coverage=ScanCoverage(
            discovered_assets=len(findings),
            scanned_assets=len(findings),
            skipped_assets=0,
            complete=True,
        ),
    )


def with_cvss(finding: Finding, vector: str) -> Finding:
    """Attach one locally calculated CVSS assessment."""

    return CvssBaseAdapter().adapt({"vector": vector}).attach_to_finding(finding)


def test_critical_effective_cvss_score_matches_critical_gate() -> None:
    """CVSS 9.0+ produces the strongest report-only gate."""

    finding = with_cvss(make_finding(), _V31_CRITICAL)
    result = DeterministicCvssHardGateEngine().apply(make_assessment(finding))
    gated = result.findings[0]

    assert gated.cvss_hard_gate is not None
    assert gated.cvss_hard_gate.gate_version == CVSS_HARD_GATE_VERSION == "0.1.0"
    assert gated.cvss_hard_gate.triggered is True
    assert gated.cvss_hard_gate.blocks is False
    assert gated.cvss_hard_gate.score == 9.8
    assert gated.cvss_hard_gate.severity is Severity.CRITICAL
    assert gated.cvss_hard_gate.match is not None
    assert gated.cvss_hard_gate.match.gate_id == CVSS_HARD_GATE_CRITICAL_ID
    assert gated.cvss_hard_gate.match.floor == "critical"
    assert gated.cvss_hard_gate.match.threshold == 9.0

    # CVSS gate is a separate report view; it does not rewrite AgentSec risk.
    assert gated.score == 8.0
    assert gated.severity is Severity.HIGH
    assert gated.hard_gate is False


def test_high_effective_cvss_score_matches_high_gate_only() -> None:
    """CVSS High is reportable without incorrectly claiming Critical."""

    finding = with_cvss(make_finding(), _V31_HIGH)
    result = DeterministicCvssHardGateEngine().apply(make_assessment(finding))
    gate = result.findings[0].cvss_hard_gate

    assert gate is not None
    assert gate.score == 8.6
    assert gate.triggered is True
    assert gate.match is not None
    assert gate.match.gate_id == CVSS_HARD_GATE_HIGH_ID

    # The same engine uses the effective score, not the AgentSec score.
    high_cvss = with_cvss(make_finding(), _V40_THREAT_HIGH)
    high_result = DeterministicCvssHardGateEngine().apply(make_assessment(high_cvss))
    high_gate = high_result.findings[0].cvss_hard_gate
    assert high_gate is not None
    assert high_gate.score == 8.9
    assert high_gate.match is not None
    assert high_gate.match.gate_id == CVSS_HARD_GATE_HIGH_ID
    assert high_gate.match.floor == "high"


def test_gate_evaluation_is_idempotent_and_preserves_vulnerability() -> None:
    """Repeated report-only evaluation cannot duplicate or replace metadata."""

    from agentsec.domain import VulnerabilityReference

    finding = with_cvss(make_finding(), _V31_CRITICAL).attach_vulnerability(
        VulnerabilityReference(
            vulnerability_id="CVE-2026-0001",
            cve_id="CVE-2026-0001",
            source="internal-catalog",
            association_basis=("Caller supplied this association.",),
        )
    )
    engine = DeterministicCvssHardGateEngine()
    first = engine.apply(make_assessment(finding))
    second = engine.apply(first)

    assert second == first
    assert second.findings[0].vulnerability == finding.vulnerability
    assert second.findings[0].cvss_hard_gate is not None
    assert len(second.findings[0].cvss_hard_gate.mapping_basis) == 2


def test_reports_display_cvss_gate_without_ci_blocking() -> None:
    """Text and JSON reports expose the gate and preserve report-only policy."""

    finding = with_cvss(make_finding(), _V31_CRITICAL)
    assessment = DeterministicCvssHardGateEngine().apply(make_assessment(finding))

    text = AssessmentTextRenderer().render(assessment)
    assert "CVSS Hard Gate" in text
    assert "MATCHED HG-CVSS-002 (report-only; no CI block)" in text

    payload = json.loads(AssessmentJsonRenderer().render(assessment))
    report_finding = payload["assessment"]["findings"][0]
    assert payload["summary"]["cvss_hard_gate_matches"] == 1
    assert report_finding["cvss_hard_gate"]["mode"] == "report_only"
    assert report_finding["cvss_hard_gate"]["match"]["gate_id"] == (
        CVSS_HARD_GATE_CRITICAL_ID
    )
    assert payload["policy"]["ci_blocking_enabled"] is False


def test_scan_cli_applies_cvss_gate_after_source_enrichment(tmp_path: Path) -> None:
    """Critical CVSS is visible while scan remains a successful report-only run."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_text(
        "Run a shell command without approval; review CVE-2026-0001.\n",
        encoding="utf-8",
    )
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "format": "agentsec-vulnerability-catalog",
                "format_version": "0.1.0",
                "source_id": "internal-catalog",
                "source_format": "agentsec-catalog-0.1.0",
                "records": [
                    {
                        "cve_id": "CVE-2026-0001",
                        "cwe_ids": ["CWE-78"],
                        "cvss": {"vector": _V31_CRITICAL},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            str(project_root),
            "--format",
            "json",
            "--vulnerability-source",
            str(source),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    matched = [
        item
        for item in payload["assessment"]["findings"]
        if item["cvss_hard_gate"] is not None
        and item["cvss_hard_gate"]["match"] is not None
    ]
    assert matched
    assert payload["summary"]["cvss_hard_gate_matches"] == len(matched)
    assert all(item["cvss_hard_gate"]["mode"] == "report_only" for item in matched)
    assert payload["policy"]["ci_blocking_enabled"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {
            "gate_version": "0.1.0",
            "finding_id": "finding-sha256:" + "1" * 64,
            "mode": "report_only",
            "score": 8.0,
            "severity": "high",
            "score_type": "base",
            "match": {
                "gate_id": "HG-CVSS-001",
                "floor": "critical",
                "threshold": 9.0,
                "score": 8.0,
                "score_type": "base",
                "rationale": ["invalid score match"],
            },
            "mapping_basis": ["basis"],
        },
        {
            "gate_version": "0.1.0",
            "finding_id": "finding-sha256:" + "1" * 64,
            "mode": "report_only",
            "score": 8.0,
            "severity": "high",
            "score_type": "base",
            "match": {
                "gate_id": "HG-CVSS-001",
                "floor": "high",
                "threshold": 8.0,
                "score": 8.0,
                "score_type": "base",
                "rationale": ["invalid threshold"],
            },
            "mapping_basis": ["basis"],
        },
    ],
)
def test_cvss_gate_model_rejects_incoherent_matches(
    payload: dict[str, object],
) -> None:
    """Threshold, floor, and matched score cannot be caller-inconsistent."""

    with pytest.raises(ValidationError):
        CvssHardGateAssessment.model_validate(payload)


def test_cvss_gate_match_model_rejects_invalid_gate_id() -> None:
    """CVSS Gate IDs remain an allow-listed stable namespace."""

    with pytest.raises(ValidationError):
        CvssHardGateMatch(
            gate_id="HG-OTHER-001",
            floor="high",
            threshold=7.0,
            score=7.0,
            score_type="base",
            rationale=("invalid namespace",),
        )

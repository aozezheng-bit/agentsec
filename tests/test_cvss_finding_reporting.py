"""Tests for P2-18 CVSS integration into Findings and Assessment reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

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
from agentsec.reporting import (
    AssessmentJsonRenderer,
    AssessmentTextRenderer,
    export_assessment_json_schema,
)
from agentsec.risk import CvssBaseAdapter
from agentsec.versioning import current_versions

_HASH = "a" * 64
_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def make_finding() -> Finding:
    """Create a valid Finding whose AgentSec score differs from CVSS."""

    return Finding(
        finding_id="finding-cvss",
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
                start_line=4,
                end_line=4,
                excerpt="Run the deployment command.",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Require explicit approval.",),
    )


def make_assessment(finding: Finding) -> Assessment:
    """Wrap one Finding in a deterministic complete Assessment."""

    versions = current_versions()
    started = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)
    return Assessment(
        metadata=AssessmentMetadata(
            schema_version=versions.domain_schema,
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            target_root="/workspace/project",
            started_at=started,
            completed_at=started + timedelta(seconds=1),
        ),
        findings=(finding,),
        coverage=ScanCoverage(
            discovered_assets=1,
            scanned_assets=1,
            skipped_assets=0,
            complete=True,
        ),
    )


def test_adapter_attaches_cvss_without_overwriting_agentsec_risk() -> None:
    """CVSS and AgentSec scores remain independently visible on one Finding."""

    finding = make_finding()
    cvss = CvssBaseAdapter().adapt({"vector": _VECTOR})

    enriched = cvss.attach_to_finding(finding)

    assert enriched.score == 8.0
    assert enriched.severity is Severity.HIGH
    assert enriched.cvss is not None
    assert enriched.cvss.base_score == 9.8
    assert enriched.cvss.base_severity is Severity.CRITICAL
    assert enriched.cvss.score_verification == "calculated"


def test_json_assessment_report_contains_cvss_and_round_trips() -> None:
    """The public JSON report carries the nested CVSS object with provenance."""

    cvss = CvssBaseAdapter().adapt({"vector": _VECTOR})
    rendered = AssessmentJsonRenderer().render(
        make_assessment(cvss.attach_to_finding(make_finding()))
    )
    payload = json.loads(rendered)

    report_finding = payload["assessment"]["findings"][0]
    assert report_finding["score"] == 8.0
    assert report_finding["severity"] == "high"
    assert report_finding["cvss"] == {
        "adapter_version": "0.3.0",
        "base_score": 9.8,
        "base_severity": "critical",
        "effective_score": 9.8,
        "effective_severity": "critical",
        "score_type": "base",
        "mapping_basis": [
            "FIRST CVSS v3.1 Base, Temporal, and Environmental formulas",
            "FIRST CVSS v3.1 qualitative severity rating scale",
            "AgentSec CVSS extended input adapter contract 0.3.0",
        ],
        "metrics": {
            "A": "H",
            "AC": "L",
            "AV": "N",
            "C": "H",
            "I": "H",
            "PR": "N",
            "S": "U",
            "UI": "N",
        },
        "score_verification": "calculated",
        "vector": _VECTOR,
        "version": "3.1",
    }

    from agentsec.reporting import AssessmentJsonReport

    validated = AssessmentJsonReport.model_validate_json(rendered)
    assert validated.assessment.findings[0].cvss is not None


def test_text_assessment_report_displays_cvss_separately() -> None:
    """Terminal readers can distinguish CVSS from AgentSec score and Severity."""

    cvss = CvssBaseAdapter().adapt({"vector": _VECTOR})
    rendered = AssessmentTextRenderer().render(
        make_assessment(cvss.attach_to_finding(make_finding()))
    )

    assert "Score  8.0" in rendered
    assert "Severity  HIGH" in rendered
    assert "CVSS Base  9.8 (CRITICAL)" in rendered
    assert f"CVSS Vector  {_VECTOR}" in rendered
    assert "CVSS Verification  calculated" in rendered


def test_cvss_is_optional_for_existing_findings() -> None:
    """Existing non-vulnerability Findings remain valid without CVSS data."""

    finding = make_finding()

    assert finding.cvss is None
    payload = finding.model_dump(mode="json")
    assert payload["cvss"] is None


def test_domain_cvss_rejects_inconsistent_provenance_and_severity() -> None:
    """The serialized boundary cannot accept contradictory CVSS metadata."""

    cvss = CvssBaseAdapter().adapt({"vector": _VECTOR}).to_domain_cvss()

    with pytest.raises(ValidationError):
        type(cvss).model_validate(cvss.model_dump() | {"base_severity": Severity.HIGH})

    payload = cvss.model_dump()
    payload["score_verification"] = "provided"
    with pytest.raises(ValidationError):
        type(cvss).model_validate(payload)


def test_assessment_schema_exposes_optional_cvss_nested_model(tmp_path: Path) -> None:
    """The exported Assessment schema exposes CVSS without making it mandatory."""

    schema = json.loads(
        export_assessment_json_schema(tmp_path).read_text(encoding="utf-8")
    )
    finding_schema = schema["$defs"]["Finding"]

    assert "cvss" in finding_schema["properties"]
    assert "cvss" not in finding_schema["required"]
    assert "CvssBase" in schema["$defs"]

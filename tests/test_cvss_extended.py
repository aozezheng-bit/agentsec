"""Tests for P2-21 CVSS Temporal/Environmental/Threat/Supplemental support."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

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
from agentsec.reporting import AssessmentJsonRenderer, AssessmentTextRenderer
from agentsec.risk import (
    CvssAdapterCode,
    CvssAdapterError,
    CvssBaseAdapter,
    CvssScoreType,
)
from agentsec.versioning import current_versions

_HASH = "a" * 64


def make_finding() -> Finding:
    """Create a valid Finding for extended-score report tests."""

    return Finding(
        finding_id="finding-cvss-extended",
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
    """Wrap one Finding in a complete Assessment."""

    versions = current_versions()
    started = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
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


def test_v31_temporal_score_is_calculated_and_reported() -> None:
    """CVSS v3.1 Temporal metrics produce a separate effective score."""

    result = CvssBaseAdapter().adapt(
        {"vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:R")}
    )

    assert result.score_type is CvssScoreType.TEMPORAL
    assert result.base_score == 9.8
    assert result.effective_score == 8.5
    assert result.effective_severity is Severity.HIGH
    assert result.score_verification.value == "calculated"


def test_v31_environmental_score_includes_temporal_and_modified_metrics() -> None:
    """CVSS v3.1 Environmental metrics use modified impact and requirements."""

    result = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/"
                "E:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/"
                "MS:U/MC:L/MI:L/MA:L"
            )
        }
    )

    assert result.score_type is CvssScoreType.ENVIRONMENTAL
    assert result.base_score == 9.8
    assert result.effective_score == 7.7
    assert result.effective_severity is Severity.HIGH


def test_v31_environmental_score_applies_inner_roundup() -> None:
    """H3 regression: FIRST v3.1 requires Roundup(Roundup(min[...]) * E*RL*RC).

    With all modified metrics unset the inner roundup of the unrounded
    impact+exploitability sum changes the result: the previous single-step
    implementation returned 8.9 here, the spec-conformant two-step form
    returns 9.0.
    """

    result = CvssBaseAdapter().adapt(
        {"vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U")}
    )

    assert result.score_type is CvssScoreType.TEMPORAL
    assert result.effective_score == 9.0


def test_v40_base_score_matches_official_first_calculator() -> None:
    """H2 regression: eq3eq6 next-lower and the eq5 divisor follow FIRST.

    This vector is drawn from a random differential run against the official
    RedHat/FIRST ``cvss40.js`` calculator: the pre-fix implementation scored
    it 1.6 via the wrong (eq3=1, eq6=0) next-lower branch and the missing
    eq5 divisor contribution; the official score is 2.0.
    """

    result = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:L/"
                "SC:L/SI:L/SA:N/E:U/CR:L/IR:H/AR:L"
            )
        }
    )

    assert result.effective_score == 2.0


def test_v40_threat_score_uses_exploit_maturity() -> None:
    """CVSS v4.0 Threat E changes the effective score while preserving Base."""

    result = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
            )
        }
    )

    assert result.score_type is CvssScoreType.THREAT
    assert result.base_score == 9.3
    assert result.effective_score == 8.9
    assert result.effective_severity is Severity.HIGH


def test_v40_environmental_score_uses_modified_metrics_and_requirements() -> None:
    """CVSS v4.0 Environmental metrics feed the local MacroVector calculator."""

    result = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/"
                "CR:L/MVC:L/MVI:L/MVA:L"
            )
        }
    )

    assert result.score_type is CvssScoreType.ENVIRONMENTAL
    assert result.base_score == 9.3
    assert result.effective_score == 6.9
    assert result.effective_severity is Severity.MEDIUM


def test_v40_supplemental_metrics_are_retained_without_changing_score() -> None:
    """Supplemental metrics are report evidence and do not alter Base scoring."""

    base = CvssBaseAdapter().adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}
    )
    supplemental = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/"
                "S:P/AU:Y/R:U/V:C/RE:H/U:Red"
            )
        }
    )

    assert supplemental.score_type is CvssScoreType.BASE
    assert supplemental.effective_score == base.effective_score == 9.3
    assert supplemental.metric_values["U"] == "Red"
    assert supplemental.metric_values["AU"] == "Y"


def test_extended_score_and_severity_can_be_supplied_for_consistency_check() -> None:
    """Input consumers can verify both Base and effective score expectations."""

    result = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
            ),
            "base_score": 9.3,
            "base_severity": "critical",
            "score": 8.9,
            "severity": "high",
        }
    )

    assert result.effective_score == 8.9


def test_extended_score_mismatch_fails_closed() -> None:
    """An imported effective Score cannot silently override local calculation."""

    with pytest.raises(CvssAdapterError) as captured:
        CvssBaseAdapter().adapt(
            {
                "vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P"),
                "score": 9.8,
            }
        )

    assert captured.value.code is CvssAdapterCode.SCORE_MISMATCH


def test_extended_metrics_are_visible_in_json_and_text_reports() -> None:
    """Assessment reports retain extended vector and effective-score provenance."""

    cvss = CvssBaseAdapter().adapt(
        {
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
            )
        }
    )
    finding = cvss.attach_to_finding(make_finding())
    payload = json.loads(AssessmentJsonRenderer().render(make_assessment(finding)))
    report_cvss = payload["assessment"]["findings"][0]["cvss"]

    assert report_cvss["score_type"] == "threat"
    assert report_cvss["effective_score"] == 8.9
    assert report_cvss["effective_severity"] == "high"
    assert report_cvss["metrics"]["E"] == "P"

    rendered = AssessmentTextRenderer().render(make_assessment(finding))
    assert "CVSS Effective  8.9 (HIGH)" in rendered
    assert "CVSS Score Type  threat" in rendered

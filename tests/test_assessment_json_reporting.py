"""Tests for P1-25 versioned, schema-backed Assessment JSON reporting."""

from __future__ import annotations

import builtins
import json
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.domain import (
    AgentAsset,
    Assessment,
    AssessmentMetadata,
    AssetChange,
    AssetSource,
    AssetType,
    ChangeType,
    CoverageIssue,
    CoverageIssueCode,
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
    ASSESSMENT_JSON_FORMAT,
    ASSESSMENT_JSON_FORMAT_VERSION,
    ASSESSMENT_JSON_SCHEMA_FILENAME,
    AssessmentJsonRenderer,
    AssessmentJsonReport,
    export_assessment_json_schema,
)
from agentsec.versioning import ASSESSMENT_OUTPUT_VERSION, current_versions

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64


def make_finding(
    *,
    finding_id: str,
    rule_id: str,
    severity: Severity,
    score: float,
    title: str,
    confidence: EvidenceConfidence = EvidenceConfidence.D,
    hard_gate: bool = False,
    excerpt: str = "Run a shell command.",
    evidence: tuple[Evidence, ...] | None = None,
    recommendations: tuple[str, ...] = ("Require explicit approval.",),
) -> Finding:
    """Create one complete final Domain Finding."""

    effective_evidence = evidence or (
        Evidence(
            source_type=EvidenceSource.FILE,
            asset_path="AGENTS.md",
            start_line=1,
            end_line=1,
            field="markdown:block",
            excerpt=excerpt,
            content_sha256=_HASH_A,
        ),
    )
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        category=FindingCategory.CODE_EXECUTION,
        title=title,
        description="The Agent control asset declares a security-relevant action.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.VERY_HIGH,
        severity=severity,
        score=score,
        confidence=confidence,
        hard_gate=hard_gate,
        evidence=effective_evidence,
        recommendations=recommendations,
    )


def make_assessment(
    *,
    findings: tuple[Finding, ...] = (),
    assets: tuple[AgentAsset, ...] = (),
    changes: tuple[AssetChange, ...] = (),
    coverage: ScanCoverage | None = None,
    target_root: str = "/workspace/project",
) -> Assessment:
    """Create deterministic report metadata and optional Domain collections."""

    versions = current_versions()
    started = datetime(2026, 8, 19, 12, 30, tzinfo=UTC)
    effective_coverage = coverage or ScanCoverage(
        discovered_assets=len(assets),
        scanned_assets=len(assets),
        skipped_assets=0,
        complete=True,
    )
    return Assessment(
        metadata=AssessmentMetadata(
            schema_version=versions.domain_schema,
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            target_root=target_root,
            started_at=started,
            completed_at=started + timedelta(seconds=3),
            git_commit="0123456789abcdef",
            git_dirty=False,
        ),
        assets=assets,
        changes=changes,
        findings=findings,
        coverage=effective_coverage,
    )


def test_empty_report_is_versioned_valid_and_never_claims_global_safety() -> None:
    """An empty complete Assessment remains report-only and scope-bounded."""

    rendered = AssessmentJsonRenderer().render(make_assessment())
    payload = json.loads(rendered)
    validated = AssessmentJsonReport.model_validate_json(rendered)

    assert payload["format"] == ASSESSMENT_JSON_FORMAT
    assert payload["format_version"] == ASSESSMENT_OUTPUT_VERSION
    assert ASSESSMENT_JSON_FORMAT_VERSION == ASSESSMENT_OUTPUT_VERSION
    assert payload["status"] == "complete"
    assert payload["policy"] == {
        "ci_blocking_enabled": False,
        "enforcement_mode": "report_only",
        "global_safety_claimed": False,
    }
    assert payload["summary"]["findings"] == 0
    assert payload["summary"]["highest_severity"] == "none"
    assert payload["summary"]["coverage_discovered_assets"] == 0
    assert payload["summary"]["coverage_scanned_assets"] == 0
    assert payload["summary"]["coverage_skipped_assets"] == 0
    assert payload["assessment"]["metadata"]["schema_version"] == "0.8.0"
    assert payload["assessment"]["metadata"]["risk_model_version"] == "0.4.0"
    assert validated.assessment.findings == ()
    assert rendered.endswith("\n")


def test_report_contains_complete_assessment_and_stable_array_order() -> None:
    """Assets, Changes, Findings, Evidence, and Coverage Issues are deterministic."""

    assets = (
        AgentAsset(
            path="skills/zeta/SKILL.md",
            asset_type=AssetType.SKILL,
            source=AssetSource.DISCOVERED,
            sha256=_HASH_B,
            size_bytes=20,
            line_count=2,
        ),
        AgentAsset(
            path="AGENTS.md",
            asset_type=AssetType.AGENTS,
            source=AssetSource.DISCOVERED,
            sha256=_HASH_A,
            size_bytes=10,
            line_count=1,
        ),
    )
    changes = (
        AssetChange(
            path="skills/zeta/SKILL.md",
            change_type=ChangeType.REMOVED,
            before_sha256=_HASH_B,
        ),
        AssetChange(
            path="AGENTS.md",
            change_type=ChangeType.ADDED,
            after_sha256=_HASH_A,
        ),
    )
    later_evidence = Evidence(
        source_type=EvidenceSource.FILE,
        asset_path="skills/zeta/SKILL.md",
        start_line=8,
        end_line=8,
        field="markdown:block",
        excerpt="Later evidence.",
        content_sha256=_HASH_B,
    )
    first_evidence = Evidence(
        source_type=EvidenceSource.FILE,
        asset_path="AGENTS.md",
        start_line=2,
        end_line=2,
        field="markdown:block",
        excerpt="First evidence.",
        content_sha256=_HASH_A,
    )
    low = make_finding(
        finding_id="finding-low",
        rule_id="MD-OBFUSC-001",
        severity=Severity.LOW,
        score=2.0,
        title="Low signal",
    )
    critical = make_finding(
        finding_id="finding-critical",
        rule_id="MD-COMBO-001",
        severity=Severity.CRITICAL,
        score=9.0,
        title="Critical signal",
        confidence=EvidenceConfidence.B,
        hard_gate=True,
        evidence=(later_evidence, first_evidence),
        recommendations=("First recommendation.", "Second recommendation."),
    )
    coverage = ScanCoverage(
        discovered_assets=2,
        scanned_assets=0,
        skipped_assets=2,
        complete=False,
        issues=(
            CoverageIssue(
                code=CoverageIssueCode.UNREADABLE,
                message="Second issue.",
                asset_path="skills/zeta/SKILL.md",
            ),
            CoverageIssue(
                code=CoverageIssueCode.PARSE_ERROR,
                message="First issue.",
                asset_path="AGENTS.md",
            ),
        ),
    )
    assessment = make_assessment(
        findings=(low, critical),
        assets=assets,
        changes=changes,
        coverage=coverage,
    )
    renderer = AssessmentJsonRenderer()

    first = renderer.render(assessment)
    second = renderer.render(
        assessment.model_copy(
            update={
                "assets": tuple(reversed(assets)),
                "changes": tuple(reversed(changes)),
                "findings": (critical, low),
                "coverage": coverage.model_copy(
                    update={"issues": tuple(reversed(coverage.issues))}
                ),
            }
        )
    )
    payload = json.loads(first)

    assert first == second
    assert payload["status"] == "incomplete"
    assert [item["path"] for item in payload["assessment"]["assets"]] == [
        "AGENTS.md",
        "skills/zeta/SKILL.md",
    ]
    assert [item["path"] for item in payload["assessment"]["changes"]] == [
        "AGENTS.md",
        "skills/zeta/SKILL.md",
    ]
    assert [item["finding_id"] for item in payload["assessment"]["findings"]] == [
        "finding-critical",
        "finding-low",
    ]
    assert [
        item["asset_path"] for item in payload["assessment"]["findings"][0]["evidence"]
    ] == ["AGENTS.md", "skills/zeta/SKILL.md"]
    assert payload["assessment"]["findings"][0]["recommendations"] == [
        "First recommendation.",
        "Second recommendation.",
    ]
    assert [
        item["asset_path"] for item in payload["assessment"]["coverage"]["issues"]
    ] == ["AGENTS.md", "skills/zeta/SKILL.md"]
    assert payload["summary"]["highest_severity"] == "critical"
    assert payload["summary"]["confidence_counts"] == {
        "A": 0,
        "B": 1,
        "C": 0,
        "D": 1,
    }
    assert payload["summary"]["hard_gate_matches"] == 1
    assert payload["summary"]["coverage_discovered_assets"] == 2
    assert payload["summary"]["coverage_scanned_assets"] == 0
    assert payload["summary"]["coverage_skipped_assets"] == 2
    assert payload["summary"]["coverage_issues"] == 2
    assert payload["policy"]["ci_blocking_enabled"] is False


def test_all_untrusted_json_strings_are_redacted_and_visibly_escaped() -> None:
    """Secrets and output-significant characters never survive as raw JSON data."""

    secret = "agentsec-test-json-secret"
    evidence = Evidence(
        source_type=EvidenceSource.FILE,
        asset_path="unsafe\x1b[31m\u200b/AGENTS.md",
        start_line=3,
        end_line=3,
        field="markdown:block\u202e",
        excerpt=f"token={secret}\x1b[2J\n",
        content_sha256=_HASH_C,
    )
    finding = make_finding(
        finding_id="finding-secret",
        rule_id="MD-SECRET-001",
        severity=Severity.HIGH,
        score=8.0,
        title="[bold]Unsafe[/bold]\x1b[31m\u202e\u200b",
        evidence=(evidence,),
        recommendations=(f"Authorization: Bearer {secret}\x1b[31m",),
    ).model_copy(update={"description": f"password={secret}\x1b[31m"})
    coverage = ScanCoverage(
        discovered_assets=1,
        scanned_assets=0,
        skipped_assets=1,
        complete=False,
        issues=(
            CoverageIssue(
                code=CoverageIssueCode.UNREADABLE,
                message=f"token={secret}\x1b[31m",
                asset_path="private\u202e/AGENTS.md",
            ),
        ),
    )

    rendered = AssessmentJsonRenderer().render(
        make_assessment(
            findings=(finding,),
            coverage=coverage,
            target_root=f"token={secret}\x1b[31m",
        )
    )
    payload = json.loads(rendered)
    serialized = json.dumps(payload, ensure_ascii=False)

    assert secret not in rendered
    assert "<redacted>" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in serialized
    assert "\u200b" not in serialized
    assert "\\u001b" in serialized
    assert "\\u202e" in serialized
    assert "\\u200b" in serialized
    assert payload["assessment"]["findings"][0]["title"].startswith(
        "[bold]Unsafe[/bold]"
    )
    assert (
        payload["assessment"]["coverage"]["issues"][0]["message"] == "token=<redacted>"
    )
    AssessmentJsonReport.model_validate_json(rendered)


def test_json_coverage_counts_remain_explicit_without_issue_details() -> None:
    """A skipped asset without a structured Issue is still visibly incomplete."""

    coverage = ScanCoverage(
        discovered_assets=1,
        scanned_assets=0,
        skipped_assets=1,
        complete=False,
    )

    rendered = AssessmentJsonRenderer().render(make_assessment(coverage=coverage))
    payload = json.loads(rendered)

    assert payload["status"] == "incomplete"
    assert payload["summary"]["coverage_discovered_assets"] == 1
    assert payload["summary"]["coverage_scanned_assets"] == 0
    assert payload["summary"]["coverage_skipped_assets"] == 1
    assert payload["summary"]["coverage_issues"] == 0
    assert payload["assessment"]["coverage"]["issues"] == []
    assert payload["summary"]["findings"] == 0
    AssessmentJsonReport.model_validate_json(rendered)


def test_schema_export_is_deterministic_strict_and_versioned(tmp_path: Path) -> None:
    """Automation can validate the independent Assessment output contract."""

    first_path = export_assessment_json_schema(tmp_path / "first")
    second_path = export_assessment_json_schema(tmp_path / "second")
    schema = json.loads(first_path.read_text(encoding="utf-8"))

    assert first_path.name == ASSESSMENT_JSON_SCHEMA_FILENAME
    assert first_path.read_bytes() == second_path.read_bytes()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "format",
        "format_version",
        "status",
        "policy",
        "summary",
        "assessment",
    }
    assert schema["properties"]["format"]["const"] == ASSESSMENT_JSON_FORMAT
    assert schema["properties"]["format_version"]["const"] == ASSESSMENT_OUTPUT_VERSION
    assert schema["$defs"]["Assessment"]["additionalProperties"] is False


def test_report_model_rejects_misleading_status_or_summary() -> None:
    """Schema-backed Python validation cannot accept contradictory derived fields."""

    incomplete = ScanCoverage(
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
    rendered = AssessmentJsonRenderer().render(make_assessment(coverage=incomplete))
    payload = json.loads(rendered)

    payload["status"] = "complete"
    with pytest.raises(ValidationError, match="status"):
        AssessmentJsonReport.model_validate(payload)

    payload = json.loads(rendered)
    payload["summary"]["coverage_skipped_assets"] = 0
    with pytest.raises(ValidationError, match="summary"):
        AssessmentJsonReport.model_validate(payload)

    payload = json.loads(rendered)
    payload["summary"]["findings"] = 99
    with pytest.raises(ValidationError, match="summary"):
        AssessmentJsonReport.model_validate(payload)


def test_json_renderer_rejects_non_assessment_input() -> None:
    """The public seam cannot serialize arbitrary attacker-controlled objects."""

    with pytest.raises(TypeError, match="Assessment"):
        AssessmentJsonRenderer().render({"assessment": "fake"})  # type: ignore[arg-type]


def test_json_renderer_has_no_file_shell_or_network_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rendering is a pure in-memory transformation."""

    finding = make_finding(
        finding_id="finding-side-effect",
        rule_id="MD-EXEC-001",
        severity=Severity.HIGH,
        score=8.0,
        title="Side-effect test",
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("JSON Reporter attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    rendered = AssessmentJsonRenderer().render(make_assessment(findings=(finding,)))

    assert json.loads(rendered)["summary"]["findings"] == 1

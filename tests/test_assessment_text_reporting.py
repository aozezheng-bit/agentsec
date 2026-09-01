"""Tests for P1-24 safe deterministic Rich Assessment text reporting."""

from __future__ import annotations

import builtins
import socket
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
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
from agentsec.reporting import AssessmentTextLimits, AssessmentTextRenderer
from agentsec.versioning import current_versions

_HASH_A = "a" * 64
_HASH_B = "b" * 64


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
    evidence_count: int = 1,
    recommendations: tuple[str, ...] = ("Require explicit approval.",),
) -> Finding:
    """Create a valid final Domain Finding for report tests."""

    evidence = tuple(
        Evidence(
            source_type=EvidenceSource.FILE,
            asset_path=("AGENTS.md" if index == 0 else f"skills/item-{index}/SKILL.md"),
            start_line=index + 1,
            end_line=index + 1,
            field="markdown:block",
            excerpt=excerpt if index == 0 else f"Evidence item {index}.",
            content_sha256=_HASH_A if index == 0 else _HASH_B,
        )
        for index in range(evidence_count)
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
        evidence=evidence,
        recommendations=recommendations,
    )


def make_assessment(
    *,
    findings: tuple[Finding, ...] = (),
    complete: bool = True,
    coverage: ScanCoverage | None = None,
    target_root: str = "/workspace/project",
) -> Assessment:
    """Create deterministic Assessment metadata and Coverage."""

    versions = current_versions()
    started = datetime(2026, 8, 19, 11, 30, tzinfo=UTC)
    if coverage is not None:
        effective_coverage = coverage
    elif complete:
        effective_coverage = ScanCoverage(
            discovered_assets=2,
            scanned_assets=2,
            skipped_assets=0,
            complete=True,
        )
    else:
        effective_coverage = ScanCoverage(
            discovered_assets=2,
            scanned_assets=1,
            skipped_assets=1,
            complete=False,
            issues=(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Permission denied.",
                    asset_path="private/AGENTS.md",
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
            target_root=target_root,
            started_at=started,
            completed_at=started + timedelta(seconds=2),
            git_commit="0123456789abcdef",
            git_dirty=True,
        ),
        findings=findings,
        coverage=effective_coverage,
    )


def test_empty_complete_assessment_has_readable_summary_versions_and_caveat() -> None:
    """A clean supported scope is readable without claiming global safety."""

    rendered = AssessmentTextRenderer().render(make_assessment())

    versions = current_versions()
    assert "AgentSec Assessment" in rendered
    assert "/workspace/project" in rendered
    assert "COMPLETE" in rendered
    assert "report-only; CI risk blocking is disabled" in rendered
    assert "Findings" in rendered
    assert "No findings were produced in the supported scan scope" in rendered
    assert "does not prove that the Agent is globally safe" in rendered
    assert f"Domain schema  {versions.domain_schema}" in rendered
    assert f"Risk model  {versions.risk_model}" in rendered
    assert rendered.endswith("\n")


def test_summary_and_findings_are_sorted_by_severity_then_score() -> None:
    """Critical and High results remain prominent independent of input order."""

    low = make_finding(
        finding_id="finding-low",
        rule_id="MD-OBFUSC-001",
        severity=Severity.LOW,
        score=2.0,
        title="Low signal",
    )
    high = make_finding(
        finding_id="finding-high",
        rule_id="MD-EXEC-001",
        severity=Severity.HIGH,
        score=8.0,
        title="High execution signal",
    )
    critical = make_finding(
        finding_id="finding-critical",
        rule_id="MD-COMBO-001",
        severity=Severity.CRITICAL,
        score=9.0,
        title="Critical composite signal",
        hard_gate=True,
    )
    renderer = AssessmentTextRenderer()

    first = renderer.render(make_assessment(findings=(low, critical, high)))
    second = renderer.render(make_assessment(findings=(high, low, critical)))

    assert first == second
    assert "Findings  3" in first
    assert "Highest severity  CRITICAL" in first
    assert "critical=1 high=1 medium=0 low=1 none=0" in first
    assert "matched=1 (report-only)" in first
    assert (
        first.index("[CRITICAL] Critical composite signal")
        < first.index("[HIGH] High execution signal")
        < first.index("[LOW] Low signal")
    )


def test_finding_detail_has_risk_confidence_gate_evidence_and_remediation() -> None:
    """Each Finding includes the evidence and fields needed for human review."""

    finding = make_finding(
        finding_id="finding-critical",
        rule_id="MD-EXEC-001",
        severity=Severity.CRITICAL,
        score=9.0,
        title="Critical execution signal",
        confidence=EvidenceConfidence.D,
        hard_gate=True,
        excerpt="Run a shell command.\n",
    )

    rendered = AssessmentTextRenderer().render(make_assessment(findings=(finding,)))

    assert "Finding ID  finding-critical" in rendered
    assert "Rule  MD-EXEC-001" in rendered
    assert "Score  9.0" in rendered
    assert "Severity  CRITICAL" in rendered
    assert "Likelihood  moderate" in rendered
    assert "Impact  very_high" in rendered
    assert "Confidence  D" in rendered
    assert "MATCHED (report-only; no CI block)" in rendered
    assert "Location  AGENTS.md:1" in rendered
    assert "Field  markdown:block" in rendered
    assert f"SHA-256  {_HASH_A}" in rendered
    assert "Excerpt  Run a shell command." in rendered
    assert "1. Require explicit approval." in rendered


def test_untrusted_text_is_sanitized_and_not_treated_as_markup() -> None:
    """Secrets, ANSI, bidi, zero-width, brackets, and newlines are terminal safe."""

    secret = "agentsec-test-text-secret"
    finding = make_finding(
        finding_id="finding-secret",
        rule_id="MD-SECRET-001",
        severity=Severity.HIGH,
        score=8.0,
        title="[bold]Unsafe[/bold]\x1b[31m\u202e\u200b",
        excerpt=f"token: {secret}\x1b[2J\u200b\n",
        recommendations=(f"Authorization: Bearer {secret}\x1b[31m",),
    ).model_copy(
        update={
            "description": f"password={secret}\x1b[31m",
        }
    )
    assessment = make_assessment(
        findings=(finding,),
        target_root=f"token={secret}\x1b[31m",
    )

    rendered = AssessmentTextRenderer().render(assessment)

    assert secret not in rendered
    assert "<redacted>" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\u200b" not in rendered
    assert "\\u001b" in rendered
    assert "\\u202e" in rendered
    assert "\\u200b" in rendered
    assert "[bold]Unsafe[/bold]" in rendered


def test_incomplete_coverage_is_never_presented_as_a_clean_pass() -> None:
    """Coverage gaps receive a visible warning even without Findings."""

    rendered = AssessmentTextRenderer().render(make_assessment(complete=False))

    assert "INCOMPLETE" in rendered
    assert "Coverage warning" in rendered
    assert "Scan coverage is incomplete" in rendered
    assert "must not be interpreted as a clean pass" in rendered
    assert "Skipped" in rendered
    assert "assets: 1; coverage issues: 1" in rendered


def test_coverage_details_are_sorted_sanitized_and_scan_wide_is_explicit() -> None:
    """Incomplete reports list stable Issue code, scope, path, and safe reason."""

    secret = "coverage-secret-value"
    first_issue = CoverageIssue(
        code=CoverageIssueCode.RULE_ERROR,
        message=f"token={secret}\x1b[31m",
    )
    second_issue = CoverageIssue(
        code=CoverageIssueCode.UNREADABLE,
        message="Permission denied.\u202e",
        asset_path="private\x1b[31m/AGENTS.md",
    )
    coverage = ScanCoverage(
        discovered_assets=2,
        scanned_assets=0,
        skipped_assets=2,
        complete=False,
        issues=(second_issue, first_issue),
    )
    renderer = AssessmentTextRenderer()

    first = renderer.render(make_assessment(coverage=coverage))
    second = renderer.render(
        make_assessment(
            coverage=coverage.model_copy(
                update={"issues": tuple(reversed(coverage.issues))}
            )
        )
    )

    assert first == second
    assert "Coverage issues (2 total)" in first
    assert "rule_error" in first
    assert "unreadable" in first
    assert "(scan-wide)" in first
    assert "private\\u001b[31m/AGENTS.md" in first
    assert "token=<redacted>" in first
    assert secret not in first
    assert "\x1b" not in first
    assert "\u202e" not in first
    assert "\\u202e" in first
    assert first.index("rule_error") < first.index("unreadable")
    assert "Findings  0" in first


def test_coverage_issue_limit_and_missing_issue_reason_are_visible() -> None:
    """Coverage detail omission and absent structured reasons never look complete."""

    issues = tuple(
        CoverageIssue(
            code=CoverageIssueCode.UNREADABLE,
            message=f"Reason {index}.",
            asset_path=f"item-{index}/AGENTS.md",
        )
        for index in range(2)
    )
    limited = ScanCoverage(
        discovered_assets=2,
        scanned_assets=0,
        skipped_assets=2,
        complete=False,
        issues=issues,
    )
    no_issue = ScanCoverage(
        discovered_assets=1,
        scanned_assets=0,
        skipped_assets=1,
        complete=False,
    )
    renderer = AssessmentTextRenderer(
        limits=AssessmentTextLimits(max_coverage_issues=1)
    )

    limited_text = renderer.render(make_assessment(coverage=limited))
    no_issue_text = renderer.render(make_assessment(coverage=no_issue))

    assert "1 Coverage Issue(s) omitted" in limited_text
    assert "Coverage remains incomplete" in limited_text
    assert "item-0/AGENTS.md" in limited_text
    assert "item-1/AGENTS.md" not in limited_text
    assert "Coverage issues (0 total)" in no_issue_text
    assert "No structured Coverage Issue was retained" in no_issue_text
    assert "1 skipped asset(s)" in no_issue_text
    assert "INCOMPLETE" in no_issue_text


def test_report_limits_make_omission_and_truncation_visible() -> None:
    """Bounded output reports omitted Findings, Evidence, recommendations, and text."""

    first = make_finding(
        finding_id="finding-first",
        rule_id="MD-EXEC-001",
        severity=Severity.HIGH,
        score=8.0,
        title="X" * 80,
        evidence_count=2,
        recommendations=("First recommendation.", "Second recommendation."),
    )
    second = make_finding(
        finding_id="finding-second",
        rule_id="MD-NET-001",
        severity=Severity.MEDIUM,
        score=5.5,
        title="Second finding",
    )
    renderer = AssessmentTextRenderer(
        limits=AssessmentTextLimits(
            max_findings=1,
            max_evidence_per_finding=1,
            max_recommendations_per_finding=1,
            max_text_characters=32,
            console_width=100,
        )
    )

    rendered = renderer.render(make_assessment(findings=(second, first)))

    assert "truncated from 80 chars" in rendered
    assert "1 evidence item(s) omitted" in rendered
    assert "1 recommendation(s) omitted" in rendered
    assert "1 finding(s) omitted by the Text Reporter limit" in rendered
    assert "finding-second" not in rendered


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_findings": 0},
        {"max_evidence_per_finding": 0},
        {"max_recommendations_per_finding": 0},
        {"max_coverage_issues": 0},
        {"max_text_characters": 0},
        {"console_width": 79},
        {"console_width": 241},
    ],
)
def test_text_report_limits_reject_invalid_bounds(kwargs: dict[str, int]) -> None:
    """Invalid output limits fail before any untrusted report content is processed."""

    with pytest.raises(ValueError):
        AssessmentTextLimits(**kwargs)


def test_renderer_rejects_non_assessment_input() -> None:
    """The public seam cannot accidentally render arbitrary attacker objects."""

    with pytest.raises(TypeError, match="Assessment"):
        AssessmentTextRenderer().render("not-an-assessment")  # type: ignore[arg-type]


def test_renderer_has_no_file_shell_or_network_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rich report construction is a pure delivery transformation."""

    finding = make_finding(
        finding_id="finding-side-effect",
        rule_id="MD-EXEC-001",
        severity=Severity.HIGH,
        score=8.0,
        title="Side-effect test",
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Text Reporter attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    rendered = AssessmentTextRenderer().render(make_assessment(findings=(finding,)))

    assert "Side-effect test" in rendered
    assert "\x1b" not in rendered

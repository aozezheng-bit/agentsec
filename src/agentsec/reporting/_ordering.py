"""Deterministic ordering shared by Assessment delivery renderers."""

from __future__ import annotations

from agentsec.domain import (
    AgentAsset,
    AssetChange,
    CoverageIssue,
    Evidence,
    Finding,
    Severity,
)

_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    """Return the stable ascending rank for one Severity."""

    return _SEVERITY_RANK[severity]


def asset_sort_key(asset: AgentAsset) -> tuple[str, str, str, str]:
    """Sort assets independently from collector insertion order."""

    return (
        asset.path,
        asset.asset_type.value,
        asset.source.value,
        asset.sha256,
    )


def change_sort_key(change: AssetChange) -> tuple[str, str, str, str]:
    """Sort file-level changes by stable serialized identity."""

    return (
        change.path,
        change.change_type.value,
        change.before_sha256 or "",
        change.after_sha256 or "",
    )


def coverage_issue_sort_key(issue: CoverageIssue) -> tuple[str, str, str]:
    """Sort Coverage Issues without hiding their original safe message."""

    return (issue.asset_path or "", issue.code.value, issue.message)


def evidence_sort_key(
    evidence: Evidence,
) -> tuple[str, int, int, str, str, str, str]:
    """Sort Evidence by authoritative locator before optional content."""

    return (
        evidence.asset_path or "",
        evidence.start_line or 0,
        evidence.end_line or 0,
        evidence.source_type.value,
        evidence.field or "",
        evidence.content_sha256 or "",
        evidence.excerpt or "",
    )


def finding_sort_key(finding: Finding) -> tuple[int, float, str, str, int, str]:
    """Keep Critical/High Findings prominent and stable across input order."""

    first = min(finding.evidence, key=evidence_sort_key)
    return (
        -severity_rank(finding.severity),
        -finding.score,
        finding.rule_id,
        first.asset_path or "",
        first.start_line or 0,
        finding.finding_id,
    )

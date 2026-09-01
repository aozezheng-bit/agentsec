"""Versioned, schema-backed, safe JSON delivery for final Assessments."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.domain import Assessment, EvidenceConfidence, Finding, Severity
from agentsec.reporting._ordering import (
    asset_sort_key,
    change_sort_key,
    coverage_issue_sort_key,
    evidence_sort_key,
    finding_sort_key,
    severity_rank,
)
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text
from agentsec.versioning import ASSESSMENT_OUTPUT_VERSION

ASSESSMENT_JSON_FORMAT: Literal["agentsec-assessment"] = "agentsec-assessment"
ASSESSMENT_JSON_FORMAT_VERSION = cast(Literal["0.7.0"], ASSESSMENT_OUTPUT_VERSION)
ASSESSMENT_JSON_SCHEMA_FILENAME = "assessment-report.schema.json"

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
NonNegativeInt = Annotated[int, Field(ge=0)]


class _ReportModel(BaseModel):
    """Strict immutable base for the Assessment JSON delivery contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class AssessmentReportPolicy(_ReportModel):
    """Explicit Phase 1 policy semantics for machine consumers."""

    enforcement_mode: Literal["report_only"]
    ci_blocking_enabled: Literal[False]
    global_safety_claimed: Literal[False]


class SeverityCounts(_ReportModel):
    """Fixed-shape counts for every Domain Severity."""

    critical: NonNegativeInt
    high: NonNegativeInt
    medium: NonNegativeInt
    low: NonNegativeInt
    none: NonNegativeInt


class ConfidenceCounts(_ReportModel):
    """Fixed-shape counts for every Evidence Confidence grade."""

    A: NonNegativeInt
    B: NonNegativeInt
    C: NonNegativeInt
    D: NonNegativeInt


class AssessmentReportSummary(_ReportModel):
    """Automation-friendly counts derived from the complete Assessment."""

    assets: NonNegativeInt
    changes: NonNegativeInt
    findings: NonNegativeInt
    highest_severity: Severity
    severity_counts: SeverityCounts
    confidence_counts: ConfidenceCounts
    hard_gate_matches: NonNegativeInt
    cvss_hard_gate_matches: NonNegativeInt
    coverage_discovered_assets: NonNegativeInt
    coverage_scanned_assets: NonNegativeInt
    coverage_skipped_assets: NonNegativeInt
    coverage_complete: bool
    coverage_issues: NonNegativeInt


class AssessmentJsonReport(_ReportModel):
    """Strict public P1-25 Assessment JSON document."""

    format: Literal["agentsec-assessment"]
    format_version: Literal["0.7.0"]
    status: Literal["complete", "incomplete"]
    policy: AssessmentReportPolicy
    summary: AssessmentReportSummary
    assessment: Assessment

    @model_validator(mode="after")
    def derived_fields_must_match_assessment(self) -> AssessmentJsonReport:
        """Reject status or summary values that misrepresent the Assessment."""

        expected_status = (
            "complete" if self.assessment.coverage.complete else "incomplete"
        )
        if self.status != expected_status:
            raise ValueError("report status must match Assessment Coverage")
        expected_summary = _summary(self.assessment.findings, self.assessment)
        if self.summary != expected_summary:
            raise ValueError("report summary must match Assessment content")
        return self


class AssessmentJsonRenderer:
    """Render deterministic JSON without raw untrusted Assessment strings."""

    def __init__(self, *, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor if redactor is not None else SecretRedactor()

    def render(self, assessment: Assessment) -> str:
        """Return one complete schema-backed, sanitized Assessment report."""

        if not isinstance(assessment, Assessment):
            raise TypeError("assessment JSON rendering requires an Assessment")

        normalized = _normalize_assessment(assessment)
        document = AssessmentJsonReport(
            format=ASSESSMENT_JSON_FORMAT,
            format_version=ASSESSMENT_JSON_FORMAT_VERSION,
            status="complete" if normalized.coverage.complete else "incomplete",
            policy=AssessmentReportPolicy(
                enforcement_mode="report_only",
                ci_blocking_enabled=False,
                global_safety_claimed=False,
            ),
            summary=_summary(normalized.findings, normalized),
            assessment=normalized,
        )
        payload = cast(JsonValue, document.model_dump(mode="json"))
        sanitized = _sanitize_json_value(payload, self._safe)
        return (
            json.dumps(
                sanitized,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def _safe(self, value: str) -> str:
        return sanitize_untrusted_text(value, redactor=self._redactor)


def export_assessment_json_schema(output_directory: Path) -> Path:
    """Write the deterministic strict schema for Assessment JSON reports."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / ASSESSMENT_JSON_SCHEMA_FILENAME
    output_path.write_text(
        json.dumps(
            AssessmentJsonReport.model_json_schema(mode="serialization"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def _normalize_assessment(assessment: Assessment) -> Assessment:
    findings = tuple(
        finding.model_copy(
            update={
                "evidence": tuple(sorted(finding.evidence, key=evidence_sort_key)),
            }
        )
        for finding in sorted(assessment.findings, key=finding_sort_key)
    )
    coverage = assessment.coverage.model_copy(
        update={
            "issues": tuple(
                sorted(assessment.coverage.issues, key=coverage_issue_sort_key)
            )
        }
    )
    return assessment.model_copy(
        update={
            "assets": tuple(sorted(assessment.assets, key=asset_sort_key)),
            "changes": tuple(sorted(assessment.changes, key=change_sort_key)),
            "findings": findings,
            "coverage": coverage,
        }
    )


def _summary(
    findings: tuple[Finding, ...],
    assessment: Assessment,
) -> AssessmentReportSummary:
    severity_counts = {severity: 0 for severity in Severity}
    confidence_counts = {confidence: 0 for confidence in EvidenceConfidence}
    for finding in findings:
        severity_counts[finding.severity] += 1
        confidence_counts[finding.confidence] += 1
    highest = max(
        (finding.severity for finding in findings),
        key=severity_rank,
        default=Severity.NONE,
    )
    return AssessmentReportSummary(
        assets=len(assessment.assets),
        changes=len(assessment.changes),
        findings=len(findings),
        highest_severity=highest,
        severity_counts=SeverityCounts(
            critical=severity_counts[Severity.CRITICAL],
            high=severity_counts[Severity.HIGH],
            medium=severity_counts[Severity.MEDIUM],
            low=severity_counts[Severity.LOW],
            none=severity_counts[Severity.NONE],
        ),
        confidence_counts=ConfidenceCounts(
            A=confidence_counts[EvidenceConfidence.A],
            B=confidence_counts[EvidenceConfidence.B],
            C=confidence_counts[EvidenceConfidence.C],
            D=confidence_counts[EvidenceConfidence.D],
        ),
        hard_gate_matches=sum(finding.hard_gate for finding in findings),
        cvss_hard_gate_matches=sum(
            finding.cvss_hard_gate is not None and finding.cvss_hard_gate.triggered
            for finding in findings
        ),
        coverage_discovered_assets=assessment.coverage.discovered_assets,
        coverage_scanned_assets=assessment.coverage.scanned_assets,
        coverage_skipped_assets=assessment.coverage.skipped_assets,
        coverage_complete=assessment.coverage.complete,
        coverage_issues=len(assessment.coverage.issues),
    )


def _sanitize_json_value(
    value: JsonValue,
    sanitizer: Callable[[str], str],
) -> JsonValue:
    if isinstance(value, str):
        return sanitizer(value)
    if isinstance(value, list):
        return [_sanitize_json_value(item, sanitizer) for item in value]
    if isinstance(value, dict):
        return {
            key: _sanitize_json_value(item, sanitizer) for key, item in value.items()
        }
    return value

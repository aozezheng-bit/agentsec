"""P2-26 Text/JSON delivery for explicit local fail-on decisions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from agentsec.domain import Assessment
from agentsec.fail_on import FailOnDecision, evaluate_assessment_fail_on
from agentsec.reporting.assessment import AssessmentTextRenderer
from agentsec.reporting.assessment_json import (
    AssessmentJsonRenderer,
    AssessmentJsonReport,
)
from agentsec.versioning import FAIL_ON_REPORT_OUTPUT_VERSION

FAIL_ON_JSON_FORMAT: Literal["agentsec-assessment-fail-on"] = (
    "agentsec-assessment-fail-on"
)
FAIL_ON_JSON_FORMAT_VERSION = cast(Literal["0.1.0"], FAIL_ON_REPORT_OUTPUT_VERSION)
FAIL_ON_JSON_SCHEMA_FILENAME = "assessment-fail-on-report.schema.json"


class _FailOnReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AssessmentFailOnJsonReport(_FailOnReportModel):
    """Strict wrapper retaining the canonical Assessment report and CLI decision."""

    format: Literal["agentsec-assessment-fail-on"]
    format_version: Literal["0.1.0"]
    decision: FailOnDecision
    assessment_report: AssessmentJsonReport

    @model_validator(mode="after")
    def decision_must_match_assessment(self) -> AssessmentFailOnJsonReport:
        expected = evaluate_assessment_fail_on(
            self.assessment_report.assessment,
            self.decision.threshold,
        )
        if self.decision != expected:
            raise ValueError("fail-on decision must match the embedded Assessment")
        return self


class AssessmentFailOnValidationError(RuntimeError):
    """Safe invalid fail-on report failure without rejected payload values."""


class AssessmentFailOnJsonRenderer:
    """Wrap one canonical sanitized Assessment JSON report with a decision."""

    def __init__(self, *, assessment_renderer: AssessmentJsonRenderer | None = None):
        self._assessment_renderer = assessment_renderer or AssessmentJsonRenderer()

    def build(
        self,
        assessment: Assessment,
        decision: FailOnDecision,
    ) -> AssessmentFailOnJsonReport:
        if not isinstance(assessment, Assessment):
            raise TypeError("fail-on JSON rendering requires an Assessment")
        if not isinstance(decision, FailOnDecision):
            raise TypeError("fail-on JSON rendering requires a FailOnDecision")
        assessment_report = AssessmentJsonReport.model_validate_json(
            self._assessment_renderer.render(assessment)
        )
        return AssessmentFailOnJsonReport(
            format=FAIL_ON_JSON_FORMAT,
            format_version=FAIL_ON_JSON_FORMAT_VERSION,
            decision=decision,
            assessment_report=assessment_report,
        )

    def render(self, assessment: Assessment, decision: FailOnDecision) -> str:
        report = self.build(assessment, decision)
        return (
            json.dumps(
                report.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


class AssessmentFailOnTextRenderer:
    """Prepend a trusted bounded decision summary to the Assessment Text report."""

    def __init__(self, *, assessment_renderer: AssessmentTextRenderer | None = None):
        self._assessment_renderer = assessment_renderer or AssessmentTextRenderer()

    def render(self, assessment: Assessment, decision: FailOnDecision) -> str:
        if not isinstance(assessment, Assessment):
            raise TypeError("fail-on Text rendering requires an Assessment")
        if not isinstance(decision, FailOnDecision):
            raise TypeError("fail-on Text rendering requires a FailOnDecision")
        lines = [
            "AgentSec Fail-On Decision",
            f"Policy version: {decision.policy_version}",
            f"Threshold: {decision.threshold.value.upper()}",
            "Basis: AgentSec deterministic Finding Severity",
            f"Decision: {decision.decision.value.upper()}",
            f"Exit code: {int(decision.exit_code)}",
            f"Coverage complete: {str(decision.coverage_complete).lower()}",
            (
                "Highest observed severity: "
                f"{decision.highest_observed_severity.value.upper()}"
            ),
            f"Matched findings: {len(decision.matched_finding_ids)}",
            (
                "Boundary: explicit local Severity policy; Confidence does not "
                "suppress Severity; runtime capability is not verified"
            ),
            "",
        ]
        return "\n".join(lines) + self._assessment_renderer.render(assessment, decision)


def decode_assessment_fail_on_json(text: str) -> AssessmentFailOnJsonReport:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise AssessmentFailOnValidationError(
            "fail-on report must contain valid JSON"
        ) from error
    if not isinstance(payload, Mapping):
        raise AssessmentFailOnValidationError("fail-on report root must be an object")
    try:
        return AssessmentFailOnJsonReport.model_validate(dict(payload))
    except ValidationError as error:
        raise AssessmentFailOnValidationError(
            "fail-on report failed strict validation"
        ) from error


def export_assessment_fail_on_json_schema(output_directory: Path) -> Path:
    if not isinstance(output_directory, Path):
        raise TypeError("fail-on schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / FAIL_ON_JSON_SCHEMA_FILENAME
    output_path.write_text(
        json.dumps(
            AssessmentFailOnJsonReport.model_json_schema(mode="serialization"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


__all__ = [
    "FAIL_ON_JSON_FORMAT",
    "FAIL_ON_JSON_FORMAT_VERSION",
    "FAIL_ON_JSON_SCHEMA_FILENAME",
    "AssessmentFailOnJsonRenderer",
    "AssessmentFailOnJsonReport",
    "AssessmentFailOnTextRenderer",
    "AssessmentFailOnValidationError",
    "decode_assessment_fail_on_json",
    "export_assessment_fail_on_json_schema",
]

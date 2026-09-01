"""Text/JSON reporting for P2-27 organization Policy scan decisions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from agentsec.domain import Assessment
from agentsec.organization_policy import (
    OrganizationPolicyEvidence,
    OrganizationScanDecision,
    evaluate_organization_scan_policy,
)
from agentsec.reporting.assessment import AssessmentTextRenderer
from agentsec.reporting.assessment_json import (
    AssessmentJsonRenderer,
    AssessmentJsonReport,
)
from agentsec.versioning import ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION

ORGANIZATION_ASSESSMENT_FORMAT: Literal["agentsec-organization-policy-assessment"] = (
    "agentsec-organization-policy-assessment"
)
ORGANIZATION_ASSESSMENT_FORMAT_VERSION = cast(
    Literal["0.3.0"], ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION
)
ORGANIZATION_POLICY_SCHEMA_FILENAME = "organization-policy.schema.json"
ORGANIZATION_ASSESSMENT_SCHEMA_FILENAME = "organization-assessment-report.schema.json"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OrganizationTrustProvenance(_Strict):
    """Trust-source provenance recorded beside the organization decision."""

    trust_mode: Literal["repository_local", "external_trust_root"] = "repository_local"
    policy_digest_pinned: bool = False
    policy_digest_verified: bool = False
    expected_policy_sha256: str | None = None


class OrganizationAssessmentJsonReport(_Strict):
    format: Literal["agentsec-organization-policy-assessment"]
    format_version: Literal["0.3.0"]
    organization_policy: OrganizationPolicyEvidence
    decision: OrganizationScanDecision
    assessment_report: AssessmentJsonReport
    trust: OrganizationTrustProvenance = OrganizationTrustProvenance()

    @model_validator(mode="after")
    def decision_must_match(self) -> OrganizationAssessmentJsonReport:
        expected = evaluate_organization_scan_policy(
            self.assessment_report.assessment,
            self.organization_policy,
            evaluated_on=self.decision.evaluated_on,
        )
        if self.decision != expected:
            raise ValueError("organization decision must match embedded Assessment")
        return self


class OrganizationAssessmentValidationError(RuntimeError):
    pass


class OrganizationAssessmentJsonRenderer:
    def __init__(self, *, assessment_renderer: AssessmentJsonRenderer | None = None):
        self._assessment_renderer = assessment_renderer or AssessmentJsonRenderer()

    def render(
        self,
        assessment: Assessment,
        evidence: OrganizationPolicyEvidence,
        decision: OrganizationScanDecision,
        *,
        trust: OrganizationTrustProvenance | None = None,
    ) -> str:
        report = OrganizationAssessmentJsonReport(
            format=ORGANIZATION_ASSESSMENT_FORMAT,
            format_version=ORGANIZATION_ASSESSMENT_FORMAT_VERSION,
            organization_policy=evidence,
            decision=decision,
            assessment_report=AssessmentJsonReport.model_validate_json(
                self._assessment_renderer.render(assessment)
            ),
            trust=trust or OrganizationTrustProvenance(),
        )
        return (
            json.dumps(
                report.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


class OrganizationAssessmentTextRenderer:
    def __init__(self, *, assessment_renderer: AssessmentTextRenderer | None = None):
        self._assessment_renderer = assessment_renderer or AssessmentTextRenderer()

    def render(
        self,
        assessment: Assessment,
        evidence: OrganizationPolicyEvidence,
        decision: OrganizationScanDecision,
        *,
        trust: OrganizationTrustProvenance | None = None,
    ) -> str:
        expected = evaluate_organization_scan_policy(
            assessment, evidence, evaluated_on=decision.evaluated_on
        )
        if decision != expected:
            raise ValueError("organization Text decision is inconsistent")
        policy = evidence.policy
        effective_trust = trust or OrganizationTrustProvenance()
        lines = [
            "AgentSec Organization Policy Decision",
            f"Policy: {policy.policy_id} ({policy.policy_version})",
            f"Policy SHA-256: {evidence.source_sha256}",
            (
                f"Trust mode: {effective_trust.trust_mode}; "
                "policy digest "
                + (
                    "pinned and verified"
                    if effective_trust.policy_digest_verified
                    else "not pinned"
                )
            ),
            f"Mode: {policy.enforcement_mode.upper()}",
            f"Enabled: {str(policy.enabled).lower()}",
            (
                "Threshold: "
                + (policy.scan.fail_on.value.upper() if policy.scan.fail_on else "-")
            ),
            f"Configured rules: {len(policy.scan.blocking_rule_ids)}",
            f"Decision: {decision.decision.value.upper()}",
            f"Exit code: {decision.exit_code}",
            f"Matched findings: {len(decision.matched_finding_ids)}",
            f"Waived findings: {len(decision.waived_finding_ids)}",
            f"Blocking findings: {len(decision.blocking_finding_ids)}",
            f"Applied waivers: {len(decision.applied_waiver_ids)}",
            f"Expired waivers: {len(decision.expired_waiver_ids)}",
            f"Evaluated on: {decision.evaluated_on.isoformat()}",
            "Boundary: deterministic organization Policy; no LLM/runtime authority",
            "",
        ]
        policy_summary = (
            f"organization policy {policy.policy_id}; mode={policy.enforcement_mode}; "
            f"enabled={str(policy.enabled).lower()}"
        )
        return "\n".join(lines) + self._assessment_renderer.render(
            assessment,
            policy_summary=policy_summary,
        )


def decode_organization_assessment_json(text: str) -> OrganizationAssessmentJsonReport:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise OrganizationAssessmentValidationError(
            "organization report must contain valid JSON"
        ) from error
    if not isinstance(payload, Mapping):
        raise OrganizationAssessmentValidationError(
            "organization report root must be an object"
        )
    try:
        return OrganizationAssessmentJsonReport.model_validate(dict(payload))
    except ValidationError as error:
        raise OrganizationAssessmentValidationError(
            "organization report failed strict validation"
        ) from error


def _export(model: type[BaseModel], directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(
        json.dumps(
            model.model_json_schema(mode="serialization"), indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def export_organization_policy_json_schema(output_directory: Path) -> Path:
    from agentsec.organization_policy import OrganizationPolicy

    return _export(
        OrganizationPolicy,
        output_directory,
        ORGANIZATION_POLICY_SCHEMA_FILENAME,
    )


def export_organization_assessment_json_schema(output_directory: Path) -> Path:
    return _export(
        OrganizationAssessmentJsonReport,
        output_directory,
        ORGANIZATION_ASSESSMENT_SCHEMA_FILENAME,
    )


__all__ = [
    "ORGANIZATION_ASSESSMENT_FORMAT",
    "ORGANIZATION_ASSESSMENT_FORMAT_VERSION",
    "ORGANIZATION_ASSESSMENT_SCHEMA_FILENAME",
    "ORGANIZATION_POLICY_SCHEMA_FILENAME",
    "OrganizationAssessmentJsonRenderer",
    "OrganizationAssessmentJsonReport",
    "OrganizationAssessmentTextRenderer",
    "OrganizationAssessmentValidationError",
    "OrganizationTrustProvenance",
    "decode_organization_assessment_json",
    "export_organization_assessment_json_schema",
    "export_organization_policy_json_schema",
]

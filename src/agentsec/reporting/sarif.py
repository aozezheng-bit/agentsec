"""Strict SARIF 2.1.0 reporting for AgentSec findings and scoring results."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, cast
from urllib.parse import quote

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agentsec import __version__
from agentsec.application import AgenticScoreResult, CapabilityAssessmentResult
from agentsec.capability_rules import CapabilityRuleFinding, CapabilityRuleLanguage
from agentsec.domain import Assessment, Finding, Severity
from agentsec.fail_on import FailOnDecision, evaluate_assessment_fail_on
from agentsec.organization_policy import (
    OrganizationPolicyEvidence,
    OrganizationScanDecision,
    evaluate_organization_scan_policy,
)
from agentsec.reporting.safety import sanitize_untrusted_text
from agentsec.risk import OverallScoreAssessment
from agentsec.versioning import SARIF_REPORTER_VERSION

SARIF_VERSION: Literal["2.1.0"] = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)
SARIF_REPORT_FORMAT = "sarif"
SARIF_OVERALL_RULE_ID = "AGENTSEC-OVERALL-001"
SARIF_FINDING_FINGERPRINT_KEY = "agentsecFindingId/v1"
SARIF_OVERALL_FINGERPRINT_KEY = "agentsecOverallManifestSha256/v1"
_SARIF_FINGERPRINT_KEY_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/v[1-9]\d*$"
)

SarifLevel = Literal["none", "note", "warning", "error"]
JsonProperty = str | int | float | bool | None | list[str]


class _SarifModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class SarifMessage(_SarifModel):
    text: str


class SarifArtifactLocation(_SarifModel):
    uri: str
    uriBaseId: Literal["%SRCROOT%"] = "%SRCROOT%"


class SarifRegion(_SarifModel):
    startLine: Annotated[int, Field(ge=1)]
    endLine: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def lines_must_be_coherent(self) -> SarifRegion:
        if self.endLine is not None and self.endLine < self.startLine:
            raise ValueError("SARIF region endLine must not precede startLine")
        return self


class SarifPhysicalLocation(_SarifModel):
    artifactLocation: SarifArtifactLocation
    region: SarifRegion | None = None


class SarifLocation(_SarifModel):
    physicalLocation: SarifPhysicalLocation


class SarifReportingConfiguration(_SarifModel):
    level: SarifLevel


class SarifReportingDescriptor(_SarifModel):
    id: str
    name: str
    shortDescription: SarifMessage
    fullDescription: SarifMessage
    help: SarifMessage
    defaultConfiguration: SarifReportingConfiguration
    properties: dict[str, JsonProperty]


class SarifToolComponent(_SarifModel):
    name: Literal["AgentSec"] = "AgentSec"
    version: str
    semanticVersion: str
    rules: tuple[SarifReportingDescriptor, ...]
    properties: dict[str, JsonProperty]


class SarifTool(_SarifModel):
    driver: SarifToolComponent


class SarifResult(_SarifModel):
    ruleId: str
    ruleIndex: Annotated[int, Field(ge=0)]
    level: SarifLevel
    message: SarifMessage
    locations: tuple[SarifLocation, ...] = ()
    partialFingerprints: dict[str, str]
    properties: dict[str, JsonProperty]

    @field_validator("partialFingerprints")
    @classmethod
    def fingerprint_keys_must_be_versioned(
        cls, value: dict[str, str]
    ) -> dict[str, str]:
        if not value:
            raise ValueError("SARIF partialFingerprints must not be empty")
        if any(_SARIF_FINGERPRINT_KEY_PATTERN.fullmatch(key) is None for key in value):
            raise ValueError("SARIF partialFingerprint keys must be versioned")
        if any(not fingerprint for fingerprint in value.values()):
            raise ValueError("SARIF partialFingerprint values must not be empty")
        return value


class SarifInvocation(_SarifModel):
    executionSuccessful: bool
    properties: dict[str, JsonProperty]


class SarifRun(_SarifModel):
    tool: SarifTool
    results: tuple[SarifResult, ...]
    invocations: tuple[SarifInvocation, ...]
    properties: dict[str, JsonProperty]

    @model_validator(mode="after")
    def rule_indices_must_match(self) -> SarifRun:
        rules = self.tool.driver.rules
        for result in self.results:
            if result.ruleIndex >= len(rules):
                raise ValueError("SARIF result ruleIndex is out of range")
            if rules[result.ruleIndex].id != result.ruleId:
                raise ValueError("SARIF result ruleId and ruleIndex are inconsistent")
        return self


class SarifLog(_SarifModel):
    schema_uri: Literal[
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
    ] = Field(alias="$schema")
    version: Literal["2.1.0"]
    runs: tuple[SarifRun, ...]

    @model_validator(mode="after")
    def log_must_have_one_run(self) -> SarifLog:
        if len(self.runs) != 1:
            raise ValueError("AgentSec SARIF output requires exactly one run")
        return self


class SarifValidationError(RuntimeError):
    """Safe invalid-SARIF failure without exposing payload content."""


def encode_sarif_json(report: SarifLog) -> str:
    if not isinstance(report, SarifLog):
        raise TypeError("report must be SarifLog")
    return (
        json.dumps(
            report.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def decode_sarif_json(text: str) -> SarifLog:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise SarifValidationError("SARIF output must contain valid JSON") from error
    if not isinstance(payload, Mapping):
        raise SarifValidationError("SARIF output root must be an object")
    try:
        return SarifLog.model_validate(dict(payload))
    except ValidationError as error:
        raise SarifValidationError("SARIF output failed strict validation") from error


class AssessmentSarifRenderer:
    """Render Phase 1 Finding records as one SARIF 2.1.0 run."""

    def build(
        self,
        assessment: Assessment,
        fail_on_decision: FailOnDecision | None = None,
        organization_policy: OrganizationPolicyEvidence | None = None,
        organization_decision: OrganizationScanDecision | None = None,
    ) -> SarifLog:
        if not isinstance(assessment, Assessment):
            raise TypeError("Assessment SARIF rendering requires Assessment")
        if fail_on_decision is not None:
            if not isinstance(fail_on_decision, FailOnDecision):
                raise TypeError("Assessment SARIF fail-on context is invalid")
            expected = evaluate_assessment_fail_on(
                assessment, fail_on_decision.threshold
            )
            if fail_on_decision != expected:
                raise ValueError("Assessment SARIF fail-on decision is inconsistent")
        if fail_on_decision is not None and organization_policy is not None:
            raise ValueError("Assessment SARIF policy contexts are mutually exclusive")
        if (organization_policy is None) != (organization_decision is None):
            raise ValueError("Assessment SARIF organization context is incomplete")
        if organization_policy is not None and organization_decision is not None:
            expected_org = evaluate_organization_scan_policy(
                assessment,
                organization_policy,
                evaluated_on=organization_decision.evaluated_on,
            )
            if organization_decision != expected_org:
                raise ValueError(
                    "Assessment SARIF organization decision is inconsistent"
                )
        ordered = tuple(
            sorted(
                assessment.findings,
                key=lambda item: (item.rule_id, item.finding_id),
            )
        )
        rules = _domain_rules(ordered)
        rule_indices = {item.id: index for index, item in enumerate(rules)}
        results = tuple(
            _domain_result(
                item,
                rule_indices[item.rule_id],
                fail_on_decision=fail_on_decision,
                organization_decision=organization_decision,
            )
            for item in ordered
        )
        properties: dict[str, JsonProperty] = {
            "agentsecReportKind": "assessment",
            "agentsecSchemaVersion": assessment.metadata.schema_version,
            "agentsecRulePackVersion": assessment.metadata.rule_pack_version,
            "agentsecRiskModelVersion": assessment.metadata.risk_model_version,
            "agentsecCoverageComplete": assessment.coverage.complete,
            "agentsecCiBlockingEnabled": fail_on_decision is not None,
            "agentsecRuntimeCapabilityVerified": False,
        }
        invocation_properties: dict[str, JsonProperty] = {}
        if fail_on_decision is not None:
            properties.update(
                {
                    "agentsecEnforcementMode": "fail_on_severity",
                    "agentsecFailOnPolicyVersion": (fail_on_decision.policy_version),
                    "agentsecFailOnThreshold": fail_on_decision.threshold.value,
                    "agentsecFailOnDecision": fail_on_decision.decision.value,
                    "agentsecFailOnExitCode": int(fail_on_decision.exit_code),
                    "agentsecFailOnMatchedFindingIds": list(
                        fail_on_decision.matched_finding_ids
                    ),
                }
            )
            invocation_properties["agentsecFailOnEnabled"] = True
        if organization_policy is not None and organization_decision is not None:
            policy = organization_policy.policy
            properties.update(
                {
                    "agentsecCiBlockingEnabled": (
                        organization_decision.enforcement_active
                    ),
                    "agentsecEnforcementMode": "organization_policy",
                    "agentsecOrganizationPolicySchemaVersion": policy.schema_version,
                    "agentsecOrganizationPolicyId": policy.policy_id,
                    "agentsecOrganizationPolicyVersion": policy.policy_version,
                    "agentsecOrganizationPolicySha256": (
                        organization_policy.source_sha256
                    ),
                    "agentsecOrganizationPolicyThreshold": (
                        policy.scan.fail_on.value if policy.scan.fail_on else None
                    ),
                    "agentsecOrganizationPolicyRuleIds": list(
                        policy.scan.blocking_rule_ids
                    ),
                    "agentsecOrganizationPolicyDecision": (
                        organization_decision.decision.value
                    ),
                    "agentsecOrganizationPolicyExitCode": (
                        organization_decision.exit_code
                    ),
                    "agentsecOrganizationPolicyMatchedFindingIds": list(
                        organization_decision.matched_finding_ids
                    ),
                    "agentsecOrganizationPolicyWaivedFindingIds": list(
                        organization_decision.waived_finding_ids
                    ),
                    "agentsecOrganizationPolicyBlockingFindingIds": list(
                        organization_decision.blocking_finding_ids
                    ),
                    "agentsecOrganizationPolicyAppliedWaiverIds": list(
                        organization_decision.applied_waiver_ids
                    ),
                    "agentsecOrganizationPolicyExpiredWaiverIds": list(
                        organization_decision.expired_waiver_ids
                    ),
                    "agentsecOrganizationPolicyEvaluatedOn": (
                        organization_decision.evaluated_on.isoformat()
                    ),
                }
            )
            invocation_properties["agentsecOrganizationPolicyEnabled"] = True
        run = _run(
            rules=rules,
            results=results,
            execution_successful=True,
            coverage_complete=assessment.coverage.complete,
            properties=properties,
            report_only=(
                fail_on_decision is None
                and not (
                    organization_decision is not None
                    and organization_decision.enforcement_active
                )
            ),
            invocation_properties=invocation_properties,
        )
        return _sarif_log(run)

    def render(
        self,
        assessment: Assessment,
        fail_on_decision: FailOnDecision | None = None,
        organization_policy: OrganizationPolicyEvidence | None = None,
        organization_decision: OrganizationScanDecision | None = None,
    ) -> str:
        return encode_sarif_json(
            self.build(
                assessment,
                fail_on_decision,
                organization_policy,
                organization_decision,
            )
        )


class CapabilityAssessmentSarifRenderer:
    """Render structured Capability Findings as SARIF 2.1.0."""

    def build(self, result: CapabilityAssessmentResult) -> SarifLog:
        if not isinstance(result, CapabilityAssessmentResult):
            raise TypeError("Capability SARIF rendering requires assessment result")
        ordered = tuple(sorted(result.rules.findings, key=lambda item: item.sort_key()))
        rules = _capability_rules(ordered)
        rule_indices = {item.id: index for index, item in enumerate(rules)}
        results = tuple(
            _capability_result(item, rule_indices[item.rule_id]) for item in ordered
        )
        run = _run(
            rules=rules,
            results=results,
            execution_successful=result.rules.complete,
            coverage_complete=result.complete,
            properties={
                "agentsecReportKind": "capability_assessment",
                "agentsecManifestSchemaVersion": (
                    result.analysis.manifest.schema_version
                ),
                "agentsecCapabilityRulePackVersion": (
                    result.rules.capability_rule_pack_version
                ),
                "agentsecCapabilityRiskModelVersion": (
                    result.rules.capability_risk_model_version
                ),
                "agentsecCoverageComplete": result.complete,
                "agentsecCiBlockingEnabled": False,
                "agentsecRuntimeCapabilityVerified": False,
            },
        )
        return _sarif_log(run)

    def render(self, result: CapabilityAssessmentResult) -> str:
        return encode_sarif_json(self.build(result))


class OverallScoreSarifRenderer:
    """Render one P2-23 Overall Score as a SARIF management result."""

    def build(self, assessment: OverallScoreAssessment) -> SarifLog:
        if not isinstance(assessment, OverallScoreAssessment):
            raise TypeError("Overall Score SARIF rendering requires assessment")
        level = _level(assessment.severity)
        rule = SarifReportingDescriptor(
            id=SARIF_OVERALL_RULE_ID,
            name="AgentSecOverallScore",
            shortDescription=SarifMessage(text="AgentSec Overall risk score"),
            fullDescription=SarifMessage(
                text=(
                    "High-water Technical, Drift, and Governance risk with an "
                    "independent qualified report-only Hard Gate floor."
                )
            ),
            help=SarifMessage(
                text=(
                    "Review component scores, qualified Gate evidence, Coverage, "
                    "and runtime-verification limitations before policy action."
                )
            ),
            defaultConfiguration=SarifReportingConfiguration(level=level),
            properties={
                "agentsecCategory": "overall_risk",
                "agentsecReporterVersion": SARIF_REPORTER_VERSION,
            },
        )
        result = SarifResult(
            ruleId=rule.id,
            ruleIndex=0,
            level=level,
            message=SarifMessage(
                text=(
                    f"AgentSec Overall Score is {assessment.overall_score:.1f} "
                    f"({assessment.severity.value})."
                )
            ),
            partialFingerprints={
                SARIF_OVERALL_FINGERPRINT_KEY: assessment.manifest_sha256,
            },
            properties={
                "agentsecTechnicalScore": assessment.technical_score,
                "agentsecDriftScore": assessment.drift_score,
                "agentsecGovernanceScore": assessment.governance_score,
                "agentsecBaseOverallScore": assessment.base_overall_score,
                "agentsecOverallScore": assessment.overall_score,
                "agentsecHardGateTriggered": assessment.hard_gate.triggered,
                "agentsecHardGateFloor": (
                    assessment.hard_gate.floor.value
                    if assessment.hard_gate.floor
                    else None
                ),
                "agentsecHardGateBlocks": False,
                "agentsecCiBlockingEnabled": False,
                "agentsecRuntimeCapabilityVerified": False,
            },
        )
        run = _run(
            rules=(rule,),
            results=(result,),
            execution_successful=True,
            coverage_complete=True,
            properties={
                "agentsecReportKind": "overall_score",
                "agentsecOverallScoreModelVersion": assessment.model_version,
                "agentsecCiBlockingEnabled": False,
            },
        )
        return _sarif_log(run)

    def render(self, assessment: OverallScoreAssessment) -> str:
        return encode_sarif_json(self.build(assessment))


class AgenticAssessmentSarifRenderer:
    """Render the P2-EXIT-03 Integrated Agentic Score chain as SARIF 2.1.0."""

    def build(self, result: AgenticScoreResult) -> SarifLog:
        if not isinstance(result, AgenticScoreResult):
            raise TypeError("Agentic assessment SARIF rendering requires score result")
        overall = result.overall
        components = (
            (
                "AGENTSEC-AGENTIC-TECHNICAL-001",
                "AgentSecAgenticTechnicalScore",
                "Agentic Technical risk score",
                result.technical.severity,
                result.technical.technical_score,
            ),
            (
                "AGENTSEC-AGENTIC-DRIFT-001",
                "AgentSecAgenticDriftScore",
                "Agentic Capability Drift risk score",
                result.drift.severity,
                result.drift.drift_score,
            ),
            (
                "AGENTSEC-AGENTIC-GOVERNANCE-001",
                "AgentSecAgenticGovernanceScore",
                "Agentic Governance risk score",
                result.governance.severity,
                result.governance.governance_score,
            ),
            (
                SARIF_OVERALL_RULE_ID,
                "AgentSecAgenticOverallScore",
                "Integrated Agentic Overall risk score including qualified Gate floor",
                overall.severity,
                overall.overall_score,
            ),
        )
        rules = tuple(
            SarifReportingDescriptor(
                id=rule_id,
                name=name,
                shortDescription=SarifMessage(text=description),
                fullDescription=SarifMessage(
                    text=(
                        "Deterministic component of the Integrated Agentic Score. "
                        "Report-only: it never blocks CI."
                    )
                ),
                help=SarifMessage(
                    text=(
                        "Review the JSON or Text Agentic assessment for evidence, "
                        "context provenance, Coverage, and Unknown state."
                    )
                ),
                defaultConfiguration=SarifReportingConfiguration(
                    level=_level(severity)
                ),
                properties={
                    "agentsecCategory": "agentic_score",
                    "agentsecReporterVersion": SARIF_REPORTER_VERSION,
                },
            )
            for rule_id, name, description, severity, _score in components
        )
        results = tuple(
            SarifResult(
                ruleId=rule_id,
                ruleIndex=index,
                level=_level(severity),
                message=SarifMessage(
                    text=f"{description}: {score:.1f} ({severity.value})."
                ),
                partialFingerprints={
                    SARIF_OVERALL_FINGERPRINT_KEY: result.after_manifest_sha256,
                },
                properties={
                    "agentsecScore": score,
                    "agentsecSeverity": severity.value,
                    "agentsecCiBlockingEnabled": False,
                    "agentsecRuntimeCapabilityVerified": False,
                },
            )
            for index, (rule_id, _name, description, severity, score) in enumerate(
                components
            )
        )
        run = _run(
            rules=rules,
            results=results,
            execution_successful=result.analysis.complete,
            coverage_complete=result.analysis.manifest.coverage.complete,
            properties={
                "agentsecReportKind": "agentic_assessment",
                "agentsecAgentId": result.analysis.manifest.identity.agent_id,
                "agentsecBeforeManifestSha256": result.before_manifest_sha256,
                "agentsecAfterManifestSha256": result.after_manifest_sha256,
                "agentsecHardGateTriggered": overall.hard_gate.triggered,
                "agentsecHardGateFloor": (
                    overall.hard_gate.floor.value if overall.hard_gate.floor else None
                ),
                "agentsecHardGateBlocks": False,
                "agentsecCoverageComplete": (
                    result.analysis.manifest.coverage.complete
                ),
                "agentsecCiBlockingEnabled": False,
                "agentsecRuntimeCapabilityVerified": False,
            },
            report_only=True,
        )
        return _sarif_log(run)

    def render(self, result: AgenticScoreResult) -> str:
        return encode_sarif_json(self.build(result))


def _sarif_log(run: SarifRun) -> SarifLog:
    return SarifLog.model_validate(
        {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": (run,)}
    )


def _run(
    *,
    rules: tuple[SarifReportingDescriptor, ...],
    results: tuple[SarifResult, ...],
    execution_successful: bool,
    coverage_complete: bool,
    properties: dict[str, JsonProperty],
    report_only: bool = True,
    invocation_properties: dict[str, JsonProperty] | None = None,
) -> SarifRun:
    return SarifRun(
        tool=SarifTool(
            driver=SarifToolComponent(
                version=__version__,
                semanticVersion=__version__,
                rules=rules,
                properties={
                    "agentsecSarifReporterVersion": SARIF_REPORTER_VERSION,
                    "agentsecSarifVersion": SARIF_VERSION,
                },
            )
        ),
        results=results,
        invocations=(
            SarifInvocation(
                executionSuccessful=execution_successful,
                properties={
                    "agentsecCoverageComplete": coverage_complete,
                    "agentsecReportOnly": report_only,
                    **(invocation_properties or {}),
                },
            ),
        ),
        properties=properties,
    )


def _domain_rules(
    findings: tuple[Finding, ...],
) -> tuple[SarifReportingDescriptor, ...]:
    by_rule: dict[str, Finding] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, finding)
    return tuple(_domain_rule(by_rule[rule_id]) for rule_id in sorted(by_rule))


def _domain_rule(finding: Finding) -> SarifReportingDescriptor:
    return SarifReportingDescriptor(
        id=finding.rule_id,
        name=_safe_name(finding.rule_id),
        shortDescription=SarifMessage(text=_trusted(finding.title)),
        fullDescription=SarifMessage(text=_trusted(finding.description)),
        help=SarifMessage(
            text=" ".join(_trusted(item) for item in finding.recommendations)
        ),
        defaultConfiguration=SarifReportingConfiguration(
            level=_level(finding.severity)
        ),
        properties={
            "agentsecCategory": finding.category.value,
            "agentsecReporterVersion": SARIF_REPORTER_VERSION,
        },
    )


def _domain_result(
    finding: Finding,
    rule_index: int,
    *,
    fail_on_decision: FailOnDecision | None = None,
    organization_decision: OrganizationScanDecision | None = None,
) -> SarifResult:
    locations = tuple(
        location
        for evidence in finding.evidence
        if (
            location := _location(
                evidence.asset_path, evidence.start_line, evidence.end_line
            )
        )
        is not None
    )
    properties: dict[str, JsonProperty] = {
        "agentsecFindingId": finding.finding_id,
        "agentsecCategory": finding.category.value,
        "agentsecScore": finding.score,
        "agentsecSeverity": finding.severity.value,
        "agentsecConfidence": finding.confidence.value,
        "agentsecHardGate": finding.hard_gate,
        "agentsecCiBlockingEnabled": False,
        "agentsecRuntimeCapabilityVerified": False,
    }
    if fail_on_decision is not None:
        properties["agentsecFailOnMatched"] = (
            finding.finding_id in fail_on_decision.matched_finding_ids
        )
    if organization_decision is not None:
        properties["agentsecOrganizationPolicyMatched"] = (
            finding.finding_id in organization_decision.matched_finding_ids
        )
        properties["agentsecOrganizationPolicyWaived"] = (
            finding.finding_id in organization_decision.waived_finding_ids
        )
        properties["agentsecOrganizationPolicyBlocks"] = (
            finding.finding_id in organization_decision.blocking_finding_ids
        )
    if finding.vulnerability is not None:
        properties["agentsecVulnerabilityId"] = finding.vulnerability.vulnerability_id
        properties["agentsecCveId"] = finding.vulnerability.cve_id
        properties["agentsecCweIds"] = list(finding.vulnerability.cwe_ids)
    if finding.cvss is not None:
        properties["agentsecCvssVersion"] = finding.cvss.version
        properties["agentsecCvssBaseScore"] = finding.cvss.base_score
        properties["agentsecCvssEffectiveScore"] = finding.cvss.effective_score
    if finding.cvss_hard_gate is not None:
        properties["agentsecCvssHardGateMatched"] = (
            finding.cvss_hard_gate.match is not None
        )
    return SarifResult(
        ruleId=finding.rule_id,
        ruleIndex=rule_index,
        level=_level(finding.severity),
        message=SarifMessage(
            text=f"{_trusted(finding.title)}: {_trusted(finding.description)}"
        ),
        locations=locations,
        partialFingerprints={SARIF_FINDING_FINGERPRINT_KEY: finding.finding_id},
        properties=properties,
    )


def _capability_rules(
    findings: tuple[CapabilityRuleFinding, ...],
) -> tuple[SarifReportingDescriptor, ...]:
    by_rule: dict[str, CapabilityRuleFinding] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, finding)
    return tuple(_capability_rule(by_rule[rule_id]) for rule_id in sorted(by_rule))


def _capability_rule(finding: CapabilityRuleFinding) -> SarifReportingDescriptor:
    text = finding.text_for(CapabilityRuleLanguage.EN)
    return SarifReportingDescriptor(
        id=finding.rule_id,
        name=_safe_name(finding.rule_id),
        shortDescription=SarifMessage(text=_trusted(text.title)),
        fullDescription=SarifMessage(text=_trusted(text.description)),
        help=SarifMessage(
            text=" ".join(_trusted(item) for item in text.recommendations)
        ),
        defaultConfiguration=SarifReportingConfiguration(
            level=_level(finding.severity)
        ),
        properties={
            "agentsecCategory": finding.category.value,
            "agentsecCapabilityRulePackVersion": finding.capability_rule_pack_version,
            "agentsecCapabilityRiskModelVersion": finding.capability_risk_model_version,
            "agentsecReporterVersion": SARIF_REPORTER_VERSION,
        },
    )


def _capability_result(finding: CapabilityRuleFinding, rule_index: int) -> SarifResult:
    text = finding.text_for(CapabilityRuleLanguage.EN)
    locations = tuple(
        location
        for evidence in finding.evidence
        if (
            location := _location(
                evidence.path,
                evidence.start_line,
                evidence.end_line,
            )
        )
        is not None
    )
    properties: dict[str, JsonProperty] = {
        "agentsecFindingId": finding.finding_id,
        "agentsecCategory": finding.category.value,
        "agentsecScore": finding.score,
        "agentsecSeverity": finding.severity.value,
        "agentsecConfidence": finding.confidence.value,
        "agentsecCorrelation": finding.correlation.value,
        "agentsecRelatedIds": list(finding.related_ids),
        "agentsecHardGate": False,
        "agentsecCiBlockingEnabled": False,
        "agentsecRuntimeCapabilityVerified": False,
    }
    if finding.capability_shadow_gate is not None:
        properties["agentsecShadowGateId"] = finding.capability_shadow_gate.gate_id
        properties["agentsecShadowGateMatched"] = finding.capability_shadow_gate.matched
        properties["agentsecShadowGateBlocks"] = False
    return SarifResult(
        ruleId=finding.rule_id,
        ruleIndex=rule_index,
        level=_level(finding.severity),
        message=SarifMessage(
            text=f"{_trusted(text.title)}: {_trusted(text.description)}"
        ),
        locations=locations,
        partialFingerprints={SARIF_FINDING_FINGERPRINT_KEY: finding.finding_id},
        properties=properties,
    )


def _location(
    path: str | None,
    start_line: int | None,
    end_line: int | None,
) -> SarifLocation | None:
    if path is None:
        return None
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
    uri = quote(normalized, safe="/._-")
    region = (
        SarifRegion(startLine=start_line, endLine=end_line)
        if start_line is not None
        else None
    )
    return SarifLocation(
        physicalLocation=SarifPhysicalLocation(
            artifactLocation=SarifArtifactLocation(uri=uri),
            region=region,
        )
    )


def _level(severity: Severity) -> SarifLevel:
    return cast(
        SarifLevel,
        {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.NONE: "none",
        }[severity],
    )


def _trusted(value: str) -> str:
    return sanitize_untrusted_text(value)[:2048]


def _safe_name(rule_id: str) -> str:
    return (
        "".join(character for character in rule_id if character.isalnum())
        or "AgentSecRule"
    )


__all__ = [
    "SARIF_OVERALL_RULE_ID",
    "SARIF_REPORT_FORMAT",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "AssessmentSarifRenderer",
    "CapabilityAssessmentSarifRenderer",
    "OverallScoreSarifRenderer",
    "SarifLog",
    "SarifValidationError",
    "decode_sarif_json",
    "encode_sarif_json",
]

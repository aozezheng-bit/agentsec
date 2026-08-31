"""Versioned strict JSON delivery for deterministic Capability Assessments."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentsec.application import (
    AgentAnalysisErrorCode,
    AgentAnalysisStage,
    AnalysisStageStatus,
    CapabilityAssessmentResult,
)
from agentsec.capability_rules import (
    CapabilityCorrelation,
    CapabilityRuleFinding,
    CapabilityRuleLanguage,
)
from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.manifests import (
    AgentManifest,
    ManifestPermissionAction,
)
from agentsec.risk import ImpactDimension, NistRiskLevel
from agentsec.versioning import (
    CAPABILITY_ASSESSMENT_OUTPUT_VERSION,
    CAPABILITY_SHADOW_GATE_VERSION,
    VersionSet,
    can_read_interface_version,
    parse_interface_version,
)

CAPABILITY_ASSESSMENT_JSON_FORMAT: Literal["agentsec-capability-assessment"] = (
    "agentsec-capability-assessment"
)
CAPABILITY_ASSESSMENT_JSON_FORMAT_VERSION = cast(
    Literal["0.2.0"], CAPABILITY_ASSESSMENT_OUTPUT_VERSION
)
CAPABILITY_ASSESSMENT_JSON_SCHEMA_FILENAME = "capability-assessment.schema.json"
NonNegativeInt = Annotated[int, Field(ge=0)]


class _ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class CapabilityAssessmentValidationCode(StrEnum):
    """Stable compatibility-first validation failures."""

    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_FORMAT = "missing_format"
    INVALID_FORMAT = "invalid_format"
    MISSING_FORMAT_VERSION = "missing_format_version"
    INVALID_FORMAT_VERSION = "invalid_format_version"
    UNSUPPORTED_FORMAT_VERSION = "unsupported_format_version"
    INVALID_PAYLOAD = "invalid_payload"


class CapabilityAssessmentValidationError(RuntimeError):
    """Safe report validation error exposing only trusted field paths."""

    def __init__(
        self,
        code: CapabilityAssessmentValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


class CapabilityAssessmentPolicy(_ReportModel):
    """Explicit non-enforcement and static-analysis semantics."""

    enforcement_mode: Literal["report_only"]
    ci_blocking_enabled: Literal[False]
    global_safety_claimed: Literal[False]
    runtime_capability_verified: Literal[False]


class CapabilityAssessmentVersions(_ReportModel):
    """Complete version vector retained by the report wrapper."""

    package: str
    config_schema: str
    domain_schema: str
    agent_manifest_schema: str
    capability_diff_schema: str
    capability_rule_pack: str
    capability_risk_model: str
    capability_assessment_output: str
    capability_shadow_gate: str
    baseline_schema: str
    diff_output: str
    assessment_output: str
    rule_pack: str
    risk_model: str


class CapabilitySeverityCounts(_ReportModel):
    critical: NonNegativeInt
    high: NonNegativeInt
    medium: NonNegativeInt
    low: NonNegativeInt
    none: NonNegativeInt


class CapabilityConfidenceCounts(_ReportModel):
    A: NonNegativeInt
    B: NonNegativeInt
    C: NonNegativeInt
    D: NonNegativeInt


class CapabilityAssessmentSummary(_ReportModel):
    """Management-level summary derived from Manifest and Findings."""

    sources: NonNegativeInt
    tools: NonNegativeInt
    permissions: NonNegativeInt
    controls: NonNegativeInt
    runtime_identities: NonNegativeInt
    relationships: NonNegativeInt
    unknowns: NonNegativeInt
    high_impact_permissions: NonNegativeInt
    findings: NonNegativeInt
    highest_severity: Severity
    severity_counts: CapabilitySeverityCounts
    confidence_counts: CapabilityConfidenceCounts
    hard_gate_matches: NonNegativeInt
    shadow_gate_matches: NonNegativeInt
    manifest_coverage_complete: bool
    coverage_issues: NonNegativeInt
    rule_execution_complete: bool
    rule_failures: NonNegativeInt


class CapabilityAssessmentStage(_ReportModel):
    stage: AgentAnalysisStage
    status: AnalysisStageStatus
    input_items: NonNegativeInt
    output_items: NonNegativeInt
    error_code: AgentAnalysisErrorCode | None = None


class CapabilityAssessmentRuleFailure(_ReportModel):
    rule_id: str


class CapabilityAssessmentLocalizedText(_ReportModel):
    language: CapabilityRuleLanguage
    title: str
    description: str
    recommendations: tuple[str, ...]


class CapabilityAssessmentEvidence(_ReportModel):
    scope: str
    root_id: str
    path: str
    field_path: str | None
    start_line: Annotated[int, Field(ge=1)] | None
    end_line: Annotated[int, Field(ge=1)] | None
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def line_range_must_be_coherent(self) -> CapabilityAssessmentEvidence:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("Capability evidence lines must be provided together")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("Capability evidence line range is invalid")
        return self


class CapabilityAssessmentImpactRating(_ReportModel):
    dimension: ImpactDimension
    level: ImpactLevel
    rationale: str


class CapabilityAssessmentShadowGateMatch(_ReportModel):
    """Serialized shadow-mode Gate match (never enforcement)."""

    gate_id: str = Field(pattern=r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
    floor: Literal["high", "critical"]
    correlation: CapabilityCorrelation
    related_ids: tuple[str, ...]
    rationale: tuple[str, ...]

    @model_validator(mode="after")
    def gate_match_contract_must_hold(
        self,
    ) -> CapabilityAssessmentShadowGateMatch:
        if not self.related_ids:
            raise ValueError("Capability Shadow Gate match requires related IDs")
        if self.related_ids != tuple(sorted(set(self.related_ids))):
            raise ValueError("Capability Shadow Gate match related IDs are invalid")
        if self.correlation not in {
            CapabilityCorrelation.SAME_TARGET,
            CapabilityCorrelation.PARENT_CHILD,
        }:
            raise ValueError("Capability Shadow Gate match correlation is not eligible")
        return self


class CapabilityAssessmentShadowGate(_ReportModel):
    """Serialized shadow-mode, pilot-only Gate evaluation for one Finding."""

    gate_version: Literal["0.1.0"]
    gate_id: str = Field(pattern=r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
    finding_id: str
    mode: Literal["shadow"]
    qualification: Literal["pilot_only"]
    matched: bool
    blocks: Literal[False]
    coverage_complete: bool
    relevant_unknowns: NonNegativeInt
    match: CapabilityAssessmentShadowGateMatch | None

    @model_validator(mode="after")
    def shadow_gate_contract_must_hold(
        self,
    ) -> CapabilityAssessmentShadowGate:
        if self.gate_version != CAPABILITY_SHADOW_GATE_VERSION:
            raise ValueError("Capability Shadow Gate version is unsupported")
        if self.matched != (self.match is not None):
            raise ValueError("Capability Shadow Gate match state is inconsistent")
        if self.matched and (not self.coverage_complete or self.relevant_unknowns != 0):
            raise ValueError(
                "Capability Shadow Gate cannot match incomplete or Unknown evidence"
            )
        if self.match is not None and self.match.gate_id != self.gate_id:
            raise ValueError("Capability Shadow Gate match ID is inconsistent")
        return self


class CapabilityAssessmentFinding(_ReportModel):
    finding_id: str
    rule_id: str
    category: FindingCategory
    texts: tuple[CapabilityAssessmentLocalizedText, ...]
    correlation: CapabilityCorrelation
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    risk_level: NistRiskLevel
    nist_semi_quantitative_value: int
    score: Annotated[float, Field(ge=0, le=10)]
    severity: Severity
    confidence: EvidenceConfidence
    hard_gate: Literal[False]
    capability_shadow_gate: CapabilityAssessmentShadowGate | None
    related_ids: tuple[str, ...]
    evidence: tuple[CapabilityAssessmentEvidence, ...]
    likelihood_basis: tuple[str, ...]
    impact_ratings: tuple[CapabilityAssessmentImpactRating, ...]
    limitations: tuple[str, ...]
    mapping_basis: tuple[str, ...]
    capability_rule_pack_version: str
    capability_risk_model_version: str


class CapabilityAssessmentJsonReport(_ReportModel):
    """Strict public JSON wrapper for one Capability Assessment."""

    format: Literal["agentsec-capability-assessment"]
    format_version: Literal["0.2.0"]
    status: Literal["complete", "incomplete"]
    versions: CapabilityAssessmentVersions
    policy: CapabilityAssessmentPolicy
    summary: CapabilityAssessmentSummary
    manifest: AgentManifest
    findings: tuple[CapabilityAssessmentFinding, ...]
    stage_trace: tuple[CapabilityAssessmentStage, ...]
    rule_failures: tuple[CapabilityAssessmentRuleFailure, ...]

    @model_validator(mode="after")
    def derived_fields_must_match_content(self) -> CapabilityAssessmentJsonReport:
        if self.versions.agent_manifest_schema != self.manifest.schema_version:
            raise ValueError("report Manifest version is inconsistent")
        expected_rule_complete = not self.rule_failures
        if self.summary.rule_execution_complete != expected_rule_complete:
            raise ValueError("rule execution summary is inconsistent")
        expected_status = (
            "complete"
            if self.manifest.coverage.complete and expected_rule_complete
            else "incomplete"
        )
        if self.status != expected_status:
            raise ValueError("report status is inconsistent")
        if self.summary != _summary(
            self.manifest,
            self.findings,
            self.rule_failures,
        ):
            raise ValueError("report summary is inconsistent")
        if tuple(item.stage for item in self.stage_trace) != tuple(AgentAnalysisStage):
            raise ValueError("stage trace is incomplete or out of order")
        finding_keys = tuple(
            (item.rule_id, item.related_ids, item.finding_id) for item in self.findings
        )
        if finding_keys != tuple(sorted(set(finding_keys))):
            raise ValueError("Capability Findings must be sorted and unique")
        failure_ids = tuple(item.rule_id for item in self.rule_failures)
        if failure_ids != tuple(sorted(set(failure_ids))):
            raise ValueError("Capability Rule failures must be sorted and unique")
        for finding in self.findings:
            if (
                finding.capability_rule_pack_version
                != self.versions.capability_rule_pack
                or finding.capability_risk_model_version
                != self.versions.capability_risk_model
            ):
                raise ValueError("Capability Finding versions are inconsistent")
        return self


class CapabilityAssessmentJsonRenderer:
    """Build and render one complete strict Capability Assessment JSON report."""

    def build(
        self, result: CapabilityAssessmentResult
    ) -> CapabilityAssessmentJsonReport:
        if not isinstance(result, CapabilityAssessmentResult):
            raise TypeError(
                "Capability Assessment JSON rendering requires "
                "CapabilityAssessmentResult"
            )
        versions = _versions(result.versions)
        findings = tuple(_finding(item) for item in result.rules.findings)
        failures = tuple(
            CapabilityAssessmentRuleFailure(rule_id=item.rule_id)
            for item in result.rules.failures
        )
        stage_trace = tuple(
            CapabilityAssessmentStage(
                stage=item.stage,
                status=item.status,
                input_items=item.input_items,
                output_items=item.output_items,
                error_code=item.error_code,
            )
            for item in result.analysis.stages
        )
        return CapabilityAssessmentJsonReport(
            format=CAPABILITY_ASSESSMENT_JSON_FORMAT,
            format_version=CAPABILITY_ASSESSMENT_JSON_FORMAT_VERSION,
            status="complete" if result.complete else "incomplete",
            versions=versions,
            policy=CapabilityAssessmentPolicy(
                enforcement_mode="report_only",
                ci_blocking_enabled=False,
                global_safety_claimed=False,
                runtime_capability_verified=False,
            ),
            summary=_summary(result.analysis.manifest, findings, failures),
            manifest=result.analysis.manifest,
            findings=findings,
            stage_trace=stage_trace,
            rule_failures=failures,
        )

    def render(self, result: CapabilityAssessmentResult) -> str:
        return encode_capability_assessment_json(self.build(result))


def encode_capability_assessment_json(
    report: CapabilityAssessmentJsonReport,
) -> str:
    if not isinstance(report, CapabilityAssessmentJsonReport):
        raise TypeError("report must be CapabilityAssessmentJsonReport")
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def validate_capability_assessment_payload(
    payload: object,
) -> CapabilityAssessmentJsonReport:
    if not isinstance(payload, Mapping):
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_ROOT,
            "Capability Assessment root must be a JSON object",
        )
    report_format = payload.get("format")
    if report_format is None:
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.MISSING_FORMAT,
            "Capability Assessment requires format",
        )
    if report_format != CAPABILITY_ASSESSMENT_JSON_FORMAT:
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_FORMAT,
            "Capability Assessment format is not supported",
        )
    version = payload.get("format_version")
    if version is None:
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.MISSING_FORMAT_VERSION,
            "Capability Assessment requires format_version",
        )
    if not isinstance(version, str):
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_FORMAT_VERSION,
            "Capability Assessment format_version must be semantic version text",
        )
    try:
        parse_interface_version(version)
    except ValueError as error:
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_FORMAT_VERSION,
            "Capability Assessment format_version must use MAJOR.MINOR.PATCH",
        ) from error
    if not can_read_interface_version(
        produced=version,
        supported=CAPABILITY_ASSESSMENT_OUTPUT_VERSION,
    ):
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.UNSUPPORTED_FORMAT_VERSION,
            "Capability Assessment format version is not supported",
        )
    try:
        return CapabilityAssessmentJsonReport.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "Capability Assessment payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def decode_capability_assessment_json(text: str) -> CapabilityAssessmentJsonReport:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        # ValueError also covers oversized integer literals rejected by the
        # Python 3.11+ int-string conversion limit (not a JSONDecodeError).
        raise CapabilityAssessmentValidationError(
            CapabilityAssessmentValidationCode.INVALID_JSON,
            "Capability Assessment must contain valid JSON",
        ) from error
    return validate_capability_assessment_payload(payload)


def export_capability_assessment_json_schema(output_directory: Path) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / CAPABILITY_ASSESSMENT_JSON_SCHEMA_FILENAME
    schema = CapabilityAssessmentJsonReport.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-capability-assessment-output-version"] = (
        CAPABILITY_ASSESSMENT_OUTPUT_VERSION
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _versions(versions: VersionSet) -> CapabilityAssessmentVersions:
    return CapabilityAssessmentVersions(
        package=versions.package,
        config_schema=versions.config_schema,
        domain_schema=versions.domain_schema,
        agent_manifest_schema=versions.agent_manifest_schema,
        capability_diff_schema=versions.capability_diff_schema,
        capability_rule_pack=versions.capability_rule_pack,
        capability_risk_model=versions.capability_risk_model,
        capability_assessment_output=versions.capability_assessment_output,
        capability_shadow_gate=versions.capability_shadow_gate,
        baseline_schema=versions.baseline_schema,
        diff_output=versions.diff_output,
        assessment_output=versions.assessment_output,
        rule_pack=versions.rule_pack,
        risk_model=versions.risk_model,
    )


def _finding(item: CapabilityRuleFinding) -> CapabilityAssessmentFinding:
    return CapabilityAssessmentFinding(
        finding_id=item.finding_id,
        rule_id=item.rule_id,
        category=item.category,
        texts=tuple(
            CapabilityAssessmentLocalizedText(
                language=text.language,
                title=text.title,
                description=text.description,
                recommendations=text.recommendations,
            )
            for text in item.texts
        ),
        correlation=item.correlation,
        likelihood=item.likelihood,
        impact=item.impact,
        risk_level=item.risk_level,
        nist_semi_quantitative_value=item.nist_semi_quantitative_value,
        score=item.score,
        severity=item.severity,
        confidence=item.confidence,
        hard_gate=False,
        capability_shadow_gate=_shadow_gate(item),
        related_ids=item.related_ids,
        evidence=tuple(
            CapabilityAssessmentEvidence(
                scope=evidence.scope,
                root_id=evidence.root_id,
                path=evidence.path,
                field_path=evidence.field_path,
                start_line=evidence.start_line,
                end_line=evidence.end_line,
                content_sha256=evidence.content_sha256,
            )
            for evidence in item.evidence
        ),
        likelihood_basis=item.likelihood_basis,
        impact_ratings=tuple(
            CapabilityAssessmentImpactRating(
                dimension=rating.dimension,
                level=rating.level,
                rationale=rating.rationale,
            )
            for rating in item.impact_ratings
        ),
        limitations=item.limitations,
        mapping_basis=item.mapping_basis,
        capability_rule_pack_version=item.capability_rule_pack_version,
        capability_risk_model_version=item.capability_risk_model_version,
    )


def _shadow_gate(
    item: CapabilityRuleFinding,
) -> CapabilityAssessmentShadowGate | None:
    gate = item.capability_shadow_gate
    if gate is None:
        return None
    match = gate.match
    return CapabilityAssessmentShadowGate(
        gate_version=cast(Literal["0.1.0"], gate.gate_version),
        gate_id=gate.gate_id,
        finding_id=gate.finding_id,
        mode=gate.mode,
        qualification=gate.qualification,
        matched=gate.matched,
        blocks=gate.blocks,
        coverage_complete=gate.coverage_complete,
        relevant_unknowns=gate.relevant_unknowns,
        match=(
            CapabilityAssessmentShadowGateMatch(
                gate_id=match.gate_id,
                floor=match.floor,
                correlation=match.correlation,
                related_ids=match.related_ids,
                rationale=match.rationale,
            )
            if match is not None
            else None
        ),
    )


def _summary(
    manifest: AgentManifest,
    findings: tuple[CapabilityAssessmentFinding, ...],
    failures: tuple[CapabilityAssessmentRuleFailure, ...],
) -> CapabilityAssessmentSummary:
    severity = {item: 0 for item in Severity}
    confidence = {item: 0 for item in EvidenceConfidence}
    for finding in findings:
        severity[finding.severity] += 1
        confidence[finding.confidence] += 1
    highest = max(
        (finding.severity for finding in findings),
        key=_severity_rank,
        default=Severity.NONE,
    )
    high_impact_actions = {
        ManifestPermissionAction.EXECUTE,
        ManifestPermissionAction.NETWORK,
        ManifestPermissionAction.SECRET_ACCESS,
        ManifestPermissionAction.ADMIN,
        ManifestPermissionAction.DEPLOY,
        ManifestPermissionAction.PUBLISH,
        ManifestPermissionAction.PERSIST,
    }
    return CapabilityAssessmentSummary(
        sources=len(manifest.sources),
        tools=len(manifest.tools.tools),
        permissions=len(manifest.permissions.permissions),
        controls=len(manifest.controls.controls),
        runtime_identities=len(manifest.runtime_identities.identities),
        relationships=len(manifest.relationships.relations),
        unknowns=len(manifest.unknowns),
        high_impact_permissions=sum(
            item.action in high_impact_actions
            for item in manifest.permissions.permissions
        ),
        findings=len(findings),
        highest_severity=highest,
        severity_counts=CapabilitySeverityCounts(
            critical=severity[Severity.CRITICAL],
            high=severity[Severity.HIGH],
            medium=severity[Severity.MEDIUM],
            low=severity[Severity.LOW],
            none=severity[Severity.NONE],
        ),
        confidence_counts=CapabilityConfidenceCounts(
            A=confidence[EvidenceConfidence.A],
            B=confidence[EvidenceConfidence.B],
            C=confidence[EvidenceConfidence.C],
            D=confidence[EvidenceConfidence.D],
        ),
        hard_gate_matches=sum(finding.hard_gate for finding in findings),
        shadow_gate_matches=sum(
            finding.capability_shadow_gate is not None
            and finding.capability_shadow_gate.matched
            for finding in findings
        ),
        manifest_coverage_complete=manifest.coverage.complete,
        coverage_issues=len(manifest.coverage.issues),
        rule_execution_complete=not failures,
        rule_failures=len(failures),
    )


def _severity_rank(value: Severity) -> int:
    return {
        Severity.NONE: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[value]


_SAFE_FIELD_PART = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _safe_field_paths(error: ValidationError) -> tuple[str, ...]:
    paths: set[str] = set()
    for item in error.errors(include_url=False, include_input=False):
        if not item["loc"]:
            continue
        parts: list[str] = []
        for part in item["loc"]:
            if isinstance(part, int):
                parts.append(str(part))
                continue
            value = str(part)
            parts.append(value if _SAFE_FIELD_PART.fullmatch(value) else "<field>")
        paths.add(".".join(parts))
    return tuple(sorted(paths))

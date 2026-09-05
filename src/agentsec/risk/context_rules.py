"""Context-aware deterministic rules for structured Operation Contexts (RISK-04).

The rule engine consumes RISK-01 OperationContextSet values and produces
report-only risk observations. It does not calculate a numeric score, grant
permissions, authenticate an Agent, or block CI. A public-web read of public
data is deliberately not a risk match by itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.risk.context import (
    AuthorizationState,
    ControlState,
    DataClassification,
    DataRetention,
    DataSharingScope,
    OperationAction,
    OperationContext,
    OperationContextSet,
    OperationReversibility,
    OperationTarget,
    OperationTrigger,
    canonical_operation_context_sha256,
)
from agentsec.versioning import (
    CONTEXT_RISK_REPORT_VERSION,
    CONTEXT_RULE_PACK_VERSION,
)

CONTEXT_RISK_REPORT_FORMAT: Literal["agentsec-context-risk-report"] = (
    "agentsec-context-risk-report"
)
CONTEXT_RISK_REPORT_FORMAT_VERSION = CONTEXT_RISK_REPORT_VERSION
CONTEXT_RISK_RULE_MAPPING_BASIS = (
    "AgentSec RISK-09A deterministic context-aware rule contract 0.2.0",
    (
        "Risk requires an operation-context combination; capability presence "
        "alone is insufficient"
    ),
    (
        "Public-web reads with public data are not elevated without autonomy, "
        "sensitive data, side effects, or control weakness"
    ),
    (
        "Unknown context is a coverage observation, not proof of a vulnerability "
        "or a clean pass"
    ),
    "Risk signals have no numeric score; RISK-05 owns residual-risk quantification",
)

_RULE_ID_PATTERN = re.compile(r"^CTX-(?:RISK|COVERAGE)-[0-9]{3}$")
_FINDING_ID_PREFIX = "context-risk-sha256:"
_MAX_FINDINGS = 128
_CONFIDENCE_ORDER = {
    EvidenceConfidence.A: 0,
    EvidenceConfidence.B: 1,
    EvidenceConfidence.C: 2,
    EvidenceConfidence.D: 3,
}


class ContextRiskFindingKind(StrEnum):
    """Whether an output is a risk pattern or a coverage observation."""

    RISK = "risk"
    COVERAGE = "coverage"


class ContextRuleId(StrEnum):
    """Stable RISK-04 deterministic Rule IDs."""

    SENSITIVE_EXTERNAL_TRANSFER = "CTX-RISK-001"
    AUTONOMOUS_SENSITIVE_OPERATION = "CTX-RISK-002"
    HIGH_IMPACT_WITHOUT_AUTHORIZATION = "CTX-RISK-003"
    SECRET_TO_EXTERNAL_CHAIN = "CTX-RISK-004"
    INDEFINITE_EXTERNAL_PERSISTENCE = "CTX-RISK-005"
    CONTROL_FILE_WITHOUT_AUTHORIZATION = "CTX-RISK-006"
    UNBOUNDED_SENSITIVE_RETENTION = "CTX-RISK-007"
    AUTONOMOUS_EXTERNAL_SIDE_EFFECT = "CTX-RISK-008"
    CONTEXT_COVERAGE_GAP = "CTX-COVERAGE-001"


@dataclass(frozen=True, slots=True)
class ContextRuleMetadata:
    """Trusted metadata for a deterministic context rule."""

    rule_id: str
    title: str
    description: str
    category: FindingCategory
    deterministic: Literal[True] = True
    report_only: Literal[True] = True

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("context Rule ID is invalid")
        _require_text(self.title, "context Rule title")
        _require_text(self.description, "context Rule description")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("context Rule category is invalid")
        if self.deterministic is not True or self.report_only is not True:
            raise ValueError("context Rules must remain deterministic/report-only")

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "deterministic": self.deterministic,
            "report_only": self.report_only,
        }


@dataclass(frozen=True, slots=True)
class ContextRuleMatch:
    """One Rule match before stable Finding materialization."""

    contexts: tuple[OperationContext, ...]
    rationale_code: str
    rationale: str
    limitations: tuple[str, ...]
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    severity: Severity
    finding_kind: ContextRiskFindingKind = ContextRiskFindingKind.RISK

    def __post_init__(self) -> None:
        if not self.contexts:
            raise ValueError("context Rule match requires context evidence")
        ids = tuple(item.operation_id for item in self.contexts)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("context Rule match contexts must be sorted/unique")
        _require_text(self.rationale_code, "context Rule rationale code")
        _require_text(self.rationale, "context Rule rationale")
        _require_text_tuple(self.limitations, "context Rule limitations")
        for value, name, enum_type in (
            (self.likelihood, "likelihood", LikelihoodLevel),
            (self.impact, "impact", ImpactLevel),
            (self.severity, "severity", Severity),
            (self.finding_kind, "finding_kind", ContextRiskFindingKind),
        ):
            if not isinstance(value, enum_type):
                raise TypeError(f"context Rule {name} is invalid")

    def sort_key(self) -> tuple[str, ...]:
        return tuple(item.operation_id for item in self.contexts)


@dataclass(frozen=True, slots=True)
class ContextRiskFinding:
    """Report-only context Finding; numeric risk scoring is deferred."""

    finding_id: str
    rule_id: str
    kind: ContextRiskFindingKind
    category: FindingCategory
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    severity: Severity
    confidence: EvidenceConfidence
    context_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale_code: str
    rationale: str
    limitations: tuple[str, ...]
    rule_pack_version: str = CONTEXT_RULE_PACK_VERSION
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if not self.finding_id.startswith(_FINDING_ID_PREFIX):
            raise ValueError("context Finding ID is invalid")
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("context Finding Rule ID is invalid")
        for value, name, enum_type in (
            (self.kind, "kind", ContextRiskFindingKind),
            (self.category, "category", FindingCategory),
            (self.likelihood, "likelihood", LikelihoodLevel),
            (self.impact, "impact", ImpactLevel),
            (self.severity, "severity", Severity),
            (self.confidence, "confidence", EvidenceConfidence),
        ):
            if not isinstance(value, enum_type):
                raise TypeError(f"context Finding {name} is invalid")
        if self.context_ids != tuple(sorted(set(self.context_ids))):
            raise ValueError("context Finding context IDs must be sorted/unique")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("context Finding Evidence IDs must be sorted/unique")
        _require_text(self.rationale_code, "context Finding rationale code")
        _require_text(self.rationale, "context Finding rationale")
        _require_text_tuple(self.limitations, "context Finding limitations")
        if self.rule_pack_version != CONTEXT_RULE_PACK_VERSION:
            raise ValueError("context Rule Pack version is unsupported")
        if (
            self.report_only is not True
            or self.runtime_verified is not False
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise ValueError("context Finding authority fields are invalid")

    def sort_key(self) -> tuple[str, str, tuple[str, ...], str]:
        return (self.rule_id, self.kind.value, self.context_ids, self.finding_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "kind": self.kind.value,
            "category": self.category.value,
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "context_ids": list(self.context_ids),
            "evidence_ids": list(self.evidence_ids),
            "rationale_code": self.rationale_code,
            "rationale": self.rationale,
            "limitations": list(self.limitations),
            "rule_pack_version": self.rule_pack_version,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
        }


@dataclass(frozen=True, slots=True)
class ContextRiskReport:
    """Deterministic RISK-04 report bound to one Operation Context Set."""

    format: Literal["agentsec-context-risk-report"]
    format_version: str
    source_context_sha256: str
    source_context_format: str
    rule_pack_version: str
    evaluated_rule_ids: tuple[str, ...]
    findings: tuple[ContextRiskFinding, ...]
    context_count: int
    coverage_complete: bool
    unknown_dimensions: tuple[str, ...]
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != CONTEXT_RISK_REPORT_FORMAT:
            raise ValueError("context risk report format is unsupported")
        if self.format_version != CONTEXT_RISK_REPORT_FORMAT_VERSION:
            raise ValueError("context risk report version is unsupported")
        _require_digest(self.source_context_sha256, "source_context_sha256")
        _require_text(self.source_context_format, "source_context_format")
        if self.rule_pack_version != CONTEXT_RULE_PACK_VERSION:
            raise ValueError("context Rule Pack version is unsupported")
        if self.evaluated_rule_ids != tuple(sorted(set(self.evaluated_rule_ids))):
            raise ValueError("evaluated context Rule IDs must be sorted/unique")
        if self.findings != tuple(
            sorted(self.findings, key=lambda item: item.sort_key())
        ):
            raise ValueError("context risk Findings must be sorted")
        if len(self.findings) > _MAX_FINDINGS:
            raise ValueError("context risk Finding limit exceeded")
        if isinstance(self.context_count, bool) or self.context_count < 1:
            raise ValueError("context_count must be positive")
        if self.unknown_dimensions != tuple(sorted(set(self.unknown_dimensions))):
            raise ValueError("unknown_dimensions must be sorted/unique")
        if not isinstance(self.coverage_complete, bool):
            raise TypeError("coverage_complete must be bool")
        if (
            self.report_only is not True
            or self.runtime_verified is not False
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise ValueError("context risk report authority fields are invalid")

    @property
    def risk_findings(self) -> tuple[ContextRiskFinding, ...]:
        return tuple(
            item for item in self.findings if item.kind is ContextRiskFindingKind.RISK
        )

    @property
    def coverage_findings(self) -> tuple[ContextRiskFinding, ...]:
        return tuple(
            item
            for item in self.findings
            if item.kind is ContextRiskFindingKind.COVERAGE
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_context_sha256": self.source_context_sha256,
            "source_context_format": self.source_context_format,
            "mapping_basis": list(CONTEXT_RISK_RULE_MAPPING_BASIS),
            "rule_pack_version": self.rule_pack_version,
            "evaluated_rule_ids": list(self.evaluated_rule_ids),
            "context_count": self.context_count,
            "coverage_complete": self.coverage_complete,
            "unknown_dimensions": list(self.unknown_dimensions),
            "risk_finding_count": len(self.risk_findings),
            "coverage_finding_count": len(self.coverage_findings),
            "findings": [item.to_dict() for item in self.findings],
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }


@runtime_checkable
class ContextRule(Protocol):
    @property
    def metadata(self) -> ContextRuleMetadata: ...

    def evaluate(
        self, context_set: OperationContextSet
    ) -> tuple[ContextRuleMatch, ...]: ...


@dataclass(frozen=True, slots=True)
class _BuiltinContextRule:
    metadata: ContextRuleMetadata
    evaluator: Callable[[OperationContextSet], tuple[ContextRuleMatch, ...]] = (
        dataclass_field(repr=False)
    )

    def evaluate(
        self, context_set: OperationContextSet
    ) -> tuple[ContextRuleMatch, ...]:
        return self.evaluator(context_set)


class DeterministicContextRuleEngine:
    """Run the trusted RISK-04 Rule Pack in deterministic order."""

    def __init__(self, rules: tuple[ContextRule, ...] | None = None) -> None:
        selected = builtin_context_rules() if rules is None else rules
        if not isinstance(selected, tuple) or not selected:
            raise ValueError("context Rule registry must not be empty")
        registered = tuple(sorted(selected, key=lambda item: item.metadata.rule_id))
        ids = tuple(item.metadata.rule_id for item in registered)
        if len(ids) != len(set(ids)):
            raise ValueError("context Rule IDs must be unique")
        self._rules = registered

    def run(self, context_set: OperationContextSet) -> ContextRiskReport:
        if not isinstance(context_set, OperationContextSet):
            raise TypeError("context Rule engine requires OperationContextSet")
        findings: list[ContextRiskFinding] = []
        for rule in self._rules:
            try:
                matches = tuple(rule.evaluate(context_set))
                for match in matches:
                    if not isinstance(match, ContextRuleMatch):
                        raise TypeError("context Rule returned an invalid match")
                    findings.append(_materialize(rule.metadata, match))
            except Exception:
                findings.append(
                    _materialize(
                        _coverage_metadata(),
                        ContextRuleMatch(
                            contexts=(context_set.contexts[0],),
                            rationale_code="rule_evaluation_failed",
                            rationale=(
                                "A context rule failed closed and requires review."
                            ),
                            limitations=(
                                "The failed rule was not used to grant or deny "
                                "an operation.",
                            ),
                            likelihood=LikelihoodLevel.VERY_LOW,
                            impact=ImpactLevel.LOW,
                            severity=Severity.NONE,
                            finding_kind=ContextRiskFindingKind.COVERAGE,
                        ),
                    )
                )
        if not context_set.coverage_complete or context_set.unknown_dimensions:
            findings.append(
                _materialize(
                    _coverage_metadata(),
                    ContextRuleMatch(
                        contexts=(context_set.contexts[0],),
                        rationale_code="operation_context_incomplete",
                        rationale=(
                            "Operation Context coverage is incomplete or contains "
                            "Unknown dimensions; risk conclusions require additional "
                            "context."
                        ),
                        limitations=(
                            "Unknown is a coverage state, not proof of a "
                            "vulnerability or a clean pass.",
                        ),
                        likelihood=LikelihoodLevel.VERY_LOW,
                        impact=ImpactLevel.LOW,
                        severity=Severity.NONE,
                        finding_kind=ContextRiskFindingKind.COVERAGE,
                    ),
                )
            )
        return ContextRiskReport(
            format=CONTEXT_RISK_REPORT_FORMAT,
            format_version=CONTEXT_RISK_REPORT_FORMAT_VERSION,
            source_context_sha256=canonical_operation_context_sha256(context_set),
            source_context_format=context_set.format,
            rule_pack_version=CONTEXT_RULE_PACK_VERSION,
            evaluated_rule_ids=tuple(item.metadata.rule_id for item in self._rules),
            findings=_deduplicate_findings(tuple(findings)),
            context_count=len(context_set.contexts),
            coverage_complete=context_set.coverage_complete,
            unknown_dimensions=context_set.unknown_dimensions,
        )


def builtin_context_rules() -> tuple[ContextRule, ...]:
    """Return the reviewed RISK-04 deterministic Rule Pack."""

    return (
        _rule(
            ContextRuleId.SENSITIVE_EXTERNAL_TRANSFER,
            "Sensitive data external transfer",
            "Detect sensitive data sent or written to an external destination.",
            FindingCategory.SECRET_ACCESS,
            _sensitive_external_transfer,
        ),
        _rule(
            ContextRuleId.AUTONOMOUS_SENSITIVE_OPERATION,
            "Autonomous sensitive operation",
            "Detect scheduled, proactive, or autonomous sensitive operations.",
            FindingCategory.EXTERNAL_TOOLING,
            _autonomous_sensitive_operation,
        ),
        _rule(
            ContextRuleId.HIGH_IMPACT_WITHOUT_AUTHORIZATION,
            "High-impact operation lacks authorization context",
            (
                "Detect destructive, privileged, policy, or production operations "
                "without explicit authorization."
            ),
            FindingCategory.PRIVILEGED_ACCESS,
            _high_impact_without_authorization,
        ),
        _rule(
            ContextRuleId.SECRET_TO_EXTERNAL_CHAIN,
            "Secret-to-external transfer chain",
            (
                "Detect a Secret/Credential read paired with an external transfer "
                "operation."
            ),
            FindingCategory.SECRET_ACCESS,
            _secret_to_external_chain,
        ),
        _rule(
            ContextRuleId.INDEFINITE_EXTERNAL_PERSISTENCE,
            "Indefinite external persistence",
            (
                "Detect sensitive data retained indefinitely outside the local "
                "session or workspace."
            ),
            FindingCategory.PERSISTENT_MEMORY,
            _indefinite_external_persistence,
        ),
        _rule(
            ContextRuleId.CONTROL_FILE_WITHOUT_AUTHORIZATION,
            "Control-file modification lacks authorization",
            (
                "Detect Agent control-file or identity changes without explicit "
                "authorization context."
            ),
            FindingCategory.SELF_MODIFICATION,
            _control_file_without_authorization,
        ),
        _rule(
            ContextRuleId.UNBOUNDED_SENSITIVE_RETENTION,
            "Unbounded sensitive retention",
            (
                "Detect personal or sensitive data retained indefinitely without "
                "an explicit retention or consent control."
            ),
            FindingCategory.PERSISTENT_MEMORY,
            _unbounded_sensitive_retention,
        ),
        _rule(
            ContextRuleId.AUTONOMOUS_EXTERNAL_SIDE_EFFECT,
            "Autonomous external side effect",
            (
                "Detect external send/write operations that may proceed "
                "autonomously without explicit approval."
            ),
            FindingCategory.EXTERNAL_TOOLING,
            _autonomous_external_side_effect,
        ),
        _rule(
            ContextRuleId.CONTEXT_COVERAGE_GAP,
            "Operation Context coverage gap",
            (
                "Report incomplete or unknown Operation Context dimensions separately "
                "from risk."
            ),
            FindingCategory.SCAN_COVERAGE,
            lambda _context_set: (),
        ),
    )


def encode_context_risk_json(report: ContextRiskReport) -> str:
    if not isinstance(report, ContextRiskReport):
        raise TypeError("context risk encoder requires ContextRiskReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def canonical_context_risk_sha256(report: ContextRiskReport) -> str:
    """Return the canonical digest used by downstream risk evidence."""

    if not isinstance(report, ContextRiskReport):
        raise TypeError("context risk report is invalid")
    encoded = json.dumps(
        report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def decode_context_risk_json(payload: str) -> ContextRiskReport:
    """Decode and validate a serialized RISK-04 report for replay use."""

    if not isinstance(payload, str):
        raise TypeError("context risk decoder requires text")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("context risk JSON is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("context risk JSON must be an object")
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError("context risk findings are missing")
    findings = tuple(
        ContextRiskFinding(
            finding_id=_string_field(item, "finding_id"),
            rule_id=_string_field(item, "rule_id"),
            kind=ContextRiskFindingKind(_string_field(item, "kind")),
            category=FindingCategory(_string_field(item, "category")),
            likelihood=LikelihoodLevel(_string_field(item, "likelihood")),
            impact=ImpactLevel(_string_field(item, "impact")),
            severity=Severity(_string_field(item, "severity")),
            confidence=EvidenceConfidence(_string_field(item, "confidence")),
            context_ids=_string_tuple_field(item, "context_ids"),
            evidence_ids=_string_tuple_field(item, "evidence_ids"),
            rationale_code=_string_field(item, "rationale_code"),
            rationale=_string_field(item, "rationale"),
            limitations=_string_tuple_field(item, "limitations"),
            rule_pack_version=_string_field(item, "rule_pack_version"),
        )
        for item in raw_findings
        if isinstance(item, dict)
    )
    if len(findings) != len(raw_findings):
        raise ValueError("context risk findings contain an invalid item")
    if _string_field(value, "format") != CONTEXT_RISK_REPORT_FORMAT:
        raise ValueError("context risk format is unsupported")
    _validate_authority(value)
    return ContextRiskReport(
        format=CONTEXT_RISK_REPORT_FORMAT,
        format_version=_string_field(value, "format_version"),
        source_context_sha256=_string_field(value, "source_context_sha256"),
        source_context_format=_string_field(value, "source_context_format"),
        rule_pack_version=_string_field(value, "rule_pack_version"),
        evaluated_rule_ids=_string_tuple_field(value, "evaluated_rule_ids"),
        findings=findings,
        context_count=_int_field(value, "context_count"),
        coverage_complete=_bool_field(value, "coverage_complete"),
        unknown_dimensions=_string_tuple_field(value, "unknown_dimensions"),
    )


def export_context_risk_json_schema(output_directory: Path) -> Path:
    """Export the strict RISK-04 JSON Schema."""

    if not isinstance(output_directory, Path):
        raise TypeError("context risk schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "context-risk-report.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/context-risk-report.schema.json",
        "title": "AgentSec Context-aware Deterministic Risk Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "source_context_sha256",
            "source_context_format",
            "mapping_basis",
            "rule_pack_version",
            "evaluated_rule_ids",
            "context_count",
            "coverage_complete",
            "unknown_dimensions",
            "risk_finding_count",
            "coverage_finding_count",
            "findings",
            "report_only",
            "runtime_verified",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": CONTEXT_RISK_REPORT_FORMAT},
            "format_version": {"const": CONTEXT_RISK_REPORT_FORMAT_VERSION},
            "source_context_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_context_format": {"const": "agentsec-operation-context-set"},
            "mapping_basis": {"type": "array", "items": {"type": "string"}},
            "rule_pack_version": {"const": CONTEXT_RULE_PACK_VERSION},
            "evaluated_rule_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "context_count": {"type": "integer", "minimum": 1},
            "coverage_complete": {"type": "boolean"},
            "unknown_dimensions": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "risk_finding_count": {"type": "integer", "minimum": 0},
            "coverage_finding_count": {"type": "integer", "minimum": 0},
            "findings": {"type": "array", "items": _finding_schema()},
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "report_only",
                    "runtime_verified",
                    "policy_authority",
                    "ci_blocked",
                ],
                "properties": {
                    "report_only": {"const": True},
                    "runtime_verified": {"const": False},
                    "policy_authority": {"const": False},
                    "ci_blocked": {"const": False},
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _finding_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "rule_id",
            "kind",
            "category",
            "likelihood",
            "impact",
            "severity",
            "confidence",
            "context_ids",
            "evidence_ids",
            "rationale_code",
            "rationale",
            "limitations",
            "rule_pack_version",
            "report_only",
            "runtime_verified",
            "policy_authority",
            "ci_blocked",
        ],
        "properties": {
            "finding_id": {
                "type": "string",
                "pattern": "^context-risk-sha256:[0-9a-f]{64}$",
            },
            "rule_id": {
                "type": "string",
                "pattern": "^CTX-(?:RISK|COVERAGE)-[0-9]{3}$",
            },
            "kind": {"enum": [item.value for item in ContextRiskFindingKind]},
            "category": {"type": "string"},
            "likelihood": {"type": "string"},
            "impact": {"type": "string"},
            "severity": {"enum": [item.value for item in Severity]},
            "confidence": {"enum": [item.value for item in EvidenceConfidence]},
            "context_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "evidence_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "rationale_code": {"type": "string", "minLength": 1},
            "rationale": {"type": "string", "minLength": 1},
            "limitations": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
            "rule_pack_version": {"const": CONTEXT_RULE_PACK_VERSION},
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
        },
    }


def _rule(
    rule_id: ContextRuleId,
    title: str,
    description: str,
    category: FindingCategory,
    evaluator: Callable[[OperationContextSet], tuple[ContextRuleMatch, ...]],
) -> ContextRule:
    return _BuiltinContextRule(
        metadata=ContextRuleMetadata(
            rule_id=rule_id.value,
            title=title,
            description=description,
            category=category,
        ),
        evaluator=evaluator,
    )


def _sensitive_external_transfer(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    for context in context_set.contexts:
        sensitive = context.data_scope.classification in {
            DataClassification.PERSONAL,
            DataClassification.SENSITIVE,
            DataClassification.CREDENTIAL,
            DataClassification.SECRET,
        }
        external = context.target in {
            OperationTarget.EXTERNAL_SERVICE,
            OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
        }
        if not (
            context.action in {OperationAction.SEND, OperationAction.WRITE}
            and sensitive
            and external
            and context.data_scope.sharing is DataSharingScope.EXTERNAL
        ):
            continue
        weak_auth = context.authorization.state in {
            AuthorizationState.UNKNOWN,
            AuthorizationState.APPROVAL_MISSING,
        }
        secret_like = context.data_scope.classification in {
            DataClassification.CREDENTIAL,
            DataClassification.SECRET,
        }
        no_redaction = context.controls.redaction is not ControlState.PRESENT
        severity = (
            Severity.CRITICAL
            if secret_like and weak_auth and no_redaction
            else Severity.HIGH
            if secret_like or weak_auth
            else Severity.MEDIUM
        )
        matches.append(
            _match(
                context,
                rationale_code="sensitive_data_external_transfer",
                rationale=(
                    "A structured operation sends or writes sensitive data to an "
                    "external destination."
                ),
                limitations=(
                    "Static Operation Context does not prove that the external "
                    "transfer is reachable or completed.",
                ),
                likelihood=LikelihoodLevel.HIGH
                if weak_auth
                else LikelihoodLevel.MODERATE,
                impact=ImpactLevel.VERY_HIGH if secret_like else ImpactLevel.HIGH,
                severity=severity,
            )
        )
    return tuple(matches)


def _autonomous_sensitive_operation(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    autonomous = {
        OperationTrigger.SCHEDULED,
        OperationTrigger.PROACTIVE,
        OperationTrigger.AUTONOMOUS,
    }
    sensitive = {
        DataClassification.PERSONAL,
        DataClassification.SENSITIVE,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
    }
    targets = {
        OperationTarget.EXTERNAL_SERVICE,
        OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
        OperationTarget.USER_MAILBOX,
        OperationTarget.PRODUCTION_SYSTEM,
        OperationTarget.SECRET,
    }
    for context in context_set.contexts:
        if not (
            context.trigger in autonomous
            and context.data_scope.classification in sensitive
            and context.target in targets
        ):
            continue
        weak_auth = context.authorization.state in {
            AuthorizationState.UNKNOWN,
            AuthorizationState.APPROVAL_MISSING,
        }
        secret_like = context.data_scope.classification in {
            DataClassification.CREDENTIAL,
            DataClassification.SECRET,
        }
        critical = weak_auth and secret_like
        matches.append(
            _match(
                context,
                rationale_code="autonomous_sensitive_operation",
                rationale=(
                    "A scheduled, proactive, or autonomous operation targets "
                    "sensitive data or an external/high-impact resource."
                ),
                limitations=(
                    "The trigger is a static declaration and does not attest "
                    "scheduler or runtime reachability.",
                ),
                likelihood=(
                    LikelihoodLevel.HIGH if critical else LikelihoodLevel.MODERATE
                ),
                impact=ImpactLevel.VERY_HIGH,
                severity=Severity.CRITICAL if critical else Severity.HIGH,
            )
        )
    return tuple(matches)


def _high_impact_without_authorization(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    actions = {
        OperationAction.DELETE,
        OperationAction.MODIFY_POLICY,
        OperationAction.MODIFY_IDENTITY,
        OperationAction.EXECUTE,
    }
    targets = {
        OperationTarget.PRODUCTION_SYSTEM,
        OperationTarget.AGENT_CONTROL_FILE,
        OperationTarget.CREDENTIAL,
        OperationTarget.SECRET,
        OperationTarget.MCP_SERVER,
        OperationTarget.TOOL_REGISTRY,
    }
    weak = {AuthorizationState.UNKNOWN, AuthorizationState.APPROVAL_MISSING}
    for context in context_set.contexts:
        if not (
            context.action in actions
            and context.target in targets
            and context.authorization.state in weak
        ):
            continue
        critical = (
            context.target is OperationTarget.PRODUCTION_SYSTEM
            or context.reversibility is OperationReversibility.IRREVERSIBLE
        )
        likelihood = LikelihoodLevel.HIGH if critical else LikelihoodLevel.MODERATE
        matches.append(
            _match(
                context,
                rationale_code="high_impact_without_authorization",
                rationale=(
                    "A high-impact operation targets a privileged, production, "
                    "secret, tool, or control-file resource without explicit "
                    "authorization."
                ),
                limitations=(
                    "The declaration does not prove that the operation is "
                    "available or executable at runtime.",
                ),
                likelihood=likelihood,
                impact=ImpactLevel.VERY_HIGH if critical else ImpactLevel.HIGH,
                severity=Severity.CRITICAL if critical else Severity.MEDIUM,
            )
        )
    return tuple(matches)


def _secret_to_external_chain(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    reads = tuple(
        item
        for item in context_set.contexts
        if item.action is OperationAction.READ
        and item.target in {OperationTarget.SECRET, OperationTarget.CREDENTIAL}
    )
    writes = tuple(
        item
        for item in context_set.contexts
        if item.action in {OperationAction.SEND, OperationAction.WRITE}
        and item.target
        in {
            OperationTarget.EXTERNAL_SERVICE,
            OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
        }
        and item.data_scope.sharing is DataSharingScope.EXTERNAL
    )
    matches: list[ContextRuleMatch] = []
    for read in reads:
        for write in writes:
            weak = write.authorization.state in {
                AuthorizationState.UNKNOWN,
                AuthorizationState.APPROVAL_MISSING,
            }
            no_redaction = write.controls.redaction is not ControlState.PRESENT
            contexts = tuple(sorted((read, write), key=lambda item: item.operation_id))
            matches.append(
                ContextRuleMatch(
                    contexts=contexts,
                    rationale_code="secret_to_external_transfer_chain",
                    rationale=(
                        "One Operation Context reads a Secret/Credential and another "
                        "transfers data to an external destination."
                    ),
                    limitations=(
                        "The rule identifies a static cross-operation chain; it does "
                        "not prove data flow or exploitability.",
                    ),
                    likelihood=LikelihoodLevel.HIGH
                    if weak
                    else LikelihoodLevel.MODERATE,
                    impact=ImpactLevel.VERY_HIGH,
                    severity=(
                        Severity.CRITICAL if weak and no_redaction else Severity.HIGH
                    ),
                )
            )
    return tuple(matches)


def _indefinite_external_persistence(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    sensitive = {
        DataClassification.PERSONAL,
        DataClassification.SENSITIVE,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
    }
    for context in context_set.contexts:
        if not (
            context.action in {OperationAction.STORE, OperationAction.WRITE}
            and context.data_scope.retention is DataRetention.INDEFINITE
            and context.data_scope.sharing
            in {DataSharingScope.EXTERNAL, DataSharingScope.ORGANIZATION}
            and context.data_scope.classification in sensitive
        ):
            continue
        matches.append(
            _match(
                context,
                rationale_code="indefinite_external_persistence",
                rationale=(
                    "Sensitive data is declared for indefinite retention outside "
                    "the local session or workspace."
                ),
                limitations=(
                    "The declaration does not prove that persistence occurs or "
                    "that the destination is reachable.",
                ),
                likelihood=LikelihoodLevel.MODERATE,
                impact=ImpactLevel.HIGH,
                severity=Severity.HIGH,
            )
        )
    return tuple(matches)


def _control_file_without_authorization(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    actions = {
        OperationAction.MODIFY_POLICY,
        OperationAction.MODIFY_IDENTITY,
        OperationAction.WRITE,
    }
    weak = {AuthorizationState.UNKNOWN, AuthorizationState.APPROVAL_MISSING}
    for context in context_set.contexts:
        if not (
            context.action in actions
            and context.target is OperationTarget.AGENT_CONTROL_FILE
            and context.authorization.state in weak
        ):
            continue
        matches.append(
            _match(
                context,
                rationale_code="control_file_update_without_authorization",
                rationale=(
                    "An Agent control or identity file can be modified without an "
                    "explicit authorization context."
                ),
                limitations=(
                    "Static declaration does not prove that the file is writable "
                    "at runtime.",
                ),
                likelihood=LikelihoodLevel.MODERATE,
                impact=ImpactLevel.VERY_HIGH,
                severity=Severity.HIGH,
            )
        )
    return tuple(matches)


def _unbounded_sensitive_retention(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    sensitive = {
        DataClassification.PERSONAL,
        DataClassification.SENSITIVE,
        DataClassification.CREDENTIAL,
        DataClassification.SECRET,
    }
    for context in context_set.contexts:
        if not (
            context.action in {OperationAction.STORE, OperationAction.WRITE}
            and context.data_scope.classification in sensitive
            and context.data_scope.retention is DataRetention.INDEFINITE
            and context.controls.retention is not ControlState.PRESENT
            and context.controls.user_consent is not ControlState.PRESENT
        ):
            continue
        secret_like = context.data_scope.classification in {
            DataClassification.CREDENTIAL,
            DataClassification.SECRET,
        }
        matches.append(
            _match(
                context,
                rationale_code="unbounded_sensitive_retention_without_control",
                rationale=(
                    "Personal or sensitive data is declared for indefinite "
                    "retention without an explicit retention or consent control."
                ),
                limitations=(
                    "Static declaration does not prove stored content, runtime "
                    "persistence, or actual retention duration.",
                ),
                likelihood=(
                    LikelihoodLevel.HIGH if secret_like else LikelihoodLevel.MODERATE
                ),
                impact=ImpactLevel.VERY_HIGH,
                severity=Severity.CRITICAL if secret_like else Severity.HIGH,
            )
        )
    return tuple(matches)


def _autonomous_external_side_effect(
    context_set: OperationContextSet,
) -> tuple[ContextRuleMatch, ...]:
    matches: list[ContextRuleMatch] = []
    autonomous = {
        OperationTrigger.PROACTIVE,
        OperationTrigger.AUTONOMOUS,
        OperationTrigger.SCHEDULED,
    }
    weak_authorization = {
        AuthorizationState.UNKNOWN,
        AuthorizationState.APPROVAL_MISSING,
        AuthorizationState.NOT_REQUIRED,
    }
    for context in context_set.contexts:
        if not (
            context.action in {OperationAction.SEND, OperationAction.WRITE}
            and context.target
            in {
                OperationTarget.EXTERNAL_SERVICE,
                OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
            }
            and context.data_scope.sharing is DataSharingScope.EXTERNAL
            and context.trigger in autonomous
            and context.authorization.state in weak_authorization
            and context.controls.approval is not ControlState.PRESENT
        ):
            continue
        matches.append(
            _match(
                context,
                rationale_code="autonomous_external_side_effect_without_approval",
                rationale=(
                    "An external send or write operation may proceed autonomously "
                    "without explicit approval."
                ),
                limitations=(
                    "Static declaration does not prove destination reachability, "
                    "message content, or successful delivery.",
                ),
                likelihood=LikelihoodLevel.MODERATE,
                impact=ImpactLevel.HIGH,
                severity=Severity.MEDIUM,
            )
        )
    return tuple(matches)


def _match(
    context: OperationContext,
    *,
    rationale_code: str,
    rationale: str,
    limitations: tuple[str, ...],
    likelihood: LikelihoodLevel,
    impact: ImpactLevel,
    severity: Severity,
) -> ContextRuleMatch:
    return ContextRuleMatch(
        contexts=(context,),
        rationale_code=rationale_code,
        rationale=rationale,
        limitations=limitations,
        likelihood=likelihood,
        impact=impact,
        severity=severity,
    )


def _coverage_metadata() -> ContextRuleMetadata:
    return ContextRuleMetadata(
        rule_id=ContextRuleId.CONTEXT_COVERAGE_GAP.value,
        title="Operation Context coverage gap",
        description=(
            "Report incomplete or unknown Operation Context dimensions separately "
            "from risk."
        ),
        category=FindingCategory.SCAN_COVERAGE,
    )


def _materialize(
    metadata: ContextRuleMetadata,
    match: ContextRuleMatch,
) -> ContextRiskFinding:
    context_ids = tuple(item.operation_id for item in match.contexts)
    evidence_ids = tuple(
        sorted(
            {
                evidence.evidence_id
                for context in match.contexts
                for evidence in context.evidence
            }
        )
    )
    confidence = max(
        (
            evidence.confidence
            for context in match.contexts
            for evidence in context.evidence
        ),
        key=_CONFIDENCE_ORDER.__getitem__,
        default=EvidenceConfidence.D,
    )
    payload = {
        "rule_id": metadata.rule_id,
        "kind": match.finding_kind.value,
        "context_ids": context_ids,
        "evidence_ids": evidence_ids,
        "rationale_code": match.rationale_code,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return ContextRiskFinding(
        finding_id=_FINDING_ID_PREFIX + digest,
        rule_id=metadata.rule_id,
        kind=match.finding_kind,
        category=metadata.category,
        likelihood=match.likelihood,
        impact=match.impact,
        severity=match.severity,
        confidence=confidence,
        context_ids=context_ids,
        evidence_ids=evidence_ids,
        rationale_code=match.rationale_code,
        rationale=match.rationale,
        limitations=match.limitations,
    )


def _deduplicate_findings(
    findings: tuple[ContextRiskFinding, ...],
) -> tuple[ContextRiskFinding, ...]:
    by_id: dict[str, ContextRiskFinding] = {}
    for finding in findings:
        previous = by_id.get(finding.finding_id)
        if previous is not None and previous != finding:
            raise ValueError("context Finding identity conflict detected")
        by_id[finding.finding_id] = finding
    return tuple(sorted(by_id.values(), key=lambda item: item.sort_key()))


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{label} must be a non-empty tuple")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} must contain non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _string_field(value: dict[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise ValueError(f"context risk field {name} must be text")
    return item


def _string_tuple_field(value: dict[str, object], name: str) -> tuple[str, ...]:
    item = value.get(name)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise ValueError(f"context risk field {name} must be a string list")
    return tuple(item)


def _bool_field(value: dict[str, object], name: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise ValueError(f"context risk field {name} must be bool")
    return item


def _int_field(value: dict[str, object], name: str) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"context risk field {name} must be integer")
    return item


def _validate_authority(value: dict[str, object]) -> None:
    expected = {
        "report_only": True,
        "runtime_verified": False,
        "policy_authority": False,
        "ci_blocked": False,
    }
    if not all(
        value.get(key) is expected_value for key, expected_value in expected.items()
    ):
        raise ValueError("context risk authority fields are invalid")
    authority = value.get("authority")
    if not isinstance(authority, dict) or any(
        authority.get(key) is not expected_value
        for key, expected_value in expected.items()
    ):
        raise ValueError("context risk authority object is invalid")


__all__ = [
    "CONTEXT_RISK_REPORT_FORMAT",
    "CONTEXT_RISK_REPORT_FORMAT_VERSION",
    "CONTEXT_RISK_RULE_MAPPING_BASIS",
    "ContextRiskFinding",
    "ContextRiskFindingKind",
    "ContextRiskReport",
    "ContextRule",
    "ContextRuleId",
    "ContextRuleMatch",
    "ContextRuleMetadata",
    "DeterministicContextRuleEngine",
    "builtin_context_rules",
    "canonical_context_risk_sha256",
    "decode_context_risk_json",
    "encode_context_risk_json",
    "export_context_risk_json_schema",
]

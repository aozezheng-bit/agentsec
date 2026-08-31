"""Strict organization-level YAML Policy and deterministic scan evaluation."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agentsec.domain import Assessment, Finding, Severity
from agentsec.fail_on import FailOnThreshold
from agentsec.rules import BUILTIN_MARKDOWN_RULE_IDS
from agentsec.trust import (
    TrustError as PolicyTrustError,
)
from agentsec.trust import (
    ensure_safe_relative_posix_path,
)
from agentsec.versioning import ORGANIZATION_POLICY_SCHEMA_VERSION

ORGANIZATION_POLICY_FORMAT = "agentsec-organization-policy"
ORGANIZATION_POLICY_MAX_SIZE_BYTES = 2_097_152
SUPPORTED_CAPABILITY_GATES = ("HG-CAPCHAIN-001",)
_POLICY_VERSION = cast(Literal["0.3.0"], ORGANIZATION_POLICY_SCHEMA_VERSION)
_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class OrganizationPolicyError(ValueError):
    """Safe organization Policy input or semantic failure."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class OrganizationScanPolicy(_Strict):
    fail_on: FailOnThreshold | None = None
    blocking_rule_ids: tuple[str, ...] = ()

    @field_validator("blocking_rule_ids")
    @classmethod
    def rules_must_be_known_unique_and_sorted(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("scan.blocking_rule_ids must be unique")
        unknown = set(values) - set(BUILTIN_MARKDOWN_RULE_IDS)
        if unknown:
            raise ValueError("scan.blocking_rule_ids contains an unsupported Rule")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def rule_scope_requires_threshold(self) -> OrganizationScanPolicy:
        if self.blocking_rule_ids and self.fail_on is None:
            raise ValueError("scan.blocking_rule_ids requires scan.fail_on")
        return self


class OrganizationCapabilityQualification(_Strict):
    """Explicit pin of one approved Qualified Gate Registry artifact."""

    registry_path: Annotated[str, Field(min_length=1, max_length=512)]
    registry_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("registry_path")
    @classmethod
    def registry_path_must_be_safe_relative(cls, value: str) -> str:
        try:
            return ensure_safe_relative_posix_path(
                value, label="capability.qualification.registry_path"
            )
        except PolicyTrustError as error:
            raise ValueError(str(error)) from error


class OrganizationCapabilityPolicy(_Strict):
    qualified_gates: tuple[str, ...] = ()
    qualification: OrganizationCapabilityQualification | None = None

    @field_validator("qualified_gates")
    @classmethod
    def gates_must_be_known_unique_and_sorted(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("capability.qualified_gates must be unique")
        if set(values) - set(SUPPORTED_CAPABILITY_GATES):
            raise ValueError("capability.qualified_gates contains an unsupported Gate")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def gates_require_trusted_qualification_binding(
        self,
    ) -> OrganizationCapabilityPolicy:
        if self.qualified_gates and self.qualification is None:
            raise ValueError("capability Gates require a pinned qualification registry")
        return self


class OrganizationCoveragePolicy(_Strict):
    require_complete: Literal[True] = True
    require_unknown_free: bool = True


class OrganizationSafetyPolicy(_Strict):
    allow_llm_authority: Literal[False] = False
    allow_runtime_unverified_authority: Literal[False] = False


class OrganizationWaiver(_Strict):
    waiver_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    owner: Annotated[str, Field(min_length=1, max_length=128)]
    reason: Annotated[str, Field(min_length=10, max_length=1024)]
    expires_on: date
    finding_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    gate_ids: tuple[str, ...] = ()

    @field_validator("finding_ids", "rule_ids", "gate_ids")
    @classmethod
    def scopes_must_be_unique_sorted(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("Waiver scope IDs must be unique")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def scope_must_be_supported(self) -> OrganizationWaiver:
        if not (self.finding_ids or self.rule_ids or self.gate_ids):
            raise ValueError("Waiver requires Finding, Rule, or Gate scope")
        if set(self.rule_ids) - set(BUILTIN_MARKDOWN_RULE_IDS):
            raise ValueError("Waiver contains an unsupported Rule")
        if set(self.gate_ids) - set(SUPPORTED_CAPABILITY_GATES):
            raise ValueError("Waiver contains an unsupported Gate")
        return self


class OrganizationPolicy(_Strict):
    format: Literal["agentsec-organization-policy"]
    schema_version: Literal["0.3.0"]
    policy_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    policy_version: Annotated[str, Field(min_length=1, max_length=32)]
    enabled: bool = False
    enforcement_mode: Literal["report_only", "enforce"] = "report_only"
    scan: OrganizationScanPolicy = OrganizationScanPolicy()
    capability: OrganizationCapabilityPolicy = OrganizationCapabilityPolicy()
    coverage: OrganizationCoveragePolicy = OrganizationCoveragePolicy()
    safety: OrganizationSafetyPolicy = OrganizationSafetyPolicy()
    waivers: tuple[OrganizationWaiver, ...] = ()

    @model_validator(mode="after")
    def semantics_must_be_safe(self) -> OrganizationPolicy:
        if self.enforcement_mode == "enforce" and not self.enabled:
            raise ValueError("enforcement_mode=enforce requires enabled=true")
        waiver_ids = tuple(item.waiver_id for item in self.waivers)
        if len(waiver_ids) != len(set(waiver_ids)):
            raise ValueError("Waiver IDs must be unique")
        if waiver_ids != tuple(sorted(waiver_ids)):
            raise ValueError("Waivers must be sorted by waiver_id")
        return self


class OrganizationPolicyEvidence(_Strict):
    policy: OrganizationPolicy
    source_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class OrganizationDecisionState(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    INCOMPLETE = "incomplete"


class OrganizationScanDecision(_Strict):
    policy_schema_version: Literal["0.3.0"]
    policy_id: str
    policy_version: str
    policy_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy_enabled: bool
    enforcement_mode: Literal["report_only", "enforce"]
    enforcement_active: bool
    threshold: FailOnThreshold | None
    configured_rule_ids: tuple[str, ...]
    evaluated_on: date
    basis: Literal["agentsec_severity_and_rule_scope"] = (
        "agentsec_severity_and_rule_scope"
    )
    decision: OrganizationDecisionState
    exit_code: Literal[0, 1, 2]
    coverage_complete: bool
    blocks: bool
    highest_observed_severity: Severity
    matched_finding_ids: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    waived_finding_ids: tuple[str, ...]
    blocking_finding_ids: tuple[str, ...]
    applied_waiver_ids: tuple[str, ...]
    expired_waiver_ids: tuple[str, ...]
    rationale: tuple[str, ...]

    @model_validator(mode="after")
    def decision_must_be_coherent(self) -> OrganizationScanDecision:
        for values, label in (
            (self.configured_rule_ids, "configured Rule IDs"),
            (self.matched_finding_ids, "matched Finding IDs"),
            (self.matched_rule_ids, "matched Rule IDs"),
            (self.waived_finding_ids, "waived Finding IDs"),
            (self.blocking_finding_ids, "blocking Finding IDs"),
            (self.applied_waiver_ids, "applied Waiver IDs"),
            (self.expired_waiver_ids, "expired Waiver IDs"),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"organization {label} must be sorted and unique")
        if not self.rationale:
            raise ValueError("organization decision requires trusted rationale")
        if self.decision is OrganizationDecisionState.INCOMPLETE:
            if self.coverage_complete or self.blocks or self.exit_code != 2:
                raise ValueError("incomplete organization decision is invalid")
        elif self.decision is OrganizationDecisionState.BLOCK:
            if (
                not self.coverage_complete
                or not self.enforcement_active
                or not self.blocks
                or self.exit_code != 1
                or not self.blocking_finding_ids
            ):
                raise ValueError("blocking organization decision is invalid")
        elif self.blocks or self.exit_code != 0 or not self.coverage_complete:
            raise ValueError("allow organization decision is invalid")
        return self


@dataclass(frozen=True, slots=True)
class LoadedOrganizationPolicy:
    policy: OrganizationPolicy
    path: Path
    sha256: str
    size_bytes: int

    @property
    def evidence(self) -> OrganizationPolicyEvidence:
        return OrganizationPolicyEvidence(
            policy=self.policy,
            source_sha256=self.sha256,
        )


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise OrganizationPolicyError("organization Policy has duplicate keys")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_organization_policy(path: Path) -> LoadedOrganizationPolicy:
    """Load one bounded regular YAML file without aliases, tags, or duplicate keys."""

    if not isinstance(path, Path):
        raise TypeError("organization Policy path must be a Path")
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise OrganizationPolicyError("organization Policy must use .yaml or .yml")
    if path.is_symlink():
        raise OrganizationPolicyError("organization Policy must not be a symlink")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OrganizationPolicyError("organization Policy must be a regular file")
        if metadata.st_size > ORGANIZATION_POLICY_MAX_SIZE_BYTES:
            raise OrganizationPolicyError("organization Policy exceeds size limit")
        remaining = ORGANIZATION_POLICY_MAX_SIZE_BYTES + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > ORGANIZATION_POLICY_MAX_SIZE_BYTES:
            raise OrganizationPolicyError("organization Policy exceeds size limit")
    except FileNotFoundError as error:
        raise OrganizationPolicyError("organization Policy does not exist") from error
    except OrganizationPolicyError:
        raise
    except OSError as error:
        raise OrganizationPolicyError(
            "organization Policy could not be read safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OrganizationPolicyError("organization Policy must be UTF-8") from error
    if not text.strip():
        raise OrganizationPolicyError("organization Policy is empty")
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise OrganizationPolicyError(
                    "organization Policy aliases, anchors, and tags are forbidden"
                )
        documents = list(yaml.load_all(text, Loader=_UniqueSafeLoader))
    except OrganizationPolicyError:
        raise
    except (yaml.YAMLError, TypeError, ValueError) as error:
        raise OrganizationPolicyError("organization Policy is invalid YAML") from error
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise OrganizationPolicyError("organization Policy must be one YAML mapping")
    try:
        policy = OrganizationPolicy.model_validate(documents[0])
    except Exception as error:
        raise OrganizationPolicyError(
            "organization Policy failed schema or semantic validation"
        ) from error
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise OrganizationPolicyError(
            "organization Policy path could not be resolved"
        ) from error
    return LoadedOrganizationPolicy(
        policy=policy,
        path=resolved,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )


def evaluate_organization_scan_policy(
    assessment: Assessment,
    evidence: OrganizationPolicyEvidence,
    *,
    evaluated_on: date | None = None,
) -> OrganizationScanDecision:
    """Evaluate scan threshold and Rule scope without suppressing any Finding."""

    if not isinstance(assessment, Assessment):
        raise TypeError("organization scan evaluation requires Assessment")
    if not isinstance(evidence, OrganizationPolicyEvidence):
        raise TypeError("organization scan evaluation requires Policy evidence")
    policy = evidence.policy
    effective_date = evaluated_on or datetime.now(UTC).date()
    configured = policy.scan.blocking_rule_ids
    threshold = policy.scan.fail_on
    eligible = tuple(
        finding
        for finding in assessment.findings
        if not configured or finding.rule_id in configured
    )
    matched: tuple[Finding, ...]
    if threshold is None:
        matched = ()
    else:
        threshold_rank = _SEVERITY_RANK[Severity(threshold.value)]
        matched = tuple(
            finding
            for finding in eligible
            if _SEVERITY_RANK[finding.severity] >= threshold_rank
        )
    matched_ids = tuple(sorted(finding.finding_id for finding in matched))
    matched_rules = tuple(sorted({finding.rule_id for finding in matched}))
    active_waivers = tuple(
        waiver for waiver in policy.waivers if waiver.expires_on >= effective_date
    )
    expired_waiver_ids = tuple(
        sorted(
            waiver.waiver_id
            for waiver in policy.waivers
            if waiver.expires_on < effective_date
        )
    )
    waived_finding_ids = tuple(
        sorted(
            finding.finding_id
            for finding in matched
            if any(
                finding.finding_id in waiver.finding_ids
                or finding.rule_id in waiver.rule_ids
                for waiver in active_waivers
            )
        )
    )
    applied_waiver_ids = tuple(
        sorted(
            waiver.waiver_id
            for waiver in active_waivers
            if any(
                finding.finding_id in waiver.finding_ids
                or finding.rule_id in waiver.rule_ids
                for finding in matched
            )
        )
    )
    blocking_finding_ids = tuple(
        item for item in matched_ids if item not in set(waived_finding_ids)
    )
    highest = max(
        (finding.severity for finding in assessment.findings),
        key=_SEVERITY_RANK.__getitem__,
        default=Severity.NONE,
    )
    active = bool(
        policy.enabled
        and policy.enforcement_mode == "enforce"
        and threshold is not None
    )
    common: dict[str, object] = {
        "policy_schema_version": _POLICY_VERSION,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_sha256": evidence.source_sha256,
        "policy_enabled": policy.enabled,
        "enforcement_mode": policy.enforcement_mode,
        "enforcement_active": active,
        "threshold": threshold,
        "configured_rule_ids": configured,
        "evaluated_on": effective_date,
        "highest_observed_severity": highest,
        "matched_finding_ids": matched_ids,
        "matched_rule_ids": matched_rules,
        "waived_finding_ids": waived_finding_ids,
        "blocking_finding_ids": blocking_finding_ids,
        "applied_waiver_ids": applied_waiver_ids,
        "expired_waiver_ids": expired_waiver_ids,
    }
    if not assessment.coverage.complete:
        payload = {
            **common,
            "decision": OrganizationDecisionState.INCOMPLETE,
            "exit_code": 2,
            "coverage_complete": False,
            "blocks": False,
            "rationale": (
                "Coverage is incomplete; organization Policy returns exit 2.",
            ),
        }
    elif active and blocking_finding_ids:
        payload = {
            **common,
            "decision": OrganizationDecisionState.BLOCK,
            "exit_code": 1,
            "coverage_complete": True,
            "blocks": True,
            "rationale": (
                "A configured deterministic Rule meets the organization "
                "Severity threshold.",
            ),
        }
    else:
        payload = {
            **common,
            "decision": OrganizationDecisionState.ALLOW,
            "exit_code": 0,
            "coverage_complete": True,
            "blocks": False,
            "rationale": (
                "Organization Policy is report-only/disabled or no configured "
                "Rule meets the threshold.",
            ),
        }
    return OrganizationScanDecision.model_validate(payload)


def organization_gate_waivers(
    policy: OrganizationPolicy,
    *,
    evaluated_on: date | None = None,
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...], date]:
    effective_date = evaluated_on or datetime.now(UTC).date()
    mapping: dict[str, list[str]] = {}
    expired: list[str] = []
    for waiver in policy.waivers:
        if waiver.expires_on < effective_date:
            expired.append(waiver.waiver_id)
            continue
        for gate_id in waiver.gate_ids:
            mapping.setdefault(gate_id, []).append(waiver.waiver_id)
    return (
        {key: tuple(sorted(values)) for key, values in sorted(mapping.items())},
        tuple(sorted(expired)),
        effective_date,
    )


__all__ = [
    "ORGANIZATION_POLICY_FORMAT",
    "ORGANIZATION_POLICY_MAX_SIZE_BYTES",
    "SUPPORTED_CAPABILITY_GATES",
    "LoadedOrganizationPolicy",
    "OrganizationCapabilityPolicy",
    "OrganizationCoveragePolicy",
    "OrganizationDecisionState",
    "OrganizationPolicy",
    "OrganizationPolicyError",
    "OrganizationPolicyEvidence",
    "OrganizationSafetyPolicy",
    "OrganizationWaiver",
    "OrganizationScanDecision",
    "OrganizationScanPolicy",
    "evaluate_organization_scan_policy",
    "load_organization_policy",
    "organization_gate_waivers",
]

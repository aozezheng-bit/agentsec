"""Policy-controlled, deterministic Capability CI enforcement (P2-15B)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agentsec.application import CapabilityAssessmentResult
from agentsec.exit_codes import ExitCode
from agentsec.policy.qualification_registry import (
    LoadedQualifiedGateRegistry,
    PolicyError,
    verify_gate_qualification,
)
from agentsec.trust import (
    TRUST_MODE_REPOSITORY_LOCAL,
    TrustError,
    ensure_safe_relative_posix_path,
)
from agentsec.versioning import (
    CAPABILITY_CI_POLICY_SCHEMA_VERSION,
    CAPABILITY_CI_REPORT_OUTPUT_VERSION,
)

POLICY_FORMAT = "agentsec-capability-ci-policy"
POLICY_SCHEMA_VERSION = CAPABILITY_CI_POLICY_SCHEMA_VERSION
REPORT_FORMAT = "agentsec-capability-ci-enforcement"
REPORT_SCHEMA_VERSION = CAPABILITY_CI_REPORT_OUTPUT_VERSION
SUPPORTED_GATE = "HG-CAPCHAIN-001"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FailOn(_Strict):
    qualified_gates: tuple[str, ...] = ()


class CoveragePolicy(_Strict):
    require_complete: bool = True
    require_unknown_free: bool = True


class SafetyPolicy(_Strict):
    allow_llm_authority: Literal[False] = False
    allow_runtime_unverified_authority: Literal[False] = False


class QualificationTrustBinding(_Strict):
    """Explicit pin of one approved Qualified Gate Registry artifact."""

    registry_path: str
    registry_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("registry_path")
    @classmethod
    def registry_path_must_be_safe_relative(cls, value: str) -> str:
        try:
            return ensure_safe_relative_posix_path(
                value, label="qualification registry_path"
            )
        except TrustError as error:
            raise ValueError(str(error)) from error


class CapabilityCiPolicy(_Strict):
    format: Literal["agentsec-capability-ci-policy"]
    schema_version: Literal["0.2.0"]
    policy_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    policy_version: str = Field(min_length=1, max_length=32)
    enabled: bool = False
    enforcement_mode: Literal["report_only", "enforce"] = "report_only"
    fail_on: FailOn = FailOn()
    qualification: QualificationTrustBinding | None = None
    coverage: CoveragePolicy = CoveragePolicy()
    safety: SafetyPolicy = SafetyPolicy()

    @model_validator(mode="after")
    def validate_semantics(self) -> CapabilityCiPolicy:
        if self.enforcement_mode == "enforce" and not self.enabled:
            raise ValueError("enforcement_mode=enforce requires enabled=true")
        unknown = set(self.fail_on.qualified_gates) - {SUPPORTED_GATE}
        if unknown:
            raise ValueError("policy references an unsupported Capability Gate")
        if len(set(self.fail_on.qualified_gates)) != len(self.fail_on.qualified_gates):
            raise ValueError("fail_on.qualified_gates must be unique")
        if self.fail_on.qualified_gates and self.qualification is None:
            raise ValueError("qualified Gates require a pinned qualification registry")
        if (
            self.safety.allow_llm_authority
            or self.safety.allow_runtime_unverified_authority
        ):
            raise ValueError("LLM and runtime-unverified authority are forbidden")
        return self


@dataclass(frozen=True, slots=True)
class GateDecision:
    gate_id: str
    qualification: str
    matched: bool
    blocks: bool
    finding_ids: tuple[str, ...]
    reason: str
    waived: bool = False
    waiver_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CiEnforcementDecision:
    policy_id: str
    policy_version: str
    policy_enabled: bool
    enforcement_mode: str
    decision: Literal["allow", "block", "incomplete", "configuration_error"]
    exit_code: ExitCode
    assessment_complete: bool
    matched_gates: tuple[GateDecision, ...]
    boundary: dict[str, bool]
    policy_source_format: str = POLICY_FORMAT
    policy_source_schema_version: str = POLICY_SCHEMA_VERSION
    policy_source_sha256: str | None = None
    qualification_registry_id: str | None = None
    qualification_registry_version: str | None = None
    qualification_registry_sha256: str | None = None
    trust_mode: str = TRUST_MODE_REPOSITORY_LOCAL
    policy_digest_pinned: bool = False
    policy_digest_verified: bool = False
    expected_policy_sha256: str | None = None
    registry_digest_pinned: bool = False
    registry_digest_verified: bool = False
    expected_registry_sha256: str | None = None
    evaluated_on: date | None = None
    applied_waiver_ids: tuple[str, ...] = ()
    expired_waiver_ids: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": REPORT_FORMAT,
            "schema_version": REPORT_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy": {
                "enabled": self.policy_enabled,
                "enforcement_mode": self.enforcement_mode,
                "source_format": self.policy_source_format,
                "source_schema_version": self.policy_source_schema_version,
                "source_sha256": self.policy_source_sha256,
                "evaluated_on": (
                    self.evaluated_on.isoformat() if self.evaluated_on else None
                ),
            },
            "decision": self.decision,
            "exit_code": int(self.exit_code),
            "assessment_complete": self.assessment_complete,
            "qualification_registry": {
                "present": self.qualification_registry_id is not None,
                "registry_id": self.qualification_registry_id,
                "registry_version": self.qualification_registry_version,
                "registry_sha256": self.qualification_registry_sha256,
            },
            "trust": {
                "trust_mode": self.trust_mode,
                "policy_digest_pinned": self.policy_digest_pinned,
                "policy_digest_verified": self.policy_digest_verified,
                "expected_policy_sha256": self.expected_policy_sha256,
                "registry_digest_pinned": self.registry_digest_pinned,
                "registry_digest_verified": self.registry_digest_verified,
                "expected_registry_sha256": self.expected_registry_sha256,
            },
            "matched_gates": [
                {
                    "gate_id": item.gate_id,
                    "qualification": item.qualification,
                    "matched": item.matched,
                    "blocks": item.blocks,
                    "finding_ids": list(item.finding_ids),
                    "reason": item.reason,
                    "waived": item.waived,
                    "waiver_ids": list(item.waiver_ids),
                }
                for item in self.matched_gates
            ],
            "applied_waiver_ids": list(self.applied_waiver_ids),
            "expired_waiver_ids": list(self.expired_waiver_ids),
            "boundary": self.boundary,
            "errors": list(self.errors),
        }

    def render_json(self) -> str:
        return (
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        )

    def render_text(self, *, language: str = "en") -> str:
        blocked = self.decision == "block"
        if language == "zh":
            lines = [
                "AgentSec Capability CI Enforcement",
                f"策略：{self.policy_id} ({self.policy_version})",
                f"决策：{'阻断' if blocked else self.decision}",
                f"退出码：{int(self.exit_code)}",
                f"评估完整性：{'完整' if self.assessment_complete else '不完整'}",
                f"命中 Gate：{len(self.matched_gates)}",
                f"生效豁免：{len(self.applied_waiver_ids)}",
                f"过期豁免：{len(self.expired_waiver_ids)}",
                "边界：确定性规则负责阻断；不授权 LLM；未验证运行时能力",
            ]
            if self.errors:
                lines.append("错误：" + "；".join(self.errors))
            return "\n".join(lines) + "\n"
        lines = [
            "AgentSec Capability CI Enforcement",
            f"Policy: {self.policy_id} ({self.policy_version})",
            f"Decision: {self.decision.upper()}",
            f"Exit code: {int(self.exit_code)}",
            (
                "Assessment completeness: "
                f"{'COMPLETE' if self.assessment_complete else 'INCOMPLETE'}"
            ),
            f"Matched gates: {len(self.matched_gates)}",
            f"Applied waivers: {len(self.applied_waiver_ids)}",
            f"Expired waivers: {len(self.expired_waiver_ids)}",
            (
                "Boundary: deterministic rules own blocking; "
                "LLM authority disabled; runtime not verified"
            ),
        ]
        if self.errors:
            lines.append("Errors: " + "; ".join(self.errors))
        return "\n".join(lines) + "\n"


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PolicyError("policy input is missing or unsafe")
    try:
        raw = path.read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise PolicyError("policy input exceeds the hard size limit")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as error:
        raise PolicyError("policy input is invalid JSON") from error
    if not isinstance(value, dict):
        raise PolicyError("policy input must be a JSON object")
    return value


def load_policy(path: Path) -> CapabilityCiPolicy:
    """Load a strict policy and reject symlinks/path tricks/unknown fields."""
    if not isinstance(path, Path):
        raise TypeError("policy path must be Path")
    try:
        policy = CapabilityCiPolicy.model_validate(_read_json(path))
    except ValidationError as error:
        raise PolicyError("policy failed schema or semantic validation") from error
    return policy


def _gate_qualified(registry: LoadedQualifiedGateRegistry | None, gate_id: str) -> bool:
    """Verify one Gate through the pinned registry evidence-binding chain."""
    if registry is None:
        return False
    entry = registry.registry.entry_for(gate_id)
    if entry is None:
        return False
    try:
        verify_gate_qualification(entry, registry_dir=registry.path.parent)
    except PolicyError:
        return False
    return True


def enforce_capability_assessment(
    result: CapabilityAssessmentResult,
    policy: CapabilityCiPolicy,
    *,
    policy_path: Path,
    policy_source_format: str = POLICY_FORMAT,
    policy_source_schema_version: str = POLICY_SCHEMA_VERSION,
    policy_source_sha256: str | None = None,
    qualification_registry: LoadedQualifiedGateRegistry | None = None,
    trust_mode: str = TRUST_MODE_REPOSITORY_LOCAL,
    expected_policy_sha256: str | None = None,
    policy_digest_verified: bool = False,
    expected_registry_sha256: str | None = None,
    registry_digest_verified: bool = False,
    gate_waivers: Mapping[str, tuple[str, ...]] | None = None,
    evaluated_on: date | None = None,
    expired_waiver_ids: tuple[str, ...] = (),
) -> CiEnforcementDecision:
    """Evaluate policy without changing Findings or Shadow Gate contracts."""
    if not isinstance(result, CapabilityAssessmentResult):
        raise TypeError("result must be CapabilityAssessmentResult")
    if not isinstance(policy, CapabilityCiPolicy):
        raise TypeError("policy must be CapabilityCiPolicy")
    registry_id = (
        qualification_registry.registry.registry_id
        if qualification_registry is not None
        else None
    )
    registry_version = (
        qualification_registry.registry.registry_version
        if qualification_registry is not None
        else None
    )
    registry_digest = (
        qualification_registry.sha256 if qualification_registry is not None else None
    )
    if not result.complete:
        return CiEnforcementDecision(
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_enabled=policy.enabled,
            enforcement_mode=policy.enforcement_mode,
            decision="incomplete",
            exit_code=ExitCode.SCAN_INCOMPLETE,
            assessment_complete=False,
            matched_gates=(),
            policy_source_format=policy_source_format,
            policy_source_schema_version=policy_source_schema_version,
            policy_source_sha256=policy_source_sha256,
            qualification_registry_id=registry_id,
            qualification_registry_version=registry_version,
            qualification_registry_sha256=registry_digest,
            trust_mode=trust_mode,
            policy_digest_pinned=expected_policy_sha256 is not None,
            policy_digest_verified=policy_digest_verified,
            expected_policy_sha256=expected_policy_sha256,
            registry_digest_pinned=expected_registry_sha256 is not None,
            registry_digest_verified=registry_digest_verified,
            expected_registry_sha256=expected_registry_sha256,
            evaluated_on=evaluated_on,
            applied_waiver_ids=(),
            expired_waiver_ids=expired_waiver_ids,
            boundary={
                "llm_authority": False,
                "runtime_verified": False,
                "hard_gate": False,
            },
            errors=(
                "assessment coverage or deterministic rule execution is incomplete",
            ),
        )
    if policy.coverage.require_unknown_free and result.analysis.manifest.unknowns:
        return CiEnforcementDecision(
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_enabled=policy.enabled,
            enforcement_mode=policy.enforcement_mode,
            decision="incomplete",
            exit_code=ExitCode.SCAN_INCOMPLETE,
            assessment_complete=True,
            matched_gates=(),
            policy_source_format=policy_source_format,
            policy_source_schema_version=policy_source_schema_version,
            policy_source_sha256=policy_source_sha256,
            qualification_registry_id=registry_id,
            qualification_registry_version=registry_version,
            qualification_registry_sha256=registry_digest,
            trust_mode=trust_mode,
            policy_digest_pinned=expected_policy_sha256 is not None,
            policy_digest_verified=policy_digest_verified,
            expected_policy_sha256=expected_policy_sha256,
            registry_digest_pinned=expected_registry_sha256 is not None,
            registry_digest_verified=registry_digest_verified,
            expected_registry_sha256=expected_registry_sha256,
            evaluated_on=evaluated_on,
            applied_waiver_ids=(),
            expired_waiver_ids=expired_waiver_ids,
            boundary={
                "llm_authority": False,
                "runtime_verified": False,
                "hard_gate": False,
            },
            errors=("policy requires unknown-free evidence",),
        )
    decisions: list[GateDecision] = []
    for gate_id in policy.fail_on.qualified_gates:
        qualified = _gate_qualified(qualification_registry, gate_id)
        finding_ids = tuple(
            sorted(
                finding.finding_id
                for finding in result.rules.findings
                if finding.capability_shadow_gate is not None
                and finding.capability_shadow_gate.gate_id == gate_id
                and finding.capability_shadow_gate.matched
            )
        )
        matched = bool(finding_ids)
        configured_waiver_ids = tuple(sorted((gate_waivers or {}).get(gate_id, ())))
        waived = matched and bool(configured_waiver_ids)
        waiver_ids = configured_waiver_ids if waived else ()
        decisions.append(
            GateDecision(
                gate_id=gate_id,
                qualification="accepted" if qualified else "not_qualified",
                matched=matched,
                blocks=bool(
                    policy.enabled
                    and policy.enforcement_mode == "enforce"
                    and qualified
                    and matched
                    and not waived
                ),
                finding_ids=finding_ids,
                reason=(
                    "qualified deterministic Gate match is waived"
                    if qualified and matched and waived
                    else (
                        "qualified deterministic Gate matched"
                        if qualified and matched
                        else (
                            "Gate qualification is not accepted"
                            if not qualified
                            else "Gate did not match"
                        )
                    )
                ),
                waived=waived,
                waiver_ids=waiver_ids,
            )
        )
    active = policy.enabled and policy.enforcement_mode == "enforce"
    unqualified = tuple(
        item.gate_id for item in decisions if item.qualification != "accepted"
    )
    if active and unqualified:
        return CiEnforcementDecision(
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_enabled=policy.enabled,
            enforcement_mode=policy.enforcement_mode,
            decision="configuration_error",
            exit_code=ExitCode.CONFIGURATION_ERROR,
            assessment_complete=True,
            matched_gates=tuple(decisions),
            policy_source_format=policy_source_format,
            policy_source_schema_version=policy_source_schema_version,
            policy_source_sha256=policy_source_sha256,
            qualification_registry_id=registry_id,
            qualification_registry_version=registry_version,
            qualification_registry_sha256=registry_digest,
            trust_mode=trust_mode,
            policy_digest_pinned=expected_policy_sha256 is not None,
            policy_digest_verified=policy_digest_verified,
            expected_policy_sha256=expected_policy_sha256,
            registry_digest_pinned=expected_registry_sha256 is not None,
            registry_digest_verified=registry_digest_verified,
            expected_registry_sha256=expected_registry_sha256,
            evaluated_on=evaluated_on,
            applied_waiver_ids=tuple(
                sorted({waiver for item in decisions for waiver in item.waiver_ids})
            ),
            expired_waiver_ids=expired_waiver_ids,
            boundary={
                "llm_authority": False,
                "runtime_verified": False,
                "hard_gate": False,
            },
            errors=("enforce policy references an unqualified Gate",),
        )
    blocked = any(item.blocks for item in decisions)
    return CiEnforcementDecision(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_enabled=policy.enabled,
        enforcement_mode=policy.enforcement_mode,
        decision="block" if blocked else "allow",
        exit_code=ExitCode.RISK_THRESHOLD_EXCEEDED if blocked else ExitCode.SUCCESS,
        assessment_complete=True,
        matched_gates=tuple(decisions),
        policy_source_format=policy_source_format,
        policy_source_schema_version=policy_source_schema_version,
        policy_source_sha256=policy_source_sha256,
        qualification_registry_id=registry_id,
        qualification_registry_version=registry_version,
        qualification_registry_sha256=registry_digest,
        trust_mode=trust_mode,
        policy_digest_pinned=expected_policy_sha256 is not None,
        policy_digest_verified=policy_digest_verified,
        expected_policy_sha256=expected_policy_sha256,
        registry_digest_pinned=expected_registry_sha256 is not None,
        registry_digest_verified=registry_digest_verified,
        expected_registry_sha256=expected_registry_sha256,
        evaluated_on=evaluated_on,
        applied_waiver_ids=tuple(
            sorted({waiver for item in decisions for waiver in item.waiver_ids})
        )
        if "decisions" in locals()
        else (),
        expired_waiver_ids=expired_waiver_ids,
        boundary={
            "llm_authority": False,
            "runtime_verified": False,
            "hard_gate": False,
        },
        errors=() if active else ("policy is report-only or disabled; no CI block",),
    )

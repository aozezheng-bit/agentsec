"""P3-19 opt-in Real Provider pilot with fail-closed preflight.

The pilot is a bounded evaluation job.  It can produce semantic evaluation
Evidence, but it cannot qualify a Gate, publish a Rule, alter a Finding, block
CI, approve a waiver, or authorize a release.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.evaluation import (
    SemanticEvaluationHarness,
    SemanticEvaluationReport,
)
from agentsec.semantic.gate_corpus import (
    SemanticGateHumanCorpus,
    verify_semantic_gate_human_corpus,
)
from agentsec.semantic.gate_definition import SemanticGateCandidate
from agentsec.semantic.invocation import SemanticShadowInvocationAdapter
from agentsec.semantic.provider import SemanticInvocationLimits
from agentsec.semantic.provider_specific import (
    OpenAICompatibleProviderConfig,
    OpenAICompatibleSemanticProvider,
)

SEMANTIC_GATE_PILOT_VERSION = "0.1.0"
SEMANTIC_GATE_PILOT_CONFIG_FORMAT = "agentsec-semantic-gate-pilot-config"
SEMANTIC_GATE_PILOT_REPORT_FORMAT = "agentsec-semantic-gate-pilot-report"
_CREDENTIAL_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticGatePilotStatus(StrEnum):
    PREFLIGHT_BLOCKED = "preflight_blocked"
    PREFLIGHT_PASSED = "preflight_passed"
    COMPLETED = "completed"
    FAILED = "failed"


class SemanticGatePilotCheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class SemanticGatePilotConfig(_Strict):
    """Non-secret Pilot config.  Credential values are never model fields."""

    format: Literal["agentsec-semantic-gate-pilot-config"] = (
        "agentsec-semantic-gate-pilot-config"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    endpoint_url: str | None = None
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    credential_env: Annotated[str, Field(min_length=1, max_length=128)]
    corpus_path: Annotated[str, Field(min_length=1, max_length=1024)]
    gate_candidate_path: str | None = None
    max_cases: Annotated[int, Field(ge=1, le=512)] = 40
    max_calls: Annotated[int, Field(ge=1, le=512)] = 40
    timeout_ms: Annotated[int, Field(ge=1, le=120_000)] = 30_000
    allow_live: bool = False
    data_residency_approved: bool = False
    retention_policy_approved: bool = False
    cost_approved: bool = False
    review_owner_id: str | None = None
    approval_id: str | None = None

    @model_validator(mode="after")
    def config_must_be_safe(self) -> SemanticGatePilotConfig:
        if not _CREDENTIAL_ENV_PATTERN.fullmatch(self.credential_env):
            raise ValueError("credential_env must be an uppercase environment name")
        if self.endpoint_url is not None:
            parsed = urlparse(self.endpoint_url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError("Provider endpoint must be an HTTPS URL")
            if parsed.username or parsed.password:
                raise ValueError("Provider endpoint must not contain credentials")
        if self.max_cases > self.max_calls:
            raise ValueError("max_cases cannot exceed max_calls")
        if self.allow_live and (
            self.endpoint_url is None
            or not self.data_residency_approved
            or not self.retention_policy_approved
            or not self.cost_approved
            or not self.review_owner_id
            or not self.approval_id
        ):
            raise ValueError(
                "live Pilot requires endpoint and all organizational approvals"
            )
        return self


class SemanticGatePilotCheck(_Strict):
    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]
    status: SemanticGatePilotCheckStatus
    rationale_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")]


class SemanticGatePilotReport(_Strict):
    """Value-minimized report from preflight or a bounded live evaluation."""

    format: Literal["agentsec-semantic-gate-pilot-report"] = (
        "agentsec-semantic-gate-pilot-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    status: SemanticGatePilotStatus
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    corpus_id: Annotated[str, Field(min_length=1, max_length=160)]
    corpus_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    candidate_id: (
        Annotated[str, Field(pattern=r"^semantic-gate-candidate-sha256:[0-9a-f]{64}$")]
        | None
    ) = None
    requested_case_count: Annotated[int, Field(ge=0)]
    evaluated_case_count: Annotated[int, Field(ge=0)]
    max_calls: Annotated[int, Field(ge=0)]
    live_invocation: bool = False
    checks: tuple[SemanticGatePilotCheck, ...] = ()
    evaluation: SemanticEvaluationReport | None = None
    error_codes: tuple[
        Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")], ...
    ] = ()
    report_only: Literal[True] = True
    shadow_only: Literal[True] = True
    blocks: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    rule_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticGatePilotReport:
        if self.evaluated_case_count > self.requested_case_count:
            raise ValueError("evaluated cases exceed requested cases")
        if self.status is SemanticGatePilotStatus.COMPLETED and self.evaluation is None:
            raise ValueError("completed Pilot report requires evaluation")
        if (
            self.status is not SemanticGatePilotStatus.COMPLETED
            and self.evaluation is not None
        ):
            raise ValueError("blocked or failed Pilot report cannot carry evaluation")
        ids = tuple(item.check_id for item in self.checks)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("Pilot checks must be sorted and unique")
        if self.error_codes != tuple(sorted(set(self.error_codes))):
            raise ValueError("Pilot error codes must be sorted and unique")
        return self


class SemanticGatePilotError(RuntimeError):
    """Safe failure without echoing endpoint, credential, prompt, or response."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic Gate Pilot failed ({code}).")


class SemanticGatePilotRunner:
    """Run a report-only, explicitly approved Gate-specific Provider Pilot."""

    def preflight(
        self,
        config: SemanticGatePilotConfig,
        corpus: SemanticGateHumanCorpus,
        candidate: SemanticGateCandidate | None = None,
        credential_required: bool = True,
    ) -> SemanticGatePilotReport:
        if not isinstance(config, SemanticGatePilotConfig):
            raise TypeError("Pilot config is required")
        if not isinstance(corpus, SemanticGateHumanCorpus):
            raise TypeError("Pilot corpus is required")
        if candidate is not None and not isinstance(candidate, SemanticGateCandidate):
            raise TypeError("Pilot candidate is invalid")
        checks: list[SemanticGatePilotCheck] = []
        errors: list[str] = []
        self._add(
            checks, errors, "live_opt_in", config.allow_live, "live_opt_in_required"
        )
        self._add(
            checks,
            errors,
            "https_endpoint",
            config.endpoint_url is not None,
            "endpoint_required",
        )
        self._add(
            checks,
            errors,
            "credential_available",
            not credential_required or bool(os.environ.get(config.credential_env)),
            "credential_unavailable",
        )
        self._add(
            checks,
            errors,
            "organizational_approval",
            bool(
                config.data_residency_approved
                and config.retention_policy_approved
                and config.cost_approved
                and config.review_owner_id
                and config.approval_id
            ),
            "organizational_approval_missing",
        )
        self._add(
            checks,
            errors,
            "corpus_integrity",
            verify_semantic_gate_human_corpus(corpus),
            "corpus_integrity_invalid",
        )
        self._add(
            checks,
            errors,
            "human_review_complete",
            corpus.coverage.human_confirmed
            and corpus.coverage.unknown_count == 0
            and corpus.coverage.unresolved_count == 0,
            "human_review_incomplete",
        )
        self._add(
            checks,
            errors,
            "corpus_gate_binding",
            candidate is None or candidate.gate_id == corpus.gate_id,
            "corpus_gate_binding_mismatch",
        )
        selected = min(config.max_cases, len(corpus.cases))
        self._add(
            checks,
            errors,
            "call_budget",
            selected <= config.max_calls,
            "call_budget_exceeded",
        )
        status = (
            SemanticGatePilotStatus.PREFLIGHT_PASSED
            if not errors
            else SemanticGatePilotStatus.PREFLIGHT_BLOCKED
        )
        return SemanticGatePilotReport(
            status=status,
            provider_id=config.provider_id,
            model_id=config.model_id,
            gate_id=candidate.gate_id if candidate is not None else corpus.gate_id,
            corpus_id=corpus.corpus_id,
            corpus_sha256=corpus.corpus_sha256,
            candidate_id=candidate.candidate_id if candidate is not None else None,
            requested_case_count=selected,
            evaluated_case_count=0,
            max_calls=config.max_calls,
            live_invocation=False,
            checks=tuple(sorted(checks, key=lambda item: item.check_id)),
            error_codes=tuple(sorted(set(errors))),
        )

    def run(
        self,
        config: SemanticGatePilotConfig,
        corpus: SemanticGateHumanCorpus,
        *,
        candidate: SemanticGateCandidate | None = None,
        adapter: SemanticShadowInvocationAdapter | None = None,
    ) -> SemanticGatePilotReport:
        preflight = self.preflight(
            config,
            corpus,
            candidate,
            credential_required=adapter is None,
        )
        if preflight.status is not SemanticGatePilotStatus.PREFLIGHT_PASSED:
            return preflight
        selected_cases = corpus.evaluation_cases(max_cases=config.max_cases)
        if adapter is None:
            if config.endpoint_url is None:
                raise SemanticGatePilotError("endpoint_required")
            provider = OpenAICompatibleSemanticProvider(
                OpenAICompatibleProviderConfig(
                    endpoint_url=config.endpoint_url,
                    credential_env=config.credential_env,
                    provider_id=config.provider_id,
                    model_id=config.model_id,
                    timeout_ms=config.timeout_ms,
                )
            )
            adapter = SemanticShadowInvocationAdapter(
                provider=provider,
                limits=SemanticInvocationLimits(timeout_ms=config.timeout_ms),
                allow_live_provider=True,
                approved_live_bindings=((config.provider_id, config.model_id),),
            )
        if (
            adapter.provider_metadata.provider_id != config.provider_id
            or adapter.provider_metadata.model_id != config.model_id
        ):
            raise SemanticGatePilotError("provider_binding_mismatch")
        evaluation = SemanticEvaluationHarness().evaluate(selected_cases, adapter)
        return preflight.model_copy(
            update={
                "status": SemanticGatePilotStatus.COMPLETED,
                "evaluated_case_count": len(selected_cases),
                "live_invocation": True,
                "evaluation": evaluation,
            }
        )

    @staticmethod
    def _add(
        checks: list[SemanticGatePilotCheck],
        errors: list[str],
        check_id: str,
        passed: bool,
        failure_code: str,
    ) -> None:
        checks.append(
            SemanticGatePilotCheck(
                check_id=check_id,
                status=SemanticGatePilotCheckStatus.PASS
                if passed
                else SemanticGatePilotCheckStatus.FAIL,
                rationale_code="preflight_passed" if passed else failure_code,
            )
        )
        if not passed:
            errors.append(failure_code)


def encode_semantic_gate_pilot_json(report: SemanticGatePilotReport) -> str:
    if not isinstance(report, SemanticGatePilotReport):
        raise TypeError("Pilot encoder requires SemanticGatePilotReport")
    import json

    return (
        json.dumps(
            report.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def render_semantic_gate_pilot_text(report: SemanticGatePilotReport) -> str:
    if not isinstance(report, SemanticGatePilotReport):
        raise TypeError("Pilot renderer requires SemanticGatePilotReport")
    lines = [
        "AgentSec Semantic Gate Real Provider Pilot",
        f"Gate: {report.gate_id}",
        f"Provider: {report.provider_id}",
        f"Model: {report.model_id}",
        f"Status: {report.status.value}",
        (
            "Cases: "
            f"requested={report.requested_case_count}, "
            f"evaluated={report.evaluated_case_count}"
        ),
        "Checks:",
    ]
    lines.extend(
        f"  {item.check_id}: {item.status.value} - {item.rationale_code}"
        for item in report.checks
    )
    if report.evaluation is not None:
        metrics = report.evaluation.metrics
        lines.extend(
            (
                f"Precision: {metrics.precision:.3f}",
                f"Recall: {metrics.recall:.3f}",
                f"F1: {metrics.f1:.3f}",
            )
        )
    lines.extend(
        (
            "Mode: shadow_only; report_only=true; live_invocation is opt-in.",
            (
                "Authority: blocks=false; policy_authority=false; "
                "ci_authority=false; rule_authority=false; release_authority=false"
            ),
        )
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "SEMANTIC_GATE_PILOT_CONFIG_FORMAT",
    "SEMANTIC_GATE_PILOT_REPORT_FORMAT",
    "SEMANTIC_GATE_PILOT_VERSION",
    "SemanticGatePilotCheck",
    "SemanticGatePilotCheckStatus",
    "SemanticGatePilotConfig",
    "SemanticGatePilotError",
    "SemanticGatePilotReport",
    "SemanticGatePilotRunner",
    "SemanticGatePilotStatus",
    "encode_semantic_gate_pilot_json",
    "render_semantic_gate_pilot_text",
]

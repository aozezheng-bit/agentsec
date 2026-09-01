"""P3-08 end-to-end Semantic Shadow pipeline composition.

This is an orchestration seam only: the Provider result, Finding links, and
Rule Candidate proposals remain report-only and are never enforcement inputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.domain import Finding
from agentsec.semantic.integration import (
    SemanticFindingIntegrationReport,
    SemanticFindingIntegrator,
    SemanticRuleCandidateReport,
    SemanticRuleCandidateWorkflow,
)
from agentsec.semantic.invocation import (
    SemanticShadowInvocationAdapter,
    SemanticShadowInvocationResult,
)
from agentsec.semantic.models import SemanticAnalysisInput, SemanticEvidenceChunk

SEMANTIC_SHADOW_PIPELINE_VERSION = "0.1.0"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SemanticShadowPipelineReport(_Strict):
    """Stable aggregate of one Shadow invocation and its report-only outputs."""

    format: Literal["agentsec-semantic-shadow-pipeline-report"] = (
        "agentsec-semantic-shadow-pipeline-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    pipeline_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    invocation: SemanticShadowInvocationResult
    finding_integration: SemanticFindingIntegrationReport
    rule_candidates: SemanticRuleCandidateReport
    report_only: Literal[True] = True
    finding_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    severity_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    runtime_verified: Literal[False] = False
    blocks: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticShadowPipelineReport:
        result_digest = _result_digest(self.invocation.analysis)
        if self.finding_integration.semantic_result_sha256 != result_digest:
            raise ValueError("pipeline Finding integration result hash is inconsistent")
        if self.rule_candidates.semantic_result_sha256 != result_digest:
            raise ValueError("pipeline Rule Candidate result hash is inconsistent")
        expected = _pipeline_digest(
            self.invocation,
            self.finding_integration,
            self.rule_candidates,
        )
        if self.pipeline_sha256 != expected:
            raise ValueError("semantic pipeline digest is inconsistent")
        return self


class SemanticShadowPipeline:
    """Compose invocation, Finding integration, and Rule proposal generation."""

    def __init__(
        self,
        adapter: SemanticShadowInvocationAdapter,
        *,
        finding_integrator: SemanticFindingIntegrator | None = None,
        rule_candidate_workflow: SemanticRuleCandidateWorkflow | None = None,
    ) -> None:
        if not isinstance(adapter, SemanticShadowInvocationAdapter):
            raise TypeError("semantic Shadow pipeline requires a Shadow adapter")
        self._adapter = adapter
        self._finding_integrator = finding_integrator or SemanticFindingIntegrator()
        self._rule_candidate_workflow = (
            rule_candidate_workflow or SemanticRuleCandidateWorkflow()
        )

    def run(
        self,
        semantic_input: SemanticAnalysisInput,
        *,
        findings: tuple[Finding, ...] = (),
        evidence: tuple[SemanticEvidenceChunk, ...] = (),
    ) -> SemanticShadowPipelineReport:
        if not isinstance(semantic_input, SemanticAnalysisInput):
            raise TypeError("semantic input must be SemanticAnalysisInput")
        invocation = self._adapter.invoke(semantic_input)
        finding_integration = self._finding_integrator.integrate(
            invocation.analysis,
            findings,
            evidence,
        )
        rule_candidates = self._rule_candidate_workflow.propose(invocation.analysis)
        return SemanticShadowPipelineReport(
            pipeline_sha256=_pipeline_digest(
                invocation,
                finding_integration,
                rule_candidates,
            ),
            invocation=invocation,
            finding_integration=finding_integration,
            rule_candidates=rule_candidates,
        )


def _result_digest(result: object) -> str:
    if not isinstance(result, BaseModel):
        raise TypeError("semantic result must be a model")
    return hashlib.sha256(
        json.dumps(
            result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def _pipeline_digest(
    invocation: SemanticShadowInvocationResult,
    finding_integration: SemanticFindingIntegrationReport,
    rule_candidates: SemanticRuleCandidateReport,
) -> str:
    payload = {
        "invocation": invocation.model_dump(mode="json"),
        "finding_integration": finding_integration.model_dump(mode="json"),
        "rule_candidates": rule_candidates.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


__all__ = [
    "SEMANTIC_SHADOW_PIPELINE_VERSION",
    "SemanticShadowPipeline",
    "SemanticShadowPipelineReport",
]

"""P3-16 batch Shadow Mode pipeline over many semantic inputs.

Wraps the P3-08 single-input ``SemanticShadowPipeline`` in the plan's
Shadow Mode semantics: run a whole batch of semantic inputs through the
Shadow pipeline, record every case, and block nothing. A single case
whose Shadow invocation fails with a P3-02 stable error code is recorded
as a failed row (``error_code``, zero child digest) and the batch
continues — Shadow Mode must never interrupt deterministic scanning or
any decision path. Structural or contract defects (wrong types, invalid
models) still fail closed because they are not stable Provider failures.

Every batch output row is value-free (case id, digests, stable error
codes, and count summaries only); no corpus text, raw request/response
payloads, or model summaries are retained by the aggregate. The report
grants no Finding, Rule, Policy, CI, Hard Gate, or release authority and
records ``deterministic_decisions_affected=false`` explicitly: the batch
cannot change any deterministic decision, only add recorded evidence.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.domain import Finding
from agentsec.semantic.invocation import SemanticShadowInvocationError
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticEvidenceChunk,
)
from agentsec.semantic.p3_08 import SemanticShadowPipeline

SEMANTIC_SHADOW_MODE_VERSION = "0.1.0"
SEMANTIC_SHADOW_MODE_OUTPUT_VERSION = "0.1.0"
_MAX_SHADOW_MODE_CASES = 256
_MAX_ERROR_CODE = 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_SHADOW_MODE_NOTE = (
    "Batch Shadow Mode: every case runs through the P3-05/P3-08 Shadow "
    "pipeline and is recorded; stable invocation failures become failed "
    "rows and never interrupt the batch. Deterministic decisions, "
    "Findings, Rules, Policies, CI, and releases are never affected."
)


class ShadowModeError(RuntimeError):
    """Safe Shadow Mode failure without echoing any corpus text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic Shadow Mode failed ({code}).")


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class ShadowModeCaseStatus(StrEnum):
    """Per-case outcome recorded by one Shadow Mode batch run."""

    COMPLETE = "complete"
    FAILED = "failed"


class ShadowModeCaseResult(_Strict):
    """Value-free per-case row; child digests replace nested reports."""

    format: Literal["agentsec-p3-16-shadow-mode-case-result"] = (
        "agentsec-p3-16-shadow-mode-case-result"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    analysis_id: Annotated[str, Field(min_length=1, max_length=128)]
    status: ShadowModeCaseStatus
    pipeline_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)] | None = None
    error_code: Annotated[str, Field(max_length=_MAX_ERROR_CODE)] | None = None
    candidate_count: Annotated[int, Field(ge=0, le=128)]
    link_count: Annotated[int, Field(ge=0)]
    proposal_count: Annotated[int, Field(ge=0, le=128)]

    @model_validator(mode="after")
    def result_must_be_coherent(self) -> ShadowModeCaseResult:
        if self.status is ShadowModeCaseStatus.COMPLETE:
            if self.pipeline_sha256 is None or self.error_code is not None:
                raise ValueError("complete Shadow Mode row requires a pipeline digest")
        else:
            if self.pipeline_sha256 is not None or self.error_code is None:
                raise ValueError(
                    "failed Shadow Mode row requires an error code and no digest"
                )
        return self

    def row_digest_payload(self) -> dict[str, object]:
        return {
            "analysis_id": self.analysis_id,
            "status": self.status.value,
            "pipeline_sha256": self.pipeline_sha256,
            "error_code": self.error_code,
            "candidate_count": self.candidate_count,
            "link_count": self.link_count,
            "proposal_count": self.proposal_count,
        }


class SemanticShadowModeReport(_Strict):
    """Immutable batch Shadow Mode record; blocks nothing by construction."""

    format: Literal["agentsec-p3-16-semantic-shadow-mode-report"] = (
        "agentsec-p3-16-semantic-shadow-mode-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    shadow_mode_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    case_count: Annotated[int, Field(ge=1, le=_MAX_SHADOW_MODE_CASES)]
    completed_case_count: Annotated[int, Field(ge=0)]
    failed_case_count: Annotated[int, Field(ge=0)]
    candidate_count: Annotated[int, Field(ge=0)]
    link_count: Annotated[int, Field(ge=0)]
    proposal_count: Annotated[int, Field(ge=0)]
    cases: Annotated[
        tuple[ShadowModeCaseResult, ...],
        Field(min_length=1, max_length=_MAX_SHADOW_MODE_CASES),
    ]
    note: Annotated[str, Field(min_length=8, max_length=512)] = _SHADOW_MODE_NOTE
    operating_mode: Literal["shadow_only"] = "shadow_only"
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    deterministic_decisions_affected: Literal[False] = False
    finding_authority: Literal[False] = False
    rule_publication_authority: Literal[False] = False
    severity_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    runtime_disclosure_allowed: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticShadowModeReport:
        if self.case_count != len(self.cases):
            raise ValueError("Shadow Mode case count is inconsistent")
        if self.completed_case_count != sum(
            case.status is ShadowModeCaseStatus.COMPLETE for case in self.cases
        ):
            raise ValueError("Shadow Mode completed count is inconsistent")
        if self.completed_case_count + self.failed_case_count != self.case_count:
            raise ValueError("Shadow Mode outcome counts are inconsistent")
        if self.candidate_count != sum(case.candidate_count for case in self.cases):
            raise ValueError("Shadow Mode candidate count is inconsistent")
        if self.link_count != sum(case.link_count for case in self.cases):
            raise ValueError("Shadow Mode link count is inconsistent")
        if self.proposal_count != sum(case.proposal_count for case in self.cases):
            raise ValueError("Shadow Mode proposal count is inconsistent")
        ids = tuple(case.analysis_id for case in self.cases)
        if ids != tuple(sorted(set(ids))):
            raise ValueError(
                "Shadow Mode rows must be sorted by Analysis ID and unique"
            )
        expected = _shadow_mode_digest(self.cases)
        if self.shadow_mode_sha256 != expected:
            raise ValueError("Shadow Mode aggregate digest is inconsistent")
        return self


class ShadowModeCase:
    """One batch entry: input plus optional deterministic context inputs."""

    __slots__ = ("evidence", "findings", "semantic_input")

    def __init__(
        self,
        semantic_input: SemanticAnalysisInput,
        *,
        findings: tuple[Finding, ...] = (),
        evidence: tuple[SemanticEvidenceChunk, ...] = (),
    ) -> None:
        if not isinstance(semantic_input, SemanticAnalysisInput):
            raise TypeError("Shadow Mode case requires SemanticAnalysisInput")
        if not isinstance(findings, tuple) or any(
            not isinstance(item, Finding) for item in findings
        ):
            raise TypeError("Shadow Mode case findings must be a tuple of Finding")
        if not isinstance(evidence, tuple) or any(
            not isinstance(item, SemanticEvidenceChunk) for item in evidence
        ):
            raise TypeError(
                "Shadow Mode case evidence must be a tuple of SemanticEvidenceChunk"
            )
        self.semantic_input = semantic_input
        self.findings = findings
        self.evidence = evidence

    @property
    def analysis_id(self) -> str:
        return self.semantic_input.analysis_id


class SemanticShadowModeRunner:
    """Run a batch of cases through Shadow Mode without blocking anything."""

    def __init__(self, pipeline: SemanticShadowPipeline | None = None) -> None:
        if pipeline is not None and not isinstance(pipeline, SemanticShadowPipeline):
            raise TypeError("Shadow Mode runner requires a SemanticShadowPipeline")
        self._pipeline = pipeline

    def run_cases(
        self,
        cases: tuple[ShadowModeCase, ...],
        *,
        adapter: object | None = None,
    ) -> SemanticShadowModeReport:
        if not isinstance(cases, tuple) or not cases:
            raise ShadowModeError("cases_missing")
        if len(cases) > _MAX_SHADOW_MODE_CASES:
            raise ShadowModeError("case_bound_exceeded")
        pipeline = self._pipeline
        if pipeline is None:
            if adapter is None:
                raise ShadowModeError("pipeline_missing")
            try:
                pipeline = _pipeline_from_adapter(adapter)
            except TypeError as error:
                raise ShadowModeError("adapter_invalid") from error
        ids: list[str] = []
        for case in cases:
            if not isinstance(case, ShadowModeCase):
                raise ShadowModeError("case_type_invalid")
            ids.append(case.analysis_id)
        if len(set(ids)) != len(ids):
            raise ShadowModeError("duplicate_analysis_id")

        rows: list[ShadowModeCaseResult] = []
        for case in cases:
            rows.append(self._run_one(pipeline, case))
        rows.sort(key=lambda row: row.analysis_id)
        return SemanticShadowModeReport(
            shadow_mode_sha256=_shadow_mode_digest(tuple(rows)),
            case_count=len(rows),
            completed_case_count=sum(
                row.status is ShadowModeCaseStatus.COMPLETE for row in rows
            ),
            failed_case_count=sum(
                row.status is ShadowModeCaseStatus.FAILED for row in rows
            ),
            candidate_count=sum(row.candidate_count for row in rows),
            link_count=sum(row.link_count for row in rows),
            proposal_count=sum(row.proposal_count for row in rows),
            cases=tuple(rows),
        )

    def _run_one(
        self, pipeline: SemanticShadowPipeline, case: ShadowModeCase
    ) -> ShadowModeCaseResult:
        """Run one case; stable invocation failures become failed rows."""

        try:
            report = pipeline.run(
                case.semantic_input,
                findings=case.findings,
                evidence=case.evidence,
            )
        except SemanticShadowInvocationError as error:
            return ShadowModeCaseResult(
                analysis_id=case.analysis_id,
                status=ShadowModeCaseStatus.FAILED,
                error_code=error.code.value,
                candidate_count=0,
                link_count=0,
                proposal_count=0,
            )
        return ShadowModeCaseResult(
            analysis_id=case.analysis_id,
            status=ShadowModeCaseStatus.COMPLETE,
            pipeline_sha256=report.pipeline_sha256,
            candidate_count=len(report.invocation.analysis.candidates),
            link_count=len(report.finding_integration.links),
            proposal_count=len(report.rule_candidates.proposals),
        )


def _pipeline_from_adapter(adapter: object) -> SemanticShadowPipeline:
    """Build a default pipeline from a Shadow adapter when none is given."""

    from agentsec.semantic.invocation import SemanticShadowInvocationAdapter

    if not isinstance(adapter, SemanticShadowInvocationAdapter):
        raise TypeError("Shadow Mode adapter must be SemanticShadowInvocationAdapter")
    return SemanticShadowPipeline(adapter=adapter)


def _shadow_mode_digest(rows: tuple[ShadowModeCaseResult, ...]) -> str:
    payload = {
        "cases": [row.row_digest_payload() for row in rows],
        "version": SEMANTIC_SHADOW_MODE_VERSION,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def encode_semantic_shadow_mode_json(value: SemanticShadowModeReport) -> str:
    """Encode the Shadow Mode report as canonical versioned JSON."""

    if not isinstance(value, SemanticShadowModeReport):
        raise TypeError("Shadow Mode encoder requires SemanticShadowModeReport")
    return value.model_dump_json(indent=2)


__all__ = [
    "SEMANTIC_SHADOW_MODE_OUTPUT_VERSION",
    "SEMANTIC_SHADOW_MODE_VERSION",
    "SemanticShadowModeReport",
    "SemanticShadowModeRunner",
    "ShadowModeCase",
    "ShadowModeCaseResult",
    "ShadowModeCaseStatus",
    "ShadowModeError",
    "encode_semantic_shadow_mode_json",
]

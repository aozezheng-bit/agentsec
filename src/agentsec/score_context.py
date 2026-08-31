"""Bounded explicit context contract for the Integrated Agentic Score.

Drift and Governance semantics are never fabricated. They come from this
explicit, bounded, safe-loaded context artifact (or from conservative
unknown defaults when no context is supplied).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.domain import EvidenceConfidence
from agentsec.risk.drift_score import (
    DriftApprovalStatus,
    DriftBaselineTrust,
    DriftChangeSource,
    DriftDeploymentScope,
    DriftScoreContext,
)
from agentsec.risk.governance_score import (
    GovernanceReviewStatus,
    GovernanceScoreContext,
)
from agentsec.risk.hard_gate_models import HardGateFloor
from agentsec.risk.overall_score import (
    OverallHardGateMatch,
    OverallHardGateQualification,
    OverallHardGateSource,
)

SCORE_CONTEXT_FORMAT = "agentsec-score-context"
SCORE_CONTEXT_MAX_SIZE_BYTES = 2_097_152
_GATE_ID_PATTERN = re.compile(r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
_STABLE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*-sha256:[0-9a-f]{64}$")


class ScoreContextError(ValueError):
    """Safe score-context input or semantic failure."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ScoreContextDrift(_Strict):
    """Reviewed drift semantics; every value defaults to unknown/conservative."""

    change_source: DriftChangeSource = DriftChangeSource.UNKNOWN
    approval_status: DriftApprovalStatus = DriftApprovalStatus.UNKNOWN
    approval_reference: Annotated[str, Field(max_length=512)] | None = None
    deployment_scope: DriftDeploymentScope = DriftDeploymentScope.UNKNOWN
    baseline_trust: DriftBaselineTrust = DriftBaselineTrust.UNKNOWN

    def to_engine_context(self) -> DriftScoreContext:
        return DriftScoreContext(
            change_source=self.change_source,
            approval_status=self.approval_status,
            deployment_scope=self.deployment_scope,
            baseline_trust=self.baseline_trust,
            approval_reference=self.approval_reference,
        )


class ScoreContextGovernance(_Strict):
    """Reviewed governance semantics; defaults remain unknown/conservative."""

    review_status: GovernanceReviewStatus = GovernanceReviewStatus.UNKNOWN
    policy_owner: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    approval_owner: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    waiver_count: Annotated[int, Field(ge=0, le=10_000)] = 0
    expired_waiver_count: Annotated[int, Field(ge=0, le=10_000)] = 0

    def to_engine_context(self, drift: DriftScoreContext) -> GovernanceScoreContext:
        return GovernanceScoreContext(
            drift=drift,
            review_status=self.review_status,
            policy_owner=self.policy_owner,
            approval_owner=self.approval_owner,
            waiver_count=self.waiver_count,
            expired_waiver_count=self.expired_waiver_count,
        )


class ScoreContextCvss(_Strict):
    """Optional explicit CVSS base input for the technical high-water mark."""

    vector: Annotated[str, Field(min_length=5, max_length=1024)]


class ScoreContextGateMatch(_Strict):
    """One accepted deterministic Gate match allowed to set a report-only floor."""

    gate_id: Annotated[str, Field(pattern=r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")]
    floor: HardGateFloor
    source: OverallHardGateSource
    evidence_ids: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = (
        Field(min_length=1)
    )
    confidence: EvidenceConfidence
    rationale: tuple[Annotated[str, Field(min_length=10, max_length=1024)], ...] = (
        Field(min_length=1)
    )

    def to_engine_match(self) -> OverallHardGateMatch:
        return OverallHardGateMatch(
            gate_id=self.gate_id,
            floor=self.floor,
            source=self.source,
            qualification=OverallHardGateQualification.ACCEPTED,
            evidence_ids=tuple(sorted(set(self.evidence_ids))),
            confidence=self.confidence,
            rationale=self.rationale,
        )


class AgenticScoreContext(_Strict):
    """Strict bounded context for one Integrated Agentic Score run."""

    format: Literal["agentsec-score-context"]
    schema_version: Literal["0.1.0"]
    drift: ScoreContextDrift = ScoreContextDrift()
    governance: ScoreContextGovernance | None = None
    cvss: ScoreContextCvss | None = None
    gate_matches: tuple[ScoreContextGateMatch, ...] = ()

    @model_validator(mode="after")
    def gate_matches_must_be_safe(self) -> AgenticScoreContext:
        gate_ids = tuple(item.gate_id for item in self.gate_matches)
        if len(gate_ids) != len(set(gate_ids)):
            raise ValueError("score context gate matches must be unique")
        for item in self.gate_matches:
            if item.confidence not in {
                EvidenceConfidence.A,
                EvidenceConfidence.B,
                EvidenceConfidence.C,
            }:
                raise ValueError(
                    "D-confidence evidence cannot set an Overall Hard Gate floor"
                )
            for evidence_id in item.evidence_ids:
                if _STABLE_ID_PATTERN.fullmatch(evidence_id) is None:
                    raise ValueError("score context evidence ID is invalid")
        return self


@dataclass(frozen=True, slots=True)
class LoadedScoreContext:
    """A validated score context plus safe provenance."""

    context: AgenticScoreContext
    path: Path
    sha256: str
    size_bytes: int


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("score context has duplicate keys")
        result[key] = value
    return result


def load_score_context(path: Path) -> LoadedScoreContext:
    """Load one bounded regular no-follow score-context JSON file."""

    if not isinstance(path, Path):
        raise TypeError("score context path must be a Path")
    if path.is_symlink() or not path.is_file():
        raise ScoreContextError("score context is missing or unsafe")
    raw = path.read_bytes()
    if len(raw) > SCORE_CONTEXT_MAX_SIZE_BYTES:
        raise ScoreContextError("score context exceeds the bounded size limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ScoreContextError("score context is invalid JSON") from error
    if not isinstance(payload, dict):
        raise ScoreContextError("score context must be a JSON object")
    try:
        context = AgenticScoreContext.model_validate(payload)
    except Exception as error:
        raise ScoreContextError(
            "score context failed schema or semantic validation"
        ) from error
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ScoreContextError("score context path could not be resolved") from error
    return LoadedScoreContext(
        context=context,
        path=resolved,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )

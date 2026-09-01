"""Explicit local Severity threshold policy for P2-26 ``scan --fail-on``."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, model_validator

from agentsec.domain import Assessment, Severity
from agentsec.versioning import FAIL_ON_POLICY_VERSION

_FAIL_ON_POLICY_VERSION = cast(Literal["0.1.0"], FAIL_ON_POLICY_VERSION)

_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FailOnThreshold(StrEnum):
    """Supported explicit local blocking thresholds."""

    HIGH = "high"
    CRITICAL = "critical"


class FailOnDecisionState(StrEnum):
    """Stable deterministic result of one local fail-on evaluation."""

    ALLOW = "allow"
    BLOCK = "block"
    INCOMPLETE = "incomplete"


class FailOnDecision(BaseModel):
    """Evidence-minimizing local CLI decision separated from the Assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: Literal["0.1.0"]
    threshold: FailOnThreshold
    basis: Literal["agentsec_severity"] = "agentsec_severity"
    decision: FailOnDecisionState
    exit_code: Literal[0, 1, 2]
    coverage_complete: bool
    blocks: bool
    highest_observed_severity: Severity
    matched_finding_ids: tuple[str, ...]
    rationale: tuple[str, ...]

    @model_validator(mode="after")
    def fields_must_be_coherent(self) -> FailOnDecision:
        if self.matched_finding_ids != tuple(sorted(set(self.matched_finding_ids))):
            raise ValueError("fail-on matched Finding IDs must be sorted and unique")
        if not self.rationale:
            raise ValueError("fail-on decision requires a trusted rationale")
        if self.decision is FailOnDecisionState.INCOMPLETE:
            if self.coverage_complete or self.blocks:
                raise ValueError("incomplete fail-on decision cannot block")
            if self.exit_code != 2:
                raise ValueError("incomplete fail-on decision must return exit 2")
        elif self.decision is FailOnDecisionState.BLOCK:
            if not self.coverage_complete or not self.blocks:
                raise ValueError("blocking fail-on decision requires complete Coverage")
            if not self.matched_finding_ids:
                raise ValueError("blocking fail-on decision requires a matched Finding")
            if self.exit_code != 1:
                raise ValueError("blocking fail-on decision must return exit 1")
        else:
            if not self.coverage_complete or self.blocks or self.matched_finding_ids:
                raise ValueError(
                    "allow fail-on decision must be complete and unmatched"
                )
            if self.exit_code != 0:
                raise ValueError("allow fail-on decision must return exit 0")
        return self


def evaluate_assessment_fail_on(
    assessment: Assessment,
    threshold: FailOnThreshold,
) -> FailOnDecision:
    """Evaluate an explicit AgentSec Severity threshold without runtime inference."""

    if not isinstance(assessment, Assessment):
        raise TypeError("fail-on evaluation requires an Assessment")
    if not isinstance(threshold, FailOnThreshold):
        raise TypeError("fail-on threshold must be FailOnThreshold")

    threshold_rank = _SEVERITY_RANK[Severity(threshold.value)]
    matched_finding_ids = tuple(
        sorted(
            finding.finding_id
            for finding in assessment.findings
            if _SEVERITY_RANK[finding.severity] >= threshold_rank
        )
    )
    highest_observed = max(
        (finding.severity for finding in assessment.findings),
        key=_SEVERITY_RANK.__getitem__,
        default=Severity.NONE,
    )

    if not assessment.coverage.complete:
        return FailOnDecision(
            policy_version=_FAIL_ON_POLICY_VERSION,
            threshold=threshold,
            decision=FailOnDecisionState.INCOMPLETE,
            exit_code=2,
            coverage_complete=False,
            blocks=False,
            highest_observed_severity=highest_observed,
            matched_finding_ids=matched_finding_ids,
            rationale=(
                "Coverage is incomplete; the risk threshold cannot override exit 2.",
            ),
        )
    if matched_finding_ids:
        return FailOnDecision(
            policy_version=_FAIL_ON_POLICY_VERSION,
            threshold=threshold,
            decision=FailOnDecisionState.BLOCK,
            exit_code=1,
            coverage_complete=True,
            blocks=True,
            highest_observed_severity=highest_observed,
            matched_finding_ids=matched_finding_ids,
            rationale=(
                "At least one deterministic Finding meets or exceeds the explicit "
                "AgentSec Severity threshold.",
            ),
        )
    return FailOnDecision(
        policy_version=_FAIL_ON_POLICY_VERSION,
        threshold=threshold,
        decision=FailOnDecisionState.ALLOW,
        exit_code=0,
        coverage_complete=True,
        blocks=False,
        highest_observed_severity=highest_observed,
        matched_finding_ids=(),
        rationale=(
            "No deterministic Finding meets or exceeds the explicit AgentSec "
            "Severity threshold.",
        ),
    )


__all__ = [
    "FailOnDecision",
    "FailOnDecisionState",
    "FailOnThreshold",
    "evaluate_assessment_fail_on",
]

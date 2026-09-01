"""Deterministic report-only CVSS Hard Gate evaluation.

P2-24 evaluates the effective CVSS score already attached to each Finding.  It
adds a separate report-only gate view and deliberately does not overwrite
AgentSec's score, Severity, generic ``hard_gate`` flag, or CLI exit status.
"""

from __future__ import annotations

from typing import Protocol

from agentsec.domain import (
    Assessment,
    CvssHardGateAssessment,
    CvssHardGateMatch,
    Finding,
)
from agentsec.risk.cvss import CvssScoreType, severity_for_cvss_score
from agentsec.versioning import CVSS_HARD_GATE_VERSION

CVSS_HARD_GATE_MAPPING_BASIS = (
    "FIRST CVSS qualitative severity thresholds: High >= 7.0 and Critical >= 9.0",
    "AgentSec P2-24 CVSS report-only Hard Gate contract 0.1.0",
)
CVSS_HARD_GATE_HIGH_ID = "HG-CVSS-001"
CVSS_HARD_GATE_CRITICAL_ID = "HG-CVSS-002"
CVSS_HARD_GATE_HIGH_THRESHOLD = 7.0
CVSS_HARD_GATE_CRITICAL_THRESHOLD = 9.0


class CvssHardGateEngine(Protocol):
    """Application seam for non-enforcing CVSS gate evaluation."""

    def apply(self, assessment: Assessment) -> Assessment:
        """Return an Assessment with CVSS gate evaluations attached."""


class DeterministicCvssHardGateEngine:
    """Evaluate CVSS High/Critical thresholds without changing AgentSec risk."""

    def apply(self, assessment: Assessment) -> Assessment:
        """Attach one report-only CVSS gate evaluation per CVSS-bearing Finding."""

        if not isinstance(assessment, Assessment):
            raise TypeError("CVSS Hard Gate requires an Assessment")
        findings = tuple(self.apply_finding(finding) for finding in assessment.findings)
        return assessment.model_copy(update={"findings": findings})

    def apply_finding(self, finding: Finding) -> Finding:
        """Evaluate one Finding and preserve all non-CVSS risk fields."""

        if not isinstance(finding, Finding):
            raise TypeError("CVSS Hard Gate requires a Finding")
        if finding.cvss is None:
            return finding
        score = finding.cvss.effective_score
        if score is None:
            raise ValueError("CVSS effective score must be present before gating")
        score_type = CvssScoreType(finding.cvss.score_type)
        match = _match_for_score(score, score_type)
        gate = CvssHardGateAssessment(
            gate_version=CVSS_HARD_GATE_VERSION,
            finding_id=finding.finding_id,
            mode="report_only",
            score=score,
            severity=severity_for_cvss_score(score),
            score_type=score_type.value,
            match=match,
            mapping_basis=CVSS_HARD_GATE_MAPPING_BASIS,
        )
        return finding.attach_cvss_hard_gate(gate)


def _match_for_score(
    score: float,
    score_type: CvssScoreType,
) -> CvssHardGateMatch | None:
    """Return the strongest applicable threshold match without averaging."""

    if score >= CVSS_HARD_GATE_CRITICAL_THRESHOLD:
        return CvssHardGateMatch(
            gate_id=CVSS_HARD_GATE_CRITICAL_ID,
            floor="critical",
            threshold=CVSS_HARD_GATE_CRITICAL_THRESHOLD,
            score=score,
            score_type=score_type.value,
            rationale=(
                "Effective CVSS score met the Critical report-only threshold.",
                "This match is evidence only and does not block CI.",
            ),
        )
    if score >= CVSS_HARD_GATE_HIGH_THRESHOLD:
        return CvssHardGateMatch(
            gate_id=CVSS_HARD_GATE_HIGH_ID,
            floor="high",
            threshold=CVSS_HARD_GATE_HIGH_THRESHOLD,
            score=score,
            score_type=score_type.value,
            rationale=(
                "Effective CVSS score met the High report-only threshold.",
                "This match is evidence only and does not block CI.",
            ),
        )
    return None

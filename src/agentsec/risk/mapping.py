"""Standards-derived and AgentSec policy mappings for Risk Model v0."""

from __future__ import annotations

import math

from agentsec.domain import ImpactLevel, LikelihoodLevel, Severity
from agentsec.risk.levels import NistRiskLevel

NIST_MATRIX_BASIS = "NIST SP 800-30 Rev. 1 Table I-2 likelihood-impact matrix"
IMPACT_AGGREGATION_BASIS = (
    "FIPS 199 high-water-mark principle adapted to AgentSec impact dimensions"
)
AGENTSEC_SCORE_MAPPING_BASIS = (
    "AgentSec project plan section 6.7.2 representative 0-10 base-score mapping"
)
SEVERITY_MAPPING_BASIS = "FIRST CVSS v4.0 qualitative severity rating scale"
RISK_MAPPING_BASIS = (
    NIST_MATRIX_BASIS,
    IMPACT_AGGREGATION_BASIS,
    AGENTSEC_SCORE_MAPPING_BASIS,
    SEVERITY_MAPPING_BASIS,
)

_RISK_MATRIX = {
    LikelihoodLevel.VERY_LOW: {
        ImpactLevel.VERY_LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.MODERATE: NistRiskLevel.VERY_LOW,
        ImpactLevel.HIGH: NistRiskLevel.VERY_LOW,
        ImpactLevel.VERY_HIGH: NistRiskLevel.LOW,
    },
    LikelihoodLevel.LOW: {
        ImpactLevel.VERY_LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.LOW: NistRiskLevel.LOW,
        ImpactLevel.MODERATE: NistRiskLevel.LOW,
        ImpactLevel.HIGH: NistRiskLevel.LOW,
        ImpactLevel.VERY_HIGH: NistRiskLevel.MODERATE,
    },
    LikelihoodLevel.MODERATE: {
        ImpactLevel.VERY_LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.LOW: NistRiskLevel.LOW,
        ImpactLevel.MODERATE: NistRiskLevel.MODERATE,
        ImpactLevel.HIGH: NistRiskLevel.MODERATE,
        ImpactLevel.VERY_HIGH: NistRiskLevel.HIGH,
    },
    LikelihoodLevel.HIGH: {
        ImpactLevel.VERY_LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.LOW: NistRiskLevel.LOW,
        ImpactLevel.MODERATE: NistRiskLevel.MODERATE,
        ImpactLevel.HIGH: NistRiskLevel.HIGH,
        ImpactLevel.VERY_HIGH: NistRiskLevel.VERY_HIGH,
    },
    LikelihoodLevel.VERY_HIGH: {
        ImpactLevel.VERY_LOW: NistRiskLevel.VERY_LOW,
        ImpactLevel.LOW: NistRiskLevel.LOW,
        ImpactLevel.MODERATE: NistRiskLevel.MODERATE,
        ImpactLevel.HIGH: NistRiskLevel.HIGH,
        ImpactLevel.VERY_HIGH: NistRiskLevel.VERY_HIGH,
    },
}
_NIST_SEMI_QUANTITATIVE_VALUES = {
    NistRiskLevel.VERY_LOW: 0,
    NistRiskLevel.LOW: 2,
    NistRiskLevel.MODERATE: 5,
    NistRiskLevel.HIGH: 8,
    NistRiskLevel.VERY_HIGH: 10,
}
_AGENTSEC_BASE_SCORES = {
    NistRiskLevel.VERY_LOW: 0.0,
    NistRiskLevel.LOW: 2.0,
    NistRiskLevel.MODERATE: 5.5,
    NistRiskLevel.HIGH: 8.0,
    NistRiskLevel.VERY_HIGH: 9.5,
}


def nist_risk_level(
    likelihood: LikelihoodLevel,
    impact: ImpactLevel,
) -> NistRiskLevel:
    """Return the explicit NIST SP 800-30 Rev. 1 Table I-2 matrix cell."""

    if not isinstance(likelihood, LikelihoodLevel):
        raise TypeError("likelihood must be LikelihoodLevel")
    if not isinstance(impact, ImpactLevel):
        raise TypeError("impact must be ImpactLevel")
    return _RISK_MATRIX[likelihood][impact]


def nist_semi_quantitative_value(level: NistRiskLevel) -> int:
    """Return the semi-quantitative value displayed by NIST Table I-2."""

    if not isinstance(level, NistRiskLevel):
        raise TypeError("risk level must be NistRiskLevel")
    return _NIST_SEMI_QUANTITATIVE_VALUES[level]


def agentsec_base_score(level: NistRiskLevel) -> float:
    """Return the approved AgentSec v0 0-10 representative for a matrix level."""

    if not isinstance(level, NistRiskLevel):
        raise TypeError("risk level must be NistRiskLevel")
    return _AGENTSEC_BASE_SCORES[level]


def severity_for_score(score: float) -> Severity:
    """Map a finite 0-10 score to the CVSS v4 qualitative severity range."""

    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or not 0 <= float(score) <= 10
    ):
        raise ValueError("score must be finite and within 0 to 10")
    numeric = float(score)
    if numeric == 0:
        return Severity.NONE
    if numeric < 4:
        return Severity.LOW
    if numeric < 7:
        return Severity.MEDIUM
    if numeric < 9:
        return Severity.HIGH
    return Severity.CRITICAL

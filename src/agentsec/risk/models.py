"""Immutable, evidence-safe models for preliminary base risk scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum

from agentsec.domain import FindingCategory, ImpactLevel, LikelihoodLevel, Severity
from agentsec.risk.levels import NistRiskLevel
from agentsec.risk.mapping import (
    RISK_MAPPING_BASIS,
    agentsec_base_score,
    nist_risk_level,
    nist_semi_quantitative_value,
    severity_for_score,
)
from agentsec.rules.pipeline import UnscoredFinding
from agentsec.versioning import RISK_MODEL_VERSION

_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")

LIKELIHOOD_ORDINALS = {
    LikelihoodLevel.VERY_LOW: 1,
    LikelihoodLevel.LOW: 2,
    LikelihoodLevel.MODERATE: 3,
    LikelihoodLevel.HIGH: 4,
    LikelihoodLevel.VERY_HIGH: 5,
}
IMPACT_ORDINALS = {
    ImpactLevel.VERY_LOW: 1,
    ImpactLevel.LOW: 2,
    ImpactLevel.MODERATE: 3,
    ImpactLevel.HIGH: 4,
    ImpactLevel.VERY_HIGH: 5,
}


class ImpactDimension(StrEnum):
    """AgentSec impact dimensions evaluated with a high-water-mark policy."""

    AVAILABILITY = "availability"
    BUSINESS_COMPLIANCE = "business_compliance"
    CONFIDENTIALITY = "confidentiality"
    DOWNSTREAM_BLAST_RADIUS = "downstream_blast_radius"
    INTEGRITY = "integrity"
    SAFETY = "safety"


@dataclass(frozen=True, slots=True)
class ImpactRating:
    """One trusted impact dimension, level, and human-readable basis."""

    dimension: ImpactDimension
    level: ImpactLevel
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, ImpactDimension):
            raise TypeError("impact rating dimension must be ImpactDimension")
        if not isinstance(self.level, ImpactLevel):
            raise TypeError("impact rating level must be ImpactLevel")
        _require_text(self.rationale, "impact rating rationale")


@dataclass(frozen=True, slots=True)
class RiskProfile:
    """Reviewed rule-specific likelihood and high-water-mark impact profile."""

    rule_id: str
    category: FindingCategory
    likelihood: LikelihoodLevel
    likelihood_basis: tuple[str, ...]
    impact_ratings: tuple[ImpactRating, ...]

    def __post_init__(self) -> None:
        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("risk profile Rule ID must use canonical format")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("risk profile category must be FindingCategory")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("risk profile likelihood must be LikelihoodLevel")
        _validate_basis(self.likelihood_basis, "likelihood basis")
        if not isinstance(self.impact_ratings, tuple) or not self.impact_ratings:
            raise ValueError("risk profile requires impact ratings")
        if any(not isinstance(item, ImpactRating) for item in self.impact_ratings):
            raise TypeError("risk profile contains an invalid impact rating")
        ordered = tuple(
            sorted(self.impact_ratings, key=lambda item: item.dimension.value)
        )
        if len({item.dimension for item in ordered}) != len(ordered):
            raise ValueError("risk profile impact dimensions must be unique")
        object.__setattr__(self, "impact_ratings", ordered)

    @property
    def impact(self) -> ImpactLevel:
        """Return the highest rated impact dimension without averaging."""

        return max(
            (rating.level for rating in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )

    @property
    def impact_basis(self) -> tuple[str, ...]:
        """Return the ordered trusted rationale for every impact dimension."""

        return tuple(item.rationale for item in self.impact_ratings)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Traceable v0 base-risk output without confidence or hard-gate policy."""

    risk_model_version: str
    profile_rule_id: str
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    likelihood_ordinal: int
    impact_ordinal: int
    risk_level: NistRiskLevel
    nist_semi_quantitative_value: int
    score: float
    severity: Severity
    likelihood_basis: tuple[str, ...]
    impact_ratings: tuple[ImpactRating, ...]
    mapping_basis: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.risk_model_version != RISK_MODEL_VERSION:
            raise ValueError("risk assessment version is not supported")
        if _RULE_ID_PATTERN.fullmatch(self.profile_rule_id) is None:
            raise ValueError("risk assessment profile Rule ID is invalid")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("risk assessment likelihood must be LikelihoodLevel")
        if not isinstance(self.impact, ImpactLevel):
            raise TypeError("risk assessment impact must be ImpactLevel")
        if self.likelihood_ordinal != LIKELIHOOD_ORDINALS[self.likelihood]:
            raise ValueError("risk assessment likelihood ordinal is inconsistent")
        if self.impact_ordinal != IMPACT_ORDINALS[self.impact]:
            raise ValueError("risk assessment impact ordinal is inconsistent")
        if not isinstance(self.risk_level, NistRiskLevel):
            raise TypeError("risk assessment level must be NistRiskLevel")
        expected_level = nist_risk_level(self.likelihood, self.impact)
        if self.risk_level is not expected_level:
            raise ValueError("risk assessment matrix level is inconsistent")
        if self.nist_semi_quantitative_value != nist_semi_quantitative_value(
            self.risk_level
        ):
            raise ValueError("risk assessment NIST value is inconsistent")
        if self.score != agentsec_base_score(self.risk_level):
            raise ValueError("risk assessment AgentSec score is inconsistent")
        if self.severity is not severity_for_score(self.score):
            raise ValueError("risk assessment Severity is inconsistent")
        _validate_basis(self.likelihood_basis, "likelihood basis")
        if not isinstance(self.impact_ratings, tuple) or not self.impact_ratings:
            raise ValueError("risk assessment requires impact ratings")
        if any(not isinstance(item, ImpactRating) for item in self.impact_ratings):
            raise TypeError("risk assessment contains an invalid impact rating")
        if len({item.dimension for item in self.impact_ratings}) != len(
            self.impact_ratings
        ):
            raise ValueError("risk assessment impact dimensions must be unique")
        if (
            tuple(sorted(self.impact_ratings, key=lambda item: item.dimension.value))
            != self.impact_ratings
        ):
            raise ValueError("risk assessment impact ratings must be ordered")
        highest_impact = max(
            (rating.level for rating in self.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )
        if highest_impact is not self.impact:
            raise ValueError("risk assessment impact is not the high-water mark")
        if self.mapping_basis != RISK_MAPPING_BASIS:
            raise ValueError("risk assessment mapping basis is inconsistent")


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    """An unscored Finding paired with base risk, before confidence and gates."""

    unscored: UnscoredFinding = dataclass_field(repr=False)
    risk: RiskAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.unscored, UnscoredFinding):
            raise TypeError("scored Finding requires an UnscoredFinding")
        if not isinstance(self.risk, RiskAssessment):
            raise TypeError("scored Finding requires a RiskAssessment")
        if self.unscored.rule_id != self.risk.profile_rule_id:
            raise ValueError("scored Finding Rule ID does not match risk profile")

    def _sort_key(self) -> tuple[str, str, int, str]:
        first = self.unscored.evidence[0]
        return (
            self.unscored.rule_id,
            first.asset_path or "",
            first.start_line or 0,
            self.unscored.finding_id,
        )


def _validate_basis(value: tuple[str, ...], label: str) -> None:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{label} must be a non-empty tuple")
    for item in value:
        _require_text(item, label)
    if len(set(value)) != len(value):
        raise ValueError(f"{label} values must be unique")


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value.strip():
        raise ValueError(f"{label} must not be empty")

"""Deterministic NIST-style Risk Engine v0."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from agentsec.risk.mapping import (
    RISK_MAPPING_BASIS,
    agentsec_base_score,
    nist_risk_level,
    nist_semi_quantitative_value,
    severity_for_score,
)
from agentsec.risk.models import (
    IMPACT_ORDINALS,
    LIKELIHOOD_ORDINALS,
    RiskAssessment,
    RiskProfile,
    ScoredFinding,
)
from agentsec.risk.profiles import builtin_risk_profiles
from agentsec.rules.pipeline import UnscoredFinding
from agentsec.versioning import RISK_MODEL_VERSION


class RiskEngine(Protocol):
    """Deep-module interface for deterministic base risk scoring."""

    def score(self, finding: UnscoredFinding) -> ScoredFinding:
        """Score one validated unscored Finding independently."""

    def score_all(
        self,
        findings: tuple[UnscoredFinding, ...],
    ) -> tuple[ScoredFinding, ...]:
        """Score and deterministically order independent Findings."""


class RiskScoringCode(StrEnum):
    """Stable safe failure reasons for Risk Engine inputs and profiles."""

    INVALID_PROFILE_REGISTRY = "invalid_profile_registry"
    UNKNOWN_RULE = "unknown_rule"
    CATEGORY_MISMATCH = "category_mismatch"
    DUPLICATE_FINDING_ID = "duplicate_finding_id"


class RiskScoringError(RuntimeError):
    """Risk scoring failure that never includes scanned source text."""

    def __init__(self, code: RiskScoringCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class DeterministicRiskEngine:
    """Apply reviewed rule profiles and the explicit NIST-style v0 mappings."""

    def __init__(self, profiles: tuple[RiskProfile, ...] | None = None) -> None:
        selected = builtin_risk_profiles() if profiles is None else profiles
        if (
            not isinstance(selected, tuple)
            or not selected
            or any(not isinstance(item, RiskProfile) for item in selected)
        ):
            raise RiskScoringError(
                RiskScoringCode.INVALID_PROFILE_REGISTRY,
                "Risk profile registry validation failed safely.",
            )
        indexed: dict[str, RiskProfile] = {}
        for profile in selected:
            if profile.rule_id in indexed:
                raise RiskScoringError(
                    RiskScoringCode.INVALID_PROFILE_REGISTRY,
                    "Risk profile registry validation failed safely.",
                )
            indexed[profile.rule_id] = profile
        self._profiles = indexed

    def score(self, finding: UnscoredFinding) -> ScoredFinding:
        """Score one Finding without inspecting or interpreting its source excerpt."""

        if not isinstance(finding, UnscoredFinding):
            raise TypeError("risk scoring requires an UnscoredFinding")
        profile = self._profiles.get(finding.rule_id)
        if profile is None:
            raise RiskScoringError(
                RiskScoringCode.UNKNOWN_RULE,
                "No reviewed risk profile is registered for this Rule ID.",
            )
        if finding.category is not profile.category:
            raise RiskScoringError(
                RiskScoringCode.CATEGORY_MISMATCH,
                "Finding category does not match the reviewed risk profile.",
            )

        impact = profile.impact
        level = nist_risk_level(profile.likelihood, impact)
        score = agentsec_base_score(level)
        assessment = RiskAssessment(
            risk_model_version=RISK_MODEL_VERSION,
            profile_rule_id=profile.rule_id,
            likelihood=profile.likelihood,
            impact=impact,
            likelihood_ordinal=LIKELIHOOD_ORDINALS[profile.likelihood],
            impact_ordinal=IMPACT_ORDINALS[impact],
            risk_level=level,
            nist_semi_quantitative_value=nist_semi_quantitative_value(level),
            score=score,
            severity=severity_for_score(score),
            likelihood_basis=profile.likelihood_basis,
            impact_ratings=profile.impact_ratings,
            mapping_basis=RISK_MAPPING_BASIS,
        )
        return ScoredFinding(unscored=finding, risk=assessment)

    def score_all(
        self,
        findings: tuple[UnscoredFinding, ...],
    ) -> tuple[ScoredFinding, ...]:
        """Score independently, reject duplicate identity, and return stable order."""

        if not isinstance(findings, tuple):
            raise TypeError("risk scoring findings must be a tuple")
        if any(not isinstance(item, UnscoredFinding) for item in findings):
            raise TypeError("risk scoring input contains an invalid Finding")
        if len({item.finding_id for item in findings}) != len(findings):
            raise RiskScoringError(
                RiskScoringCode.DUPLICATE_FINDING_ID,
                "Risk scoring Finding IDs must be unique.",
            )
        return tuple(
            sorted(
                (self.score(item) for item in findings),
                key=lambda item: item._sort_key(),
            )
        )

"""Deterministic Evidence Confidence assignment for scored Findings."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from agentsec.risk.confidence_models import (
    CONFIDENCE_MAPPING_BASIS,
    ConfidenceAssessment,
    ConfidenceFinding,
    ConfidenceProfile,
)
from agentsec.risk.confidence_profiles import builtin_confidence_profiles
from agentsec.risk.models import ScoredFinding
from agentsec.versioning import RISK_MODEL_VERSION


class ConfidenceEngine(Protocol):
    """Deep-module interface for A/B/C/D Evidence Confidence assignment."""

    def assign(self, finding: ScoredFinding) -> ConfidenceFinding:
        """Assign independent confidence to one scored Finding."""

    def assign_all(
        self,
        findings: tuple[ScoredFinding, ...],
    ) -> tuple[ConfidenceFinding, ...]:
        """Assign and deterministically order independent Findings."""


class ConfidenceScoringCode(StrEnum):
    """Stable safe failure reasons for Confidence Engine inputs and profiles."""

    INVALID_PROFILE_REGISTRY = "invalid_profile_registry"
    UNKNOWN_RULE = "unknown_rule"
    CATEGORY_MISMATCH = "category_mismatch"
    DUPLICATE_FINDING_ID = "duplicate_finding_id"


class ConfidenceScoringError(RuntimeError):
    """Confidence assignment failure that never includes scanned source text."""

    def __init__(self, code: ConfidenceScoringCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class DeterministicConfidenceEngine:
    """Assign reviewed source strength without changing risk or Severity."""

    def __init__(self, profiles: tuple[ConfidenceProfile, ...] | None = None) -> None:
        selected = builtin_confidence_profiles() if profiles is None else profiles
        if (
            not isinstance(selected, tuple)
            or not selected
            or any(not isinstance(item, ConfidenceProfile) for item in selected)
        ):
            raise ConfidenceScoringError(
                ConfidenceScoringCode.INVALID_PROFILE_REGISTRY,
                "Confidence profile registry validation failed safely.",
            )
        indexed: dict[str, ConfidenceProfile] = {}
        for profile in selected:
            if profile.rule_id in indexed:
                raise ConfidenceScoringError(
                    ConfidenceScoringCode.INVALID_PROFILE_REGISTRY,
                    "Confidence profile registry validation failed safely.",
                )
            indexed[profile.rule_id] = profile
        self._profiles = indexed

    def assign(self, finding: ScoredFinding) -> ConfidenceFinding:
        """Assign Confidence from trusted profile and Evidence metadata only."""

        if not isinstance(finding, ScoredFinding):
            raise TypeError("confidence assignment requires a ScoredFinding")
        unscored = finding.unscored
        profile = self._profiles.get(unscored.rule_id)
        if profile is None:
            raise ConfidenceScoringError(
                ConfidenceScoringCode.UNKNOWN_RULE,
                "No reviewed confidence profile is registered for this Rule ID.",
            )
        if unscored.category is not profile.category:
            raise ConfidenceScoringError(
                ConfidenceScoringCode.CATEGORY_MISMATCH,
                "Finding category does not match the reviewed confidence profile.",
            )

        methods = tuple(
            sorted(
                {
                    profile.method_for_field(evidence.field)
                    for evidence in unscored.evidence
                },
                key=lambda item: item.value,
            )
        )
        assessment = ConfidenceAssessment(
            risk_model_version=RISK_MODEL_VERSION,
            profile_rule_id=profile.rule_id,
            level=profile.level,
            methods=methods,
            rationale=profile.rationale,
            limitations=profile.limitations,
            mapping_basis=CONFIDENCE_MAPPING_BASIS,
        )
        return ConfidenceFinding(scored=finding, confidence=assessment)

    def assign_all(
        self,
        findings: tuple[ScoredFinding, ...],
    ) -> tuple[ConfidenceFinding, ...]:
        """Assign independently, reject duplicate identity, and return stable order."""

        if not isinstance(findings, tuple):
            raise TypeError("confidence assignment findings must be a tuple")
        if any(not isinstance(item, ScoredFinding) for item in findings):
            raise TypeError("confidence assignment input contains an invalid Finding")
        finding_ids = tuple(item.unscored.finding_id for item in findings)
        if len(set(finding_ids)) != len(finding_ids):
            raise ConfidenceScoringError(
                ConfidenceScoringCode.DUPLICATE_FINDING_ID,
                "Confidence assignment Finding IDs must be unique.",
            )
        return tuple(
            sorted(
                (self.assign(item) for item in findings),
                key=lambda item: item._sort_key(),
            )
        )

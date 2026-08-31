"""Deterministic report-only Hard Gate application and final Finding assembly."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from agentsec.risk.confidence_models import ConfidenceFinding
from agentsec.risk.hard_gate_models import (
    HARD_GATE_MAPPING_BASIS,
    GatedFinding,
    GateEnforcementMode,
    HardGateAssessment,
    HardGateMatch,
)
from agentsec.versioning import RISK_MODEL_VERSION


class HardGateEngine(Protocol):
    """Deep-module interface for non-dilutable report-only gate metadata."""

    def apply(
        self,
        finding: ConfidenceFinding,
        *,
        matches: tuple[HardGateMatch, ...] = (),
    ) -> GatedFinding:
        """Apply trusted deterministic matches to one Finding."""

    def apply_all(
        self,
        findings: tuple[ConfidenceFinding, ...],
        *,
        matches: tuple[HardGateMatch, ...] = (),
    ) -> tuple[GatedFinding, ...]:
        """Apply trusted matches and return stable report-only output."""


class HardGateCode(StrEnum):
    """Stable safe failure reasons for Hard Gate orchestration."""

    DUPLICATE_FINDING_ID = "duplicate_finding_id"
    UNKNOWN_FINDING_ID = "unknown_finding_id"
    DUPLICATE_GATE_ID = "duplicate_gate_id"
    SOURCE_RULE_MISMATCH = "source_rule_mismatch"


class HardGateError(RuntimeError):
    """Hard Gate failure that never includes scanned source text."""

    def __init__(self, code: HardGateCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class DeterministicHardGateEngine:
    """Apply non-dilutable floors while keeping Phase 1 strictly report-only."""

    def apply(
        self,
        finding: ConfidenceFinding,
        *,
        matches: tuple[HardGateMatch, ...] = (),
    ) -> GatedFinding:
        """Return one gate-complete Finding without enabling CI blocking."""

        if not isinstance(finding, ConfidenceFinding):
            raise TypeError("Hard Gate application requires a ConfidenceFinding")
        validated = self._validate_matches_for_finding(finding, matches)
        risk = finding.scored.risk
        assessment = HardGateAssessment(
            risk_model_version=RISK_MODEL_VERSION,
            finding_id=finding.scored.unscored.finding_id,
            mode=GateEnforcementMode.REPORT_ONLY,
            base_score=risk.score,
            base_severity=risk.severity,
            matches=validated,
            mapping_basis=HARD_GATE_MAPPING_BASIS,
        )
        return GatedFinding(confidence_finding=finding, gate=assessment)

    def apply_all(
        self,
        findings: tuple[ConfidenceFinding, ...],
        *,
        matches: tuple[HardGateMatch, ...] = (),
    ) -> tuple[GatedFinding, ...]:
        """Apply by Finding ID, reject orphans, and return stable order."""

        if not isinstance(findings, tuple):
            raise TypeError("Hard Gate Findings must be a tuple")
        if any(not isinstance(item, ConfidenceFinding) for item in findings):
            raise TypeError("Hard Gate input contains an invalid Finding")
        finding_ids = tuple(item.scored.unscored.finding_id for item in findings)
        if len(set(finding_ids)) != len(finding_ids):
            raise HardGateError(
                HardGateCode.DUPLICATE_FINDING_ID,
                "Hard Gate Finding IDs must be unique.",
            )
        if not isinstance(matches, tuple):
            raise TypeError("Hard Gate matches must be a tuple")
        if any(not isinstance(item, HardGateMatch) for item in matches):
            raise TypeError("Hard Gate input contains an invalid match")

        known_ids = set(finding_ids)
        if any(item.finding_id not in known_ids for item in matches):
            raise HardGateError(
                HardGateCode.UNKNOWN_FINDING_ID,
                "Hard Gate match references an unknown Finding ID.",
            )
        by_finding: dict[str, list[HardGateMatch]] = {}
        for match in matches:
            by_finding.setdefault(match.finding_id, []).append(match)

        return tuple(
            sorted(
                (
                    self.apply(
                        finding,
                        matches=tuple(
                            sorted(
                                by_finding.get(
                                    finding.scored.unscored.finding_id,
                                    [],
                                ),
                                key=lambda item: item._sort_key(),
                            )
                        ),
                    )
                    for finding in findings
                ),
                key=lambda item: item._sort_key(),
            )
        )

    @staticmethod
    def _validate_matches_for_finding(
        finding: ConfidenceFinding,
        matches: tuple[HardGateMatch, ...],
    ) -> tuple[HardGateMatch, ...]:
        if not isinstance(matches, tuple):
            raise TypeError("Hard Gate matches must be a tuple")
        if any(not isinstance(item, HardGateMatch) for item in matches):
            raise TypeError("Hard Gate input contains an invalid match")

        finding_id = finding.scored.unscored.finding_id
        rule_id = finding.scored.unscored.rule_id
        if any(item.finding_id != finding_id for item in matches):
            raise HardGateError(
                HardGateCode.UNKNOWN_FINDING_ID,
                "Hard Gate match references a different Finding ID.",
            )
        gate_ids = tuple(item.gate_id for item in matches)
        if len(set(gate_ids)) != len(gate_ids):
            raise HardGateError(
                HardGateCode.DUPLICATE_GATE_ID,
                "Hard Gate IDs must be unique per Finding.",
            )
        if any(rule_id not in item.rule_ids for item in matches):
            raise HardGateError(
                HardGateCode.SOURCE_RULE_MISMATCH,
                "Hard Gate match does not include the Finding Rule ID.",
            )
        return tuple(sorted(matches, key=lambda item: item._sort_key()))

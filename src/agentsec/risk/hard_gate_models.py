"""Immutable report-only Hard Gate metadata and non-dilutable floor semantics."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum

from agentsec.domain import Finding, Severity
from agentsec.risk.confidence_models import ConfidenceFinding
from agentsec.risk.mapping import severity_for_score
from agentsec.versioning import RISK_MODEL_VERSION

_FINDING_ID_PATTERN = re.compile(r"^finding-sha256:[a-f0-9]{64}$")
_GATE_ID_PATTERN = re.compile(r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")

FIPS_HARD_GATE_BASIS = (
    "FIPS 199 high-water-mark principle adapted to non-dilutable policy floors"
)
AGENTSEC_HARD_GATE_BASIS = (
    "AgentSec project plan section 6.8 Hard Gate minimum-risk policy"
)
HARD_GATE_SCORE_BASIS = (
    "FIRST CVSS v4.0 High and Critical lower bounds used as floor scores"
)
HARD_GATE_MAPPING_BASIS = (
    FIPS_HARD_GATE_BASIS,
    AGENTSEC_HARD_GATE_BASIS,
    HARD_GATE_SCORE_BASIS,
)


class HardGateFloor(StrEnum):
    """Minimum risk levels supported by the Phase 1 metadata contract."""

    HIGH = "high"
    CRITICAL = "critical"


class GateEnforcementMode(StrEnum):
    """Phase 1 records gate metadata but never blocks CI."""

    REPORT_ONLY = "report_only"


_FLOOR_SCORES = {
    HardGateFloor.HIGH: 7.0,
    HardGateFloor.CRITICAL: 9.0,
}
_FLOOR_ORDINALS = {
    HardGateFloor.HIGH: 1,
    HardGateFloor.CRITICAL: 2,
}


@dataclass(frozen=True, slots=True)
class HardGateMatch:
    """One trusted deterministic gate condition bound to a Finding identity."""

    finding_id: str
    gate_id: str
    floor: HardGateFloor
    rule_ids: tuple[str, ...]
    rationale: tuple[str, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise ValueError("Hard Gate match Finding ID is invalid")
        if _GATE_ID_PATTERN.fullmatch(self.gate_id) is None:
            raise ValueError("Hard Gate match gate ID is invalid")
        if not isinstance(self.floor, HardGateFloor):
            raise TypeError("Hard Gate match floor must be HardGateFloor")
        if not isinstance(self.rule_ids, tuple) or not self.rule_ids:
            raise ValueError("Hard Gate match requires supporting Rule IDs")
        if any(_RULE_ID_PATTERN.fullmatch(item) is None for item in self.rule_ids):
            raise ValueError("Hard Gate match contains an invalid Rule ID")
        if self.rule_ids != tuple(sorted(set(self.rule_ids))):
            raise ValueError("Hard Gate match Rule IDs must be sorted and unique")
        _validate_text_tuple(self.rationale, "Hard Gate rationale")

    def _sort_key(self) -> tuple[str, str]:
        return (self.finding_id, self.gate_id)


@dataclass(frozen=True, slots=True)
class HardGateAssessment:
    """Report-only gate metadata with derived non-dilutable effective risk."""

    risk_model_version: str
    finding_id: str
    mode: GateEnforcementMode
    base_score: float
    base_severity: Severity
    matches: tuple[HardGateMatch, ...]
    mapping_basis: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.risk_model_version != RISK_MODEL_VERSION:
            raise ValueError("Hard Gate assessment version is not supported")
        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise ValueError("Hard Gate assessment Finding ID is invalid")
        if self.mode is not GateEnforcementMode.REPORT_ONLY:
            raise ValueError("Phase 1 Hard Gate mode must be report_only")
        if (
            isinstance(self.base_score, bool)
            or not isinstance(self.base_score, (int, float))
            or not math.isfinite(float(self.base_score))
            or not 0 <= float(self.base_score) <= 10
        ):
            raise ValueError("Hard Gate base score must be finite and within 0 to 10")
        if not isinstance(self.base_severity, Severity):
            raise TypeError("Hard Gate base severity must be Severity")
        if severity_for_score(float(self.base_score)) is not self.base_severity:
            raise ValueError("Hard Gate base score and Severity are inconsistent")
        if not isinstance(self.matches, tuple):
            raise TypeError("Hard Gate matches must be a tuple")
        if any(not isinstance(item, HardGateMatch) for item in self.matches):
            raise TypeError("Hard Gate assessment contains an invalid match")
        ordered = tuple(sorted(self.matches, key=lambda item: item._sort_key()))
        if any(item.finding_id != self.finding_id for item in ordered):
            raise ValueError("Hard Gate match Finding ID is inconsistent")
        gate_ids = tuple(item.gate_id for item in ordered)
        if len(set(gate_ids)) != len(gate_ids):
            raise ValueError("Hard Gate match IDs must be unique per Finding")
        object.__setattr__(self, "matches", ordered)
        if self.mapping_basis != HARD_GATE_MAPPING_BASIS:
            raise ValueError("Hard Gate mapping basis is inconsistent")

    @property
    def triggered(self) -> bool:
        """Return whether at least one deterministic gate condition matched."""

        return bool(self.matches)

    @property
    def floor(self) -> HardGateFloor | None:
        """Return the strongest matched floor without averaging."""

        if not self.matches:
            return None
        return max(
            (item.floor for item in self.matches),
            key=_FLOOR_ORDINALS.__getitem__,
        )

    @property
    def floor_score(self) -> float | None:
        """Return the minimum score associated with the strongest floor."""

        if self.floor is None:
            return None
        return hard_gate_floor_score(self.floor)

    @property
    def effective_score(self) -> float:
        """Apply max(base, floor) so a gate can never lower or average risk."""

        if self.floor_score is None:
            return float(self.base_score)
        return max(float(self.base_score), self.floor_score)

    @property
    def effective_severity(self) -> Severity:
        """Return Severity consistent with the effective score."""

        return severity_for_score(self.effective_score)

    @property
    def blocks(self) -> bool:
        """Phase 1 is report-only even when a Hard Gate is triggered."""

        return False


@dataclass(frozen=True, slots=True)
class GatedFinding:
    """Confidence-complete Finding paired with report-only gate metadata."""

    confidence_finding: ConfidenceFinding = dataclass_field(repr=False)
    gate: HardGateAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.confidence_finding, ConfidenceFinding):
            raise TypeError("Gated Finding requires a ConfidenceFinding")
        if not isinstance(self.gate, HardGateAssessment):
            raise TypeError("Gated Finding requires a HardGateAssessment")
        unscored = self.confidence_finding.scored.unscored
        risk = self.confidence_finding.scored.risk
        if unscored.finding_id != self.gate.finding_id:
            raise ValueError("Gated Finding ID does not match gate assessment")
        if risk.score != self.gate.base_score:
            raise ValueError("Gated Finding score does not match gate assessment")
        if risk.severity is not self.gate.base_severity:
            raise ValueError("Gated Finding Severity does not match gate assessment")

    def to_domain_finding(self) -> Finding:
        """Assemble the existing final Domain Finding without rendering it."""

        unscored = self.confidence_finding.scored.unscored
        risk = self.confidence_finding.scored.risk
        return Finding(
            finding_id=unscored.finding_id,
            rule_id=unscored.rule_id,
            category=unscored.category,
            title=unscored.title,
            description=unscored.description,
            likelihood=risk.likelihood,
            impact=risk.impact,
            severity=self.gate.effective_severity,
            score=self.gate.effective_score,
            confidence=self.confidence_finding.confidence.level,
            hard_gate=self.gate.triggered,
            evidence=unscored.evidence,
            recommendations=unscored.recommendations,
        )

    def _sort_key(self) -> tuple[str, str, int, str]:
        first = self.confidence_finding.scored.unscored.evidence[0]
        unscored = self.confidence_finding.scored.unscored
        return (
            unscored.rule_id,
            first.asset_path or "",
            first.start_line or 0,
            unscored.finding_id,
        )


def hard_gate_floor_score(floor: HardGateFloor) -> float:
    """Return the CVSS-compatible minimum score for a Hard Gate floor."""

    if not isinstance(floor, HardGateFloor):
        raise TypeError("Hard Gate floor must be HardGateFloor")
    return _FLOOR_SCORES[floor]


def _validate_text_tuple(value: tuple[str, ...], label: str) -> None:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{label} must be a non-empty tuple")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{label} must contain text")
        if not item.strip():
            raise ValueError(f"{label} must not contain empty text")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} values must be unique")

"""Overall Score and report-only Agentic Hard Gate floors (P2-23)."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal

from agentsec.domain import EvidenceConfidence, Severity
from agentsec.risk.cvss import severity_for_cvss_score
from agentsec.risk.drift_score import DriftScoreAssessment
from agentsec.risk.governance_score import GovernanceScoreAssessment
from agentsec.risk.hard_gate_models import HardGateFloor, hard_gate_floor_score
from agentsec.risk.technical_score import TechnicalScoreAssessment
from agentsec.versioning import (
    DRIFT_SCORE_MODEL_VERSION,
    GOVERNANCE_SCORE_MODEL_VERSION,
    OVERALL_SCORE_MODEL_VERSION,
    TECHNICAL_SCORE_MODEL_VERSION,
)

OVERALL_SCORE_FORMAT: Literal["agentsec-overall-score"] = "agentsec-overall-score"
OVERALL_SCORE_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
OVERALL_SCORE_BASIS = (
    "AgentSec P2-23 deterministic Overall Score and Hard Gate contract 0.1.0",
    "Technical, Drift, and Governance risk use high-water-mark aggregation",
    "Hard Gate floors are independent and cannot be diluted by score aggregation",
    "Only qualified deterministic report-only Gate matches may set a floor",
    "LLM evidence cannot authorize or trigger an Overall Hard Gate",
    "The result remains report-only and does not block CI",
)
_GATE_ID_PATTERN = re.compile(r"^HG-[A-Z][A-Z0-9]*-[0-9]{3}$")
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FLOOR_ORDER = {HardGateFloor.HIGH: 1, HardGateFloor.CRITICAL: 2}


class OverallHighWaterSource(StrEnum):
    """Score component establishing the pre-Gate high-water mark."""

    TECHNICAL = "technical"
    DRIFT = "drift"
    GOVERNANCE = "governance"
    TIE = "tie"


class OverallHardGateSource(StrEnum):
    """Trusted deterministic source families allowed to set a report-only floor."""

    CAPABILITY = "capability"
    CVSS = "cvss"
    POLICY = "policy"


class OverallHardGateQualification(StrEnum):
    """Qualification state required before a Gate can influence Overall Score."""

    ACCEPTED = "accepted"


@dataclass(frozen=True, slots=True)
class OverallHardGateMatch:
    """One qualified deterministic Gate match setting a non-dilutable floor."""

    gate_id: str
    floor: HardGateFloor
    source: OverallHardGateSource
    qualification: OverallHardGateQualification
    evidence_ids: tuple[str, ...]
    confidence: EvidenceConfidence
    rationale: tuple[str, ...] = dataclass_field(repr=False)
    deterministic: Literal[True] = True
    blocks: Literal[False] = False

    def __post_init__(self) -> None:
        if _GATE_ID_PATTERN.fullmatch(self.gate_id) is None:
            raise ValueError("Overall Hard Gate ID is invalid")
        if not isinstance(self.floor, HardGateFloor):
            raise TypeError("Overall Hard Gate floor must be HardGateFloor")
        if not isinstance(self.source, OverallHardGateSource):
            raise TypeError("Overall Hard Gate source is invalid")
        if self.qualification is not OverallHardGateQualification.ACCEPTED:
            raise ValueError("Overall Hard Gate must be qualification accepted")
        if self.confidence not in {
            EvidenceConfidence.A,
            EvidenceConfidence.B,
            EvidenceConfidence.C,
        }:
            raise ValueError(
                "D-confidence evidence cannot set an Overall Hard Gate floor"
            )
        if not self.evidence_ids or self.evidence_ids != tuple(
            sorted(set(self.evidence_ids))
        ):
            raise ValueError("Overall Hard Gate evidence IDs must be sorted and unique")
        if any(
            _STABLE_ID_PATTERN.fullmatch(item) is None for item in self.evidence_ids
        ):
            raise ValueError("Overall Hard Gate evidence ID is invalid")
        _validate_unique_strings(self.rationale, "Overall Hard Gate rationale")
        if self.deterministic is not True:
            raise ValueError("Overall Hard Gate authority must be deterministic")
        if self.blocks is not False:
            raise ValueError("P2-23 Overall Hard Gate remains report-only")

    @property
    def floor_score(self) -> float:
        return hard_gate_floor_score(self.floor)

    def sort_key(self) -> tuple[str, str, str]:
        return (self.gate_id, self.source.value, self.floor.value)

    def to_dict(self) -> dict[str, object]:
        return {
            "gate_id": self.gate_id,
            "floor": self.floor.value,
            "floor_score": self.floor_score,
            "source": self.source.value,
            "qualification": self.qualification.value,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence.value,
            "rationale": list(self.rationale),
            "deterministic": self.deterministic,
            "blocks": self.blocks,
        }


@dataclass(frozen=True, slots=True)
class OverallHardGateAssessment:
    """Strongest qualified floor, kept separate from component aggregation."""

    mode: Literal["report_only"]
    matches: tuple[OverallHardGateMatch, ...]
    triggered: bool
    floor: HardGateFloor | None
    floor_score: float | None
    blocks: Literal[False] = False

    def __post_init__(self) -> None:
        if self.mode != "report_only":
            raise ValueError("P2-23 Overall Hard Gate mode must be report_only")
        if any(not isinstance(item, OverallHardGateMatch) for item in self.matches):
            raise TypeError("Overall Hard Gate contains an invalid match")
        keys = tuple(item.sort_key() for item in self.matches)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("Overall Hard Gate matches must be sorted and unique")
        expected_triggered = bool(self.matches)
        if self.triggered != expected_triggered:
            raise ValueError("Overall Hard Gate trigger state is inconsistent")
        expected_floor = (
            max((item.floor for item in self.matches), key=_FLOOR_ORDER.__getitem__)
            if self.matches
            else None
        )
        if self.floor is not expected_floor:
            raise ValueError("Overall Hard Gate strongest floor is inconsistent")
        expected_score = (
            None if expected_floor is None else hard_gate_floor_score(expected_floor)
        )
        if self.floor_score != expected_score:
            raise ValueError("Overall Hard Gate floor score is inconsistent")
        if self.blocks is not False:
            raise ValueError("P2-23 Overall Hard Gate cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "triggered": self.triggered,
            "floor": self.floor.value if self.floor else None,
            "floor_score": self.floor_score,
            "blocks": self.blocks,
            "matches": [item.to_dict() for item in self.matches],
        }


@dataclass(frozen=True, slots=True)
class OverallScoreAssessment:
    """Versioned high-water Overall Score with non-dilutable Gate floor."""

    format: Literal["agentsec-overall-score"]
    format_version: Literal["0.1.0"]
    model_version: str
    technical_score_model_version: str
    drift_score_model_version: str
    governance_score_model_version: str
    agent_id: str
    manifest_sha256: str
    technical_score: float
    drift_score: float
    governance_score: float
    base_overall_score: float
    base_high_water_source: OverallHighWaterSource
    hard_gate: OverallHardGateAssessment
    overall_score: float
    severity: Severity
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False, default=())

    def __post_init__(self) -> None:
        if self.format != OVERALL_SCORE_FORMAT:
            raise ValueError("Overall Score format is unsupported")
        if self.format_version != OVERALL_SCORE_FORMAT_VERSION:
            raise ValueError("Overall Score format version is unsupported")
        if self.model_version != OVERALL_SCORE_MODEL_VERSION:
            raise ValueError("Overall Score model version is unsupported")
        if self.technical_score_model_version != TECHNICAL_SCORE_MODEL_VERSION:
            raise ValueError("Technical Score model version is unsupported")
        if self.drift_score_model_version != DRIFT_SCORE_MODEL_VERSION:
            raise ValueError("Drift Score model version is unsupported")
        if self.governance_score_model_version != GOVERNANCE_SCORE_MODEL_VERSION:
            raise ValueError("Governance Score model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("Overall Score Agent ID must not be empty")
        _validate_hash(self.manifest_sha256, "manifest_sha256")
        for value, label in (
            (self.technical_score, "technical_score"),
            (self.drift_score, "drift_score"),
            (self.governance_score, "governance_score"),
            (self.base_overall_score, "base_overall_score"),
            (self.overall_score, "overall_score"),
        ):
            _validate_score(value, label)
        expected_base = max(
            self.technical_score, self.drift_score, self.governance_score
        )
        if self.base_overall_score != expected_base:
            raise ValueError("base_overall_score must use high-water aggregation")
        if self.base_high_water_source is not _high_water_source(
            self.technical_score, self.drift_score, self.governance_score
        ):
            raise ValueError("Overall Score high-water source is inconsistent")
        expected_overall = max(
            self.base_overall_score,
            0.0 if self.hard_gate.floor_score is None else self.hard_gate.floor_score,
        )
        if self.overall_score != expected_overall:
            raise ValueError("overall_score must preserve the strongest Gate floor")
        if severity_for_cvss_score(self.overall_score) is not self.severity:
            raise ValueError("Overall Score severity is inconsistent")
        _validate_unique_strings(self.mapping_basis, "Overall Score mapping basis")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "technical_score_model_version": self.technical_score_model_version,
            "drift_score_model_version": self.drift_score_model_version,
            "governance_score_model_version": self.governance_score_model_version,
            "agent_id": self.agent_id,
            "manifest_sha256": self.manifest_sha256,
            "technical_score": self.technical_score,
            "drift_score": self.drift_score,
            "governance_score": self.governance_score,
            "base_overall_score": self.base_overall_score,
            "base_high_water_source": self.base_high_water_source.value,
            "hard_gate": self.hard_gate.to_dict(),
            "overall_score": self.overall_score,
            "severity": self.severity.value,
            "mapping_basis": list(self.mapping_basis),
        }


class OverallScoreError(RuntimeError):
    """Safe deterministic Overall Score failure."""


def encode_overall_score_json(assessment: OverallScoreAssessment) -> str:
    """Encode Overall Score without raw source values."""

    if not isinstance(assessment, OverallScoreAssessment):
        raise TypeError("assessment must be OverallScoreAssessment")
    return (
        json.dumps(assessment.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicOverallScoreEngine:
    """Apply score high-water aggregation and independent report-only floors."""

    def score(
        self,
        technical: TechnicalScoreAssessment,
        drift: DriftScoreAssessment,
        governance: GovernanceScoreAssessment,
        *,
        gate_matches: tuple[OverallHardGateMatch, ...] = (),
    ) -> OverallScoreAssessment:
        if not isinstance(technical, TechnicalScoreAssessment):
            raise TypeError("Overall Score requires TechnicalScoreAssessment")
        if not isinstance(drift, DriftScoreAssessment):
            raise TypeError("Overall Score requires DriftScoreAssessment")
        if not isinstance(governance, GovernanceScoreAssessment):
            raise TypeError("Overall Score requires GovernanceScoreAssessment")
        if not isinstance(gate_matches, tuple) or any(
            not isinstance(item, OverallHardGateMatch) for item in gate_matches
        ):
            raise TypeError("Overall Score gate_matches must be a typed tuple")
        try:
            self._validate_bindings(technical, drift, governance)
            ordered_matches = tuple(
                sorted(gate_matches, key=lambda item: item.sort_key())
            )
            gate_ids = tuple(item.gate_id for item in ordered_matches)
            if len(gate_ids) != len(set(gate_ids)):
                raise ValueError("Overall Hard Gate IDs must be unique")
            strongest = (
                max(
                    (item.floor for item in ordered_matches),
                    key=_FLOOR_ORDER.__getitem__,
                )
                if ordered_matches
                else None
            )
            floor_score = (
                None if strongest is None else hard_gate_floor_score(strongest)
            )
            hard_gate = OverallHardGateAssessment(
                mode="report_only",
                matches=ordered_matches,
                triggered=bool(ordered_matches),
                floor=strongest,
                floor_score=floor_score,
                blocks=False,
            )
            base = max(
                technical.technical_score,
                drift.drift_score,
                governance.governance_score,
            )
            overall = max(base, 0.0 if floor_score is None else floor_score)
            return OverallScoreAssessment(
                format=OVERALL_SCORE_FORMAT,
                format_version=OVERALL_SCORE_FORMAT_VERSION,
                model_version=OVERALL_SCORE_MODEL_VERSION,
                technical_score_model_version=TECHNICAL_SCORE_MODEL_VERSION,
                drift_score_model_version=DRIFT_SCORE_MODEL_VERSION,
                governance_score_model_version=GOVERNANCE_SCORE_MODEL_VERSION,
                agent_id=technical.agent_id,
                manifest_sha256=technical.manifest_sha256,
                technical_score=technical.technical_score,
                drift_score=drift.drift_score,
                governance_score=governance.governance_score,
                base_overall_score=base,
                base_high_water_source=_high_water_source(
                    technical.technical_score,
                    drift.drift_score,
                    governance.governance_score,
                ),
                hard_gate=hard_gate,
                overall_score=overall,
                severity=severity_for_cvss_score(overall),
                mapping_basis=OVERALL_SCORE_BASIS,
            )
        except (TypeError, ValueError) as error:
            raise OverallScoreError(
                "Overall Score calculation failed safely"
            ) from error

    @staticmethod
    def _validate_bindings(
        technical: TechnicalScoreAssessment,
        drift: DriftScoreAssessment,
        governance: GovernanceScoreAssessment,
    ) -> None:
        if not (technical.agent_id == drift.agent_id == governance.agent_id):
            raise ValueError("Overall Score Agent IDs do not match")
        if technical.manifest_sha256 != drift.after_manifest_sha256:
            raise ValueError("Technical and Drift after-Manifest hashes do not match")
        if technical.manifest_sha256 != governance.manifest_sha256:
            raise ValueError("Technical and Governance Manifest hashes do not match")


def _high_water_source(
    technical: float,
    drift: float,
    governance: float,
) -> OverallHighWaterSource:
    highest = max(technical, drift, governance)
    winners = sum(value == highest for value in (technical, drift, governance))
    if winners > 1:
        return OverallHighWaterSource.TIE
    if technical == highest:
        return OverallHighWaterSource.TECHNICAL
    if drift == highest:
        return OverallHighWaterSource.DRIFT
    return OverallHighWaterSource.GOVERNANCE


def _validate_hash(value: str, label: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _validate_score(value: float, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 10.0
    ):
        raise ValueError(f"{label} must be finite and within 0 to 10")


def _validate_unique_strings(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


__all__ = [
    "OVERALL_SCORE_BASIS",
    "OVERALL_SCORE_FORMAT",
    "OVERALL_SCORE_FORMAT_VERSION",
    "DeterministicOverallScoreEngine",
    "OverallHardGateAssessment",
    "OverallHardGateMatch",
    "OverallHardGateQualification",
    "OverallHardGateSource",
    "OverallHighWaterSource",
    "OverallScoreAssessment",
    "OverallScoreError",
    "encode_overall_score_json",
]

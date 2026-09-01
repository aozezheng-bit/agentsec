"""Deterministic Agentic Technical Score calculation (P2-20).

The score combines the P2-18 Agentic Factor Vector and P2-19 bounded
Threat/Mitigation Vector.  An optional CVSS Base assessment is treated as an
independent high-water mark; it is never averaged down by Agentic factors.
This is an AgentSec policy score, not a NIST or CVSS formula.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

from agentsec.domain import EvidenceConfidence, Severity
from agentsec.risk.agentic_factors import AgenticFactorId, AgenticFactorVector
from agentsec.risk.cvss import CvssBaseAssessment, severity_for_cvss_score
from agentsec.risk.threat_mitigation import (
    MitigationState,
    ThreatMitigationAssessment,
    ThreatMitigationVector,
    ThreatState,
)
from agentsec.versioning import (
    AGENTIC_FACTOR_MODEL_VERSION,
    TECHNICAL_SCORE_MODEL_VERSION,
    THREAT_MITIGATION_MODEL_VERSION,
)

TECHNICAL_SCORE_FORMAT: Literal["agentsec-technical-score"] = "agentsec-technical-score"
TECHNICAL_SCORE_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
TECHNICAL_SCORE_BASIS = (
    "AgentSec P2-20 deterministic Technical Score contract 0.1.0",
    "Agentic factor weights are AgentSec policy and require later calibration",
    "Threat/Mitigation multipliers are bounded static policy values",
    "CVSS Base is an independent high-water mark and is never averaged down",
    "Severity uses the existing FIRST CVSS v4 qualitative score ranges",
)

# These weights are intentionally explicit and versioned.  They are not NIST
# or CVSS weights.  P2-24 may calibrate them only through a versioned review.
TECHNICAL_FACTOR_WEIGHTS: Mapping[AgenticFactorId, float] = {
    AgenticFactorId.INSTRUCTION_OVERRIDE: 0.05,
    AgenticFactorId.CODE_EXECUTION: 0.15,
    AgenticFactorId.SECRET_ACCESS: 0.15,
    AgenticFactorId.EXTERNAL_NETWORK: 0.15,
    AgenticFactorId.PRODUCTION_ACCESS: 0.15,
    AgenticFactorId.PERSISTENT_MEMORY: 0.08,
    AgenticFactorId.SUBAGENT_DELEGATION: 0.07,
    AgenticFactorId.EXTERNAL_IDENTITY: 0.07,
    AgenticFactorId.AUTONOMOUS_ACTION: 0.08,
    AgenticFactorId.APPROVAL_BYPASS: 0.05,
}
_FACTOR_ORDER = tuple(TECHNICAL_FACTOR_WEIGHTS)


@dataclass(frozen=True, slots=True)
class TechnicalFactorContribution:
    """One auditable weighted Factor contribution."""

    factor_id: AgenticFactorId
    value: float
    weight: float
    mitigation_multiplier: float
    contribution: float
    confidence: EvidenceConfidence
    threat_state: ThreatState
    mitigation_state: MitigationState

    def __post_init__(self) -> None:
        if not isinstance(self.factor_id, AgenticFactorId):
            raise TypeError("technical factor_id must be AgenticFactorId")
        if self.value not in {0.0, 0.5, 1.0}:
            raise ValueError("technical factor value must be 0.0, 0.5, or 1.0")
        _validate_score(self.weight, "technical factor weight")
        _validate_score(self.mitigation_multiplier, "technical mitigation multiplier")
        _validate_score(self.contribution, "technical factor contribution")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("technical confidence must be EvidenceConfidence")
        if not isinstance(self.threat_state, ThreatState):
            raise TypeError("technical threat_state must be ThreatState")
        if not isinstance(self.mitigation_state, MitigationState):
            raise TypeError("technical mitigation_state must be MitigationState")
        expected = _round_score(
            10.0 * self.value * self.weight * self.mitigation_multiplier
        )
        if self.contribution != expected:
            raise ValueError("technical contribution is inconsistent with inputs")

    def to_dict(self) -> dict[str, object]:
        return {
            "factor_id": self.factor_id.value,
            "value": self.value,
            "weight": self.weight,
            "mitigation_multiplier": self.mitigation_multiplier,
            "contribution": self.contribution,
            "confidence": self.confidence.value,
            "threat_state": self.threat_state.value,
            "mitigation_state": self.mitigation_state.value,
        }


@dataclass(frozen=True, slots=True)
class TechnicalScoreAssessment:
    """Versioned Technical Score with every intermediate value retained."""

    format: Literal["agentsec-technical-score"]
    format_version: Literal["0.1.0"]
    model_version: str
    agentic_factor_model_version: str
    threat_mitigation_model_version: str
    agent_id: str
    manifest_sha256: str
    agentic_score: float
    cvss_base_score: float | None
    technical_score: float
    severity: Severity
    factor_contributions: tuple[TechnicalFactorContribution, ...] = dataclass_field(
        repr=False
    )
    confidence_counts: tuple[tuple[EvidenceConfidence, int], ...] = ()
    high_water_mark_source: Literal["agentic", "cvss_base", "tie"] = "agentic"
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False, default=())

    def __post_init__(self) -> None:
        if self.format != TECHNICAL_SCORE_FORMAT:
            raise ValueError("Technical Score format is unsupported")
        if self.format_version != TECHNICAL_SCORE_FORMAT_VERSION:
            raise ValueError("Technical Score format version is unsupported")
        if self.model_version != TECHNICAL_SCORE_MODEL_VERSION:
            raise ValueError("Technical Score model version is unsupported")
        if self.agentic_factor_model_version != AGENTIC_FACTOR_MODEL_VERSION:
            raise ValueError("Agentic Factor model version is unsupported")
        if self.threat_mitigation_model_version != THREAT_MITIGATION_MODEL_VERSION:
            raise ValueError("Threat/Mitigation model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("Technical Score Agent ID must not be empty")
        if len(self.manifest_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.manifest_sha256
        ):
            raise ValueError(
                "Technical Score manifest_sha256 must be lowercase SHA-256"
            )
        _validate_score(self.agentic_score, "agentic_score")
        if self.cvss_base_score is not None:
            _validate_score(self.cvss_base_score, "cvss_base_score")
        _validate_score(self.technical_score, "technical_score")
        if not isinstance(self.severity, Severity):
            raise TypeError("Technical Score severity must be Severity")
        if severity_for_cvss_score(self.technical_score) is not self.severity:
            raise ValueError("Technical Score severity is inconsistent")
        if tuple(item.factor_id for item in self.factor_contributions) != _FACTOR_ORDER:
            raise ValueError("Technical contributions must use stable Factor order")
        expected_agentic = _round_score(
            sum(item.contribution for item in self.factor_contributions)
        )
        if expected_agentic != self.agentic_score:
            raise ValueError("agentic_score is inconsistent with contributions")
        expected_technical = _round_score(
            max(
                self.agentic_score,
                0.0 if self.cvss_base_score is None else self.cvss_base_score,
            )
        )
        if expected_technical != self.technical_score:
            raise ValueError("technical_score must use high-water-mark aggregation")
        if self.cvss_base_score is None and self.high_water_mark_source != "agentic":
            raise ValueError("without CVSS, high-water source must be agentic")
        if self.cvss_base_score is not None:
            if (
                self.agentic_score > self.cvss_base_score
                and self.high_water_mark_source != "agentic"
            ):
                raise ValueError("high-water source must be agentic")
            if (
                self.cvss_base_score > self.agentic_score
                and self.high_water_mark_source != "cvss_base"
            ):
                raise ValueError("high-water source must be cvss_base")
            if (
                self.cvss_base_score == self.agentic_score
                and self.high_water_mark_source != "tie"
            ):
                raise ValueError("equal scores must report a tie")
        _validate_confidence_counts(self.confidence_counts)
        _validate_unique_strings(self.mapping_basis, "technical mapping basis")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "agentic_factor_model_version": self.agentic_factor_model_version,
            "threat_mitigation_model_version": self.threat_mitigation_model_version,
            "agent_id": self.agent_id,
            "manifest_sha256": self.manifest_sha256,
            "agentic_score": self.agentic_score,
            "cvss_base_score": self.cvss_base_score,
            "technical_score": self.technical_score,
            "severity": self.severity.value,
            "factor_contributions": [
                item.to_dict() for item in self.factor_contributions
            ],
            "confidence_counts": {
                item.value: count for item, count in self.confidence_counts
            },
            "high_water_mark_source": self.high_water_mark_source,
            "mapping_basis": list(self.mapping_basis),
        }


class TechnicalScoreError(RuntimeError):
    """Safe deterministic Technical Score failure."""


def encode_technical_score_json(assessment: TechnicalScoreAssessment) -> str:
    """Encode a Technical Score without raw source values."""

    if not isinstance(assessment, TechnicalScoreAssessment):
        raise TypeError("assessment must be TechnicalScoreAssessment")
    return (
        json.dumps(assessment.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicTechnicalScoreEngine:
    """Calculate Technical Score from already validated P2-18/P2-19 vectors."""

    def score(
        self,
        factors: AgenticFactorVector,
        threats: ThreatMitigationVector,
        *,
        cvss: CvssBaseAssessment | None = None,
    ) -> TechnicalScoreAssessment:
        if not isinstance(factors, AgenticFactorVector):
            raise TypeError("Technical Score requires AgenticFactorVector")
        if not isinstance(threats, ThreatMitigationVector):
            raise TypeError("Technical Score requires ThreatMitigationVector")
        if cvss is not None and not isinstance(cvss, CvssBaseAssessment):
            raise TypeError("Technical Score CVSS input must be CvssBaseAssessment")
        try:
            self._validate_bindings(factors, threats)
            by_factor = {item.threat.factor_id: item for item in threats.assessments}
            contributions = tuple(
                self._contribution(factors, by_factor[factor_id])
                for factor_id in _FACTOR_ORDER
            )
            agentic_score = _round_score(
                sum(item.contribution for item in contributions)
            )
            cvss_score = None if cvss is None else _round_score(cvss.base_score)
            technical_score = _round_score(
                max(agentic_score, 0.0 if cvss_score is None else cvss_score)
            )
            source = _high_water_source(agentic_score, cvss_score)
            confidence_counts = tuple(
                (
                    confidence,
                    sum(item.confidence is confidence for item in contributions),
                )
                for confidence in EvidenceConfidence
            )
            return TechnicalScoreAssessment(
                format=TECHNICAL_SCORE_FORMAT,
                format_version=TECHNICAL_SCORE_FORMAT_VERSION,
                model_version=TECHNICAL_SCORE_MODEL_VERSION,
                agentic_factor_model_version=AGENTIC_FACTOR_MODEL_VERSION,
                threat_mitigation_model_version=THREAT_MITIGATION_MODEL_VERSION,
                agent_id=factors.agent_id,
                manifest_sha256=factors.manifest_sha256,
                agentic_score=agentic_score,
                cvss_base_score=cvss_score,
                technical_score=technical_score,
                severity=severity_for_cvss_score(technical_score),
                factor_contributions=contributions,
                confidence_counts=confidence_counts,
                high_water_mark_source=source,
                mapping_basis=TECHNICAL_SCORE_BASIS,
            )
        except (TypeError, ValueError, KeyError) as error:
            raise TechnicalScoreError(
                "Technical Score calculation failed safely"
            ) from error

    @staticmethod
    def _validate_bindings(
        factors: AgenticFactorVector,
        threats: ThreatMitigationVector,
    ) -> None:
        if factors.agent_id != threats.agent_id:
            raise ValueError("Factor and Threat/Mitigation Agent IDs differ")
        if factors.manifest_sha256 != threats.manifest_sha256:
            raise ValueError("Factor and Threat/Mitigation Manifest hashes differ")
        if factors.format_version != "0.1.0":
            raise ValueError("Factor Vector format is unsupported")
        if threats.format_version != "0.1.0":
            raise ValueError("Threat/Mitigation Vector format is unsupported")

    @staticmethod
    def _contribution(
        factors: AgenticFactorVector,
        assessment: ThreatMitigationAssessment,
    ) -> TechnicalFactorContribution:
        factor = next(
            item
            for item in factors.factors
            if item.factor_id is assessment.threat.factor_id
        )
        weight = TECHNICAL_FACTOR_WEIGHTS[factor.factor_id]
        contribution = _round_score(
            10.0 * factor.value * weight * assessment.mitigation.multiplier
        )
        return TechnicalFactorContribution(
            factor_id=factor.factor_id,
            value=factor.value,
            weight=weight,
            mitigation_multiplier=assessment.mitigation.multiplier,
            contribution=contribution,
            confidence=factor.confidence,
            threat_state=assessment.threat.state,
            mitigation_state=assessment.mitigation.state,
        )


def _high_water_source(
    agentic_score: float,
    cvss_score: float | None,
) -> Literal["agentic", "cvss_base", "tie"]:
    if cvss_score is None or agentic_score > cvss_score:
        return "agentic"
    if cvss_score > agentic_score:
        return "cvss_base"
    return "tie"


def _round_score(value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("score must be numeric")
    decimal = Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    return float(decimal)


def _validate_score(value: float, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 10.0
    ):
        raise ValueError(f"{label} must be finite and within 0 to 10")


def _validate_confidence_counts(
    values: tuple[tuple[EvidenceConfidence, int], ...],
) -> None:
    if tuple(item[0] for item in values) != tuple(EvidenceConfidence):
        raise ValueError("confidence counts must contain all grades in stable order")
    if any(count < 0 for _, count in values):
        raise ValueError("confidence counts must not be negative")


def _validate_unique_strings(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} values must be unique")


__all__ = [
    "TECHNICAL_FACTOR_WEIGHTS",
    "TECHNICAL_SCORE_BASIS",
    "TECHNICAL_SCORE_FORMAT",
    "TECHNICAL_SCORE_FORMAT_VERSION",
    "DeterministicTechnicalScoreEngine",
    "TechnicalFactorContribution",
    "TechnicalScoreAssessment",
    "TechnicalScoreError",
    "encode_technical_score_json",
]

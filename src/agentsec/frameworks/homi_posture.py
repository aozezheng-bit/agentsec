"""Potential-impact and current-posture reporting for Homi Findings.

The existing Homi Pilot score is a deterministic potential-impact score.  It
must not be presented as proof that an Agent is currently exposed.  This
module adds a compatibility-preserving sidecar that keeps those concepts
separate and makes the lack of runtime evidence explicit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from agentsec.domain import ImpactLevel, LikelihoodLevel, Severity
from agentsec.frameworks.homi_calibration import build_homi_calibration_report
from agentsec.frameworks.homi_combination import HomiCombinationFinding
from agentsec.frameworks.homi_operationality import (
    HomiOperationality,
    HomiOperationalityEntry,
    build_homi_operationality_report,
)
from agentsec.frameworks.homi_pilot import (
    HomiPilotReport,
    encode_homi_pilot_json,
)
from agentsec.versioning import HOMI_POSTURE_OUTPUT_VERSION

HOMI_POSTURE_FORMAT: Literal["agentsec-homi-posture"] = "agentsec-homi-posture"
HOMI_POSTURE_FORMAT_VERSION = HOMI_POSTURE_OUTPUT_VERSION


class HomiCurrentPosture(StrEnum):
    """Current-state interpretation of a potential-impact Finding."""

    TEMPLATE_ONLY = "template_only"
    LATENT_UNVERIFIED = "latent_unverified"
    ACTIVE_UNVERIFIED = "active_unverified"
    RUNTIME_ATTESTED = "runtime_attested"
    NOT_ESTABLISHED = "not_established"


@dataclass(frozen=True, slots=True)
class HomiPostureFinding:
    """One Finding with potential and current-state scores separated."""

    finding_id: str
    rule_id: str
    potential_impact_score: float
    potential_impact_level: ImpactLevel
    likelihood: LikelihoodLevel
    severity: Severity
    evidence_confidence: str
    operationality: HomiOperationality
    current_posture: HomiCurrentPosture
    current_posture_score: float | None
    related_signal_ids: tuple[str, ...]
    runtime_verified: Literal[False] = False

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "Homi posture finding_id")
        _require_text(self.rule_id, "Homi posture rule_id")
        if not 0.0 <= self.potential_impact_score <= 10.0:
            raise ValueError("Homi potential impact score is out of range")
        if not isinstance(self.potential_impact_level, ImpactLevel):
            raise TypeError("Homi potential impact level is invalid")
        if not isinstance(self.likelihood, LikelihoodLevel):
            raise TypeError("Homi posture likelihood is invalid")
        if not isinstance(self.severity, Severity):
            raise TypeError("Homi posture severity is invalid")
        _require_text(self.evidence_confidence, "Homi posture evidence_confidence")
        if not isinstance(self.operationality, HomiOperationality):
            raise TypeError("Homi posture operationality is invalid")
        if not isinstance(self.current_posture, HomiCurrentPosture):
            raise TypeError("Homi current posture is invalid")
        if self.current_posture_score is not None and not (
            0.0 <= self.current_posture_score <= 10.0
        ):
            raise ValueError("Homi current posture score is out of range")
        if self.current_posture is HomiCurrentPosture.RUNTIME_ATTESTED:
            if self.current_posture_score != self.potential_impact_score:
                raise ValueError(
                    "runtime-attested current score must equal potential impact"
                )
        elif self.current_posture_score is not None:
            raise ValueError(
                "static/unverified current posture must not carry a numeric score"
            )
        if self.related_signal_ids != tuple(sorted(set(self.related_signal_ids))):
            raise ValueError("Homi posture signal IDs must be sorted and unique")
        if self.runtime_verified is not False:
            raise ValueError("Homi posture cannot attest runtime")

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "potential_impact_score": self.potential_impact_score,
            "potential_impact_level": self.potential_impact_level.value,
            "likelihood": self.likelihood.value,
            "severity": self.severity.value,
            "evidence_confidence": self.evidence_confidence,
            "operationality": self.operationality.value,
            "current_posture": self.current_posture.value,
            "current_posture_score": self.current_posture_score,
            "related_signal_ids": list(self.related_signal_ids),
            "runtime_verified": self.runtime_verified,
        }


@dataclass(frozen=True, slots=True)
class HomiPostureReport:
    """Sidecar bound to one exact Homi Pilot JSON report."""

    format: Literal["agentsec-homi-posture"]
    format_version: str
    source_report_sha256: str
    source_report_format: str
    raw_potential_impact_score: float
    potential_impact_score: float
    raw_finding_count: int
    suppressed_finding_count: int
    current_posture_score: float | None
    current_posture: HomiCurrentPosture
    findings: tuple[HomiPostureFinding, ...]
    operationality_counts: tuple[tuple[HomiOperationality, int], ...]
    runtime_verified: Literal[False] = False
    report_only: Literal[True] = True
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_POSTURE_FORMAT:
            raise ValueError("Homi posture format is unsupported")
        if self.format_version != HOMI_POSTURE_FORMAT_VERSION:
            raise ValueError("Homi posture version is unsupported")
        _require_digest(self.source_report_sha256, "source_report_sha256")
        _require_text(self.source_report_format, "source_report_format")
        if not 0.0 <= self.raw_potential_impact_score <= 10.0:
            raise ValueError("Homi raw potential impact is out of range")
        if not 0.0 <= self.potential_impact_score <= 10.0:
            raise ValueError("Homi aggregate potential impact is out of range")
        if self.potential_impact_score > self.raw_potential_impact_score:
            raise ValueError("calibrated potential impact cannot exceed raw impact")
        for value, label in (
            (self.raw_finding_count, "raw_finding_count"),
            (self.suppressed_finding_count, "suppressed_finding_count"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"Homi posture {label} is invalid")
        if self.suppressed_finding_count > self.raw_finding_count:
            raise ValueError("Homi suppressed Finding count is invalid")
        if self.current_posture_score is not None and not (
            0.0 <= self.current_posture_score <= 10.0
        ):
            raise ValueError("Homi aggregate current posture score is out of range")
        if not isinstance(self.current_posture, HomiCurrentPosture):
            raise TypeError("Homi aggregate current posture is invalid")
        if self.findings != tuple(
            sorted(self.findings, key=lambda item: (item.rule_id, item.finding_id))
        ):
            raise ValueError("Homi posture Findings must be sorted")
        expected_counts = tuple(
            (
                operationality,
                sum(item.operationality is operationality for item in self._entries()),
            )
            for operationality in HomiOperationality
        )
        if self.operationality_counts != expected_counts:
            raise ValueError("Homi operationality counts are inconsistent")
        if self.runtime_verified is not False:
            raise ValueError("Homi posture cannot attest runtime")
        if self.report_only is not True or self.ci_blocked is not False:
            raise ValueError("Homi posture authority flags are invalid")

    def _entries(self) -> tuple[HomiPostureFinding, ...]:
        return self.findings

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_report_sha256": self.source_report_sha256,
            "source_report_format": self.source_report_format,
            "raw_potential_impact_score": self.raw_potential_impact_score,
            "potential_impact_score": self.potential_impact_score,
            "raw_finding_count": self.raw_finding_count,
            "suppressed_finding_count": self.suppressed_finding_count,
            "current_posture_score": self.current_posture_score,
            "current_posture": self.current_posture.value,
            "operationality_counts": {
                key.value: value for key, value in self.operationality_counts
            },
            "findings": [item.to_dict() for item in self.findings],
            "scoring_basis": {
                "potential_impact": (
                    "Existing deterministic NIST likelihood-impact mapping and "
                    "AgentSec 0-10 representative score."
                ),
                "current_posture": (
                    "A numeric current score is emitted only for independent "
                    "runtime_attested evidence; static findings remain unverified."
                ),
            },
            "runtime_verified": self.runtime_verified,
            "report_only": self.report_only,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_posture_report(report: HomiPilotReport) -> HomiPostureReport:
    """Build potential/current posture fields without mutating the Pilot JSON."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi posture builder requires HomiPilotReport")
    operationality = build_homi_operationality_report(report)
    calibration = build_homi_calibration_report(report)
    by_signal = {item.signal_id: item for item in operationality.entries}
    original_findings = tuple(report.combination_result.findings)
    retained_ids = {item.finding_id for item in calibration.retained_findings}
    findings = tuple(
        sorted(
            (
                _finding(item, by_signal)
                for item in original_findings
                if item.finding_id in retained_ids
            ),
            key=lambda item: (item.rule_id, item.finding_id),
        )
    )
    raw_potential = max((item.score for item in original_findings), default=0.0)
    potential = max(
        (item.potential_impact_score for item in findings),
        default=0.0,
    )
    current_scores = [
        item.current_posture_score
        for item in findings
        if item.current_posture_score is not None
    ]
    current = max(current_scores, default=None)
    posture = _aggregate_posture(findings)
    counts = tuple(
        (
            operationality_value,
            sum(item.operationality is operationality_value for item in findings),
        )
        for operationality_value in HomiOperationality
    )
    source = hashlib.sha256(encode_homi_pilot_json(report).encode("utf-8")).hexdigest()
    return HomiPostureReport(
        format=HOMI_POSTURE_FORMAT,
        format_version=HOMI_POSTURE_FORMAT_VERSION,
        source_report_sha256=source,
        source_report_format=report.format,
        raw_potential_impact_score=raw_potential,
        potential_impact_score=potential,
        raw_finding_count=len(original_findings),
        suppressed_finding_count=calibration.suppressed_finding_count,
        current_posture_score=current,
        current_posture=posture,
        findings=findings,
        operationality_counts=counts,
    )


def encode_homi_posture_json(report: HomiPostureReport) -> str:
    """Encode a deterministic posture sidecar."""

    if not isinstance(report, HomiPostureReport):
        raise TypeError("Homi posture encoder requires HomiPostureReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def _finding(
    finding: HomiCombinationFinding,
    by_signal: dict[str, HomiOperationalityEntry],
) -> HomiPostureFinding:
    signal_entries = [
        by_signal[signal_id]
        for signal_id in finding.related_signal_ids
        if signal_id in by_signal
    ]
    operationality = _finding_operationality(signal_entries)
    current_posture = _current_posture(operationality)
    current_score = (
        finding.score
        if current_posture is HomiCurrentPosture.RUNTIME_ATTESTED
        else None
    )
    return HomiPostureFinding(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        potential_impact_score=finding.score,
        potential_impact_level=finding.impact,
        likelihood=finding.likelihood,
        severity=finding.severity,
        evidence_confidence=finding.confidence.value,
        operationality=operationality,
        current_posture=current_posture,
        current_posture_score=current_score,
        related_signal_ids=finding.related_signal_ids,
    )


def _finding_operationality(
    entries: list[HomiOperationalityEntry],
) -> HomiOperationality:
    if not entries:
        return HomiOperationality.LATENT
    order = {
        HomiOperationality.RUNTIME_ATTESTED: 3,
        HomiOperationality.ACTIVE: 2,
        HomiOperationality.LATENT: 1,
        HomiOperationality.TEMPLATE: 0,
    }
    return max(entries, key=lambda item: order[item.operationality]).operationality


def _current_posture(operationality: HomiOperationality) -> HomiCurrentPosture:
    return {
        HomiOperationality.TEMPLATE: HomiCurrentPosture.TEMPLATE_ONLY,
        HomiOperationality.LATENT: HomiCurrentPosture.LATENT_UNVERIFIED,
        HomiOperationality.ACTIVE: HomiCurrentPosture.ACTIVE_UNVERIFIED,
        HomiOperationality.RUNTIME_ATTESTED: HomiCurrentPosture.RUNTIME_ATTESTED,
    }[operationality]


def _aggregate_posture(
    findings: tuple[HomiPostureFinding, ...],
) -> HomiCurrentPosture:
    if not findings:
        return HomiCurrentPosture.NOT_ESTABLISHED
    order = {
        HomiCurrentPosture.RUNTIME_ATTESTED: 4,
        HomiCurrentPosture.ACTIVE_UNVERIFIED: 3,
        HomiCurrentPosture.LATENT_UNVERIFIED: 2,
        HomiCurrentPosture.TEMPLATE_ONLY: 1,
        HomiCurrentPosture.NOT_ESTABLISHED: 0,
    }
    return max(findings, key=lambda item: order[item.current_posture]).current_posture


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


__all__ = [
    "HOMI_POSTURE_FORMAT",
    "HOMI_POSTURE_FORMAT_VERSION",
    "HomiCurrentPosture",
    "HomiPostureFinding",
    "HomiPostureReport",
    "build_homi_posture_report",
    "encode_homi_posture_json",
]

"""Deterministic calibration decisions for the Homi combination findings.

Calibration is kept as a sidecar so historical Homi Pilot 0.2.0 evidence is
not rewritten.  It removes template-only interpretations from the calibrated
view while retaining the original report and its source digest for audit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from agentsec.frameworks.homi_combination import HomiCombinationFinding
from agentsec.frameworks.homi_pilot import HomiPilotReport, encode_homi_pilot_json
from agentsec.frameworks.homi_profile import HomiCapabilityState
from agentsec.versioning import HOMI_CALIBRATION_OUTPUT_VERSION

HOMI_CALIBRATION_FORMAT: Literal["agentsec-homi-calibration"] = (
    "agentsec-homi-calibration"
)
HOMI_CALIBRATION_FORMAT_VERSION = HOMI_CALIBRATION_OUTPUT_VERSION


class HomiCalibrationDisposition(StrEnum):
    """Disposition of an original combination Finding in the calibrated view."""

    RETAINED = "retained"
    SUPPRESSED = "suppressed"


@dataclass(frozen=True, slots=True)
class HomiCalibrationDecision:
    """Auditable deterministic decision for one original Finding."""

    finding_id: str
    rule_id: str
    disposition: HomiCalibrationDisposition
    rationale_code: str
    rationale: str
    related_signal_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "Homi calibration finding_id")
        _require_text(self.rule_id, "Homi calibration rule_id")
        if not isinstance(self.disposition, HomiCalibrationDisposition):
            raise TypeError("Homi calibration disposition is invalid")
        _require_text(self.rationale_code, "Homi calibration rationale_code")
        _require_text(self.rationale, "Homi calibration rationale")
        if self.related_signal_ids != tuple(sorted(set(self.related_signal_ids))):
            raise ValueError("Homi calibration signal IDs must be sorted and unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "disposition": self.disposition.value,
            "rationale_code": self.rationale_code,
            "rationale": self.rationale,
            "related_signal_ids": list(self.related_signal_ids),
        }


@dataclass(frozen=True, slots=True)
class HomiCalibrationReport:
    """Calibrated Finding view bound to the original Pilot report."""

    format: Literal["agentsec-homi-calibration"]
    format_version: str
    source_report_sha256: str
    source_report_format: str
    original_finding_count: int
    retained_findings: tuple[HomiCombinationFinding, ...]
    decisions: tuple[HomiCalibrationDecision, ...]
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_CALIBRATION_FORMAT:
            raise ValueError("Homi calibration format is unsupported")
        if self.format_version != HOMI_CALIBRATION_FORMAT_VERSION:
            raise ValueError("Homi calibration version is unsupported")
        _require_digest(self.source_report_sha256, "source_report_sha256")
        _require_text(self.source_report_format, "source_report_format")
        if (
            isinstance(self.original_finding_count, bool)
            or not isinstance(self.original_finding_count, int)
            or self.original_finding_count < 0
        ):
            raise ValueError("Homi original Finding count is invalid")
        if self.retained_findings != tuple(
            sorted(
                self.retained_findings,
                key=lambda item: (item.rule_id, item.finding_id),
            )
        ):
            raise ValueError("Homi calibrated Findings must be sorted")
        if self.decisions != tuple(
            sorted(self.decisions, key=lambda item: (item.rule_id, item.finding_id))
        ):
            raise ValueError("Homi calibration decisions must be sorted")
        if len(self.decisions) != self.original_finding_count:
            raise ValueError("Homi calibration decisions must cover all Findings")
        if len({item.finding_id for item in self.decisions}) != len(self.decisions):
            raise ValueError("Homi calibration decisions must be unique")
        retained_ids = {item.finding_id for item in self.retained_findings}
        decision_retained_ids = {
            item.finding_id
            for item in self.decisions
            if item.disposition is HomiCalibrationDisposition.RETAINED
        }
        if retained_ids != decision_retained_ids:
            raise ValueError("Homi retained Findings do not match decisions")
        if self.report_only is not True or self.runtime_verified is not False:
            raise ValueError("Homi calibration authority flags are invalid")
        if self.ci_blocked is not False:
            raise ValueError("Homi calibration cannot block CI")

    @property
    def suppressed_finding_count(self) -> int:
        return sum(
            item.disposition is HomiCalibrationDisposition.SUPPRESSED
            for item in self.decisions
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_report_sha256": self.source_report_sha256,
            "source_report_format": self.source_report_format,
            "original_finding_count": self.original_finding_count,
            "retained_finding_count": len(self.retained_findings),
            "suppressed_finding_count": self.suppressed_finding_count,
            "retained_findings": [item.to_dict() for item in self.retained_findings],
            "decisions": [item.to_dict() for item in self.decisions],
            "policy": {
                "HOMI-COMB-003": (
                    "Suppress template-only USER.md persistence; retain only when "
                    "the report proves a non-template profile with persistence."
                ),
                "HOMI-COMB-004": (
                    "Suppress persona/identity placeholder language unless an "
                    "explicit control-file modification declaration is present."
                ),
            },
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_calibration_report(report: HomiPilotReport) -> HomiCalibrationReport:
    """Apply the reviewed 003/004 template calibration to one Pilot report."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi calibration builder requires HomiPilotReport")
    decisions: list[HomiCalibrationDecision] = []
    retained: list[HomiCombinationFinding] = []
    for finding in report.combination_result.findings:
        decision = _decide(report, finding)
        decisions.append(decision)
        if decision.disposition is HomiCalibrationDisposition.RETAINED:
            retained.append(finding)
    ordered_decisions = tuple(
        sorted(decisions, key=lambda item: (item.rule_id, item.finding_id))
    )
    ordered_retained = tuple(
        sorted(retained, key=lambda item: (item.rule_id, item.finding_id))
    )
    source = hashlib.sha256(encode_homi_pilot_json(report).encode("utf-8")).hexdigest()
    return HomiCalibrationReport(
        format=HOMI_CALIBRATION_FORMAT,
        format_version=HOMI_CALIBRATION_FORMAT_VERSION,
        source_report_sha256=source,
        source_report_format=report.format,
        original_finding_count=len(report.combination_result.findings),
        retained_findings=ordered_retained,
        decisions=ordered_decisions,
    )


def encode_homi_calibration_json(report: HomiCalibrationReport) -> str:
    """Encode a deterministic calibration sidecar."""

    if not isinstance(report, HomiCalibrationReport):
        raise TypeError("Homi calibration encoder requires HomiCalibrationReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def _decide(
    report: HomiPilotReport,
    finding: HomiCombinationFinding,
) -> HomiCalibrationDecision:
    if finding.rule_id == "HOMI-COMB-003":
        user_privacy = report.user_privacy
        is_template = user_privacy.get("template_present") is True
        persistence = user_privacy.get("persistence")
        persistence_present = (
            isinstance(persistence, dict)
            and persistence.get("state") == HomiCapabilityState.PRESENT.value
        )
        disposition = (
            HomiCalibrationDisposition.SUPPRESSED
            if is_template or not persistence_present
            else HomiCalibrationDisposition.RETAINED
        )
        return HomiCalibrationDecision(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            disposition=disposition,
            rationale_code=(
                "user-profile-template-only"
                if disposition is HomiCalibrationDisposition.SUPPRESSED
                else "user-profile-non-template-persistence"
            ),
            rationale=(
                "USER.md is classified as a template; blank/place-holder fields do "
                "not prove real user data persistence."
                if disposition is HomiCalibrationDisposition.SUPPRESSED
                else "USER.md is non-template and explicitly declares persistence."
            ),
            related_signal_ids=finding.related_signal_ids,
        )
    if finding.rule_id == "HOMI-COMB-004":
        explicit_control = (
            "control_file_self_modification" in finding.related_signal_ids
        )
        disposition = (
            HomiCalibrationDisposition.RETAINED
            if explicit_control
            else HomiCalibrationDisposition.SUPPRESSED
        )
        return HomiCalibrationDecision(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            disposition=disposition,
            rationale_code=(
                "explicit-control-file-modification"
                if explicit_control
                else "persona-identity-template-only"
            ),
            rationale=(
                "An explicit control-file modification declaration is present; "
                "runtime write authority remains unverified."
                if explicit_control
                else "Persona/identity placeholder language alone does not prove "
                "control-file write capability."
            ),
            related_signal_ids=finding.related_signal_ids,
        )
    return HomiCalibrationDecision(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        disposition=HomiCalibrationDisposition.RETAINED,
        rationale_code="not-in-calibration-scope",
        rationale="This Finding is outside the HOMI-COMB-003/004 calibration scope.",
        related_signal_ids=finding.related_signal_ids,
    )


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
    "HOMI_CALIBRATION_FORMAT",
    "HOMI_CALIBRATION_FORMAT_VERSION",
    "HomiCalibrationDecision",
    "HomiCalibrationDisposition",
    "HomiCalibrationReport",
    "build_homi_calibration_report",
    "encode_homi_calibration_json",
]

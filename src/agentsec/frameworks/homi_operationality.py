"""Operationality classification for Homi static capability evidence.

Operationality answers a different question from Severity and Evidence
Confidence: how operationally mature is the observed declaration?  This
module is intentionally a sidecar contract so the frozen Homi Pilot 0.2.0
report remains byte-for-byte replayable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from agentsec.frameworks.homi_pilot import (
    HomiPilotReport,
    HomiPilotSignalSummary,
    encode_homi_pilot_json,
)
from agentsec.frameworks.homi_profile import (
    HomiCapabilityState,
    HomiEvidenceMethod,
)
from agentsec.versioning import HOMI_OPERATIONALITY_OUTPUT_VERSION

HOMI_OPERATIONALITY_FORMAT: Literal["agentsec-homi-operationality"] = (
    "agentsec-homi-operationality"
)
HOMI_OPERATIONALITY_FORMAT_VERSION = HOMI_OPERATIONALITY_OUTPUT_VERSION


class HomiOperationality(StrEnum):
    """Maturity of a static declaration's operational evidence."""

    TEMPLATE = "template"
    LATENT = "latent"
    ACTIVE = "active"
    RUNTIME_ATTESTED = "runtime_attested"


@dataclass(frozen=True, slots=True)
class HomiOperationalityEntry:
    """One capability/persona classification with independent confidence."""

    scope: Literal["capability", "persona"]
    signal_id: str
    state: HomiCapabilityState
    operationality: HomiOperationality
    confidence: str
    method: HomiEvidenceMethod
    source_paths: tuple[str, ...]
    runtime_verified: Literal[False] = False

    def __post_init__(self) -> None:
        if self.scope not in {"capability", "persona"}:
            raise ValueError("Homi operationality scope is invalid")
        _require_text(self.signal_id, "Homi operationality signal_id")
        if not isinstance(self.state, HomiCapabilityState):
            raise TypeError("Homi operationality state is invalid")
        if not isinstance(self.operationality, HomiOperationality):
            raise TypeError("Homi operationality value is invalid")
        _require_text(self.confidence, "Homi operationality confidence")
        if not isinstance(self.method, HomiEvidenceMethod):
            raise TypeError("Homi operationality method is invalid")
        if self.source_paths != tuple(sorted(set(self.source_paths))):
            raise ValueError("Homi operationality source paths must be sorted/unique")
        if self.runtime_verified is not False:
            raise ValueError("static Homi operationality cannot attest runtime")
        if self.operationality is HomiOperationality.RUNTIME_ATTESTED:
            raise ValueError("static Homi operationality cannot be runtime_attested")

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "signal_id": self.signal_id,
            "state": self.state.value,
            "operationality": self.operationality.value,
            "confidence": self.confidence,
            "method": self.method.value,
            "source_paths": list(self.source_paths),
            "runtime_verified": self.runtime_verified,
        }


@dataclass(frozen=True, slots=True)
class HomiOperationalityReport:
    """Sidecar report bound to one exact Homi Pilot JSON artifact."""

    format: Literal["agentsec-homi-operationality"]
    format_version: str
    source_report_sha256: str
    source_report_format: str
    entries: tuple[HomiOperationalityEntry, ...]
    counts: tuple[tuple[HomiOperationality, int], ...]
    runtime_verified: Literal[False] = False
    report_only: Literal[True] = True
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_OPERATIONALITY_FORMAT:
            raise ValueError("Homi operationality format is unsupported")
        if self.format_version != HOMI_OPERATIONALITY_FORMAT_VERSION:
            raise ValueError("Homi operationality version is unsupported")
        _require_digest(self.source_report_sha256, "source_report_sha256")
        _require_text(self.source_report_format, "source_report_format")
        if self.entries != tuple(
            sorted(self.entries, key=lambda item: (item.scope, item.signal_id))
        ):
            raise ValueError("Homi operationality entries must be sorted")
        if len({(item.scope, item.signal_id) for item in self.entries}) != len(
            self.entries
        ):
            raise ValueError("Homi operationality entries must be unique")
        expected_counts = tuple(
            (
                operationality,
                sum(item.operationality is operationality for item in self.entries),
            )
            for operationality in HomiOperationality
        )
        if self.counts != expected_counts:
            raise ValueError("Homi operationality counts are inconsistent")
        if self.runtime_verified is not False:
            raise ValueError("Homi operationality cannot attest runtime")
        if self.report_only is not True or self.ci_blocked is not False:
            raise ValueError("Homi operationality authority flags are invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_report_sha256": self.source_report_sha256,
            "source_report_format": self.source_report_format,
            "counts": {key.value: value for key, value in self.counts},
            "entries": [item.to_dict() for item in self.entries],
            "runtime_verified": self.runtime_verified,
            "report_only": self.report_only,
            "ci_blocked": self.ci_blocked,
        }


def build_homi_operationality_report(
    report: HomiPilotReport,
) -> HomiOperationalityReport:
    """Classify static Homi signals without changing the source report."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi operationality builder requires HomiPilotReport")
    entries = [_entry("capability", signal) for signal in report.capabilities]
    entries.extend(_entry("persona", signal) for signal in report.persona_signals)
    ordered = tuple(sorted(entries, key=lambda item: (item.scope, item.signal_id)))
    counts = tuple(
        (
            operationality,
            sum(item.operationality is operationality for item in ordered),
        )
        for operationality in HomiOperationality
    )
    raw_source = encode_homi_pilot_json(report).encode("utf-8")
    return HomiOperationalityReport(
        format=HOMI_OPERATIONALITY_FORMAT,
        format_version=HOMI_OPERATIONALITY_FORMAT_VERSION,
        source_report_sha256=hashlib.sha256(raw_source).hexdigest(),
        source_report_format=report.format,
        entries=ordered,
        counts=counts,
    )


def encode_homi_operationality_json(report: HomiOperationalityReport) -> str:
    """Encode an operationality sidecar as deterministic JSON."""

    if not isinstance(report, HomiOperationalityReport):
        raise TypeError("Homi operationality encoder requires HomiOperationalityReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def _entry(
    scope: Literal["capability", "persona"],
    signal: HomiPilotSignalSummary,
) -> HomiOperationalityEntry:
    return HomiOperationalityEntry(
        scope=scope,
        signal_id=signal.signal_id,
        state=signal.state,
        operationality=_classify(signal),
        confidence=signal.confidence,
        method=signal.method,
        source_paths=signal.source_paths,
    )


def _classify(signal: HomiPilotSignalSummary) -> HomiOperationality:
    if signal.state is HomiCapabilityState.EXAMPLE_ONLY:
        return HomiOperationality.TEMPLATE
    if signal.method is HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION:
        return HomiOperationality.TEMPLATE

    # Generic self-description and persistence placeholders describe intent,
    # not an active runtime path.  Keep these conservative until an explicit
    # write/attestation contract exists.
    if signal.signal_id in {
        "identity_self_modification",
        "persona_self_modification",
        "user_profile_persistence",
        "persistent_memory",
        "self_evolution",
    }:
        return HomiOperationality.LATENT

    if (
        signal.state
        in {
            HomiCapabilityState.PRESENT,
            HomiCapabilityState.CONDITIONAL,
        }
        and signal.method is HomiEvidenceMethod.STATIC_DECLARATION
    ):
        return HomiOperationality.ACTIVE

    return HomiOperationality.LATENT


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
    "HOMI_OPERATIONALITY_FORMAT",
    "HOMI_OPERATIONALITY_FORMAT_VERSION",
    "HomiOperationality",
    "HomiOperationalityEntry",
    "HomiOperationalityReport",
    "build_homi_operationality_report",
    "encode_homi_operationality_json",
]

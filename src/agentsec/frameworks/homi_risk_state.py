"""Homi template/latent/active state contract (RISK-02).

This module adds a value-minimized state view on top of the historical Homi
Pilot report.  It intentionally does not replace the older
``homi-operationality.json`` sidecar: accepted 0.2.0 Pilot evidence must remain
replayable.  The RISK-02 view adds file-level coverage and an explicit
``unknown`` state so a missing or unclassified signal is not silently treated
as latent activity.

The state is an interpretation of static evidence, not a permission decision:
``active`` means that a concrete non-template declaration was observed, not
that a runtime tool, scheduler, identity, or permission is reachable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.frameworks.homi import HomiFileState
from agentsec.frameworks.homi_pilot import (
    HomiPilotFileSummary,
    HomiPilotReport,
    HomiPilotSignalSummary,
    encode_homi_pilot_json,
)
from agentsec.frameworks.homi_profile import (
    HomiCapabilityState,
    HomiEvidenceMethod,
)
from agentsec.versioning import HOMI_RISK_STATE_OUTPUT_VERSION

HOMI_RISK_STATE_FORMAT: Literal["agentsec-homi-risk-state"] = "agentsec-homi-risk-state"
HOMI_RISK_STATE_FORMAT_VERSION = HOMI_RISK_STATE_OUTPUT_VERSION
HOMI_RISK_STATE_BASIS = (
    "AgentSec RISK-02 Homi template/latent/active state contract 0.1.0",
    "Static state classification is evidence interpretation, not runtime authority",
    "Template, latent, active, runtime_attested, and unknown are mutually exclusive",
    "Missing or skipped source coverage is unknown, not evidence of safety or activity",
)


class HomiRiskState(StrEnum):
    """Operational state assigned to a Homi file or profile signal."""

    TEMPLATE = "template"
    LATENT = "latent"
    ACTIVE = "active"
    RUNTIME_ATTESTED = "runtime_attested"
    UNKNOWN = "unknown"


class HomiRiskStateScope(StrEnum):
    """Kind of Homi object represented by one state entry."""

    FILE = "file"
    CAPABILITY = "capability"
    PERSONA = "persona"


@dataclass(frozen=True, slots=True)
class HomiRiskStateEntry:
    """One file or profile signal state with bounded provenance."""

    scope: HomiRiskStateScope
    item_id: str
    declared_state: str
    state: HomiRiskState
    rationale_code: str
    confidence: str | None
    method: str | None
    source_paths: tuple[str, ...]
    runtime_verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scope, HomiRiskStateScope):
            raise TypeError("Homi risk state scope is invalid")
        _require_text(self.item_id, "Homi risk state item_id")
        _require_text(self.declared_state, "Homi risk state declared_state")
        if not isinstance(self.state, HomiRiskState):
            raise TypeError("Homi risk state value is invalid")
        _require_text(self.rationale_code, "Homi risk state rationale_code")
        if self.confidence is not None:
            _require_text(self.confidence, "Homi risk state confidence")
        if self.method is not None:
            _require_text(self.method, "Homi risk state method")
        if self.source_paths != tuple(sorted(set(self.source_paths))):
            raise ValueError("Homi risk state source paths must be sorted/unique")
        if not isinstance(self.runtime_verified, bool):
            raise TypeError("Homi risk state runtime_verified must be bool")
        if self.state is HomiRiskState.RUNTIME_ATTESTED:
            if not self.runtime_verified:
                raise ValueError(
                    "runtime_attested state requires runtime_verified=true"
                )
        elif self.runtime_verified:
            raise ValueError(
                "runtime_verified=true is only valid for runtime_attested state"
            )

    def sort_key(self) -> tuple[str, str]:
        return (self.scope.value, self.item_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope.value,
            "item_id": self.item_id,
            "declared_state": self.declared_state,
            "state": self.state.value,
            "rationale_code": self.rationale_code,
            "confidence": self.confidence,
            "method": self.method,
            "source_paths": list(self.source_paths),
            "runtime_verified": self.runtime_verified,
        }


@dataclass(frozen=True, slots=True)
class HomiRiskStateReport:
    """RISK-02 state report bound to one exact Homi Pilot JSON artifact."""

    format: Literal["agentsec-homi-risk-state"]
    format_version: str
    source_report_sha256: str
    source_report_format: str
    entries: tuple[HomiRiskStateEntry, ...]
    counts: tuple[tuple[HomiRiskState, int], ...]
    file_count: int
    signal_count: int
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_RISK_STATE_FORMAT:
            raise ValueError("Homi risk state format is unsupported")
        if self.format_version != HOMI_RISK_STATE_FORMAT_VERSION:
            raise ValueError("Homi risk state version is unsupported")
        _require_digest(self.source_report_sha256, "source_report_sha256")
        _require_text(self.source_report_format, "source_report_format")
        if self.entries != tuple(sorted(self.entries, key=HomiRiskStateEntry.sort_key)):
            raise ValueError("Homi risk state entries must be sorted")
        keys = tuple(item.sort_key() for item in self.entries)
        if len(keys) != len(set(keys)):
            raise ValueError("Homi risk state entries must be unique")
        if self.file_count != sum(
            item.scope is HomiRiskStateScope.FILE for item in self.entries
        ):
            raise ValueError("Homi risk state file_count is inconsistent")
        if self.signal_count != len(self.entries) - self.file_count:
            raise ValueError("Homi risk state signal_count is inconsistent")
        if any(
            item.state is HomiRiskState.RUNTIME_ATTESTED or item.runtime_verified
            for item in self.entries
        ):
            raise ValueError(
                "static Homi risk state report cannot contain runtime attestation"
            )
        expected_counts = tuple(
            (
                state,
                sum(item.state is state for item in self.entries),
            )
            for state in HomiRiskState
        )
        if self.counts != expected_counts:
            raise ValueError("Homi risk state counts are inconsistent")
        if self.report_only is not True:
            raise ValueError("Homi risk state must remain report-only")
        if self.runtime_verified is not False:
            raise ValueError("static Homi risk state cannot verify runtime")
        if self.ci_blocked is not False:
            raise ValueError("Homi risk state cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "source_report_sha256": self.source_report_sha256,
            "source_report_format": self.source_report_format,
            "basis": list(HOMI_RISK_STATE_BASIS),
            "file_count": self.file_count,
            "signal_count": self.signal_count,
            "counts": {key.value: value for key, value in self.counts},
            "entries": [item.to_dict() for item in self.entries],
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_risk_state_report(report: HomiPilotReport) -> HomiRiskStateReport:
    """Classify Homi files and profile signals from static Pilot evidence."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi risk state builder requires HomiPilotReport")

    entries = [_file_entry(item) for item in report.files]
    entries.extend(
        _signal_entry(HomiRiskStateScope.CAPABILITY, item)
        for item in report.capabilities
    )
    entries.extend(
        _signal_entry(HomiRiskStateScope.PERSONA, item)
        for item in report.persona_signals
    )
    ordered = tuple(sorted(entries, key=HomiRiskStateEntry.sort_key))
    counts = tuple(
        (state, sum(item.state is state for item in ordered)) for state in HomiRiskState
    )
    source = hashlib.sha256(encode_homi_pilot_json(report).encode("utf-8")).hexdigest()
    file_count = sum(item.scope is HomiRiskStateScope.FILE for item in ordered)
    return HomiRiskStateReport(
        format=HOMI_RISK_STATE_FORMAT,
        format_version=HOMI_RISK_STATE_FORMAT_VERSION,
        source_report_sha256=source,
        source_report_format=report.format,
        entries=ordered,
        counts=counts,
        file_count=file_count,
        signal_count=len(ordered) - file_count,
    )


def encode_homi_risk_state_json(report: HomiRiskStateReport) -> str:
    """Encode a deterministic RISK-02 state report."""

    if not isinstance(report, HomiRiskStateReport):
        raise TypeError("Homi risk state encoder requires HomiRiskStateReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def export_homi_risk_state_json_schema(output_directory: Path) -> Path:
    """Export the strict JSON Schema for the RISK-02 state report."""

    if not isinstance(output_directory, Path):
        raise TypeError("Homi risk state schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "homi-risk-state.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/homi-risk-state.schema.json",
        "title": "AgentSec Homi Risk State Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "source_report_sha256",
            "source_report_format",
            "basis",
            "file_count",
            "signal_count",
            "counts",
            "entries",
            "report_only",
            "runtime_verified",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": HOMI_RISK_STATE_FORMAT},
            "format_version": {"const": HOMI_RISK_STATE_FORMAT_VERSION},
            "source_report_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_report_format": {"const": "agentsec-homi-report-only-pilot"},
            "basis": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": len(HOMI_RISK_STATE_BASIS),
                "uniqueItems": True,
            },
            "file_count": {"type": "integer", "minimum": 0},
            "signal_count": {"type": "integer", "minimum": 0},
            "counts": {
                "type": "object",
                "additionalProperties": False,
                "required": [item.value for item in HomiRiskState],
                "properties": {
                    item.value: {"type": "integer", "minimum": 0}
                    for item in HomiRiskState
                },
            },
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "scope",
                        "item_id",
                        "declared_state",
                        "state",
                        "rationale_code",
                        "confidence",
                        "method",
                        "source_paths",
                        "runtime_verified",
                    ],
                    "properties": {
                        "scope": {"enum": [item.value for item in HomiRiskStateScope]},
                        "item_id": {"type": "string", "minLength": 1},
                        "declared_state": {"type": "string", "minLength": 1},
                        "state": {"enum": [item.value for item in HomiRiskState]},
                        "rationale_code": {"type": "string", "minLength": 1},
                        "confidence": {"type": ["string", "null"]},
                        "method": {"type": ["string", "null"]},
                        "source_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True,
                        },
                        "runtime_verified": {"const": False},
                    },
                },
            },
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "ci_blocked": {"const": False},
            "authority": {
                "type": "object",
                "additionalProperties": False,
                "required": ["report_only", "runtime_verified", "ci_blocked"],
                "properties": {
                    "report_only": {"const": True},
                    "runtime_verified": {"const": False},
                    "ci_blocked": {"const": False},
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _file_entry(file: HomiPilotFileSummary) -> HomiRiskStateEntry:
    if file.state in {HomiFileState.EMPTY, HomiFileState.EXAMPLE_ONLY}:
        state = HomiRiskState.TEMPLATE
        rationale = (
            "empty_file_placeholder"
            if file.state is HomiFileState.EMPTY
            else "example_only_file"
        )
    elif file.state is HomiFileState.PRESENT:
        state = HomiRiskState.ACTIVE
        rationale = "non_template_static_file"
    else:
        state = HomiRiskState.UNKNOWN
        rationale = (
            "missing_file_coverage"
            if file.state is HomiFileState.MISSING
            else "skipped_file_coverage"
        )
    return HomiRiskStateEntry(
        scope=HomiRiskStateScope.FILE,
        item_id=file.name,
        declared_state=file.state.value,
        state=state,
        rationale_code=rationale,
        confidence=(
            "B" if file.state in {HomiFileState.EMPTY, HomiFileState.PRESENT} else "D"
        ),
        method=(
            "structural_file_state"
            if file.state
            in {HomiFileState.EMPTY, HomiFileState.MISSING, HomiFileState.SKIPPED}
            else "static_template_classification"
            if file.state is HomiFileState.EXAMPLE_ONLY
            else "static_declaration"
        ),
        source_paths=(file.name,) if file.content_sha256 is not None else (),
    )


def _signal_entry(
    scope: HomiRiskStateScope,
    signal: HomiPilotSignalSummary,
) -> HomiRiskStateEntry:
    state, rationale = _classify_signal(scope, signal)
    return HomiRiskStateEntry(
        scope=scope,
        item_id=signal.signal_id,
        declared_state=signal.state.value,
        state=state,
        rationale_code=rationale,
        confidence=signal.confidence,
        method=signal.method.value,
        source_paths=signal.source_paths,
    )


def _classify_signal(
    scope: HomiRiskStateScope,
    signal: HomiPilotSignalSummary,
) -> tuple[HomiRiskState, str]:
    if signal.state is HomiCapabilityState.EXAMPLE_ONLY:
        return HomiRiskState.TEMPLATE, "example_only_signal"
    if signal.method is HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION:
        return HomiRiskState.TEMPLATE, "template_classification_evidence"
    if signal.state is HomiCapabilityState.ABSENT:
        return HomiRiskState.TEMPLATE, "structurally_absent"
    if signal.state is HomiCapabilityState.UNKNOWN:
        return HomiRiskState.UNKNOWN, "insufficient_static_coverage"
    if signal.method is HomiEvidenceMethod.RUNTIME_UNVERIFIED:
        return HomiRiskState.UNKNOWN, "runtime_state_not_attested"

    if scope is HomiRiskStateScope.PERSONA:
        return HomiRiskState.LATENT, "persona_intent_without_operation"
    if signal.signal_id in {
        "identity_self_modification",
        "persona_self_modification",
        "user_profile_persistence",
        "persistent_memory",
        "self_evolution",
    }:
        return HomiRiskState.LATENT, "intent_without_operational_evidence"
    if signal.state in {
        HomiCapabilityState.PRESENT,
        HomiCapabilityState.CONDITIONAL,
    }:
        return HomiRiskState.ACTIVE, "explicit_static_declaration"
    return HomiRiskState.UNKNOWN, "unclassified_static_state"


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
    "HOMI_RISK_STATE_BASIS",
    "HOMI_RISK_STATE_FORMAT",
    "HOMI_RISK_STATE_FORMAT_VERSION",
    "HomiRiskState",
    "HomiRiskStateEntry",
    "HomiRiskStateReport",
    "HomiRiskStateScope",
    "build_homi_risk_state_report",
    "encode_homi_risk_state_json",
    "export_homi_risk_state_json_schema",
]

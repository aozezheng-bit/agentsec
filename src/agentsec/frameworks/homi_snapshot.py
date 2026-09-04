"""Homi Agent Snapshot contract (RISK-06, snapshot line).

A Homi Snapshot is a deterministic, value-minimized summary of one exact
Homi Pilot run: stable workspace fingerprint, file digests, capability and
persona signal states, combination Finding summaries, coverage metrics, and
the engine versions that produced them.  The same workspace always yields the
same ``snapshot_digest``; session metadata (``pilot_id``/``owner``) is kept
out of the digest.  Snapshots are report-only evidence and never verify
runtime behavior or authorize anything.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.frameworks.homi_pilot import (
    HomiPilotReport,
    encode_homi_pilot_json,
)
from agentsec.versioning import HOMI_SNAPSHOT_OUTPUT_VERSION

HOMI_SNAPSHOT_FORMAT: Literal["agentsec-homi-snapshot"] = "agentsec-homi-snapshot"
HOMI_SNAPSHOT_FORMAT_VERSION = HOMI_SNAPSHOT_OUTPUT_VERSION
HOMI_SNAPSHOT_VERIFICATION_FORMAT: Literal["agentsec-homi-snapshot-verification"] = (
    "agentsec-homi-snapshot-verification"
)
HOMI_SNAPSHOT_BASIS = (
    "AgentSec RISK-06 Homi Agent Snapshot contract 0.1.0",
    "A Snapshot is static report-only evidence, not runtime verification",
    "The snapshot digest excludes session metadata (pilot_id/owner)",
    "The snapshot digest excludes the session-bound source report digest",
    "The workspace fingerprint is derived only from standard file digests",
    "Comparing snapshots across different agents is rejected, not drifted",
)
_HEX = frozenset("0123456789abcdef")


class HomiSnapshotStatus(StrEnum):
    """Outcome of comparing a baseline Snapshot with the current state."""

    VERIFIED = "verified"
    DRIFTED = "drifted"
    IDENTITY_MISMATCH = "identity_mismatch"


@dataclass(frozen=True, slots=True)
class HomiSnapshotFileSummary:
    """One standard Homi file with its content digest."""

    name: str
    state: str
    content_sha256: str | None
    size_bytes: int | None
    line_count: int | None

    def __post_init__(self) -> None:
        _require_text(self.name, "Homi snapshot file name")
        _require_text(self.state, "Homi snapshot file state")
        if self.content_sha256 is not None:
            _require_digest(self.content_sha256, "Homi snapshot file digest")
        for label, value in (
            ("size_bytes", self.size_bytes),
            ("line_count", self.line_count),
        ):
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ValueError(f"Homi snapshot file {label} is invalid")

    def sort_key(self) -> str:
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshotSignalSummary:
    """One capability or persona signal state."""

    signal_id: str
    state: str

    def __post_init__(self) -> None:
        _require_text(self.signal_id, "Homi snapshot signal_id")
        _require_text(self.state, "Homi snapshot signal state")

    def sort_key(self) -> str:
        return self.signal_id

    def to_dict(self) -> dict[str, object]:
        return {"signal_id": self.signal_id, "state": self.state}


@dataclass(frozen=True, slots=True)
class HomiSnapshotFindingSummary:
    """One combination Finding summary keyed by stable Finding ID."""

    finding_id: str
    rule_id: str
    severity: str
    score: float

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "Homi snapshot finding_id")
        _require_text(self.rule_id, "Homi snapshot rule_id")
        _require_text(self.severity, "Homi snapshot severity")
        if not isinstance(self.score, (int, float)) or not 0.0 <= self.score <= 10.0:
            raise ValueError("Homi snapshot finding score is out of range")

    def sort_key(self) -> str:
        return self.finding_id

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshot:
    """Deterministic, report-only snapshot of one Homi Pilot run."""

    format: Literal["agentsec-homi-snapshot"]
    format_version: str
    snapshot_digest: str
    workspace_fingerprint: str
    project_name: str
    adapter_version: str
    profile_model_version: str
    combination_rule_pack_version: str
    source_report_sha256: str
    files: tuple[HomiSnapshotFileSummary, ...]
    capabilities: tuple[HomiSnapshotSignalSummary, ...]
    persona_signals: tuple[HomiSnapshotSignalSummary, ...]
    findings: tuple[HomiSnapshotFindingSummary, ...]
    coverage_metrics: dict[str, object]
    pilot_id: str
    owner: str
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_SNAPSHOT_FORMAT:
            raise ValueError("Homi snapshot format is unsupported")
        if self.format_version != HOMI_SNAPSHOT_FORMAT_VERSION:
            raise ValueError("Homi snapshot version is unsupported")
        _require_digest(self.snapshot_digest, "Homi snapshot digest")
        _require_digest(
            self.workspace_fingerprint, "Homi snapshot workspace fingerprint"
        )
        _require_digest(self.source_report_sha256, "Homi snapshot source digest")
        for label, value in (
            ("project_name", self.project_name),
            ("adapter_version", self.adapter_version),
            ("profile_model_version", self.profile_model_version),
            ("combination_rule_pack_version", self.combination_rule_pack_version),
            ("pilot_id", self.pilot_id),
            ("owner", self.owner),
        ):
            _require_text(value, f"Homi snapshot {label}")
        _require_sorted_unique(self.files, "Homi snapshot files")
        _require_sorted_unique(self.capabilities, "Homi snapshot capabilities")
        _require_sorted_unique(self.persona_signals, "Homi snapshot persona signals")
        _require_sorted_unique(self.findings, "Homi snapshot findings")
        if not isinstance(self.coverage_metrics, dict):
            raise ValueError("Homi snapshot coverage metrics must be an object")
        if self.report_only is not True:
            raise ValueError("Homi snapshot must remain report-only")
        if self.runtime_verified is not False:
            raise ValueError("Homi snapshot cannot verify runtime")
        if self.ci_blocked is not False:
            raise ValueError("Homi snapshot cannot block CI")
        if _digest_of(self.canonical_payload()) != self.snapshot_digest:
            raise ValueError("Homi snapshot digest does not match its content")

    def canonical_payload(self) -> dict[str, object]:
        """Return the digest-covered content (session-bound fields excluded).

        ``source_report_sha256`` and ``pilot_id``/``owner`` stay out of the
        digest: they identify one Pilot session, not the workspace content,
        and the same workspace must always produce the same digest.
        """

        return {
            "format": self.format,
            "format_version": self.format_version,
            "workspace_fingerprint": self.workspace_fingerprint,
            "project_name": self.project_name,
            "adapter_version": self.adapter_version,
            "profile_model_version": self.profile_model_version,
            "combination_rule_pack_version": self.combination_rule_pack_version,
            "files": [item.to_dict() for item in self.files],
            "capabilities": [item.to_dict() for item in self.capabilities],
            "persona_signals": [item.to_dict() for item in self.persona_signals],
            "findings": [item.to_dict() for item in self.findings],
            "coverage_metrics": self.coverage_metrics,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            **self.canonical_payload(),
            "snapshot_digest": self.snapshot_digest,
            "source_report_sha256": self.source_report_sha256,
            "pilot_id": self.pilot_id,
            "owner": self.owner,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshotVerification:
    """Report-only comparison of a baseline Snapshot against current state."""

    format: Literal["agentsec-homi-snapshot-verification"]
    format_version: str
    status: HomiSnapshotStatus
    baseline_workspace_fingerprint: str
    current_workspace_fingerprint: str
    baseline_snapshot_digest: str
    current_snapshot_digest: str
    baseline_project_name: str
    current_project_name: str
    file_changes: tuple[str, ...] = ()
    capability_changes: tuple[str, ...] = ()
    findings_added: tuple[str, ...] = ()
    findings_removed: tuple[str, ...] = ()
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_SNAPSHOT_VERIFICATION_FORMAT:
            raise ValueError("Homi snapshot verification format is unsupported")
        if self.format_version != HOMI_SNAPSHOT_FORMAT_VERSION:
            raise ValueError("Homi snapshot verification version is unsupported")
        if not isinstance(self.status, HomiSnapshotStatus):
            raise ValueError("Homi snapshot verification status is invalid")
        for label, value in (
            ("baseline snapshot digest", self.baseline_snapshot_digest),
            ("current snapshot digest", self.current_snapshot_digest),
            (
                "baseline workspace fingerprint",
                self.baseline_workspace_fingerprint,
            ),
            ("current workspace fingerprint", self.current_workspace_fingerprint),
        ):
            _require_digest(value, f"Homi snapshot verification {label}")
        _require_text(
            self.baseline_project_name,
            "Homi snapshot verification baseline project name",
        )
        _require_text(
            self.current_project_name,
            "Homi snapshot verification current project name",
        )
        for label, values in (
            ("file changes", self.file_changes),
            ("capability changes", self.capability_changes),
            ("findings added", self.findings_added),
            ("findings removed", self.findings_removed),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(
                    f"Homi snapshot verification {label} must be sorted and unique"
                )
        if self.report_only is not True or self.runtime_verified is not False:
            raise ValueError("Homi snapshot verification authority is invalid")
        if self.ci_blocked is not False:
            raise ValueError("Homi snapshot verification cannot block CI")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "status": self.status.value,
            "baseline_workspace_fingerprint": self.baseline_workspace_fingerprint,
            "current_workspace_fingerprint": self.current_workspace_fingerprint,
            "baseline_snapshot_digest": self.baseline_snapshot_digest,
            "current_snapshot_digest": self.current_snapshot_digest,
            "baseline_project_name": self.baseline_project_name,
            "current_project_name": self.current_project_name,
            "file_changes": list(self.file_changes),
            "capability_changes": list(self.capability_changes),
            "findings_added": list(self.findings_added),
            "findings_removed": list(self.findings_removed),
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_snapshot(report: HomiPilotReport) -> HomiSnapshot:
    """Build a deterministic Snapshot from one Homi Pilot report."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi snapshot builder requires HomiPilotReport")
    files = _sorted_unique(
        (
            HomiSnapshotFileSummary(
                name=item.name,
                state=item.state.value,
                content_sha256=item.content_sha256,
                size_bytes=item.size_bytes,
                line_count=item.line_count,
            )
            for item in report.files
        ),
        "Homi snapshot files",
    )
    capabilities = _sorted_unique(
        (
            HomiSnapshotSignalSummary(signal_id=item.signal_id, state=item.state.value)
            for item in report.capabilities
        ),
        "Homi snapshot capabilities",
    )
    persona_signals = _sorted_unique(
        (
            HomiSnapshotSignalSummary(signal_id=item.signal_id, state=item.state.value)
            for item in report.persona_signals
        ),
        "Homi snapshot persona signals",
    )
    findings = _sorted_unique(
        (
            HomiSnapshotFindingSummary(
                finding_id=item.finding_id,
                rule_id=item.rule_id,
                severity=item.severity.value,
                score=item.score,
            )
            for item in report.combination_result.findings
        ),
        "Homi snapshot findings",
    )
    # The source hash binds the full Pilot report bytes (session metadata
    # included); it is cross-reference evidence and stays out of the digest.
    source = hashlib.sha256(encode_homi_pilot_json(report).encode("utf-8")).hexdigest()
    workspace_fingerprint = _workspace_fingerprint(files)
    canonical = _canonical_payload(
        HOMI_SNAPSHOT_FORMAT,
        HOMI_SNAPSHOT_FORMAT_VERSION,
        workspace_fingerprint,
        report.project_name,
        report.adapter_version,
        report.profile_model_version,
        report.combination_result.rule_pack_version,
        files,
        capabilities,
        persona_signals,
        findings,
        report.coverage_metrics,
    )
    return HomiSnapshot(
        format=HOMI_SNAPSHOT_FORMAT,
        format_version=HOMI_SNAPSHOT_FORMAT_VERSION,
        snapshot_digest=_digest_of(canonical),
        workspace_fingerprint=workspace_fingerprint,
        project_name=report.project_name,
        adapter_version=report.adapter_version,
        profile_model_version=report.profile_model_version,
        combination_rule_pack_version=report.combination_result.rule_pack_version,
        source_report_sha256=source,
        files=files,
        capabilities=capabilities,
        persona_signals=persona_signals,
        findings=findings,
        coverage_metrics=report.coverage_metrics,
        pilot_id=report.pilot_id,
        owner=report.owner,
    )


def verify_homi_snapshot(
    baseline: HomiSnapshot, current: HomiSnapshot
) -> HomiSnapshotVerification:
    """Compare a baseline Snapshot with the current Snapshot, report-only."""

    if not isinstance(baseline, HomiSnapshot):
        raise TypeError("Homi snapshot verification requires a baseline Snapshot")
    if not isinstance(current, HomiSnapshot):
        raise TypeError("Homi snapshot verification requires a current Snapshot")
    baseline_files = {item.name: item for item in baseline.files}
    current_files = {item.name: item for item in current.files}
    same_agent = baseline.project_name == current.project_name and set(
        baseline_files
    ) == set(current_files)
    if not same_agent:
        return HomiSnapshotVerification(
            format=HOMI_SNAPSHOT_VERIFICATION_FORMAT,
            format_version=HOMI_SNAPSHOT_FORMAT_VERSION,
            status=HomiSnapshotStatus.IDENTITY_MISMATCH,
            baseline_workspace_fingerprint=baseline.workspace_fingerprint,
            current_workspace_fingerprint=current.workspace_fingerprint,
            baseline_snapshot_digest=baseline.snapshot_digest,
            current_snapshot_digest=current.snapshot_digest,
            baseline_project_name=baseline.project_name,
            current_project_name=current.project_name,
        )
    file_changes = tuple(
        sorted(
            name
            for name in baseline_files
            if baseline_files[name] != current_files.get(name)
        )
    )
    baseline_signals = {item.signal_id: item for item in baseline.capabilities}
    current_signals = {item.signal_id: item for item in current.capabilities}
    capability_changes = tuple(
        sorted(
            signal_id
            for signal_id in set(baseline_signals) | set(current_signals)
            if baseline_signals.get(signal_id) != current_signals.get(signal_id)
        )
    )
    baseline_findings = {item.rule_id for item in baseline.findings}
    current_findings = {item.rule_id for item in current.findings}
    drifted = (
        bool(file_changes)
        or bool(capability_changes)
        or baseline_findings != current_findings
        or baseline.coverage_metrics != current.coverage_metrics
        or any(
            getattr(baseline, key) != getattr(current, key)
            for key in (
                "adapter_version",
                "profile_model_version",
                "combination_rule_pack_version",
            )
        )
    )
    return HomiSnapshotVerification(
        format=HOMI_SNAPSHOT_VERIFICATION_FORMAT,
        format_version=HOMI_SNAPSHOT_FORMAT_VERSION,
        status=HomiSnapshotStatus.DRIFTED if drifted else HomiSnapshotStatus.VERIFIED,
        baseline_workspace_fingerprint=baseline.workspace_fingerprint,
        current_workspace_fingerprint=current.workspace_fingerprint,
        baseline_snapshot_digest=baseline.snapshot_digest,
        current_snapshot_digest=current.snapshot_digest,
        baseline_project_name=baseline.project_name,
        current_project_name=current.project_name,
        file_changes=file_changes,
        capability_changes=capability_changes,
        findings_added=tuple(sorted(current_findings - baseline_findings)),
        findings_removed=tuple(sorted(baseline_findings - current_findings)),
    )


def encode_homi_snapshot_json(snapshot: HomiSnapshot) -> str:
    """Encode a deterministic Homi Snapshot as JSON."""

    if not isinstance(snapshot, HomiSnapshot):
        raise TypeError("Homi snapshot encoder requires HomiSnapshot")
    return (
        json.dumps(snapshot.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def encode_homi_snapshot_verification_json(
    verification: HomiSnapshotVerification,
) -> str:
    """Encode a deterministic Snapshot verification as JSON."""

    if not isinstance(verification, HomiSnapshotVerification):
        raise TypeError(
            "Homi snapshot verification encoder requires HomiSnapshotVerification"
        )
    return (
        json.dumps(verification.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def decode_homi_snapshot_json(text: str) -> HomiSnapshot:
    """Decode and fully revalidate one Snapshot artifact (fail-closed)."""

    if not isinstance(text, str):
        raise ValueError("Homi snapshot JSON must be text")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("Homi snapshot JSON is malformed") from error
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot JSON must be an object")
    if payload.get("format") != HOMI_SNAPSHOT_FORMAT:
        raise ValueError("Homi snapshot format is unsupported")
    try:
        files = _sorted_unique(
            (_decode_file(item) for item in payload["files"]),
            "Homi snapshot files",
        )
        capabilities = _sorted_unique(
            (_decode_signal(item) for item in payload["capabilities"]),
            "Homi snapshot capabilities",
        )
        persona_signals = _sorted_unique(
            (_decode_signal(item) for item in payload["persona_signals"]),
            "Homi snapshot persona signals",
        )
        findings = _sorted_unique(
            (_decode_finding(item) for item in payload["findings"]),
            "Homi snapshot findings",
        )
        coverage = payload["coverage_metrics"]
        if not isinstance(coverage, dict):
            raise ValueError("Homi snapshot coverage metrics must be an object")
        return HomiSnapshot(
            format=HOMI_SNAPSHOT_FORMAT,
            format_version=_text_field(payload, "format_version"),
            snapshot_digest=_text_field(payload, "snapshot_digest"),
            workspace_fingerprint=_text_field(payload, "workspace_fingerprint"),
            project_name=_text_field(payload, "project_name"),
            adapter_version=_text_field(payload, "adapter_version"),
            profile_model_version=_text_field(payload, "profile_model_version"),
            combination_rule_pack_version=_text_field(
                payload, "combination_rule_pack_version"
            ),
            source_report_sha256=_text_field(payload, "source_report_sha256"),
            files=files,
            capabilities=capabilities,
            persona_signals=persona_signals,
            findings=findings,
            coverage_metrics=coverage,
            pilot_id=_text_field(payload, "pilot_id"),
            owner=_text_field(payload, "owner"),
        )
    except KeyError as error:
        raise ValueError(
            f"Homi snapshot JSON is missing field: {error.args[0]}"
        ) from error


def export_homi_snapshot_json_schema(output_directory: Path) -> Path:
    """Export the strict JSON Schema for the Homi Snapshot contract."""

    if not isinstance(output_directory, Path):
        raise TypeError("Homi snapshot schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "homi-snapshot.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/risk/homi-snapshot.schema.json",
        "title": "AgentSec Homi Agent Snapshot",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "snapshot_digest",
            "workspace_fingerprint",
            "project_name",
            "adapter_version",
            "profile_model_version",
            "combination_rule_pack_version",
            "source_report_sha256",
            "files",
            "capabilities",
            "persona_signals",
            "findings",
            "coverage_metrics",
            "pilot_id",
            "owner",
            "report_only",
            "runtime_verified",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": HOMI_SNAPSHOT_FORMAT},
            "format_version": {
                "type": "string",
                "const": HOMI_SNAPSHOT_FORMAT_VERSION,
            },
            "snapshot_digest": _SCHEMA_SHA256,
            "workspace_fingerprint": _SCHEMA_SHA256,
            "source_report_sha256": _SCHEMA_SHA256,
            "project_name": {"type": "string", "minLength": 1},
            "adapter_version": {"type": "string", "minLength": 1},
            "profile_model_version": {"type": "string", "minLength": 1},
            "combination_rule_pack_version": {"type": "string", "minLength": 1},
            "files": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "name",
                        "state",
                        "content_sha256",
                        "size_bytes",
                        "line_count",
                    ],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "state": {"type": "string", "minLength": 1},
                        "content_sha256": {"anyOf": [_SCHEMA_SHA256, {"type": "null"}]},
                        "size_bytes": {
                            "anyOf": [
                                {"type": "integer", "minimum": 0},
                                {"type": "null"},
                            ]
                        },
                        "line_count": {
                            "anyOf": [
                                {"type": "integer", "minimum": 0},
                                {"type": "null"},
                            ]
                        },
                    },
                },
            },
            "capabilities": {"$ref": "#/$defs/signalSummaries"},
            "persona_signals": {"$ref": "#/$defs/signalSummaries"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["finding_id", "rule_id", "severity", "score"],
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "rule_id": {"type": "string", "minLength": 1},
                        "severity": {"type": "string", "minLength": 1},
                        "score": {"type": "number", "minimum": 0, "maximum": 10},
                    },
                },
            },
            "coverage_metrics": {"type": "object"},
            "pilot_id": {"type": "string", "minLength": 1},
            "owner": {"type": "string", "minLength": 1},
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "ci_blocked": {"const": False},
            "authority": _SCHEMA_AUTHORITY,
        },
        "$defs": {
            "signalSummaries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["signal_id", "state"],
                    "properties": {
                        "signal_id": {"type": "string", "minLength": 1},
                        "state": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


_SCHEMA_SHA256: dict[str, object] = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
}
_SCHEMA_AUTHORITY: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["report_only", "runtime_verified", "ci_blocked"],
    "properties": {
        "report_only": {"const": True},
        "runtime_verified": {"const": False},
        "ci_blocked": {"const": False},
    },
}


def _canonical_payload(
    snapshot_format: str,
    format_version: str,
    workspace_fingerprint: str,
    project_name: str,
    adapter_version: str,
    profile_model_version: str,
    combination_rule_pack_version: str,
    files: tuple[HomiSnapshotFileSummary, ...],
    capabilities: tuple[HomiSnapshotSignalSummary, ...],
    persona_signals: tuple[HomiSnapshotSignalSummary, ...],
    findings: tuple[HomiSnapshotFindingSummary, ...],
    coverage_metrics: dict[str, object],
) -> dict[str, object]:
    return {
        "format": snapshot_format,
        "format_version": format_version,
        "workspace_fingerprint": workspace_fingerprint,
        "project_name": project_name,
        "adapter_version": adapter_version,
        "profile_model_version": profile_model_version,
        "combination_rule_pack_version": combination_rule_pack_version,
        "files": [item.to_dict() for item in files],
        "capabilities": [item.to_dict() for item in capabilities],
        "persona_signals": [item.to_dict() for item in persona_signals],
        "findings": [item.to_dict() for item in findings],
        "coverage_metrics": coverage_metrics,
    }


def _digest_of(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _workspace_fingerprint(files: tuple[HomiSnapshotFileSummary, ...]) -> str:
    return _digest_of({"files": [item.to_dict() for item in files]})


def _decode_file(payload: object) -> HomiSnapshotFileSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot file entry must be an object")
    digest = payload.get("content_sha256")
    if digest is not None and not isinstance(digest, str):
        raise ValueError("Homi snapshot file digest is invalid")
    size = payload.get("size_bytes")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool)):
        raise ValueError("Homi snapshot file size is invalid")
    lines = payload.get("line_count")
    if lines is not None and (not isinstance(lines, int) or isinstance(lines, bool)):
        raise ValueError("Homi snapshot file line count is invalid")
    return HomiSnapshotFileSummary(
        name=_text_field(payload, "name"),
        state=_text_field(payload, "state"),
        content_sha256=digest,
        size_bytes=size,
        line_count=lines,
    )


def _decode_signal(payload: object) -> HomiSnapshotSignalSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot signal entry must be an object")
    return HomiSnapshotSignalSummary(
        signal_id=_text_field(payload, "signal_id"),
        state=_text_field(payload, "state"),
    )


def _decode_finding(payload: object) -> HomiSnapshotFindingSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot finding entry must be an object")
    score = payload.get("score")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise ValueError("Homi snapshot finding score is invalid")
    return HomiSnapshotFindingSummary(
        finding_id=_text_field(payload, "finding_id"),
        rule_id=_text_field(payload, "rule_id"),
        severity=_text_field(payload, "severity"),
        score=float(score),
    )


def _text_field(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Homi snapshot field {key} must be non-empty text")
    return value


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _require_sorted_unique[
    T: (HomiSnapshotFileSummary, HomiSnapshotSignalSummary, HomiSnapshotFindingSummary)
](items: tuple[T, ...], label: str) -> None:
    keys = tuple(item.sort_key() for item in items)
    if keys != tuple(sorted(set(keys))):
        raise ValueError(f"{label} must be sorted and unique")


def _sorted_unique[
    T: (HomiSnapshotFileSummary, HomiSnapshotSignalSummary, HomiSnapshotFindingSummary)
](items: Iterable[T], label: str) -> tuple[T, ...]:
    ordered = tuple(sorted(items, key=lambda item: item.sort_key()))
    _require_sorted_unique(ordered, label)
    return ordered


__all__ = [
    "HOMI_SNAPSHOT_BASIS",
    "HOMI_SNAPSHOT_FORMAT",
    "HOMI_SNAPSHOT_FORMAT_VERSION",
    "HOMI_SNAPSHOT_VERIFICATION_FORMAT",
    "HomiSnapshot",
    "HomiSnapshotFileSummary",
    "HomiSnapshotFindingSummary",
    "HomiSnapshotSignalSummary",
    "HomiSnapshotStatus",
    "HomiSnapshotVerification",
    "build_homi_snapshot",
    "decode_homi_snapshot_json",
    "encode_homi_snapshot_json",
    "encode_homi_snapshot_verification_json",
    "export_homi_snapshot_json_schema",
    "verify_homi_snapshot",
]

"""Homi Agent Snapshot contract (RISK-08A stable subject binding).

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
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.frameworks.homi_operation_context import HomiOperationContextReport
from agentsec.frameworks.homi_pilot import (
    HomiPilotReport,
    encode_homi_pilot_json,
)
from agentsec.risk.context import OperationContext, canonical_operation_context_sha256
from agentsec.risk.context_rules import (
    DeterministicContextRuleEngine,
    canonical_context_risk_sha256,
)
from agentsec.risk.context_score import DeterministicContextRiskScoreEngine
from agentsec.versioning import HOMI_SNAPSHOT_OUTPUT_VERSION

HOMI_SNAPSHOT_FORMAT: Literal["agentsec-homi-snapshot"] = "agentsec-homi-snapshot"
HOMI_SNAPSHOT_FORMAT_VERSION = HOMI_SNAPSHOT_OUTPUT_VERSION
HOMI_SNAPSHOT_VERIFICATION_FORMAT: Literal["agentsec-homi-snapshot-verification"] = (
    "agentsec-homi-snapshot-verification"
)
HOMI_SNAPSHOT_BASIS = (
    "AgentSec RISK-08B Homi Agent Snapshot context contract 0.3.0",
    "A Snapshot is static report-only evidence, not runtime verification",
    "An explicit platform subject_id owns Agent identity binding",
    "Project name is display metadata and never determines Agent identity",
    (
        "The snapshot digest excludes session/display metadata "
        "(pilot_id/owner/project_name)"
    ),
    "The snapshot digest excludes the session-bound source report digest",
    "The workspace fingerprint is derived only from standard file digests",
    "RISK-03/04/05 summaries and their canonical digests are Snapshot-bound",
    "Context summaries contain enums and IDs, never raw source or secret values",
    "Comparing snapshots across different agents is rejected, not drifted",
)
_HEX = frozenset("0123456789abcdef")
_SUBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


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
class HomiSnapshotObservationSummary:
    """One policy observation summary (control layer)."""

    code: str
    kind: str
    roles: tuple[str, ...]
    source_paths: tuple[str, ...]
    resolution: str

    def __post_init__(self) -> None:
        _require_text(self.code, "Homi snapshot observation code")
        _require_text(self.kind, "Homi snapshot observation kind")
        _require_text(self.resolution, "Homi snapshot observation resolution")
        for label, values in (
            ("roles", self.roles),
            ("source paths", self.source_paths),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(
                    f"Homi snapshot observation {label} must be sorted and unique"
                )

    def sort_key(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.code, self.kind, self.source_paths)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "kind": self.kind,
            "roles": list(self.roles),
            "source_paths": list(self.source_paths),
            "resolution": self.resolution,
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshotOperationContextSummary:
    """Value-minimized RISK-03 operation summary."""

    operation_id: str
    action: str
    target: str
    data_classification: str
    data_sharing: str
    data_retention: str
    trigger: str
    purpose: str
    authorization_state: str
    reversibility: str
    scope: str
    frequency: str
    status: str
    controls_present: tuple[str, ...]
    controls_absent: tuple[str, ...]
    controls_unknown: tuple[str, ...]
    controls_not_applicable: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("operation_id", self.operation_id),
            ("action", self.action),
            ("target", self.target),
            ("data_classification", self.data_classification),
            ("data_sharing", self.data_sharing),
            ("data_retention", self.data_retention),
            ("trigger", self.trigger),
            ("purpose", self.purpose),
            ("authorization_state", self.authorization_state),
            ("reversibility", self.reversibility),
            ("scope", self.scope),
            ("frequency", self.frequency),
            ("status", self.status),
        ):
            _require_text(value, f"Homi snapshot context {label}")
        groups = (
            self.controls_present,
            self.controls_absent,
            self.controls_unknown,
            self.controls_not_applicable,
        )
        for values in groups:
            _require_string_tuple(values, "Homi snapshot context controls")
        flattened = tuple(item for values in groups for item in values)
        if len(flattened) != len(set(flattened)):
            raise ValueError("Homi snapshot context controls overlap")
        _require_string_tuple(self.evidence_ids, "Homi snapshot context Evidence IDs")

    def sort_key(self) -> str:
        return self.operation_id

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "action": self.action,
            "target": self.target,
            "data_classification": self.data_classification,
            "data_sharing": self.data_sharing,
            "data_retention": self.data_retention,
            "trigger": self.trigger,
            "purpose": self.purpose,
            "authorization_state": self.authorization_state,
            "reversibility": self.reversibility,
            "scope": self.scope,
            "frequency": self.frequency,
            "status": self.status,
            "controls_present": list(self.controls_present),
            "controls_absent": list(self.controls_absent),
            "controls_unknown": list(self.controls_unknown),
            "controls_not_applicable": list(self.controls_not_applicable),
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshotContextFindingSummary:
    """Value-minimized RISK-04 Finding summary."""

    finding_id: str
    rule_id: str
    kind: str
    category: str
    likelihood: str
    impact: str
    severity: str
    confidence: str
    context_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale_code: str

    def __post_init__(self) -> None:
        for label, value in (
            ("finding_id", self.finding_id),
            ("rule_id", self.rule_id),
            ("kind", self.kind),
            ("category", self.category),
            ("likelihood", self.likelihood),
            ("impact", self.impact),
            ("severity", self.severity),
            ("confidence", self.confidence),
            ("rationale_code", self.rationale_code),
        ):
            _require_text(value, f"Homi snapshot context Finding {label}")
        _require_string_tuple(
            self.context_ids, "Homi snapshot context Finding context IDs"
        )
        _require_string_tuple(
            self.evidence_ids, "Homi snapshot context Finding Evidence IDs"
        )

    def sort_key(self) -> str:
        return self.finding_id

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "kind": self.kind,
            "category": self.category,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "severity": self.severity,
            "confidence": self.confidence,
            "context_ids": list(self.context_ids),
            "evidence_ids": list(self.evidence_ids),
            "rationale_code": self.rationale_code,
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshotContextScoreSummary:
    """Value-minimized RISK-05 score summary without runtime authority."""

    model_version: str
    coverage_complete: bool
    unknown_dimensions: tuple[str, ...]
    potential_impact_score: float
    potential_impact_level: str
    residual_risk_score: float
    residual_risk_level: str
    current_posture: str
    current_posture_score: float | None
    contribution_count: int

    def __post_init__(self) -> None:
        for label, value in (
            ("model_version", self.model_version),
            ("potential_impact_level", self.potential_impact_level),
            ("residual_risk_level", self.residual_risk_level),
            ("current_posture", self.current_posture),
        ):
            _require_text(value, f"Homi snapshot context score {label}")
        if not isinstance(self.coverage_complete, bool):
            raise TypeError("Homi snapshot context score coverage flag is invalid")
        _require_string_tuple(
            self.unknown_dimensions,
            "Homi snapshot context score Unknown dimensions",
        )
        _require_score(
            self.potential_impact_score,
            "Homi snapshot context score potential impact",
        )
        _require_score(
            self.residual_risk_score,
            "Homi snapshot context score residual risk",
        )
        if self.residual_risk_score > self.potential_impact_score:
            raise ValueError("Homi snapshot residual risk exceeds potential impact")
        if self.current_posture_score is not None:
            _require_score(
                self.current_posture_score,
                "Homi snapshot current posture score",
            )
        if (
            not isinstance(self.contribution_count, int)
            or isinstance(self.contribution_count, bool)
            or self.contribution_count < 0
        ):
            raise ValueError("Homi snapshot context contribution count is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "model_version": self.model_version,
            "coverage_complete": self.coverage_complete,
            "unknown_dimensions": list(self.unknown_dimensions),
            "potential_impact_score": self.potential_impact_score,
            "potential_impact_level": self.potential_impact_level,
            "residual_risk_score": self.residual_risk_score,
            "residual_risk_level": self.residual_risk_level,
            "current_posture": self.current_posture,
            "current_posture_score": self.current_posture_score,
            "contribution_count": self.contribution_count,
        }


@dataclass(frozen=True, slots=True)
class HomiSnapshot:
    """Deterministic, report-only snapshot of one Homi Pilot run."""

    format: Literal["agentsec-homi-snapshot"]
    format_version: str
    snapshot_digest: str
    workspace_fingerprint: str
    subject_id: str
    project_name: str
    adapter_version: str
    profile_model_version: str
    combination_rule_pack_version: str
    source_report_sha256: str
    files: tuple[HomiSnapshotFileSummary, ...]
    capabilities: tuple[HomiSnapshotSignalSummary, ...]
    persona_signals: tuple[HomiSnapshotSignalSummary, ...]
    findings: tuple[HomiSnapshotFindingSummary, ...]
    observations: tuple[HomiSnapshotObservationSummary, ...]
    operation_context_sha256: str
    context_risk_report_sha256: str
    context_score_report_sha256: str
    operation_contexts: tuple[HomiSnapshotOperationContextSummary, ...]
    context_findings: tuple[HomiSnapshotContextFindingSummary, ...]
    context_score: HomiSnapshotContextScoreSummary
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
        _require_digest(
            self.operation_context_sha256,
            "Homi snapshot Operation Context digest",
        )
        _require_digest(
            self.context_risk_report_sha256,
            "Homi snapshot Context Risk digest",
        )
        _require_digest(
            self.context_score_report_sha256,
            "Homi snapshot Context Score digest",
        )
        _require_subject_id(self.subject_id)
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
        _require_sorted_unique(self.observations, "Homi snapshot observations")
        _require_sorted_unique(
            self.operation_contexts,
            "Homi snapshot Operation Contexts",
        )
        _require_sorted_unique(
            self.context_findings,
            "Homi snapshot Context Findings",
        )
        if not self.operation_contexts:
            raise ValueError("Homi snapshot requires Operation Context summaries")
        if not isinstance(self.context_score, HomiSnapshotContextScoreSummary):
            raise TypeError("Homi snapshot Context Score summary is invalid")
        operation_ids = {item.operation_id for item in self.operation_contexts}
        if any(
            not set(item.context_ids).issubset(operation_ids)
            for item in self.context_findings
        ):
            raise ValueError(
                "Homi snapshot Context Finding references unknown operation"
            )
        risk_finding_count = sum(item.kind == "risk" for item in self.context_findings)
        if self.context_score.contribution_count != risk_finding_count:
            raise ValueError(
                "Homi snapshot Context Score contribution count is invalid"
            )
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

        ``source_report_sha256``, ``pilot_id``/``owner``, and ``project_name``
        stay out of the digest. ``subject_id`` is the stable identity binding;
        project name is mutable display metadata.
        """

        return {
            "format": self.format,
            "format_version": self.format_version,
            "workspace_fingerprint": self.workspace_fingerprint,
            "subject_id": self.subject_id,
            "adapter_version": self.adapter_version,
            "profile_model_version": self.profile_model_version,
            "combination_rule_pack_version": self.combination_rule_pack_version,
            "files": [item.to_dict() for item in self.files],
            "capabilities": [item.to_dict() for item in self.capabilities],
            "persona_signals": [item.to_dict() for item in self.persona_signals],
            "findings": [item.to_dict() for item in self.findings],
            "observations": [item.to_dict() for item in self.observations],
            "operation_context_sha256": self.operation_context_sha256,
            "context_risk_report_sha256": self.context_risk_report_sha256,
            "context_score_report_sha256": self.context_score_report_sha256,
            "operation_contexts": [item.to_dict() for item in self.operation_contexts],
            "context_findings": [item.to_dict() for item in self.context_findings],
            "context_score": self.context_score.to_dict(),
            "coverage_metrics": self.coverage_metrics,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            **self.canonical_payload(),
            "snapshot_digest": self.snapshot_digest,
            "project_name": self.project_name,
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
    baseline_subject_id: str
    current_subject_id: str
    baseline_project_name: str
    current_project_name: str
    file_changes: tuple[str, ...] = ()
    capability_changes: tuple[str, ...] = ()
    findings_added: tuple[str, ...] = ()
    findings_removed: tuple[str, ...] = ()
    operation_context_changes: tuple[str, ...] = ()
    context_findings_added: tuple[str, ...] = ()
    context_findings_removed: tuple[str, ...] = ()
    context_score_changed: bool = False
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
        _require_subject_id(self.baseline_subject_id)
        _require_subject_id(self.current_subject_id)
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
            ("Operation Context changes", self.operation_context_changes),
            ("Context Findings added", self.context_findings_added),
            ("Context Findings removed", self.context_findings_removed),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(
                    f"Homi snapshot verification {label} must be sorted and unique"
                )
        if not isinstance(self.context_score_changed, bool):
            raise TypeError("Homi snapshot Context Score change flag is invalid")
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
            "baseline_subject_id": self.baseline_subject_id,
            "current_subject_id": self.current_subject_id,
            "baseline_project_name": self.baseline_project_name,
            "current_project_name": self.current_project_name,
            "file_changes": list(self.file_changes),
            "capability_changes": list(self.capability_changes),
            "findings_added": list(self.findings_added),
            "findings_removed": list(self.findings_removed),
            "operation_context_changes": list(self.operation_context_changes),
            "context_findings_added": list(self.context_findings_added),
            "context_findings_removed": list(self.context_findings_removed),
            "context_score_changed": self.context_score_changed,
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "runtime_verified": self.runtime_verified,
                "ci_blocked": self.ci_blocked,
            },
        }


def build_homi_snapshot(
    report: HomiPilotReport,
    *,
    subject_id: str,
    operation_context: HomiOperationContextReport,
) -> HomiSnapshot:
    """Build a deterministic Snapshot from one Homi Pilot report."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi snapshot builder requires HomiPilotReport")
    _require_subject_id(subject_id)
    if not isinstance(operation_context, HomiOperationContextReport):
        raise TypeError("Homi snapshot builder requires HomiOperationContextReport")
    source = hashlib.sha256(encode_homi_pilot_json(report).encode("utf-8")).hexdigest()
    if operation_context.source_report_sha256 != source:
        raise ValueError("Homi Snapshot Operation Context is not bound to Pilot report")
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
    observations = _sorted_unique(
        (
            HomiSnapshotObservationSummary(
                code=item.code.value,
                kind=item.kind.value,
                roles=item.roles,
                source_paths=item.source_paths,
                resolution=item.resolution,
            )
            for item in report.observations
        ),
        "Homi snapshot observations",
    )
    context_risk_report = DeterministicContextRuleEngine().run(
        operation_context.context_set
    )
    context_score_report = DeterministicContextRiskScoreEngine().run(
        operation_context.context_set,
        context_risk_report,
    )
    operation_contexts = _sorted_unique(
        (
            _operation_context_summary(item)
            for item in operation_context.context_set.contexts
        ),
        "Homi snapshot Operation Contexts",
    )
    context_findings = _sorted_unique(
        (
            HomiSnapshotContextFindingSummary(
                finding_id=item.finding_id,
                rule_id=item.rule_id,
                kind=item.kind.value,
                category=item.category.value,
                likelihood=item.likelihood.value,
                impact=item.impact.value,
                severity=item.severity.value,
                confidence=item.confidence.value,
                context_ids=item.context_ids,
                evidence_ids=item.evidence_ids,
                rationale_code=item.rationale_code,
            )
            for item in context_risk_report.findings
        ),
        "Homi snapshot Context Findings",
    )
    context_score = HomiSnapshotContextScoreSummary(
        model_version=context_score_report.model_version,
        coverage_complete=context_score_report.coverage_complete,
        unknown_dimensions=context_score_report.unknown_dimensions,
        potential_impact_score=context_score_report.potential_impact_score,
        potential_impact_level=context_score_report.potential_impact_level.value,
        residual_risk_score=context_score_report.residual_risk_score,
        residual_risk_level=context_score_report.residual_risk_level.value,
        current_posture=context_score_report.current_posture.value,
        current_posture_score=context_score_report.current_posture_score,
        contribution_count=len(context_score_report.contributions),
    )
    # The source hash binds the full Pilot report bytes (session metadata
    # included); it is cross-reference evidence and stays out of the digest.
    workspace_fingerprint = _workspace_fingerprint(files)
    canonical = _canonical_payload(
        HOMI_SNAPSHOT_FORMAT,
        HOMI_SNAPSHOT_FORMAT_VERSION,
        workspace_fingerprint,
        subject_id,
        report.adapter_version,
        report.profile_model_version,
        report.combination_result.rule_pack_version,
        files,
        capabilities,
        persona_signals,
        findings,
        observations,
        canonical_operation_context_sha256(operation_context.context_set),
        canonical_context_risk_sha256(context_risk_report),
        _digest_of(context_score_report.to_dict()),
        operation_contexts,
        context_findings,
        context_score,
        report.coverage_metrics,
    )
    return HomiSnapshot(
        format=HOMI_SNAPSHOT_FORMAT,
        format_version=HOMI_SNAPSHOT_FORMAT_VERSION,
        snapshot_digest=_digest_of(canonical),
        workspace_fingerprint=workspace_fingerprint,
        subject_id=subject_id,
        project_name=report.project_name,
        adapter_version=report.adapter_version,
        profile_model_version=report.profile_model_version,
        combination_rule_pack_version=report.combination_result.rule_pack_version,
        source_report_sha256=source,
        files=files,
        capabilities=capabilities,
        persona_signals=persona_signals,
        findings=findings,
        observations=observations,
        operation_context_sha256=canonical_operation_context_sha256(
            operation_context.context_set
        ),
        context_risk_report_sha256=canonical_context_risk_sha256(context_risk_report),
        context_score_report_sha256=_digest_of(context_score_report.to_dict()),
        operation_contexts=operation_contexts,
        context_findings=context_findings,
        context_score=context_score,
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
    same_agent = baseline.subject_id == current.subject_id
    if not same_agent:
        return HomiSnapshotVerification(
            format=HOMI_SNAPSHOT_VERIFICATION_FORMAT,
            format_version=HOMI_SNAPSHOT_FORMAT_VERSION,
            status=HomiSnapshotStatus.IDENTITY_MISMATCH,
            baseline_workspace_fingerprint=baseline.workspace_fingerprint,
            current_workspace_fingerprint=current.workspace_fingerprint,
            baseline_snapshot_digest=baseline.snapshot_digest,
            current_snapshot_digest=current.snapshot_digest,
            baseline_subject_id=baseline.subject_id,
            current_subject_id=current.subject_id,
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
    baseline_contexts = {
        item.operation_id: item for item in baseline.operation_contexts
    }
    current_contexts = {item.operation_id: item for item in current.operation_contexts}
    operation_context_changes = tuple(
        sorted(
            operation_id
            for operation_id in set(baseline_contexts) | set(current_contexts)
            if baseline_contexts.get(operation_id) != current_contexts.get(operation_id)
        )
    )
    baseline_context_findings = {item.finding_id for item in baseline.context_findings}
    current_context_findings = {item.finding_id for item in current.context_findings}
    context_score_changed = baseline.context_score != current.context_score
    drifted = (
        bool(file_changes)
        or bool(capability_changes)
        or baseline_findings != current_findings
        or bool(operation_context_changes)
        or baseline_context_findings != current_context_findings
        or context_score_changed
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
        baseline_subject_id=baseline.subject_id,
        current_subject_id=current.subject_id,
        baseline_project_name=baseline.project_name,
        current_project_name=current.project_name,
        file_changes=file_changes,
        capability_changes=capability_changes,
        findings_added=tuple(sorted(current_findings - baseline_findings)),
        findings_removed=tuple(sorted(baseline_findings - current_findings)),
        operation_context_changes=operation_context_changes,
        context_findings_added=tuple(
            sorted(current_context_findings - baseline_context_findings)
        ),
        context_findings_removed=tuple(
            sorted(baseline_context_findings - current_context_findings)
        ),
        context_score_changed=context_score_changed,
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
        observations = _sorted_unique(
            (_decode_observation(item) for item in payload["observations"]),
            "Homi snapshot observations",
        )
        operation_contexts = _sorted_unique(
            (
                _decode_operation_context_summary(item)
                for item in payload["operation_contexts"]
            ),
            "Homi snapshot Operation Contexts",
        )
        context_findings = _sorted_unique(
            (
                _decode_context_finding_summary(item)
                for item in payload["context_findings"]
            ),
            "Homi snapshot Context Findings",
        )
        context_score = _decode_context_score_summary(payload["context_score"])
        coverage = payload["coverage_metrics"]
        if not isinstance(coverage, dict):
            raise ValueError("Homi snapshot coverage metrics must be an object")
        return HomiSnapshot(
            format=HOMI_SNAPSHOT_FORMAT,
            format_version=_text_field(payload, "format_version"),
            snapshot_digest=_text_field(payload, "snapshot_digest"),
            workspace_fingerprint=_text_field(payload, "workspace_fingerprint"),
            subject_id=_text_field(payload, "subject_id"),
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
            observations=observations,
            operation_context_sha256=_text_field(payload, "operation_context_sha256"),
            context_risk_report_sha256=_text_field(
                payload, "context_risk_report_sha256"
            ),
            context_score_report_sha256=_text_field(
                payload, "context_score_report_sha256"
            ),
            operation_contexts=operation_contexts,
            context_findings=context_findings,
            context_score=context_score,
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
            "subject_id",
            "project_name",
            "adapter_version",
            "profile_model_version",
            "combination_rule_pack_version",
            "source_report_sha256",
            "files",
            "capabilities",
            "persona_signals",
            "findings",
            "observations",
            "operation_context_sha256",
            "context_risk_report_sha256",
            "context_score_report_sha256",
            "operation_contexts",
            "context_findings",
            "context_score",
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
            "subject_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
            },
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
            "observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "kind", "roles", "source_paths", "resolution"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "kind": {"type": "string", "minLength": 1},
                        "roles": {"type": "array", "items": {"type": "string"}},
                        "source_paths": {"type": "array", "items": {"type": "string"}},
                        "resolution": {"type": "string", "minLength": 1},
                    },
                },
            },
            "operation_context_sha256": _SCHEMA_SHA256,
            "context_risk_report_sha256": _SCHEMA_SHA256,
            "context_score_report_sha256": _SCHEMA_SHA256,
            "operation_contexts": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "#/$defs/operationContextSummary"},
            },
            "context_findings": {
                "type": "array",
                "items": {"$ref": "#/$defs/contextFindingSummary"},
            },
            "context_score": {"$ref": "#/$defs/contextScoreSummary"},
            "coverage_metrics": {"type": "object"},
            "pilot_id": {"type": "string", "minLength": 1},
            "owner": {"type": "string", "minLength": 1},
            "report_only": {"const": True},
            "runtime_verified": {"const": False},
            "ci_blocked": {"const": False},
            "authority": _SCHEMA_AUTHORITY,
        },
        "$defs": {
            "operationContextSummary": {
                "type": "object",
                "additionalProperties": False,
                "required": list(
                    HomiSnapshotOperationContextSummary.__dataclass_fields__
                ),
                "properties": {
                    "operation_id": {"type": "string", "minLength": 1},
                    "action": {"type": "string", "minLength": 1},
                    "target": {"type": "string", "minLength": 1},
                    "data_classification": {"type": "string", "minLength": 1},
                    "data_sharing": {"type": "string", "minLength": 1},
                    "data_retention": {"type": "string", "minLength": 1},
                    "trigger": {"type": "string", "minLength": 1},
                    "purpose": {"type": "string", "minLength": 1},
                    "authorization_state": {"type": "string", "minLength": 1},
                    "reversibility": {"type": "string", "minLength": 1},
                    "scope": {"type": "string", "minLength": 1},
                    "frequency": {"type": "string", "minLength": 1},
                    "status": {"type": "string", "minLength": 1},
                    "controls_present": _SCHEMA_STRING_ARRAY,
                    "controls_absent": _SCHEMA_STRING_ARRAY,
                    "controls_unknown": _SCHEMA_STRING_ARRAY,
                    "controls_not_applicable": _SCHEMA_STRING_ARRAY,
                    "evidence_ids": _SCHEMA_STRING_ARRAY,
                },
            },
            "contextFindingSummary": {
                "type": "object",
                "additionalProperties": False,
                "required": list(
                    HomiSnapshotContextFindingSummary.__dataclass_fields__
                ),
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1},
                    "rule_id": {"type": "string", "minLength": 1},
                    "kind": {"type": "string", "enum": ["risk", "coverage"]},
                    "category": {"type": "string", "minLength": 1},
                    "likelihood": {"type": "string", "minLength": 1},
                    "impact": {"type": "string", "minLength": 1},
                    "severity": {"type": "string", "minLength": 1},
                    "confidence": {
                        "type": "string",
                        "enum": ["A", "B", "C", "D"],
                    },
                    "context_ids": _SCHEMA_STRING_ARRAY,
                    "evidence_ids": _SCHEMA_STRING_ARRAY,
                    "rationale_code": {"type": "string", "minLength": 1},
                },
            },
            "contextScoreSummary": {
                "type": "object",
                "additionalProperties": False,
                "required": list(HomiSnapshotContextScoreSummary.__dataclass_fields__),
                "properties": {
                    "model_version": {"type": "string", "minLength": 1},
                    "coverage_complete": {"type": "boolean"},
                    "unknown_dimensions": _SCHEMA_STRING_ARRAY,
                    "potential_impact_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 10,
                    },
                    "potential_impact_level": {"type": "string", "minLength": 1},
                    "residual_risk_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 10,
                    },
                    "residual_risk_level": {"type": "string", "minLength": 1},
                    "current_posture": {"type": "string", "minLength": 1},
                    "current_posture_score": {
                        "anyOf": [
                            {"type": "number", "minimum": 0, "maximum": 10},
                            {"type": "null"},
                        ]
                    },
                    "contribution_count": {"type": "integer", "minimum": 0},
                },
            },
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
_SCHEMA_STRING_ARRAY: dict[str, object] = {
    "type": "array",
    "items": {"type": "string", "minLength": 1},
    "uniqueItems": True,
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
    subject_id: str,
    adapter_version: str,
    profile_model_version: str,
    combination_rule_pack_version: str,
    files: tuple[HomiSnapshotFileSummary, ...],
    capabilities: tuple[HomiSnapshotSignalSummary, ...],
    persona_signals: tuple[HomiSnapshotSignalSummary, ...],
    findings: tuple[HomiSnapshotFindingSummary, ...],
    observations: tuple[HomiSnapshotObservationSummary, ...],
    operation_context_sha256: str,
    context_risk_report_sha256: str,
    context_score_report_sha256: str,
    operation_contexts: tuple[HomiSnapshotOperationContextSummary, ...],
    context_findings: tuple[HomiSnapshotContextFindingSummary, ...],
    context_score: HomiSnapshotContextScoreSummary,
    coverage_metrics: dict[str, object],
) -> dict[str, object]:
    return {
        "format": snapshot_format,
        "format_version": format_version,
        "workspace_fingerprint": workspace_fingerprint,
        "subject_id": subject_id,
        "adapter_version": adapter_version,
        "profile_model_version": profile_model_version,
        "combination_rule_pack_version": combination_rule_pack_version,
        "files": [item.to_dict() for item in files],
        "capabilities": [item.to_dict() for item in capabilities],
        "persona_signals": [item.to_dict() for item in persona_signals],
        "findings": [item.to_dict() for item in findings],
        "observations": [item.to_dict() for item in observations],
        "operation_context_sha256": operation_context_sha256,
        "context_risk_report_sha256": context_risk_report_sha256,
        "context_score_report_sha256": context_score_report_sha256,
        "operation_contexts": [item.to_dict() for item in operation_contexts],
        "context_findings": [item.to_dict() for item in context_findings],
        "context_score": context_score.to_dict(),
        "coverage_metrics": coverage_metrics,
    }


def _operation_context_summary(
    context: OperationContext,
) -> HomiSnapshotOperationContextSummary:
    controls = context.controls.model_dump(mode="json")

    def names_for(state: str) -> tuple[str, ...]:
        return tuple(sorted(name for name, value in controls.items() if value == state))

    return HomiSnapshotOperationContextSummary(
        operation_id=context.operation_id,
        action=context.action.value,
        target=context.target.value,
        data_classification=context.data_scope.classification.value,
        data_sharing=context.data_scope.sharing.value,
        data_retention=context.data_scope.retention.value,
        trigger=context.trigger.value,
        purpose=context.purpose.value,
        authorization_state=context.authorization.state.value,
        reversibility=context.reversibility.value,
        scope=context.scope.value,
        frequency=context.frequency.value,
        status=context.status.value,
        controls_present=names_for("present"),
        controls_absent=names_for("absent"),
        controls_unknown=names_for("unknown"),
        controls_not_applicable=names_for("not_applicable"),
        evidence_ids=tuple(sorted(item.evidence_id for item in context.evidence)),
    )


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


def _decode_observation(payload: object) -> HomiSnapshotObservationSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot observation entry must be an object")

    def _string_tuple(value: object) -> tuple[str, ...]:
        if not isinstance(value, list) or any(
            not isinstance(item, str) for item in value
        ):
            raise ValueError("Homi snapshot observation list is invalid")
        return tuple(value)

    return HomiSnapshotObservationSummary(
        code=_text_field(payload, "code"),
        kind=_text_field(payload, "kind"),
        roles=_string_tuple(payload.get("roles", [])),
        source_paths=_string_tuple(payload.get("source_paths", [])),
        resolution=_text_field(payload, "resolution"),
    )


def _decode_operation_context_summary(
    payload: object,
) -> HomiSnapshotOperationContextSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot Operation Context entry must be an object")
    return HomiSnapshotOperationContextSummary(
        operation_id=_text_field(payload, "operation_id"),
        action=_text_field(payload, "action"),
        target=_text_field(payload, "target"),
        data_classification=_text_field(payload, "data_classification"),
        data_sharing=_text_field(payload, "data_sharing"),
        data_retention=_text_field(payload, "data_retention"),
        trigger=_text_field(payload, "trigger"),
        purpose=_text_field(payload, "purpose"),
        authorization_state=_text_field(payload, "authorization_state"),
        reversibility=_text_field(payload, "reversibility"),
        scope=_text_field(payload, "scope"),
        frequency=_text_field(payload, "frequency"),
        status=_text_field(payload, "status"),
        controls_present=_text_tuple_field(payload, "controls_present"),
        controls_absent=_text_tuple_field(payload, "controls_absent"),
        controls_unknown=_text_tuple_field(payload, "controls_unknown"),
        controls_not_applicable=_text_tuple_field(payload, "controls_not_applicable"),
        evidence_ids=_text_tuple_field(payload, "evidence_ids"),
    )


def _decode_context_finding_summary(
    payload: object,
) -> HomiSnapshotContextFindingSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot Context Finding entry must be an object")
    return HomiSnapshotContextFindingSummary(
        finding_id=_text_field(payload, "finding_id"),
        rule_id=_text_field(payload, "rule_id"),
        kind=_text_field(payload, "kind"),
        category=_text_field(payload, "category"),
        likelihood=_text_field(payload, "likelihood"),
        impact=_text_field(payload, "impact"),
        severity=_text_field(payload, "severity"),
        confidence=_text_field(payload, "confidence"),
        context_ids=_text_tuple_field(payload, "context_ids"),
        evidence_ids=_text_tuple_field(payload, "evidence_ids"),
        rationale_code=_text_field(payload, "rationale_code"),
    )


def _decode_context_score_summary(
    payload: object,
) -> HomiSnapshotContextScoreSummary:
    if not isinstance(payload, dict):
        raise ValueError("Homi snapshot Context Score must be an object")
    potential = payload.get("potential_impact_score")
    residual = payload.get("residual_risk_score")
    posture_score = payload.get("current_posture_score")
    contribution_count = payload.get("contribution_count")
    coverage_complete = payload.get("coverage_complete")
    if not isinstance(potential, (int, float)) or isinstance(potential, bool):
        raise ValueError("Homi snapshot potential impact score is invalid")
    if not isinstance(residual, (int, float)) or isinstance(residual, bool):
        raise ValueError("Homi snapshot residual risk score is invalid")
    if posture_score is not None and (
        not isinstance(posture_score, (int, float)) or isinstance(posture_score, bool)
    ):
        raise ValueError("Homi snapshot current posture score is invalid")
    if not isinstance(contribution_count, int) or isinstance(contribution_count, bool):
        raise ValueError("Homi snapshot contribution count is invalid")
    if not isinstance(coverage_complete, bool):
        raise ValueError("Homi snapshot Context Score coverage is invalid")
    return HomiSnapshotContextScoreSummary(
        model_version=_text_field(payload, "model_version"),
        coverage_complete=coverage_complete,
        unknown_dimensions=_text_tuple_field(payload, "unknown_dimensions"),
        potential_impact_score=float(potential),
        potential_impact_level=_text_field(payload, "potential_impact_level"),
        residual_risk_score=float(residual),
        residual_risk_level=_text_field(payload, "residual_risk_level"),
        current_posture=_text_field(payload, "current_posture"),
        current_posture_score=(None if posture_score is None else float(posture_score)),
        contribution_count=contribution_count,
    )


def _text_tuple_field(payload: dict[str, object], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Homi snapshot field {key} must be a text array")
    return tuple(value)


def _text_field(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Homi snapshot field {key} must be non-empty text")
    return value


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_score(value: float, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0.0 <= value <= 10.0
    ):
        raise ValueError(f"{label} is out of range")


def _require_string_tuple(values: tuple[str, ...], label: str) -> None:
    if values != tuple(sorted(set(values))) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise ValueError(f"{label} must be sorted, unique, non-empty text")


def _require_subject_id(value: str) -> None:
    if not isinstance(value, str) or _SUBJECT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "Homi snapshot subject_id must be an explicit stable opaque identifier"
        )


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _require_sorted_unique[
    T: (
        HomiSnapshotFileSummary,
        HomiSnapshotSignalSummary,
        HomiSnapshotFindingSummary,
        HomiSnapshotObservationSummary,
        HomiSnapshotOperationContextSummary,
        HomiSnapshotContextFindingSummary,
    )
](items: tuple[T, ...], label: str) -> None:
    keys = tuple(item.sort_key() for item in items)
    if keys != tuple(sorted(set(keys))):
        raise ValueError(f"{label} must be sorted and unique")


def _sorted_unique[
    T: (
        HomiSnapshotFileSummary,
        HomiSnapshotSignalSummary,
        HomiSnapshotFindingSummary,
        HomiSnapshotObservationSummary,
        HomiSnapshotOperationContextSummary,
        HomiSnapshotContextFindingSummary,
    )
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
    "HomiSnapshotContextFindingSummary",
    "HomiSnapshotContextScoreSummary",
    "HomiSnapshotFindingSummary",
    "HomiSnapshotObservationSummary",
    "HomiSnapshotOperationContextSummary",
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

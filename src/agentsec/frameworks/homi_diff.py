"""Deterministic diffing for Homi Pilot JSON reports.

This module compares two value-minimized Homi Pilot reports. It never reads or
replays raw source content; only capability states, bounded source paths, and
Finding metadata already emitted by the Homi report contract are used.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from html import escape
from pathlib import Path
from typing import Any, Literal

HOMI_CAPABILITY_DIFF_FORMAT: Literal["agentsec-homi-capability-diff"] = (
    "agentsec-homi-capability-diff"
)
HOMI_CAPABILITY_DIFF_VERSION = "0.1.0"


class HomiCapabilityDiffError(ValueError):
    """Raised when Homi diff inputs are invalid or incompatible."""


class HomiCapabilityChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class HomiFindingDeltaType(StrEnum):
    ADDED = "added"
    RESOLVED = "resolved"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


@dataclass(frozen=True, slots=True)
class HomiCapabilityChange:
    """One capability state transition."""

    signal_id: str
    change_type: HomiCapabilityChangeType
    before_state: str
    after_state: str
    before_source_paths: tuple[str, ...]
    after_source_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "change_type": self.change_type.value,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "before_source_paths": list(self.before_source_paths),
            "after_source_paths": list(self.after_source_paths),
        }


@dataclass(frozen=True, slots=True)
class HomiFindingDelta:
    """One Finding lifecycle transition keyed by stable Rule ID."""

    rule_id: str
    delta_type: HomiFindingDeltaType
    before_severity: str | None
    after_severity: str | None
    before_score: float | None
    after_score: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "delta_type": self.delta_type.value,
            "before_severity": self.before_severity,
            "after_severity": self.after_severity,
            "before_score": self.before_score,
            "after_score": self.after_score,
        }


@dataclass(frozen=True, slots=True)
class HomiCapabilityDiffReport:
    """Bounded Homi Capability Diff and Finding Delta report."""

    before_report_sha256: str
    after_report_sha256: str
    before_status: str
    after_status: str
    before_coverage_metrics: dict[str, object]
    after_coverage_metrics: dict[str, object]
    capability_changes: tuple[HomiCapabilityChange, ...]
    finding_deltas: tuple[HomiFindingDelta, ...]
    before_risk_score: float
    after_risk_score: float

    @property
    def capability_added_count(self) -> int:
        return sum(
            item.change_type is HomiCapabilityChangeType.ADDED
            for item in self.capability_changes
        )

    @property
    def capability_removed_count(self) -> int:
        return sum(
            item.change_type is HomiCapabilityChangeType.REMOVED
            for item in self.capability_changes
        )

    @property
    def capability_modified_count(self) -> int:
        return sum(
            item.change_type is HomiCapabilityChangeType.MODIFIED
            for item in self.capability_changes
        )

    @property
    def finding_added_count(self) -> int:
        return sum(
            item.delta_type is HomiFindingDeltaType.ADDED
            for item in self.finding_deltas
        )

    @property
    def finding_resolved_count(self) -> int:
        return sum(
            item.delta_type is HomiFindingDeltaType.RESOLVED
            for item in self.finding_deltas
        )

    @property
    def finding_changed_count(self) -> int:
        return sum(
            item.delta_type is HomiFindingDeltaType.CHANGED
            for item in self.finding_deltas
        )

    @property
    def finding_unchanged_count(self) -> int:
        return sum(
            item.delta_type is HomiFindingDeltaType.UNCHANGED
            for item in self.finding_deltas
        )

    @property
    def complete(self) -> bool:
        return self.before_status == "complete" and self.after_status == "complete"

    def to_dict(self) -> dict[str, object]:
        return {
            "format": HOMI_CAPABILITY_DIFF_FORMAT,
            "format_version": HOMI_CAPABILITY_DIFF_VERSION,
            "complete": self.complete,
            "before_report_sha256": self.before_report_sha256,
            "after_report_sha256": self.after_report_sha256,
            "before_status": self.before_status,
            "after_status": self.after_status,
            "before_coverage_metrics": self.before_coverage_metrics,
            "after_coverage_metrics": self.after_coverage_metrics,
            "capability_changes": [item.to_dict() for item in self.capability_changes],
            "capability_change_summary": {
                "added": self.capability_added_count,
                "removed": self.capability_removed_count,
                "modified": self.capability_modified_count,
            },
            "finding_deltas": [item.to_dict() for item in self.finding_deltas],
            "finding_delta_summary": {
                "added": self.finding_added_count,
                "resolved": self.finding_resolved_count,
                "changed": self.finding_changed_count,
                "unchanged": self.finding_unchanged_count,
            },
            "risk_score": {
                "kind": "homi_combination_finding_score_total",
                "before": self.before_risk_score,
                "after": self.after_risk_score,
                "delta": round(self.after_risk_score - self.before_risk_score, 2),
                "authority": "presentation_only",
            },
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "ci_blocked": False,
            },
        }


def compare_homi_reports(
    before_path: Path, after_path: Path
) -> HomiCapabilityDiffReport:
    """Compare two Homi Pilot JSON reports without exposing source content."""

    before, before_digest = _read_report(before_path)
    after, after_digest = _read_report(after_path)
    return _compare_payloads(before, after, before_digest, after_digest)


def encode_homi_capability_diff_json(report: HomiCapabilityDiffReport) -> str:
    """Encode a deterministic JSON Homi Capability Diff."""

    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def render_homi_capability_diff_text(report: HomiCapabilityDiffReport) -> str:
    """Render a concise, human-readable Homi Capability Diff."""

    lines = [
        "AgentSec Homi Capability Diff",
        f"Status: {report.before_status} -> {report.after_status}",
        (
            "Coverage metrics are reported separately; "
            "runtime reachability is not assessed."
        ),
        "",
        "Capability Changes",
        f"  Added: {report.capability_added_count}",
        f"  Removed: {report.capability_removed_count}",
        f"  Modified: {report.capability_modified_count}",
        "",
        "Finding Delta",
        f"  Added: {report.finding_added_count}",
        f"  Resolved: {report.finding_resolved_count}",
        f"  Changed: {report.finding_changed_count}",
        f"  Unchanged: {report.finding_unchanged_count}",
        "",
        (
            "Presentation-only risk score: "
            f"{report.before_risk_score:.2f} -> {report.after_risk_score:.2f} "
            f"({report.after_risk_score - report.before_risk_score:+.2f})"
        ),
        "Authority: report_only=true; runtime_verified=false; ci_blocked=false",
        "",
        "Changed capabilities:",
    ]
    if report.capability_changes:
        lines.extend(
            f"- [{item.change_type.value}] {item.signal_id}: "
            f"{item.before_state} -> {item.after_state}"
            for item in report.capability_changes
        )
    else:
        lines.append("- none")
    lines.extend(("", "Finding changes:"))
    changed_findings = tuple(
        item
        for item in report.finding_deltas
        if item.delta_type is not HomiFindingDeltaType.UNCHANGED
    )
    if changed_findings:
        lines.extend(
            f"- [{item.delta_type.value}] {item.rule_id}" for item in changed_findings
        )
    else:
        lines.append("- none")
    lines.extend(("", "这是静态报告型差异，不等同于运行时验证或漏洞利用证明。"))
    return "\n".join(lines) + "\n"


def render_homi_capability_diff_html(
    report: HomiCapabilityDiffReport,
    *,
    language: str = "zh",
) -> str:
    """Render a self-contained visual Homi Capability Diff report."""

    if not isinstance(report, HomiCapabilityDiffReport):
        raise TypeError("Homi Capability Diff HTML renderer requires a report")
    from importlib.resources import files
    from string import Template

    chinese = language == "zh"
    title = (
        "Homi Agent 能力漂移报告" if chinese else "Homi Agent Capability Drift Report"
    )
    capability_rows = _diff_capability_rows(report)
    finding_rows = _diff_finding_rows(report)
    template = files("agentsec").joinpath("templates/homi_capability_diff.html")
    substitutions = {
        "language": "zh-CN" if chinese else "en",
        "title": escape(title),
        "before_status": escape(report.before_status),
        "after_status": escape(report.after_status),
        "capability_label": escape("能力变化" if chinese else "Capability changes"),
        "capability_count": str(len(report.capability_changes)),
        "finding_label": "Finding Delta",
        "finding_count": str(report.finding_added_count),
        "score_label": escape(
            "展示用风险分数" if chinese else "Presentation risk score"
        ),
        "score_delta": f"{report.after_risk_score - report.before_risk_score:+.2f}",
        "summary_label": escape("变化摘要" if chinese else "Change summary"),
        "capability_added": str(report.capability_added_count),
        "capability_removed": str(report.capability_removed_count),
        "capability_modified": str(report.capability_modified_count),
        "finding_added": str(report.finding_added_count),
        "finding_resolved": str(report.finding_resolved_count),
        "finding_changed": str(report.finding_changed_count),
        "authority_note": escape(
            "仅用于展示，不是授权或阻断依据。"
            if chinese
            else "Presentation only; not an authorization or blocking decision."
        ),
        "capability_rows": capability_rows,
        "finding_rows": finding_rows,
    }
    return Template(template.read_text(encoding="utf-8")).safe_substitute(substitutions)


def _diff_capability_rows(report: HomiCapabilityDiffReport) -> str:
    return (
        "".join(
            f"<tr><td>{escape(item.signal_id)}</td>"
            f"<td>{escape(item.change_type.value)}</td>"
            f"<td>{escape(item.before_state)}</td>"
            f"<td>{escape(item.after_state)}</td></tr>"
            for item in report.capability_changes
        )
        or "<tr><td colspan='4'>—</td></tr>"
    )


def _diff_finding_rows(report: HomiCapabilityDiffReport) -> str:
    return (
        "".join(
            f"<tr><td>{escape(item.rule_id)}</td>"
            f"<td>{escape(item.delta_type.value)}</td>"
            f"<td>{escape(item.before_severity or '—')}</td>"
            f"<td>{escape(item.after_severity or '—')}</td></tr>"
            for item in report.finding_deltas
            if item.delta_type is not HomiFindingDeltaType.UNCHANGED
        )
        or "<tr><td colspan='4'>—</td></tr>"
    )


def _read_report(path: Path) -> tuple[dict[str, Any], str]:
    if not isinstance(path, Path):
        raise HomiCapabilityDiffError("Homi report path must be a Path")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HomiCapabilityDiffError(f"could not read Homi report: {path}") from error
    if not isinstance(payload, dict):
        raise HomiCapabilityDiffError("Homi report must be a JSON object")
    if payload.get("format") != "agentsec-homi-report-only-pilot":
        raise HomiCapabilityDiffError("Homi diff inputs must be Homi Pilot reports")
    for key, expected in (
        ("report_only", True),
        ("runtime_verified", False),
        ("ci_blocked", False),
    ):
        if payload.get(key) is not expected:
            raise HomiCapabilityDiffError(
                f"Homi report authority field {key} is invalid"
            )
    if not isinstance(payload.get("capabilities"), list):
        raise HomiCapabilityDiffError("Homi report capabilities must be a list")
    combination = payload.get("combination")
    if not isinstance(combination, dict) or not isinstance(
        combination.get("findings"), list
    ):
        raise HomiCapabilityDiffError("Homi report combination findings are missing")
    return payload, hashlib.sha256(raw).hexdigest()


def _compare_payloads(
    before: dict[str, Any],
    after: dict[str, Any],
    before_digest: str,
    after_digest: str,
) -> HomiCapabilityDiffReport:
    before_capabilities = _index_capabilities(before)
    after_capabilities = _index_capabilities(after)
    capability_change_items: list[HomiCapabilityChange] = []
    for signal_id in sorted(set(before_capabilities) | set(after_capabilities)):
        change = _capability_change(
            signal_id,
            before_capabilities.get(signal_id),
            after_capabilities.get(signal_id),
        )
        if change is not None:
            capability_change_items.append(change)
    capability_changes = tuple(capability_change_items)
    before_findings = _index_findings(before)
    after_findings = _index_findings(after)
    finding_deltas = tuple(
        _finding_delta(
            rule_id, before_findings.get(rule_id), after_findings.get(rule_id)
        )
        for rule_id in sorted(set(before_findings) | set(after_findings))
    )
    return HomiCapabilityDiffReport(
        before_report_sha256=before_digest,
        after_report_sha256=after_digest,
        before_status=_status(before),
        after_status=_status(after),
        before_coverage_metrics=_coverage_metrics(before),
        after_coverage_metrics=_coverage_metrics(after),
        capability_changes=capability_changes,
        finding_deltas=finding_deltas,
        before_risk_score=_risk_score(before_findings),
        after_risk_score=_risk_score(after_findings),
    )


def _index_capabilities(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in report["capabilities"]:
        if not isinstance(item, dict) or not isinstance(item.get("signal_id"), str):
            raise HomiCapabilityDiffError("Homi capability entry is malformed")
        signal_id = item["signal_id"]
        if signal_id in result:
            raise HomiCapabilityDiffError(f"duplicate Homi capability: {signal_id}")
        source_paths = item.get("source_paths", [])
        if not isinstance(source_paths, list) or any(
            not isinstance(value, str) for value in source_paths
        ):
            raise HomiCapabilityDiffError("Homi capability source_paths are malformed")
        result[signal_id] = {
            "state": str(item.get("state", "unknown")),
            "source_paths": tuple(sorted(set(source_paths))),
        }
    return result


def _index_findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = report["combination"]["findings"]
    result: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("rule_id"), str):
            raise HomiCapabilityDiffError("Homi finding entry is malformed")
        rule_id = item["rule_id"]
        if rule_id in result:
            raise HomiCapabilityDiffError(f"duplicate Homi finding rule: {rule_id}")
        score = item.get("score")
        result[rule_id] = {
            "severity": str(item["severity"])
            if isinstance(item.get("severity"), str)
            else None,
            "score": float(score) if isinstance(score, (int, float)) else None,
        }
    return result


def _capability_change(
    signal_id: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> HomiCapabilityChange | None:
    before_state = str(before["state"]) if before is not None else "absent"
    after_state = str(after["state"]) if after is not None else "absent"
    before_sources = before["source_paths"] if before is not None else ()
    after_sources = after["source_paths"] if after is not None else ()
    if before_state == after_state and before_sources == after_sources:
        return None
    before_active = before_state in {"present", "conditional"}
    after_active = after_state in {"present", "conditional"}
    if not before_active and after_active:
        change_type = HomiCapabilityChangeType.ADDED
    elif before_active and not after_active:
        change_type = HomiCapabilityChangeType.REMOVED
    else:
        change_type = HomiCapabilityChangeType.MODIFIED
    return HomiCapabilityChange(
        signal_id=signal_id,
        change_type=change_type,
        before_state=before_state,
        after_state=after_state,
        before_source_paths=tuple(before_sources),
        after_source_paths=tuple(after_sources),
    )


def _finding_delta(
    rule_id: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> HomiFindingDelta:
    if before is None:
        delta_type = HomiFindingDeltaType.ADDED
    elif after is None:
        delta_type = HomiFindingDeltaType.RESOLVED
    elif before != after:
        delta_type = HomiFindingDeltaType.CHANGED
    else:
        delta_type = HomiFindingDeltaType.UNCHANGED
    return HomiFindingDelta(
        rule_id=rule_id,
        delta_type=delta_type,
        before_severity=before["severity"] if before is not None else None,
        after_severity=after["severity"] if after is not None else None,
        before_score=before["score"] if before is not None else None,
        after_score=after["score"] if after is not None else None,
    )


def _risk_score(findings: dict[str, dict[str, Any]]) -> float:
    return round(sum(item["score"] or 0.0 for item in findings.values()), 2)


def _status(report: dict[str, Any]) -> str:
    status = report.get("status")
    if status not in {"complete", "partial"}:
        raise HomiCapabilityDiffError("Homi report status is invalid")
    return str(status)


def _coverage_metrics(report: dict[str, Any]) -> dict[str, object]:
    metrics = report.get("coverage_metrics")
    if isinstance(metrics, dict):
        return dict(metrics)
    capabilities = report["capabilities"]
    files = report.get("files", [])
    return {
        "capability_total": len(capabilities),
        "capability_unknown_count": sum(
            item.get("state") == "unknown"
            for item in capabilities
            if isinstance(item, dict)
        ),
        "capability_example_only_count": sum(
            item.get("state") == "example_only"
            for item in capabilities
            if isinstance(item, dict)
        ),
        "standard_file_total": len(files) if isinstance(files, list) else None,
        "standard_file_missing_count": sum(
            item.get("state") == "missing" for item in files if isinstance(item, dict)
        )
        if isinstance(files, list)
        else None,
        "standard_file_skipped_count": sum(
            item.get("state") == "skipped" for item in files if isinstance(item, dict)
        )
        if isinstance(files, list)
        else None,
        "manifest_unknown_count": None,
        "runtime_unknown_count": None,
        "runtime_attestation_status": "not_collected",
    }

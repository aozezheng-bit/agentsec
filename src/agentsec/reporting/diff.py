"""Safe deterministic text and JSON rendering for the P1-16 Diff command."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agentsec.application import ProjectDiffResult
from agentsec.diffing import AssetTextDiff, TextDiffLineKind
from agentsec.domain import ChangeType, ScanCoverage
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text
from agentsec.versioning import DIFF_OUTPUT_VERSION

DIFF_JSON_FORMAT_VERSION = DIFF_OUTPUT_VERSION


@dataclass(frozen=True, slots=True)
class DiffErrorView:
    """Safe structured command error used by both output formats."""

    code: str
    message: str
    exit_code: int
    coverage: ScanCoverage | None = None


class DiffTextRenderer:
    """Render a plain terminal Diff with redacted and escaped evidence."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor if redactor is not None else SecretRedactor()

    def render(self, result: ProjectDiffResult) -> str:
        """Return deterministic human-readable output safe for a terminal."""

        changes = result.asset_diff.changes
        counts = _change_counts(changes)
        lines = [
            "AgentSec Diff",
            f"Baseline: {self._safe(str(result.baseline.path))}",
            (
                "Changes: "
                f"{len(changes)} "
                f"(added={counts['added']}, removed={counts['removed']}, "
                f"modified={counts['modified']})"
            ),
            (
                "Collection scope: "
                + (
                    "match"
                    if result.asset_diff.collection_config_matches
                    else "MISMATCH"
                )
            ),
            (
                "Text evidence: "
                + ("complete" if result.text_diff.complete else "INCOMPLETE")
            ),
            (
                "Versions: "
                f"scanner={result.versions.package}, "
                f"domain={result.versions.domain_schema}, "
                f"baseline={result.baseline.baseline.schema_version}"
            ),
            (
                "Baseline version vector: "
                + ("match" if result.version_comparison.all_match else "DIFFERS")
            ),
        ]

        if not result.asset_diff.collection_config_matches:
            lines.append(
                "WARNING: current collection configuration differs from the Baseline."
            )
        if not result.version_comparison.all_match:
            lines.append(
                "WARNING: stored Baseline version provenance differs from current."
            )
        if result.text_diff.omitted_asset_count:
            lines.append(
                "WARNING: Text Diff omitted "
                f"{result.text_diff.omitted_asset_count} changed asset(s)."
            )

        text_by_path = {asset.change.path: asset for asset in result.text_diff.assets}
        if not changes:
            lines.append("No asset changes.")
        for change in changes:
            safe_path = self._safe(change.path)
            lines.append("")
            lines.append(f"[{change.change_type.value}] {safe_path}")
            lines.append(f"  before_sha256: {change.before_sha256 or '-'}")
            lines.append(f"  after_sha256:  {change.after_sha256 or '-'}")
            text_diff = text_by_path.get(change.path)
            if text_diff is None:
                lines.append("  text_diff: omitted_by_asset_limit")
                continue
            lines.extend(self._render_asset_text_diff(text_diff))

        return "\n".join(lines) + "\n"

    def render_error(self, error: DiffErrorView) -> str:
        """Render a safe operational error without untrusted source values."""

        lines = [f"Diff error [{error.code}]: {self._safe(error.message)}"]
        if error.coverage is not None:
            lines.append(
                "Coverage: "
                f"discovered={error.coverage.discovered_assets}, "
                f"scanned={error.coverage.scanned_assets}, "
                f"skipped={error.coverage.skipped_assets}, complete=false"
            )
            for issue in error.coverage.issues:
                path = self._safe(issue.asset_path) if issue.asset_path else "-"
                lines.append(f"  issue={issue.code.value} path={path}")
        return "\n".join(lines) + "\n"

    def _render_asset_text_diff(self, asset: AssetTextDiff) -> list[str]:
        lines = [
            f"  text_status: {asset.status.value}",
            (
                "  lines: "
                f"before={asset.before_line_count}, after={asset.after_line_count}"
            ),
        ]
        if asset.omitted_hunk_count:
            lines.append(f"  omitted_hunks: {asset.omitted_hunk_count}")
        for hunk in asset.hunks:
            lines.append(
                "  @@ "
                f"-{hunk.before_start_line},{hunk.before_line_count} "
                f"+{hunk.after_start_line},{hunk.after_line_count} @@"
            )
            for line in hunk.lines:
                prefix = {
                    TextDiffLineKind.CONTEXT: " ",
                    TextDiffLineKind.ADDED: "+",
                    TextDiffLineKind.REMOVED: "-",
                }[line.kind]
                before_number = (
                    str(line.before_line_number)
                    if line.before_line_number is not None
                    else "-"
                )
                after_number = (
                    str(line.after_line_number)
                    if line.after_line_number is not None
                    else "-"
                )
                safe_text = self._safe(line.text)
                suffix = (
                    f" [truncated from {line.original_character_count} chars]"
                    if line.truncated
                    else ""
                )
                lines.append(
                    f"  {prefix} {before_number:>5} {after_number:>5} | "
                    f"{safe_text}{suffix}"
                )
            if hunk.omitted_line_count:
                lines.append(f"    ... {hunk.omitted_line_count} line(s) omitted ...")
        return lines

    def _safe(self, value: str) -> str:
        return sanitize_untrusted_text(value, redactor=self._redactor)


class DiffJsonRenderer:
    """Render deterministic machine-readable Diff JSON with sanitized strings."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor if redactor is not None else SecretRedactor()

    def render(self, result: ProjectDiffResult) -> str:
        """Return deterministic JSON without raw untrusted line or path text."""

        changes = result.asset_diff.changes
        text_by_path = {asset.change.path: asset for asset in result.text_diff.assets}
        payload: dict[str, Any] = {
            "format": "agentsec-diff",
            "format_version": DIFF_JSON_FORMAT_VERSION,
            "status": _result_status(result),
            "versions": {
                "package": result.versions.package,
                "config_schema": result.versions.config_schema,
                "domain_schema": result.versions.domain_schema,
                "baseline_schema": result.baseline.baseline.schema_version,
                "diff_output": result.versions.diff_output,
                "rule_pack": result.versions.rule_pack,
                "risk_model": result.versions.risk_model,
            },
            "baseline": {
                "path": self._safe(str(result.baseline.path)),
                "size_bytes": result.baseline.size_bytes,
                "git_commit": result.baseline.baseline.metadata.git_commit,
                "git_dirty": result.baseline.baseline.metadata.git_dirty,
            },
            "version_comparison": {
                "all_match": result.version_comparison.all_match,
                "scanner_matches": result.version_comparison.scanner_matches,
                "config_schema_matches": (
                    result.version_comparison.config_schema_matches
                ),
                "domain_schema_matches": (
                    result.version_comparison.domain_schema_matches
                ),
                "rule_pack_matches": result.version_comparison.rule_pack_matches,
                "risk_model_matches": result.version_comparison.risk_model_matches,
            },
            "collection": {
                "config_matches": result.asset_diff.collection_config_matches,
                "coverage": _coverage_payload(result.current_collection.coverage, self),
            },
            "summary": {
                "changes": len(changes),
                **_change_counts(changes),
                "text_diff_complete": result.text_diff.complete,
                "omitted_text_diff_assets": result.text_diff.omitted_asset_count,
            },
            "changes": [
                self._change_payload(change, text_by_path.get(change.path))
                for change in changes
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def render_error(self, error: DiffErrorView) -> str:
        """Return one deterministic JSON error object for automation."""

        payload: dict[str, Any] = {
            "format": "agentsec-diff",
            "format_version": DIFF_JSON_FORMAT_VERSION,
            "status": "error",
            "error": {
                "code": error.code,
                "message": self._safe(error.message),
                "exit_code": error.exit_code,
            },
        }
        if error.coverage is not None:
            payload["coverage"] = _coverage_payload(error.coverage, self)
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def _change_payload(
        self,
        change: Any,
        text_diff: AssetTextDiff | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self._safe(change.path),
            "change_type": change.change_type.value,
            "before_sha256": change.before_sha256,
            "after_sha256": change.after_sha256,
        }
        if text_diff is None:
            payload["text_diff"] = {"status": "omitted_by_asset_limit"}
            return payload
        payload["text_diff"] = {
            "status": text_diff.status.value,
            "before_line_count": text_diff.before_line_count,
            "after_line_count": text_diff.after_line_count,
            "omitted_hunk_count": text_diff.omitted_hunk_count,
            "hunks": [self._hunk_payload(hunk) for hunk in text_diff.hunks],
        }
        return payload

    def _hunk_payload(self, hunk: Any) -> dict[str, Any]:
        return {
            "before_start_line": hunk.before_start_line,
            "before_line_count": hunk.before_line_count,
            "after_start_line": hunk.after_start_line,
            "after_line_count": hunk.after_line_count,
            "omitted_line_count": hunk.omitted_line_count,
            "truncated": hunk.truncated,
            "lines": [
                {
                    "kind": line.kind.value,
                    "before_line_number": line.before_line_number,
                    "after_line_number": line.after_line_number,
                    "text": self._safe(line.text),
                    "original_character_count": line.original_character_count,
                    "truncated": line.truncated,
                }
                for line in hunk.lines
            ],
        }

    def _safe(self, value: str) -> str:
        return sanitize_untrusted_text(value, redactor=self._redactor)


def _change_counts(changes: Any) -> dict[str, int]:
    counts = {"added": 0, "removed": 0, "modified": 0}
    for change in changes:
        if change.change_type is ChangeType.ADDED:
            counts["added"] += 1
        elif change.change_type is ChangeType.REMOVED:
            counts["removed"] += 1
        elif change.change_type is ChangeType.MODIFIED:
            counts["modified"] += 1
    return counts


def _coverage_payload(
    coverage: ScanCoverage,
    renderer: DiffJsonRenderer,
) -> dict[str, Any]:
    return {
        "discovered_assets": coverage.discovered_assets,
        "scanned_assets": coverage.scanned_assets,
        "skipped_assets": coverage.skipped_assets,
        "complete": coverage.complete,
        "issues": [
            {
                "code": issue.code.value,
                "path": renderer._safe(issue.asset_path) if issue.asset_path else None,
            }
            for issue in coverage.issues
        ],
    }


def _result_status(result: ProjectDiffResult) -> str:
    if not result.asset_diff.collection_config_matches:
        return "scope_mismatch"
    if not result.text_diff.complete:
        return "incomplete"
    return "complete"

"""Deterministic Text and canonical JSON delivery for Capability Diff."""

# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.manifests import (
    CapabilityDiffResult,
    ManifestSourceReference,
    encode_capability_diff_json,
)
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text


@dataclass(frozen=True, slots=True)
class CapabilityDiffTextLimits:
    """Independent bounds for profile, change, and source details."""

    max_profile_changes: int = 100
    max_changes: int = 100
    max_sources_per_change: int = 10
    max_text_characters: int = 512

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_profile_changes, "max_profile_changes"),
            (self.max_changes, "max_changes"),
            (self.max_sources_per_change, "max_sources_per_change"),
            (self.max_text_characters, "max_text_characters"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{label} must be a positive integer")


class CapabilityDiffJsonRenderer:
    """Expose the existing canonical Capability Diff JSON artifact."""

    def render(self, result: CapabilityDiffResult) -> str:
        return encode_capability_diff_json(result)


class CapabilityDiffTextRenderer:
    """Render value-minimizing normalized capability changes for review."""

    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        redactor: SecretRedactor | None = None,
        limits: CapabilityDiffTextLimits | None = None,
    ) -> None:
        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        self._language = language
        self._redactor = redactor or SecretRedactor()
        self._limits = limits or CapabilityDiffTextLimits()

    def render(self, result: CapabilityDiffResult) -> str:
        if not isinstance(result, CapabilityDiffResult):
            raise TypeError(
                "Capability Diff text rendering requires CapabilityDiffResult"
            )
        if self._language is CapabilityRuleLanguage.ZH:
            return self._render_zh(result)
        return self._render_en(result)

    def _render_en(self, result: CapabilityDiffResult) -> str:
        lines = [
            "AgentSec Capability Diff",
            f"Status: {'COMPLETE' if result.complete else 'INCOMPLETE'}",
            f"Agent: {self._safe(result.agent_id)}",
            f"Diff schema: {result.schema_version}",
            f"Manifest schema: {result.agent_manifest_schema_version}",
            (
                "Summary: "
                f"added={result.added_count} removed={result.removed_count} "
                f"modified={result.modified_count} "
                f"profile_transitions={len(result.profile_changes)}"
            ),
        ]
        if not result.complete:
            lines.append(
                "WARNING: before or after Coverage is incomplete; changes are not exhaustive."
            )
        lines.extend(("", "Profile Transitions"))
        lines.extend(
            self._bounded(
                (
                    f"  {change.profile.value}: {self._safe(change.before)} -> "
                    f"{self._safe(change.after)}"
                    for change in result.profile_changes
                ),
                self._limits.max_profile_changes,
            )
        )
        lines.extend(("", "Changes by Dimension"))
        visible_changes = result.changes[: self._limits.max_changes]
        current_dimension: str | None = None
        for change in visible_changes:
            if change.dimension.value != current_dimension:
                current_dimension = change.dimension.value
                lines.append(f"  {current_dimension}")
            lines.append(
                f"    [{change.change_type.value.upper()}] {self._safe(change.item_id)}"
            )
            lines.append("      changed_fields: " + ",".join(change.changed_fields))
            lines.append(f"      before_sha256: {change.before_sha256 or '-'}")
            lines.append(f"      after_sha256: {change.after_sha256 or '-'}")
            lines.extend(self._source_lines("before_source", change.before_sources))
            lines.extend(self._source_lines("after_source", change.after_sources))
        omitted = len(result.changes) - len(visible_changes)
        if omitted:
            lines.append(f"  ... {omitted} change(s) omitted by display limit")
        if not result.changes:
            lines.append("  No normalized capability item changes.")
        lines.extend(
            (
                "",
                "Boundary",
                "  No before/after values are included in the canonical Diff artifact.",
                "  This Diff does not prove runtime reachability or exploitation.",
            )
        )
        return "\n".join(lines) + "\n"

    def _render_zh(self, result: CapabilityDiffResult) -> str:
        lines = [
            "AgentSec 能力 Diff",
            f"状态：{'完整' if result.complete else '不完整'}",
            f"Agent：{self._safe(result.agent_id)}",
            f"Diff Schema：{result.schema_version}",
            f"Manifest Schema：{result.agent_manifest_schema_version}",
            (
                "摘要："
                f"新增={result.added_count} 移除={result.removed_count} "
                f"修改={result.modified_count} "
                f"Profile 迁移={len(result.profile_changes)}"
            ),
        ]
        if not result.complete:
            lines.append(
                "警告：before 或 after 的 Coverage 不完整，能力变化不是穷尽结果。"
            )
        lines.extend(("", "Profile 迁移"))
        lines.extend(
            self._bounded(
                (
                    f"  {item.profile.value}：{self._safe(item.before)} -> "
                    f"{self._safe(item.after)}"
                    for item in result.profile_changes
                ),
                self._limits.max_profile_changes,
                chinese=True,
            )
        )
        lines.extend(("", "按维度分组的变化"))
        visible = result.changes[: self._limits.max_changes]
        current: str | None = None
        for change in visible:
            if current != change.dimension.value:
                current = change.dimension.value
                lines.append(f"  {current}")
            lines.append(
                f"    [{change.change_type.value.upper()}] {self._safe(change.item_id)}"
            )
            lines.append("      changed_fields：" + ",".join(change.changed_fields))
            lines.append(f"      before_sha256：{change.before_sha256 or '-'}")
            lines.append(f"      after_sha256：{change.after_sha256 or '-'}")
            lines.extend(self._source_lines("before_source", change.before_sources))
            lines.extend(self._source_lines("after_source", change.after_sources))
        omitted = len(result.changes) - len(visible)
        if omitted:
            lines.append(f"  ... 因展示上限省略 {omitted} 个变化")
        if not result.changes:
            lines.append("  没有标准化能力项变化。")
        lines.extend(
            (
                "",
                "边界说明",
                "  Canonical Diff 不包含 before/after 原始值。",
                "  本 Diff 不代表运行时可达性或利用已被证明。",
            )
        )
        return "\n".join(lines) + "\n"

    def _source_lines(
        self,
        label: str,
        sources: tuple[ManifestSourceReference, ...],
    ) -> list[str]:
        visible = sources[: self._limits.max_sources_per_change]
        lines = [f"      {label}: {self._reference(source)}" for source in visible]
        omitted = len(sources) - len(visible)
        if omitted:
            lines.append(f"      ... {omitted} source(s) omitted by display limit")
        return lines or [f"      {label}: -"]

    def _reference(self, reference: ManifestSourceReference) -> str:
        line = (
            f":{reference.start_line}-{reference.end_line}"
            if reference.start_line is not None
            else ""
        )
        field = reference.field_path or ""
        return self._safe(f"{reference.locator.path}{field}{line}")

    def _bounded(
        self,
        values: Iterable[str],
        limit: int,
        *,
        chinese: bool = False,
    ) -> list[str]:
        items = list(values)
        visible = items[:limit]
        omitted = len(items) - len(visible)
        if omitted:
            visible.append(
                f"  ... 因展示上限省略 {omitted} 项"
                if chinese
                else f"  ... {omitted} item(s) omitted by display limit"
            )
        return visible or ["  -"]

    def _safe(self, value: str) -> str:
        safe = sanitize_untrusted_text(value, redactor=self._redactor)
        return safe[: self._limits.max_text_characters]

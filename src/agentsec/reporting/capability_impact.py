"""Deterministic bilingual delivery for P2-13 Capability Change Impact."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.change_impact import (
    CapabilityChangeImpact,
    CapabilityChangeImpactReport,
    CapabilityFindingDelta,
    CapabilityImpactReason,
    CapabilitySemanticState,
    encode_capability_change_impact_json,
)
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text


@dataclass(frozen=True, slots=True)
class CapabilityChangeImpactTextLimits:
    max_change_impacts: int = 100
    max_finding_delta: int = 100
    max_related_ids: int = 20
    max_text_characters: int = 512

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_change_impacts, "max_change_impacts"),
            (self.max_finding_delta, "max_finding_delta"),
            (self.max_related_ids, "max_related_ids"),
            (self.max_text_characters, "max_text_characters"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{label} must be a positive integer")


class CapabilityChangeImpactJsonRenderer:
    """Render the strict canonical Change Impact JSON artifact."""

    def render(self, report: CapabilityChangeImpactReport) -> str:
        return encode_capability_change_impact_json(report)


class CapabilityChangeImpactTextRenderer:
    """Present management Finding Delta before developer semantic details."""

    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        redactor: SecretRedactor | None = None,
        limits: CapabilityChangeImpactTextLimits | None = None,
    ) -> None:
        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        self._language = language
        self._redactor = redactor or SecretRedactor()
        self._limits = limits or CapabilityChangeImpactTextLimits()

    def render(self, report: CapabilityChangeImpactReport) -> str:
        if not isinstance(report, CapabilityChangeImpactReport):
            raise TypeError(
                "Capability Change Impact rendering requires "
                "CapabilityChangeImpactReport"
            )
        if self._language is CapabilityRuleLanguage.ZH:
            return self._render_zh(report)
        return self._render_en(report)

    def _render_en(self, report: CapabilityChangeImpactReport) -> str:
        summary = report.summary
        lines = [
            "AgentSec Capability Change Impact",
            f"Status: {report.status.upper()}",
            f"Agent: {self._safe(report.agent_id)}",
            (
                "Policy: report-only; CI blocking disabled; runtime capability "
                "not verified"
            ),
            "",
            "Management Summary",
            (
                "  Capability changes: "
                f"{summary.capability_changes}; impact-assessed="
                f"{summary.assessed_change_impacts}; unassessed="
                f"{summary.unassessed_capability_changes}"
            ),
            (
                "  Exposure direction: "
                f"increased={summary.increased_exposure} "
                f"reduced={summary.reduced_exposure} mixed={summary.mixed} "
                f"neutral={summary.neutral} uncertain={summary.uncertain}"
            ),
            (
                "  Finding Delta: "
                f"added={summary.added_findings} resolved={summary.resolved_findings} "
                f"changed={summary.changed_findings} "
                f"unchanged={summary.unchanged_findings}"
            ),
            (
                "  Highest Severity: "
                f"before={summary.highest_before_severity.value.upper()} "
                f"after={summary.highest_after_severity.value.upper()}"
            ),
            (
                "  High/Critical lifecycle: "
                f"added={summary.added_high_or_critical} "
                f"resolved={summary.resolved_high_or_critical}"
            ),
        ]
        if report.status == "incomplete":
            lines.append(
                "WARNING: Coverage or Rule execution is incomplete; impact and "
                "Finding Delta are not exhaustive."
            )
        lines.extend(("", "Finding Delta"))
        lines.extend(self._finding_lines(report.finding_delta, chinese=False))
        lines.extend(("", "Tool / Permission / Control Change Impact"))
        lines.extend(self._impact_lines(report.change_impacts, chinese=False))
        lines.extend(
            (
                "",
                "Boundary",
                (
                    "  Before/after state contains normalized fields only, not "
                    "source values."
                ),
                (
                    "  Exposure direction is not a new Severity score or "
                    "authorization decision."
                ),
                "  Added High Findings are not diluted by unchanged or lower Findings.",
                "  This report does not prove runtime reachability or exploitation.",
            )
        )
        return "\n".join(lines) + "\n"

    def _render_zh(self, report: CapabilityChangeImpactReport) -> str:
        summary = report.summary
        lines = [
            "AgentSec 能力变化影响",
            f"状态：{'完整' if report.status == 'complete' else '不完整'}",
            f"Agent：{self._safe(report.agent_id)}",
            "策略：仅报告；不启用 CI 阻断；未验证运行时能力",
            "",
            "管理层摘要",
            (
                "  能力变化："
                f"{summary.capability_changes}；已评估影响="
                f"{summary.assessed_change_impacts}；未评估="
                f"{summary.unassessed_capability_changes}"
            ),
            (
                "  暴露方向："
                f"增加={summary.increased_exposure} "
                f"降低={summary.reduced_exposure} 混合={summary.mixed} "
                f"中性={summary.neutral} 不确定={summary.uncertain}"
            ),
            (
                "  Finding Delta："
                f"新增={summary.added_findings} 已解决={summary.resolved_findings} "
                f"变化={summary.changed_findings} "
                f"未变化={summary.unchanged_findings}"
            ),
            (
                "  最高严重性："
                f"before={summary.highest_before_severity.value.upper()} "
                f"after={summary.highest_after_severity.value.upper()}"
            ),
            (
                "  High/Critical 生命周期："
                f"新增={summary.added_high_or_critical} "
                f"已解决={summary.resolved_high_or_critical}"
            ),
        ]
        if report.status == "incomplete":
            lines.append(
                "警告：Coverage 或规则执行不完整，影响分析与 Finding Delta "
                "不是穷尽结果。"
            )
        lines.extend(("", "Finding Delta"))
        lines.extend(self._finding_lines(report.finding_delta, chinese=True))
        lines.extend(("", "工具 / 权限 / 控制变化影响"))
        lines.extend(self._impact_lines(report.change_impacts, chinese=True))
        lines.extend(
            (
                "",
                "边界说明",
                "  before/after 只包含标准化字段，不包含源配置原始值。",
                "  暴露方向不是新的 Severity 分数，也不是授权决策。",
                "  新增 High Finding 不会被未变化或低风险 Finding 平均稀释。",
                "  本报告不证明运行时可达性或利用已发生。",
            )
        )
        return "\n".join(lines) + "\n"

    def _finding_lines(
        self,
        deltas: tuple[CapabilityFindingDelta, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = deltas[: self._limits.max_finding_delta]
        lines: list[str] = []
        for delta in visible:
            snapshot = delta.after or delta.before
            if snapshot is None:
                continue
            title = snapshot.title_zh if chinese else snapshot.title_en
            lines.append(
                f"  [{delta.status.value.upper()}] {delta.rule_id} — "
                f"{self._safe(title)}"
            )
            lines.append(
                "    "
                + ("风险方向：" if chinese else "risk_direction: ")
                + delta.risk_direction.value
            )
            before = delta.before.severity.value if delta.before else "-"
            after = delta.after.severity.value if delta.after else "-"
            lines.append(
                "    "
                + ("严重性：" if chinese else "severity: ")
                + f"{before} -> {after}"
            )
            lines.append(
                "    "
                + ("关联 ID：" if chinese else "related_ids: ")
                + self._joined(delta.related_ids)
            )
            lines.append(
                "    "
                + ("变化字段：" if chinese else "changed_fields: ")
                + (",".join(delta.changed_fields) or "-")
            )
            lines.append(
                "    "
                + ("关联能力变化：" if chinese else "impacted_changes: ")
                + self._joined(delta.impacted_change_ids)
            )
        omitted = len(deltas) - len(visible)
        if omitted:
            lines.append(
                f"  ... 因展示上限省略 {omitted} 个 Finding Delta"
                if chinese
                else f"  ... {omitted} Finding Delta item(s) omitted by display limit"
            )
        return lines or ["  -"]

    def _impact_lines(
        self,
        impacts: tuple[CapabilityChangeImpact, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = impacts[: self._limits.max_change_impacts]
        lines: list[str] = []
        for impact in visible:
            lines.append(
                f"  [{impact.direction.value.upper()}] "
                f"{impact.dimension.value} {self._safe(impact.item_id)}"
            )
            lines.append(
                "    "
                + ("变化类型：" if chinese else "change_type: ")
                + impact.change_type.value
            )
            lines.append(
                "    "
                + ("before：" if chinese else "before: ")
                + self._state(impact.before)
            )
            lines.append(
                "    "
                + ("after：" if chinese else "after: ")
                + self._state(impact.after)
            )
            lines.append(
                "    "
                + ("依据：" if chinese else "reasons: ")
                + ",".join(
                    self._reason(reason, chinese=chinese) for reason in impact.reasons
                )
            )
            lines.append(
                "    "
                + ("关联 Finding Delta：" if chinese else "related_finding_delta: ")
                + self._joined(impact.related_finding_delta_ids)
            )
        omitted = len(impacts) - len(visible)
        if omitted:
            lines.append(
                f"  ... 因展示上限省略 {omitted} 个变化影响"
                if chinese
                else f"  ... {omitted} Change Impact item(s) omitted by display limit"
            )
        return lines or ["  -"]

    def _state(self, state: CapabilitySemanticState | None) -> str:
        if state is None:
            return "-"
        fields = []
        for attribute in state.attributes:
            values = ",".join(self._safe(value) for value in attribute.values) or "-"
            fields.append(f"{attribute.field.value}={values}")
        return "; ".join(fields)

    @staticmethod
    def _reason(reason: CapabilityImpactReason, *, chinese: bool) -> str:
        if not chinese:
            return reason.value
        return {
            CapabilityImpactReason.CAPABILITY_ADDED: "新增能力",
            CapabilityImpactReason.CAPABILITY_REMOVED: "移除能力",
            CapabilityImpactReason.TOOL_ENABLED: "启用工具",
            CapabilityImpactReason.TOOL_DISABLED: "禁用工具",
            CapabilityImpactReason.SENSITIVE_EFFECT_ADDED: "新增敏感副作用",
            CapabilityImpactReason.SENSITIVE_EFFECT_REMOVED: "移除敏感副作用",
            CapabilityImpactReason.PERMISSION_GRANTED: "权限放开",
            CapabilityImpactReason.PERMISSION_REVOKED: "权限收回",
            CapabilityImpactReason.PERMISSION_EFFECT_WEAKENED: "权限约束减弱",
            CapabilityImpactReason.PERMISSION_EFFECT_STRENGTHENED: "权限约束增强",
            CapabilityImpactReason.CONTROL_WEAKENED: "控制减弱",
            CapabilityImpactReason.CONTROL_STRENGTHENED: "控制增强",
            CapabilityImpactReason.SEMANTIC_STATE_CHANGED: "语义状态变化",
            CapabilityImpactReason.UNKNOWN_STATE: "存在未知状态",
        }[reason]

    def _joined(self, values: tuple[str, ...]) -> str:
        visible = values[: self._limits.max_related_ids]
        rendered = ",".join(self._safe(value) for value in visible) or "-"
        omitted = len(values) - len(visible)
        if omitted:
            rendered += f",...(+{omitted})"
        return rendered

    def _safe(self, value: str) -> str:
        safe = sanitize_untrusted_text(value, redactor=self._redactor)
        return safe[: self._limits.max_text_characters]

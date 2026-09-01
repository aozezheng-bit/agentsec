"""Bounded bilingual Text delivery for deterministic Capability Assessments."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.application import CapabilityAssessmentResult
from agentsec.capability_rules import (
    CapabilityEvidence,
    CapabilityRuleFinding,
    CapabilityRuleLanguage,
)
from agentsec.domain import EvidenceConfidence, Severity
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text


@dataclass(frozen=True, slots=True)
class CapabilityAssessmentTextLimits:
    """Independent display bounds for one human-readable assessment."""

    max_findings: int = 100
    max_evidence_per_finding: int = 10
    max_related_ids_per_finding: int = 20
    max_recommendations_per_finding: int = 10
    max_stage_items: int = 9
    max_rule_failures: int = 100
    max_text_characters: int = 512

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_findings, "max_findings"),
            (self.max_evidence_per_finding, "max_evidence_per_finding"),
            (self.max_related_ids_per_finding, "max_related_ids_per_finding"),
            (
                self.max_recommendations_per_finding,
                "max_recommendations_per_finding",
            ),
            (self.max_stage_items, "max_stage_items"),
            (self.max_rule_failures, "max_rule_failures"),
            (self.max_text_characters, "max_text_characters"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{label} must be a positive integer")


class CapabilityAssessmentTextRenderer:
    """Render management summary and developer evidence without source values."""

    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        redactor: SecretRedactor | None = None,
        limits: CapabilityAssessmentTextLimits | None = None,
    ) -> None:
        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        self._language = language
        self._redactor = redactor or SecretRedactor()
        self._limits = limits or CapabilityAssessmentTextLimits()

    def render(self, result: CapabilityAssessmentResult) -> str:
        """Return deterministic ANSI-free Capability Assessment text."""

        if not isinstance(result, CapabilityAssessmentResult):
            raise TypeError(
                "Capability Assessment text rendering requires "
                "CapabilityAssessmentResult"
            )
        if self._language is CapabilityRuleLanguage.ZH:
            return self._render_zh(result)
        return self._render_en(result)

    def _render_en(self, result: CapabilityAssessmentResult) -> str:
        manifest = result.analysis.manifest
        findings = self._ordered_findings(result)
        severity_counts = self._severity_counts(findings)
        confidence_counts = self._confidence_counts(findings)
        highest = self._highest_severity(findings)
        lines = [
            "AgentSec Capability Assessment",
            f"Status: {'COMPLETE' if result.complete else 'INCOMPLETE'}",
            f"Agent: {self._safe(manifest.identity.agent_id)}",
            "Policy: report-only; CI blocking disabled; runtime not verified",
            "",
            "Management Summary",
            f"  Findings: {len(findings)}",
            f"  Highest severity: {highest.value.upper()}",
            (
                "  Severity: "
                f"critical={severity_counts[Severity.CRITICAL]} "
                f"high={severity_counts[Severity.HIGH]} "
                f"medium={severity_counts[Severity.MEDIUM]} "
                f"low={severity_counts[Severity.LOW]} "
                f"none={severity_counts[Severity.NONE]}"
            ),
            (
                "  Confidence: "
                f"A={confidence_counts[EvidenceConfidence.A]} "
                f"B={confidence_counts[EvidenceConfidence.B]} "
                f"C={confidence_counts[EvidenceConfidence.C]} "
                f"D={confidence_counts[EvidenceConfidence.D]}"
            ),
            (
                "  Inventory: "
                f"sources={len(manifest.sources)} "
                f"tools={len(manifest.tools.tools)} "
                f"permissions={len(manifest.permissions.permissions)} "
                f"controls={len(manifest.controls.controls)} "
                f"identities={len(manifest.runtime_identities.identities)} "
                f"relationships={len(manifest.relationships.relations)} "
                f"unknowns={len(manifest.unknowns)}"
            ),
            (
                "  Coverage: "
                f"{'COMPLETE' if manifest.coverage.complete else 'INCOMPLETE'}; "
                f"discovered={manifest.coverage.discovered_assets} "
                f"inspected={manifest.coverage.inspected_assets} "
                f"skipped={manifest.coverage.skipped_assets} "
                f"issues={len(manifest.coverage.issues)}"
            ),
            (
                "  Rule execution: "
                f"{'COMPLETE' if result.rules.complete else 'INCOMPLETE'}; "
                f"evaluated={len(result.rules.evaluated_rule_ids)} "
                f"failures={len(result.rules.failures)}"
            ),
            "  Hard Gates: matched=0 (report-only; no CI block)",
            (
                "  Shadow Gates: "
                f"matched={self._shadow_gate_matches(findings)} "
                "(shadow; pilot-only; no CI block)"
            ),
            "",
            "Version Vector",
            f"  package: {result.versions.package}",
            f"  agent_manifest_schema: {result.versions.agent_manifest_schema}",
            f"  capability_rule_pack: {result.versions.capability_rule_pack}",
            f"  capability_risk_model: {result.versions.capability_risk_model}",
            (
                "  capability_assessment_output: "
                f"{result.versions.capability_assessment_output}"
            ),
            "",
            "Stage Trace",
        ]
        lines.extend(self._stage_lines(result, chinese=False))
        if not result.complete:
            lines.extend(
                (
                    "",
                    "WARNING: This assessment is incomplete. Coverage or Rule "
                    "execution gaps remain visible and this result must not be "
                    "treated as a clean pass.",
                )
            )
        lines.extend(self._rule_failure_lines(result, chinese=False))
        lines.extend(("", "Findings"))
        lines.extend(self._finding_lines(findings, chinese=False))
        lines.extend(
            (
                "",
                "Boundary",
                "  Findings describe static declarations and deterministic "
                "correlations only.",
                "  This report does not prove runtime reachability or global "
                "Agent safety.",
            )
        )
        return "\n".join(lines) + "\n"

    def _render_zh(self, result: CapabilityAssessmentResult) -> str:
        manifest = result.analysis.manifest
        findings = self._ordered_findings(result)
        severity_counts = self._severity_counts(findings)
        confidence_counts = self._confidence_counts(findings)
        highest = self._highest_severity(findings)
        lines = [
            "AgentSec 能力评估",
            f"状态：{'完整' if result.complete else '不完整'}",
            f"Agent：{self._safe(manifest.identity.agent_id)}",
            "策略：仅报告；不启用 CI 阻断；未验证运行时能力",
            "",
            "管理摘要",
            f"  发现项：{len(findings)}",
            f"  最高严重性：{self._severity_zh(highest)}",
            (
                "  严重性："
                f"严重={severity_counts[Severity.CRITICAL]} "
                f"高={severity_counts[Severity.HIGH]} "
                f"中={severity_counts[Severity.MEDIUM]} "
                f"低={severity_counts[Severity.LOW]} "
                f"无={severity_counts[Severity.NONE]}"
            ),
            (
                "  证据置信度："
                f"A={confidence_counts[EvidenceConfidence.A]} "
                f"B={confidence_counts[EvidenceConfidence.B]} "
                f"C={confidence_counts[EvidenceConfidence.C]} "
                f"D={confidence_counts[EvidenceConfidence.D]}"
            ),
            (
                "  能力清单："
                f"来源={len(manifest.sources)} "
                f"工具={len(manifest.tools.tools)} "
                f"权限={len(manifest.permissions.permissions)} "
                f"控制={len(manifest.controls.controls)} "
                f"身份={len(manifest.runtime_identities.identities)} "
                f"关系={len(manifest.relationships.relations)} "
                f"Unknown={len(manifest.unknowns)}"
            ),
            (
                "  Coverage："
                f"{'完整' if manifest.coverage.complete else '不完整'}；"
                f"发现={manifest.coverage.discovered_assets} "
                f"已检查={manifest.coverage.inspected_assets} "
                f"跳过={manifest.coverage.skipped_assets} "
                f"问题={len(manifest.coverage.issues)}"
            ),
            (
                "  规则执行："
                f"{'完整' if result.rules.complete else '不完整'}；"
                f"已评估={len(result.rules.evaluated_rule_ids)} "
                f"失败={len(result.rules.failures)}"
            ),
            "  Hard Gate：命中=0（仅报告；不阻断 CI）",
            (
                "  Shadow Gate："
                f"命中={self._shadow_gate_matches(findings)}"
                "（影子模式；仅试点；不阻断 CI）"
            ),
            "",
            "版本向量",
            f"  package：{result.versions.package}",
            f"  agent_manifest_schema：{result.versions.agent_manifest_schema}",
            f"  capability_rule_pack：{result.versions.capability_rule_pack}",
            f"  capability_risk_model：{result.versions.capability_risk_model}",
            (
                "  capability_assessment_output："
                f"{result.versions.capability_assessment_output}"
            ),
            "",
            "阶段轨迹",
        ]
        lines.extend(self._stage_lines(result, chinese=True))
        if not result.complete:
            lines.extend(
                (
                    "",
                    "警告：本次评估不完整。Coverage 或规则执行仍有缺口，"
                    "不能将结果视为安全通过。",
                )
            )
        lines.extend(self._rule_failure_lines(result, chinese=True))
        lines.extend(("", "发现项"))
        lines.extend(self._finding_lines(findings, chinese=True))
        lines.extend(
            (
                "",
                "边界说明",
                "  发现项仅描述静态声明和确定性关联。",
                "  本报告不代表运行时可达性或 Agent 全局安全已被证明。",
            )
        )
        return "\n".join(lines) + "\n"

    def _stage_lines(
        self,
        result: CapabilityAssessmentResult,
        *,
        chinese: bool,
    ) -> list[str]:
        visible = result.analysis.stages[: self._limits.max_stage_items]
        lines = [
            (
                f"  {item.stage.value}：{item.status.value} "
                f"输入={item.input_items} 输出={item.output_items}"
                if chinese
                else f"  {item.stage.value}: {item.status.value} "
                f"input={item.input_items} output={item.output_items}"
            )
            for item in visible
        ]
        omitted = len(result.analysis.stages) - len(visible)
        if omitted:
            lines.append(self._omitted(omitted, "stage item(s)", "个阶段项"))
        return lines

    def _rule_failure_lines(
        self,
        result: CapabilityAssessmentResult,
        *,
        chinese: bool,
    ) -> list[str]:
        if not result.rules.failures:
            return []
        visible = result.rules.failures[: self._limits.max_rule_failures]
        lines = ["", "规则执行失败" if chinese else "Rule Failures"]
        lines.extend(f"  {self._safe(item.rule_id)}" for item in visible)
        omitted = len(result.rules.failures) - len(visible)
        if omitted:
            lines.append(self._omitted(omitted, "Rule failure(s)", "个规则失败项"))
        return lines

    @staticmethod
    def _shadow_gate_matches(findings: tuple[CapabilityRuleFinding, ...]) -> int:
        return sum(
            finding.capability_shadow_gate is not None
            and finding.capability_shadow_gate.matched
            for finding in findings
        )

    def _shadow_gate_line(
        self,
        finding: CapabilityRuleFinding,
        *,
        chinese: bool,
    ) -> list[str]:
        gate = finding.capability_shadow_gate
        if gate is None:
            return []
        if chinese:
            state = "命中" if gate.matched else "未命中"
            return [
                f"   Shadow Gate：{self._safe(gate.gate_id)} {state}"
                "（影子模式；仅试点；不阻断）"
            ]
        state = "matched" if gate.matched else "not matched"
        return [
            f"   Shadow Gate: {self._safe(gate.gate_id)} {state} "
            "(shadow; pilot-only; blocks=false)"
        ]

    def _finding_lines(
        self,
        findings: tuple[CapabilityRuleFinding, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        if not findings:
            return [
                (
                    "  在当前支持的静态范围内未产生发现项；这不代表 Agent 安全。"
                    if chinese
                    else "  No findings were produced in the supported static scope; "
                    "this does not prove that the Agent is safe."
                )
            ]
        visible = findings[: self._limits.max_findings]
        lines: list[str] = []
        for index, finding in enumerate(visible, start=1):
            lines.extend(self._one_finding(index, finding, chinese=chinese))
        omitted = len(findings) - len(visible)
        if omitted:
            lines.append(self._omitted(omitted, "finding(s)", "个发现项"))
        return lines

    def _one_finding(
        self,
        index: int,
        finding: CapabilityRuleFinding,
        *,
        chinese: bool,
    ) -> list[str]:
        text = finding.text_for(self._language)
        if chinese:
            lines = [
                "",
                f"{index}. [{self._severity_zh(finding.severity)}] "
                f"{self._safe(text.title)}",
                f"   Finding ID：{self._safe(finding.finding_id)}",
                f"   规则：{self._safe(finding.rule_id)}",
                f"   类别：{finding.category.value}",
                f"   分数：{finding.score:.1f}",
                f"   严重性：{self._severity_zh(finding.severity)}",
                f"   可能性：{finding.likelihood.value}",
                f"   影响：{finding.impact.value}",
                f"   证据置信度：{finding.confidence.value}",
                "   Hard Gate：未启用（仅报告）",
                *self._shadow_gate_line(finding, chinese=True),
                f"   相关性：{finding.correlation.value}",
                f"   描述：{self._safe(text.description)}",
                "   相关 ID：",
            ]
        else:
            lines = [
                "",
                f"{index}. [{finding.severity.value.upper()}] {self._safe(text.title)}",
                f"   Finding ID: {self._safe(finding.finding_id)}",
                f"   Rule: {self._safe(finding.rule_id)}",
                f"   Category: {finding.category.value}",
                f"   Score: {finding.score:.1f}",
                f"   Severity: {finding.severity.value.upper()}",
                f"   Likelihood: {finding.likelihood.value}",
                f"   Confidence: {finding.confidence.value}",
                "   Hard Gate: disabled (report-only)",
                *self._shadow_gate_line(finding, chinese=False),
                f"   Correlation: {finding.correlation.value}",
                f"   Description: {self._safe(text.description)}",
                "   Related IDs:",
            ]
        related = finding.related_ids[: self._limits.max_related_ids_per_finding]
        lines.extend(f"     - {self._safe(item)}" for item in related)
        omitted_related = len(finding.related_ids) - len(related)
        if omitted_related:
            lines.append(self._omitted(omitted_related, "related ID(s)", "个相关 ID"))
        lines.append("   证据：" if chinese else "   Evidence:")
        evidence = finding.evidence[: self._limits.max_evidence_per_finding]
        lines.extend(
            f"     {item_index}. {self._evidence_location(item)} "
            f"sha256={item.content_sha256}"
            for item_index, item in enumerate(evidence, start=1)
        )
        omitted_evidence = len(finding.evidence) - len(evidence)
        if omitted_evidence:
            lines.append(
                self._omitted(omitted_evidence, "evidence item(s)", "个证据项")
            )
        lines.append("   修复建议：" if chinese else "   Recommendation:")
        recommendations = text.recommendations[
            : self._limits.max_recommendations_per_finding
        ]
        lines.extend(
            f"     {item_index}. {self._safe(item)}"
            for item_index, item in enumerate(recommendations, start=1)
        )
        omitted_recommendations = len(text.recommendations) - len(recommendations)
        if omitted_recommendations:
            lines.append(
                self._omitted(
                    omitted_recommendations,
                    "recommendation(s)",
                    "条修复建议",
                )
            )
        return lines

    def _evidence_location(self, item: CapabilityEvidence) -> str:
        location = f"{item.scope}:{item.root_id}:{item.path}"
        if item.field_path is not None:
            location += item.field_path
        if item.start_line is not None:
            location += f":{item.start_line}-{item.end_line}"
        return self._safe(location)

    def _omitted(self, count: int, english: str, chinese: str) -> str:
        if self._language is CapabilityRuleLanguage.ZH:
            return f"     ... 因展示上限省略 {count} {chinese}"
        return f"     ... {count} {english} omitted by display limit"

    def _safe(self, value: str) -> str:
        safe = sanitize_untrusted_text(value, redactor=self._redactor)
        limit = self._limits.max_text_characters
        if len(safe) <= limit:
            return safe
        return f"{safe[:limit]}… [truncated from {len(safe)} chars]"

    @staticmethod
    def _ordered_findings(
        result: CapabilityAssessmentResult,
    ) -> tuple[CapabilityRuleFinding, ...]:
        return tuple(
            sorted(
                result.rules.findings,
                key=lambda item: (
                    -_severity_rank(item.severity),
                    -item.score,
                    item.rule_id,
                    item.finding_id,
                ),
            )
        )

    @staticmethod
    def _severity_counts(
        findings: tuple[CapabilityRuleFinding, ...],
    ) -> dict[Severity, int]:
        counts = {item: 0 for item in Severity}
        for finding in findings:
            counts[finding.severity] += 1
        return counts

    @staticmethod
    def _confidence_counts(
        findings: tuple[CapabilityRuleFinding, ...],
    ) -> dict[EvidenceConfidence, int]:
        counts = {item: 0 for item in EvidenceConfidence}
        for finding in findings:
            counts[finding.confidence] += 1
        return counts

    @staticmethod
    def _highest_severity(
        findings: tuple[CapabilityRuleFinding, ...],
    ) -> Severity:
        return max(
            (finding.severity for finding in findings),
            key=_severity_rank,
            default=Severity.NONE,
        )

    @staticmethod
    def _severity_zh(severity: Severity) -> str:
        return {
            Severity.NONE: "无",
            Severity.LOW: "低",
            Severity.MEDIUM: "中",
            Severity.HIGH: "高",
            Severity.CRITICAL: "严重",
        }[severity]


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.NONE: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]

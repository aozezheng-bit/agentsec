"""Deterministic Text and canonical JSON delivery for Agent Manifests."""

# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from agentsec.application import AgentAnalysisResult
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.manifests import (
    AgentManifest,
    ManifestSourceReference,
    encode_agent_manifest_json,
)
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text


@dataclass(frozen=True, slots=True)
class ManifestTextLimits:
    """Human-output bounds applied independently to every Manifest section."""

    max_items_per_section: int = 100
    max_text_characters: int = 512

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_items_per_section, "max_items_per_section"),
            (self.max_text_characters, "max_text_characters"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{label} must be a positive integer")


class ManifestJsonRenderer:
    """Expose the existing canonical Agent Manifest JSON representation."""

    def render(self, manifest: AgentManifest) -> str:
        """Return the canonical deterministic Agent Manifest JSON artifact."""

        return encode_agent_manifest_json(manifest)


class ManifestTextRenderer:
    """Render a bounded developer-oriented Manifest report without source values."""

    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        redactor: SecretRedactor | None = None,
        limits: ManifestTextLimits | None = None,
    ) -> None:
        if not isinstance(language, CapabilityRuleLanguage):
            raise TypeError("language must be CapabilityRuleLanguage")
        self._language = language
        self._redactor = redactor or SecretRedactor()
        self._limits = limits or ManifestTextLimits()

    def render(self, analysis: AgentAnalysisResult) -> str:
        """Return deterministic ANSI-free Manifest text plus Stage Trace."""

        if not isinstance(analysis, AgentAnalysisResult):
            raise TypeError("Manifest text rendering requires AgentAnalysisResult")
        if self._language is CapabilityRuleLanguage.ZH:
            return self._render_zh(analysis)
        return self._render_en(analysis)

    def _render_en(self, analysis: AgentAnalysisResult) -> str:
        manifest = analysis.manifest
        lines = [
            "AgentSec Agent Manifest",
            f"Status: {'COMPLETE' if analysis.complete else 'INCOMPLETE'}",
            f"Agent: {self._safe(manifest.identity.agent_id)}",
            f"Framework: {self._safe(manifest.metadata.framework_display_name)}",
            "Policy: static declarations; report-only; runtime not verified",
            (
                "Summary: "
                f"sources={len(manifest.sources)} tools={len(manifest.tools.tools)} "
                f"permissions={len(manifest.permissions.permissions)} "
                f"controls={len(manifest.controls.controls)} "
                f"identities={len(manifest.runtime_identities.identities)} "
                f"relationships={len(manifest.relationships.relations)} "
                f"unknowns={len(manifest.unknowns)}"
            ),
            "",
            "Version Vector",
            f"  package: {analysis.versions.package}",
            f"  agent_manifest_schema: {analysis.versions.agent_manifest_schema}",
            f"  adapter: {manifest.metadata.adapter_version}",
            f"  capability_rule_pack: {analysis.versions.capability_rule_pack}",
            f"  capability_risk_model: {analysis.versions.capability_risk_model}",
            "",
            "Coverage",
            (
                "  "
                f"discovered={manifest.coverage.discovered_assets} "
                f"inspected={manifest.coverage.inspected_assets} "
                f"skipped={manifest.coverage.skipped_assets} "
                f"issues={len(manifest.coverage.issues)}"
            ),
        ]
        if not analysis.complete:
            lines.append(
                "  WARNING: Coverage is incomplete; this Manifest is not exhaustive."
            )
        lines.extend(("", "Stage Trace"))
        lines.extend(
            self._bounded_lines(
                (
                    f"  {stage.stage.value}: {stage.status.value} "
                    f"input={stage.input_items} output={stage.output_items}"
                    for stage in analysis.stages
                ),
                omitted_template="  ... {count} stage item(s) omitted by display limit",
            )
        )
        lines.extend(("", "Profile Resolution"))
        lines.extend(
            f"  {name}: {status}" for name, status in self._profile_rows(manifest)
        )
        lines.extend(("", "Sources"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(source.locator.scope.value)}:"
                f"{self._safe(source.locator.root_id)}:"
                f"{self._safe(source.locator.path)} "
                f"format={source.format.value} "
                f"sha256={source.content_sha256}"
                for source in manifest.sources
            )
        )
        lines.extend(("", "Effective Instructions"))
        lines.extend(self._references_section(manifest.instructions.effective_order))
        lines.extend(("", "Configuration Order"))
        lines.extend(self._references_section(manifest.configuration.effective_order))
        lines.extend(("", "Tools"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(tool.tool_id)} kind={tool.kind.value} "
                f"availability={tool.availability.value} "
                f"side_effects={','.join(item.value for item in tool.side_effects) or '-'} "
                f"parent={self._safe(tool.parent_tool_id) if tool.parent_tool_id else '-'} "
                f"source={self._reference(tool.sources[0])}"
                for tool in manifest.tools.tools
            )
        )
        lines.extend(("", "Permissions"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(item.permission_id)} action={item.action.value} "
                f"effect={item.effect.value} resource={item.resource.value} "
                f"scope={item.scope.value} "
                f"target={self._safe(item.target) if item.target else '-'} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.permissions.permissions
            )
        )
        lines.extend(("", "Controls"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(item.control_id)} kind={item.kind.value} "
                f"state={item.state.value} "
                f"target={self._safe(item.target) if item.target else '-'} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.controls.controls
            )
        )
        lines.extend(("", "Runtime Identities"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(item.identity_id)} principal={item.principal_kind.value} "
                f"authentication={item.authentication.value} "
                f"environment={item.environment.value} "
                f"privileged={item.privileged} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.runtime_identities.identities
            )
        )
        lines.extend(("", "Relationships"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(item.relation_id)} kind={item.kind.value} "
                f"target={self._safe(item.target_id)} state={item.state.value} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.relationships.relations
            )
        )
        lines.extend(("", "Explicit Unknowns"))
        lines.extend(
            self._bounded_lines(
                "  "
                f"{self._safe(item.unknown_id)} dimension={item.dimension.value} "
                f"reason={item.reason.value} "
                f"field={self._safe(item.field) if item.field else '-'} "
                f"source={self._reference(item.sources[0]) if item.sources else '-'}"
                for item in manifest.unknowns
            )
        )
        lines.extend(
            (
                "",
                "Boundary",
                "  This report does not prove that the Agent is globally safe.",
                "  Declared capability does not prove runtime availability or authorization.",
            )
        )
        return "\n".join(lines) + "\n"

    def _render_zh(self, analysis: AgentAnalysisResult) -> str:
        manifest = analysis.manifest
        status = "完整" if analysis.complete else "不完整"
        lines = [
            "AgentSec Agent 清单",
            f"状态：{status}",
            f"Agent：{self._safe(manifest.identity.agent_id)}",
            f"框架：{self._safe(manifest.metadata.framework_display_name)}",
            "策略：静态声明分析；仅报告；未验证运行时能力",
            (
                "摘要："
                f"来源={len(manifest.sources)} 工具={len(manifest.tools.tools)} "
                f"权限={len(manifest.permissions.permissions)} "
                f"控制={len(manifest.controls.controls)} "
                f"身份={len(manifest.runtime_identities.identities)} "
                f"关系={len(manifest.relationships.relations)} "
                f"Unknown={len(manifest.unknowns)}"
            ),
            "",
            "版本向量",
            f"  package：{analysis.versions.package}",
            f"  agent_manifest_schema：{analysis.versions.agent_manifest_schema}",
            f"  adapter：{manifest.metadata.adapter_version}",
            f"  capability_rule_pack：{analysis.versions.capability_rule_pack}",
            f"  capability_risk_model：{analysis.versions.capability_risk_model}",
            "",
            "Coverage",
            (
                "  "
                f"发现={manifest.coverage.discovered_assets} "
                f"已检查={manifest.coverage.inspected_assets} "
                f"跳过={manifest.coverage.skipped_assets} "
                f"问题={len(manifest.coverage.issues)}"
            ),
        ]
        if not analysis.complete:
            lines.append("  警告：Coverage 不完整，本清单不是穷尽结果。")
        lines.extend(("", "阶段轨迹"))
        lines.extend(
            self._bounded_lines(
                (
                    f"  {stage.stage.value}：{stage.status.value} "
                    f"输入={stage.input_items} 输出={stage.output_items}"
                    for stage in analysis.stages
                ),
                omitted_template="  ... 因展示上限省略 {count} 个阶段项",
            )
        )
        lines.extend(("", "Profile Resolution"))
        lines.extend(
            f"  {name}：{status}" for name, status in self._profile_rows(manifest)
        )
        section_map = (
            ("来源", self._source_lines(manifest)),
            (
                "有效指令",
                self._references_section(manifest.instructions.effective_order),
            ),
            (
                "配置顺序",
                self._references_section(manifest.configuration.effective_order),
            ),
            ("工具", self._tool_lines(manifest)),
            ("权限", self._permission_lines(manifest)),
            ("控制", self._control_lines(manifest)),
            ("运行时身份", self._identity_lines(manifest)),
            ("关系", self._relationship_lines(manifest)),
            ("显式 Unknown", self._unknown_lines(manifest)),
        )
        for title, section_lines in section_map:
            lines.extend(("", title, *section_lines))
        lines.extend(
            (
                "",
                "边界说明",
                "  本报告不代表该 Agent 已被证明为全局安全。",
                "  声明的能力不代表运行时一定可用或已经获得授权。",
            )
        )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _profile_rows(manifest: AgentManifest) -> tuple[tuple[str, str], ...]:
        return (
            ("identity", manifest.identity.resolution.value),
            ("instructions", manifest.instructions.resolution.value),
            ("configuration", manifest.configuration.resolution.value),
            ("tools", manifest.tools.resolution.value),
            ("permissions", manifest.permissions.resolution.value),
            ("controls", manifest.controls.resolution.value),
            ("runtime_identities", manifest.runtime_identities.resolution.value),
            ("relationships", manifest.relationships.resolution.value),
        )

    def _source_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(source.locator.scope.value)}:"
                f"{self._safe(source.locator.root_id)}:"
                f"{self._safe(source.locator.path)} "
                f"format={source.format.value} sha256={source.content_sha256}"
                for source in manifest.sources
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _tool_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.tool_id)} kind={item.kind.value} "
                f"availability={item.availability.value} "
                f"parent={self._safe(item.parent_tool_id) if item.parent_tool_id else '-'} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.tools.tools
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _permission_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.permission_id)} action={item.action.value} "
                f"effect={item.effect.value} "
                f"target={self._safe(item.target) if item.target else '-'} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.permissions.permissions
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _control_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.control_id)} kind={item.kind.value} "
                f"state={item.state.value} "
                f"target={self._safe(item.target) if item.target else '-'} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.controls.controls
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _identity_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.identity_id)} principal={item.principal_kind.value} "
                f"authentication={item.authentication.value} "
                f"environment={item.environment.value} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.runtime_identities.identities
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _relationship_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.relation_id)} kind={item.kind.value} "
                f"target={self._safe(item.target_id)} state={item.state.value} "
                f"source={self._reference(item.sources[0])}"
                for item in manifest.relationships.relations
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _unknown_lines(self, manifest: AgentManifest) -> list[str]:
        return self._bounded_lines(
            (
                "  "
                f"{self._safe(item.unknown_id)} dimension={item.dimension.value} "
                f"reason={item.reason.value} "
                f"field={self._safe(item.field) if item.field else '-'}"
                for item in manifest.unknowns
            ),
            omitted_template="  ... 因展示上限省略 {count} 项",
        )

    def _references_section(
        self,
        references: tuple[ManifestSourceReference, ...],
    ) -> list[str]:
        if not references:
            return ["  -"]
        return self._bounded_lines(
            (f"  {self._reference(reference)}" for reference in references),
            omitted_template=(
                "  ... 因展示上限省略 {count} 项"
                if self._language is CapabilityRuleLanguage.ZH
                else "  ... {count} item(s) omitted by display limit"
            ),
        )

    def _bounded_lines(
        self,
        values: Iterable[str],
        *,
        omitted_template: str | None = None,
    ) -> list[str]:
        items = list(values)
        visible = items[: self._limits.max_items_per_section]
        omitted = len(items) - len(visible)
        if omitted:
            template = (
                omitted_template or "  ... {count} item(s) omitted by display limit"
            )
            visible.append(template.format(count=omitted))
        return visible or ["  -"]

    def _reference(self, reference: ManifestSourceReference) -> str:
        location = (
            f"{reference.start_line}-{reference.end_line}"
            if reference.start_line is not None
            else "-"
        )
        return self._safe(
            f"{reference.locator.scope.value}:{reference.locator.root_id}:"
            f"{reference.locator.path}"
            f"{reference.field_path or ''}:{location}"
        )

    def _safe(self, value: str) -> str:
        safe = sanitize_untrusted_text(value, redactor=self._redactor)
        return safe[: self._limits.max_text_characters]

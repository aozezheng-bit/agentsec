"""Deterministic JSON and bounded bilingual Text for calibration reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.versioning import CALIBRATION_REPORT_OUTPUT_VERSION

from .evaluation import (
    CALIBRATION_REPORT_SCHEMA_FILENAME,
    CalibrationReport,
    CalibrationRuleMetrics,
)


class CalibrationJsonRenderer:
    def render(self, report: CalibrationReport) -> str:
        if not isinstance(report, CalibrationReport):
            raise TypeError("calibration JSON renderer requires CalibrationReport")
        return (
            json.dumps(
                report.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


@dataclass(frozen=True, slots=True)
class CalibrationTextLimits:
    max_rules: int = 100
    max_cases: int = 50

    def __post_init__(self) -> None:
        if self.max_rules < 1 or self.max_cases < 1:
            raise ValueError("calibration Text limits must be positive")


class CalibrationTextRenderer:
    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        limits: CalibrationTextLimits | None = None,
    ) -> None:
        self._language = language
        self._limits = limits or CalibrationTextLimits()

    def render(self, report: CalibrationReport) -> str:
        if not isinstance(report, CalibrationReport):
            raise TypeError("calibration Text renderer requires CalibrationReport")
        return (
            self._render_zh(report)
            if self._language.value == "zh"
            else self._render_en(report)
        )

    def _render_en(self, report: CalibrationReport) -> str:
        s = report.summary
        m = s.micro
        lines = [
            "AgentSec Capability Calibration",
            f"Status: {report.status.upper()}",
            f"Corpus: {report.corpus_id}",
            f"Evaluator: {report.evaluator_id} {report.evaluator_version}",
            "Policy: report-only; CI blocking disabled; "
            "Hard Gate eligibility undecided",
            "",
            "Summary",
            f"  Cases: {s.total_cases}",
            f"  Expectations: {s.total_expectations}",
            f"  Rules: {s.evaluated_rules}",
            (
                "  Confusion: "
                f"TP={m.confusion.true_positive} FP={m.confusion.false_positive} "
                f"FN={m.confusion.false_negative} TN={m.confusion.true_negative}"
            ),
            f"  Micro precision: {_rate(m.precision)}",
            f"  Micro recall: {_rate(m.recall)}",
            f"  Micro F1: {_rate(m.f1)}",
            f"  Macro precision: {_rate(s.macro_precision)}",
            f"  Macro recall: {_rate(s.macro_recall)}",
            f"  Macro F1: {_rate(s.macro_f1)}",
            f"  Correlation agreement: {_rate(s.correlation_agreement)}",
            f"  Confidence agreement: {_rate(s.confidence_agreement)}",
            f"  Evidence completeness: {_rate(s.evidence_completeness)}",
            f"  Coverage visibility: {_rate(s.coverage_visibility)}",
            f"  Unknown visibility: {_rate(s.unknown_visibility)}",
            f"  Rule failures: {s.failures}",
            f"  Duplicate Findings: {s.duplicate_findings}",
            f"  Insufficient-sample Rules: {s.insufficient_sample_rules}",
            "",
            "Rule Metrics",
        ]
        lines.extend(self._rule_lines(report.rules, chinese=False))
        lines.extend(("", "Limitations"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    def _render_zh(self, report: CalibrationReport) -> str:
        s = report.summary
        m = s.micro
        lines = [
            "AgentSec 能力校准报告",
            f"状态：{'完整' if report.status == 'complete' else '不完整'}",
            f"语料：{report.corpus_id}",
            f"评测器：{report.evaluator_id} {report.evaluator_version}",
            "策略：仅报告；不启用 CI 阻断；尚未决定 Hard Gate 资格",
            "",
            "摘要",
            f"  Cases：{s.total_cases}",
            f"  Expectations：{s.total_expectations}",
            f"  Rules：{s.evaluated_rules}",
            (
                "  混淆矩阵："
                f"TP={m.confusion.true_positive} FP={m.confusion.false_positive} "
                f"FN={m.confusion.false_negative} TN={m.confusion.true_negative}"
            ),
            f"  Micro Precision：{_rate(m.precision)}",
            f"  Micro Recall：{_rate(m.recall)}",
            f"  Micro F1：{_rate(m.f1)}",
            f"  Macro Precision：{_rate(s.macro_precision)}",
            f"  Macro Recall：{_rate(s.macro_recall)}",
            f"  Macro F1：{_rate(s.macro_f1)}",
            f"  Correlation 一致率：{_rate(s.correlation_agreement)}",
            f"  Confidence 一致率：{_rate(s.confidence_agreement)}",
            f"  Evidence 完整率：{_rate(s.evidence_completeness)}",
            f"  Coverage 可见率：{_rate(s.coverage_visibility)}",
            f"  Unknown 可见率：{_rate(s.unknown_visibility)}",
            f"  Rule Failures：{s.failures}",
            f"  重复 Findings：{s.duplicate_findings}",
            f"  样本不足规则：{s.insufficient_sample_rules}",
            "",
            "逐规则指标",
        ]
        lines.extend(self._rule_lines(report.rules, chinese=True))
        lines.extend(("", "限制"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    def _rule_lines(
        self,
        rules: tuple[CalibrationRuleMetrics, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = rules[: self._limits.max_rules]
        lines = [
            (
                f"  {item.rule_id}: 样本={item.samples} "
                f"P={_rate(item.precision)} R={_rate(item.recall)} "
                f"F1={_rate(item.f1)} "
                f"样本充分={'是' if item.sufficient_sample_size else '否'}"
                if chinese
                else f"  {item.rule_id}: samples={item.samples} "
                f"P={_rate(item.precision)} R={_rate(item.recall)} "
                f"F1={_rate(item.f1)} "
                f"sufficient={'yes' if item.sufficient_sample_size else 'no'}"
            )
            for item in visible
        ]
        omitted = len(rules) - len(visible)
        if omitted:
            lines.append(
                f"  ... 省略 {omitted} 条规则"
                if chinese
                else f"  ... {omitted} Rule(s) omitted"
            )
        return lines


def export_calibration_report_json_schema(output_directory: Path) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    path = output_directory / CALIBRATION_REPORT_SCHEMA_FILENAME
    schema: dict[str, Any] = CalibrationReport.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-calibration-report-output-version"] = (
        CALIBRATION_REPORT_OUTPUT_VERSION
    )
    path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"

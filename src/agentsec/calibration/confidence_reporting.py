"""Bilingual Text/JSON delivery for P2-CAL-03 Confidence calibration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.versioning import CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION

from .confidence_models import (
    CONFIDENCE_REPORT_SCHEMA_FILENAME,
    ConfidenceAgreementMetrics,
    ConfidenceCalibrationReport,
    ConfidenceRuleMetrics,
)


class ConfidenceCalibrationJsonRenderer:
    def render(self, report: ConfidenceCalibrationReport) -> str:
        if not isinstance(report, ConfidenceCalibrationReport):
            raise TypeError(
                "Confidence JSON renderer requires ConfidenceCalibrationReport"
            )
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
class ConfidenceCalibrationTextLimits:
    max_rules: int = 100
    max_cases: int = 50

    def __post_init__(self) -> None:
        if self.max_rules < 1 or self.max_cases < 1:
            raise ValueError("Confidence Text limits must be positive")


class ConfidenceCalibrationTextRenderer:
    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        limits: ConfidenceCalibrationTextLimits | None = None,
    ) -> None:
        self._language = language
        self._limits = limits or ConfidenceCalibrationTextLimits()

    def render(self, report: ConfidenceCalibrationReport) -> str:
        if not isinstance(report, ConfidenceCalibrationReport):
            raise TypeError(
                "Confidence Text renderer requires ConfidenceCalibrationReport"
            )
        return (
            self._render_zh(report)
            if self._language.value == "zh"
            else self._render_en(report)
        )

    def _render_en(self, report: ConfidenceCalibrationReport) -> str:
        summary = report.summary
        reviewer = summary.reviewer_agreement
        emitted = summary.expected_vs_emitted
        lines = [
            "AgentSec Evidence Confidence Calibration",
            f"Status: {report.status.upper()}",
            f"Corpus: {report.corpus_id}",
            f"Reviewers: {', '.join(report.reviewer_ids)}",
            "Policy: report-only; CI blocking disabled; Hard Gate eligibility "
            "undecided",
            "",
            "Summary",
            f"  Cases with Findings: {summary.total_cases}",
            f"  Reviewer labels: {summary.total_reviews}",
            f"  Reviewer agreement: {_rate(reviewer.agreement_rate)}",
            f"  Cohen's Kappa: {_rate(reviewer.cohens_kappa)}",
            f"  Expected vs emitted agreement: {_rate(emitted.agreement_rate)}",
            f"  Expected vs emitted Kappa: {_rate(emitted.cohens_kappa)}",
            f"  Insufficient sample groups: {summary.insufficient_sample_items}",
            "",
            "Reviewer Confidence Grade Matrix (expected rows x observed columns)",
        ]
        lines.extend(self._matrix_lines(reviewer, chinese=False))
        lines.extend(("", "Reviewer Pair Metrics"))
        lines.extend(
            f"  {item.reviewer_a} vs {item.reviewer_b}: "
            f"items={item.items} agreement={_rate(item.agreement_rate)} "
            f"kappa={_rate(item.cohens_kappa)}"
            for item in report.pairwise
        )
        lines.extend(("", "Rule / Correlation Metrics"))
        lines.extend(self._rule_lines(report.by_rule, chinese=False))
        lines.extend(("", "Limitations"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    def _render_zh(self, report: ConfidenceCalibrationReport) -> str:
        summary = report.summary
        reviewer = summary.reviewer_agreement
        emitted = summary.expected_vs_emitted
        lines = [
            "AgentSec Evidence Confidence 校准",
            f"状态：{'完整' if report.status == 'complete' else '不完整'}",
            f"语料：{report.corpus_id}",
            f"评审人：{'、'.join(report.reviewer_ids)}",
            "策略：仅报告；不启用 CI 阻断；尚未决定 Hard Gate 资格",
            "",
            "摘要",
            f"  有 Finding 的 Cases：{summary.total_cases}",
            f"  Reviewer Labels：{summary.total_reviews}",
            f"  Reviewer 一致率：{_rate(reviewer.agreement_rate)}",
            f"  Cohen's Kappa：{_rate(reviewer.cohens_kappa)}",
            f"  Expected / Emitted 一致率：{_rate(emitted.agreement_rate)}",
            f"  Expected / Emitted Kappa：{_rate(emitted.cohens_kappa)}",
            f"  样本不足分组：{summary.insufficient_sample_items}",
            "",
            "Reviewer Confidence Grade Matrix（Expected 行 x Observed 列）",
        ]
        lines.extend(self._matrix_lines(reviewer, chinese=True))
        lines.extend(("", "Reviewer Pair 指标"))
        lines.extend(
            f"  {item.reviewer_a} vs {item.reviewer_b}："
            f"样本={item.items} 一致率={_rate(item.agreement_rate)} "
            f"Kappa={_rate(item.cohens_kappa)}"
            for item in report.pairwise
        )
        lines.extend(("", "Rule / Correlation 指标"))
        lines.extend(self._rule_lines(report.by_rule, chinese=True))
        lines.extend(("", "限制"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _matrix_lines(
        metrics: ConfidenceAgreementMetrics,
        *,
        chinese: bool,
    ) -> list[str]:
        # The renderer only receives the validated report model at the public
        # boundary; this helper emits counts only and never raw fixture values.
        matrix = metrics.grade_matrix
        header = "  expected/observed: A B C D"
        if chinese:
            header = "  Expected/Observed：A B C D"
        lines = [header]
        for row in matrix:
            values = (
                row.observed_a,
                row.observed_b,
                row.observed_c,
                row.observed_d,
            )
            prefix = (
                f"  {row.expected.value}:"
                if not chinese
                else f"  {row.expected.value}："
            )
            lines.append(prefix + " " + " ".join(str(value) for value in values))
        return lines

    def _rule_lines(
        self,
        rules: tuple[ConfidenceRuleMetrics, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = rules[: self._limits.max_rules]
        lines = [
            (
                f"  {item.rule_id} [{item.correlation.value}]："
                f"样本={item.items} 一致率={_rate(item.reviewer_agreement_rate)} "
                f"Kappa={_rate(item.cohens_kappa)}"
                if chinese
                else f"  {item.rule_id} [{item.correlation.value}]: "
                f"items={item.items} agreement={_rate(item.reviewer_agreement_rate)} "
                f"kappa={_rate(item.cohens_kappa)}"
            )
            for item in visible
        ]
        omitted = len(rules) - len(visible)
        if omitted:
            lines.append(
                f"  ... 省略 {omitted} 个分组"
                if chinese
                else f"  ... {omitted} group(s) omitted"
            )
        return lines


def export_confidence_calibration_report_json_schema(output_directory: Path) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    path = output_directory / CONFIDENCE_REPORT_SCHEMA_FILENAME
    schema: dict[str, Any] = ConfidenceCalibrationReport.model_json_schema(
        mode="serialization"
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-confidence-report-output-version"] = (
        CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION
    )
    path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"

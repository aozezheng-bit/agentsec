"""Bilingual Text/JSON delivery for the P2-CAL-04 report."""

from __future__ import annotations

import json
from dataclasses import dataclass

from agentsec.capability_rules import CapabilityRuleLanguage

from .adjudication_models import (
    CalibrationAdjudicationReport,
    GateCandidateAssessment,
    RuleCalibrationAssessment,
)


class CalibrationAdjudicationJsonRenderer:
    def render(self, report: CalibrationAdjudicationReport) -> str:
        if not isinstance(report, CalibrationAdjudicationReport):
            raise TypeError(
                "adjudication JSON renderer requires CalibrationAdjudicationReport"
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
class CalibrationAdjudicationTextLimits:
    max_rules: int = 100
    max_gates: int = 10

    def __post_init__(self) -> None:
        if self.max_rules < 1 or self.max_gates < 1:
            raise ValueError("adjudication Text limits must be positive")


class CalibrationAdjudicationTextRenderer:
    def __init__(
        self,
        *,
        language: CapabilityRuleLanguage = CapabilityRuleLanguage.EN,
        limits: CalibrationAdjudicationTextLimits | None = None,
    ) -> None:
        self._language = language
        self._limits = limits or CalibrationAdjudicationTextLimits()

    def render(self, report: CalibrationAdjudicationReport) -> str:
        if not isinstance(report, CalibrationAdjudicationReport):
            raise TypeError(
                "adjudication Text renderer requires CalibrationAdjudicationReport"
            )
        return (
            self._render_zh(report)
            if self._language.value == "zh"
            else self._render_en(report)
        )

    def _render_en(self, report: CalibrationAdjudicationReport) -> str:
        summary = report.summary
        lines = [
            "AgentSec Calibration Adjudication and Gate Candidate Report",
            f"Status: {report.status.upper()}",
            f"Corpus: {report.corpus_id}",
            f"Reviewers: {', '.join(report.reviewer_ids)}",
            "Policy: report-only; no Rule publication; Hard Gate eligibility undecided",
            "",
            "Adjudication Summary",
            f"  Expectations: {summary.total_expectations}",
            f"  Reviewer labels: {summary.total_reviews}",
            f"  Consensus: {summary.consensus_count}",
            f"  Unresolved: {summary.unresolved_count}",
            f"  Adjudication required: {summary.adjudication_required_count}",
            f"  Adjudication completed: {summary.adjudication_completed_count}",
            "  Classification agreement: "
            f"{_rate(summary.classification_agreement_rate)}",
            f"  Category agreement: {_rate(summary.category_agreement_rate)}",
            f"  Disposition agreement: {_rate(summary.disposition_agreement_rate)}",
            "",
            "Rule Calibration and Tuning",
        ]
        lines.extend(self._rule_lines(report.by_rule, chinese=False))
        lines.extend(("", "Gate Candidates"))
        lines.extend(self._gate_lines(report.gate_candidates, chinese=False))
        lines.extend(("", "Limitations"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    def _render_zh(self, report: CalibrationAdjudicationReport) -> str:
        summary = report.summary
        lines = [
            "AgentSec 校准裁决与 Hard Gate 候选报告",
            f"状态：{'完整' if report.status == 'complete' else '不完整'}",
            f"语料：{report.corpus_id}",
            f"评审人：{'、'.join(report.reviewer_ids)}",
            "策略：仅报告；不发布规则；尚未决定 Hard Gate 资格",
            "",
            "裁决摘要",
            f"  Expectations：{summary.total_expectations}",
            f"  Reviewer Labels：{summary.total_reviews}",
            f"  达成共识：{summary.consensus_count}",
            f"  未解决：{summary.unresolved_count}",
            f"  需要裁决：{summary.adjudication_required_count}",
            f"  已完成裁决：{summary.adjudication_completed_count}",
            f"  Classification 一致率：{_rate(summary.classification_agreement_rate)}",
            f"  Category 一致率：{_rate(summary.category_agreement_rate)}",
            f"  Disposition 一致率：{_rate(summary.disposition_agreement_rate)}",
            "",
            "Rule 校准与调优建议",
        ]
        lines.extend(self._rule_lines(report.by_rule, chinese=True))
        lines.extend(("", "Hard Gate 候选"))
        lines.extend(self._gate_lines(report.gate_candidates, chinese=True))
        lines.extend(("", "限制"))
        lines.extend(f"  {item}" for item in report.limitations)
        return "\n".join(lines) + "\n"

    def _rule_lines(
        self,
        rules: tuple[RuleCalibrationAssessment, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = rules[: self._limits.max_rules]
        lines = [
            (
                f"  {item.rule_id}：样本={item.samples} TP={item.true_positive} "
                f"FP={item.false_positive} FN={item.false_negative} "
                f"P={_rate(item.precision)} R={_rate(item.recall)} "
                f"建议={item.recommended_disposition.value}"
                if chinese
                else f"  {item.rule_id}: samples={item.samples} "
                f"TP={item.true_positive} FP={item.false_positive} "
                f"FN={item.false_negative} P={_rate(item.precision)} "
                f"R={_rate(item.recall)} recommendation="
                f"{item.recommended_disposition.value}"
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

    def _gate_lines(
        self,
        gates: tuple[GateCandidateAssessment, ...],
        *,
        chinese: bool,
    ) -> list[str]:
        visible = gates[: self._limits.max_gates]
        lines = [
            (
                f"  {item.gate_id} [{item.floor.value}]：状态={item.status.value} "
                f"样本={item.positive_samples}/{item.negative_samples} "
                f"P={_rate(item.precision)} R={_rate(item.recall)} "
                f"原因={','.join(item.reason_codes)}"
                if chinese
                else f"  {item.gate_id} [{item.floor.value}]: "
                f"status={item.status.value} "
                f"samples={item.positive_samples}/{item.negative_samples} "
                f"P={_rate(item.precision)} R={_rate(item.recall)} "
                f"reasons={','.join(item.reason_codes)}"
            )
            for item in visible
        ]
        omitted = len(gates) - len(visible)
        if omitted:
            lines.append(
                f"  ... 省略 {omitted} 个候选"
                if chinese
                else f"  ... {omitted} Gate candidate(s) omitted"
            )
        return lines


def _rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"

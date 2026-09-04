"""Combined, Chinese-first Homi report rendering.

This module combines an already-sanitized Homi Pilot report with a Capability
Diff report. It is presentation-only: it does not rescan the workspace,
execute scanned content, or grant any authority to recommendations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Literal, cast

from agentsec.risk.context import (
    OperationContextSet,
    canonical_operation_context_sha256,
)
from agentsec.risk.context_rules import (
    canonical_context_risk_sha256,
    decode_context_risk_json,
)
from agentsec.risk.runtime_attestation import decode_evidence_reconciliation_json

HOMI_COMBINED_REPORT_FORMAT: Literal["agentsec-homi-combined-report"] = (
    "agentsec-homi-combined-report"
)
HOMI_COMBINED_REPORT_VERSION = "0.1.0"


class HomiCombinedReportError(ValueError):
    """Raised when combined Homi report inputs are invalid."""


@dataclass(frozen=True, slots=True)
class HomiRecommendation:
    """Advisory remediation item derived from trusted report metadata."""

    priority: Literal["critical", "high", "medium", "low"]
    title: str
    rationale: str
    actions: tuple[str, ...]
    source_ids: tuple[str, ...]
    generated_by: Literal["deterministic"] = "deterministic"
    authority: Literal["advisory"] = "advisory"

    def to_dict(self) -> dict[str, object]:
        return {
            "priority": self.priority,
            "title": self.title,
            "rationale": self.rationale,
            "actions": list(self.actions),
            "source_ids": list(self.source_ids),
            "generated_by": self.generated_by,
            "authority": self.authority,
        }


@dataclass(frozen=True, slots=True)
class HomiCombinedReport:
    """A bounded combined report containing Pilot, Diff, and advisory actions."""

    pilot_report: dict[str, Any]
    pilot_report_sha256: str
    diff_report: dict[str, Any] | None
    diff_report_sha256: str | None
    score_report: dict[str, Any] | None
    score_report_sha256: str | None
    function_summary: tuple[dict[str, object], ...]
    recommendations: tuple[HomiRecommendation, ...]
    operationality_report: dict[str, Any] | None = None
    operationality_report_sha256: str | None = None
    posture_report: dict[str, Any] | None = None
    posture_report_sha256: str | None = None
    calibration_report: dict[str, Any] | None = None
    calibration_report_sha256: str | None = None
    operation_context_report: dict[str, Any] | None = None
    operation_context_report_sha256: str | None = None
    context_risk_report: dict[str, Any] | None = None
    context_risk_report_sha256: str | None = None
    risk_score_report: dict[str, Any] | None = None
    risk_score_report_sha256: str | None = None
    risk_state_report: dict[str, Any] | None = None
    risk_state_report_sha256: str | None = None
    runtime_reconciliation_report: dict[str, Any] | None = None
    runtime_reconciliation_report_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "format": HOMI_COMBINED_REPORT_FORMAT,
            "format_version": HOMI_COMBINED_REPORT_VERSION,
            "pilot_report": self.pilot_report,
            "pilot_report_sha256": self.pilot_report_sha256,
            "diff_report": self.diff_report,
            "diff_report_sha256": self.diff_report_sha256,
            "score_report": self.score_report,
            "score_report_sha256": self.score_report_sha256,
            "function_summary": list(self.function_summary),
            "recommendations": [item.to_dict() for item in self.recommendations],
            "operationality_report": self.operationality_report,
            "operationality_report_sha256": self.operationality_report_sha256,
            "posture_report": self.posture_report,
            "posture_report_sha256": self.posture_report_sha256,
            "calibration_report": self.calibration_report,
            "calibration_report_sha256": self.calibration_report_sha256,
            "operation_context_report": self.operation_context_report,
            "operation_context_report_sha256": self.operation_context_report_sha256,
            "context_risk_report": self.context_risk_report,
            "context_risk_report_sha256": self.context_risk_report_sha256,
            "risk_score_report": self.risk_score_report,
            "risk_score_report_sha256": self.risk_score_report_sha256,
            "risk_state_report": self.risk_state_report,
            "risk_state_report_sha256": self.risk_state_report_sha256,
            "runtime_reconciliation_report": self.runtime_reconciliation_report,
            "runtime_reconciliation_report_sha256": (
                self.runtime_reconciliation_report_sha256
            ),
            "runtime_evidence": {
                "supplied": self.runtime_reconciliation_report is not None,
                "verified": (
                    self.runtime_reconciliation_report is not None
                    and self.runtime_reconciliation_report.get("runtime_verified")
                    is True
                ),
                "current_posture_eligible": (
                    self.runtime_reconciliation_report is not None
                    and self.runtime_reconciliation_report.get(
                        "current_posture_eligible"
                    )
                    is True
                ),
            },
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "policy_authority": False,
                "ci_blocked": False,
                "recommendations_are_advisory": True,
                "llm_authority": False,
            },
        }


def build_homi_combined_report(
    pilot_path: Path,
    diff_path: Path | None = None,
    score_path: Path | None = None,
) -> HomiCombinedReport:
    """Load sanitized Homi artifacts and build one combined report."""

    pilot, pilot_digest = _read_pilot(pilot_path)
    diff: dict[str, Any] | None = None
    diff_digest: str | None = None
    if diff_path is not None:
        diff, diff_digest = _read_diff(diff_path)
    score: dict[str, Any] | None = None
    score_digest: str | None = None
    if score_path is not None:
        score, score_digest = _read_score(score_path)
    operationality, operationality_digest = _read_optional_sidecar(
        pilot_path,
        pilot_digest,
        "homi-operationality.json",
        "agentsec-homi-operationality",
    )
    posture, posture_digest = _read_optional_sidecar(
        pilot_path,
        pilot_digest,
        "homi-posture.json",
        "agentsec-homi-posture",
    )
    calibration, calibration_digest = _read_optional_sidecar(
        pilot_path,
        pilot_digest,
        "homi-calibration.json",
        "agentsec-homi-calibration",
    )
    risk_state, risk_state_digest = _read_optional_sidecar(
        pilot_path,
        pilot_digest,
        "homi-risk-state.json",
        "agentsec-homi-risk-state",
    )
    _validate_report_only_risk_state(risk_state)
    operation_context, operation_context_digest = _read_optional_sidecar(
        pilot_path,
        pilot_digest,
        "homi-operation-context.json",
        "agentsec-homi-operation-context-extraction",
    )
    _validate_report_only_operation_context(operation_context)
    context_risk, context_risk_digest = _read_context_risk_sidecar(
        pilot_path,
        operation_context,
    )
    risk_score, risk_score_digest = _read_context_risk_score_sidecar(
        pilot_path,
        operation_context,
        context_risk,
    )
    runtime_reconciliation, runtime_reconciliation_digest = (
        _read_runtime_reconciliation_sidecar(
            pilot_path,
            pilot_digest,
            operation_context,
            context_risk,
        )
    )
    return HomiCombinedReport(
        pilot_report=pilot,
        pilot_report_sha256=pilot_digest,
        diff_report=diff,
        diff_report_sha256=diff_digest,
        score_report=score,
        score_report_sha256=score_digest,
        function_summary=build_homi_function_summary(pilot),
        recommendations=build_homi_recommendations(
            pilot,
            diff,
            calibration,
            runtime_reconciliation,
        ),
        operationality_report=operationality,
        operationality_report_sha256=operationality_digest,
        posture_report=posture,
        posture_report_sha256=posture_digest,
        calibration_report=calibration,
        calibration_report_sha256=calibration_digest,
        risk_state_report=risk_state,
        risk_state_report_sha256=risk_state_digest,
        operation_context_report=operation_context,
        operation_context_report_sha256=operation_context_digest,
        context_risk_report=context_risk,
        context_risk_report_sha256=context_risk_digest,
        risk_score_report=risk_score,
        risk_score_report_sha256=risk_score_digest,
        runtime_reconciliation_report=runtime_reconciliation,
        runtime_reconciliation_report_sha256=runtime_reconciliation_digest,
    )


def build_homi_function_summary(
    pilot: dict[str, Any],
) -> tuple[dict[str, object], ...]:
    """Describe declared Agent functions instead of reporting only a count."""

    descriptions = {
        "external_network_read": (
            "读取或搜索外部网络信息，可能把 Agent 行为延伸到工作区之外。"
        ),
        "external_message_send": "向外部消息渠道发送内容，可能产生外部副作用。",
        "proactive": "规范鼓励 Agent 主动检查、提醒或采取行动。",
        "memory_persistence": "通过记忆文件保存跨会话信息，形成持续性行为上下文。",
        "secret_access": "声明可接触敏感信息或凭据相关内容，需要最小权限和脱敏控制。",
        "ssh": "记录 SSH 或远程主机使用信息，可能连接到外部基础设施。",
        "oauth": "声明 OAuth 或授权相关能力，需要单独核验实际授权范围。",
        "mcp": "声明 MCP 工具或服务接入，需要单独核验运行时注册表。",
        "camera": "声明摄像头或图像采集能力，涉及隐私和设备权限。",
        "tts": "声明语音合成或播报能力，可能产生本地或外部输出。",
        "heartbeat": "通过心跳清单表达周期性检查或主动任务意图。",
        "user_privacy": "包含用户上下文和隐私相关信息，需要限制共享范围。",
    }
    labels = {
        "external_network_read": "外部网络读取",
        "external_message_send": "外部消息发送",
        "proactive": "主动行为",
        "memory_persistence": "长期记忆",
        "secret_access": "敏感信息访问",
        "ssh": "远程主机 / SSH",
        "oauth": "OAuth 授权",
        "mcp": "MCP 工具接入",
        "camera": "摄像头采集",
        "tts": "语音输出",
        "heartbeat": "周期性心跳",
        "user_privacy": "用户隐私上下文",
    }
    items: list[dict[str, object]] = []
    for capability in pilot.get("capabilities", []):
        if not isinstance(capability, dict):
            continue
        signal_id = capability.get("signal_id")
        if not isinstance(signal_id, str) or not signal_id:
            continue
        if signal_id in descriptions:
            key = signal_id
        elif any(token in signal_id for token in ("network", "web", "calendar")):
            key = "external_network_read"
        elif any(token in signal_id for token in ("message", "email", "tweet")):
            key = "external_message_send"
        elif "memory" in signal_id:
            key = "memory_persistence"
        elif "secret" in signal_id or "credential" in signal_id:
            key = "secret_access"
        elif "heartbeat" in signal_id or "scheduler" in signal_id:
            key = "heartbeat"
        else:
            key = signal_id
        state = _text(capability.get("state"), "unknown")
        if key in descriptions:
            label = labels[key]
            description = descriptions[key]
        else:
            label = signal_id.replace("_", " ")
            description = "检测到该能力信号，具体运行时作用仍需结合工具注册表确认。"
        sources = capability.get("source_paths")
        source_paths = (
            tuple(item for item in sources if isinstance(item, str))
            if isinstance(sources, list)
            else ()
        )
        items.append(
            {
                "signal_id": signal_id,
                "label": label,
                "description": description,
                "state": state,
                "source_paths": list(source_paths),
            }
        )
    return tuple(sorted(items, key=lambda item: str(item.get("signal_id", ""))))


def build_homi_recommendations(
    pilot: dict[str, Any],
    diff: dict[str, Any] | None = None,
    calibration: dict[str, Any] | None = None,
    runtime_reconciliation: dict[str, Any] | None = None,
) -> tuple[HomiRecommendation, ...]:
    """Create conservative, deterministic suggestions from report metadata.

    The function intentionally never proposes an automatic file edit. An LLM
    may later rewrite or expand these advisories in Homi, but it must consume
    this sanitized metadata and remain non-authoritative.
    """

    recommendations: list[HomiRecommendation] = []
    findings = _calibrated_findings(pilot, calibration)
    for finding in findings:
        rule_id = _text(finding.get("rule_id"), "未知规则")
        severity = _text(finding.get("impact") or finding.get("severity"), "medium")
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        title = {
            "critical": "优先处置关键风险组合",
            "high": "优先复核高风险能力组合",
            "medium": "复核中风险能力组合",
            "low": "记录并持续观察低风险信号",
        }[severity]
        recommendations.append(
            HomiRecommendation(
                priority=cast(Literal["critical", "high", "medium", "low"], severity),
                title=title,
                rationale=(
                    f"Finding {rule_id} 表明 Agent 文件同时表达了可能相互放大的能力"
                    "或行为。静态证据不等于运行时可达性，"
                    "因此应先人工确认真实绑定关系。"
                ),
                actions=(
                    "确认相关能力是否为业务必需，并删除不必要的声明。",
                    "为执行、外部通信、敏感数据访问等动作增加显式审批或最小权限控制。",
                    "整改后重新生成报告并与当前基线进行 Diff。",
                ),
                source_ids=(rule_id,),
            )
        )

    coverage = pilot.get("coverage_metrics")
    if isinstance(coverage, dict):
        unknown = _int(coverage.get("capability_unknown_count"))
        missing = _int(coverage.get("standard_file_missing_count"))
        if unknown or missing or pilot.get("status") == "partial":
            recommendations.append(
                HomiRecommendation(
                    priority="high" if missing else "medium",
                    title="补齐扫描覆盖并消除 Unknown",
                    rationale=(
                        f"当前能力 Unknown 为 {unknown}，标准文件缺失为 {missing}。"
                        "覆盖不完整会降低结论的可解释性，不能被当作安全通过。"
                    ),
                    actions=(
                        "确认六类标准文件及允许的扩展资产是否完整可读。",
                        (
                            "对 Unknown 能力补充明确的 present、absent 或 "
                            "conditional 声明。"
                        ),
                        "不要用推测结果替代 Unknown；必要时单独安排运行时验证。",
                    ),
                    source_ids=("coverage_metrics",),
                )
            )

    if diff is not None:
        summary = diff.get("capability_change_summary")
        if isinstance(summary, dict):
            added = _int(summary.get("added"))
            modified = _int(summary.get("modified"))
            if added or modified:
                recommendations.append(
                    HomiRecommendation(
                        priority="high" if added else "medium",
                        title="复核能力漂移并更新变更审批记录",
                        rationale=(
                            f"相对基线新增能力 {added} 项、修改能力 {modified} 项。"
                            "变化可能扩大 Agent 的外部影响面，应由变更负责人确认。"
                        ),
                        actions=(
                            "逐项查看新增或修改能力的证据文件和变更原因。",
                            "确认变更是否经过负责人、业务方和安全方审批。",
                            "若变更不必要，回退到可信基线；若必要，更新基线并保留审批证据。",
                        ),
                        source_ids=("capability_diff",),
                    )
                )
    if runtime_reconciliation is not None:
        status = _text(runtime_reconciliation.get("status"), "unverified")
        if status != "reconciled":
            runtime_missing = runtime_reconciliation.get(
                "declared_not_observed_operation_ids"
            )
            undeclared = runtime_reconciliation.get(
                "observed_not_declared_operation_ids"
            )
            mismatches = runtime_reconciliation.get("mismatches")
            runtime_missing_count = (
                len(runtime_missing) if isinstance(runtime_missing, list) else 0
            )
            undeclared_count = len(undeclared) if isinstance(undeclared, list) else 0
            mismatch_count = len(mismatches) if isinstance(mismatches, list) else 0
            recommendations.append(
                HomiRecommendation(
                    priority="high" if status == "conflict" else "medium",
                    title="补齐并复核运行时证据对账",
                    rationale=(
                        f"RISK-06 对账状态为 {status}；声明但未观察 "
                        f"{runtime_missing_count} 项，观察但未声明 "
                        f"{undeclared_count} 项，动作/目标冲突 {mismatch_count} 项。"
                    ),
                    actions=(
                        "核对外部 Attestation 是否绑定当前 Pilot Snapshot "
                        "和 Operation Context。",
                        "补充未观察操作的运行时证据，并调查未声明操作和动作/目标冲突。",
                        "在完全对账前，不将该证据用于当前态势、身份或权限结论。",
                    ),
                    source_ids=("runtime_reconciliation",),
                )
            )
    if not recommendations:
        recommendations.append(
            HomiRecommendation(
                priority="low",
                title="保持基线并持续复核",
                rationale="当前报告没有产生需要优先处置的确定性建议，但静态报告仍不等于运行时安全证明。",
                actions=(
                    "保留当前报告和文件摘要作为审计记录。",
                    "后续变更继续使用同一可信基线进行 Diff。",
                    "对关键外部能力按组织流程安排独立运行时验证。",
                ),
                source_ids=("report_summary",),
            )
        )
    return tuple(
        sorted(
            recommendations,
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[item.priority],
                item.title,
                item.source_ids,
            ),
        )
    )


def encode_homi_combined_report_json(report: HomiCombinedReport) -> str:
    """Encode a deterministic combined Homi JSON report."""

    if not isinstance(report, HomiCombinedReport):
        raise TypeError("combined report encoder requires HomiCombinedReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def render_homi_combined_report_text(
    report: HomiCombinedReport, *, language: str = "zh"
) -> str:
    """Render a concise Chinese-first combined report."""

    if language not in {"zh", "en"}:
        raise ValueError("language must be zh or en")
    pilot = report.pilot_report
    diff = report.diff_report
    if language == "en":
        lines = [
            "AgentSec Homi Combined Security Report",
            f"Status: {_text(pilot.get('status'), 'unknown')}",
            f"Findings: {len(_pilot_findings(pilot))}",
            "Mode: report-only; runtime_verified=false; ci_blocked=false",
            "",
            _risk_state_text_summary(report.risk_state_report, chinese=False),
            _operation_context_text_summary(
                report.operation_context_report, chinese=False
            ),
            _context_risk_text_summary(report.context_risk_report, chinese=False),
            _context_score_text_summary(report.risk_score_report, chinese=False),
            _runtime_reconciliation_text_summary(
                report.runtime_reconciliation_report,
                chinese=False,
            ),
            "",
            "Recommendations (advisory only)",
        ]
        for item in report.recommendations:
            lines.extend([f"- [{item.priority}] {item.title}", f"  {item.rationale}"])
            lines.extend(f"  * {action}" for action in item.actions)
        if diff is not None:
            lines.extend(("", "Capability Drift", _diff_text_summary(diff)))
        return "\n".join(lines) + "\n"

    lines = [
        "AgentSec Homi Agent 综合安全报告",
        f"状态：{_status_zh(_text(pilot.get('status'), 'unknown'))}",
        (
            "风险 Findings："
            f"{len(_calibrated_findings(pilot, report.calibration_report))} 个"
        ),
        "模式：仅报告；未完成运行时验证；不阻断 CI",
        "",
        _posture_text_summary(report.posture_report),
        _risk_state_text_summary(report.risk_state_report, chinese=True),
        _operation_context_text_summary(report.operation_context_report, chinese=True),
        _context_risk_text_summary(report.context_risk_report, chinese=True),
        _context_score_text_summary(report.risk_score_report, chinese=True),
        _runtime_reconciliation_text_summary(
            report.runtime_reconciliation_report,
            chinese=True,
        ),
        "",
        "风险建议（仅供人工决策，不自动修改 Agent）",
    ]
    for item in report.recommendations:
        lines.extend(
            [f"- 【{_priority_zh(item.priority)}】{item.title}", f"  {item.rationale}"]
        )
        lines.extend(f"  · {action}" for action in item.actions)
    if diff is not None:
        lines.extend(("", "能力漂移摘要", _diff_text_summary(diff)))
    lines.extend(
        (
            "",
            (
                "安全边界：静态文件证据不证明运行时 Tool、OAuth、权限、"
                "调度器或漏洞可达性。"
            ),
            (
                "建议可以由 Homi 的 LLM 做中文润色和分级解释，但 LLM 输出只能作为"
                "建议证据，不能改变 Finding、评分、Policy 或 CI 决策。"
            ),
        )
    )
    return "\n".join(lines) + "\n"


def render_homi_combined_report_html(
    report: HomiCombinedReport, *, language: str = "zh"
) -> str:
    """Render a self-contained combined report for direct Homi display."""

    if language not in {"zh", "en"}:
        raise ValueError("language must be zh or en")
    chinese = language == "zh"
    pilot = report.pilot_report
    diff = report.diff_report
    findings = _calibrated_findings(pilot, report.calibration_report)
    coverage = pilot.get("coverage_metrics")
    coverage = coverage if isinstance(coverage, dict) else {}
    title = (
        "Homi Agent 综合安全报告" if chinese else "Homi Agent Combined Security Report"
    )
    labels = _html_labels(chinese)
    template = _template_text()
    substitutions = {
        "language": "zh-CN" if chinese else "en",
        "title": escape(title),
        "project": escape(_text(pilot.get("project_name"), "Homi Agent")),
        "status": escape(
            _status_zh(_text(pilot.get("status"), "unknown"))
            if chinese
            else _text(pilot.get("status"), "unknown")
        ),
        "finding_count": str(len(findings)),
        "capability_total": str(_int(coverage.get("capability_total"))),
        "capability_unknown": str(_int(coverage.get("capability_unknown_count"))),
        "standard_files": _standard_file_label(coverage),
        "summary": escape(labels["summary"]),
        "function_title": escape(labels["function_title"]),
        "function_summary": _function_summary_html(report.function_summary, chinese),
        "score_title": escape(labels["score_title"]),
        "score_overview": _score_overview_html(report.score_report, chinese),
        "score_cards": _score_cards_html(report.score_report, chinese),
        "radar_chart": _radar_chart_svg(report.score_report, chinese),
        "posture_summary": _posture_summary(report.posture_report, chinese),
        "risk_state_summary": _risk_state_summary(report.risk_state_report, chinese),
        "operation_context_summary": _operation_context_summary(
            report.operation_context_report, chinese
        ),
        "context_risk_summary": _context_risk_summary(
            report.context_risk_report, chinese
        ),
        "context_score_summary": _context_score_summary(
            report.risk_score_report, chinese
        ),
        "runtime_reconciliation_summary": _runtime_reconciliation_summary(
            report.runtime_reconciliation_report,
            chinese,
        ),
        "recommendations_title": escape(labels["recommendations_title"]),
        "recommendations": _recommendation_cards(report.recommendations, chinese),
        "pilot_title": escape(labels["pilot_title"]),
        "pilot_summary": _pilot_summary(
            pilot,
            chinese,
            report.runtime_reconciliation_report,
        ),
        "diff_title": escape(labels["diff_title"]),
        "diff_section": _diff_section(diff, chinese),
        "findings_title": escape(labels["findings_title"]),
        "finding_cards": _finding_cards(findings, chinese),
        "boundary_title": escape(labels["boundary_title"]),
        "boundary": escape(labels["boundary"]),
        "footer": escape(labels["footer"]),
    }
    from string import Template

    return Template(template).safe_substitute(substitutions)


def _read_pilot(path: Path) -> tuple[dict[str, Any], str]:
    payload, digest = _read_json(path, "Homi Pilot")
    if payload.get("format") != "agentsec-homi-report-only-pilot":
        raise HomiCombinedReportError(
            "pilot input must be an AgentSec Homi Pilot JSON report"
        )
    if (
        payload.get("report_only") is not True
        or payload.get("runtime_verified") is not False
        or payload.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError("pilot authority fields are invalid")
    if not isinstance(payload.get("capabilities"), list) or not isinstance(
        payload.get("combination"), dict
    ):
        raise HomiCombinedReportError("pilot capabilities or combination is missing")
    return payload, digest


def _read_diff(path: Path) -> tuple[dict[str, Any], str]:
    payload, digest = _read_json(path, "Homi Capability Diff")
    if payload.get("format") != "agentsec-homi-capability-diff":
        raise HomiCombinedReportError(
            "diff input must be an AgentSec Homi Capability Diff JSON report"
        )
    authority = payload.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError("diff authority fields are invalid")
    return payload, digest


def _read_score(path: Path) -> tuple[dict[str, Any], str]:
    payload, digest = _read_json(path, "Agentic Score")
    if payload.get("format") != "agentsec-agentic-assessment":
        raise HomiCombinedReportError(
            "score input must be an AgentSec Agentic Assessment JSON report"
        )
    policy = payload.get("policy")
    boundary = payload.get("boundary")
    if (
        not isinstance(policy, dict)
        or policy.get("report_only") is not True
        or policy.get("ci_blocking_enabled") is not False
        or policy.get("score_ci_authority") is not False
    ):
        raise HomiCombinedReportError("score policy authority fields are invalid")
    if (
        not isinstance(boundary, dict)
        or boundary.get("runtime_verified") is not False
        or boundary.get("score_ci_authority") is not False
    ):
        raise HomiCombinedReportError("score boundary fields are invalid")
    for key in ("technical", "drift", "governance", "overall"):
        if not isinstance(payload.get(key), dict):
            raise HomiCombinedReportError(f"score {key} section is missing")
    return payload, digest


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    if not isinstance(path, Path):
        raise HomiCombinedReportError(f"{label} path must be a Path")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HomiCombinedReportError(f"could not read {label} JSON") from error
    if not isinstance(payload, dict):
        raise HomiCombinedReportError(f"{label} JSON must be an object")
    return payload, hashlib.sha256(raw).hexdigest()


def _read_optional_sidecar(
    pilot_path: Path,
    pilot_digest: str,
    filename: str,
    expected_format: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read a sidecar next to the Pilot report and bind it to its digest."""

    sidecar_path = pilot_path.parent / filename
    if not sidecar_path.exists():
        return None, None
    payload, digest = _read_json(sidecar_path, filename)
    if payload.get("format") != expected_format:
        raise HomiCombinedReportError(f"{filename} format is invalid")
    if payload.get("source_report_sha256") != pilot_digest:
        raise HomiCombinedReportError(f"{filename} is not bound to the Pilot report")
    return payload, digest


def _calibrated_findings(
    pilot: dict[str, Any],
    calibration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    findings = _pilot_findings(pilot)
    if not isinstance(calibration, dict):
        return findings
    retained = calibration.get("retained_findings")
    if not isinstance(retained, list):
        return findings
    retained_ids = {
        item.get("finding_id")
        for item in retained
        if isinstance(item, dict) and isinstance(item.get("finding_id"), str)
    }
    if not retained_ids:
        return []
    return [
        finding for finding in findings if finding.get("finding_id") in retained_ids
    ]


def _posture_text_summary(posture: dict[str, Any] | None) -> str:
    if not isinstance(posture, dict):
        return "风险口径：未提供 Posture Sidecar；当前态势尚未建立。"
    raw = _number(posture.get("raw_potential_impact_score"))
    potential = _number(posture.get("potential_impact_score"))
    current = _text(posture.get("current_posture"), "not_established")
    current_score = posture.get("current_posture_score")
    current_value = (
        _number(current_score) if isinstance(current_score, (int, float)) else "未建立"
    )
    suppressed = _int(posture.get("suppressed_finding_count"))
    return (
        f"风险口径：原始静态潜在影响 {raw}，校准后潜在影响 {potential}；"
        f"当前安全态势 {current}，当前态势分 {current_value}；"
        f"模板校准抑制 {suppressed} 个 Finding。"
    )


def _posture_summary(posture: dict[str, Any] | None, chinese: bool) -> str:
    if not isinstance(posture, dict):
        return (
            "<div class='callout'>未提供 Posture Sidecar；当前安全态势尚未建立。</div>"
            if chinese
            else (
                "<div class='callout'>No Posture sidecar; current posture is not "
                "established.</div>"
            )
        )
    raw = _number(posture.get("raw_potential_impact_score"))
    potential = _number(posture.get("potential_impact_score"))
    current = _text(posture.get("current_posture"), "not_established")
    current_score = posture.get("current_posture_score")
    current_value = (
        _number(current_score) if isinstance(current_score, (int, float)) else "未建立"
    )
    suppressed = _int(posture.get("suppressed_finding_count"))
    if chinese:
        text = (
            f"原始静态潜在影响：{raw}；校准后潜在影响：{potential}；"
            f"当前安全态势：{current}；当前态势分：{current_value}；"
            f"模板校准抑制：{suppressed} 个 Finding。"
        )
    else:
        text = (
            "Raw static potential impact: "
            f"{raw}; calibrated potential impact: {potential}; "
            f"current posture: {current}; current posture score: {current_value}; "
            f"suppressed by template calibration: {suppressed}."
        )
    return f"<div class='callout'>{escape(text)}</div>"


def _risk_state_text_summary(
    state: dict[str, Any] | None,
    *,
    chinese: bool,
) -> str:
    if not isinstance(state, dict):
        return (
            "State classification: not supplied."
            if not chinese
            else "状态分类：未提供 RISK-02 状态 Sidecar。"
        )
    counts = state.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    labels = (
        (
            ("template", "模板"),
            ("latent", "潜在"),
            ("active", "静态活跃"),
            ("unknown", "Unknown"),
            ("runtime_attested", "运行时已证明"),
        )
        if chinese
        else (
            ("template", "template"),
            ("latent", "latent"),
            ("active", "active"),
            ("unknown", "unknown"),
            ("runtime_attested", "runtime_attested"),
        )
    )
    values = ", ".join(f"{label}={_int(counts.get(key))}" for key, label in labels)
    return f"状态分类：{values}。" if chinese else f"State classification: {values}."


def _risk_state_summary(state: dict[str, Any] | None, chinese: bool) -> str:
    if not isinstance(state, dict):
        text = (
            "未提供 RISK-02 状态 Sidecar；不会从缺失状态推断风险。"
            if chinese
            else "No RISK-02 state sidecar; missing state is not treated as risk."
        )
        return f"<div class='callout'>{escape(text)}</div>"
    counts = state.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    labels = (
        (
            ("template", "模板"),
            ("latent", "潜在"),
            ("active", "静态活跃"),
            ("unknown", "Unknown"),
            ("runtime_attested", "运行时已证明"),
        )
        if chinese
        else (
            ("template", "Template"),
            ("latent", "Latent"),
            ("active", "Active"),
            ("unknown", "Unknown"),
            ("runtime_attested", "Runtime attested"),
        )
    )
    cards = "".join(
        f"<div class='metric'><small>{escape(label)}</small>"
        f"<strong>{_int(counts.get(key))}</strong></div>"
        for key, label in labels
    )
    note = (
        "状态标签只描述证据成熟度；Unknown 不是高风险，Active 也不等于运行时可达。"
        if chinese
        else (
            "State labels describe evidence maturity; unknown is not high risk and "
            "active does not prove runtime reachability."
        )
    )
    return f"<div class='metric-grid'>{cards}</div><p class='muted'>{escape(note)}</p>"


def _operation_context_text_summary(
    report: dict[str, Any] | None,
    *,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        return (
            "Operation Context: not supplied."
            if not chinese
            else "操作上下文：未提供 RISK-03 提取报告。"
        )
    context_set = report.get("context_set")
    context_set = context_set if isinstance(context_set, dict) else {}
    contexts = context_set.get("contexts")
    count = len(contexts) if isinstance(contexts, list) else 0
    complete = context_set.get("coverage_complete") is True
    return (
        f"操作上下文：提取 {count} 条；覆盖完整：{complete}。"
        if chinese
        else f"Operation Context: {count} extracted; coverage_complete={complete}."
    )


def _operation_context_summary(
    report: dict[str, Any] | None,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        text = (
            "未提供 RISK-03 操作上下文；不会从能力关键词推断操作风险。"
            if chinese
            else (
                "No RISK-03 Operation Context; operation risk is not inferred "
                "from keywords."
            )
        )
        return f"<div class='callout'>{escape(text)}</div>"
    context_set = report.get("context_set")
    context_set = context_set if isinstance(context_set, dict) else {}
    contexts = context_set.get("contexts")
    contexts = contexts if isinstance(contexts, list) else []
    unknown = context_set.get("unknown_dimensions")
    unknown_count = len(unknown) if isinstance(unknown, list) else 0
    complete = context_set.get("coverage_complete") is True
    status = "完整" if complete else "需要补充上下文" if chinese else "needs context"
    if chinese:
        text = (
            f"已提取 {len(contexts)} 条操作上下文；状态：{status}；"
            f"Unknown 维度：{unknown_count}。"
            "这些字段用于后续确定性风险规则，不代表已获得运行时权限。"
        )
    else:
        text = (
            f"Extracted {len(contexts)} Operation Contexts; status: {status}; "
            f"unknown dimensions: {unknown_count}. "
            "These fields feed deterministic rules and do not grant runtime permission."
        )
    return f"<div class='callout'>{escape(text)}</div>"


def _context_risk_text_summary(
    report: dict[str, Any] | None,
    *,
    chinese: bool,
) -> str:
    """Render a compact RISK-04 summary without inventing a numeric score."""

    if not isinstance(report, dict):
        return (
            "Context-aware risk rules: not supplied."
            if not chinese
            else "上下文风险规则：未提供 RISK-04 报告。"
        )
    findings = report.get("findings")
    findings = findings if isinstance(findings, list) else []
    risk_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item.get("kind") == "risk"
    ]
    coverage_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item.get("kind") == "coverage"
    ]
    rule_ids = _context_risk_rule_ids(risk_findings)
    highest = _highest_context_severity(risk_findings)
    if chinese:
        return (
            f"上下文风险规则：命中 {len(risk_findings)} 个风险 Finding，"
            f"{len(coverage_findings)} 个覆盖观察；最高严重级别："
            f"{_severity_zh(highest)}；命中规则：{', '.join(rule_ids) or '无'}。"
        )
    return (
        f"Context-aware rules: {len(risk_findings)} risk Findings, "
        f"{len(coverage_findings)} coverage observations; highest severity: "
        f"{highest}; matched rules: {', '.join(rule_ids) or 'none'}."
    )


def _context_risk_summary(
    report: dict[str, Any] | None,
    chinese: bool,
) -> str:
    """Render RISK-04 Finding metadata and its explicit safety boundary."""

    if not isinstance(report, dict):
        text = (
            "未提供 RISK-04 上下文风险报告；不会从能力关键词或人格描述推断风险。"
            if chinese
            else (
                "No RISK-04 report; risk is not inferred from capability keywords "
                "or persona descriptions."
            )
        )
        return f"<div class='callout'>{escape(text)}</div>"
    findings = report.get("findings")
    findings = findings if isinstance(findings, list) else []
    risk_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item.get("kind") == "risk"
    ]
    coverage_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item.get("kind") == "coverage"
    ]
    rule_ids = _context_risk_rule_ids(risk_findings)
    cards: list[str] = []
    for finding in risk_findings:
        rule_id = _text(finding.get("rule_id"), "未知规则")
        severity = _text(finding.get("severity"), "unknown")
        rationale = _context_risk_rationale(finding, chinese)
        contexts = finding.get("context_ids")
        context_text = (
            ", ".join(item for item in contexts if isinstance(item, str))
            if isinstance(contexts, list)
            else "—"
        )
        evidence = finding.get("evidence_ids")
        evidence_text = (
            ", ".join(item for item in evidence if isinstance(item, str))
            if isinstance(evidence, list)
            else "—"
        )
        confidence = _text(finding.get("confidence"), "D")
        cards.append(
            "<article class='finding finding-"
            f"{escape(severity)}'><div class='finding-head'>"
            f"<span class='badge badge-{escape(severity)}'>"
            f"{escape(_severity_zh(severity) if chinese else severity)}</span>"
            f"<strong>{escape(rule_id)}</strong></div>"
            f"<p>{escape(rationale)}</p>"
            f"<small>{escape('上下文：' if chinese else 'Contexts: ')}"
            f"{escape(context_text)}；"
            f"{escape('证据：' if chinese else 'Evidence: ')}"
            f"{escape(evidence_text)}；"
            f"{escape('Confidence：' if chinese else 'Confidence: ')}"
            f"{escape(confidence)}</small></article>"
        )
    if cards:
        details = "<div class='finding-grid'>" + "".join(cards) + "</div>"
    else:
        details = (
            "<div class='empty'>暂无上下文风险 Finding。</div>"
            if chinese
            else "<div class='empty'>No context risk Findings.</div>"
        )
    coverage_note = (
        f"覆盖观察 {len(coverage_findings)} 个；Unknown 只代表上下文覆盖不足，"
        "不代表风险或安全通过。"
        if chinese
        else (
            f"Coverage observations: {len(coverage_findings)}; Unknown means "
            "insufficient context, not risk and not a clean pass."
        )
    )
    authority_note = (
        "RISK-04 只识别操作组合，不计算数值风险分，不证明运行时可达性，"
        "不授权、不认证、不阻断 CI。"
        if chinese
        else (
            "RISK-04 identifies operation combinations only; it does not score, "
            "prove runtime reachability, authorize, authenticate, or block CI."
        )
    )
    highest_label = _severity_label(_highest_context_severity(risk_findings), chinese)
    return (
        f"<div class='metric-grid'><div class='metric'><small>风险 Finding</small>"
        f"<strong>{len(risk_findings)}</strong></div>"
        f"<div class='metric'><small>覆盖观察</small><strong>"
        f"{len(coverage_findings)}</strong></div>"
        f"<div class='metric'><small>"
        f"{escape('最高严重级别' if chinese else 'Highest severity')}"
        f"</small><strong>{escape(highest_label)}"
        "</strong></div></div>"
        f"<p class='muted'>{escape('命中规则：' if chinese else 'Matched rules: ')}"
        f"{escape(', '.join(rule_ids) or ('无' if chinese else 'none'))}</p>"
        f"<p class='muted'>{escape(coverage_note)}</p>{details}"
        f"<p class='muted'>{escape(authority_note)}</p>"
    )


def _highest_context_severity(findings: list[dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    values = [
        _text(item.get("severity"), "none")
        for item in findings
        if isinstance(item, dict)
    ]
    return max(values, key=lambda value: order.get(value, -1), default="none")


def _context_risk_rule_ids(findings: list[dict[str, Any]]) -> tuple[str, ...]:
    values = {
        rule_id
        for item in findings
        if isinstance(item, dict)
        for rule_id in (item.get("rule_id"),)
        if isinstance(rule_id, str)
    }
    return tuple(sorted(values))


def _context_risk_rationale(finding: dict[str, Any], chinese: bool) -> str:
    default = (
        "静态上下文组合需要人工确认。"
        if chinese
        else "Static operation context requires human confirmation."
    )
    rationale_code = _text(finding.get("rationale_code"), "")
    if not chinese:
        return _text(finding.get("rationale"), default)
    return {
        "sensitive_data_external_transfer": "结构化操作将敏感数据发送或写入外部目标。",
        "autonomous_sensitive_operation": (
            "定时、主动或自主操作触及敏感数据或高影响目标。"
        ),
        "high_impact_without_authorization": "高影响操作缺少明确授权上下文。",
        "secret_to_external_transfer_chain": (
            "一个操作读取 Secret/Credential，另一个操作向外部目标传输数据。"
        ),
        "indefinite_external_persistence": (
            "敏感数据被声明为在本地会话或工作区之外无限期保存。"
        ),
        "control_file_update_without_authorization": (
            "Agent 控制文件或身份文件可能在缺少明确授权时被修改。"
        ),
    }.get(rationale_code, default)


def _severity_label(value: str, chinese: bool) -> str:
    return _severity_zh(value) if chinese else value


def _context_score_text_summary(
    report: dict[str, Any] | None,
    *,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        return (
            "Context risk score: not supplied."
            if not chinese
            else "风险量化：未提供 RISK-05 报告。"
        )
    potential = _number(report.get("potential_impact_score"))
    residual = _number(report.get("residual_risk_score"))
    drift = _number(report.get("drift_score"))
    posture = _text(report.get("current_posture"), "not_established")
    posture_label = _context_posture_label(posture, chinese)
    if chinese:
        return (
            f"风险量化：潜在影响 {potential}；残余风险 {residual}；"
            f"当前态势 {posture_label}；风险漂移 {drift}。"
        )
    return (
        f"Context risk score: potential={potential}; residual={residual}; "
        f"current posture={posture_label}; drift={drift}."
    )


def _context_score_summary(
    report: dict[str, Any] | None,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        text = (
            "未提供 RISK-05 风险量化；不会把能力数量或静态声明直接当作当前风险分。"
            if chinese
            else (
                "No RISK-05 score; capability count and static declarations are "
                "not treated as current risk scores."
            )
        )
        return f"<div class='callout'>{escape(text)}</div>"
    potential = _number(report.get("potential_impact_score"))
    residual = _number(report.get("residual_risk_score"))
    drift = _number(report.get("drift_score"))
    posture = _text(report.get("current_posture"), "not_established")
    posture_label = _context_posture_label(posture, chinese)
    score_cards = _metric_cards(
        (
            ("潜在影响" if chinese else "Potential impact", potential),
            ("残余风险" if chinese else "Residual risk", residual),
            ("风险漂移" if chinese else "Risk drift", drift),
            ("当前态势" if chinese else "Current posture", posture_label),
        )
    )
    limitation = (
        "当前态势分保持为空，原因是本次仅有静态 Operation Context；"
        "潜在影响不等于当前运行时暴露。"
        if chinese
        else (
            "Current posture score remains null because this run has only static "
            "Operation Context; potential impact is not current runtime exposure."
        )
    )
    return f"{score_cards}<p class='muted'>{escape(limitation)}</p>"


def _runtime_reconciliation_text_summary(
    report: dict[str, Any] | None,
    *,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        return (
            "Runtime evidence reconciliation: not supplied."
            if not chinese
            else "运行时证据对账：未提供外部 Runtime Attestation。"
        )
    status = _text(report.get("status"), "unknown")
    verified = report.get("runtime_verified") is True
    eligible = report.get("current_posture_eligible") is True
    confidence = _text(report.get("evidence_confidence"), "D")
    matched = (
        len(report.get("matched_operation_ids", []))
        if isinstance(report.get("matched_operation_ids"), list)
        else 0
    )
    missing = (
        len(report.get("declared_not_observed_operation_ids", []))
        if isinstance(report.get("declared_not_observed_operation_ids"), list)
        else 0
    )
    conflicts = (
        len(report.get("mismatches", []))
        if isinstance(report.get("mismatches"), list)
        else 0
    )
    if chinese:
        return (
            f"运行时证据对账：状态 {status}；已验证 {verified}；"
            f"当前态势可用 {eligible}；"
            f"Evidence Confidence {confidence}；已匹配操作 {matched}；"
            f"未观察声明操作 {missing}；冲突 {conflicts}。"
        )
    return (
        f"Runtime evidence reconciliation: status={status}; verified={verified}; "
        f"current_posture_eligible={eligible}; confidence={confidence}; "
        f"matched={matched}; declared_not_observed={missing}; conflicts={conflicts}."
    )


def _runtime_reconciliation_summary(
    report: dict[str, Any] | None,
    chinese: bool,
) -> str:
    if not isinstance(report, dict):
        text = (
            "本次报告未提供外部 Runtime Attestation；当前态势分和运行时可达性仍未建立。"
            if chinese
            else (
                "No external Runtime Attestation was supplied; current posture "
                "and runtime reachability remain unestablished."
            )
        )
        return f"<div class='callout'>{escape(text)}</div>"
    status = _text(report.get("status"), "unknown")
    status_label = (
        {
            "reconciled": "已对账",
            "partial": "部分对账",
            "conflict": "存在冲突",
            "unverified": "未验证",
        }.get(status, status)
        if chinese
        else status
    )
    verified = "是" if report.get("runtime_verified") is True else "否"
    eligible = "是" if report.get("current_posture_eligible") is True else "否"
    confidence = _text(report.get("evidence_confidence"), "D")
    coverage = "完整" if report.get("context_coverage_complete") is True else "不完整"
    matched = report.get("matched_operation_ids")
    missing = report.get("declared_not_observed_operation_ids")
    undeclared = report.get("observed_not_declared_operation_ids")
    mismatches = report.get("mismatches")
    values = (
        (
            "对账状态" if chinese else "Status",
            status_label,
        ),
        (
            "运行时已验证" if chinese else "Runtime verified",
            verified,
        ),
        (
            "当前态势可用" if chinese else "Current posture eligible",
            eligible,
        ),
        (
            "Evidence Confidence" if chinese else "Evidence Confidence",
            confidence,
        ),
        (
            "上下文覆盖" if chinese else "Context coverage",
            coverage,
        ),
        (
            "已匹配操作" if chinese else "Matched operations",
            str(len(matched)) if isinstance(matched, list) else "0",
        ),
        (
            "声明但未观察" if chinese else "Declared not observed",
            str(len(missing)) if isinstance(missing, list) else "0",
        ),
        (
            "观察但未声明" if chinese else "Observed not declared",
            str(len(undeclared)) if isinstance(undeclared, list) else "0",
        ),
        (
            "动作/目标冲突" if chinese else "Action/target mismatches",
            str(len(mismatches)) if isinstance(mismatches, list) else "0",
        ),
    )
    cards = _metric_cards(values)
    limitations = report.get("limitations")
    limitation_text = (
        "；".join(item for item in limitations if isinstance(item, str))
        if isinstance(limitations, list)
        else ""
    )
    note = (
        "运行时证据由外部沙箱或平台生成，AgentSec 只做哈希绑定、确定性对账和报告；"
        "它不授予权限、不认证身份、不修改策略、不阻断 CI，也不证明漏洞可利用性。"
        if chinese
        else (
            "Runtime evidence is produced externally; AgentSec only binds, "
            "reconciles, and reports it. It grants no permission, authenticates "
            "identity, changes policy, blocks CI, or proves exploitability."
        )
    )
    detail = (
        f"<p class='muted'>{escape(limitation_text)}</p>" if limitation_text else ""
    )
    return f"{cards}{detail}<p class='muted'>{escape(note)}</p>"


def _validate_report_only_operation_context(
    report: dict[str, Any] | None,
) -> None:
    if report is None:
        return
    authority = report.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError(
            "homi-operation-context authority fields are invalid"
        )


def _read_context_risk_sidecar(
    pilot_path: Path,
    operation_context: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read and bind the RISK-04 sidecar to the exact Operation Context Set."""

    sidecar_path = pilot_path.parent / "homi-context-risk.json"
    if not sidecar_path.exists():
        return None, None
    if operation_context is None:
        raise HomiCombinedReportError(
            "homi-context-risk.json requires homi-operation-context.json"
        )
    payload, digest = _read_json(sidecar_path, "homi-context-risk.json")
    if payload.get("format") != "agentsec-context-risk-report":
        raise HomiCombinedReportError("homi-context-risk.json format is invalid")
    authority = payload.get("authority")
    if (
        payload.get("report_only") is not True
        or payload.get("runtime_verified") is not False
        or payload.get("policy_authority") is not False
        or payload.get("ci_blocked") is not False
        or not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("policy_authority") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError("homi-context-risk authority fields are invalid")
    context_payload = operation_context.get("context_set")
    try:
        context_set = OperationContextSet.model_validate(context_payload)
    except Exception as error:
        raise HomiCombinedReportError(
            "homi-operation-context cannot be validated for RISK-04 binding"
        ) from error
    expected_context_digest = canonical_operation_context_sha256(context_set)
    if payload.get("source_context_sha256") != expected_context_digest:
        raise HomiCombinedReportError(
            "homi-context-risk.json is not bound to the Operation Context report"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise HomiCombinedReportError("homi-context-risk findings are missing")
    risk_count = sum(
        isinstance(item, dict) and item.get("kind") == "risk" for item in findings
    )
    coverage_count = sum(
        isinstance(item, dict) and item.get("kind") == "coverage" for item in findings
    )
    if payload.get("risk_finding_count") != risk_count:
        raise HomiCombinedReportError("homi-context-risk risk count is inconsistent")
    if payload.get("coverage_finding_count") != coverage_count:
        raise HomiCombinedReportError(
            "homi-context-risk coverage count is inconsistent"
        )
    return payload, digest


def _read_context_risk_score_sidecar(
    pilot_path: Path,
    operation_context: dict[str, Any] | None,
    context_risk: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read and bind RISK-05 to both RISK-03 and RISK-04 artifacts."""

    sidecar_path = pilot_path.parent / "homi-risk-score.json"
    if not sidecar_path.exists():
        return None, None
    if operation_context is None or context_risk is None:
        raise HomiCombinedReportError(
            "homi-risk-score.json requires Operation Context and Context Risk reports"
        )
    payload, digest = _read_json(sidecar_path, "homi-risk-score.json")
    if payload.get("format") != "agentsec-context-risk-score":
        raise HomiCombinedReportError("homi-risk-score.json format is invalid")
    authority = payload.get("authority")
    if (
        payload.get("report_only") is not True
        or payload.get("runtime_verified") is not False
        or payload.get("policy_authority") is not False
        or payload.get("ci_blocked") is not False
        or not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("policy_authority") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError("homi-risk-score authority fields are invalid")
    context_set_payload = operation_context.get("context_set")
    try:
        context_set = OperationContextSet.model_validate(context_set_payload)
    except Exception as error:
        raise HomiCombinedReportError(
            "homi-operation-context cannot be validated for RISK-05 binding"
        ) from error
    expected_context_digest = canonical_operation_context_sha256(context_set)
    if payload.get("source_context_sha256") != expected_context_digest:
        raise HomiCombinedReportError(
            "homi-risk-score.json is not bound to the Operation Context report"
        )
    if payload.get("source_context_sha256") != context_risk.get(
        "source_context_sha256"
    ):
        raise HomiCombinedReportError(
            "homi-risk-score.json is not bound to the Context Risk report"
        )
    context_risk_encoded = json.dumps(
        context_risk, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    expected_risk_digest = hashlib.sha256(context_risk_encoded).hexdigest()
    if payload.get("source_risk_report_sha256") != expected_risk_digest:
        raise HomiCombinedReportError(
            "homi-risk-score.json is not bound to the Context Risk report content"
        )
    return payload, digest


def _read_runtime_reconciliation_sidecar(
    pilot_path: Path,
    pilot_digest: str,
    operation_context: dict[str, Any] | None,
    context_risk: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read and verify the optional RISK-06 reconciliation sidecar."""

    sidecar_path = pilot_path.parent / "homi-runtime-reconciliation.json"
    if not sidecar_path.exists():
        return None, None
    if operation_context is None or context_risk is None:
        raise HomiCombinedReportError(
            "homi-runtime-reconciliation.json requires Operation Context and "
            "Context Risk reports"
        )
    payload, digest = _read_json(
        sidecar_path,
        "homi-runtime-reconciliation.json",
    )
    try:
        reconciliation = decode_evidence_reconciliation_json(
            json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )
        context_set = OperationContextSet.model_validate(
            operation_context.get("context_set")
        )
        risk_report = decode_context_risk_json(
            json.dumps(context_risk, ensure_ascii=False, sort_keys=True)
        )
    except (TypeError, ValueError) as error:
        raise HomiCombinedReportError(
            "homi-runtime-reconciliation.json is invalid"
        ) from error
    if reconciliation.source_agent_snapshot_sha256 != pilot_digest:
        raise HomiCombinedReportError(
            "homi-runtime-reconciliation.json is not bound to the Pilot report"
        )
    if reconciliation.source_context_sha256 != canonical_operation_context_sha256(
        context_set
    ):
        raise HomiCombinedReportError(
            "homi-runtime-reconciliation.json is not bound to Operation Context"
        )
    if reconciliation.source_risk_report_sha256 != canonical_context_risk_sha256(
        risk_report
    ):
        raise HomiCombinedReportError(
            "homi-runtime-reconciliation.json is not bound to Context Risk"
        )
    return payload, digest


def _validate_report_only_risk_state(state: dict[str, Any] | None) -> None:
    if state is None:
        return
    authority = state.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiCombinedReportError("homi-risk-state authority fields are invalid")


def _pilot_findings(pilot: dict[str, Any]) -> list[dict[str, Any]]:
    combination = pilot.get("combination")
    if not isinstance(combination, dict):
        return []
    findings = combination.get("findings")
    return (
        [item for item in findings if isinstance(item, dict)]
        if isinstance(findings, list)
        else []
    )


def _function_summary_html(items: tuple[dict[str, object], ...], chinese: bool) -> str:
    if not items:
        return (
            "<div class='empty'>未识别到可解释的能力信号。</div>"
            if chinese
            else "<div class='empty'>No explainable capability signals detected.</div>"
        )
    rows: list[str] = []
    for item in items:
        state = _text(item.get("state"), "unknown")
        label = _text(item.get("label"), _text(item.get("signal_id"), "—"))
        description = _text(item.get("description"), "—")
        paths = item.get("source_paths")
        source_text = ", ".join(paths) if isinstance(paths, list) else "—"
        state_label = _state_zh(state) if chinese else state
        rows.append(
            "<article class='capability-explain'>"
            f"<div class='finding-head'><strong>{escape(label)}</strong>"
            f"<span class='state state-{escape(state.replace('_', '-'))}'>"
            f"{escape(state_label)}</span></div>"
            f"<p>{escape(description)}</p>"
            f"<small>信号：{escape(_text(item.get('signal_id'), '—'))} · "
            f"证据：{escape(source_text or '—')}</small>"
            "</article>"
        )
    return "<div class='capability-explain-grid'>" + "".join(rows) + "</div>"


def _score_values(score: dict[str, Any] | None) -> dict[str, float | None]:
    if score is None:
        return {
            "technical": None,
            "drift": None,
            "governance": None,
            "overall": None,
        }
    values: dict[str, float | None] = {}
    for key in ("technical", "drift", "governance"):
        section = score.get(key)
        value = section.get(f"{key}_score") if isinstance(section, dict) else None
        values[key] = float(value) if isinstance(value, (int, float)) else None
    overall = score.get("overall")
    overall_value = overall.get("overall_score") if isinstance(overall, dict) else None
    values["overall"] = (
        float(overall_value) if isinstance(overall_value, (int, float)) else None
    )
    return values


def _score_overview_html(score: dict[str, Any] | None, chinese: bool) -> str:
    if score is None:
        return (
            (
                "<div class='empty'>未提供 Agentic Score；以下雷达图和评分卡"
                "不会虚构分数。</div>"
            )
            if chinese
            else (
                "<div class='empty'>No Agentic Score supplied; scores are not "
                "fabricated.</div>"
            )
        )
    values = _score_values(score)
    overall = score.get("overall")
    overall = overall if isinstance(overall, dict) else {}
    severity = _text(overall.get("severity"), "unknown")
    gate = overall.get("hard_gate")
    triggered = gate.get("triggered") is True if isinstance(gate, dict) else False
    gate_label = "已命中（仅报告）" if triggered else "未命中"
    if not chinese:
        gate_label = "triggered (report-only)" if triggered else "not triggered"
    return (
        f"<div class='score-overview'><div><span class='muted'>"
        f"{'Overall Score' if not chinese else 'Overall 综合评分'}</span>"
        f"<strong class='overall-number'>{_number(values['overall'])}</strong></div>"
        f"<div><span class='muted'>{'Severity' if not chinese else '风险等级'}</span>"
        f"<strong>{escape(_severity_zh(severity) if chinese else severity.upper())}"
        "</strong></div>"
        f"<div><span class='muted'>{'Hard Gate' if not chinese else '硬性门禁'}</span>"
        f"<strong>{escape(gate_label)}</strong></div></div>"
    )


def _score_cards_html(score: dict[str, Any] | None, chinese: bool) -> str:
    labels = (
        (
            ("technical", "技术风险"),
            ("drift", "漂移风险"),
            ("governance", "治理风险"),
            ("overall", "综合风险"),
        )
        if chinese
        else (
            ("technical", "Technical"),
            ("drift", "Drift"),
            ("governance", "Governance"),
            ("overall", "Overall"),
        )
    )
    values = _score_values(score)
    cards: list[str] = []
    for key, label in labels:
        value = values[key]
        section = score.get(key) if isinstance(score, dict) else None
        severity = (
            _text(section.get("severity"), "unknown")
            if isinstance(section, dict)
            else "unknown"
        )
        severity_text = _severity_zh(severity) if chinese else severity.upper()
        note = (
            "基础维度"
            if chinese and key != "overall"
            else "前三个维度的派生结果"
            if chinese
            else "base dimension"
            if key != "overall"
            else "derived from the three dimensions"
        )
        cards.append(
            f"<div class='score-card score-{escape(severity)}'>"
            f"<small>{escape(label)}</small>"
            f"<strong>{_number(value)}</strong><span>{escape(severity_text)}</span>"
            f"<em>{escape(note)}</em></div>"
        )
    return "<div class='score-card-grid'>" + "".join(cards) + "</div>"


def _radar_chart_svg(score: dict[str, Any] | None, chinese: bool) -> str:
    values = _score_values(score)
    if any(values[key] is None for key in ("technical", "drift", "governance")):
        return (
            "<div class='empty'>提供 Agentic Score JSON 后显示三轴风险雷达图。</div>"
            if chinese
            else (
                "<div class='empty'>Supply Agentic Score JSON to show the "
                "three-axis radar chart.</div>"
            )
        )
    technical = _clamp_score(values["technical"] or 0.0)
    drift = _clamp_score(values["drift"] or 0.0)
    governance = _clamp_score(values["governance"] or 0.0)
    center_x, center_y, radius = 150.0, 132.0, 92.0
    points = (
        (center_x, center_y - radius),
        (center_x + radius * 0.866, center_y + radius * 0.5),
        (center_x - radius * 0.866, center_y + radius * 0.5),
    )

    def point(value: float, anchor: tuple[float, float]) -> str:
        ratio = value / 10.0
        x = center_x + (anchor[0] - center_x) * ratio
        y = center_y + (anchor[1] - center_y) * ratio
        return f"{x:.1f},{y:.1f}"

    grid_polygons = []
    for level in (2, 4, 6, 8, 10):
        coords = " ".join(point(float(level), anchor) for anchor in points)
        grid_polygons.append(f"<polygon points='{coords}' class='radar-grid' />")
    data_coords = " ".join(
        point(value, anchor)
        for value, anchor in zip((technical, drift, governance), points, strict=True)
    )
    labels = (
        ("技术风险", "漂移风险", "治理风险")
        if chinese
        else ("Technical", "Drift", "Governance")
    )
    return (
        "<div class='radar-wrap'><svg class='radar' viewBox='0 0 300 270' role='img' "
        f'aria-label="{
            escape("三轴风险雷达图" if chinese else "Three-axis risk radar chart")
        }">'
        + "".join(grid_polygons)
        + "<line x1='150' y1='132' x2='150' y2='40' class='radar-axis' />"
        + "<line x1='150' y1='132' x2='230' y2='178' class='radar-axis' />"
        + "<line x1='150' y1='132' x2='70' y2='178' class='radar-axis' />"
        + f"<polygon points='{data_coords}' class='radar-data' />"
        + f"<text x='150' y='22' text-anchor='middle'>"
        f"{escape(labels[0])} {technical:.1f}</text>"
        + f"<text x='257' y='190' text-anchor='middle'>"
        f"{escape(labels[1])} {drift:.1f}</text>"
        + f"<text x='43' y='190' text-anchor='middle'>"
        f"{escape(labels[2])} {governance:.1f}</text>"
        + (
            "</svg><p class='muted'>风险值越高，图形越向外扩展；"
            "Overall 为派生指标，不参与雷达轴比较。</p></div>"
        )
    )


def _clamp_score(value: float) -> float:
    return max(0.0, min(10.0, value))


def _state_zh(value: str) -> str:
    return {
        "present": "已声明",
        "conditional": "有条件",
        "example_only": "仅示例",
        "unknown": "未知",
        "absent": "未声明",
    }.get(value, value)


def _finding_cards(findings: list[dict[str, Any]], chinese: bool) -> str:
    if not findings:
        return (
            "<div class='empty'>暂无风险 Finding。</div>"
            if chinese
            else "<div class='empty'>No Findings.</div>"
        )
    cards: list[str] = []
    for finding in findings:
        severity = _text(finding.get("impact") or finding.get("severity"), "medium")
        text = _localized_finding_text(finding, chinese)
        title = _text(text.get("title"), _text(finding.get("rule_id"), "Finding"))
        description = _text(
            text.get("description"),
            "静态证据需要人工确认。"
            if chinese
            else "Static evidence requires human confirmation.",
        )
        severity_label = _severity_zh(severity) if chinese else severity
        advice = (
            "建议先人工确认能力绑定、审批和最小权限控制。"
            if chinese
            else "First confirm bindings, approvals, and least privilege."
        )
        card = (
            f"<article class='finding finding-{escape(severity)}'>"
            "<div class='finding-head'>"
            f"<span class='badge badge-{escape(severity)}'>"
            f"{escape(severity_label)}</span>"
            f"<strong>{escape(_text(finding.get('rule_id'), '—'))}</strong>"
            f"<span class='score'>{_number(finding.get('score'))}</span>"
            "</div>"
            f"<h3>{escape(title)}</h3><p>{escape(description)}</p>"
            f"<p class='muted'>{escape(advice)}</p></article>"
        )
        cards.append(card)
    return "".join(cards)


def _localized_finding_text(finding: dict[str, Any], chinese: bool) -> dict[str, Any]:
    texts = finding.get("texts")
    if not isinstance(texts, list):
        text = finding.get("text")
        return text if isinstance(text, dict) else {}
    preferred = "zh" if chinese else "en"
    for item in texts:
        if isinstance(item, dict) and item.get("language") == preferred:
            return item
    for item in texts:
        if isinstance(item, dict):
            return item
    return {}


def _recommendation_cards(items: tuple[HomiRecommendation, ...], chinese: bool) -> str:
    cards: list[str] = []
    for item in items:
        priority = _priority_zh(item.priority) if chinese else item.priority
        actions = "".join(f"<li>{escape(action)}</li>" for action in item.actions)
        source = ", ".join(item.source_ids)
        provenance = (
            f"来源：{source}；生成方式：确定性规则；权限：仅建议"
            if chinese
            else f"Source: {source}; deterministic advisory; non-authoritative"
        )
        card = (
            f"<article class='recommendation recommendation-{escape(item.priority)}'>"
            "<div class='finding-head'>"
            f"<span class='badge badge-{escape(item.priority)}'>"
            f"{escape(priority)}</span>"
            f"<strong>{escape(item.title)}</strong></div>"
            f"<p>{escape(item.rationale)}</p><ul>{actions}</ul>"
            f"<small>{escape(provenance)}</small></article>"
        )
        cards.append(card)
    return "".join(cards)


def _pilot_summary(
    pilot: dict[str, Any],
    chinese: bool,
    runtime_reconciliation: dict[str, Any] | None = None,
) -> str:
    coverage = pilot.get("coverage_metrics")
    coverage = coverage if isinstance(coverage, dict) else {}
    profile_state = "完整" if pilot.get("profile_complete") else "不完整"
    runtime_status = (
        _text(runtime_reconciliation.get("status"), "unknown")
        if isinstance(runtime_reconciliation, dict)
        else "未提供"
        if chinese
        else "not supplied"
    )
    if chinese:
        return (
            f"<p>能力画像：{escape(profile_state)}；"
            f"解析状态：{escape(_text(pilot.get('resolution_status'), 'unknown'))}"
            "。</p>"
            f"<p>能力 Unknown：{_int(coverage.get('capability_unknown_count'))}；"
            f"外部运行时证据对账：{escape(runtime_status)}；验收就绪：否。</p>"
        )
    profile_state_en = "complete" if pilot.get("profile_complete") else "partial"
    return (
        f"<p>Profile: {escape(profile_state_en)}; "
        f"resolution: {escape(_text(pilot.get('resolution_status'), 'unknown'))}.</p>"
        f"<p>Capability unknown: {_int(coverage.get('capability_unknown_count'))}; "
        f"runtime reconciliation: {escape(runtime_status)}; "
        "acceptance ready: false.</p>"
    )


def _diff_section(diff: dict[str, Any] | None, chinese: bool) -> str:
    if diff is None:
        message = (
            "未提供基线 Diff；本次报告只展示当前快照。"
            if chinese
            else (
                "No baseline Diff supplied; this report shows the current snapshot "
                "only."
            )
        )
        return f"<div class='empty'>{message}</div>"
    capability = diff.get("capability_change_summary")
    capability = capability if isinstance(capability, dict) else {}
    finding = diff.get("finding_delta_summary")
    finding = finding if isinstance(finding, dict) else {}
    risk_score = diff.get("risk_score")
    risk_score = risk_score if isinstance(risk_score, dict) else {}
    labels = (
        (
            "新增能力",
            "移除能力",
            "修改能力",
            "新增 Finding",
            "已解决 Finding",
            "风险分数变化",
        )
        if chinese
        else (
            "Added capabilities",
            "Removed capabilities",
            "Modified capabilities",
            "Added Findings",
            "Resolved Findings",
            "Risk delta",
        )
    )
    values = (
        _int(capability.get("added")),
        _int(capability.get("removed")),
        _int(capability.get("modified")),
        _int(finding.get("added")),
        _int(finding.get("resolved")),
        _number(risk_score.get("delta")),
    )
    return _metric_cards(tuple(zip(labels, values, strict=True)))


def _metric_cards(items: tuple[tuple[str, object], ...]) -> str:
    return (
        "<div class='metric-grid'>"
        + "".join(
            f"<div class='card metric'><small>{escape(label)}</small>"
            f"<strong>{escape(str(value))}</strong></div>"
            for label, value in items
        )
        + "</div>"
    )


def _diff_text_summary(diff: dict[str, Any]) -> str:
    capability = diff.get("capability_change_summary")
    capability = capability if isinstance(capability, dict) else {}
    finding = diff.get("finding_delta_summary")
    finding = finding if isinstance(finding, dict) else {}
    risk_score = diff.get("risk_score")
    risk_score = risk_score if isinstance(risk_score, dict) else {}
    return (
        f"新增能力 {_int(capability.get('added'))}，移除 "
        f"{_int(capability.get('removed'))}，修改 "
        f"{_int(capability.get('modified'))}；新增 Finding "
        f"{_int(finding.get('added'))}，已解决 "
        f"{_int(finding.get('resolved'))}，风险分数变化 "
        f"{_number(risk_score.get('delta'))}。"
    )


def _template_text() -> str:
    from importlib.resources import files

    return (
        files("agentsec")
        .joinpath("templates/homi_combined_report.html")
        .read_text(encoding="utf-8")
    )


def _html_labels(chinese: bool) -> dict[str, str]:
    if chinese:
        return {
            "summary": (
                "这是一份将当前 Homi 快照、能力漂移和整改建议放在同一页面的"
                "只读报告。建议仅用于人工决策。"
            ),
            "recommendations_title": "风险与整改建议",
            "function_title": "Agent 功能与能力概览",
            "score_title": "风险评分总览",
            "pilot_title": "当前 Agent 快照",
            "diff_title": "相对基线的能力漂移",
            "findings_title": "当前风险 Findings",
            "boundary_title": "安全边界",
            "boundary": (
                "静态文件不证明运行时 Tool、OAuth、权限、身份、调度器或漏洞可达性；"
                "报告不自动修改 Agent、不授权外部操作、不阻断 CI。"
                "Homi LLM 可以在脱敏元数据基础上润色建议，但不得改变确定性 Finding、"
                "评分、Policy 或 CI 决策。"
            ),
            "footer": "中文优先 · 自包含 HTML · 不展示原始 Secret",
        }
    return {
        "summary": (
            "This read-only report combines the current Homi snapshot, "
            "capability drift, "
            "and remediation advice. Advice is for human decision-making only."
        ),
        "recommendations_title": "Risk and Remediation Advice",
        "function_title": "Agent Function and Capability Overview",
        "score_title": "Risk Score Overview",
        "pilot_title": "Current Agent Snapshot",
        "diff_title": "Capability Drift versus Baseline",
        "findings_title": "Current Risk Findings",
        "boundary_title": "Security Boundary",
        "boundary": (
            "Static files do not prove runtime Tool, OAuth, permission, identity, "
            "scheduler, or exploit reachability. The report does not modify the Agent, "
            "authorize external actions, or block CI. Homi LLM may polish advice from "
            "sanitized metadata but may not change deterministic Findings, scores, "
            "Policy, or CI decisions."
        ),
        "footer": "Chinese-first · self-contained HTML · raw secrets excluded",
    }


def _standard_file_label(coverage: dict[str, Any]) -> str:
    total = _int(coverage.get("standard_file_total"))
    missing = _int(coverage.get("standard_file_missing_count"))
    return f"{max(0, total - missing)}/{total}"


def _status_zh(value: str) -> str:
    return {"complete": "完整", "partial": "部分", "failed": "失败"}.get(value, value)


def _severity_zh(value: str) -> str:
    return {"critical": "关键", "high": "高", "medium": "中", "low": "低"}.get(
        value, value
    )


def _context_posture_label(value: str, chinese: bool) -> str:
    if not chinese:
        return value
    return {
        "template_only": "仅模板",
        "latent_unverified": "潜在，未验证",
        "active_unverified": "静态活跃，未验证",
        "runtime_attested": "运行时已证明",
        "not_established": "尚未建立",
    }.get(value, value)


def _priority_zh(value: str) -> str:
    return _severity_zh(value)


def _text(value: object, default: str) -> str:
    return value if isinstance(value, str) and value.strip() else default


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _number(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:.2f}"
    return "—"


__all__ = [
    "HOMI_COMBINED_REPORT_FORMAT",
    "HOMI_COMBINED_REPORT_VERSION",
    "HomiCombinedReport",
    "HomiCombinedReportError",
    "HomiRecommendation",
    "build_homi_combined_report",
    "build_homi_recommendations",
    "encode_homi_combined_report_json",
    "render_homi_combined_report_html",
    "render_homi_combined_report_text",
]

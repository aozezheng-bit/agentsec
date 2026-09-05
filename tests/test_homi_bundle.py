"""Combined Homi report and advisory rendering tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.frameworks.homi_bundle import (
    build_homi_combined_report,
    encode_homi_combined_report_json,
    render_homi_combined_report_html,
    render_homi_combined_report_text,
)
from agentsec.frameworks.homi_pilot import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotRequest,
)

runner = CliRunner()


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _pilot() -> dict[str, object]:
    return {
        "format": "agentsec-homi-report-only-pilot",
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
        "status": "partial",
        "project_name": "中文演示 Agent",
        "profile_complete": False,
        "resolution_status": "conflict",
        "coverage_metrics": {
            "capability_total": 4,
            "capability_unknown_count": 1,
            "standard_file_total": 6,
            "standard_file_missing_count": 1,
        },
        "capabilities": [],
        "combination": {
            "findings": [
                {
                    "rule_id": "HOMI-COMB-001",
                    "impact": "high",
                    "score": 5.5,
                    "texts": [
                        {
                            "language": "zh",
                            "title": "主动行为与外部能力组合出现",
                            "description": (
                                "人格规范鼓励主动行动，同时静态声明了外部能力。"
                            ),
                        }
                    ],
                }
            ]
        },
    }


def _diff() -> dict[str, object]:
    return {
        "format": "agentsec-homi-capability-diff",
        "authority": {
            "report_only": True,
            "runtime_verified": False,
            "ci_blocked": False,
        },
        "capability_change_summary": {"added": 1, "removed": 0, "modified": 1},
        "finding_delta_summary": {"added": 1, "resolved": 0},
        "risk_score": {"delta": 5.5},
    }


def _score() -> dict[str, object]:
    return {
        "format": "agentsec-agentic-assessment",
        "policy": {
            "report_only": True,
            "ci_blocking_enabled": False,
            "score_ci_authority": False,
        },
        "boundary": {
            "runtime_verified": False,
            "score_ci_authority": False,
        },
        "technical": {"technical_score": 8.2, "severity": "high"},
        "drift": {"drift_score": 6.4, "severity": "medium"},
        "governance": {"governance_score": 3.1, "severity": "low"},
        "overall": {
            "overall_score": 8.2,
            "severity": "high",
            "hard_gate": {"triggered": False},
        },
    }


def test_combined_report_contains_snapshot_diff_and_advisory_recommendations(
    tmp_path: Path,
) -> None:
    pilot_path = _write(tmp_path / "pilot.json", _pilot())
    diff_path = _write(tmp_path / "diff.json", _diff())
    score_path = _write(tmp_path / "score.json", _score())

    report = build_homi_combined_report(pilot_path, diff_path, score_path)
    payload = json.loads(encode_homi_combined_report_json(report))
    html = render_homi_combined_report_html(report, language="zh")

    assert payload["format"] == "agentsec-homi-combined-report"
    assert payload["authority"]["recommendations_are_advisory"] is True
    assert payload["authority"]["llm_authority"] is False
    assert payload["diff_report"] == _diff()
    assert payload["score_report"] == _score()
    assert "Agent 功能与能力概览" in html
    assert "技术风险" in html
    assert "三轴风险雷达图" in html
    assert "风险与整改建议" in html
    assert "主动行为与外部能力组合出现" in html
    assert "新增能力" in html
    assert "Homi LLM" in html
    assert "运行时" in html


def test_homi_bundle_cli_writes_chinese_html(tmp_path: Path) -> None:
    pilot_path = _write(tmp_path / "pilot.json", _pilot())
    diff_path = _write(tmp_path / "diff.json", _diff())
    score_path = _write(tmp_path / "score.json", _score())
    output = tmp_path / "combined.html"

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "bundle",
            "--pilot",
            str(pilot_path),
            "--diff",
            str(diff_path),
            "--score",
            str(score_path),
            "--format",
            "html",
            "--language",
            "zh",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    text = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in text
    assert "相对基线的能力漂移" in text
    assert "三轴风险雷达图" in text
    assert "Overall 综合评分" in text
    assert "不自动修改 Agent" in text


def test_combined_report_consumes_bound_calibration_and_posture_sidecars(
    tmp_path: Path,
) -> None:
    pilot_payload = _pilot()
    # Give the fixture Finding a stable identity so calibration can bind to it.
    finding = pilot_payload["combination"]["findings"][0]  # type: ignore[index]
    assert isinstance(finding, dict)
    finding["finding_id"] = "homi-combination-sha256:" + "a" * 64
    pilot_path = _write(tmp_path / "homi-pilot-report.json", pilot_payload)
    pilot_digest = hashlib.sha256(pilot_path.read_bytes()).hexdigest()
    _write(
        tmp_path / "homi-calibration.json",
        {
            "format": "agentsec-homi-calibration",
            "source_report_sha256": pilot_digest,
            "retained_findings": [],
        },
    )
    _write(
        tmp_path / "homi-posture.json",
        {
            "format": "agentsec-homi-posture",
            "source_report_sha256": pilot_digest,
            "raw_potential_impact_score": 8.0,
            "potential_impact_score": 0.0,
            "current_posture": "not_established",
            "current_posture_score": None,
            "suppressed_finding_count": 1,
        },
    )
    _write(
        tmp_path / "homi-risk-state.json",
        {
            "format": "agentsec-homi-risk-state",
            "source_report_sha256": pilot_digest,
            "counts": {
                "template": 2,
                "latent": 3,
                "active": 4,
                "unknown": 5,
                "runtime_attested": 0,
            },
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "ci_blocked": False,
            },
        },
    )
    _write(
        tmp_path / "homi-operation-context.json",
        {
            "format": "agentsec-homi-operation-context-extraction",
            "source_report_sha256": pilot_digest,
            "context_set": {
                "contexts": [{"operation_id": "homi.operation.unknown"}],
                "coverage_complete": False,
                "unknown_dimensions": ["homi.operation.unknown.action"],
            },
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "ci_blocked": False,
            },
        },
    )

    report = build_homi_combined_report(pilot_path)
    assert report.calibration_report is not None
    assert report.posture_report is not None
    assert report.calibration_report_sha256
    assert report.posture_report_sha256
    assert report.risk_state_report is not None
    assert report.risk_state_report_sha256
    assert report.operation_context_report is not None
    assert report.operation_context_report_sha256
    assert all(
        "HOMI-COMB-001" not in item.source_ids for item in report.recommendations
    )
    html = render_homi_combined_report_html(report, language="zh")
    assert "校准后潜在影响：0.0" in html
    assert "模板校准抑制：1 个 Finding" in html
    assert "状态分类 / Evidence State" in html
    assert "静态活跃" in html
    assert "操作上下文 / Operation Context" in html
    assert "已提取 1 条操作上下文" in html
    assert "暂无风险 Finding" in html


def _identified_pilot_with_two_findings() -> dict[str, object]:
    pilot_payload = _pilot()
    findings = pilot_payload["combination"]["findings"]  # type: ignore[index]
    assert isinstance(findings, list)
    first = findings[0]
    assert isinstance(first, dict)
    first["finding_id"] = "homi-combination-sha256:" + "a" * 64
    second = dict(first)
    second["finding_id"] = "homi-combination-sha256:" + "b" * 64
    findings.append(second)
    return pilot_payload


def test_combined_report_text_counts_match_calibrated_findings_in_both_languages(
    tmp_path: Path,
) -> None:
    pilot_path = _write(
        tmp_path / "homi-pilot-report.json", _identified_pilot_with_two_findings()
    )
    pilot_digest = hashlib.sha256(pilot_path.read_bytes()).hexdigest()
    _write(
        tmp_path / "homi-calibration.json",
        {
            "format": "agentsec-homi-calibration",
            "source_report_sha256": pilot_digest,
            "retained_findings": [
                {"finding_id": "homi-combination-sha256:" + "a" * 64}
            ],
        },
    )

    report = build_homi_combined_report(pilot_path)
    en = render_homi_combined_report_text(report, language="en")
    zh = render_homi_combined_report_text(report, language="zh")

    assert "Findings: 1\n" in en
    assert "风险 Findings：1 个" in zh
    assert "Findings: 2" not in en
    assert "风险 Findings：2 个" not in zh


def test_combined_report_rejects_malformed_calibration_retained_findings(
    tmp_path: Path,
) -> None:
    pilot_path = _write(
        tmp_path / "homi-pilot-report.json", _identified_pilot_with_two_findings()
    )
    pilot_digest = hashlib.sha256(pilot_path.read_bytes()).hexdigest()
    malformed_inputs = (
        ["not-an-object"],
        [{"finding_id": 123}],
        {"finding_id": "homi-combination-sha256:" + "a" * 64},
        "homi-combination-sha256:" + "a" * 64,
    )
    for retained in malformed_inputs:
        _write(
            tmp_path / "homi-calibration.json",
            {
                "format": "agentsec-homi-calibration",
                "source_report_sha256": pilot_digest,
                "retained_findings": retained,
            },
        )
        try:
            build_homi_combined_report(pilot_path)
        except ValueError as error:
            assert "retained_findings" in str(error)
        else:
            raise AssertionError("malformed retained_findings must be rejected")


def test_combined_report_rejects_sidecar_bound_to_a_different_pilot(
    tmp_path: Path,
) -> None:
    pilot_path = _write(tmp_path / "homi-pilot-report.json", _pilot())
    _write(
        tmp_path / "homi-posture.json",
        {
            "format": "agentsec-homi-posture",
            "source_report_sha256": "0" * 64,
        },
    )

    try:
        build_homi_combined_report(pilot_path)
    except ValueError as error:
        assert "not bound" in str(error)
    else:
        raise AssertionError("unbound sidecar must be rejected")


def test_combined_report_consumes_bound_context_risk_sidecar(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {
        "AGENTS.md": (
            "Read files for analysis.\n"
            "Read secrets only with approval.\n"
            "Sending emails requires asking first.\n"
            "Update AGENTS.md when a reviewed lesson matters.\n"
        ),
        "SOUL.md": "Be helpful.\n",
        "IDENTITY.md": "Name: Demo\n",
        "USER.md": "Timezone: Asia/Shanghai\n",
        "TOOLS.md": "No external tools.\n",
        "HEARTBEAT.md": "# disabled\n",
    }
    for name, content in files.items():
        (workspace / name).write_text(content, encoding="utf-8")
    output_dir = tmp_path / "report"
    DeterministicHomiReportOnlyPilot().run_and_write(
        HomiPilotRequest(
            pilot_id="bundle-risk-test",
            project_name="Context risk test",
            owner="security",
            target_root=workspace,
            output_root=output_dir,
        )
    )

    report = build_homi_combined_report(output_dir / "homi-pilot-report.json")
    assert report.context_risk_report is not None
    assert report.context_risk_report_sha256
    assert report.risk_score_report is not None
    assert report.risk_score_report_sha256
    html = render_homi_combined_report_html(report, language="zh")
    assert "上下文风险 / Context-aware Risk" in html
    assert "风险量化 / Risk Quantification" in html
    assert "残余风险" in html
    assert "RISK-04" in html


def test_homi_bundle_rejects_non_json_pilot(tmp_path: Path) -> None:
    pilot_path = tmp_path / "pilot.html"
    pilot_path.write_text("<html>untrusted</html>", encoding="utf-8")
    result = runner.invoke(
        create_app(),
        ["homi", "bundle", "--pilot", str(pilot_path)],
    )

    assert result.exit_code == 4

"""Combined Homi report and advisory rendering tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.frameworks.homi_bundle import (
    build_homi_combined_report,
    encode_homi_combined_report_json,
    render_homi_combined_report_html,
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


def test_homi_bundle_rejects_non_json_pilot(tmp_path: Path) -> None:
    pilot_path = tmp_path / "pilot.html"
    pilot_path.write_text("<html>untrusted</html>", encoding="utf-8")
    result = runner.invoke(
        create_app(),
        ["homi", "bundle", "--pilot", str(pilot_path)],
    )

    assert result.exit_code == 4

"""Run the qualified, non-enforcing HG-CAPCHAIN-001 Report-only Gate demo.

The live scenarios are evaluated by the existing deterministic Shadow Gate demo.
This command adds the independently qualified Human Evidence status as a
presentation layer; it never changes Findings, score, Severity, hard_gate, or
CI behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

EXIT_READY = 0
EXIT_NOT_READY = 2
EXIT_INVALID = 4
EXIT_FAILED = 5
REPORT_FORMAT = "agentsec-report-only-gate-demo"
REPORT_SCHEMA_VERSION = "0.1.0"
GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"
MAX_JSON_BYTES = 8 * 1024 * 1024


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds the bounded size")
    payload: object = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, Any], payload)


def _artifact_id(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return (
        "report-only-gate-demo-sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )


def _run_shadow_demo(
    repository_root: Path, corpus: Path, language: str
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(repository_root / "scripts/run-shadow-gate-demo.py"),
        "--corpus",
        str(corpus),
        "--language",
        language,
        "--format",
        "json",
    ]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository_root / "src")
    completed = subprocess.run(
        command,
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in {EXIT_READY, EXIT_NOT_READY}:
        raise ValueError("Shadow Gate demo failed")
    payload: object = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise ValueError("Shadow Gate demo returned an invalid report")
    return cast(dict[str, Any], payload)


def _qualification(path: Path) -> dict[str, Any]:
    report = _read_json(path, "Qualification report")
    if (
        report.get("gate_id") != GATE_ID
        or report.get("rule_id") != RULE_ID
        or report.get("status") != "complete"
    ):
        raise ValueError("Qualification report binding is invalid")
    qualification = report.get("qualification")
    if not isinstance(qualification, dict):
        raise ValueError("Qualification section is invalid")
    artifact_id = report.get("artifact_id")
    if not isinstance(artifact_id, str) or artifact_id != _qualification_id(report):
        raise ValueError("Qualification report artifact ID is invalid")
    return report


def _qualification_id(report: dict[str, Any]) -> str:
    unsigned = dict(report)
    unsigned["artifact_id"] = None
    return (
        "qualification-report-sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )


def _build_report(
    *,
    shadow: dict[str, Any],
    qualification: dict[str, Any],
) -> dict[str, Any]:
    gate_qualification = qualification["qualification"]
    eligible = gate_qualification.get("eligible_for_report_only_gate") is True
    status = "passed" if eligible and shadow.get("status") == "passed" else "not_ready"
    scenarios = []
    for scenario in shadow.get("scenarios", []):
        if not isinstance(scenario, dict):
            raise ValueError("Shadow scenario is invalid")
        item = dict(scenario)
        item["report_only_mode"] = "report_only"
        item["report_only_qualified"] = eligible
        item["blocks"] = False
        item["hard_gate"] = False
        scenarios.append(item)
    matches = sum(item.get("actual_match") is True for item in scenarios)
    no_matches = len(scenarios) - matches
    return {
        "format": REPORT_FORMAT,
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": status,
        "gate": {
            "gate_id": GATE_ID,
            "component_rule_id": RULE_ID,
            "floor": "high",
            "mode": "report_only",
            "qualification": "accepted"
            if eligible
            else gate_qualification.get("status"),
            "qualification_report_artifact_id": qualification["artifact_id"],
            "blocks": False,
            "hard_gate": False,
            "ci_blocking": False,
        },
        "qualification": {
            "status": gate_qualification.get("status"),
            "eligible_for_report_only_gate": eligible,
            "metrics": qualification.get("metrics", {}),
            "confidence_calibration": qualification.get("confidence_calibration", {}),
            "sample_scope": qualification.get("sample_scope", {}),
        },
        "source_evaluation": {
            "format": shadow.get("format"),
            "status": shadow.get("status"),
            "mode": "shadow_evaluation",
            "gate_version": shadow.get("gate", {}).get("gate_version"),
        },
        "scenarios": scenarios,
        "summary": {
            "scenario_count": len(scenarios),
            "report_only_match_count": matches,
            "report_only_no_match_count": no_matches,
            "qualification_status": gate_qualification.get("status"),
            "qualification_eligible": eligible,
            "blocks": False,
            "hard_gate": False,
            "ci_blocking": False,
        },
        "boundary": {
            "enforcement_mode": "report_only",
            "runtime_capability_verified": False,
            "global_safety_claimed": False,
            "hard_gate_enabled": False,
            "ci_blocking_enabled": False,
            "fail_on_enabled": False,
            "llm_used": False,
            "source_evaluation_is_deterministic": True,
        },
        "artifact_id": None,
    }


def _render_text(report: dict[str, Any], language: str) -> str:
    zh = language == "zh"
    gate = report["gate"]
    qualification = report["qualification"]
    summary = report["summary"]
    lines = [
        "AgentSec HG-CAPCHAIN-001 Report-only Gate Demo"
        if not zh
        else "AgentSec HG-CAPCHAIN-001 Report-only Gate 演示",
        (
            f"Status: {report['status'].upper()}"
            if not zh
            else f"状态：{'通过' if report['status'] == 'passed' else '未就绪'}"
        ),
        f"Gate: {gate['gate_id']}",
        (
            "Mode: report_only; qualification=accepted; blocks=false; "
            "hard_gate=false; CI blocking=false"
            if not zh
            else "模式：仅报告；资格=accepted；blocks=false；hard_gate=false；不阻断 CI"
        ),
        "",
        "Qualification" if not zh else "资格结果",
        (
            f"  Status: {qualification['status']}"
            if not zh
            else f"  状态：{qualification['status']}"
        ),
        (
            f"  Precision: {qualification['metrics'].get('precision')}"
            if not zh
            else f"  Precision：{qualification['metrics'].get('precision')}"
        ),
        (
            f"  Recall: {qualification['metrics'].get('recall')}"
            if not zh
            else f"  Recall：{qualification['metrics'].get('recall')}"
        ),
        (
            "  Confidence calibration: "
            f"{qualification['confidence_calibration'].get('human_vs_detector_agreement_rate')}"
            if not zh
            else "  Confidence 校准："
            f"{qualification['confidence_calibration'].get('human_vs_detector_agreement_rate')}"
        ),
        "",
        "Live Report-only Scenarios" if not zh else "实时 Report-only 场景",
    ]
    for item in report["scenarios"]:
        state = "MATCH" if item["actual_match"] else "NO-MATCH"
        if zh:
            state = "命中" if item["actual_match"] else "未命中"
        lines.append(
            f"  [{state}] {item['scenario_id']} "
            f"correlation={item['finding_correlation']} "
            f"coverage_complete={item['coverage_complete']} "
            f"relevant_unknowns={item['relevant_unknowns']}"
        )
    lines.extend(
        [
            "",
            (
                f"Report-only matches: {summary['report_only_match_count']}; "
                f"no-match: {summary['report_only_no_match_count']}"
            )
            if not zh
            else (
                f"Report-only 命中：{summary['report_only_match_count']}；"
                f"未命中：{summary['report_only_no_match_count']}"
            ),
            (
                "Boundary: qualification affects presentation only; no runtime "
                "proof, authorization, or CI enforcement."
            )
            if not zh
            else "边界：资格只影响展示；不证明运行时能力，不授权，不阻断 CI。",
        ]
    )
    return "\n".join(lines) + "\n"


def _write_output(path: Path, content: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument(
        "--qualification-report",
        type=Path,
        default=Path(
            "calibration/p2-15a-capchain-40/human-evidence/"
            "hg-capchain-001-qualification-report-v2.json"
        ),
    )
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        repository_root = Path(__file__).resolve().parents[1]
        qualification = _qualification(args.qualification_report)
        shadow = _run_shadow_demo(repository_root, args.corpus, args.language)
        report = _build_report(shadow=shadow, qualification=qualification)
        report["artifact_id"] = _artifact_id(report)
        rendered = (
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if args.format == "json"
            else _render_text(report, args.language)
        )
        if args.output is None:
            print(rendered, end="")
        else:
            _write_output(args.output, rendered)
        if report["status"] != "passed":
            raise SystemExit(EXIT_NOT_READY)
    except SystemExit:
        raise
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"report-only Gate demo failed: {error}", file=sys.stderr)
        raise SystemExit(EXIT_INVALID) from None
    except Exception as error:  # noqa: BLE001 - bounded demo boundary
        print(
            f"report-only Gate demo failed: {type(error).__name__}",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILED) from None


if __name__ == "__main__":
    main()

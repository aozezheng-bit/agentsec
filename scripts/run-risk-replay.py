#!/usr/bin/env python3
"""Deterministic RISK-09 replay runner over the fixed scenario corpus.

Runs every scenario in ``pilots/risk-replay-r09`` through the production
Homi Pilot, Snapshot, Drift, and Risk APIs, asserts the recorded
expectations plus the machine-checkable acceptance rules from the risk
model plan (benign copy changes never raise risk; injected operations
always do; the corpus replays deterministically), and writes a summary.

The runner stays report-only: it never executes scenario content, never
touches a real Homi workspace, and never blocks CI.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from agentsec.frameworks import (  # noqa: E402
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
    build_homi_operation_context_report_from_workspace,
    build_homi_risk_report,
    build_homi_snapshot,
    decode_homi_snapshot_json,
    encode_homi_snapshot_json,
)

CORPUS_ROOT = REPOSITORY_ROOT / "pilots" / "risk-replay-r09"
PROJECT_NAME = "risk-replay-agent"
SUBJECT_ID = "homi:agent:risk-replay"
BENIGN_SCENARIOS = (
    "scenario-02",
    "scenario-03",
    "scenario-04",
    "scenario-05",
    "scenario-06",
)
INJECTED_SCENARIOS = (
    "scenario-07",
    "scenario-08",
    "scenario-10",
    "scenario-12",
    "scenario-14",
)


def _pilot() -> DeterministicHomiReportOnlyPilot:
    return DeterministicHomiReportOnlyPilot()


def _report(
    pilot: DeterministicHomiReportOnlyPilot, workspace: Path
) -> HomiPilotReport:
    return pilot.run(
        HomiPilotRequest(
            pilot_id="risk-replay",
            project_name=PROJECT_NAME,
            owner="security",
            target_root=workspace,
            output_root=workspace.parent / "replay-output",
        )
    )


def _check_scenario(
    name: str,
    expectation: dict[str, Any],
    risk: Any,
) -> list[str]:
    problems: list[str] = []
    expected_rules = list(expectation.get("expected_rule_ids", []))
    if sorted(risk.risk_reasons) != sorted(expected_rules):
        problems.append(
            f"rule mismatch: expected={expected_rules} actual={list(risk.risk_reasons)}"
        )
    direction = expectation.get("expected_risk_direction", "review")
    if direction == "low":
        if risk.risk_score != 0.0:
            problems.append(f"expected low risk, got {risk.risk_score}")
    elif direction == "high" and risk.risk_level != "high":
        problems.append(f"expected high risk, got {risk.risk_level}")
    if name in BENIGN_SCENARIOS and risk.drift_risk_score != 0.0:
        problems.append(f"benign change raised drift risk to {risk.drift_risk_score}")
    if name in INJECTED_SCENARIOS and risk.drift_risk_score <= 0.0:
        problems.append("injected operation did not raise drift risk")
    return problems


def run(corpus: Path, output_dir: Path) -> bool:
    expectations = json.loads(
        (corpus / "expectations.json").read_text(encoding="utf-8")
    )
    pilot = _pilot()
    scenario_names = sorted(
        item.name
        for item in corpus.iterdir()
        if item.is_dir() and item.name.startswith("scenario-")
    )
    if not scenario_names:
        raise RuntimeError(f"no scenarios found under {corpus}")

    reports: dict[str, Any] = {}
    risks: dict[str, Any] = {}
    problems: dict[str, list[str]] = {}

    baseline_report = _report(pilot, corpus / "scenario-01")
    baseline_operation_context = build_homi_operation_context_report_from_workspace(
        corpus / "scenario-01",
        baseline_report,
    )
    baseline_snapshot = build_homi_snapshot(
        baseline_report,
        subject_id=SUBJECT_ID,
        operation_context=baseline_operation_context,
    )
    first_digest = baseline_snapshot.snapshot_digest
    second_report = _report(pilot, corpus / "scenario-01")
    second_digest = build_homi_snapshot(
        second_report,
        subject_id=SUBJECT_ID,
        operation_context=build_homi_operation_context_report_from_workspace(
            corpus / "scenario-01",
            second_report,
        ),
    ).snapshot_digest
    if first_digest != second_digest:
        problems.setdefault("scenario-01", []).append("snapshot is not deterministic")
    if baseline_snapshot.coverage_metrics.get("standard_file_missing_count") != 0:
        problems.setdefault("scenario-01", []).append(
            "baseline scenario should have all six standard files"
        )

    for name in scenario_names:
        report = _report(pilot, corpus / name)
        reports[name] = report
        operation_context = build_homi_operation_context_report_from_workspace(
            corpus / name,
            report,
        )
        risk = build_homi_risk_report(
            report,
            subject_id=SUBJECT_ID,
            operation_context=operation_context,
            baseline=baseline_snapshot,
            baseline_operation_context=baseline_operation_context,
        )
        risks[name] = risk
        scenario_problems = _check_scenario(name, expectations.get(name, {}), risk)
        if scenario_problems:
            problems[name] = scenario_problems

    if risks["scenario-02"].drift_status != "verified":
        problems.setdefault("scenario-02", []).append(
            f"identical corpus should verify, got {risks['scenario-02'].drift_status}"
        )
    missing = reports["scenario-16"].coverage_metrics
    if missing.get("standard_file_missing_count") != 4:
        problems.setdefault("scenario-16", []).append(
            "incomplete coverage scenario should report four missing files"
        )
    if risks["scenario-16"].drift_status != "drifted":
        problems.setdefault("scenario-16", []).append(
            "deleted standard files must be reported as drift, got "
            f"{risks['scenario-16'].drift_status}"
        )
    if risks["scenario-16"].file_change_count != 4:
        problems.setdefault("scenario-16", []).append(
            "incomplete-file corpus should report four removed files"
        )

    tampered = json.loads(encode_homi_snapshot_json(baseline_snapshot))
    tampered["files"] = [
        dict(item, content_sha256="0" * 64) for item in tampered["files"]
    ]
    try:
        decode_homi_snapshot_json(json.dumps(tampered))
    except ValueError:
        pass
    else:
        problems.setdefault("scenario-15", []).append("tampered snapshot was accepted")

    passed = sum(1 for name in scenario_names if name not in problems)
    summary: dict[str, Any] = {
        "format": "agentsec-risk-replay-summary",
        "format_version": "0.1.0",
        "corpus": str(corpus.relative_to(REPOSITORY_ROOT)),
        "scenario_total": len(scenario_names),
        "scenario_passed": passed,
        "all_passed": passed == len(scenario_names),
        "authority": {
            "report_only": True,
            "runtime_verified": False,
            "ci_blocked": False,
        },
        "scenarios": {
            name: {
                "expected_rule_ids": expectations.get(name, {}).get(
                    "expected_rule_ids", []
                ),
                "actual_rule_ids": list(risks[name].risk_reasons),
                "risk_score": risks[name].risk_score,
                "risk_level": risks[name].risk_level,
                "drift_status": risks[name].drift_status,
                "drift_risk_score": risks[name].drift_risk_score,
                "passed": name not in problems,
                "problems": problems.get(name, []),
            }
            for name in scenario_names
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "replay-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# AgentSec RISK-09 回放结果",
        "",
        f"- 场景：{len(scenario_names)}，通过：{passed}",
        f"- 全部通过：{'是' if passed == len(scenario_names) else '否'}",
        "- 权限：report_only=true；runtime_verified=false；ci_blocked=false",
        "",
        "| 场景 | 预期规则 | 实际规则 | 风险 | 漂移 | 漂移风险 | 结果 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in scenario_names:
        entry = summary["scenarios"][name]
        lines.append(
            "| {name} | {expected} | {actual} | {score:.1f} ({level}) | {drift} | "
            "{drift_score:.1f} | {result} |".format(
                name=name,
                expected=", ".join(entry["expected_rule_ids"]) or "—",
                actual=", ".join(entry["actual_rule_ids"]) or "—",
                score=entry["risk_score"],
                level=entry["risk_level"],
                drift=entry["drift_status"],
                drift_score=entry["drift_risk_score"],
                result="✅" if entry["passed"] else "❌",
            )
        )
    (output_dir / "replay-summary.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    print(f"Risk replay: {passed}/{len(scenario_names)} scenarios passed")
    print(
        "AgentSec remains report-only; no runtime verification or CI blocking "
        "is claimed."
    )
    for name in scenario_names:
        if name in problems:
            for problem in problems[name]:
                print(f"FAIL {name}: {problem}", file=sys.stderr)
    return passed == len(scenario_names)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS_ROOT)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    corpus = args.corpus.resolve()
    if not corpus.is_dir():
        print(f"Corpus directory does not exist: {corpus}", file=sys.stderr)
        return 2
    if args.output_dir is None:
        with tempfile.TemporaryDirectory(prefix="agentsec-risk-replay-") as temporary:
            ok = run(corpus, Path(temporary))
    else:
        ok = run(corpus, args.output_dir.resolve())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

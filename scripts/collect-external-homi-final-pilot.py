#!/usr/bin/env python3
"""Collect the 20-state P2-EXIT-06 external Homi report-only Pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from agentsec.external_pilot import (
    EXTERNAL_HOMI_PILOT_ID,
    HOMI_PILOT_SCENARIOS,
    deploy_external_homi_bundle,
    prepare_external_homi_bundle,
)
from agentsec.pilot import (
    PilotError,
    PilotRunner,
    encode_pilot_report_json,
    load_pilot_plan,
    render_pilot_report_markdown,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = (
    REPOSITORY_ROOT
    / "pilots"
    / "external-homi-demo"
    / "source"
    / "workspace-files-20260826.zip"
)
DEFAULT_BUNDLE = REPOSITORY_ROOT / "pilots" / "external-homi-demo" / "final-pilot"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--bundle-root", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--trust-root", type=Path, required=True)
    parser.add_argument("--collection-date", default="2026-08-26")
    parser.add_argument("--owner", default="homi-agent-platform-owner")
    parser.add_argument(
        "--agentsec", type=Path, default=REPOSITORY_ROOT / ".venv/bin/agentsec"
    )
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _write_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _decision_evidence(raw_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    active_seen = False
    expired_seen = False
    active_finding_visible = False
    expired_block_restored = False
    for scenario in HOMI_PILOT_SCENARIOS:
        path = raw_root / scenario.case_id / "agentsec-assessment.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        decision = payload["decision"]
        assessment = payload["assessment_report"]["assessment"]
        rules = sorted({item["rule_id"] for item in assessment["findings"]})
        applied = sorted(decision["applied_waiver_ids"])
        expired = sorted(decision["expired_waiver_ids"])
        if scenario.case_id == "pr-03":
            active_seen = "external-pilot-exec-active" in applied
            active_finding_visible = "MD-EXEC-001" in rules
        if scenario.case_id == "pr-04":
            expired_seen = "external-pilot-secret-expired" in expired
            expired_block_restored = (
                decision["decision"] == "block"
                and "MD-SECRET-001" in decision["matched_rule_ids"]
            )
        decisions.append(
            {
                "case_id": scenario.case_id,
                "decision": decision["decision"],
                "exit_code": decision["exit_code"],
                "coverage_complete": decision["coverage_complete"],
                "observed_rule_ids": rules,
                "applied_waiver_ids": applied,
                "expired_waiver_ids": expired,
                "blocking_finding_count": len(decision["blocking_finding_ids"]),
            }
        )
    lifecycle = {
        "active_waiver_applied": active_seen,
        "active_waived_finding_remained_visible": active_finding_visible,
        "expired_waiver_reported": expired_seen,
        "expired_waiver_restored_blocking": expired_block_restored,
        "passed": all(
            (
                active_seen,
                active_finding_visible,
                expired_seen,
                expired_block_restored,
            )
        ),
    }
    return decisions, lifecycle


def _summary(evidence: dict[str, Any]) -> str:
    report = evidence["report"]
    scope = evidence["scope"]
    waiver = evidence["waiver_lifecycle"]
    return "\n".join(
        (
            "# P2-EXIT-06-04 External Homi Final Pilot Collection",
            "",
            f"- Collection date: {evidence['collection_date']}",
            f"- Pilot ID: `{evidence['pilot_id']}`",
            f"- Engineering contracts: {report['passed_cases']}/{report['cases']}",
            f"- Status: `{report['status']}`",
            f"- Scope complete: {scope['complete']}",
            (
                f"- Baseline / PR states: {scope['baseline_states']} / "
                f"{scope['pull_request_states']}"
            ),
            f"- Required drills complete: {scope['required_drills_complete']}",
            f"- Waiver lifecycle passed: {waiver['passed']}",
            f"- Independent labels complete: {report['human_labels_complete']}",
            f"- Acceptance ready: {report['acceptance_ready']}",
            "",
            "## Boundary",
            "",
            "- Report-only engineering evidence; no release authorization.",
            (
                "- Scanned Markdown, scripts, Hooks, Skills, and MCP servers were "
                "not executed."
            ),
            "- Engineering expectations are not independent human labels.",
            (
                "- A real independent Reviewer must complete `reviewer-pack/` "
                "before final replay."
            ),
            "",
        )
    )


def main() -> int:
    args = _arguments()
    final_root = args.bundle_root
    if final_root.exists() or final_root.is_symlink():
        print("Collection failed safely: bundle root must not already exist")
        return 5
    try:
        final_root.resolve().relative_to(REPOSITORY_ROOT.resolve())
    except (OSError, RuntimeError, ValueError):
        print(
            "Collection failed safely: bundle root must be inside AgentSec control root"
        )
        return 5
    working = final_root.parent / f".{final_root.name}.collect-{os.getpid()}"
    target_created = False
    trust_created = False
    try:
        prepared = prepare_external_homi_bundle(
            source_archive=args.source_archive,
            bundle_root=working,
            collection_date=args.collection_date,
            owner=args.owner,
        )
        target, trust = deploy_external_homi_bundle(
            bundle_root=working,
            target_root=args.target_root,
            trust_root=args.trust_root,
        )
        target_created = True
        trust_created = True
        before = _tree_hashes(target)
        loaded = load_pilot_plan(
            prepared.plan_path,
            repository_root=REPOSITORY_ROOT,
            target_root=target,
            trust_root=trust,
        )
        raw = working / ".raw-agentsec-results"
        report = PilotRunner().run(
            loaded,
            repository_root=REPOSITORY_ROOT,
            agentsec_executable=args.agentsec,
            output_root=raw,
            target_root=target,
            trust_root=trust,
            expect_policy_sha256=prepared.policy_sha256,
        )
        after = _tree_hashes(target)
        if before != after:
            raise PilotError("target workspace changed during report-only collection")
        decisions, waiver_lifecycle = _decision_evidence(raw)
        if report.metrics.failed_cases:
            raise PilotError("one or more engineering scenario contracts failed")
        if not report.metrics.scope_complete:
            raise PilotError("external Pilot scope contract is incomplete")
        if not waiver_lifecycle["passed"]:
            raise PilotError("Waiver lifecycle drill did not close")
        results = working / "results"
        _write_text(results / "pilot-report.json", encode_pilot_report_json(report))
        _write_text(results / "pilot-report.md", render_pilot_report_markdown(report))
        evidence: dict[str, Any] = {
            "format": "agentsec-external-homi-final-pilot-evidence",
            "format_version": "0.1.0",
            "task_id": "P2-EXIT-06-04",
            "collection_date": args.collection_date,
            "pilot_id": EXTERNAL_HOMI_PILOT_ID,
            "source_archive_sha256": prepared.source_sha256,
            "policy": {
                "sha256": prepared.policy_sha256,
                "digest_pin_verified": True,
                "separate_trust_root": True,
                "target_controlled": False,
            },
            "scope": {
                "states": report.metrics.cases,
                "baseline_states": report.metrics.baseline_scans,
                "pull_request_states": report.metrics.pull_request_scans,
                "required_drills": report.metrics.drill_counts,
                "required_drills_complete": all(
                    report.metrics.drill_counts.get(item, 0) >= 1
                    for item in (
                        "incomplete_coverage",
                        "risky_change",
                        "waiver_lifecycle",
                    )
                ),
                "complete": report.metrics.scope_complete,
            },
            "report": {
                "path": "results/pilot-report.json",
                "sha256": _sha256(results / "pilot-report.json"),
                "status": report.status,
                "cases": report.metrics.cases,
                "passed_cases": report.metrics.passed_cases,
                "failed_cases": report.metrics.failed_cases,
                "precision": report.metrics.precision,
                "recall": report.metrics.recall,
                "p95_duration_ms": report.metrics.p95_duration_ms,
                "human_labels_complete": report.metrics.human_labels_complete,
                "acceptance_ready": report.metrics.acceptance_ready,
            },
            "waiver_lifecycle": waiver_lifecycle,
            "safety": {
                "target_unchanged": True,
                "scanned_content_executed": False,
                "target_code_executed": False,
                "hooks_invoked": False,
                "skills_invoked": False,
                "mcp_servers_connected": False,
                "network_accessed": False,
            },
            "review": {
                "engineering_expectations_complete": True,
                "independent_human_labels_complete": False,
                "reviewer_pack_path": "reviewer-pack",
                "acceptance_ready": False,
            },
        }
        evidence_dir = working / "evidence"
        _write_json(evidence_dir / "collection-evidence.json", evidence)
        _write_json(
            evidence_dir / "waiver-drill-evidence.json",
            {
                "format": "agentsec-external-pilot-waiver-drill-evidence",
                "format_version": "0.1.0",
                "task_id": "P2-EXIT-06-04",
                "policy_sha256": prepared.policy_sha256,
                "waiver_lifecycle": waiver_lifecycle,
                "decisions": decisions,
            },
        )
        _write_text(evidence_dir / "collection-summary.md", _summary(evidence))
        shutil.rmtree(raw)
        os.replace(working, final_root)
    except (OSError, ValueError, PilotError) as error:
        if working.exists() and working.is_dir():
            shutil.rmtree(working)
        if target_created and args.target_root.exists():
            shutil.rmtree(args.target_root)
        if trust_created and args.trust_root.exists():
            shutil.rmtree(args.trust_root)
        print(f"Collection failed safely: {error}")
        return 5

    print(f"External Homi Pilot bundle: {final_root}")
    print(
        f"Engineering evidence: {report.metrics.passed_cases}/{report.metrics.cases} "
        f"cases; status={report.status}; scope_complete={report.metrics.scope_complete}"
    )
    print("Independent human labels remain pending; acceptance_ready=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

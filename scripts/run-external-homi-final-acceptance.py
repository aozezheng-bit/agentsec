#!/usr/bin/env python3
"""Replay the external Homi Pilot with independent labels and run entry review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

from agentsec.external_pilot import (
    ExternalPilotWorkflowError,
    deploy_external_homi_bundle,
    validate_external_human_evidence,
)
from agentsec.pilot import (
    PilotError,
    PilotRunner,
    encode_pilot_report_json,
    load_pilot_plan,
    render_pilot_report_markdown,
)
from agentsec.release_review import (
    DeterministicPhase3EntryReview,
    Phase3EntryReviewRequest,
    Phase3ReviewLanguage,
    Phase3ReviewStage,
    encode_phase3_entry_review_json,
    render_phase3_entry_review_text,
)
from agentsec.versioning import PACKAGE_VERSION, RISK_MODEL_VERSION, RULE_PACK_VERSION

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = REPOSITORY_ROOT / "pilots" / "external-homi-demo" / "final-pilot"
DEFAULT_HUMAN_EVIDENCE = DEFAULT_BUNDLE / "human-evidence"
DEFAULT_OUTPUT = DEFAULT_BUNDLE / "final-results"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument(
        "--human-evidence-root", type=Path, default=DEFAULT_HUMAN_EVIDENCE
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--trust-root", type=Path, required=True)
    parser.add_argument(
        "--agentsec", type=Path, default=REPOSITORY_ROOT / ".venv/bin/agentsec"
    )
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    args = _arguments()
    if args.output_root.exists() or args.output_root.is_symlink():
        print("Final acceptance failed safely: output root must not already exist")
        return 5
    try:
        args.output_root.resolve().relative_to(REPOSITORY_ROOT.resolve())
    except (OSError, RuntimeError, ValueError):
        print("Final acceptance failed safely: output root must be inside AgentSec")
        return 5
    working = args.output_root.parent / f".{args.output_root.name}.tmp-{os.getpid()}"
    target_created = False
    trust_created = False
    output_promoted = False
    try:
        bundle = args.bundle_root.resolve(strict=True)
        policy_path = bundle / "protected-policy" / "organization-policy.yaml"
        policy_sha256 = _sha256(policy_path)
        target, trust = deploy_external_homi_bundle(
            bundle_root=bundle,
            target_root=args.target_root,
            trust_root=args.trust_root,
        )
        target_created = True
        trust_created = True
        before = _tree_hashes(target)
        loaded = load_pilot_plan(
            bundle / "pilot.yaml",
            repository_root=REPOSITORY_ROOT,
            target_root=target,
            trust_root=trust,
        )
        _labels_path, labels, _import_report = validate_external_human_evidence(
            human_evidence_root=args.human_evidence_root,
            reviewer_pack_root=bundle / "reviewer-pack",
        )
        raw = working / ".raw-agentsec-results"
        report = PilotRunner().run(
            loaded,
            repository_root=REPOSITORY_ROOT,
            agentsec_executable=args.agentsec,
            output_root=raw,
            target_root=target,
            trust_root=trust,
            expect_policy_sha256=policy_sha256,
            human_labels=labels,
        )
        after = _tree_hashes(target)
        if before != after:
            raise PilotError("target workspace changed during final replay")
        if report.status != "complete" or not report.metrics.acceptance_ready:
            raise PilotError("independent-label replay is not acceptance-ready")
        if report.metrics.failed_cases:
            raise PilotError("independent labels disagree with scanner outcomes")
        working.mkdir(parents=True, exist_ok=True)
        pilot_json = working / "pilot-report.json"
        _write_text(pilot_json, encode_pilot_report_json(report))
        _write_text(working / "pilot-report.md", render_pilot_report_markdown(report))
        shutil.rmtree(raw)
        os.replace(working, args.output_root)
        output_promoted = True
        pilot_json = args.output_root / "pilot-report.json"
        entry = DeterministicPhase3EntryReview().run(
            Phase3EntryReviewRequest(
                repository_root=REPOSITORY_ROOT,
                stage=Phase3ReviewStage.ENTRY_READINESS,
                external_pilot_report=pilot_json,
            )
        )
        _write_text(
            args.output_root / "phase3-entry-readiness.json",
            encode_phase3_entry_review_json(entry),
        )
        _write_text(
            args.output_root / "phase3-entry-readiness.md",
            render_phase3_entry_review_text(entry),
        )
        _write_text(
            args.output_root / "phase3-entry-readiness.zh.md",
            render_phase3_entry_review_text(entry, language=Phase3ReviewLanguage.ZH),
        )
        evidence = {
            "format": "agentsec-external-homi-final-acceptance-evidence",
            "format_version": "0.1.0",
            "task_id": "P2-EXIT-06-05",
            "pilot_id": report.pilot_id,
            "package_version": PACKAGE_VERSION,
            "rule_pack_version": RULE_PACK_VERSION,
            "risk_model_version": RISK_MODEL_VERSION,
            "pilot_report_sha256": _sha256(pilot_json),
            "human_label_source": report.human_label_source,
            "human_reviewer_ids": list(report.human_reviewer_ids),
            "cases": report.metrics.cases,
            "passed_cases": report.metrics.passed_cases,
            "false_positives": report.metrics.false_positives,
            "false_negatives": report.metrics.false_negatives,
            "precision": report.metrics.precision,
            "recall": report.metrics.recall,
            "p95_duration_ms": report.metrics.p95_duration_ms,
            "scope_complete": report.metrics.scope_complete,
            "human_labels_complete": report.metrics.human_labels_complete,
            "acceptance_ready": report.metrics.acceptance_ready,
            "target_unchanged": True,
            "phase3_entry_state": entry.state.value,
            "ready_for_phase3_shadow": entry.ready_for_phase3_shadow,
            "ready_for_release": entry.ready_for_release,
        }
        _write_text(
            args.output_root / "acceptance-evidence.json",
            json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        PilotError,
        ExternalPilotWorkflowError,
    ) as error:
        if working.exists() and working.is_dir():
            shutil.rmtree(working)
        if output_promoted and args.output_root.exists():
            shutil.rmtree(args.output_root)
        if target_created and args.target_root.exists():
            shutil.rmtree(args.target_root)
        if trust_created and args.trust_root.exists():
            shutil.rmtree(args.trust_root)
        print(f"Final acceptance failed safely: {error}")
        return 5

    print(
        f"External Pilot accepted: {report.metrics.passed_cases}/"
        f"{report.metrics.cases}; reviewer={report.human_reviewer_ids[0]}"
    )
    print(
        f"Phase 3 entry state: {entry.state.value}; "
        f"ready_for_phase3_shadow={entry.ready_for_phase3_shadow}; "
        "ready_for_release=false"
    )
    return 0 if entry.ready_for_phase3_shadow else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run the sanitized Homi capability-drift story through the production CLI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEMO_ROOT = REPOSITORY_ROOT / "demos" / "homi-capability-drift-zh"
CASES = (
    "baseline",
    "drift-add-external-message",
    "drift-modify-memory-policy",
    "drift-remove-safety-control",
)
EXPECTED_FINDINGS = {
    "baseline": set(),
    "drift-add-external-message": {"HOMI-COMB-001"},
    "drift-modify-memory-policy": {"HOMI-COMB-003"},
    "drift-remove-safety-control": {"HOMI-COMB-004"},
}


def _run_cli(*arguments: str) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(REPOSITORY_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    )
    process = subprocess.run(
        [sys.executable, "-m", "agentsec", *arguments],
        cwd=REPOSITORY_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return process.returncode, process.stdout, process.stderr


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid JSON artifact: {path}") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON artifact must be an object: {path}")
    return payload


def _finding_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    combination = report.get("combination")
    if not isinstance(combination, dict):
        raise RuntimeError("Homi report has no combination object")
    findings = combination.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError("Homi combination has no findings list")
    result: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("rule_id"), str):
            raise RuntimeError("Homi finding entry is malformed")
        result[item["rule_id"]] = item
    return result


def _render_story_text(payload: dict[str, Any]) -> str:
    lines = [
        "AgentSec Homi Capability Drift Demo",
        "===================================",
        f"Scenario: {payload['scenario']}",
        f"Status: {payload['status']}",
        f"Capability changes: {sum(payload['capability_change_summary'].values())}",
        (
            "  added={added} removed={removed} modified={modified}".format(
                **payload["capability_change_summary"]
            )
        ),
        (
            "Finding Delta: added={added} resolved={resolved} "
            "changed={changed} unchanged={unchanged}"
        ).format(
            **{key: len(value) for key, value in payload["finding_delta"].items()}
        ),
        (
            "Static score delta: {before} -> {after} ({delta:+.2f})".format(
                **payload["risk_score"]
            )
        ),
        "Authority: report_only=true runtime_verified=false ci_blocked=false",
        "",
        "Key changes:",
    ]
    for change in payload["capability_changes"]:
        lines.append(
            "- [{change_type}] {signal_id}: {before_state} -> {after_state}".format(
                **change
            )
        )
    if not payload["capability_changes"]:
        lines.append("- none")
    lines.extend(("", "Key Findings:"))
    for finding_id in payload["finding_ids"]:
        lines.append(f"- added {finding_id}")
    if not payload["finding_ids"]:
        lines.append("- none")
    lines.extend(
        ("", "This is static report-only evidence; it is not runtime attestation.")
    )
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-root", type=Path, default=DEFAULT_DEMO_ROOT)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--language", choices=("zh", "en"), default="zh")
    return parser


def _write_report_aliases(case: str, case_output: Path, output_root: Path) -> Path:
    """Expose paired report artifacts at stable demo paths."""

    source_json = case_output / "homi-pilot-report.json"
    source_md = case_output / "homi-pilot-report.md"
    source_html = case_output / "homi-pilot-report.html"
    for source in (source_json, source_md, source_html):
        if not source.is_file():
            raise RuntimeError(f"Homi report command did not produce {source}")
    aliases = {
        source_json: output_root / f"{case}.report.json",
        source_md: output_root / f"{case}.report.md",
        source_html: output_root / f"{case}.report.html",
    }
    for source, target in aliases.items():
        shutil.copyfile(source, target)
    return source_json


def _run_formal_diff(
    before_path: Path,
    after_path: Path,
    output_root: Path,
    case: str,
    language: str,
) -> dict[str, Any]:
    """Run the production Homi diff CLI for all supported output formats."""

    artifacts: dict[str, Path] = {}
    for output_format, suffix in (("json", "json"), ("text", "txt"), ("html", "html")):
        target = output_root / f"{case}.capability-diff.{suffix}"
        code, _stdout, stderr = _run_cli(
            "homi",
            "diff",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--format",
            output_format,
            "--language",
            language,
            "--output",
            str(target),
            "--force",
        )
        if code != 0:
            raise RuntimeError(f"Homi diff failed for {case}: exit={code} {stderr}")
        if not target.is_file():
            raise RuntimeError(f"Homi diff did not produce {target}")
        artifacts[output_format] = target

    formal = _load_json(artifacts["json"])
    if formal.get("format") != "agentsec-homi-capability-diff":
        raise RuntimeError(f"Unexpected Homi diff format for {case}")
    return formal


def _story_payload(
    case: str,
    report: dict[str, Any],
    formal_diff: dict[str, Any],
) -> dict[str, Any]:
    capability_changes = formal_diff["capability_changes"]
    finding_deltas = formal_diff["finding_deltas"]
    delta = {
        key: [item["rule_id"] for item in finding_deltas if item["delta_type"] == key]
        for key in ("added", "resolved", "changed", "unchanged")
    }
    finding_ids = list(delta["added"])
    return {
        "format": "agentsec-homi-capability-drift-demo-report",
        "schema_version": "0.1.0",
        "scenario": case,
        "status": report["status"],
        "capability_changes": capability_changes,
        "capability_change_summary": formal_diff["capability_change_summary"],
        "finding_delta": delta,
        "finding_delta_summary": formal_diff["finding_delta_summary"],
        "finding_ids": finding_ids,
        "risk_score": formal_diff["risk_score"],
        "authority": formal_diff["authority"],
        "formal_diff": {
            "format": formal_diff["format"],
            "format_version": formal_diff["format_version"],
            "before_report_sha256": formal_diff["before_report_sha256"],
            "after_report_sha256": formal_diff["after_report_sha256"],
        },
    }


def main() -> int:
    args = _build_parser().parse_args()
    demo_root = args.demo_root.resolve()
    if not demo_root.is_dir():
        print(f"Demo root does not exist: {demo_root}", file=sys.stderr)
        return 2

    temporary_output: tempfile.TemporaryDirectory[str] | None = None
    if args.output_dir is None:
        temporary_output = tempfile.TemporaryDirectory(prefix="agentsec-homi-drift-")
        output_root = Path(temporary_output.name)
    else:
        output_root = args.output_dir.resolve()
        if output_root.exists() and any(output_root.iterdir()):
            print(f"Output directory must be empty: {output_root}", file=sys.stderr)
            return 2
        output_root.mkdir(parents=True, exist_ok=True)

    try:
        reports: dict[str, dict[str, Any]] = {}
        report_paths: dict[str, Path] = {}
        for case in CASES:
            case_root = demo_root / case
            if not case_root.is_dir():
                print(f"Missing demo case: {case_root}", file=sys.stderr)
                return 2
            case_output = output_root / "reports" / case
            case_output.parent.mkdir(parents=True, exist_ok=True)
            code, _stdout, stderr = _run_cli(
                "homi",
                "report",
                str(case_root),
                "--output-dir",
                str(case_output),
                "--language",
                args.language,
                "--force",
            )
            # Homi report intentionally uses a non-zero finding status while still
            # producing artifacts. Only unexpected operational failures abort demo.
            if code not in (0, 2):
                print(
                    f"Homi report failed for {case}: exit={code}\n{stderr}",
                    file=sys.stderr,
                )
                return 1
            report_paths[case] = _write_report_aliases(case, case_output, output_root)
            reports[case] = _load_json(report_paths[case])

        for case in CASES:
            actual_findings = set(_finding_map(reports[case]))
            if actual_findings != EXPECTED_FINDINGS[case]:
                print(
                    f"Unexpected findings for {case}: "
                    f"expected={sorted(EXPECTED_FINDINGS[case])} "
                    f"actual={sorted(actual_findings)}",
                    file=sys.stderr,
                )
                return 1

        story_index: dict[str, Any] = {
            "format": "agentsec-homi-capability-drift-demo",
            "schema_version": "0.1.0",
            "language": args.language,
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "ci_blocked": False,
            },
            "scenarios": {},
        }
        baseline_path = report_paths["baseline"]
        for case in CASES[1:]:
            formal_diff = _run_formal_diff(
                baseline_path,
                report_paths[case],
                output_root,
                case,
                args.language,
            )
            story = _story_payload(case, reports[case], formal_diff)
            for suffix, content in (
                ("json", json.dumps(story, ensure_ascii=False, indent=2) + "\n"),
                ("txt", _render_story_text(story)),
            ):
                (output_root / f"{case}.drift.{suffix}").write_text(
                    content, encoding="utf-8"
                )
            shutil.copyfile(
                output_root / f"{case}.capability-diff.html",
                output_root / f"{case}.drift.html",
            )
            story_index["scenarios"][case] = {
                "report": f"{case}.report.html",
                "formal_diff": {
                    "json": f"{case}.capability-diff.json",
                    "text": f"{case}.capability-diff.txt",
                    "html": f"{case}.capability-diff.html",
                },
                "story": {
                    "json": f"{case}.drift.json",
                    "text": f"{case}.drift.txt",
                    "html": f"{case}.drift.html",
                },
                "capability_changes": story["capability_change_summary"],
                "finding_delta": {
                    key: len(value) for key, value in story["finding_delta"].items()
                },
                "risk_score_delta": story["risk_score"]["delta"],
            }

        (output_root / "story-index.json").write_text(
            json.dumps(story_index, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Homi Capability Drift Demo output directory: {output_root}")
        print("Homi Capability Drift Demo validation passed")
        print(
            "AgentSec remains static and report-only; "
            "no runtime exploit or CI block is claimed."
        )
        return 0
    except (OSError, RuntimeError, KeyError, TypeError, ValueError) as error:
        print(f"Homi Capability Drift Demo failed safely: {error}", file=sys.stderr)
        return 1
    finally:
        if temporary_output is not None:
            temporary_output.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

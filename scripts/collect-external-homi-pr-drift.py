#!/usr/bin/env python3
"""Collect ten inert Homi PR snapshots and deterministic drift evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotLanguage,
    HomiPilotRequest,
    encode_homi_pilot_json,
    render_homi_pilot_text,
)

_PLAN_FORMAT = "agentsec-external-homi-pr-change-plan"
_PLAN_VERSION = "0.1.0"
_DRIFT_FORMAT = "agentsec-homi-capability-drift-evidence"
_DRIFT_VERSION = "0.1.0"
_AGGREGATE_FORMAT = "agentsec-external-homi-pr-change-evidence"
_AGGREGATE_VERSION = "0.1.0"
_STANDARD_FILES = (
    "AGENTS.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "SOUL.md",
    "TOOLS.md",
    "USER.md",
)
_SCENARIO_IDS = tuple(
    f"pr-{index:02d}-{suffix}"
    for index, suffix in enumerate(
        (
            "heartbeat-template-disabled",
            "startup-policy-alignment",
            "real-heartbeat-activation",
            "remove-external-actions",
            "remove-external-approval-boundary",
            "activate-ssh-binding",
            "activate-mcp-oauth-secret",
            "disable-persistent-memory",
            "disable-self-modification",
            "tools-coverage-missing",
        ),
        start=1,
    )
)
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
_FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
_FORBIDDEN_REPORT_VALUES = (
    "192.168.1.100",
    "mdn.alipayobjects.com",
    "prod-bastion.internal",
    "release.write",
    "deployment-token",
    "internal-ops-mcp",
)

Workspace = dict[str, str]
Transformer = Callable[[Workspace], Workspace]


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-archive", required=True, type=Path)
    parser.add_argument("--baseline-report", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--collection-date", required=True)
    parser.add_argument("--owner", default="homi-agent-platform-owner")
    return parser.parse_args()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"{label} is missing, non-regular, or oversized")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _read_baseline_archive(path: Path) -> tuple[Path, Workspace]:
    if path.is_symlink():
        raise ValueError("baseline archive must not be a symbolic link")
    archive = path.resolve(strict=True)
    if not archive.is_file() or archive.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise ValueError("baseline archive is missing or oversized")
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = tuple(sorted(item.filename for item in infos if not item.is_dir()))
            if names != _STANDARD_FILES or len(infos) != len(_STANDARD_FILES):
                raise ValueError("baseline archive must contain six Homi files")
            workspace: Workspace = {}
            for item in infos:
                name = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                if (
                    name.is_absolute()
                    or ".." in name.parts
                    or "\\" in item.filename
                    or stat.S_ISLNK(mode)
                ):
                    raise ValueError("baseline archive contains unsafe paths")
                workspace[item.filename] = bundle.read(item).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile) as error:
        raise ValueError("baseline archive is unreadable") from error
    return archive, workspace


def _validated_new_directory(path: Path, label: str) -> Path:
    if path.exists() or path.is_symlink():
        raise ValueError(f"{label} must not already exist")
    parent = path.parent.resolve(strict=True)
    if not path.name:
        raise ValueError(f"{label} is invalid")
    return parent / path.name


def _load_plan(path: Path) -> tuple[dict[str, Any], ...]:
    payload = _read_json(path, label="PR change plan")
    if payload.get("format") != _PLAN_FORMAT:
        raise ValueError("PR change plan format is unsupported")
    if payload.get("format_version") != _PLAN_VERSION:
        raise ValueError("PR change plan version is unsupported")
    if payload.get("task_id") != "P2-EXIT-06-03":
        raise ValueError("PR change plan task ID is invalid")
    if payload.get("independent_human_review") is not False:
        raise ValueError("PR change plan cannot claim independent human review")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 10:
        raise ValueError("PR change plan requires exactly ten scenarios")
    if tuple(item.get("scenario_id") for item in scenarios) != _SCENARIO_IDS:
        raise ValueError("PR change scenarios are missing or out of order")
    for item in scenarios:
        if not isinstance(item.get("expected"), dict):
            raise ValueError("each PR change scenario requires expected drift")
    return tuple(scenarios)


def _align_soul(text: str) -> str:
    old = (
        "## Continuity\n\n"
        "Each session, you wake up fresh. These files _are_ your memory. "
        "Read them. Update them. They're how you persist.\n\n"
        "If you change this file, tell the user — it's your soul, and they "
        "should know.\n"
    )
    new = (
        "## Continuity\n\n"
        "Use runtime-provided startup context first. Read a workspace file only "
        "when the provided context is missing required information.\n\n"
        "If this persona file is changed through an approved review, tell the "
        "user.\n"
    )
    if old not in text:
        raise ValueError("baseline SOUL.md continuity section is unexpected")
    return text.replace(old, new)


def _copy_workspace(workspace: Workspace) -> Workspace:
    return dict(workspace)


def _pr_01(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["HEARTBEAT.md"] = (
        "# No scheduled tasks are configured.\n"
        "# Keep this file comment-only to disable heartbeat work.\n"
    )
    return result


def _pr_02(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["SOUL.md"] = _align_soul(result["SOUL.md"])
    return result


def _pr_03(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["HEARTBEAT.md"] = (
        "# Active Heartbeat Tasks\n\n"
        "- Check urgent unread email every 30 minutes.\n"
        "- Check calendar events in the next 24 hours.\n"
        "- Search the web for relevant weather alerts.\n"
    )
    return result


def _pr_04(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    excluded = (
        "search the web",
        "check calendars",
        "sending emails",
        "public posts",
        "emails**",
        "calendar**",
        "mentions**",
        "weather",
    )
    result["AGENTS.md"] = (
        "\n".join(
            line
            for line in result["AGENTS.md"].splitlines()
            if not any(marker in line.lower() for marker in excluded)
        )
        + "\n"
    )
    return result


def _pr_05(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    text = result["SOUL.md"]
    text = text.replace(
        "Be careful with external actions (emails, tweets, anything public). "
        "Be bold with internal ones (reading, organizing, learning).",
        "Communicate outside the workspace when useful. Be bold with internal work.",
    )
    text = text.replace(
        "When in doubt, ask before acting externally.",
        "Use your own judgment before communicating outside the workspace.",
    )
    result["SOUL.md"] = text
    return result


def _pr_06(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["TOOLS.md"] = (
        "# TOOLS.md - Active Local Bindings\n\n"
        "## SSH\n"
        "- production-bastion -> prod-bastion.internal, user: deploy\n\n"
        "## TTS\n"
        "- Preferred voice: Nova\n"
    )
    return result


def _pr_07(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["TOOLS.md"] = (
        "# TOOLS.md - Active Service Bindings\n\n"
        "## MCP\n"
        "- internal-ops-mcp -> configured by the platform\n\n"
        "## OAuth\n"
        "- deployment-service -> scope: release.write\n\n"
        "## Credential Alias\n"
        "- deployment-token -> managed secret reference; value not stored here\n"
    )
    return result


def _pr_08(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    agents = result["AGENTS.md"]
    memory_start = agents.index("## Memory\n")
    memory_end = agents.index("\n## Red Lines\n")
    agents = (
        agents[:memory_start]
        + "## Session Data\n\n"
        + "Use only information provided in the current session. Do not store "
        + "personal details after the session ends.\n"
        + agents[memory_end:]
    )
    maintenance_start = agents.index("### 🔄 Memory Maintenance")
    maintenance_end = agents.index("\n## Make It Yours\n")
    result["AGENTS.md"] = agents[:maintenance_start] + agents[maintenance_end:]
    result["USER.md"] = (
        "# USER.md - Current Request Only\n\n"
        "Use only details explicitly provided for the current request.\n"
        "Do not maintain a reusable user profile.\n"
    )
    return result


def _pr_09(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    soul = result["SOUL.md"]
    soul = soul.replace(
        "If you change this file, tell the user — it's your soul, and they "
        "should know.",
        "Persona changes require an explicit reviewed change request.",
    )
    soul = soul.replace(
        "_This file is yours to evolve. As you learn who you are, update it._",
        "_This persona is controlled configuration and changes require review._",
    )
    result["SOUL.md"] = soul
    result["IDENTITY.md"] = (
        "# IDENTITY.md - Fixed Demo Identity\n\n"
        "- Name: HomiClaw\n"
        "- Creature: AI assistant\n"
        "- Vibe: calm and precise\n"
        "- Emoji: ✨\n"
        "- Avatar: avatars/homiclaw.png\n\n"
        "Identity changes require an explicit reviewed configuration update.\n"
    )
    return result


def _pr_10(workspace: Workspace) -> Workspace:
    result = _copy_workspace(workspace)
    result["SOUL.md"] = _align_soul(result["SOUL.md"])
    del result["TOOLS.md"]
    return result


_TRANSFORMERS: dict[str, Transformer] = dict(
    zip(
        _SCENARIO_IDS,
        (
            _pr_01,
            _pr_02,
            _pr_03,
            _pr_04,
            _pr_05,
            _pr_06,
            _pr_07,
            _pr_08,
            _pr_09,
            _pr_10,
        ),
        strict=True,
    )
)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _workspace_hashes(workspace: Path) -> dict[str, str]:
    return {
        path.name: _sha256_path(path)
        for path in sorted(workspace.iterdir())
        if path.is_file()
    }


def _write_workspace(path: Path, workspace: Workspace) -> None:
    path.mkdir()
    for name, text in sorted(workspace.items()):
        _write_text(path / name, text)


def _write_snapshot(path: Path, workspace: Workspace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, text in sorted(workspace.items()):
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, text.encode("utf-8"))


def _signals(report: dict[str, Any], key: str) -> dict[str, str]:
    values = report.get(key, [])
    if not isinstance(values, list):
        raise ValueError(f"report {key} is invalid")
    return {
        str(item["signal_id"]): str(item["state"])
        for item in values
        if isinstance(item, dict)
    }


def _file_map(report: dict[str, Any]) -> dict[str, tuple[str, str | None]]:
    return {
        str(item["name"]): (
            str(item["state"]),
            item.get("content_sha256")
            if isinstance(item.get("content_sha256"), str)
            else None,
        )
        for item in report["files"]
    }


def _finding_map(report: dict[str, Any]) -> dict[str, str]:
    return {
        str(item["rule_id"]): str(item["finding_id"])
        for item in report["combination"]["findings"]
    }


def _simulation_map(report: dict[str, Any]) -> dict[str, str]:
    return {
        str(item["scenario_id"]): str(item["outcome"])
        for item in report["simulation"]["steps"]
    }


def _observation_codes(report: dict[str, Any]) -> set[str]:
    return {str(item["code"]) for item in report["observations"]}


def _transition_map(
    before: dict[str, str], after: dict[str, str]
) -> dict[str, list[str]]:
    return {
        key: [before.get(key, "unknown"), after.get(key, "unknown")]
        for key in sorted(set(before) | set(after))
        if before.get(key, "unknown") != after.get(key, "unknown")
    }


def _file_changes(
    before: dict[str, tuple[str, str | None]],
    after: dict[str, tuple[str, str | None]],
) -> dict[str, str]:
    changes: dict[str, str] = {}
    for name in sorted(set(before) | set(after)):
        if before.get(name) == after.get(name):
            continue
        after_state = after.get(name, ("missing", None))[0]
        changes[name] = "removed" if after_state == "missing" else "modified"
    return changes


def _build_drift(
    baseline: dict[str, Any],
    current: dict[str, Any],
    scenario: dict[str, Any],
    *,
    baseline_sha256: str,
    snapshot_sha256: str,
    report_sha256: str,
) -> dict[str, Any]:
    before_findings = _finding_map(baseline)
    after_findings = _finding_map(current)
    before_observations = _observation_codes(baseline)
    after_observations = _observation_codes(current)
    actual = {
        "status": current["status"],
        "resolution_status": current["resolution_status"],
        "file_changes": _file_changes(_file_map(baseline), _file_map(current)),
        "capability_changes": _transition_map(
            _signals(baseline, "capabilities"),
            _signals(current, "capabilities"),
        ),
        "persona_changes": _transition_map(
            _signals(baseline, "persona_signals"),
            _signals(current, "persona_signals"),
        ),
        "added_observations": sorted(after_observations - before_observations),
        "removed_observations": sorted(before_observations - after_observations),
        "added_findings": sorted(set(after_findings) - set(before_findings)),
        "removed_findings": sorted(set(before_findings) - set(after_findings)),
        "changed_findings": sorted(
            rule_id
            for rule_id in set(before_findings) & set(after_findings)
            if before_findings[rule_id] != after_findings[rule_id]
        ),
        "simulation_changes": _transition_map(
            _simulation_map(baseline),
            _simulation_map(current),
        ),
    }
    expected = scenario["expected"]
    contract_pass = actual == expected
    return {
        "format": _DRIFT_FORMAT,
        "format_version": _DRIFT_VERSION,
        "task_id": "P2-EXIT-06-03",
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "risk_direction": scenario["risk_direction"],
        "drill": scenario["drill"],
        "review": {
            "mode": "deterministic_scenario_contract",
            "outcome": scenario["review_outcome"],
            "contract_pass": contract_pass,
            "independent_human_review": False,
        },
        "provenance": {
            "baseline_report_sha256": baseline_sha256,
            "snapshot_archive_sha256": snapshot_sha256,
            "snapshot_report_sha256": report_sha256,
        },
        "before": {
            "status": baseline["status"],
            "resolution_status": baseline["resolution_status"],
            "report_only": baseline["report_only"],
            "runtime_verified": baseline["runtime_verified"],
            "ci_blocked": baseline["ci_blocked"],
        },
        "after": {
            "status": current["status"],
            "resolution_status": current["resolution_status"],
            "report_only": current["report_only"],
            "runtime_verified": current["runtime_verified"],
            "ci_blocked": current["ci_blocked"],
        },
        "expected": expected,
        "actual": actual,
        "limitations": [
            "Static Homi drift does not prove runtime reachability or execution.",
            (
                "Scenario-contract review is engineering evidence, not independent "
                "human TP/FP/FN adjudication."
            ),
            (
                "No drift result authorizes CI blocking, release, Tool access, "
                "or a waiver."
            ),
        ],
    }


def _render_drift(drift: dict[str, Any]) -> str:
    actual = drift["actual"]
    review = drift["review"]
    lines = [
        f"# Homi PR Drift: {drift['scenario_id']}",
        "",
        f"- Title: {drift['title']}",
        f"- Risk direction: {drift['risk_direction']}",
        f"- Contract pass: {review['contract_pass']}",
        f"- Review outcome: {review['outcome']}",
        f"- Independent human review: {review['independent_human_review']}",
        f"- Status: {drift['before']['status']} → {drift['after']['status']}",
        (
            "- Resolution: "
            f"{drift['before']['resolution_status']} → "
            f"{drift['after']['resolution_status']}"
        ),
        "",
        "## File changes",
        "",
    ]
    lines.extend(
        f"- `{name}`: {change}" for name, change in actual["file_changes"].items()
    )
    for heading, key in (
        ("Capability changes", "capability_changes"),
        ("Persona changes", "persona_changes"),
        ("Simulation changes", "simulation_changes"),
    ):
        lines.extend(("", f"## {heading}", ""))
        if actual[key]:
            lines.extend(
                f"- `{name}`: {values[0]} → {values[1]}"
                for name, values in actual[key].items()
            )
        else:
            lines.append("- None")
    lines.extend(("", "## Finding delta", ""))
    for label, key in (
        ("Added", "added_findings"),
        ("Removed", "removed_findings"),
        ("Changed evidence", "changed_findings"),
    ):
        values = actual[key]
        lines.append(f"- {label}: {', '.join(values) if values else 'None'}")
    lines.extend(("", "## Limitations", ""))
    lines.extend(f"- {item}" for item in drift["limitations"])
    return "\n".join(lines) + "\n"


def _summary_markdown(aggregate: dict[str, Any]) -> str:
    lines = [
        "# P2-EXIT-06-03 Homi PR/Change Drift Evidence",
        "",
        f"- Collection date: {aggregate['collection_date']}",
        f"- PR snapshots: {aggregate['metrics']['scenario_count']}",
        f"- Contract passes: {aggregate['metrics']['contract_pass_count']}",
        (
            "- Calibration-required scenarios: "
            f"{aggregate['metrics']['calibration_required_count']}"
        ),
        (
            "- Independent human review: "
            f"{aggregate['review']['independent_human_review']}"
        ),
        f"- Acceptance ready: {aggregate['acceptance_ready']}",
        "",
        "| Scenario | Direction | Status | Added | Removed | Changed | Review |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in aggregate["scenarios"]:
        lines.append(
            "| {scenario_id} | {risk_direction} | {status} | {added} | "
            "{removed} | {changed} | {review_outcome} |".format(
                scenario_id=item["scenario_id"],
                risk_direction=item["risk_direction"],
                status=item["status"],
                added=", ".join(item["added_findings"]) or "-",
                removed=", ".join(item["removed_findings"]) or "-",
                changed=", ".join(item["changed_findings"]) or "-",
                review_outcome=item["review_outcome"],
            )
        )
    lines.extend(("", "## Limitations", ""))
    lines.extend(f"- {item}" for item in aggregate["limitations"])
    return "\n".join(lines) + "\n"


def _validate_report_safety(report_text: str, target: Path) -> None:
    if str(target) in report_text:
        raise RuntimeError("Homi report leaked the absolute target path")
    if any(value in report_text for value in _FORBIDDEN_REPORT_VALUES):
        raise RuntimeError("Homi report leaked a source binding value")
    payload = json.loads(report_text)
    if (
        payload.get("report_only") is not True
        or payload.get("runtime_verified") is not False
        or payload.get("ci_blocked") is not False
        or payload.get("acceptance_ready") is not False
        or payload.get("simulation", {}).get("executed") is not False
        or payload.get("simulation", {}).get("side_effects") is not False
    ):
        raise RuntimeError("Homi report authority/simulation boundary changed")


def main() -> int:
    args = _arguments()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.collection_date):
        raise SystemExit("--collection-date must use YYYY-MM-DD")
    archive, baseline_workspace = _read_baseline_archive(args.baseline_archive)
    baseline_report_path = args.baseline_report.resolve(strict=True)
    baseline_report = _read_json(baseline_report_path, label="baseline report")
    if baseline_report.get("format") != "agentsec-homi-report-only-pilot":
        raise SystemExit("baseline report is not a Homi Pilot report")
    scenarios = _load_plan(args.plan)
    target_root = _validated_new_directory(args.target_root, "target root")
    output_root = _validated_new_directory(args.output_root, "output root")
    if (
        target_root == output_root
        or target_root in output_root.parents
        or output_root in target_root.parents
    ):
        raise SystemExit("target and output roots must not overlap")
    staging = output_root.with_name(f".{output_root.name}.tmp-{os.getpid()}")
    target_created = False
    aggregate_rows: list[dict[str, Any]] = []
    try:
        target_root.mkdir(mode=0o700)
        target_created = True
        staging.mkdir()
        baseline_sha256 = _sha256_path(baseline_report_path)
        for scenario in scenarios:
            scenario_id = str(scenario["scenario_id"])
            workspace = _TRANSFORMERS[scenario_id](baseline_workspace)
            target = target_root / scenario_id
            _write_workspace(target, workspace)
            before_scan = _workspace_hashes(target)

            snapshot_path = staging / "snapshots" / f"{scenario_id}.zip"
            _write_snapshot(snapshot_path, workspace)
            report_root = staging / "results" / scenario_id
            report_root.parent.mkdir(parents=True, exist_ok=True)
            report = DeterministicHomiReportOnlyPilot().run_and_write(
                HomiPilotRequest(
                    pilot_id=scenario_id,
                    project_name=f"Homi PR Snapshot {scenario_id}",
                    owner=args.owner,
                    target_root=target,
                    output_root=report_root,
                )
            )
            report_text = encode_homi_pilot_json(report)
            _validate_report_safety(report_text, target)
            _write_text(
                report_root / "homi-pilot-report.zh.md",
                render_homi_pilot_text(report, language=HomiPilotLanguage.ZH),
            )
            if before_scan != _workspace_hashes(target):
                raise RuntimeError("PR snapshot changed during report-only scan")

            report_path = report_root / "homi-pilot-report.json"
            current = json.loads(report_text)
            drift = _build_drift(
                baseline_report,
                current,
                scenario,
                baseline_sha256=baseline_sha256,
                snapshot_sha256=_sha256_path(snapshot_path),
                report_sha256=_sha256_path(report_path),
            )
            if drift["review"]["contract_pass"] is not True:
                raise RuntimeError(f"scenario contract failed: {scenario_id}")
            drift_path = staging / "drift" / f"{scenario_id}.json"
            _write_text(
                drift_path,
                json.dumps(drift, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            )
            _write_text(
                staging / "drift" / f"{scenario_id}.md",
                _render_drift(drift),
            )
            actual = drift["actual"]
            aggregate_rows.append(
                {
                    "scenario_id": scenario_id,
                    "title": scenario["title"],
                    "risk_direction": scenario["risk_direction"],
                    "drill": scenario["drill"],
                    "review_outcome": scenario["review_outcome"],
                    "contract_pass": True,
                    "status": actual["status"],
                    "resolution_status": actual["resolution_status"],
                    "snapshot_path": f"snapshots/{scenario_id}.zip",
                    "snapshot_sha256": _sha256_path(snapshot_path),
                    "report_path": f"results/{scenario_id}/homi-pilot-report.json",
                    "report_sha256": _sha256_path(report_path),
                    "drift_path": f"drift/{scenario_id}.json",
                    "drift_sha256": _sha256_path(drift_path),
                    "capability_change_count": len(actual["capability_changes"]),
                    "persona_change_count": len(actual["persona_changes"]),
                    "added_findings": actual["added_findings"],
                    "removed_findings": actual["removed_findings"],
                    "changed_findings": actual["changed_findings"],
                }
            )

        calibration_required = tuple(
            item["scenario_id"]
            for item in aggregate_rows
            if item["review_outcome"] == "calibration_required"
        )
        aggregate: dict[str, Any] = {
            "format": _AGGREGATE_FORMAT,
            "format_version": _AGGREGATE_VERSION,
            "task_id": "P2-EXIT-06-03",
            "collection_date": args.collection_date,
            "source": {
                "baseline_archive_name": archive.name,
                "baseline_archive_sha256": _sha256_path(archive),
                "baseline_report_sha256": baseline_sha256,
                "untrusted_input": True,
                "instruction_authority": False,
            },
            "review": {
                "mode": "deterministic_scenario_contract",
                "engineering_review_complete": True,
                "independent_human_review": False,
                "tp_fp_fn_complete": False,
                "calibration_required_scenarios": list(calibration_required),
            },
            "metrics": {
                "scenario_count": len(aggregate_rows),
                "pull_request_snapshot_count": len(aggregate_rows),
                "contract_pass_count": sum(
                    item["contract_pass"] is True for item in aggregate_rows
                ),
                "calibration_required_count": len(calibration_required),
                "risky_change_drill_count": sum(
                    item["drill"] == "risky_change" for item in aggregate_rows
                ),
                "incomplete_coverage_drill_count": sum(
                    item["drill"] == "incomplete_coverage" for item in aggregate_rows
                ),
                "waiver_lifecycle_drill_count": 0,
                "runtime_execution_count": 0,
                "side_effect_count": 0,
                "ci_block_count": 0,
            },
            "acceptance_ready": False,
            "scenarios": aggregate_rows,
            "limitations": [
                (
                    "Engineering scenario-contract review is complete, but "
                    "independent human labels are pending."
                ),
                (
                    "The baseline plus ten PR snapshots do not yet constitute "
                    "the full 20-scan acceptance set."
                ),
                "Waiver lifecycle evidence is deferred to P2-EXIT-06-04.",
                (
                    "Static drift does not prove runtime Tool, OAuth, scheduler, "
                    "permission, or exploit reachability."
                ),
                (
                    "All evidence remains report-only and cannot authorize CI "
                    "blocking or Phase 3 entry."
                ),
            ],
        }
        evidence_root = staging / "evidence"
        evidence_root.mkdir()
        _write_text(
            evidence_root / "pr-change-evidence.json",
            json.dumps(aggregate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        _write_text(
            evidence_root / "pr-change-summary.md", _summary_markdown(aggregate)
        )
        _write_text(
            staging / "README.md",
            (
                "# Homi PR/Change Drift Evidence\n\n"
                "Ten deterministic, inert PR snapshots derived from the "
                "user-supplied Homi baseline. Snapshots are stored as ZIP files "
                "so untrusted nested AGENTS.md files do not enter the AgentSec "
                "source instruction hierarchy.\n\n"
                "The engineering scenario contracts passed, but independent "
                "human review and final external acceptance remain pending.\n"
            ),
        )
        os.replace(staging, output_root)
    except Exception:
        if staging.exists() and staging.is_dir():
            shutil.rmtree(staging)
        if target_created and target_root.exists() and target_root.is_dir():
            shutil.rmtree(target_root)
        raise

    print(f"Homi PR demo root: {target_root}")
    print(f"PR drift evidence: {output_root}")
    print("Scenario contracts: 10/10 pass; acceptance_ready=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

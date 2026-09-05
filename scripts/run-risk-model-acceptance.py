#!/usr/bin/env python3
"""RISK-10A formal risk-model acceptance and installed Homi CLI smoke."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "pilots" / "risk-replay-r09"
FORMAT = "agentsec-risk-model-acceptance"
FORMAT_VERSION = "0.1.0"
TASK_ID = "RISK-10A"
SUBJECT_ID = "homi:agent:risk-10a-smoke"


class AcceptanceError(RuntimeError):
    """Fail-closed RISK-10A acceptance error."""


def _run(
    command: list[str], *, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"command failed safely: {command[1:3]}")
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError(f"invalid smoke artifact: {path.name}") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"smoke artifact must be object: {path.name}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _authority(payload: dict[str, Any]) -> bool:
    return (
        payload.get("report_only") is True
        and payload.get("runtime_verified") is False
        and payload.get("ci_blocked") is False
    )


def run(agentsec: Path, output: Path) -> dict[str, Any]:
    executable = agentsec.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise AcceptanceError("AgentSec executable is missing or not executable")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise AcceptanceError("output directory must be empty")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"

    version = _run([str(executable), "version"], env=env).stdout.strip()
    fingerprint_path = output / "homi-build-fingerprint.json"
    _run(
        [
            str(executable),
            "homi",
            "fingerprint",
            "--format",
            "json",
            "--output",
            str(fingerprint_path),
        ],
        env=env,
    )
    fingerprint = _load(fingerprint_path)

    baseline_dir = output / "baseline"
    current_dirs: dict[str, Path] = {}
    _run(
        [
            str(executable),
            "homi",
            "report",
            str(CORPUS / "scenario-01"),
            "--output-dir",
            str(baseline_dir),
            "--language",
            "zh",
            "--force",
        ],
        env=env,
    )
    expected = {
        "scenario-08": ("CTX-RISK-002", 8.0, "high"),
        "scenario-10": ("CTX-RISK-008", 5.5, "medium"),
        "scenario-12": ("CTX-RISK-006", 8.0, "high"),
    }
    scenario_results: dict[str, dict[str, Any]] = {}
    for scenario, (expected_rule_id, score, level) in expected.items():
        target = output / scenario
        current_dirs[scenario] = target
        _run(
            [
                str(executable),
                "homi",
                "report",
                str(CORPUS / scenario),
                "--output-dir",
                str(target),
                "--baseline-dir",
                str(baseline_dir),
                "--language",
                "zh",
                "--force",
            ],
            env=env,
        )
        risk = _load(target / "homi-risk-score.json")
        findings = _load(target / "homi-context-risk.json")
        ids: list[str] = []
        for item in findings.get("findings", []):
            if not isinstance(item, dict) or item.get("kind") != "risk":
                continue
            found_rule_id = item.get("rule_id")
            if isinstance(found_rule_id, str):
                ids.append(found_rule_id)
        ids.sort()
        checks = {
            "expected_rule_present": expected_rule_id in ids,
            "residual_score": risk.get("residual_risk_score") == score,
            "residual_level": risk.get("residual_risk_level") == level,
            "drift_score": risk.get("drift_score") == score,
            "report_only": _authority(risk) and _authority(findings),
            "html_written": (target / "homi-pilot-report.html").is_file(),
        }
        if not all(checks.values()):
            raise AcceptanceError(f"Homi smoke expectation failed: {scenario}")
        scenario_results[scenario] = {
            "rule_ids": ids,
            "risk_score": score,
            "risk_level": level,
            "checks": checks,
        }

    baseline_risk = _load(baseline_dir / "homi-risk-score.json")
    baseline_findings = _load(baseline_dir / "homi-context-risk.json")
    baseline_checks = {
        "zero_risk": baseline_risk.get("residual_risk_score") == 0.0,
        "zero_findings": baseline_findings.get("risk_finding_count") == 0,
        "report_only": _authority(baseline_risk) and _authority(baseline_findings),
        "html_written": (baseline_dir / "homi-pilot-report.html").is_file(),
    }
    if not all(baseline_checks.values()):
        raise AcceptanceError("baseline Homi smoke expectation failed")

    replay_dir = output / "replay"
    replay_env = env.copy()
    replay_env["PYTHONPATH"] = str(ROOT / "src")
    replay = subprocess.run(
        [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "scripts" / "run-risk-replay.py"),
            "--output-dir",
            str(replay_dir),
        ],
        cwd=ROOT,
        env=replay_env,
        capture_output=True,
        text=True,
        check=False,
    )
    replay_summary = _load(replay_dir / "replay-summary.json")
    replay_ok = replay.returncode == 0 and replay_summary.get("all_passed") is True
    if not replay_ok:
        raise AcceptanceError("fixed risk replay did not pass")

    artifacts = tuple(sorted(path for path in output.rglob("*") if path.is_file()))
    report: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "task_id": TASK_ID,
        "status": "accepted",
        "agentsec_version": version,
        "package_version": fingerprint.get("package_version"),
        "implementation_digest": fingerprint.get("implementation_digest"),
        "baseline_checks": baseline_checks,
        "scenario_results": scenario_results,
        "replay": {
            "scenario_total": replay_summary.get("scenario_total"),
            "scenario_passed": replay_summary.get("scenario_passed"),
            "all_passed": replay_ok,
        },
        "artifact_count": len(artifacts),
        "artifacts": [
            {
                "path": path.relative_to(output).as_posix(),
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
            for path in artifacts
        ],
        "report_only": True,
        "runtime_verified": False,
        "policy_authority": False,
        "ci_blocked": False,
        "network_accessed": False,
        "scanned_content_executed": False,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agentsec", type=Path, default=ROOT / ".venv" / "bin" / "agentsec"
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(prefix="agentsec-risk-10a-") as raw:
                report = run(args.agentsec, Path(raw))
        else:
            report = run(args.agentsec, args.output_dir.resolve())
    except (OSError, ValueError, AcceptanceError) as error:
        print(f"{TASK_ID} failed safely: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

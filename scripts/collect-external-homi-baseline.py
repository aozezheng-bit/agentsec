#!/usr/bin/env python3
"""Deploy an inert Homi export and collect report-only baseline evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotLanguage,
    HomiPilotRequest,
    encode_homi_pilot_json,
    render_homi_pilot_text,
)

_REQUIRED_FILES = (
    "AGENTS.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "SOUL.md",
    "TOOLS.md",
    "USER.md",
)
_MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
_MAX_EXPANDED_BYTES = 50 * 1024 * 1024
_MAX_FILE_BYTES = 2 * 1024 * 1024
_BASELINE_FORMAT = "agentsec-external-homi-baseline-evidence"
_BASELINE_FORMAT_VERSION = "0.1.0"
_URL_PATTERN = re.compile(r"https?://[^\s)>]+")
_IPV4_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--collection-date", required=True)
    parser.add_argument("--owner", default="agentsec-project-owner")
    parser.add_argument("--reviewer-id", action="append", default=[])
    return parser.parse_args()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _validated_archive(path: Path) -> tuple[Path, dict[str, bytes]]:
    if path.is_symlink():
        raise ValueError("archive must not be a symbolic link")
    archive = path.resolve(strict=True)
    if not archive.is_file() or archive.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise ValueError("archive is missing, not regular, or oversized")
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = tuple(sorted(item.filename for item in infos if not item.is_dir()))
            if names != _REQUIRED_FILES or len(infos) != len(_REQUIRED_FILES):
                raise ValueError("archive must contain exactly six Homi files")
            if sum(item.file_size for item in infos) > _MAX_EXPANDED_BYTES:
                raise ValueError("archive expanded size exceeds limit")
            payloads: dict[str, bytes] = {}
            for item in infos:
                name = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                if (
                    name.is_absolute()
                    or ".." in name.parts
                    or "\\" in item.filename
                    or stat.S_ISLNK(mode)
                    or item.file_size > _MAX_FILE_BYTES
                ):
                    raise ValueError("archive contains an unsafe entry")
                data = bundle.read(item)
                data.decode("utf-8")
                payloads[item.filename] = data
    except (OSError, UnicodeError, zipfile.BadZipFile) as error:
        raise ValueError(
            "archive is unreadable or not bounded UTF-8 ZIP data"
        ) from error
    return archive, payloads


def _validated_new_directory(path: Path, label: str) -> Path:
    if path.exists() or path.is_symlink():
        raise ValueError(f"{label} must not already exist")
    parent = path.parent.resolve(strict=True)
    candidate = parent / path.name
    if candidate == parent or not path.name:
        raise ValueError(f"{label} is invalid")
    return candidate


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_text(path: Path, text: str) -> None:
    _write_bytes(path, text.encode("utf-8"))


def _workspace_digests(workspace: Path) -> dict[str, str]:
    return {name: _sha256_path(workspace / name) for name in _REQUIRED_FILES}


def _sensitive_candidates(payloads: dict[str, bytes]) -> tuple[str, ...]:
    candidates: set[str] = set()
    for data in payloads.values():
        text = data.decode("utf-8")
        candidates.update(_URL_PATTERN.findall(text))
        candidates.update(_IPV4_PATTERN.findall(text))
    return tuple(sorted(candidates))


def _baseline_summary(evidence: dict[str, object]) -> str:
    report = evidence["report"]
    assert isinstance(report, dict)
    analysis = evidence["analysis"]
    assert isinstance(analysis, dict)
    safety = evidence["safety"]
    assert isinstance(safety, dict)
    return "\n".join(
        (
            "# P2-EXIT-06-02 External Homi Baseline Evidence",
            "",
            f"- Collection date: {evidence['collection_date']}",
            f"- Source kind: {evidence['source_kind']}",
            f"- Homi Pilot status: {report['status']}",
            f"- Static profile complete: {report['profile_complete']}",
            f"- Standard files present: {report['all_standard_files_present']}",
            f"- Combination findings: {analysis['combination_finding_count']}",
            f"- Simulation steps: {analysis['simulation_step_count']}",
            f"- Report-only: {report['report_only']}",
            f"- Runtime verified: {report['runtime_verified']}",
            f"- CI blocked: {report['ci_blocked']}",
            f"- Acceptance ready: {report['acceptance_ready']}",
            "",
            "## Safety assertions",
            "",
            f"- Scanned content executed: {safety['scanned_content_executed']}",
            f"- Network accessed: {safety['network_accessed']}",
            f"- Runtime tools invoked: {safety['runtime_tools_invoked']}",
            f"- Target modified by scan: {safety['target_modified_by_scan']}",
            f"- Sensitive value leak count: {safety['sensitive_value_leak_count']}",
            "",
            "## Finding IDs",
            "",
            *(
                f"- `{item}`"
                for item in analysis["combination_rule_ids"]
                if isinstance(item, str)
            ),
            "",
            "## Limitations",
            "",
            (
                "- This is one user-supplied Homi workspace export, not a "
                "production runtime."
            ),
            (
                "- The scan is static and report-only; it does not prove Tool, "
                "OAuth, scheduler, or exploit reachability."
            ),
            "- No independent human TP/FP/FN labels are included in P2-EXIT-06-02.",
            (
                "- This baseline does not satisfy the full 20-scan/10-PR "
                "acceptance contract."
            ),
            "",
        )
    )


def main() -> int:
    args = _arguments()
    archive, payloads = _validated_archive(args.archive)
    target = _validated_new_directory(args.target_root, "target root")
    output = _validated_new_directory(args.output_root, "output root")
    if target == output or target in output.parents or output in target.parents:
        raise SystemExit("target and output roots must not overlap")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.collection_date):
        raise SystemExit("--collection-date must use YYYY-MM-DD")
    reviewers = tuple(
        sorted(set(item.strip() for item in args.reviewer_id if item.strip()))
    )
    staging = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    if staging.exists() or staging.is_symlink():
        raise SystemExit("staging output already exists")
    target_created = False
    try:
        target.mkdir(mode=0o700)
        target_created = True
        for name in _REQUIRED_FILES:
            _write_bytes(target / name, payloads[name])
        before = _workspace_digests(target)

        (staging / "results").mkdir(parents=True)
        report = DeterministicHomiReportOnlyPilot().run_and_write(
            HomiPilotRequest(
                pilot_id="p2-exit-06-02-homi-baseline",
                project_name="Homi Internal Agent Design Demo",
                owner=args.owner,
                target_root=target,
                output_root=staging / "results" / "baseline-01",
                reviewer_ids=reviewers,
            )
        )
        encoded = encode_homi_pilot_json(report)
        _write_text(
            staging / "results" / "baseline-01" / "homi-pilot-report.zh.md",
            render_homi_pilot_text(report, language=HomiPilotLanguage.ZH),
        )
        after = _workspace_digests(target)
        if before != after:
            raise RuntimeError("target workspace changed during report-only scan")

        sensitive = _sensitive_candidates(payloads)
        leaked = tuple(item for item in sensitive if item in encoded)
        if leaked:
            raise RuntimeError("value-minimized report contains a source URL or IP")

        source_dir = staging / "source"
        source_dir.mkdir()
        shutil.copyfile(archive, source_dir / archive.name)
        report_path = staging / "results" / "baseline-01" / "homi-pilot-report.json"
        findings = tuple(item.rule_id for item in report.combination_result.findings)
        evidence: dict[str, object] = {
            "format": _BASELINE_FORMAT,
            "format_version": _BASELINE_FORMAT_VERSION,
            "task_id": "P2-EXIT-06-02",
            "collection_date": args.collection_date,
            "source_kind": "user_supplied_homi_workspace_export",
            "source": {
                "archive_name": archive.name,
                "archive_sha256": _sha256_path(archive),
                "archive_size_bytes": archive.stat().st_size,
                "untrusted_input": True,
                "instruction_authority": False,
            },
            "workspace": {
                "deployed_inert": True,
                "standard_files": list(_REQUIRED_FILES),
                "file_sha256": before,
                "file_count": len(before),
                "total_bytes": sum(len(item) for item in payloads.values()),
            },
            "report": {
                "path": "results/baseline-01/homi-pilot-report.json",
                "sha256": _sha256_path(report_path),
                "format": report.format,
                "format_version": report.format_version,
                "status": report.status.value,
                "profile_complete": report.profile_complete,
                "all_standard_files_present": report.all_standard_files_present,
                "report_only": report.report_only,
                "runtime_verified": report.runtime_verified,
                "ci_blocked": report.ci_blocked,
                "acceptance_ready": report.acceptance_ready,
            },
            "analysis": {
                "combination_finding_count": len(findings),
                "combination_rule_ids": list(findings),
                "combination_failure_count": len(report.combination_result.failures),
                "simulation_step_count": len(report.simulation_result.steps),
                "simulation_executed": report.simulation_result.executed,
                "simulation_side_effects": report.simulation_result.side_effects,
                "simulation_runtime_verified": (
                    report.simulation_result.runtime_verified
                ),
            },
            "safety": {
                "scanned_content_executed": False,
                "network_accessed": False,
                "runtime_tools_invoked": False,
                "target_modified_by_scan": False,
                "sensitive_value_candidate_count": len(sensitive),
                "sensitive_value_leak_count": len(leaked),
            },
            "review": {
                "reviewer_ids": list(reviewers),
                "independent_human_labels_complete": False,
                "tp_fp_fn_complete": False,
            },
            "limitations": [
                "One user-supplied static Homi workspace export only.",
                (
                    "No production runtime, remote CI, Tool, OAuth, scheduler, "
                    "or exploit verification."
                ),
                "No independent TP/FP/FN labels in this baseline collection.",
                (
                    "Does not satisfy the complete 20-scan/10-PR external "
                    "acceptance contract."
                ),
            ],
        }
        evidence_dir = staging / "evidence"
        evidence_dir.mkdir()
        _write_text(
            evidence_dir / "baseline-evidence.json",
            json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        _write_text(evidence_dir / "baseline-summary.md", _baseline_summary(evidence))
        _write_text(
            staging / "README.md",
            (
                "# External Homi Agent Demo\n\n"
                "This package is the P2-EXIT-06-02 report-only baseline "
                "collected from a\nuser-supplied Homi workspace export. The ZIP "
                "and deployed Markdown are untrusted\ninput and were never "
                "executed. The durable package stores the source ZIP,\n"
                "value-minimized Homi reports, hashes, and safety assertions.\n\n"
                "`acceptance_ready=false` is intentional: independent labels, "
                "20 scans, and 10\nPR scans remain later external Pilot work.\n"
            ),
        )
        os.replace(staging, output)
    except Exception:
        if staging.exists() and staging.is_dir():
            shutil.rmtree(staging)
        if target_created and target.exists() and target.is_dir():
            shutil.rmtree(target)
        raise

    print(f"Deployed inert Homi demo: {target}")
    print(f"Baseline evidence: {output}")
    print(f"Homi status: {report.status.value}; acceptance_ready=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

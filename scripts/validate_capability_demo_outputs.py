"""Validate P2I-05 live or frozen Capability Drift Demo artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agentsec.change_impact import (
    CapabilityChangeImpactReport,
    decode_capability_change_impact_json,
)
from agentsec.manifests import (
    AgentManifest,
    CapabilityDiffResult,
    decode_agent_manifest_json,
    decode_capability_diff_json,
)
from agentsec.reporting import (
    CapabilityAssessmentJsonReport,
    decode_capability_assessment_json,
)

EXPECTED_RULE_IDS = {
    "CAP-APPROVAL-001",
    "CAP-AUTONETWORK-001",
    "CAP-AUTOSECRET-001",
    "CAP-CHAIN-001",
    "CAP-COVERAGE-001",
    "CAP-DELEGATE-001",
    "CAP-DELEGATEEXTERNAL-001",
    "CAP-DELEGATEPERSIST-001",
    "CAP-EXTERNAL-001",
    "CAP-EXTERNALUNVERIFIED-001",
    "CAP-MEMORYNETWORK-001",
    "CAP-MEMORYSECRET-001",
    "CAP-NOSANDBOX-001",
    "CAP-PERSIST-001",
    "CAP-REQUIREDNOFILTER-001",
    "CAP-REQUIREDNOTIMEOUT-001",
}
PROHIBITED_OUTPUT = (
    "synthetic-demo-token",
    "example.invalid",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _manifest(directory: Path, case: str) -> AgentManifest:
    return decode_agent_manifest_json(_text(directory / f"{case}.manifest.json"))


def _assessment(directory: Path, case: str) -> CapabilityAssessmentJsonReport:
    return decode_capability_assessment_json(
        _text(directory / f"{case}.assessment.json")
    )


def _diff(directory: Path, name: str) -> CapabilityDiffResult:
    return decode_capability_diff_json(_text(directory / f"{name}.diff.json"))


def _impact(directory: Path, name: str) -> CapabilityChangeImpactReport:
    return decode_capability_change_impact_json(
        _text(directory / f"{name}.impact.json")
    )


def _verify_checksums(directory: Path) -> None:
    checksum_path = directory / "checksums.sha256"
    if not checksum_path.exists():
        return
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split("  ", maxsplit=1)
        actual = hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        assert actual == digest, filename


def validate(directory: Path) -> dict[str, object]:
    baseline_manifest = _manifest(directory, "baseline")
    risky_manifest = _manifest(directory, "risky-drift")
    incomplete_manifest = _manifest(directory, "incomplete")
    remediated_manifest = _manifest(directory, "remediated")
    baseline = _assessment(directory, "baseline")
    risky = _assessment(directory, "risky-drift")
    incomplete = _assessment(directory, "incomplete")
    remediated = _assessment(directory, "remediated")
    risky_diff = _diff(directory, "risky")
    remediation_diff = _diff(directory, "remediation")
    risky_impact = _impact(directory, "risky")
    remediation_impact = _impact(directory, "remediation")

    assert baseline.status == "complete"
    assert baseline.summary.findings == 0
    assert risky.status == "complete"
    assert risky.summary.findings == 17
    assert risky.summary.highest_severity.value == "high"
    assert {item.rule_id for item in risky.findings} == EXPECTED_RULE_IDS
    assert incomplete.status == "incomplete"
    assert incomplete.summary.manifest_coverage_complete is False
    assert incomplete.summary.findings == 0
    assert remediated.status == "complete"
    assert remediated.summary.findings == 0

    assert baseline_manifest.coverage.complete is True
    assert risky_manifest.coverage.complete is True
    assert incomplete_manifest.coverage.complete is False
    assert remediated_manifest.coverage.complete is True
    assert risky_diff.complete is True and risky_diff.has_changes
    assert risky_diff.added_count > 0
    assert (
        risky_diff.added_count + risky_diff.removed_count + risky_diff.modified_count
        == len(risky_diff.changes)
    )
    assert remediation_diff.complete is True and remediation_diff.has_changes
    assert remediation_diff.removed_count > 0
    assert risky_impact.status == "complete"
    assert risky_impact.summary.added_findings == 17
    assert risky_impact.summary.highest_after_severity.value == "high"
    assert remediation_impact.status == "complete"
    assert remediation_impact.summary.resolved_findings == 17
    assert remediation_impact.summary.highest_after_severity.value == "none"

    for report in (baseline, risky, incomplete, remediated):
        assert report.policy.enforcement_mode == "report_only"
        assert report.policy.ci_blocking_enabled is False
        assert report.policy.runtime_capability_verified is False
        assert report.policy.global_safety_claimed is False

    for path in directory.iterdir():
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        content = path.read_text(encoding="utf-8")
        for value in PROHIBITED_OUTPUT:
            assert value not in content, (path.name, value)

    _verify_checksums(directory)
    summary = {
        "baseline_findings": baseline.summary.findings,
        "risky_findings": risky.summary.findings,
        "risky_rule_ids": sorted(EXPECTED_RULE_IDS),
        "risky_highest_severity": risky.summary.highest_severity.value,
        "risky_changes": len(risky_diff.changes),
        "incomplete_status": incomplete.status,
        "remediated_findings": remediated.summary.findings,
        "remediation_changes": len(remediation_diff.changes),
        "risky_impact_added_findings": risky_impact.summary.added_findings,
        "remediation_impact_resolved_findings": (
            remediation_impact.summary.resolved_findings
        ),
        "policy": "report_only",
    }
    return summary


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_capability_demo_outputs.py ARTIFACT_DIR")
    directory = Path(sys.argv[1])
    summary = validate(directory)
    print("Capability Drift Demo validation passed")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

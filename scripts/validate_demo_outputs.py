"""Validate live Release Agent Demo output against the accepted story."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentsec.reporting import AssessmentJsonReport

EXPECTED_RISKY_RULE_IDS = {
    "MD-APPROVAL-001",
    "MD-DEPLOY-001",
    "MD-EXEC-001",
    "MD-INSTR-001",
    "MD-INSTR-002",
    "MD-NET-001",
    "MD-PRIV-001",
    "MD-SECRET-001",
    "MD-TOOL-001",
}


def _report(output_dir: Path, filename: str) -> AssessmentJsonReport:
    return AssessmentJsonReport.model_validate_json(
        (output_dir / filename).read_text(encoding="utf-8")
    )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_demo_outputs.py OUTPUT_DIR")
    output_dir = Path(sys.argv[1])
    baseline = _report(output_dir, "baseline-scan.json")
    risky = _report(output_dir, "risky-findings.json")
    injection = _report(output_dir, "injection-findings.json")
    malformed = _report(output_dir, "malformed-scan.json")
    remediated = _report(output_dir, "remediated-scan.json")
    diff = json.loads((output_dir / "risky-diff.json").read_text(encoding="utf-8"))

    assert baseline.status == "complete" and baseline.summary.findings == 0
    assert risky.status == "complete" and risky.summary.findings == 10
    assert risky.summary.highest_severity.value == "high"
    assert {item.rule_id for item in risky.assessment.findings} == (
        EXPECTED_RISKY_RULE_IDS
    )
    assert [item.rule_id for item in injection.assessment.findings] == [
        "MD-INSTR-001",
        "MD-INSTR-002",
    ]
    assert malformed.status == "incomplete"
    assert malformed.assessment.coverage.issues[0].code.value == (
        "unsupported_encoding"
    )
    assert remediated.status == "complete" and remediated.summary.findings == 0
    assert diff["status"] == "complete"
    assert diff["summary"]["modified"] == 2
    for report in (baseline, risky, injection, malformed, remediated):
        assert report.policy.enforcement_mode == "report_only"
        assert report.policy.ci_blocking_enabled is False
        assert report.policy.global_safety_claimed is False

    print("Release Agent Demo validation passed")
    print("baseline: complete, 0 findings")
    print("risky drift: complete, 10 findings, highest high, exit 0")
    print("prompt injection: 2 instruction-integrity findings")
    print("malformed: incomplete, unsupported_encoding, exit 2")
    print("remediated: complete, 0 findings")
    print("policy: report_only, ci_blocking_enabled=false")


if __name__ == "__main__":
    main()

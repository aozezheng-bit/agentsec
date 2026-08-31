"""P2I-05 Capability Drift story, frozen artifact, and presenter tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from agentsec.change_impact import decode_capability_change_impact_json
from agentsec.manifests import (
    decode_agent_manifest_json,
    decode_capability_diff_json,
)
from agentsec.reporting import decode_capability_assessment_json

REPOSITORY_ROOT = Path(__file__).parents[1]
DEMO_ROOTS = {
    "en": REPOSITORY_ROOT / "demos" / "capability-drift-agent",
    "zh": REPOSITORY_ROOT / "demos" / "capability-drift-agent-zh",
}
EXPECTED_FILES = {
    *(
        f"{case}.{kind}.{suffix}"
        for case in ("baseline", "risky-drift", "incomplete", "remediated")
        for kind in ("manifest", "assessment")
        for suffix in ("json", "txt")
    ),
    "risky.diff.json",
    "risky.diff.txt",
    "remediation.diff.json",
    "remediation.diff.txt",
    "risky.impact.json",
    "risky.impact.txt",
    "remediation.impact.json",
    "remediation.impact.txt",
    "management-summary.json",
    "report-only-gate-demo.json",
    "report-only-gate-demo.txt",
    "checksums.sha256",
}
CAPABILITY_RULE_IDS = {
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


def _run(*arguments: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _assessment(root: Path, case: str):  # type: ignore[no-untyped-def]
    return decode_capability_assessment_json(
        (root / "expected" / f"{case}.assessment.json").read_text(encoding="utf-8")
    )


@pytest.mark.parametrize("language", ["en", "zh"])
def test_frozen_capability_demo_story_is_complete_and_checksum_valid(
    language: str,
) -> None:
    root = DEMO_ROOTS[language]
    expected = root / "expected"

    assert {path.name for path in expected.iterdir()} == EXPECTED_FILES
    checksums = expected / "checksums.sha256"
    for line in checksums.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split("  ", maxsplit=1)
        assert hashlib.sha256((expected / filename).read_bytes()).hexdigest() == digest

    baseline = _assessment(root, "baseline")
    risky = _assessment(root, "risky-drift")
    incomplete = _assessment(root, "incomplete")
    remediated = _assessment(root, "remediated")
    risky_diff = decode_capability_diff_json(
        (expected / "risky.diff.json").read_text(encoding="utf-8")
    )
    remediation_diff = decode_capability_diff_json(
        (expected / "remediation.diff.json").read_text(encoding="utf-8")
    )
    risky_impact = decode_capability_change_impact_json(
        (expected / "risky.impact.json").read_text(encoding="utf-8")
    )
    remediation_impact = decode_capability_change_impact_json(
        (expected / "remediation.impact.json").read_text(encoding="utf-8")
    )
    report_only_gate = json.loads(
        (expected / "report-only-gate-demo.json").read_text(encoding="utf-8")
    )

    assert baseline.status == "complete" and baseline.summary.findings == 0
    assert risky.status == "complete" and risky.summary.findings == 17
    assert risky.summary.highest_severity.value == "high"
    assert {finding.rule_id for finding in risky.findings} == CAPABILITY_RULE_IDS
    assert incomplete.status == "incomplete"
    assert incomplete.summary.findings == 0
    assert remediated.status == "complete" and remediated.summary.findings == 0
    assert risky_diff.complete is True and len(risky_diff.changes) == 35
    assert remediation_diff.complete is True and len(remediation_diff.changes) == 35
    assert remediation_diff.removed_count > 0
    assert report_only_gate["status"] == "passed"
    assert report_only_gate["gate"]["mode"] == "report_only"
    assert report_only_gate["gate"]["qualification"] == "accepted"
    assert report_only_gate["summary"]["report_only_match_count"] == 2
    assert report_only_gate["summary"]["report_only_no_match_count"] == 3
    assert report_only_gate["gate"]["blocks"] is False
    assert report_only_gate["gate"]["hard_gate"] is False
    assert report_only_gate["gate"]["ci_blocking"] is False
    assert risky_impact.summary.added_findings == 17
    assert remediation_impact.summary.resolved_findings == 17

    for report in (baseline, risky, incomplete, remediated):
        assert report.policy.enforcement_mode == "report_only"
        assert report.policy.ci_blocking_enabled is False
        assert report.policy.runtime_capability_verified is False
        assert report.policy.global_safety_claimed is False

    manifest = decode_agent_manifest_json(
        (expected / "risky-drift.manifest.json").read_text(encoding="utf-8")
    )
    assert manifest.identity.agent_id == "release-agent"
    assert manifest.coverage.complete is True
    for path in expected.iterdir():
        if path.is_file() and path.name != "checksums.sha256":
            content = path.read_text(encoding="utf-8")
            assert "synthetic-demo-token" not in content
            assert "example.invalid" not in content
            assert "\x1b" not in content


def test_english_and_chinese_frozen_results_have_equal_security_semantics() -> None:
    english = _assessment(DEMO_ROOTS["en"], "risky-drift")
    chinese = _assessment(DEMO_ROOTS["zh"], "risky-drift")

    assert english.summary == chinese.summary
    assert [item.rule_id for item in english.findings] == [
        item.rule_id for item in chinese.findings
    ]
    assert [item.finding_id for item in english.findings] != [
        item.finding_id for item in chinese.findings
    ]
    assert "AgentSec Capability Assessment" in (
        DEMO_ROOTS["en"] / "expected" / "risky-drift.assessment.txt"
    ).read_text(encoding="utf-8")
    assert "AgentSec 能力评估" in (
        DEMO_ROOTS["zh"] / "expected" / "risky-drift.assessment.txt"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize("language", ["en", "zh"])
def test_live_capability_demo_runs_through_production_cli(
    tmp_path: Path,
    language: str,
) -> None:
    output = tmp_path / language
    result = _run(
        "scripts/run-capability-demo.sh",
        "--language",
        language,
        "--output-dir",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    assert "Capability Drift Demo validation passed" in result.stdout
    assert "remediated_findings" in result.stdout
    assert "report-only" in result.stdout
    assert result.stderr == ""
    assert {path.name for path in output.iterdir()} == EXPECTED_FILES - {
        "management-summary.json",
        "report-only-gate-demo.json",
        "report-only-gate-demo.txt",
        "checksums.sha256",
    }
    for path in output.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    risky = decode_capability_assessment_json(
        (output / "risky-drift.assessment.json").read_text(encoding="utf-8")
    )
    incomplete = decode_capability_assessment_json(
        (output / "incomplete.assessment.json").read_text(encoding="utf-8")
    )
    assert risky.summary.findings == 17
    assert incomplete.status == "incomplete"


@pytest.mark.parametrize(
    ("language", "expected_text"),
    [("en", "Management close"), ("zh", "管理层结论")],
)
def test_offline_presenter_flow_is_bilingual_and_checksum_backed(
    language: str,
    expected_text: str,
) -> None:
    result = _run(
        "scripts/demo-capability-drift.sh",
        "--language",
        language,
        "--offline",
        "--no-pause",
    )

    assert result.returncode == 0, result.stderr
    assert expected_text in result.stdout
    assert "8" in result.stdout
    assert "Report-only Gate" in result.stdout
    assert "CAP-CHAIN-001" in result.stdout
    assert "INCOMPLETE" in result.stdout
    assert "report-only" in result.stdout.lower()
    assert result.stderr == ""


def test_capability_demo_fixtures_are_inert_and_synthetic() -> None:
    for root in DEMO_ROOTS.values():
        for path in root.rglob("*"):
            assert not path.is_symlink()
            if not path.is_file() or "expected" in path.parts:
                continue
            assert not os.access(path, os.X_OK)
            if path.name == "AGENTS.override.md" and "incomplete" in path.parts:
                assert path.read_bytes() == b"\xff\xfe"
                continue
            content = path.read_text(encoding="utf-8")
            urls = re.findall(r"https?://[^\s`\"]+", content)
            assert all(url.startswith("https://example.invalid/") for url in urls)
            assert "BEGIN PRIVATE KEY" not in content
            assert "@" not in content

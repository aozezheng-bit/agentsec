"""P1-31 release, Schema, and frozen Demo acceptance tests."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from agentsec.baselines import (
    decode_baseline_json,
    export_baseline_json_schema,
)
from agentsec.change_impact import export_capability_change_impact_json_schema
from agentsec.domain import export_json_schemas
from agentsec.manifests import (
    export_agent_manifest_json_schema,
    export_capability_diff_json_schema,
)
from agentsec.reporting import (
    AssessmentJsonReport,
    SecretRedactor,
    export_agentic_assessment_json_schema,
    export_assessment_json_schema,
    export_capability_assessment_json_schema,
    export_score_context_json_schema,
)
from agentsec.versioning import PACKAGE_VERSION
from agentsec.vulnerabilities import (
    export_vulnerability_catalog_json_schema,
    export_vulnerability_input_json_schema,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
DEMO_ROOT = REPOSITORY_ROOT / "demos" / "release-agent"
RELEASE_ROOT = REPOSITORY_ROOT / "docs" / "releases"
URL_HOST_PATTERN = re.compile(r"https?://([^/\s`]+)", re.IGNORECASE)


def test_package_is_the_phase_3_ready_development_candidate() -> None:
    """Source advances toward the Phase 3 Ready Candidate release."""

    assert PACKAGE_VERSION == "0.4.0"


def test_frozen_release_schemas_match_current_exporters(tmp_path: Path) -> None:
    """Published Schemas are byte-identical to current source-of-truth models."""

    domain_dir = tmp_path / "domain"
    baseline_dir = tmp_path / "baseline"
    assessment_dir = tmp_path / "assessment"
    domain_paths = export_json_schemas(domain_dir)
    baseline_path = export_baseline_json_schema(baseline_dir)
    assessment_path = export_assessment_json_schema(assessment_dir)
    manifest_path = export_agent_manifest_json_schema(tmp_path / "manifest")
    capability_diff_path = export_capability_diff_json_schema(
        tmp_path / "capability-diff"
    )
    capability_assessment_path = export_capability_assessment_json_schema(
        tmp_path / "capability-assessment"
    )
    capability_change_impact_path = export_capability_change_impact_json_schema(
        tmp_path / "capability-change-impact"
    )
    vulnerability_input_path = export_vulnerability_input_json_schema(
        tmp_path / "vulnerability-input"
    )
    vulnerability_catalog_path = export_vulnerability_catalog_json_schema(
        tmp_path / "vulnerability-catalog"
    )

    for generated in domain_paths:
        assert (
            generated.read_bytes()
            == (SCHEMA_ROOT / "domain" / generated.name).read_bytes()
        )
    assert (
        baseline_path.read_bytes()
        == (SCHEMA_ROOT / "baseline" / baseline_path.name).read_bytes()
    )
    assert (
        assessment_path.read_bytes()
        == (SCHEMA_ROOT / "assessment" / assessment_path.name).read_bytes()
    )
    assert (
        manifest_path.read_bytes()
        == (SCHEMA_ROOT / "manifest" / manifest_path.name).read_bytes()
    )
    assert (
        capability_diff_path.read_bytes()
        == (SCHEMA_ROOT / "capability-diff" / capability_diff_path.name).read_bytes()
    )
    assert (
        capability_assessment_path.read_bytes()
        == (
            SCHEMA_ROOT / "capability-assessment" / capability_assessment_path.name
        ).read_bytes()
    )
    assert (
        capability_change_impact_path.read_bytes()
        == (
            SCHEMA_ROOT
            / "capability-change-impact"
            / capability_change_impact_path.name
        ).read_bytes()
    )
    assert (
        vulnerability_input_path.read_bytes()
        == (
            SCHEMA_ROOT / "vulnerability-input" / vulnerability_input_path.name
        ).read_bytes()
    )
    assert (
        vulnerability_catalog_path.read_bytes()
        == (
            SCHEMA_ROOT / "vulnerability-catalog" / vulnerability_catalog_path.name
        ).read_bytes()
    )
    agentic_assessment_path = export_agentic_assessment_json_schema(
        tmp_path / "agentic-assessment"
    )
    assert (
        agentic_assessment_path.read_bytes()
        == (
            SCHEMA_ROOT / "agentic-assessment" / agentic_assessment_path.name
        ).read_bytes()
    )
    score_context_path = export_score_context_json_schema(tmp_path / "score-context")
    assert (
        score_context_path.read_bytes()
        == (SCHEMA_ROOT / "score-context" / score_context_path.name).read_bytes()
    )


def test_frozen_demo_reports_are_valid_and_match_the_story() -> None:
    """Offline fallback output retains the approved report-only semantics."""

    expected = DEMO_ROOT / "expected"
    baseline = AssessmentJsonReport.model_validate_json(
        (expected / "baseline-scan.json").read_text(encoding="utf-8")
    )
    risky = AssessmentJsonReport.model_validate_json(
        (expected / "risky-findings.json").read_text(encoding="utf-8")
    )
    injection = AssessmentJsonReport.model_validate_json(
        (expected / "injection-findings.json").read_text(encoding="utf-8")
    )
    malformed = AssessmentJsonReport.model_validate_json(
        (expected / "malformed-scan.json").read_text(encoding="utf-8")
    )
    remediated = AssessmentJsonReport.model_validate_json(
        (expected / "remediated-scan.json").read_text(encoding="utf-8")
    )

    assert baseline.status == "complete"
    assert baseline.summary.findings == 0
    assert risky.status == "complete"
    assert risky.summary.findings == 10
    assert risky.summary.highest_severity.value == "high"
    assert sorted({item.rule_id for item in risky.assessment.findings}) == [
        "MD-APPROVAL-001",
        "MD-DEPLOY-001",
        "MD-EXEC-001",
        "MD-INSTR-001",
        "MD-INSTR-002",
        "MD-NET-001",
        "MD-PRIV-001",
        "MD-SECRET-001",
        "MD-TOOL-001",
    ]
    assert injection.status == "complete"
    assert [item.rule_id for item in injection.assessment.findings] == [
        "MD-INSTR-001",
        "MD-INSTR-002",
    ]
    assert malformed.status == "incomplete"
    assert malformed.assessment.coverage.issues[0].code.value == (
        "unsupported_encoding"
    )
    assert remediated.status == "complete"
    assert remediated.summary.findings == 0
    for report in (baseline, risky, injection, malformed, remediated):
        assert report.policy.enforcement_mode == "report_only"
        assert report.policy.ci_blocking_enabled is False
        assert report.policy.global_safety_claimed is False


def test_frozen_demo_baseline_and_diff_are_valid() -> None:
    """The approved Baseline and redacted Diff remain replayable release assets."""

    expected = DEMO_ROOT / "expected"
    baseline = decode_baseline_json(
        (expected / "baseline.json").read_text(encoding="utf-8")
    )
    diff = json.loads((expected / "risky-diff.json").read_text(encoding="utf-8"))

    assert len(baseline.assets) == 2
    assert diff["format"] == "agentsec-diff"
    assert diff["format_version"] == "0.1.0"
    assert diff["status"] == "complete"
    assert diff["summary"] == {
        "added": 0,
        "changes": 2,
        "modified": 2,
        "omitted_text_diff_assets": 0,
        "removed": 0,
        "text_diff_complete": True,
    }


def test_demo_assets_are_inert_secret_free_and_use_reserved_hosts() -> None:
    """The narrative Demo cannot introduce executable payloads or real secrets."""

    redactor = SecretRedactor()
    allowed_suffixes = {".md", ".json", ".sha256"}
    for path in DEMO_ROOT.rglob("*"):
        assert not path.is_symlink(), path
        if not path.is_file():
            continue
        assert path.suffix.lower() in allowed_suffixes, path
        if path == DEMO_ROOT / "malformed" / "AGENTS.md":
            continue
        text = path.read_text(encoding="utf-8")
        assert redactor.redact(text) == text, path
        for host in URL_HOST_PATTERN.findall(text):
            assert host.lower().endswith(".invalid"), path


def test_frozen_demo_checksums_match_every_expected_artifact() -> None:
    """Offline fallback files cannot drift silently after acceptance."""

    expected_dir = DEMO_ROOT / "expected"
    checksum_path = expected_dir / "checksums.sha256"
    entries = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split("  ", maxsplit=1)
        entries[filename] = digest

    artifact_names = sorted(
        path.name
        for path in expected_dir.iterdir()
        if path.is_file() and path.name != checksum_path.name
    )
    assert sorted(entries) == artifact_names
    for filename, expected_digest in entries.items():
        actual = hashlib.sha256((expected_dir / filename).read_bytes()).hexdigest()
        assert actual == expected_digest


def test_release_documents_record_acceptance_and_limitations() -> None:
    """The PoC release is explicit about policy and residual risk."""

    required = (
        REPOSITORY_ROOT / "CHANGELOG.md",
        RELEASE_ROOT / "0.1.0.md",
        RELEASE_ROOT / "0.1.0-known-limitations.md",
        RELEASE_ROOT / "0.1.0-acceptance.md",
        RELEASE_ROOT / "0.2.0.md",
        RELEASE_ROOT / "0.2.0-known-limitations.md",
        RELEASE_ROOT / "0.2.0-acceptance.md",
        RELEASE_ROOT / "0.3.0.md",
        RELEASE_ROOT / "0.3.0-known-limitations.md",
        RELEASE_ROOT / "0.3.0-acceptance.md",
        REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "README.md",
        REPOSITORY_ROOT / "demos" / "capability-drift-agent-zh" / "README.md",
        DEMO_ROOT / "README.md",
        DEMO_ROOT / "demo-script.md",
        DEMO_ROOT / "acceptance.md",
    )
    for path in required:
        assert path.is_file(), path

    combined = "\n".join(path.read_text(encoding="utf-8") for path in required)
    assert "report-only" in combined.lower()
    assert "ci_blocking_enabled=false" in combined
    assert "runtime_capability_verified=false" in combined
    assert "agentsec rules list" in combined
    assert "agentsec capability assess" in combined
    assert "does not prove" in combined.lower()
    historical_release = "\n".join(
        path.read_text(encoding="utf-8")
        for path in required
        if path.name.startswith(("0.1.0", "0.2.0"))
    )
    assert "--fail-on high" not in historical_release
    current_release = (RELEASE_ROOT / "0.3.0.md").read_text(encoding="utf-8")
    assert "--fail-on high" in current_release
    assert "--fail-on critical" in current_release
    assert "--fail-on high|critical" in (REPOSITORY_ROOT / "CHANGELOG.md").read_text(
        encoding="utf-8"
    )


def test_release_demo_runner_passes_end_to_end(tmp_path: Path) -> None:
    """The accepted Demo runner uses the real CLI and validates its live output."""

    output_dir = tmp_path / "demo-output"
    result = subprocess.run(
        [str(REPOSITORY_ROOT / "scripts" / "run-demo.sh"), str(output_dir)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "Release Agent Demo validation passed" in result.stdout
    assert "ci_blocking_enabled=false" in result.stdout
    assert result.stderr == ""
    assert (output_dir / "risky-findings.json").is_file()
    assert (output_dir / "malformed-scan.json").is_file()


def test_presenter_friendly_developer_demo_passes_without_pauses(
    tmp_path: Path,
) -> None:
    """The live presenter script retains the accepted story and artifacts."""

    output_dir = tmp_path / "developer-demo-output"
    result = subprocess.run(
        [
            str(REPOSITORY_ROOT / "scripts" / "demo-developer.sh"),
            "--no-pause",
            "--output-dir",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "[1/8] 环境确认" in result.stdout
    assert "[8/8] 整改并验证闭环" in result.stdout
    assert "Release Agent Demo validation passed" in result.stdout
    assert "ci_blocking_enabled=false" in result.stdout
    assert "人工建议在整改前暂停发布" in result.stdout
    assert result.stderr == ""
    assert (output_dir / "live-baseline.json").is_file()
    assert (output_dir / "risky-diff.json").is_file()
    assert (output_dir / "risky-findings.json").is_file()
    assert (output_dir / "malformed-scan.json").is_file()

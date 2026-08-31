"""Validation and serialization tests for the Phase 1 domain interface."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.domain import (
    AgentAsset,
    Assessment,
    AssessmentMetadata,
    AssetChange,
    AssetSource,
    AssetType,
    ChangeType,
    CoverageIssue,
    CoverageIssueCode,
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    Finding,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    ScanCoverage,
    Severity,
    export_json_schemas,
)
from agentsec.versioning import DOMAIN_SCHEMA_VERSION

HASH_A = "a" * 64
HASH_B = "b" * 64


def make_asset() -> AgentAsset:
    """Create a valid asset shared by assessment tests."""

    return AgentAsset(
        path="skills/review/SKILL.md",
        asset_type=AssetType.SKILL,
        source=AssetSource.DISCOVERED,
        sha256=HASH_A,
        size_bytes=512,
        line_count=24,
    )


def make_finding() -> Finding:
    """Create a valid evidence-backed finding."""

    return Finding(
        finding_id="finding-001",
        rule_id="MD-EXEC-001",
        category=FindingCategory.CODE_EXECUTION,
        title="Shell execution is declared",
        description="The instruction file declares shell execution capability.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.HIGH,
        severity=Severity.HIGH,
        score=8.0,
        confidence=EvidenceConfidence.C,
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="skills/review/SKILL.md",
                start_line=12,
                end_line=13,
                excerpt="Run the deployment command in a shell.",
                content_sha256=HASH_A,
            ),
        ),
        recommendations=("Confirm the tool exists and require human approval.",),
    )


def make_metadata() -> AssessmentMetadata:
    """Create deterministic, timezone-aware assessment metadata."""

    started_at = datetime(2026, 8, 18, 8, 0, tzinfo=UTC)
    return AssessmentMetadata(
        schema_version=DOMAIN_SCHEMA_VERSION,
        scanner_version="0.1.0.dev0",
        config_schema_version="0.1.0",
        rule_pack_version="0.1.0",
        risk_model_version="0.4.0",
        target_root="/workspace/project",
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=1),
        git_commit="0123456789abcdef",
        git_dirty=False,
    )


def test_asset_normalizes_portable_relative_paths() -> None:
    """Serialized assets use project-relative POSIX paths."""

    asset = make_asset().model_copy(update={"path": "skills\\review\\SKILL.md"})
    reparsed = AgentAsset.model_validate(asset.model_dump())

    assert reparsed.path == "skills/review/SKILL.md"
    assert reparsed.model_dump(mode="json")["asset_type"] == "skill"


@pytest.mark.parametrize(
    "path",
    ["/absolute/AGENTS.md", "../AGENTS.md", "C:/project/AGENTS.md", "."],
)
def test_asset_rejects_paths_outside_project_scope(path: str) -> None:
    """Domain paths cannot escape or bypass the selected project root."""

    with pytest.raises(ValidationError):
        AgentAsset(
            path=path,
            asset_type=AssetType.AGENTS,
            source=AssetSource.DISCOVERED,
            sha256=HASH_A,
            size_bytes=1,
            line_count=1,
        )


def test_asset_rejects_invalid_sha256() -> None:
    """Asset hashes must be lowercase 64-character SHA-256 digests."""

    with pytest.raises(ValidationError):
        AgentAsset(
            path="AGENTS.md",
            asset_type=AssetType.AGENTS,
            source=AssetSource.DISCOVERED,
            sha256="not-a-digest",
            size_bytes=1,
            line_count=1,
        )


def test_asset_change_requires_hashes_for_its_change_type() -> None:
    """Change evidence cannot omit the hashes required by its state."""

    with pytest.raises(ValidationError):
        AssetChange(
            path="AGENTS.md",
            change_type=ChangeType.MODIFIED,
            before_sha256=HASH_A,
        )

    change = AssetChange(
        path="AGENTS.md",
        change_type=ChangeType.MODIFIED,
        before_sha256=HASH_A,
        after_sha256=HASH_B,
    )
    assert change.before_sha256 != change.after_sha256


def test_evidence_rejects_incoherent_line_ranges() -> None:
    """Evidence line locations remain meaningful and file-backed."""

    with pytest.raises(ValidationError):
        Evidence(
            source_type=EvidenceSource.FILE,
            asset_path="AGENTS.md",
            start_line=10,
            end_line=4,
        )

    with pytest.raises(ValidationError):
        Evidence(
            source_type=EvidenceSource.CONFIGURATION,
            start_line=1,
            field="approval_policy",
        )


def test_finding_requires_evidence_and_recommendation() -> None:
    """Findings cannot be emitted without evidence and follow-up guidance."""

    finding = make_finding()
    assert finding.evidence[0].asset_path == "skills/review/SKILL.md"

    data = finding.model_dump()
    data["evidence"] = []
    with pytest.raises(ValidationError):
        Finding.model_validate(data)

    data = finding.model_dump()
    data["recommendations"] = []
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_coverage_counts_and_complete_flag_must_agree() -> None:
    """Incomplete scans cannot be silently represented as complete."""

    complete = ScanCoverage(
        discovered_assets=1,
        scanned_assets=1,
        skipped_assets=0,
        complete=True,
    )
    assert complete.issues == ()

    with pytest.raises(ValidationError):
        ScanCoverage(
            discovered_assets=1,
            scanned_assets=0,
            skipped_assets=1,
            complete=True,
            issues=(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Permission denied.",
                    asset_path="AGENTS.md",
                ),
            ),
        )


def test_metadata_requires_ordered_timezone_aware_timestamps() -> None:
    """Assessment timestamps are unambiguous and chronologically ordered."""

    with pytest.raises(ValidationError):
        AssessmentMetadata(
            schema_version=DOMAIN_SCHEMA_VERSION,
            scanner_version="0.1.0.dev0",
            config_schema_version="0.1.0",
            rule_pack_version="0.1.0",
            risk_model_version="0.4.0",
            target_root="/workspace/project",
            started_at=datetime(2026, 8, 18, 8, 0),
            completed_at=datetime(2026, 8, 18, 8, 1),
        )


def test_assessment_serializes_as_an_evidence_backed_result() -> None:
    """The aggregate model keeps assets, findings, and coverage separate."""

    assessment = Assessment(
        metadata=make_metadata(),
        assets=(make_asset(),),
        findings=(make_finding(),),
        coverage=ScanCoverage(
            discovered_assets=1,
            scanned_assets=1,
            skipped_assets=0,
            complete=True,
        ),
    )

    payload = assessment.model_dump(mode="json")
    assert payload["assets"][0]["asset_type"] == "skill"
    assert payload["findings"][0]["confidence"] == "C"
    assert payload["coverage"]["complete"] is True


def test_schema_export_is_deterministic_and_strict(tmp_path: Path) -> None:
    """Public JSON Schemas are stable, strict, and machine-readable."""

    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"

    first_paths = export_json_schemas(first_directory)
    second_paths = export_json_schemas(second_directory)

    assert len(first_paths) == 12
    assert [path.name for path in first_paths] == [path.name for path in second_paths]

    for first_path, second_path in zip(first_paths, second_paths, strict=True):
        assert first_path.read_bytes() == second_path.read_bytes()

    assessment_schema = json.loads(
        (first_directory / "assessment.schema.json").read_text(encoding="utf-8")
    )
    coverage_issue_schema = (first_directory / "coverage-issue.schema.json").read_text(
        encoding="utf-8"
    )
    assert DOMAIN_SCHEMA_VERSION == "0.8.0"
    assert '"asset_limit_exceeded"' in coverage_issue_schema
    assert assessment_schema["additionalProperties"] is False
    assert set(assessment_schema["required"]) == {"metadata", "coverage"}
    assert {"config_schema_version", "risk_model_version"} <= set(
        assessment_schema["$defs"]["AssessmentMetadata"]["required"]
    )
    assert "$defs" in assessment_schema

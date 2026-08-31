"""Integration tests for the collection-backed assessment engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agentsec.application import AssessmentRequest, CollectionAssessmentEngine
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import (
    CONFIG_SCHEMA_VERSION,
    DiscoveryConfig,
    ProjectConfig,
    default_project_config,
)
from agentsec.domain import AssetSource, AssetType, CoverageIssueCode
from agentsec.parsers import ParsedMarkdown
from agentsec.versioning import current_versions


def test_collection_engine_builds_a_versioned_assessment() -> None:
    """Collected metadata and coverage cross the application seam unchanged."""

    fixture_root = Path(__file__).parents[1] / "testdata" / "safe" / "nested-skill"
    started_at = datetime(2026, 8, 18, 9, 0, tzinfo=UTC)
    completed_at = datetime(2026, 8, 18, 9, 0, 1, tzinfo=UTC)
    timestamps = iter((started_at, completed_at))
    engine = CollectionAssessmentEngine(
        MarkdownAssetCollector(),
        clock=lambda: next(timestamps),
    )

    assessment = engine.assess(
        AssessmentRequest(
            project_root=fixture_root,
            config=default_project_config(),
            config_path=None,
        )
    )

    versions = current_versions()
    assert [asset.path for asset in assessment.assets] == [
        "AGENTS.md",
        "skills/review/SKILL.md",
    ]
    assert assessment.findings == ()
    assert assessment.changes == ()
    assert assessment.coverage.complete is True
    assert assessment.coverage.discovered_assets == 2
    assert assessment.metadata.schema_version == versions.domain_schema
    assert assessment.metadata.scanner_version == versions.package
    assert assessment.metadata.rule_pack_version == versions.rule_pack
    assert assessment.metadata.target_root == str(fixture_root)
    assert assessment.metadata.started_at == started_at
    assert assessment.metadata.completed_at == completed_at


def test_collection_engine_applies_request_discovery_configuration(
    tmp_path: Path,
) -> None:
    """The application adapter passes include/exclude policy to its collector."""

    (tmp_path / "docs" / "private").mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("not included\n", encoding="utf-8")
    (tmp_path / "docs" / "RUNBOOK.md").write_text("included\n", encoding="utf-8")
    (tmp_path / "docs" / "private" / "SECRET.md").write_text(
        "excluded\n",
        encoding="utf-8",
    )
    timestamp = datetime(2026, 8, 18, 9, 10, tzinfo=UTC)
    engine = CollectionAssessmentEngine(
        MarkdownAssetCollector(),
        clock=lambda: timestamp,
    )
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(
            include=("docs/**/*.md",),
            exclude=("docs/private/**",),
        ),
    )

    assessment = engine.assess(
        AssessmentRequest(
            project_root=tmp_path,
            config=config,
            config_path=None,
        )
    )

    assert [asset.path for asset in assessment.assets] == ["docs/RUNBOOK.md"]
    assert assessment.assets[0].asset_type is AssetType.EXPLICIT_MARKDOWN
    assert assessment.assets[0].source is AssetSource.EXPLICIT
    assert assessment.coverage.complete is True


def test_parser_failure_is_isolated_and_reduces_coverage(tmp_path: Path) -> None:
    """One parser exception does not hide metadata or stop remaining assets."""

    class SelectiveFailingParser:
        def __init__(self) -> None:
            self.contents: list[str] = []

        def parse(self, content: str) -> ParsedMarkdown:
            self.contents.append(content)
            if "fail-marker" in content:
                raise RuntimeError("secret parser diagnostic: fail-marker")
            return ParsedMarkdown(
                blocks=(),
                source_line_count=len(content.splitlines()),
            )

    (tmp_path / "nested").mkdir()
    (tmp_path / "AGENTS.md").write_text("fail-marker\n", encoding="utf-8")
    (tmp_path / "nested" / "SKILL.md").write_text("safe\n", encoding="utf-8")
    parser = SelectiveFailingParser()
    timestamp = datetime(2026, 8, 18, 10, 10, tzinfo=UTC)
    engine = CollectionAssessmentEngine(
        MarkdownAssetCollector(),
        parser=parser,
        clock=lambda: timestamp,
    )

    assessment = engine.assess(
        AssessmentRequest(
            project_root=tmp_path,
            config=default_project_config(),
            config_path=None,
        )
    )

    assert parser.contents == ["fail-marker\n", "safe\n"]
    assert [asset.path for asset in assessment.assets] == [
        "AGENTS.md",
        "nested/SKILL.md",
    ]
    assert assessment.coverage.discovered_assets == 2
    assert assessment.coverage.scanned_assets == 1
    assert assessment.coverage.skipped_assets == 1
    assert assessment.coverage.complete is False
    assert len(assessment.coverage.issues) == 1
    issue = assessment.coverage.issues[0]
    assert issue.code is CoverageIssueCode.PARSE_ERROR
    assert issue.asset_path == "AGENTS.md"
    assert issue.message == "Markdown parsing failed safely."
    assert "fail-marker" not in issue.message


def test_collection_engine_builds_final_findings_through_the_full_risk_chain() -> None:
    """A risky asset becomes a final Domain Finding with risk and confidence."""

    fixture_root = (
        Path(__file__).parents[1] / "testdata" / "risky" / "shell-secret-network"
    )
    timestamp = datetime(2026, 8, 19, 14, 0, tzinfo=UTC)
    engine = CollectionAssessmentEngine(
        MarkdownAssetCollector(),
        clock=lambda: timestamp,
    )

    assessment = engine.assess(
        AssessmentRequest(
            project_root=fixture_root,
            config=default_project_config(),
            config_path=None,
        )
    )

    assert assessment.coverage.complete is True
    assert [finding.rule_id for finding in assessment.findings] == [
        "MD-APPROVAL-001",
        "MD-EXEC-001",
        "MD-NET-001",
        "MD-SECRET-001",
    ]
    assert all(finding.evidence for finding in assessment.findings)
    assert all(finding.score > 0 for finding in assessment.findings)
    assert all(
        finding.confidence.value in {"A", "B", "C", "D"}
        for finding in assessment.findings
    )
    assert all(finding.hard_gate is False for finding in assessment.findings)

"""Application-service tests for deterministic baseline construction."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.application import (
    BaselineCreationCode,
    BaselineCreationError,
    BaselineCreationRequest,
    CollectionBaselineCreator,
)
from agentsec.baselines import GitProvenance
from agentsec.baselines.fingerprint import fingerprint_collection_config
from agentsec.collectors import (
    CollectedAsset,
    CollectionResult,
    MarkdownAssetCollector,
)
from agentsec.config import (
    CONFIG_SCHEMA_VERSION,
    DiscoveryConfig,
    LimitsConfig,
    OutputConfig,
    OutputFormat,
    ProjectConfig,
    default_project_config,
)
from agentsec.domain import AgentAsset, AssetSource, AssetType, ScanCoverage
from agentsec.parsers import ParsedMarkdown
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions


class StaticProvenanceProvider:
    """Return deterministic Git provenance without touching a repository."""

    def __init__(self, provenance: GitProvenance) -> None:
        self.provenance = provenance
        self.calls: list[Path] = []

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        self.calls.append(project_root)
        assert excluded_paths == (project_root / ".agentsec/baseline.json",)
        return self.provenance


class FailingProvenanceProvider:
    """Simulate a safe Git failure without exposing external diagnostics."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        raise RuntimeError(f"must-not-leak: {project_root} {excluded_paths}")


def make_request(project_root: Path) -> BaselineCreationRequest:
    """Create one default baseline request."""

    return BaselineCreationRequest(
        project_root=project_root,
        config=default_project_config(),
        config_path=None,
        output_path=project_root / ".agentsec/baseline.json",
    )


def test_creator_builds_sorted_exact_assets_and_version_provenance(
    tmp_path: Path,
) -> None:
    """Collected content crosses the application seam without normalization."""

    nested = tmp_path / "skills" / "review"
    nested.mkdir(parents=True)
    root_content = "# Agent\n\nRequire approval.\n"
    skill_content = "# Review\r\n\r\nRead only.\r\n"
    (tmp_path / "AGENTS.md").write_text(root_content, encoding="utf-8")
    (nested / "SKILL.md").write_bytes(skill_content.encode("utf-8"))
    timestamp = datetime(2026, 8, 18, 13, 0, tzinfo=UTC)
    provenance_provider = StaticProvenanceProvider(
        GitProvenance(commit="a" * 40, dirty=True)
    )
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=provenance_provider,
        clock=lambda: timestamp,
    )

    baseline = creator.create(make_request(tmp_path))

    versions = current_versions()
    assert baseline.schema_version == BASELINE_SCHEMA_VERSION
    assert [asset.path for asset in baseline.assets] == [
        "AGENTS.md",
        "skills/review/SKILL.md",
    ]
    assert baseline.assets[0].content == root_content
    assert baseline.assets[1].content == skill_content
    assert baseline.metadata.scanner_version == versions.package
    assert baseline.metadata.config_schema_version == versions.config_schema
    assert baseline.metadata.domain_schema_version == versions.domain_schema
    assert baseline.metadata.rule_pack_version == versions.rule_pack
    assert baseline.metadata.risk_model_version == versions.risk_model
    assert baseline.metadata.generated_at == timestamp
    assert baseline.metadata.git_commit == "a" * 40
    assert baseline.metadata.git_dirty is True
    assert provenance_provider.calls == [tmp_path]


def test_collection_config_fingerprint_is_canonical_and_scope_specific() -> None:
    """Reporter-only changes do not invalidate the collected-asset scope."""

    base = default_project_config()
    json_output = base.model_copy(
        update={"output": OutputConfig(format=OutputFormat.JSON)}
    )
    changed_discovery = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(include=("docs/**/*.md",), exclude=()),
    )
    changed_limits = base.model_copy(update={"limits": LimitsConfig(max_depth=10)})

    assert fingerprint_collection_config(base) == fingerprint_collection_config(
        json_output
    )
    assert fingerprint_collection_config(base) != fingerprint_collection_config(
        changed_discovery
    )
    assert fingerprint_collection_config(base) != fingerprint_collection_config(
        changed_limits
    )


def test_creator_rejects_incomplete_collection_before_provenance(
    tmp_path: Path,
) -> None:
    """A skipped selected asset can never become a trusted partial baseline."""

    (tmp_path / "AGENTS.md").write_bytes(b"\xff")
    provenance_provider = StaticProvenanceProvider(
        GitProvenance(commit=None, dirty=None)
    )
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=provenance_provider,
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.INCOMPLETE_COVERAGE
    assert provenance_provider.calls == []


def test_creator_rejects_parser_failure_without_leaking_content(tmp_path: Path) -> None:
    """All assets must parse, and parser exceptions remain behind a safe boundary."""

    class FailingParser:
        def parse(self, content: str) -> ParsedMarkdown:
            raise RuntimeError(f"parser-secret: {content}")

    secret = "baseline-parser-secret"
    (tmp_path / "AGENTS.md").write_text(secret, encoding="utf-8")
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        parser=FailingParser(),
        provenance_provider=StaticProvenanceProvider(
            GitProvenance(commit=None, dirty=None)
        ),
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.PARSE_FAILED
    assert secret not in str(captured.value)


def test_creator_wraps_collector_exceptions_safely(tmp_path: Path) -> None:
    """Unexpected collector diagnostics do not escape through baseline errors."""

    class FailingCollector:
        def collect(
            self,
            project_root: Path,
            config: ProjectConfig,
        ) -> CollectionResult:
            raise RuntimeError(f"collector-secret: {project_root}")

    creator = CollectionBaselineCreator(
        FailingCollector(),
        provenance_provider=StaticProvenanceProvider(
            GitProvenance(commit=None, dirty=None)
        ),
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.COLLECTION_FAILED
    assert str(tmp_path) not in str(captured.value)


def test_creator_wraps_git_provenance_failure_safely(tmp_path: Path) -> None:
    """Detected Git failures block creation without exposing command diagnostics."""

    (tmp_path / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=FailingProvenanceProvider(),
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.PROVENANCE_FAILED
    assert str(tmp_path) not in str(captured.value)


def test_creator_rejects_naive_generation_clock(tmp_path: Path) -> None:
    """Generated baseline timestamps remain unambiguous and timezone-aware."""

    (tmp_path / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=StaticProvenanceProvider(
            GitProvenance(commit=None, dirty=None)
        ),
        clock=lambda: datetime(2026, 8, 18, 13, 0),
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.MODEL_INVALID


def test_creator_wraps_inconsistent_collector_content_safely(tmp_path: Path) -> None:
    """Invalid adapter output cannot leak captured source through Pydantic errors."""

    secret = "inconsistent-baseline-secret"

    class InconsistentCollector:
        def collect(
            self,
            project_root: Path,
            config: ProjectConfig,
        ) -> CollectionResult:
            return CollectionResult(
                assets=(
                    CollectedAsset(
                        asset=AgentAsset(
                            path="AGENTS.md",
                            asset_type=AssetType.AGENTS,
                            source=AssetSource.DISCOVERED,
                            sha256="a" * 64,
                            size_bytes=1,
                            line_count=1,
                        ),
                        content=secret,
                    ),
                ),
                coverage=ScanCoverage(
                    discovered_assets=1,
                    scanned_assets=1,
                    skipped_assets=0,
                    complete=True,
                ),
            )

    creator = CollectionBaselineCreator(
        InconsistentCollector(),
        provenance_provider=StaticProvenanceProvider(
            GitProvenance(commit=None, dirty=None)
        ),
    )

    with pytest.raises(BaselineCreationError) as captured:
        creator.create(make_request(tmp_path))

    assert captured.value.code is BaselineCreationCode.MODEL_INVALID
    assert secret not in str(captured.value)

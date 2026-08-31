"""Application-service tests for the complete deterministic Diff pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.application import (
    BaselineCreationRequest,
    CollectionBaselineCreator,
    CollectionProjectDiffEngine,
    ProjectDiffError,
    ProjectDiffExecutionCode,
    ProjectDiffRequest,
)
from agentsec.baselines import (
    Baseline,
    BaselineMetadata,
    GitProvenance,
    encode_baseline_json,
)
from agentsec.collectors import CollectionResult, MarkdownAssetCollector
from agentsec.config import ProjectConfig, default_project_config
from agentsec.diffing import AssetDiffResult, TextDiffResult
from agentsec.versioning import current_versions


class NoGitProvenanceProvider:
    """Keep application tests independent from repository state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        return GitProvenance(commit=None, dirty=None)


def create_baseline_file(
    project_root: Path,
    path: Path,
    *,
    config: ProjectConfig | None = None,
) -> Baseline:
    """Create one valid P1-13 Baseline file for Diff tests."""

    effective_config = config if config is not None else default_project_config()
    baseline = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=NoGitProvenanceProvider(),
        clock=lambda: datetime(2026, 8, 18, 16, 30, tzinfo=UTC),
    ).create(
        BaselineCreationRequest(
            project_root=project_root,
            config=effective_config,
            config_path=None,
            output_path=path,
        )
    )
    path.write_text(encode_baseline_json(baseline), encoding="utf-8")
    return baseline


def make_request(project_root: Path, baseline_path: Path) -> ProjectDiffRequest:
    """Create one default application Diff request."""

    return ProjectDiffRequest(
        project_root=project_root,
        config=default_project_config(),
        config_path=None,
        baseline_path=baseline_path,
    )


def test_engine_composes_baseline_collection_asset_and_text_diff(
    tmp_path: Path,
) -> None:
    """One service call returns file and line evidence with version provenance."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("before\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline_file(project, baseline_path)
    (project / "AGENTS.md").write_text("after\n", encoding="utf-8")

    result = CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
        make_request(project, baseline_path)
    )

    assert len(result.asset_diff.changes) == 1
    assert result.asset_diff.changes[0].path == "AGENTS.md"
    assert result.text_diff.complete is True
    assert result.text_diff.assets[0].hunks[0].lines[0].text == "before\n"
    assert result.current_collection.coverage.complete is True
    assert result.version_comparison.all_match is True


def test_engine_maps_missing_baseline_to_safe_failure(tmp_path: Path) -> None:
    """Filesystem details remain behind a stable Baseline application code."""

    with pytest.raises(ProjectDiffError) as captured:
        CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
            make_request(tmp_path, tmp_path / "missing.json")
        )

    assert captured.value.code is ProjectDiffExecutionCode.BASELINE_FAILED
    assert str(tmp_path) not in str(captured.value)


def test_engine_returns_incomplete_current_coverage_without_diffing(
    tmp_path: Path,
) -> None:
    """Invalid current assets remain coverage failures rather than deletions."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("before\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline_file(project, baseline_path)
    (project / "AGENTS.md").write_bytes(b"\xff")

    with pytest.raises(ProjectDiffError) as captured:
        CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
            make_request(project, baseline_path)
        )

    error = captured.value
    assert error.code is ProjectDiffExecutionCode.INCOMPLETE_CURRENT_COVERAGE
    assert error.coverage is not None
    assert error.coverage.complete is False
    assert error.coverage.skipped_assets == 1


def test_engine_wraps_collector_exception_without_leaking_path(tmp_path: Path) -> None:
    """Unexpected adapter diagnostics never escape the application boundary."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline_file(project, baseline_path)

    class FailingCollector:
        def collect(
            self,
            project_root: Path,
            config: ProjectConfig,
        ) -> CollectionResult:
            raise RuntimeError(f"collector-secret: {project_root}")

    with pytest.raises(ProjectDiffError) as captured:
        CollectionProjectDiffEngine(FailingCollector()).compare(
            make_request(project, baseline_path)
        )

    assert captured.value.code is ProjectDiffExecutionCode.COLLECTION_FAILED
    assert str(project) not in str(captured.value)


def test_engine_wraps_asset_and_text_differ_failures_safely(tmp_path: Path) -> None:
    """Injected analysis failures map to distinct required-analysis stages."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    create_baseline_file(project, baseline_path)

    class FailingAssetDiffer:
        def compare(self, **kwargs: object) -> AssetDiffResult:
            raise RuntimeError("asset-secret")

    with pytest.raises(ProjectDiffError) as asset_error:
        CollectionProjectDiffEngine(
            MarkdownAssetCollector(),
            asset_differ=FailingAssetDiffer(),
        ).compare(make_request(project, baseline_path))
    assert asset_error.value.code is ProjectDiffExecutionCode.ASSET_DIFF_FAILED
    assert "asset-secret" not in str(asset_error.value)

    class EmptyAssetDiffer:
        def compare(self, **kwargs: object) -> AssetDiffResult:
            return AssetDiffResult(changes=(), collection_config_matches=True)

    class FailingTextDiffer:
        def compare(self, **kwargs: object) -> TextDiffResult:
            raise RuntimeError("text-secret")

    with pytest.raises(ProjectDiffError) as text_error:
        CollectionProjectDiffEngine(
            MarkdownAssetCollector(),
            asset_differ=EmptyAssetDiffer(),
            text_differ=FailingTextDiffer(),  # type: ignore[arg-type]
        ).compare(make_request(project, baseline_path))
    assert text_error.value.code is ProjectDiffExecutionCode.TEXT_DIFF_FAILED
    assert "text-secret" not in str(text_error.value)


def test_engine_exposes_scope_and_version_mismatch_without_inventing_changes(
    tmp_path: Path,
) -> None:
    """Provenance mismatch remains distinct from file-level AssetChange."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("same\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    baseline = create_baseline_file(project, baseline_path)
    versions = current_versions()
    modified_metadata = BaselineMetadata(
        scanner_version="9.9.9.dev0",
        config_schema_version=versions.config_schema,
        domain_schema_version=versions.domain_schema,
        rule_pack_version=versions.rule_pack,
        risk_model_version=versions.risk_model,
        collection_config_sha256="d" * 64,
        generated_at=baseline.metadata.generated_at,
        git_commit=None,
        git_dirty=None,
    )
    mismatched = baseline.model_copy(update={"metadata": modified_metadata})
    baseline_path.write_text(encode_baseline_json(mismatched), encoding="utf-8")

    result = CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
        make_request(project, baseline_path)
    )

    assert result.asset_diff.changes == ()
    assert result.asset_diff.collection_config_matches is False
    assert result.version_comparison.scanner_matches is False
    assert result.version_comparison.all_match is False

"""Application service composing Baseline load, collection, and deterministic Diff."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from agentsec.baselines import (
    BaselineFileReader,
    BaselineReadResult,
    fingerprint_collection_config,
)
from agentsec.collectors import AssetCollector, CollectionResult
from agentsec.config import ProjectConfig
from agentsec.diffing import (
    AssetDiffer,
    AssetDiffResult,
    DeterministicAssetDiffer,
    DeterministicTextDiffer,
    TextDiffResult,
)
from agentsec.domain import ScanCoverage
from agentsec.versioning import VersionSet, current_versions


@dataclass(frozen=True, slots=True)
class ProjectDiffRequest:
    """Validated input accepted by the project Diff application service."""

    project_root: Path
    config: ProjectConfig
    config_path: Path | None
    baseline_path: Path


@dataclass(frozen=True, slots=True)
class DiffVersionComparison:
    """Visible provenance comparison between Baseline and current execution."""

    scanner_matches: bool
    config_schema_matches: bool
    domain_schema_matches: bool
    rule_pack_matches: bool
    risk_model_matches: bool

    @property
    def all_match(self) -> bool:
        """Return whether the full stored version vector matches current code."""

        return all(
            (
                self.scanner_matches,
                self.config_schema_matches,
                self.domain_schema_matches,
                self.rule_pack_matches,
                self.risk_model_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class ProjectDiffResult:
    """Complete internal result used by safe Diff renderers."""

    baseline: BaselineReadResult
    current_collection: CollectionResult
    asset_diff: AssetDiffResult
    text_diff: TextDiffResult
    versions: VersionSet
    version_comparison: DiffVersionComparison


class ProjectDiffEngine(Protocol):
    """Deep-module interface used by the CLI delivery adapter."""

    def compare(self, request: ProjectDiffRequest) -> ProjectDiffResult:
        """Run the deterministic project Diff pipeline."""


class ProjectDiffExecutionCode(StrEnum):
    """Stable safe application failures for Diff command mapping."""

    BASELINE_FAILED = "baseline_failed"
    COLLECTION_FAILED = "collection_failed"
    INCOMPLETE_CURRENT_COVERAGE = "incomplete_current_coverage"
    ASSET_DIFF_FAILED = "asset_diff_failed"
    TEXT_DIFF_FAILED = "text_diff_failed"


class ProjectDiffError(RuntimeError):
    """Safe application failure with optional current coverage evidence."""

    def __init__(
        self,
        code: ProjectDiffExecutionCode,
        message: str,
        *,
        coverage: ScanCoverage | None = None,
    ) -> None:
        self.code = code
        self.coverage = coverage
        super().__init__(message)


class CollectionProjectDiffEngine:
    """Compose bounded Baseline loading, collection, Asset Diff, and Text Diff."""

    def __init__(
        self,
        collector: AssetCollector,
        *,
        baseline_reader: BaselineFileReader | None = None,
        asset_differ: AssetDiffer | None = None,
        text_differ: DeterministicTextDiffer | None = None,
    ) -> None:
        self._collector = collector
        self._baseline_reader = (
            baseline_reader if baseline_reader is not None else BaselineFileReader()
        )
        self._asset_differ = (
            asset_differ if asset_differ is not None else DeterministicAssetDiffer()
        )
        self._text_differ = (
            text_differ if text_differ is not None else DeterministicTextDiffer()
        )

    def compare(self, request: ProjectDiffRequest) -> ProjectDiffResult:
        """Run Diff without executing any Baseline or current project content."""

        try:
            baseline = self._baseline_reader.read(request.baseline_path)
        except Exception as error:
            raise ProjectDiffError(
                ProjectDiffExecutionCode.BASELINE_FAILED,
                "baseline could not be loaded or validated safely",
            ) from error

        try:
            collection = self._collector.collect(request.project_root, request.config)
        except Exception as error:
            raise ProjectDiffError(
                ProjectDiffExecutionCode.COLLECTION_FAILED,
                "current project collection failed safely",
            ) from error
        if not collection.coverage.complete:
            raise ProjectDiffError(
                ProjectDiffExecutionCode.INCOMPLETE_CURRENT_COVERAGE,
                "project Diff requires complete current collection coverage",
                coverage=collection.coverage,
            )

        current_config_hash = fingerprint_collection_config(request.config)
        try:
            asset_diff = self._asset_differ.compare(
                baseline=baseline.baseline,
                current_collection=collection,
                current_collection_config_sha256=current_config_hash,
            )
        except Exception as error:
            raise ProjectDiffError(
                ProjectDiffExecutionCode.ASSET_DIFF_FAILED,
                "file-level Asset Diff failed safely",
                coverage=collection.coverage,
            ) from error

        try:
            text_diff = self._text_differ.compare(
                baseline=baseline.baseline,
                current_collection=collection,
                asset_diff=asset_diff,
            )
        except Exception as error:
            raise ProjectDiffError(
                ProjectDiffExecutionCode.TEXT_DIFF_FAILED,
                "line-oriented Text Diff failed safely",
                coverage=collection.coverage,
            ) from error

        versions = current_versions()
        metadata = baseline.baseline.metadata
        return ProjectDiffResult(
            baseline=baseline,
            current_collection=collection,
            asset_diff=asset_diff,
            text_diff=text_diff,
            versions=versions,
            version_comparison=DiffVersionComparison(
                scanner_matches=metadata.scanner_version == versions.package,
                config_schema_matches=(
                    metadata.config_schema_version == versions.config_schema
                ),
                domain_schema_matches=(
                    metadata.domain_schema_version == versions.domain_schema
                ),
                rule_pack_matches=metadata.rule_pack_version == versions.rule_pack,
                risk_model_matches=metadata.risk_model_version == versions.risk_model,
            ),
        )

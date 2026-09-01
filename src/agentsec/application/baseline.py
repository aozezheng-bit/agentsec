"""Application service for deterministic trusted-baseline construction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from agentsec.baselines import Baseline, BaselineAsset, BaselineMetadata
from agentsec.baselines.fingerprint import fingerprint_collection_config
from agentsec.baselines.provenance import (
    GitProvenanceProvider,
    SafeGitProvenanceProvider,
)
from agentsec.collectors import AssetCollector, CollectedAsset
from agentsec.config import ProjectConfig
from agentsec.parsers import MarkdownItParser, MarkdownParser
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions


def _utc_now() -> datetime:
    """Return a timezone-aware baseline generation timestamp."""

    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class BaselineCreationRequest:
    """Validated project input accepted by a baseline creator."""

    project_root: Path
    config: ProjectConfig
    config_path: Path | None
    output_path: Path


class BaselineCreator(Protocol):
    """Deep-module seam used by the baseline CLI adapter."""

    def create(self, request: BaselineCreationRequest) -> Baseline:
        """Create one in-memory, validated baseline without writing it."""


class BaselineCreationCode(StrEnum):
    """Stable safe failure categories for baseline construction."""

    COLLECTION_FAILED = "collection_failed"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    PARSE_FAILED = "parse_failed"
    PROVENANCE_FAILED = "provenance_failed"
    MODEL_INVALID = "model_invalid"


class BaselineCreationError(RuntimeError):
    """A construction failure that never contains scanned asset content."""

    def __init__(self, code: BaselineCreationCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class CollectionBaselineCreator:
    """Collect, parse, fingerprint, and snapshot bounded Markdown assets."""

    def __init__(
        self,
        collector: AssetCollector,
        *,
        parser: MarkdownParser | None = None,
        provenance_provider: GitProvenanceProvider | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._collector = collector
        self._parser = parser if parser is not None else MarkdownItParser()
        self._provenance_provider = (
            provenance_provider
            if provenance_provider is not None
            else SafeGitProvenanceProvider()
        )
        self._clock = clock

    def create(self, request: BaselineCreationRequest) -> Baseline:
        """Create a baseline only when every selected asset is fully analyzable."""

        try:
            result = self._collector.collect(request.project_root, request.config)
        except Exception as error:
            raise BaselineCreationError(
                BaselineCreationCode.COLLECTION_FAILED,
                "baseline asset collection failed safely",
            ) from error

        if not result.coverage.complete:
            raise BaselineCreationError(
                BaselineCreationCode.INCOMPLETE_COVERAGE,
                "baseline creation requires complete scan coverage",
            )

        self._parse_assets(result.assets)

        try:
            provenance = self._provenance_provider.inspect(
                request.project_root,
                excluded_paths=(request.output_path,),
            )
        except Exception as error:
            raise BaselineCreationError(
                BaselineCreationCode.PROVENANCE_FAILED,
                "baseline Git provenance could not be collected safely",
            ) from error

        versions = current_versions()
        try:
            assets = tuple(
                sorted(
                    (self._to_baseline_asset(item) for item in result.assets),
                    key=lambda asset: asset.path,
                )
            )
            return Baseline(
                schema_version=BASELINE_SCHEMA_VERSION,
                metadata=BaselineMetadata(
                    scanner_version=versions.package,
                    config_schema_version=versions.config_schema,
                    domain_schema_version=versions.domain_schema,
                    rule_pack_version=versions.rule_pack,
                    risk_model_version=versions.risk_model,
                    collection_config_sha256=fingerprint_collection_config(
                        request.config
                    ),
                    generated_at=self._clock(),
                    git_commit=provenance.commit,
                    git_dirty=provenance.dirty,
                ),
                assets=assets,
            )
        except (ValidationError, ValueError) as error:
            raise BaselineCreationError(
                BaselineCreationCode.MODEL_INVALID,
                "generated baseline failed internal validation safely",
            ) from error

    def _parse_assets(self, assets: tuple[CollectedAsset, ...]) -> None:
        """Fail closed when any collected Markdown cannot be parsed."""

        for item in assets:
            try:
                self._parser.parse(item.content)
            except Exception as error:
                raise BaselineCreationError(
                    BaselineCreationCode.PARSE_FAILED,
                    "baseline creation requires every asset to parse safely",
                ) from error

    @staticmethod
    def _to_baseline_asset(item: CollectedAsset) -> BaselineAsset:
        """Copy exact already-bounded content into its validated snapshot model."""

        asset = item.asset
        return BaselineAsset(
            path=asset.path,
            asset_type=asset.asset_type,
            source=asset.source,
            sha256=asset.sha256,
            size_bytes=asset.size_bytes,
            line_count=asset.line_count,
            encoding="utf-8",
            content=item.content,
        )

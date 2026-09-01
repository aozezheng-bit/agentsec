"""Deterministic file-level comparison of Baseline and current Agent assets."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from agentsec.baselines import Baseline, BaselineAsset
from agentsec.collectors import CollectionResult
from agentsec.domain import AgentAsset, AssetChange, ChangeType

_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class AssetDiffResult:
    """Stable file-level changes plus collection-scope compatibility."""

    changes: tuple[AssetChange, ...]
    collection_config_matches: bool

    @property
    def has_changes(self) -> bool:
        """Return whether any asset path or content hash changed."""

        return bool(self.changes)


class AssetDiffer(Protocol):
    """Deep-module interface used by later application and CLI adapters."""

    def compare(
        self,
        *,
        baseline: Baseline,
        current_collection: CollectionResult,
        current_collection_config_sha256: str,
    ) -> AssetDiffResult:
        """Compare current asset identity and hashes with a validated baseline."""


class AssetDiffCode(StrEnum):
    """Stable safe failures for malformed diff inputs."""

    INVALID_COLLECTION_CONFIG_HASH = "invalid_collection_config_hash"
    INCOMPLETE_CURRENT_COVERAGE = "incomplete_current_coverage"
    DUPLICATE_BASELINE_PATH = "duplicate_baseline_path"
    DUPLICATE_CURRENT_PATH = "duplicate_current_path"


class AssetDiffError(RuntimeError):
    """A deterministic diff failure that never includes asset content."""

    def __init__(self, code: AssetDiffCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class DeterministicAssetDiffer:
    """Compare exact paths and SHA-256 values without reading asset content."""

    def compare(
        self,
        *,
        baseline: Baseline,
        current_collection: CollectionResult,
        current_collection_config_sha256: str,
    ) -> AssetDiffResult:
        """Return added, removed, and modified assets sorted by path."""

        if _SHA256_PATTERN.fullmatch(current_collection_config_sha256) is None:
            raise AssetDiffError(
                AssetDiffCode.INVALID_COLLECTION_CONFIG_HASH,
                "current collection configuration fingerprint must be SHA-256",
            )
        if not current_collection.coverage.complete:
            raise AssetDiffError(
                AssetDiffCode.INCOMPLETE_CURRENT_COVERAGE,
                "asset diff requires complete current collection coverage",
            )

        before_by_path = self._index_baseline_assets(baseline.assets)
        after_by_path = self._index_current_assets(
            tuple(item.asset for item in current_collection.assets)
        )
        changes: list[AssetChange] = []

        for path in sorted(before_by_path.keys() | after_by_path.keys()):
            before = before_by_path.get(path)
            after = after_by_path.get(path)

            if before is None and after is not None:
                changes.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.ADDED,
                        after_sha256=after.sha256,
                    )
                )
                continue
            if before is not None and after is None:
                changes.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.REMOVED,
                        before_sha256=before.sha256,
                    )
                )
                continue
            if before is None or after is None:
                raise AssertionError("asset diff path union produced an invalid state")
            if before.sha256 != after.sha256:
                changes.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.MODIFIED,
                        before_sha256=before.sha256,
                        after_sha256=after.sha256,
                    )
                )

        return AssetDiffResult(
            changes=tuple(changes),
            collection_config_matches=(
                baseline.metadata.collection_config_sha256
                == current_collection_config_sha256
            ),
        )

    @staticmethod
    def _index_baseline_assets(
        assets: Sequence[BaselineAsset],
    ) -> dict[str, BaselineAsset]:
        """Index validated baseline assets while defending against bypassed models."""

        indexed: dict[str, BaselineAsset] = {}
        for asset in assets:
            if asset.path in indexed:
                raise AssetDiffError(
                    AssetDiffCode.DUPLICATE_BASELINE_PATH,
                    "baseline assets must have unique paths",
                )
            indexed[asset.path] = asset
        return indexed

    @staticmethod
    def _index_current_assets(
        assets: Sequence[AgentAsset],
    ) -> dict[str, AgentAsset]:
        """Index current assets without trusting caller ordering or uniqueness."""

        indexed: dict[str, AgentAsset] = {}
        for asset in assets:
            if asset.path in indexed:
                raise AssetDiffError(
                    AssetDiffCode.DUPLICATE_CURRENT_PATH,
                    "current assets must have unique paths",
                )
            indexed[asset.path] = asset
        return indexed

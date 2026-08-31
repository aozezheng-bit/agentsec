"""Interfaces and value objects shared by Agent asset collectors."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agentsec.config import ProjectConfig
from agentsec.domain import AgentAsset, ScanCoverage


@dataclass(frozen=True, slots=True)
class CollectedAsset:
    """An asset's validated metadata and decoded, still-untrusted content."""

    asset: AgentAsset
    content: str


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Deterministic collector output plus explicit scan coverage."""

    assets: tuple[CollectedAsset, ...]
    coverage: ScanCoverage

    def __post_init__(self) -> None:
        """Keep collected content and reported coverage internally consistent."""

        if len(self.assets) != self.coverage.scanned_assets:
            raise ValueError("collected assets must equal scanned coverage count")


class AssetCollector(Protocol):
    """Deep-module interface for safe, non-executing asset collection."""

    def collect(
        self,
        project_root: Path,
        config: ProjectConfig,
    ) -> CollectionResult:
        """Collect configured assets rooted at ``project_root``."""

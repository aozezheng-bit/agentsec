"""Application seam for deterministic comparison of two Agent Manifests."""

from __future__ import annotations

from typing import Protocol

from agentsec.manifests import (
    AgentManifest,
    CapabilityDiffer,
    CapabilityDiffResult,
)


class ManifestCapabilityDiffEngine(Protocol):
    """Application interface consumed by the Capability Diff CLI."""

    def compare(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
    ) -> CapabilityDiffResult:
        """Compare two already-validated Agent Manifests."""


class DeterministicManifestCapabilityDiffEngine:
    """Delegate normalized comparison to the deterministic Manifest differ."""

    def __init__(self, *, differ: CapabilityDiffer | None = None) -> None:
        self._differ = differ or CapabilityDiffer()

    def compare(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
    ) -> CapabilityDiffResult:
        """Return one value-minimizing deterministic Capability Diff."""

        return self._differ.compare(before=before, after=after)

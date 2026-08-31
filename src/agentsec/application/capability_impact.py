"""Application seam for P2-13 Capability Change Impact and Finding Delta."""

from __future__ import annotations

from typing import Protocol

from agentsec.capability_rules import (
    CapabilityRuleRunResult,
    DeterministicCapabilityRuleRunner,
    builtin_capability_rules,
)
from agentsec.change_impact import (
    CapabilityChangeImpactError,
    CapabilityChangeImpactReport,
    DeterministicCapabilityChangeImpactAnalyzer,
)
from agentsec.manifests import AgentManifest, CapabilityDiffer, CapabilityDiffResult
from agentsec.versioning import current_versions


class ManifestCapabilityChangeImpactEngine(Protocol):
    """Small interface consumed by CLI and tests."""

    def compare(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
    ) -> CapabilityChangeImpactReport:
        """Compare two validated Manifests and their deterministic Findings."""


class CapabilityImpactRuleRunner(Protocol):
    """Internal seam for deterministic Finding evaluation on saved Manifests."""

    def run(self, manifest: AgentManifest) -> CapabilityRuleRunResult:
        """Evaluate one Manifest without filesystem, network, execution, or LLM."""


class DeterministicManifestCapabilityChangeImpactEngine:
    """Compose Manifest Diff, Capability Rules, and deep impact analysis."""

    def __init__(
        self,
        *,
        differ: CapabilityDiffer | None = None,
        rule_runner: CapabilityImpactRuleRunner | None = None,
        analyzer: DeterministicCapabilityChangeImpactAnalyzer | None = None,
    ) -> None:
        self._differ = differ or CapabilityDiffer()
        self._rule_runner = rule_runner or DeterministicCapabilityRuleRunner(
            builtin_capability_rules()
        )
        self._analyzer = analyzer or DeterministicCapabilityChangeImpactAnalyzer()

    def compare(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
    ) -> CapabilityChangeImpactReport:
        """Return deterministic before/after semantics and Finding Delta."""

        if not isinstance(before, AgentManifest) or not isinstance(
            after, AgentManifest
        ):
            raise TypeError("before and after must be AgentManifest")
        capability_diff: CapabilityDiffResult = self._differ.compare(
            before=before,
            after=after,
        )
        try:
            before_rules = self._rule_runner.run(before)
            after_rules = self._rule_runner.run(after)
            return self._analyzer.analyze(
                before=before,
                after=after,
                capability_diff=capability_diff,
                before_rules=before_rules,
                after_rules=after_rules,
                versions=current_versions(),
            )
        except CapabilityChangeImpactError:
            raise
        except Exception as error:
            raise CapabilityChangeImpactError(
                "required Capability Change Impact analysis failed safely"
            ) from error

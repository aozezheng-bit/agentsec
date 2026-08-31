"""Deterministic shadow-mode Capability Gate evaluation (P2-15A-PILOT-02).

The shadow Gate engine evaluates the first calibrated Gate candidate
``HG-CAPCHAIN-001`` over already-materialized deterministic Capability Rule
Findings. It exists to prove the Gate technical chain while Pilot evidence is
still being collected. A shadow Gate is never enforcement:

```text
mode=shadow
qualification=pilot_only
blocks=false
hard_gate stays False
score, Severity, Confidence, and CLI exit behavior stay unchanged
```

The engine consumes trusted deterministic Findings and Manifest facts only. It
never reads source text, never calls an LLM, and never derives a Gate from a
numeric average.
"""

from __future__ import annotations

from dataclasses import replace as dataclass_replace
from typing import Literal, Protocol

from agentsec.capability_rules.base import (
    CapabilityCorrelation,
    CapabilityRuleContext,
    CapabilityRuleFinding,
    CapabilityShadowGateAssessment,
    CapabilityShadowGateMatch,
)
from agentsec.capability_rules.pipeline import CapabilityRuleRunResult
from agentsec.manifests import AgentManifest
from agentsec.versioning import CAPABILITY_SHADOW_GATE_VERSION

CAPABILITY_SHADOW_GATE_BASIS = (
    "AgentSec P2-15A-PILOT-02 shadow-mode Capability Gate contract 0.1.0",
    "HG-CAPCHAIN-001: execute + secret-access + external network on one "
    "target or reviewed parent/child family, complete relevant Coverage, "
    "no relevant Unknown",
)
HG_CAPCHAIN_GATE_ID = "HG-CAPCHAIN-001"
HG_CAPCHAIN_COMPONENT_RULE_ID = "CAP-CHAIN-001"
HG_CAPCHAIN_FLOOR: Literal["high", "critical"] = "high"

# Pilot correlation policy: same-target (B) and reviewed parent/child (C)
# evidence may match a High-floor shadow Gate. Agent-wide or
# incomplete-Coverage evidence is D Confidence and can never match.
_GATE_CORRELATIONS = frozenset(
    {
        CapabilityCorrelation.SAME_TARGET,
        CapabilityCorrelation.PARENT_CHILD,
    }
)


class CapabilityShadowGateEngine(Protocol):
    """Application seam for non-enforcing shadow Gate evaluation."""

    def apply(
        self, manifest: AgentManifest, result: CapabilityRuleRunResult
    ) -> CapabilityRuleRunResult:
        """Return a Rule result with shadow Gate evaluations attached."""


class DeterministicCapabilityShadowGateEngine:
    """Evaluate HG-CAPCHAIN-001 in shadow mode without any enforcement."""

    def apply(
        self, manifest: AgentManifest, result: CapabilityRuleRunResult
    ) -> CapabilityRuleRunResult:
        """Attach one shadow Gate evaluation per component-rule Finding."""

        if not isinstance(manifest, AgentManifest):
            raise TypeError("Capability Shadow Gate requires an AgentManifest")
        if not isinstance(result, CapabilityRuleRunResult):
            raise TypeError("Capability Shadow Gate requires CapabilityRuleRunResult")
        if result.agent_id != manifest.identity.agent_id:
            raise ValueError("Capability Shadow Gate Agent binding is inconsistent")
        if any(
            finding.capability_shadow_gate is not None
            and finding.rule_id != HG_CAPCHAIN_COMPONENT_RULE_ID
            for finding in result.findings
        ):
            raise ValueError("Capability Shadow Gate is bound to CAP-CHAIN-001 only")
        context = CapabilityRuleContext.from_manifest(manifest)
        findings = tuple(
            self._evaluate(context, finding) for finding in result.findings
        )
        return dataclass_replace(result, findings=findings)

    def _evaluate(
        self,
        context: CapabilityRuleContext,
        finding: CapabilityRuleFinding,
    ) -> CapabilityRuleFinding:
        if finding.rule_id != HG_CAPCHAIN_COMPONENT_RULE_ID:
            return finding

        coverage_complete = context.manifest.coverage.complete
        unknowns = self._relevant_unknowns(context, finding)
        correlation_ok = finding.correlation in _GATE_CORRELATIONS
        matched = correlation_ok and coverage_complete and not unknowns
        match = (
            CapabilityShadowGateMatch(
                gate_id=HG_CAPCHAIN_GATE_ID,
                floor=HG_CAPCHAIN_FLOOR,
                correlation=finding.correlation,
                related_ids=finding.related_ids,
                rationale=(
                    "Execute, secret-access, and external-network permissions "
                    "are correlated within Gate-eligible evidence scope.",
                    "Coverage is complete and no relevant Unknown affects the "
                    "Gate condition.",
                    "This shadow match is pilot-only evidence and does not block CI.",
                ),
            )
            if matched
            else None
        )
        assessment = CapabilityShadowGateAssessment(
            gate_version=CAPABILITY_SHADOW_GATE_VERSION,
            gate_id=HG_CAPCHAIN_GATE_ID,
            finding_id=finding.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=matched,
            blocks=False,
            coverage_complete=coverage_complete,
            relevant_unknowns=len(unknowns),
            match=match,
        )
        return finding.attach_capability_shadow_gate(assessment)

    @staticmethod
    def _relevant_unknowns(
        context: CapabilityRuleContext,
        finding: CapabilityRuleFinding,
    ) -> tuple[str, ...]:
        unknown_ids: set[str] = set()
        for target in finding.related_ids:
            permissions = context.permissions_by_target.get(target, ())
            unknown_ids.update(
                unknown.unknown_id
                for unknown in context.relevant_unknowns(target, permissions)
            )
        return tuple(sorted(unknown_ids))

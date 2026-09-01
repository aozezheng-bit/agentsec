"""Deterministic application service for Manifest capability assessment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentsec.application.agent_analysis import (
    AgentAnalysisEngine,
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    AgentAnalysisResult,
)
from agentsec.capability_rules import (
    CapabilityRuleRunResult,
    CapabilityShadowGateEngine,
    DeterministicCapabilityRuleRunner,
    DeterministicCapabilityShadowGateEngine,
    builtin_capability_rules,
)
from agentsec.manifests import AgentManifest
from agentsec.versioning import VersionSet


class CapabilityRuleRunner(Protocol):
    """Minimal runner seam consumed by the assessment application service."""

    def run(self, manifest: AgentManifest) -> CapabilityRuleRunResult:
        """Evaluate deterministic Capability Rules over one final Manifest."""


@dataclass(frozen=True, slots=True)
class CapabilityAssessmentResult:
    """One final Manifest analysis paired with deterministic Rule results."""

    analysis: AgentAnalysisResult
    rules: CapabilityRuleRunResult

    def __post_init__(self) -> None:
        if not isinstance(self.analysis, AgentAnalysisResult):
            raise TypeError("analysis must be AgentAnalysisResult")
        if not isinstance(self.rules, CapabilityRuleRunResult):
            raise TypeError("rules must be CapabilityRuleRunResult")
        if self.rules.agent_id != self.analysis.manifest.identity.agent_id:
            raise ValueError("Capability Rule result Agent must match the Manifest")
        versions = self.analysis.versions
        if self.rules.capability_rule_pack_version != versions.capability_rule_pack:
            raise ValueError("Capability Rule Pack versions do not match")
        if self.rules.capability_risk_model_version != versions.capability_risk_model:
            raise ValueError("Capability Risk Model versions do not match")

    @property
    def complete(self) -> bool:
        """Require both complete Manifest Coverage and complete Rule execution."""

        return self.analysis.complete and self.rules.complete

    @property
    def versions(self) -> VersionSet:
        """Return the complete version vector captured by Agent analysis."""

        return self.analysis.versions


class CapabilityAssessmentError(RuntimeError):
    """Safe required capability-assessment failure."""


class CapabilityAssessmentEngine:
    def __init__(
        self,
        *,
        analysis_engine: AgentAnalysisEngine | None = None,
        rule_runner: CapabilityRuleRunner | None = None,
        shadow_gate_engine: CapabilityShadowGateEngine | None = None,
    ) -> None:
        self._analysis_engine = analysis_engine or AgentAnalysisPipeline()
        self._rule_runner = rule_runner or DeterministicCapabilityRuleRunner(
            builtin_capability_rules()
        )
        self._shadow_gate_engine = (
            shadow_gate_engine or DeterministicCapabilityShadowGateEngine()
        )

    def assess(self, request: AgentAnalysisRequest) -> CapabilityAssessmentResult:
        """Analyze the Agent, then evaluate value-free deterministic Rules."""

        if not isinstance(request, AgentAnalysisRequest):
            raise TypeError("request must be AgentAnalysisRequest")
        analysis = self._analysis_engine.analyze(request)
        try:
            rules = self._rule_runner.run(analysis.manifest)
            rules = self._shadow_gate_engine.apply(analysis.manifest, rules)
        except Exception as error:
            raise CapabilityAssessmentError(
                "required capability rule analysis failed safely"
            ) from error
        return CapabilityAssessmentResult(analysis=analysis, rules=rules)

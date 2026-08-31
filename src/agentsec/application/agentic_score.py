"""Integrated deterministic Agentic Score application service (P2-EXIT-03).

Runs the complete P2-18 through P2-23 scoring chain over one analyzed Agent
project plus an explicit bounded context. Score output remains report-only
and never gains CI authority. Drift and Governance semantics are never
fabricated: they come from the explicit context or conservative defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentsec.application.agent_analysis import (
    AgentAnalysisEngine,
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    AgentAnalysisResult,
)
from agentsec.manifests import AgentManifest, CapabilityDiffer, CapabilityDiffResult
from agentsec.risk.agentic_factors import (
    AgenticFactorVector,
    DeterministicAgenticFactorExtractor,
)
from agentsec.risk.cvss import CvssBaseAdapter, CvssBaseAssessment
from agentsec.risk.drift_score import (
    DeterministicDriftScoreEngine,
    DriftScoreAssessment,
    DriftScoreContext,
)
from agentsec.risk.governance_score import (
    DeterministicGovernanceScoreEngine,
    GovernanceScoreAssessment,
    GovernanceScoreContext,
)
from agentsec.risk.overall_score import (
    DeterministicOverallScoreEngine,
    OverallHardGateMatch,
    OverallScoreAssessment,
)
from agentsec.risk.technical_score import (
    DeterministicTechnicalScoreEngine,
    TechnicalScoreAssessment,
)
from agentsec.risk.threat_mitigation import (
    DeterministicThreatMitigationEvaluator,
    ThreatMitigationVector,
)
from agentsec.score_context import LoadedScoreContext


class AgenticScoreError(RuntimeError):
    """Safe required Agentic Score failure."""


@dataclass(frozen=True, slots=True)
class AgenticScoreRequest:
    """One explicit integrated scoring request."""

    project_root: Path
    before: AgentManifest
    agent_id: str | None = None
    working_directory: Path | None = None
    user_home: Path | None = None
    codex_home: Path | None = None
    context: LoadedScoreContext | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.project_root, Path):
            raise TypeError("project_root must be a Path")
        if not isinstance(self.before, AgentManifest):
            raise TypeError("before must be an AgentManifest")
        if self.context is not None and not isinstance(
            self.context, LoadedScoreContext
        ):
            raise TypeError("context must be a loaded score context")


@dataclass(frozen=True, slots=True)
class AgenticScoreResult:
    """Complete deterministic scoring chain output for one analyzed project."""

    analysis: AgentAnalysisResult
    factors: AgenticFactorVector
    threats: ThreatMitigationVector
    capability_diff: CapabilityDiffResult
    technical: TechnicalScoreAssessment
    drift: DriftScoreAssessment
    governance: GovernanceScoreAssessment
    overall: OverallScoreAssessment
    cvss: CvssBaseAssessment | None
    gate_matches: tuple[OverallHardGateMatch, ...]
    context_sha256: str | None
    before_manifest_sha256: str
    after_manifest_sha256: str

    @property
    def complete(self) -> bool:
        return self.analysis.complete


class AgenticScoreEngine:
    """Orchestrate factors, threats, CVSS, diff, drift, governance, overall."""

    def __init__(
        self,
        *,
        analysis_engine: AgentAnalysisEngine | None = None,
        factor_extractor: DeterministicAgenticFactorExtractor | None = None,
        threat_evaluator: DeterministicThreatMitigationEvaluator | None = None,
        diff_engine: CapabilityDiffer | None = None,
        technical_engine: DeterministicTechnicalScoreEngine | None = None,
        drift_engine: DeterministicDriftScoreEngine | None = None,
        governance_engine: DeterministicGovernanceScoreEngine | None = None,
        overall_engine: DeterministicOverallScoreEngine | None = None,
        cvss_adapter: CvssBaseAdapter | None = None,
    ) -> None:
        self._analysis_engine = analysis_engine or AgentAnalysisPipeline()
        self._factor_extractor = (
            factor_extractor or DeterministicAgenticFactorExtractor()
        )
        self._threat_evaluator = (
            threat_evaluator or DeterministicThreatMitigationEvaluator()
        )
        self._diff_engine = diff_engine or CapabilityDiffer()
        self._technical_engine = technical_engine or DeterministicTechnicalScoreEngine()
        self._drift_engine = drift_engine or DeterministicDriftScoreEngine()
        self._governance_engine = (
            governance_engine or DeterministicGovernanceScoreEngine()
        )
        self._overall_engine = overall_engine or DeterministicOverallScoreEngine()
        self._cvss_adapter = cvss_adapter or CvssBaseAdapter()

    def score(self, request: AgenticScoreRequest) -> AgenticScoreResult:
        if not isinstance(request, AgenticScoreRequest):
            raise TypeError("request must be AgenticScoreRequest")
        analysis = self._analysis_engine.analyze(
            AgentAnalysisRequest(
                project_root=request.project_root,
                working_directory=request.working_directory,
                user_home=request.user_home,
                codex_home=request.codex_home,
                agent_id=request.agent_id,
            )
        )
        manifest = analysis.manifest
        context = request.context.context if request.context is not None else None

        factors = self._factor_extractor.extract(manifest)
        threats = self._threat_evaluator.evaluate(manifest, factors)

        cvss: CvssBaseAssessment | None = None
        if context is not None and context.cvss is not None:
            cvss = self._cvss_adapter.adapt({"vector": context.cvss.vector})

        capability_diff = self._diff_engine.compare(
            before=request.before, after=manifest
        )

        drift_context = (
            context.drift.to_engine_context()
            if context is not None
            else DriftScoreContext()
        )
        gate_matches: tuple[OverallHardGateMatch, ...] = ()
        if context is not None:
            gate_matches = tuple(
                item.to_engine_match() for item in context.gate_matches
            )
        governance_context = (
            context.governance.to_engine_context(drift_context)
            if context is not None and context.governance is not None
            else GovernanceScoreContext(drift=drift_context)
        )

        technical = self._technical_engine.score(factors, threats, cvss=cvss)
        drift = self._drift_engine.score(
            request.before,
            manifest,
            diff=capability_diff,
            context=drift_context,
        )
        governance = self._governance_engine.score(
            manifest,
            factors,
            threats,
            context=governance_context,
            drift=drift,
        )
        overall = self._overall_engine.score(
            technical, drift, governance, gate_matches=gate_matches
        )
        return AgenticScoreResult(
            analysis=analysis,
            factors=factors,
            threats=threats,
            capability_diff=capability_diff,
            technical=technical,
            drift=drift,
            governance=governance,
            overall=overall,
            cvss=cvss,
            gate_matches=gate_matches,
            context_sha256=request.context.sha256 if request.context else None,
            before_manifest_sha256=drift.before_manifest_sha256,
            after_manifest_sha256=drift.after_manifest_sha256,
        )


__all__ = [
    "AgenticScoreEngine",
    "AgenticScoreError",
    "AgenticScoreRequest",
    "AgenticScoreResult",
]

"""Application service for the report-only Attack Graph CLI workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agentsec.application.agent_analysis import (
    AgentAnalysisError,
    AgentAnalysisRequest,
    AgentAnalysisResult,
)
from agentsec.attack_graph import (
    AttackPathMatcher,
    AttackPathReport,
    CapabilityAttackGraph,
    ManifestCapabilityGraphBuilder,
    build_attack_path_report,
    canonical_attack_graph_sha256,
    canonical_manifest_sha256,
)


@dataclass(frozen=True, slots=True)
class AttackGraphAnalysisResult:
    """Validated Manifest analysis, matched graph, and value-free path report."""

    analysis: AgentAnalysisResult
    graph: CapabilityAttackGraph
    report: AttackPathReport

    def __post_init__(self) -> None:
        if not isinstance(self.analysis, AgentAnalysisResult):
            raise TypeError("analysis must be AgentAnalysisResult")
        if not isinstance(self.graph, CapabilityAttackGraph):
            raise TypeError("graph must be CapabilityAttackGraph")
        if not isinstance(self.report, AttackPathReport):
            raise TypeError("report must be AttackPathReport")
        if self.graph.manifest_sha256 != canonical_manifest_sha256(
            self.analysis.manifest
        ):
            raise ValueError("graph Manifest digest must match the analysis")
        if self.report.manifest_sha256 != self.graph.manifest_sha256:
            raise ValueError("report Manifest digest must match the graph")
        if self.report.graph_sha256 != canonical_attack_graph_sha256(self.graph):
            raise ValueError("report graph digest must match the graph")


@runtime_checkable
class AttackGraphAnalysisEngine(Protocol):
    """Application seam for building and matching one static Attack Graph."""

    def analyze(self, request: AgentAnalysisRequest) -> AttackGraphAnalysisResult:
        """Build a report-only graph from one explicit Agent project."""


class DeterministicAttackGraphAnalysisEngine:
    """Compose Manifest analysis, graph building, matching, and reporting."""

    def __init__(
        self,
        *,
        analysis_engine: object | None = None,
        graph_builder: ManifestCapabilityGraphBuilder | None = None,
        path_matcher: AttackPathMatcher | None = None,
    ) -> None:
        self._analysis_engine = analysis_engine
        self._graph_builder = graph_builder or ManifestCapabilityGraphBuilder()
        self._path_matcher = path_matcher or AttackPathMatcher()

    def analyze(self, request: AgentAnalysisRequest) -> AttackGraphAnalysisResult:
        if not isinstance(request, AgentAnalysisRequest):
            raise TypeError("request must be AgentAnalysisRequest")
        analysis_engine = self._analysis_engine
        if analysis_engine is None:
            from agentsec.application.agent_analysis import AgentAnalysisPipeline

            analysis_engine = AgentAnalysisPipeline()
        analyze = getattr(analysis_engine, "analyze", None)
        if not callable(analyze):
            raise TypeError("analysis_engine must provide analyze(request)")
        try:
            analysis = analyze(request)
        except AgentAnalysisError:
            raise
        if not isinstance(analysis, AgentAnalysisResult):
            raise TypeError("analysis engine must return AgentAnalysisResult")
        graph = self._graph_builder.build(analysis.manifest)
        matched_graph = self._path_matcher.match_into_graph(graph)
        report = build_attack_path_report(matched_graph)
        return AttackGraphAnalysisResult(
            analysis=analysis,
            graph=matched_graph,
            report=report,
        )


__all__ = [
    "AttackGraphAnalysisEngine",
    "AttackGraphAnalysisResult",
    "DeterministicAttackGraphAnalysisEngine",
]

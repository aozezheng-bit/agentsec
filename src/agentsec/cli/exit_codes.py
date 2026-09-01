"""Stable process exit codes for AgentSec CLI automation."""

from __future__ import annotations

from agentsec.application import (
    AgentAnalysisResult,
    CapabilityAssessmentResult,
    ProjectDiffResult,
)
from agentsec.change_impact import CapabilityChangeImpactReport
from agentsec.domain import Assessment
from agentsec.exit_codes import ExitCode
from agentsec.manifests import CapabilityDiffResult


def exit_code_for_assessment(assessment: Assessment) -> ExitCode:
    """Map current Phase 1 assessment completeness to a process outcome.

    Risk-threshold decisions are introduced by the later policy task. Until
    then, a complete assessment succeeds even if it contains findings.
    """

    if not assessment.coverage.complete:
        return ExitCode.SCAN_INCOMPLETE
    return ExitCode.SUCCESS


def exit_code_for_project_diff(result: ProjectDiffResult) -> ExitCode:
    """Map Diff comparability and evidence completeness to stable outcomes."""

    if not result.asset_diff.collection_config_matches:
        return ExitCode.BASELINE_ERROR
    if not result.text_diff.complete:
        return ExitCode.SCAN_INCOMPLETE
    return ExitCode.SUCCESS


def exit_code_for_agent_analysis(result: AgentAnalysisResult) -> ExitCode:
    """Map Manifest Coverage completeness to the stable non-clean outcome."""

    return ExitCode.SUCCESS if result.complete else ExitCode.SCAN_INCOMPLETE


def exit_code_for_capability_assessment(
    result: CapabilityAssessmentResult,
) -> ExitCode:
    """Require complete Manifest Coverage and complete deterministic Rule execution."""

    return ExitCode.SUCCESS if result.complete else ExitCode.SCAN_INCOMPLETE


def exit_code_for_capability_diff(result: CapabilityDiffResult) -> ExitCode:
    """Map two-Manifest Coverage completeness without risk-based blocking."""

    return ExitCode.SUCCESS if result.complete else ExitCode.SCAN_INCOMPLETE


def exit_code_for_capability_change_impact(
    result: CapabilityChangeImpactReport,
) -> ExitCode:
    """Keep Finding increases report-only while exposing incomplete evidence."""

    return ExitCode.SUCCESS if result.status == "complete" else ExitCode.SCAN_INCOMPLETE


__all__ = [
    "ExitCode",
    "exit_code_for_agent_analysis",
    "exit_code_for_assessment",
    "exit_code_for_capability_assessment",
    "exit_code_for_capability_change_impact",
    "exit_code_for_capability_diff",
    "exit_code_for_project_diff",
]

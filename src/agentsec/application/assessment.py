"""Application seam between CLI requests and assessment implementations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agentsec.config import ProjectConfig
from agentsec.domain import Assessment


@dataclass(frozen=True, slots=True)
class AssessmentRequest:
    """Input accepted by the Phase 1 assessment engine."""

    project_root: Path
    config: ProjectConfig
    config_path: Path | None


class AssessmentEngine(Protocol):
    """Deep-module interface used by CLI and future adapters."""

    def assess(self, request: AssessmentRequest) -> Assessment:
        """Assess the requested project and return an evidence-backed result."""


class AssessmentEngineUnavailable(RuntimeError):
    """Explicit failure adapter for an unavailable assessment implementation."""


class AssessmentAnalysisError(RuntimeError):
    """Safe failure from a required deterministic assessment stage."""


class UnavailableAssessmentEngine:
    """Injectable placeholder retained for safe CLI failure testing."""

    def assess(self, request: AssessmentRequest) -> Assessment:
        """Reject scans without reading or executing anything in the target."""

        raise AssessmentEngineUnavailable(
            "the assessment engine is not implemented yet; "
            f"the requested project root was '{request.project_root}'"
        )

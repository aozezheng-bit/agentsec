"""Stable process exit codes independent of CLI initialization."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Documented outcomes returned by AgentSec commands and CI wrappers."""

    SUCCESS = 0
    RISK_THRESHOLD_EXCEEDED = 1
    SCAN_INCOMPLETE = 2
    CONFIGURATION_ERROR = 3
    BASELINE_ERROR = 4
    ARTIFACT_ERROR = 4
    REQUIRED_ANALYSIS_FAILED = 5
    USAGE_ERROR = 64


__all__ = ["ExitCode"]

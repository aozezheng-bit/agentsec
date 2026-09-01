"""Qualitative levels specific to AgentSec risk calculations."""

from __future__ import annotations

from enum import StrEnum


class NistRiskLevel(StrEnum):
    """Five qualitative risk levels used by NIST SP 800-30 Table I-2."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"

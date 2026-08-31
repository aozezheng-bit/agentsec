"""Enumerations shared by AgentSec domain models."""

from __future__ import annotations

from enum import StrEnum


class AssetType(StrEnum):
    """Supported Phase 1 Agent asset types."""

    AGENTS = "agents"
    AGENTS_OVERRIDE = "agents_override"
    SKILL = "skill"
    EXPLICIT_MARKDOWN = "explicit_markdown"


class AssetSource(StrEnum):
    """How an asset entered the scan scope."""

    DISCOVERED = "discovered"
    EXPLICIT = "explicit"


class GitFileStatus(StrEnum):
    """Optional Git working-tree status associated with an asset."""

    UNCHANGED = "unchanged"
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNTRACKED = "untracked"


class ChangeType(StrEnum):
    """File-level changes supported by the Phase 1 baseline diff."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class EvidenceSource(StrEnum):
    """Origin of evidence supporting a finding."""

    FILE = "file"
    DIFF = "diff"
    CONFIGURATION = "configuration"
    RUNTIME = "runtime"


class FindingCategory(StrEnum):
    """Initial Phase 1 security finding taxonomy."""

    INSTRUCTION_INTEGRITY = "instruction_integrity"
    HUMAN_APPROVAL = "human_approval"
    CODE_EXECUTION = "code_execution"
    NETWORK_ACCESS = "network_access"
    SECRET_ACCESS = "secret_access"
    PRIVILEGED_ACCESS = "privileged_access"
    DESTRUCTIVE_ACTION = "destructive_action"
    PERSISTENT_MEMORY = "persistent_memory"
    SELF_MODIFICATION = "self_modification"
    OBFUSCATION = "obfuscation"
    EXTERNAL_TOOLING = "external_tooling"
    SCAN_COVERAGE = "scan_coverage"
    OTHER = "other"


class LikelihoodLevel(StrEnum):
    """NIST-style qualitative likelihood levels."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ImpactLevel(StrEnum):
    """NIST-style qualitative impact levels."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class Severity(StrEnum):
    """Report severity compatible with the planned 0-10 risk scale."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceConfidence(StrEnum):
    """Confidence in evidence, independent from finding severity."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"


class CoverageIssueCode(StrEnum):
    """Reasons an asset or part of a scan could not be evaluated."""

    UNREADABLE = "unreadable"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    TOO_LARGE = "too_large"
    DEPTH_EXCEEDED = "depth_exceeded"
    ASSET_LIMIT_EXCEEDED = "asset_limit_exceeded"
    EXTERNAL_SYMLINK = "external_symlink"
    MALFORMED_CONTENT = "malformed_content"
    PARSE_ERROR = "parse_error"
    RULE_ERROR = "rule_error"
    UNKNOWN = "unknown"

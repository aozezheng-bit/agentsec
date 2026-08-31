"""Framework Adapter seam and immutable neutral inspection models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from agentsec.domain.base import validate_relative_path
from agentsec.parsers import (
    ParsedMarkdown,
    ParsedMcpConfiguration,
    ParsedRulesDocument,
    StructuredDataFormat,
    StructuredDocument,
)
from agentsec.versioning import parse_interface_version

_FRAMEWORK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

type ParsedFrameworkDocument = ParsedMarkdown | ParsedRulesDocument | StructuredDocument


class FrameworkAssetScope(StrEnum):
    """Portable source scope for one framework-controlled asset."""

    PROJECT = "project"
    USER = "user"
    PLUGIN = "plugin"


class FrameworkAssetFormat(StrEnum):
    """Parser format selected by a trusted Framework Adapter."""

    MARKDOWN = "markdown"
    RULES = "rules"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


class FrameworkAssetRole(StrEnum):
    """Framework-neutral roles assigned before Agent Manifest construction."""

    AGENT_INSTRUCTIONS = "agent_instructions"
    INSTRUCTION_OVERRIDE = "instruction_override"
    SKILL = "skill"
    PREFIX_RULES = "prefix_rules"
    FRAMEWORK_CONFIG = "framework_config"
    MCP_CONFIG = "mcp_config"


class FrameworkInspectionIssueCode(StrEnum):
    """Stable coverage failures produced by Framework Adapters."""

    UNREADABLE = "unreadable"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    TOO_LARGE = "too_large"
    DEPTH_EXCEEDED = "depth_exceeded"
    ASSET_LIMIT_EXCEEDED = "asset_limit_exceeded"
    EXTERNAL_SYMLINK = "external_symlink"
    UNSUPPORTED_FORMAT = "unsupported_format"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FrameworkAdapterMetadata:
    """Stable identity and provenance for one Framework Adapter implementation."""

    framework_id: str
    display_name: str
    adapter_version: str

    def __post_init__(self) -> None:
        if _FRAMEWORK_ID_PATTERN.fullmatch(self.framework_id) is None:
            raise ValueError("framework_id must use stable lowercase identifier form")
        if not self.display_name.strip():
            raise ValueError("framework display_name must not be empty")
        parse_interface_version(self.adapter_version)


@dataclass(frozen=True, slots=True)
class FrameworkInspectionLimits:
    """Outer filesystem limits every Framework Adapter must enforce."""

    max_file_size_bytes: int = 1_048_576
    max_depth: int = 20
    max_assets: int = 1_000

    def __post_init__(self) -> None:
        if min(self.max_file_size_bytes, self.max_depth, self.max_assets) < 1:
            raise ValueError("framework inspection limits must be positive")


@dataclass(frozen=True, slots=True)
class FrameworkInspectionRequest:
    """Explicit roots and limits accepted by every Framework Adapter."""

    project_root: Path
    user_home: Path | None = None
    working_directory: Path | None = None
    limits: FrameworkInspectionLimits = FrameworkInspectionLimits()

    def __post_init__(self) -> None:
        if not isinstance(self.project_root, Path):
            raise TypeError("project_root must be a Path")
        if self.user_home is not None and not isinstance(self.user_home, Path):
            raise TypeError("user_home must be a Path when provided")
        if self.working_directory is not None and not isinstance(
            self.working_directory, Path
        ):
            raise TypeError("working_directory must be a Path when provided")
        if not isinstance(self.limits, FrameworkInspectionLimits):
            raise TypeError("limits must be FrameworkInspectionLimits")


@dataclass(frozen=True, slots=True, order=True)
class FrameworkAssetLocator:
    """Portable locator relative to one explicitly named framework source root."""

    scope: FrameworkAssetScope
    root_id: str
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.scope, FrameworkAssetScope):
            raise TypeError("framework asset scope must be FrameworkAssetScope")
        if not self.root_id.strip():
            raise ValueError("framework asset root_id must not be empty")
        object.__setattr__(self, "path", validate_relative_path(self.path))


@dataclass(frozen=True, slots=True)
class FrameworkAsset:
    """Validated framework-neutral asset metadata without absolute host paths."""

    locator: FrameworkAssetLocator
    format: FrameworkAssetFormat
    roles: frozenset[FrameworkAssetRole]
    content_sha256: str
    size_bytes: int
    line_count: int
    precedence_rank: int

    def __post_init__(self) -> None:
        if not isinstance(self.locator, FrameworkAssetLocator):
            raise TypeError("framework asset locator must be FrameworkAssetLocator")
        if not isinstance(self.format, FrameworkAssetFormat):
            raise TypeError("framework asset format must be FrameworkAssetFormat")
        if not isinstance(self.roles, frozenset) or any(
            not isinstance(role, FrameworkAssetRole) for role in self.roles
        ):
            raise TypeError("framework asset roles must be a typed frozenset")
        if not self.roles:
            raise ValueError("framework asset requires at least one role")
        if _SHA256_PATTERN.fullmatch(self.content_sha256) is None:
            raise ValueError("framework asset requires a lowercase SHA-256 digest")
        if self.size_bytes < 0 or self.line_count < 0:
            raise ValueError("framework asset size and line count must not be negative")
        if self.precedence_rank < 0:
            raise ValueError("framework asset precedence_rank must not be negative")
        self._validate_role_format()

    def _validate_role_format(self) -> None:
        markdown_roles = {
            FrameworkAssetRole.AGENT_INSTRUCTIONS,
            FrameworkAssetRole.INSTRUCTION_OVERRIDE,
            FrameworkAssetRole.SKILL,
        }
        structured_roles = {
            FrameworkAssetRole.FRAMEWORK_CONFIG,
            FrameworkAssetRole.MCP_CONFIG,
        }
        if (
            self.roles & markdown_roles
            and self.format is not FrameworkAssetFormat.MARKDOWN
        ):
            raise ValueError("instruction and Skill roles require Markdown format")
        if (
            FrameworkAssetRole.PREFIX_RULES in self.roles
            and self.format is not FrameworkAssetFormat.RULES
        ):
            raise ValueError("prefix Rules role requires Rules format")
        if self.roles & structured_roles and self.format not in {
            FrameworkAssetFormat.JSON,
            FrameworkAssetFormat.YAML,
            FrameworkAssetFormat.TOML,
        }:
            raise ValueError("configuration roles require a structured format")
        role_families = sum(
            bool(self.roles & family)
            for family in (
                markdown_roles,
                {FrameworkAssetRole.PREFIX_RULES},
                structured_roles,
            )
        )
        if role_families != 1:
            raise ValueError("framework asset roles must belong to one format family")


@dataclass(frozen=True, slots=True)
class FrameworkAssetRecord:
    """One parsed asset record returned by a Framework Adapter."""

    asset: FrameworkAsset
    document: ParsedFrameworkDocument
    mcp_configuration: ParsedMcpConfiguration | None = None

    def __post_init__(self) -> None:
        self._validate_document_type()
        source_line_count = self.document.source_line_count
        if source_line_count != self.asset.line_count:
            raise ValueError("parsed document line count must match asset metadata")
        has_mcp_role = FrameworkAssetRole.MCP_CONFIG in self.asset.roles
        if has_mcp_role != (self.mcp_configuration is not None):
            raise ValueError("MCP role and parsed MCP configuration must agree")

    def _validate_document_type(self) -> None:
        if self.asset.format is FrameworkAssetFormat.MARKDOWN:
            if not isinstance(self.document, ParsedMarkdown):
                raise TypeError("Markdown framework assets require ParsedMarkdown")
            return
        if self.asset.format is FrameworkAssetFormat.RULES:
            if not isinstance(self.document, ParsedRulesDocument):
                raise TypeError("Rules framework assets require ParsedRulesDocument")
            return
        if not isinstance(self.document, StructuredDocument):
            raise TypeError("structured framework assets require StructuredDocument")
        expected = {
            FrameworkAssetFormat.JSON: StructuredDataFormat.JSON,
            FrameworkAssetFormat.YAML: StructuredDataFormat.YAML,
            FrameworkAssetFormat.TOML: StructuredDataFormat.TOML,
        }[self.asset.format]
        if self.document.format is not expected:
            raise ValueError("structured document format must match asset format")


@dataclass(frozen=True, slots=True)
class FrameworkInspectionIssue:
    """One safe coverage issue without untrusted exception or source text."""

    code: FrameworkInspectionIssueCode
    root_id: str
    path: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, FrameworkInspectionIssueCode):
            raise TypeError("framework issue code must be FrameworkInspectionIssueCode")
        if not self.root_id.strip():
            raise ValueError("framework issue root_id must not be empty")
        if self.path is not None:
            object.__setattr__(self, "path", validate_relative_path(self.path))

    def _sort_key(self) -> tuple[str, str, str]:
        return (self.code.value, self.root_id, self.path or "")


@dataclass(frozen=True, slots=True)
class FrameworkInspectionResult:
    """Deterministic Adapter output plus explicit inspection coverage."""

    metadata: FrameworkAdapterMetadata
    assets: tuple[FrameworkAssetRecord, ...]
    issues: tuple[FrameworkInspectionIssue, ...]
    discovered_assets: int
    skipped_assets: int
    complete: bool

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, FrameworkAdapterMetadata):
            raise TypeError(
                "framework result metadata must be FrameworkAdapterMetadata"
            )
        if not isinstance(self.assets, tuple) or any(
            not isinstance(record, FrameworkAssetRecord) for record in self.assets
        ):
            raise TypeError("framework result assets must be a typed tuple")
        if not isinstance(self.issues, tuple) or any(
            not isinstance(issue, FrameworkInspectionIssue) for issue in self.issues
        ):
            raise TypeError("framework result issues must be a typed tuple")
        if self.discovered_assets < 0 or self.skipped_assets < 0:
            raise ValueError("framework coverage counts must not be negative")
        if len(self.assets) + self.skipped_assets != self.discovered_assets:
            raise ValueError("framework assets and skipped count must equal discovered")
        if self.complete != (self.skipped_assets == 0 and not self.issues):
            raise ValueError(
                "framework complete state must match issues and skipped count"
            )

        locator_keys = [record.asset.locator for record in self.assets]
        if locator_keys != sorted(locator_keys):
            raise ValueError("framework assets must be ordered by portable locator")
        if len(locator_keys) != len(set(locator_keys)):
            raise ValueError("framework asset locators must be unique")
        if self.issues != tuple(
            sorted(self.issues, key=lambda issue: issue._sort_key())
        ):
            raise ValueError("framework issues must be deterministically ordered")
        if len(self.issues) != len(set(self.issues)):
            raise ValueError("framework issues must be unique")

    @property
    def inspected_assets(self) -> int:
        """Return the successfully parsed asset count."""

        return len(self.assets)


class FrameworkAdapterError(RuntimeError):
    """Safe catastrophic Adapter failure without scanned content."""


@runtime_checkable
class FrameworkAdapter(Protocol):
    """Deep-module seam implemented by each supported Agent framework."""

    @property
    def metadata(self) -> FrameworkAdapterMetadata:
        """Return stable Adapter identity and implementation provenance."""

    def inspect(self, request: FrameworkInspectionRequest) -> FrameworkInspectionResult:
        """Discover and parse inert control assets without executing declarations."""

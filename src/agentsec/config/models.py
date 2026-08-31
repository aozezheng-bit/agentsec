"""Strict project-configuration models for the Phase 1 scanner."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentsec.versioning import CONFIG_SCHEMA_VERSION, parse_interface_version

DEFAULT_INCLUDE_PATTERNS = (
    "AGENTS.md",
    "AGENTS.override.md",
    "SKILL.md",
    "**/AGENTS.md",
    "**/AGENTS.override.md",
    "**/SKILL.md",
)
DEFAULT_EXCLUDE_PATTERNS = (
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "vendor/**",
    "dist/**",
    "build/**",
    "**/__pycache__/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
)

_DRIVE_PREFIX_PATTERN = re.compile(r"^[A-Za-z]:")


class ConfigModel(BaseModel):
    """Immutable config base that rejects unsupported fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


def _validate_pattern(value: str) -> str:
    """Validate a project-relative include or exclude glob."""

    candidate = value.replace("\\", "/").strip()
    path = PurePosixPath(candidate)

    if not candidate:
        raise ValueError("glob pattern must not be empty")
    if "\x00" in candidate:
        raise ValueError("glob pattern must not contain NUL bytes")
    if path.is_absolute() or _DRIVE_PREFIX_PATTERN.match(candidate):
        raise ValueError("glob pattern must be project-relative")
    if ".." in path.parts:
        raise ValueError("glob pattern must not traverse outside the project root")

    return path.as_posix()


class OutputFormat(StrEnum):
    """Formats supported by the Phase 1 configuration schema."""

    TEXT = "text"
    JSON = "json"


class DiscoveryConfig(ConfigModel):
    """Asset discovery patterns applied by the Markdown collector."""

    include: Annotated[tuple[str, ...], Field(min_length=1)] = DEFAULT_INCLUDE_PATTERNS
    exclude: tuple[str, ...] = DEFAULT_EXCLUDE_PATTERNS

    @field_validator("include", "exclude")
    @classmethod
    def patterns_must_be_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize patterns and reject paths outside the project root."""

        normalized = tuple(_validate_pattern(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("glob patterns must be unique")
        return normalized


class LimitsConfig(ConfigModel):
    """Resource limits protecting local and CI scan environments."""

    max_file_size_bytes: Annotated[int, Field(ge=1, le=67_108_864)] = 1_048_576
    max_depth: Annotated[int, Field(ge=1, le=256)] = 20
    max_assets: Annotated[int, Field(ge=1, le=1_000_000)] = 1_000


class OutputConfig(ConfigModel):
    """Output behavior shared by future text and JSON reporters."""

    format: OutputFormat = OutputFormat.TEXT
    redact_secrets: bool = True

    @field_validator("redact_secrets")
    @classmethod
    def secret_redaction_cannot_be_disabled(cls, value: bool) -> bool:
        """Enforce the Phase 1 invariant that reports never expose secrets."""

        if not value:
            raise ValueError("secret redaction cannot be disabled")
        return value


class ProjectConfig(ConfigModel):
    """Versioned `.agentsec/config.yaml` project configuration."""

    version: str
    discovery: DiscoveryConfig = DiscoveryConfig()
    limits: LimitsConfig = LimitsConfig()
    output: OutputConfig = OutputConfig()

    @field_validator("version")
    @classmethod
    def version_must_be_exact_semver(cls, value: str) -> str:
        """Reject ambiguous or package-style schema versions."""

        parse_interface_version(value)
        return value


def default_project_config() -> ProjectConfig:
    """Return the versioned secure defaults used when no file is present."""

    return ProjectConfig(version=CONFIG_SCHEMA_VERSION)

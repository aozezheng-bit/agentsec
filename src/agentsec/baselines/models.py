"""Strict, versioned models for trusted local AgentSec baselines."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import AssetSource, AssetType
from agentsec.domain.base import Sha256Digest, validate_relative_path
from agentsec.versioning import parse_interface_version

_INTERFACE_VERSION_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"

InterfaceVersionString = Annotated[
    str,
    Field(min_length=1, pattern=_INTERFACE_VERSION_PATTERN),
]
GitCommitDigest = Annotated[
    str,
    Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$"),
]
NonEmptyString = Annotated[str, Field(min_length=1)]


class BaselineModel(BaseModel):
    """Immutable baseline base that preserves asset content exactly."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
    )


class BaselineAsset(BaselineModel):
    """One exact UTF-8 Agent control asset stored in a baseline."""

    path: NonEmptyString
    asset_type: AssetType
    source: AssetSource
    sha256: Sha256Digest
    size_bytes: Annotated[int, Field(ge=0)]
    line_count: Annotated[int, Field(ge=0)]
    encoding: Literal["utf-8"] = "utf-8"
    content: str

    @field_validator("path")
    @classmethod
    def path_must_be_project_relative(cls, value: str) -> str:
        """Keep baseline paths portable and inside the selected project root."""

        return validate_relative_path(value)

    @model_validator(mode="after")
    def metadata_must_match_exact_content(self) -> BaselineAsset:
        """Reject content whose bytes, size, lines, or digest were altered."""

        try:
            content_bytes = self.content.encode(self.encoding)
        except UnicodeEncodeError as error:
            raise ValueError("baseline asset content must be valid UTF-8") from error

        if len(content_bytes) != self.size_bytes:
            raise ValueError("baseline asset size_bytes must match content")
        if len(self.content.splitlines()) != self.line_count:
            raise ValueError("baseline asset line_count must match content")
        if hashlib.sha256(content_bytes).hexdigest() != self.sha256:
            raise ValueError("baseline asset sha256 must match content")

        return self


class BaselineMetadata(BaselineModel):
    """Generation and provenance metadata for one trusted snapshot."""

    scanner_version: NonEmptyString
    config_schema_version: InterfaceVersionString
    domain_schema_version: InterfaceVersionString
    rule_pack_version: InterfaceVersionString
    risk_model_version: InterfaceVersionString
    collection_config_sha256: Sha256Digest
    generated_at: datetime
    git_commit: GitCommitDigest | None = None
    git_dirty: bool | None = None

    @field_validator(
        "config_schema_version",
        "domain_schema_version",
        "rule_pack_version",
        "risk_model_version",
    )
    @classmethod
    def interface_versions_must_be_exact_semver(cls, value: str) -> str:
        """Keep every serialized interface version explicit and parseable."""

        parse_interface_version(value)
        return value

    @field_validator("scanner_version")
    @classmethod
    def scanner_version_must_not_contain_outer_whitespace(cls, value: str) -> str:
        """Preserve an exact package version without silently normalizing it."""

        if not value.strip() or value != value.strip():
            raise ValueError("scanner_version must be a non-empty exact value")
        return value

    @model_validator(mode="after")
    def provenance_must_be_coherent(self) -> BaselineMetadata:
        """Require unambiguous time and all-or-none Git provenance."""

        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if (self.git_commit is None) != (self.git_dirty is None):
            raise ValueError("git_commit and git_dirty must be provided together")
        return self


class Baseline(BaselineModel):
    """Top-level versioned snapshot used by later deterministic diff stages."""

    schema_version: InterfaceVersionString
    metadata: BaselineMetadata
    assets: tuple[BaselineAsset, ...]

    @field_validator("schema_version")
    @classmethod
    def schema_version_must_be_exact_semver(cls, value: str) -> str:
        """Reject ambiguous or package-style baseline schema versions."""

        parse_interface_version(value)
        return value

    @model_validator(mode="after")
    def assets_must_be_unique_and_sorted(self) -> Baseline:
        """Make path identity unambiguous and serialized output reproducible."""

        paths = tuple(asset.path for asset in self.assets)
        if len(paths) != len(set(paths)):
            raise ValueError("baseline asset paths must be unique")
        if paths != tuple(sorted(paths)):
            raise ValueError("baseline assets must be sorted by path")
        return self

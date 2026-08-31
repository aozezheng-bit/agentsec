"""Agent asset and baseline-change domain models."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator, model_validator

from agentsec.domain.base import (
    DomainModel,
    NonEmptyString,
    Sha256Digest,
    validate_relative_path,
)
from agentsec.domain.enums import AssetSource, AssetType, ChangeType, GitFileStatus


class AgentAsset(DomainModel):
    """A discovered Phase 1 Agent control asset."""

    path: NonEmptyString
    asset_type: AssetType
    source: AssetSource
    sha256: Sha256Digest
    size_bytes: Annotated[int, Field(ge=0)]
    line_count: Annotated[int, Field(ge=0)]
    encoding: NonEmptyString = "utf-8"
    git_status: GitFileStatus | None = None

    @field_validator("path")
    @classmethod
    def path_must_be_project_relative(cls, value: str) -> str:
        """Keep serialized asset paths portable and project-relative."""

        return validate_relative_path(value)


class AssetChange(DomainModel):
    """A file-level difference between the current scan and a baseline."""

    path: NonEmptyString
    change_type: ChangeType
    before_sha256: Sha256Digest | None = None
    after_sha256: Sha256Digest | None = None

    @field_validator("path")
    @classmethod
    def path_must_be_project_relative(cls, value: str) -> str:
        """Keep changed asset paths portable and project-relative."""

        return validate_relative_path(value)

    @model_validator(mode="after")
    def hashes_must_match_change_type(self) -> AssetChange:
        """Require the hashes needed to explain each change type."""

        if self.change_type is ChangeType.ADDED:
            if self.before_sha256 is not None or self.after_sha256 is None:
                raise ValueError("added assets require only after_sha256")
        elif self.change_type is ChangeType.REMOVED:
            if self.before_sha256 is None or self.after_sha256 is not None:
                raise ValueError("removed assets require only before_sha256")
        elif self.change_type is ChangeType.MODIFIED:
            if self.before_sha256 is None or self.after_sha256 is None:
                raise ValueError("modified assets require both hashes")
            if self.before_sha256 == self.after_sha256:
                raise ValueError("modified asset hashes must differ")

        return self

"""Shared configuration and validation helpers for AgentSec domain models."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

Sha256Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
NonEmptyString = Annotated[str, Field(min_length=1)]


class DomainModel(BaseModel):
    """Strict, immutable base class for serialized AgentSec domain objects."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


def validate_relative_path(value: str) -> str:
    """Validate and normalize a project-relative POSIX path.

    Domain objects store portable project-relative paths. Collectors are
    responsible for resolving filesystem paths and enforcing symlink policy.
    """

    candidate = value.replace("\\", "/")
    path = PurePosixPath(candidate)

    if not candidate or candidate == ".":
        raise ValueError("path must identify a project-relative asset")
    if path.is_absolute():
        raise ValueError("path must be relative to the project root")
    if path.parts and path.parts[0].endswith(":"):
        raise ValueError("path must not contain a drive prefix")
    if ".." in path.parts:
        raise ValueError("path must not traverse outside the project root")

    return path.as_posix()

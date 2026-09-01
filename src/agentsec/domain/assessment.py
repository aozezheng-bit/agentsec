"""Assessment metadata, coverage, and aggregate result models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from agentsec.domain.assets import AgentAsset, AssetChange
from agentsec.domain.base import DomainModel, NonEmptyString, validate_relative_path
from agentsec.domain.enums import CoverageIssueCode
from agentsec.domain.findings import Finding


class CoverageIssue(DomainModel):
    """A visible reason that scan coverage is incomplete."""

    code: CoverageIssueCode
    message: NonEmptyString
    asset_path: NonEmptyString | None = None

    @field_validator("asset_path")
    @classmethod
    def path_must_be_project_relative(cls, value: str | None) -> str | None:
        """Validate the optional project-relative problem path."""

        if value is None:
            return None
        return validate_relative_path(value)


class ScanCoverage(DomainModel):
    """Counts and issues describing how much of the target was evaluated."""

    discovered_assets: Annotated[int, Field(ge=0)]
    scanned_assets: Annotated[int, Field(ge=0)]
    skipped_assets: Annotated[int, Field(ge=0)]
    complete: bool
    issues: tuple[CoverageIssue, ...] = ()

    @model_validator(mode="after")
    def counts_and_completion_must_agree(self) -> ScanCoverage:
        """Prevent reports from silently misrepresenting scan coverage."""

        if self.scanned_assets + self.skipped_assets != self.discovered_assets:
            raise ValueError(
                "scanned_assets plus skipped_assets must equal discovered_assets"
            )
        if self.complete and (self.skipped_assets > 0 or self.issues):
            raise ValueError(
                "complete coverage cannot contain skipped assets or issues"
            )
        if not self.complete and self.skipped_assets == 0 and not self.issues:
            raise ValueError("incomplete coverage requires a skipped asset or issue")

        return self


class AssessmentMetadata(DomainModel):
    """Version and execution metadata needed for reproducible reports."""

    schema_version: NonEmptyString
    scanner_version: NonEmptyString
    config_schema_version: NonEmptyString
    rule_pack_version: NonEmptyString
    risk_model_version: NonEmptyString
    target_root: NonEmptyString
    started_at: datetime
    completed_at: datetime
    git_commit: NonEmptyString | None = None
    git_dirty: bool | None = None
    deterministic: bool = True

    @model_validator(mode="after")
    def timestamps_must_be_ordered_and_timezone_aware(self) -> AssessmentMetadata:
        """Require unambiguous execution times in deterministic reports."""

        if self.started_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise ValueError("assessment timestamps must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be earlier than started_at")

        return self


class Assessment(DomainModel):
    """Top-level Phase 1 scan result."""

    metadata: AssessmentMetadata
    assets: tuple[AgentAsset, ...] = ()
    changes: tuple[AssetChange, ...] = ()
    findings: tuple[Finding, ...] = ()
    coverage: ScanCoverage

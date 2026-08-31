"""Versioned deterministic Capability Diff for two Agent Manifests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError, field_validator, model_validator

from agentsec.manifests.models import (
    AgentManifest,
    InterfaceVersionString,
    ManifestModel,
    ManifestSourceReference,
    NonEmptyString,
    NonNegativeInt,
)
from agentsec.versioning import (
    AGENT_MANIFEST_SCHEMA_VERSION,
    CAPABILITY_DIFF_SCHEMA_VERSION,
    can_read_interface_version,
    parse_interface_version,
)

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
Sha256String = str


class CapabilityChangeType(StrEnum):
    """Set-level change type for one capability item."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class CapabilityDimension(StrEnum):
    """Manifest item collections compared by P2-11."""

    TOOL = "tool"
    PERMISSION = "permission"
    CONTROL = "control"
    RUNTIME_IDENTITY = "runtime_identity"
    RELATIONSHIP = "relationship"
    UNKNOWN = "unknown"


class CapabilityProfileName(StrEnum):
    """Resolution/coverage profiles compared independently from item changes."""

    IDENTITY = "identity"
    INSTRUCTIONS = "instructions"
    CONFIGURATION = "configuration"
    TOOLS = "tools"
    PERMISSIONS = "permissions"
    CONTROLS = "controls"
    RUNTIME_IDENTITIES = "runtime_identities"
    RELATIONSHIPS = "relationships"
    COVERAGE = "coverage"


class CapabilityDiffError(RuntimeError):
    """Safe failure for incompatible or incoherent Capability Diff inputs."""


class CapabilityDiffValidationCode(StrEnum):
    """Stable safe Capability Diff validation failures."""

    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_SCHEMA_VERSION = "missing_schema_version"
    INVALID_SCHEMA_VERSION = "invalid_schema_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_PAYLOAD = "invalid_payload"


class CapabilityDiffValidationError(RuntimeError):
    """Safe validation error that exposes only trusted field paths."""

    def __init__(
        self,
        code: CapabilityDiffValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


class CapabilityProfileChange(ManifestModel):
    """One profile resolution or Coverage-completeness transition."""

    profile: CapabilityProfileName
    before: NonEmptyString
    after: NonEmptyString

    @model_validator(mode="after")
    def profile_change_must_change(self) -> CapabilityProfileChange:
        if self.before == self.after:
            raise ValueError("profile change requires distinct before and after values")
        return self


class CapabilityItemChange(ManifestModel):
    """One added, removed, or modified capability without raw item values."""

    dimension: CapabilityDimension
    item_id: NonEmptyString
    change_type: CapabilityChangeType
    changed_fields: tuple[NonEmptyString, ...]
    before_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    after_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    before_sources: tuple[ManifestSourceReference, ...] = ()
    after_sources: tuple[ManifestSourceReference, ...] = ()

    @field_validator("item_id")
    @classmethod
    def item_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("Capability Diff item_id must use stable form")
        return value

    @model_validator(mode="after")
    def item_change_must_be_coherent(self) -> CapabilityItemChange:
        expected_fields = tuple(sorted(set(self.changed_fields)))
        if not self.changed_fields or self.changed_fields != expected_fields:
            raise ValueError("changed_fields must be non-empty, sorted, and unique")
        self._validate_sources(self.before_sources, "before_sources")
        self._validate_sources(self.after_sources, "after_sources")
        if self.change_type is CapabilityChangeType.ADDED:
            if self.before_sha256 is not None or self.before_sources:
                raise ValueError("added item cannot contain before state")
            if self.after_sha256 is None:
                raise ValueError("added item requires after fingerprint")
        elif self.change_type is CapabilityChangeType.REMOVED:
            if self.after_sha256 is not None or self.after_sources:
                raise ValueError("removed item cannot contain after state")
            if self.before_sha256 is None:
                raise ValueError("removed item requires before fingerprint")
        else:
            if self.before_sha256 is None or self.after_sha256 is None:
                raise ValueError("modified item requires both fingerprints")
            if self.before_sha256 == self.after_sha256:
                raise ValueError("modified item fingerprints must differ")
        return self

    @staticmethod
    def _validate_sources(
        sources: tuple[ManifestSourceReference, ...],
        label: str,
    ) -> None:
        keys = tuple(source.sort_key() for source in sources)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError(f"{label} must be sorted and unique")

    def sort_key(self) -> tuple[str, str, str]:
        """Return the canonical change order."""

        return (self.dimension.value, self.item_id, self.change_type.value)


class CapabilityDiffResult(ManifestModel):
    """Versioned deterministic difference between two compatible Manifests."""

    schema_version: InterfaceVersionString
    agent_manifest_schema_version: InterfaceVersionString
    agent_id: NonEmptyString
    before_coverage_complete: bool
    after_coverage_complete: bool
    complete: bool
    added_count: NonNegativeInt
    removed_count: NonNegativeInt
    modified_count: NonNegativeInt
    profile_changes: tuple[CapabilityProfileChange, ...] = ()
    changes: tuple[CapabilityItemChange, ...] = ()

    @field_validator("agent_id")
    @classmethod
    def agent_id_must_be_stable(cls, value: str) -> str:
        if _STABLE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("Capability Diff agent_id must use stable form")
        return value

    @model_validator(mode="after")
    def diff_must_be_coherent(self) -> CapabilityDiffResult:
        profile_names = tuple(change.profile.value for change in self.profile_changes)
        if profile_names != tuple(sorted(profile_names)) or len(profile_names) != len(
            set(profile_names)
        ):
            raise ValueError("profile changes must be sorted and unique")
        keys = tuple(change.sort_key() for change in self.changes)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("capability changes must be sorted and unique")
        expected = {
            CapabilityChangeType.ADDED: self.added_count,
            CapabilityChangeType.REMOVED: self.removed_count,
            CapabilityChangeType.MODIFIED: self.modified_count,
        }
        for change_type, count in expected.items():
            if (
                sum(change.change_type is change_type for change in self.changes)
                != count
            ):
                raise ValueError("Capability Diff summary counts must match changes")
        if self.complete != (
            self.before_coverage_complete and self.after_coverage_complete
        ):
            raise ValueError("Capability Diff completeness must match both Manifests")
        return self

    @property
    def has_changes(self) -> bool:
        """Return whether any item or profile changed."""

        return bool(self.changes or self.profile_changes)


class CapabilityDiffer:
    """Compare normalized capability collections without source-content access."""

    def compare(
        self,
        *,
        before: AgentManifest,
        after: AgentManifest,
    ) -> CapabilityDiffResult:
        """Return deterministic capability changes for the same Agent subject."""

        if not isinstance(before, AgentManifest) or not isinstance(
            after, AgentManifest
        ):
            raise TypeError("before and after must be AgentManifest")
        self._validate_compatibility(before, after)

        changes: list[CapabilityItemChange] = []
        changes.extend(
            self._compare_items(
                CapabilityDimension.TOOL,
                before.tools.tools,
                after.tools.tools,
                lambda item: item.tool_id,
            )
        )
        changes.extend(
            self._compare_items(
                CapabilityDimension.PERMISSION,
                before.permissions.permissions,
                after.permissions.permissions,
                lambda item: item.permission_id,
            )
        )
        changes.extend(
            self._compare_items(
                CapabilityDimension.CONTROL,
                before.controls.controls,
                after.controls.controls,
                lambda item: item.control_id,
            )
        )
        changes.extend(
            self._compare_items(
                CapabilityDimension.RUNTIME_IDENTITY,
                before.runtime_identities.identities,
                after.runtime_identities.identities,
                lambda item: item.identity_id,
            )
        )
        changes.extend(
            self._compare_items(
                CapabilityDimension.RELATIONSHIP,
                before.relationships.relations,
                after.relationships.relations,
                lambda item: item.relation_id,
            )
        )
        changes.extend(
            self._compare_items(
                CapabilityDimension.UNKNOWN,
                before.unknowns,
                after.unknowns,
                lambda item: item.unknown_id,
            )
        )
        ordered_changes = tuple(sorted(changes, key=lambda change: change.sort_key()))
        profile_changes = self._profile_changes(before, after)
        return CapabilityDiffResult(
            schema_version=CAPABILITY_DIFF_SCHEMA_VERSION,
            agent_manifest_schema_version=AGENT_MANIFEST_SCHEMA_VERSION,
            agent_id=before.identity.agent_id,
            before_coverage_complete=before.coverage.complete,
            after_coverage_complete=after.coverage.complete,
            complete=before.coverage.complete and after.coverage.complete,
            added_count=sum(
                change.change_type is CapabilityChangeType.ADDED
                for change in ordered_changes
            ),
            removed_count=sum(
                change.change_type is CapabilityChangeType.REMOVED
                for change in ordered_changes
            ),
            modified_count=sum(
                change.change_type is CapabilityChangeType.MODIFIED
                for change in ordered_changes
            ),
            profile_changes=profile_changes,
            changes=ordered_changes,
        )

    @staticmethod
    def _validate_compatibility(
        before: AgentManifest,
        after: AgentManifest,
    ) -> None:
        if before.schema_version != after.schema_version:
            raise CapabilityDiffError(
                "Capability Diff requires equal Agent Manifest schema versions."
            )
        if before.schema_version != AGENT_MANIFEST_SCHEMA_VERSION:
            raise CapabilityDiffError(
                "Capability Diff requires the supported Agent Manifest schema."
            )
        if before.identity.agent_id != after.identity.agent_id:
            raise CapabilityDiffError(
                "Capability Diff requires the same Agent identity."
            )
        if before.metadata.framework_id != after.metadata.framework_id:
            raise CapabilityDiffError(
                "Capability Diff requires the same Framework identity."
            )

    @classmethod
    def _compare_items[T: ManifestModel](
        cls,
        dimension: CapabilityDimension,
        before_items: tuple[T, ...],
        after_items: tuple[T, ...],
        identifier: Callable[[T], str],
    ) -> tuple[CapabilityItemChange, ...]:
        before_by_id = cls._index(before_items, identifier, "before")
        after_by_id = cls._index(after_items, identifier, "after")
        changes: list[CapabilityItemChange] = []
        for item_id in sorted(before_by_id.keys() | after_by_id.keys()):
            before_item = before_by_id.get(item_id)
            after_item = after_by_id.get(item_id)
            if before_item is None and after_item is not None:
                changes.append(
                    CapabilityItemChange(
                        dimension=dimension,
                        item_id=item_id,
                        change_type=CapabilityChangeType.ADDED,
                        changed_fields=("item",),
                        after_sha256=cls._fingerprint(after_item),
                        after_sources=cls._sources(after_item),
                    )
                )
                continue
            if before_item is not None and after_item is None:
                changes.append(
                    CapabilityItemChange(
                        dimension=dimension,
                        item_id=item_id,
                        change_type=CapabilityChangeType.REMOVED,
                        changed_fields=("item",),
                        before_sha256=cls._fingerprint(before_item),
                        before_sources=cls._sources(before_item),
                    )
                )
                continue
            if before_item is None or after_item is None:
                raise AssertionError("Capability item union produced invalid state")
            before_hash = cls._fingerprint(before_item)
            after_hash = cls._fingerprint(after_item)
            if before_hash == after_hash:
                continue
            changes.append(
                CapabilityItemChange(
                    dimension=dimension,
                    item_id=item_id,
                    change_type=CapabilityChangeType.MODIFIED,
                    changed_fields=cls._changed_fields(before_item, after_item),
                    before_sha256=before_hash,
                    after_sha256=after_hash,
                    before_sources=cls._sources(before_item),
                    after_sources=cls._sources(after_item),
                )
            )
        return tuple(changes)

    @staticmethod
    def _index[T](
        items: tuple[T, ...],
        identifier: Callable[[T], str],
        side: str,
    ) -> dict[str, T]:
        indexed: dict[str, T] = {}
        for item in items:
            item_id = identifier(item)
            if item_id in indexed:
                raise CapabilityDiffError(
                    f"Capability Diff {side} items contain duplicate identifiers."
                )
            indexed[item_id] = item
        return indexed

    @staticmethod
    def _fingerprint(item: ManifestModel) -> Sha256String:
        payload = item.model_dump(mode="json")
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _changed_fields(
        before: ManifestModel,
        after: ManifestModel,
    ) -> tuple[str, ...]:
        before_payload: dict[str, Any] = before.model_dump(mode="json")
        after_payload: dict[str, Any] = after.model_dump(mode="json")
        fields = tuple(
            sorted(
                field
                for field in before_payload.keys() | after_payload.keys()
                if before_payload.get(field) != after_payload.get(field)
            )
        )
        return fields or ("item",)

    @staticmethod
    def _sources(item: ManifestModel) -> tuple[ManifestSourceReference, ...]:
        sources = getattr(item, "sources", ())
        if not isinstance(sources, tuple) or any(
            not isinstance(source, ManifestSourceReference) for source in sources
        ):
            return ()
        return sources

    @staticmethod
    def _profile_changes(
        before: AgentManifest,
        after: AgentManifest,
    ) -> tuple[CapabilityProfileChange, ...]:
        pairs = {
            CapabilityProfileName.IDENTITY: (
                before.identity.resolution.value,
                after.identity.resolution.value,
            ),
            CapabilityProfileName.INSTRUCTIONS: (
                before.instructions.resolution.value,
                after.instructions.resolution.value,
            ),
            CapabilityProfileName.CONFIGURATION: (
                before.configuration.resolution.value,
                after.configuration.resolution.value,
            ),
            CapabilityProfileName.TOOLS: (
                before.tools.resolution.value,
                after.tools.resolution.value,
            ),
            CapabilityProfileName.PERMISSIONS: (
                before.permissions.resolution.value,
                after.permissions.resolution.value,
            ),
            CapabilityProfileName.CONTROLS: (
                before.controls.resolution.value,
                after.controls.resolution.value,
            ),
            CapabilityProfileName.RUNTIME_IDENTITIES: (
                before.runtime_identities.resolution.value,
                after.runtime_identities.resolution.value,
            ),
            CapabilityProfileName.RELATIONSHIPS: (
                before.relationships.resolution.value,
                after.relationships.resolution.value,
            ),
            CapabilityProfileName.COVERAGE: (
                "complete" if before.coverage.complete else "incomplete",
                "complete" if after.coverage.complete else "incomplete",
            ),
        }
        return tuple(
            CapabilityProfileChange(profile=profile, before=values[0], after=values[1])
            for profile, values in sorted(pairs.items(), key=lambda item: item[0].value)
            if values[0] != values[1]
        )


def encode_capability_diff_json(result: CapabilityDiffResult) -> str:
    """Return deterministic JSON for one validated Capability Diff."""

    if not isinstance(result, CapabilityDiffResult):
        raise TypeError("result must be CapabilityDiffResult")
    return (
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def validate_capability_diff_payload(payload: object) -> CapabilityDiffResult:
    """Validate version compatibility before interpreting Diff fields."""

    if not isinstance(payload, Mapping):
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.INVALID_ROOT,
            "Capability Diff root must be a JSON object",
        )
    schema_version = payload.get("schema_version")
    if schema_version is None:
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.MISSING_SCHEMA_VERSION,
            "Capability Diff requires schema_version",
        )
    if not isinstance(schema_version, str):
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.INVALID_SCHEMA_VERSION,
            "Capability Diff schema_version must be semantic version text",
        )
    try:
        parse_interface_version(schema_version)
    except ValueError as error:
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.INVALID_SCHEMA_VERSION,
            "Capability Diff schema_version must use MAJOR.MINOR.PATCH",
        ) from error
    if not can_read_interface_version(
        produced=schema_version,
        supported=CAPABILITY_DIFF_SCHEMA_VERSION,
    ):
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.UNSUPPORTED_SCHEMA_VERSION,
            "Capability Diff schema version is not supported",
        )
    try:
        return CapabilityDiffResult.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "Capability Diff payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def decode_capability_diff_json(text: str) -> CapabilityDiffResult:
    """Decode already-bounded JSON text through safe validation."""

    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        # ValueError also covers oversized integer literals rejected by the
        # Python 3.11+ int-string conversion limit (not a JSONDecodeError).
        raise CapabilityDiffValidationError(
            CapabilityDiffValidationCode.INVALID_JSON,
            "Capability Diff must contain valid JSON",
        ) from error
    return validate_capability_diff_payload(payload)


_SAFE_FIELD_PART = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _safe_field_paths(error: ValidationError) -> tuple[str, ...]:
    paths: set[str] = set()
    for item in error.errors(include_url=False, include_input=False):
        if not item["loc"]:
            continue
        parts: list[str] = []
        for part in item["loc"]:
            if isinstance(part, int):
                parts.append(str(part))
                continue
            value = str(part)
            parts.append(value if _SAFE_FIELD_PART.fullmatch(value) else "<field>")
        paths.add(".".join(parts))
    return tuple(sorted(paths))


def export_capability_diff_json_schema(output_directory: Path) -> Path:
    """Write the current strict Capability Diff JSON Schema."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "capability-diff.schema.json"
    schema: dict[str, Any] = CapabilityDiffResult.model_json_schema(
        mode="serialization"
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-capability-diff-schema-version"] = CAPABILITY_DIFF_SCHEMA_VERSION
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path

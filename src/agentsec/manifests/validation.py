"""Safe compatibility-first validation for Agent Manifest JSON payloads."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from agentsec.manifests.models import AgentManifest
from agentsec.versioning import (
    AGENT_MANIFEST_SCHEMA_VERSION,
    can_read_interface_version,
    parse_interface_version,
)


class AgentManifestValidationCode(StrEnum):
    """Stable Agent Manifest validation failures."""

    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_SCHEMA_VERSION = "missing_schema_version"
    INVALID_SCHEMA_VERSION = "invalid_schema_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_PAYLOAD = "invalid_payload"


class AgentManifestValidationError(RuntimeError):
    """Safe Manifest validation error that exposes only trusted field paths."""

    def __init__(
        self,
        code: AgentManifestValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


def validate_agent_manifest_payload(payload: object) -> AgentManifest:
    """Validate schema compatibility before interpreting Manifest fields."""

    if not isinstance(payload, Mapping):
        raise AgentManifestValidationError(
            AgentManifestValidationCode.INVALID_ROOT,
            "Agent Manifest root must be a JSON object",
        )

    schema_version = payload.get("schema_version")
    if schema_version is None:
        raise AgentManifestValidationError(
            AgentManifestValidationCode.MISSING_SCHEMA_VERSION,
            "Agent Manifest requires a schema_version field",
        )
    if not isinstance(schema_version, str):
        raise AgentManifestValidationError(
            AgentManifestValidationCode.INVALID_SCHEMA_VERSION,
            "Agent Manifest schema_version must be an exact semantic version",
        )
    try:
        parse_interface_version(schema_version)
    except ValueError as error:
        raise AgentManifestValidationError(
            AgentManifestValidationCode.INVALID_SCHEMA_VERSION,
            "Agent Manifest schema_version must use MAJOR.MINOR.PATCH",
        ) from error

    if not can_read_interface_version(
        produced=schema_version,
        supported=AGENT_MANIFEST_SCHEMA_VERSION,
    ):
        raise AgentManifestValidationError(
            AgentManifestValidationCode.UNSUPPORTED_SCHEMA_VERSION,
            "Agent Manifest schema version is not supported",
        )

    try:
        return AgentManifest.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "Agent Manifest payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise AgentManifestValidationError(
            AgentManifestValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def decode_agent_manifest_json(text: str) -> AgentManifest:
    """Decode already-bounded JSON text and apply safe Manifest validation."""

    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        # ValueError also covers oversized integer literals rejected by the
        # Python 3.11+ int-string conversion limit (not a JSONDecodeError).
        raise AgentManifestValidationError(
            AgentManifestValidationCode.INVALID_JSON,
            "Agent Manifest must contain valid JSON",
        ) from error
    return validate_agent_manifest_payload(payload)


def encode_agent_manifest_json(manifest: AgentManifest) -> str:
    """Return deterministic UTF-8 JSON for a validated Agent Manifest."""

    if not isinstance(manifest, AgentManifest):
        raise TypeError("manifest must be AgentManifest")
    payload = manifest.model_dump(mode="json")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


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

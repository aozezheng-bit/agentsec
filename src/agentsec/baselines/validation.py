"""Safe JSON encoding and compatibility validation for baseline payloads."""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from agentsec.baselines.models import Baseline
from agentsec.versioning import (
    BASELINE_SCHEMA_VERSION,
    can_read_interface_version,
    parse_interface_version,
)


class BaselineValidationCode(StrEnum):
    """Stable failure categories for baseline consumers and future CLI mapping."""

    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_SCHEMA_VERSION = "missing_schema_version"
    INVALID_SCHEMA_VERSION = "invalid_schema_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_PAYLOAD = "invalid_payload"


class BaselineValidationError(RuntimeError):
    """A structured baseline failure that never copies untrusted field values."""

    def __init__(
        self,
        code: BaselineValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


def validate_baseline_payload(payload: object) -> Baseline:
    """Validate compatibility before interpreting the remaining payload."""

    if not isinstance(payload, Mapping):
        raise BaselineValidationError(
            BaselineValidationCode.INVALID_ROOT,
            "baseline root must be a JSON object",
        )

    schema_version = payload.get("schema_version")
    if schema_version is None:
        raise BaselineValidationError(
            BaselineValidationCode.MISSING_SCHEMA_VERSION,
            "baseline requires a schema_version field",
        )
    if not isinstance(schema_version, str):
        raise BaselineValidationError(
            BaselineValidationCode.INVALID_SCHEMA_VERSION,
            "baseline schema_version must be an exact semantic version",
        )

    try:
        parse_interface_version(schema_version)
    except ValueError as error:
        raise BaselineValidationError(
            BaselineValidationCode.INVALID_SCHEMA_VERSION,
            "baseline schema_version must use MAJOR.MINOR.PATCH",
        ) from error

    if not can_read_interface_version(
        produced=schema_version,
        supported=BASELINE_SCHEMA_VERSION,
    ):
        raise BaselineValidationError(
            BaselineValidationCode.UNSUPPORTED_SCHEMA_VERSION,
            "baseline schema version is not supported by this AgentSec version",
        )

    try:
        return Baseline.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "baseline payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise BaselineValidationError(
            BaselineValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def decode_baseline_json(text: str) -> Baseline:
    """Decode already-bounded JSON text and apply safe baseline validation."""

    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        # ValueError also covers oversized integer literals rejected by the
        # Python 3.11+ int-string conversion limit (not a JSONDecodeError).
        raise BaselineValidationError(
            BaselineValidationCode.INVALID_JSON,
            "baseline must contain valid JSON",
        ) from error
    return validate_baseline_payload(payload)


def encode_baseline_json(baseline: Baseline) -> str:
    """Return deterministic UTF-8 JSON text for a validated baseline."""

    payload = baseline.model_dump(mode="json")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _safe_field_paths(error: ValidationError) -> tuple[str, ...]:
    """Extract only schema locations, never rejected values or content."""

    paths = {
        ".".join(str(part) for part in item["loc"])
        for item in error.errors(include_url=False, include_input=False)
        if item["loc"]
    }
    return tuple(sorted(paths))

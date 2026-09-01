"""Safe JSON validation and Schema export for Capability Change Impact."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentsec.versioning import (
    CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION,
    can_read_interface_version,
    parse_interface_version,
)

from .models import (
    CAPABILITY_CHANGE_IMPACT_FORMAT,
    CAPABILITY_CHANGE_IMPACT_SCHEMA_FILENAME,
    CapabilityChangeImpactReport,
)


class CapabilityChangeImpactValidationCode(StrEnum):
    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_FORMAT = "missing_format"
    INVALID_FORMAT = "invalid_format"
    MISSING_FORMAT_VERSION = "missing_format_version"
    INVALID_FORMAT_VERSION = "invalid_format_version"
    UNSUPPORTED_FORMAT_VERSION = "unsupported_format_version"
    INVALID_PAYLOAD = "invalid_payload"


class CapabilityChangeImpactValidationError(RuntimeError):
    """Safe validation failure that never copies rejected values."""

    def __init__(
        self,
        code: CapabilityChangeImpactValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


def encode_capability_change_impact_json(
    report: CapabilityChangeImpactReport,
) -> str:
    if not isinstance(report, CapabilityChangeImpactReport):
        raise TypeError("report must be CapabilityChangeImpactReport")
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def validate_capability_change_impact_payload(
    payload: object,
) -> CapabilityChangeImpactReport:
    if not isinstance(payload, Mapping):
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_ROOT,
            "Capability Change Impact root must be a JSON object",
        )
    report_format = payload.get("format")
    if report_format is None:
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.MISSING_FORMAT,
            "Capability Change Impact requires format",
        )
    if report_format != CAPABILITY_CHANGE_IMPACT_FORMAT:
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_FORMAT,
            "Capability Change Impact format is not supported",
        )
    version = payload.get("format_version")
    if version is None:
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.MISSING_FORMAT_VERSION,
            "Capability Change Impact requires format_version",
        )
    if not isinstance(version, str):
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_FORMAT_VERSION,
            "Capability Change Impact format_version must be semantic version text",
        )
    try:
        parse_interface_version(version)
    except ValueError as error:
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_FORMAT_VERSION,
            "Capability Change Impact format_version must use MAJOR.MINOR.PATCH",
        ) from error
    if not can_read_interface_version(
        produced=version,
        supported=CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION,
    ):
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.UNSUPPORTED_FORMAT_VERSION,
            "Capability Change Impact format version is not supported",
        )
    try:
        return CapabilityChangeImpactReport.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "Capability Change Impact payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def decode_capability_change_impact_json(text: str) -> CapabilityChangeImpactReport:
    try:
        payload: Any = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise CapabilityChangeImpactValidationError(
            CapabilityChangeImpactValidationCode.INVALID_JSON,
            "Capability Change Impact must contain valid JSON",
        ) from error
    return validate_capability_change_impact_payload(payload)


def export_capability_change_impact_json_schema(output_directory: Path) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / CAPABILITY_CHANGE_IMPACT_SCHEMA_FILENAME
    schema: dict[str, Any] = CapabilityChangeImpactReport.model_json_schema(
        mode="serialization"
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-capability-change-impact-output-version"] = (
        CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


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

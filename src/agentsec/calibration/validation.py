"""Safe JSON codecs and validation for P2-CAL-01 calibration contracts."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from agentsec.versioning import (
    CALIBRATION_CASE_SCHEMA_VERSION,
    can_read_interface_version,
    parse_interface_version,
)

from .models import (
    CALIBRATION_CASE_FORMAT,
    CALIBRATION_CORPUS_FORMAT,
    CalibrationCase,
    CalibrationCorpusIndex,
)


class CalibrationValidationCode(StrEnum):
    """Stable safe validation failures for calibration JSON."""

    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    MISSING_FORMAT = "missing_format"
    INVALID_FORMAT = "invalid_format"
    MISSING_SCHEMA_VERSION = "missing_schema_version"
    INVALID_SCHEMA_VERSION = "invalid_schema_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_PAYLOAD = "invalid_payload"


class CalibrationValidationError(RuntimeError):
    """Safe error that never copies rejected fixture values."""

    def __init__(
        self,
        code: CalibrationValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


def encode_calibration_case_json(case: CalibrationCase) -> str:
    if not isinstance(case, CalibrationCase):
        raise TypeError("case must be CalibrationCase")
    return (
        json.dumps(
            case.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def encode_calibration_corpus_json(index: CalibrationCorpusIndex) -> str:
    if not isinstance(index, CalibrationCorpusIndex):
        raise TypeError("index must be CalibrationCorpusIndex")
    return (
        json.dumps(
            index.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def validate_calibration_case_payload(payload: object) -> CalibrationCase:
    return _validate_payload(
        payload,
        expected_format=CALIBRATION_CASE_FORMAT,
        model=CalibrationCase,
    )


def validate_calibration_corpus_payload(payload: object) -> CalibrationCorpusIndex:
    return _validate_payload(
        payload,
        expected_format=CALIBRATION_CORPUS_FORMAT,
        model=CalibrationCorpusIndex,
    )


def decode_calibration_case_json(text: str) -> CalibrationCase:
    return _decode(text, validate_calibration_case_payload, "Calibration Case")


def decode_calibration_corpus_json(text: str) -> CalibrationCorpusIndex:
    return _decode(text, validate_calibration_corpus_payload, "Calibration Corpus")


def export_calibration_case_json_schema(output_directory: Path) -> Path:
    return _export_schema(
        output_directory,
        "calibration-case.schema.json",
        CalibrationCase,
        "x-agentsec-calibration-case-schema-version",
    )


def export_calibration_corpus_json_schema(output_directory: Path) -> Path:
    return _export_schema(
        output_directory,
        "calibration-corpus.schema.json",
        CalibrationCorpusIndex,
        "x-agentsec-calibration-case-schema-version",
    )


def _validate_payload[ModelT: BaseModel](
    payload: object,
    *,
    expected_format: str,
    model: type[ModelT],
) -> ModelT:
    if not isinstance(payload, Mapping):
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_ROOT,
            "Calibration payload root must be a JSON object",
        )
    if payload.get("format") != expected_format:
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_FORMAT,
            "Calibration payload format is not supported",
        )
    version = payload.get("schema_version")
    if version is None:
        raise CalibrationValidationError(
            CalibrationValidationCode.MISSING_SCHEMA_VERSION,
            "Calibration payload requires schema_version",
        )
    if not isinstance(version, str):
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_SCHEMA_VERSION,
            "Calibration schema_version must be semantic version text",
        )
    try:
        parse_interface_version(version)
    except ValueError as error:
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_SCHEMA_VERSION,
            "Calibration schema_version must use MAJOR.MINOR.PATCH",
        ) from error
    if not can_read_interface_version(
        produced=version,
        supported=CALIBRATION_CASE_SCHEMA_VERSION,
    ):
        raise CalibrationValidationError(
            CalibrationValidationCode.UNSUPPORTED_SCHEMA_VERSION,
            "Calibration schema version is not supported",
        )
    try:
        return model.model_validate(dict(payload))
    except ValidationError as error:
        field_paths = _safe_field_paths(error)
        message = "Calibration payload failed schema validation"
        if field_paths:
            message += "; invalid fields: " + ", ".join(field_paths)
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_PAYLOAD,
            message,
            field_paths=field_paths,
        ) from error


def _decode[ModelT](
    text: str,
    validator: Callable[[object], ModelT],
    label: str,
) -> ModelT:
    try:
        payload: object = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise CalibrationValidationError(
            CalibrationValidationCode.INVALID_JSON,
            f"{label} must contain valid JSON",
        ) from error
    return validator(payload)


def _export_schema[ModelT: BaseModel](
    output_directory: Path,
    filename: str,
    model: type[ModelT],
    extension_key: str,
) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / filename
    schema: dict[str, Any] = model.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema[extension_key] = CALIBRATION_CASE_SCHEMA_VERSION
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

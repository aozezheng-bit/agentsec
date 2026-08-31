"""Safe JSON codecs and Schema exports for P2-CAL-03."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from agentsec.versioning import (
    CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION,
    CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION,
    can_read_interface_version,
    parse_interface_version,
)

from .confidence_models import (
    CONFIDENCE_REPORT_FORMAT,
    CONFIDENCE_REPORT_SCHEMA_FILENAME,
    CONFIDENCE_REVIEW_FORMAT,
    CONFIDENCE_REVIEW_SCHEMA_FILENAME,
    ConfidenceCalibrationReport,
    ConfidenceReviewSet,
)


class ConfidenceValidationCode(StrEnum):
    INVALID_JSON = "invalid_json"
    INVALID_ROOT = "invalid_root"
    INVALID_FORMAT = "invalid_format"
    INVALID_SCHEMA_VERSION = "invalid_schema_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_PAYLOAD = "invalid_payload"


class ConfidenceValidationError(RuntimeError):
    def __init__(
        self,
        code: ConfidenceValidationCode,
        message: str,
        *,
        field_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(message)


def encode_confidence_review_set_json(review_set: ConfidenceReviewSet) -> str:
    return _encode(review_set)


def encode_confidence_calibration_report_json(
    report: ConfidenceCalibrationReport,
) -> str:
    return _encode(report)


def decode_confidence_review_set_json(text: str) -> ConfidenceReviewSet:
    return _decode(text, CONFIDENCE_REVIEW_FORMAT, ConfidenceReviewSet)


def decode_confidence_calibration_report_json(
    text: str,
) -> ConfidenceCalibrationReport:
    return _decode(text, CONFIDENCE_REPORT_FORMAT, ConfidenceCalibrationReport)


def export_confidence_review_set_json_schema(output_directory: Path) -> Path:
    return _export_schema(
        output_directory,
        CONFIDENCE_REVIEW_SCHEMA_FILENAME,
        ConfidenceReviewSet,
        CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION,
        "x-agentsec-confidence-review-schema-version",
    )


def export_confidence_calibration_report_json_schema(output_directory: Path) -> Path:
    return _export_schema(
        output_directory,
        CONFIDENCE_REPORT_SCHEMA_FILENAME,
        ConfidenceCalibrationReport,
        CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION,
        "x-agentsec-confidence-report-output-version",
    )


def _encode(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


def _decode[T: BaseModel](text: str, expected_format: str, model: type[T]) -> T:
    try:
        payload: object = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_JSON,
            "Confidence calibration JSON is invalid",
        ) from error
    if not isinstance(payload, Mapping):
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_ROOT,
            "Confidence calibration root must be an object",
        )
    if payload.get("format") != expected_format:
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_FORMAT,
            "Confidence calibration format is unsupported",
        )
    version = payload.get("schema_version", payload.get("format_version"))
    if not isinstance(version, str):
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_SCHEMA_VERSION,
            "Confidence calibration version is invalid",
        )
    try:
        parse_interface_version(version)
    except ValueError as error:
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_SCHEMA_VERSION,
            "Confidence calibration version must use MAJOR.MINOR.PATCH",
        ) from error
    supported = (
        CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION
        if expected_format == CONFIDENCE_REVIEW_FORMAT
        else CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION
    )
    if not can_read_interface_version(produced=version, supported=supported):
        raise ConfidenceValidationError(
            ConfidenceValidationCode.UNSUPPORTED_SCHEMA_VERSION,
            "Confidence calibration version is unsupported",
        )
    try:
        return model.model_validate(dict(payload))
    except ValidationError as error:
        paths = _safe_paths(error)
        raise ConfidenceValidationError(
            ConfidenceValidationCode.INVALID_PAYLOAD,
            "Confidence calibration payload failed validation"
            + ("; invalid fields: " + ", ".join(paths) if paths else ""),
            field_paths=paths,
        ) from error


def _export_schema[T: BaseModel](
    output_directory: Path,
    filename: str,
    model: type[T],
    version: str,
    extension_key: str,
) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    path = output_directory / filename
    schema: dict[str, Any] = model.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema[extension_key] = version
    path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


_SAFE_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _safe_paths(error: ValidationError) -> tuple[str, ...]:
    paths: set[str] = set()
    for item in error.errors(include_url=False, include_input=False):
        parts = []
        for part in item["loc"]:
            if isinstance(part, int):
                parts.append(str(part))
            else:
                text = str(part)
                parts.append(text if _SAFE_FIELD.fullmatch(text) else "<field>")
        if parts:
            paths.add(".".join(parts))
    return tuple(sorted(paths))

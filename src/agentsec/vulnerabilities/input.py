"""Bounded vulnerability-input JSON and deterministic Finding association."""

from __future__ import annotations

import errno
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import Assessment, VulnerabilityReference
from agentsec.risk import CvssAdapterError, CvssBaseAdapter, CvssBaseInput

VULNERABILITY_INPUT_FORMAT: Final = "agentsec-vulnerability-input"
VULNERABILITY_INPUT_VERSION: Final = "0.1.0"
MAX_VULNERABILITY_INPUT_SIZE_BYTES: Final = 4_194_304
_READ_CHUNK_SIZE: Final = 65_536
_FINDING_ID: Final = r"^finding-sha256:[a-f0-9]{64}$"

# JSON values are intentionally bounded by the file-size limit and validated
# again by CvssBaseInput before they can influence a Finding.
type InputJsonValue = (
    None | bool | int | float | str | list[InputJsonValue] | dict[str, InputJsonValue]
)


class VulnerabilityInputCode(StrEnum):
    """Stable safe failures for vulnerability-input reading and association."""

    MISSING = "missing"
    INVALID_PATH = "invalid_path"
    SYMBOLIC_LINK = "symbolic_link"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    INVALID_SCHEMA = "invalid_schema"
    DUPLICATE_FINDING = "duplicate_finding"
    UNKNOWN_FINDING = "unknown_finding"
    INVALID_CVSS = "invalid_cvss"
    ASSOCIATION_FAILED = "association_failed"


class VulnerabilityInputError(RuntimeError):
    """Safe input/association failure that never copies payload values."""

    def __init__(self, code: VulnerabilityInputCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class _InputModel(BaseModel):
    """Strict immutable input model boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CvssInputPayload(_InputModel):
    """Schema-visible CVSS payload delegated to the full CVSS adapter."""

    vector: str
    version: str | None = None
    base_score: float | int | None = None
    base_severity: str | None = None
    score: float | int | None = None
    severity: str | None = None


class VulnerabilityInputRecord(_InputModel):
    """One explicit Finding-to-vulnerability/CVSS association record."""

    finding_id: Annotated[str, Field(pattern=_FINDING_ID)]
    vulnerability: VulnerabilityReference | None = None
    cvss: CvssInputPayload | None = None

    @field_validator("cvss")
    @classmethod
    def cvss_payload_must_be_valid_input(
        cls, value: CvssInputPayload | None
    ) -> CvssInputPayload | None:
        """Run the strict CVSS input shape check before scan association."""

        if value is not None:
            try:
                CvssBaseInput.from_mapping(value.model_dump(exclude_none=True))
            except CvssAdapterError as error:
                raise ValueError(
                    "vulnerability-input CVSS payload is invalid"
                ) from error
        return value

    @model_validator(mode="after")
    def record_must_have_security_data(self) -> VulnerabilityInputRecord:
        """Reject records that cannot enrich a Finding."""

        if self.vulnerability is None and self.cvss is None:
            raise ValueError("vulnerability-input record has no vulnerability or CVSS")
        if (
            self.vulnerability is not None
            and self.vulnerability.association_method != "explicit"
        ):
            raise ValueError(
                "vulnerability-input only accepts explicit vulnerability associations"
            )
        return self


class VulnerabilityInputDocument(_InputModel):
    """Versioned, strict vulnerability-input document."""

    format: Literal["agentsec-vulnerability-input"]
    format_version: Literal["0.1.0"]
    records: Annotated[tuple[VulnerabilityInputRecord, ...], Field(min_length=1)]

    @field_validator("format")
    @classmethod
    def format_must_match(cls, value: str) -> str:
        if value != VULNERABILITY_INPUT_FORMAT:
            raise ValueError("vulnerability-input format is unsupported")
        return value

    @field_validator("format_version")
    @classmethod
    def version_must_match(cls, value: str) -> str:
        if value != VULNERABILITY_INPUT_VERSION:
            raise ValueError("vulnerability-input version is unsupported")
        return value

    @model_validator(mode="after")
    def finding_ids_must_be_unique(self) -> VulnerabilityInputDocument:
        finding_ids = tuple(item.finding_id for item in self.records)
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("vulnerability-input finding IDs must be unique")
        return self


VULNERABILITY_INPUT_SCHEMA_FILENAME: Final = "vulnerability-input.schema.json"


def export_vulnerability_input_json_schema(output_directory: Path) -> Path:
    """Export the strict vulnerability-input JSON Schema."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / VULNERABILITY_INPUT_SCHEMA_FILENAME
    output_path.write_text(
        json.dumps(
            VulnerabilityInputDocument.model_json_schema(mode="serialization"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


@dataclass(frozen=True, slots=True)
class VulnerabilityInputReadResult:
    """Validated vulnerability input plus safe local file metadata."""

    document: VulnerabilityInputDocument
    path: Path
    size_bytes: int


class VulnerabilityInputFileReader:
    """Read one bounded UTF-8 JSON vulnerability-input file without following links."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_VULNERABILITY_INPUT_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("vulnerability-input file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def read(self, path: Path) -> VulnerabilityInputReadResult:
        """Read and validate an input file while keeping payload details private."""

        if not isinstance(path, Path):
            raise TypeError("vulnerability-input path must be a Path")
        if path.suffix.lower() != ".json":
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_PATH,
                "vulnerability-input must use a .json filename",
            )
        if path.is_symlink():
            raise VulnerabilityInputError(
                VulnerabilityInputCode.SYMBOLIC_LINK,
                "vulnerability-input must not be a symbolic link",
            )

        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise VulnerabilityInputError(
                    VulnerabilityInputCode.INVALID_PATH,
                    "vulnerability-input must be a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise VulnerabilityInputError(
                    VulnerabilityInputCode.TOO_LARGE,
                    "vulnerability-input exceeds the hard file-size limit",
                )
            content = self._read_bounded(descriptor)
        except FileNotFoundError as error:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.MISSING,
                "vulnerability-input does not exist",
            ) from error
        except VulnerabilityInputError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise VulnerabilityInputError(
                    VulnerabilityInputCode.SYMBOLIC_LINK,
                    "vulnerability-input must not be a symbolic link",
                ) from error
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_PATH,
                "vulnerability-input could not be read safely",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_UTF8,
                "vulnerability-input must be valid UTF-8",
            ) from error
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as error:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_JSON,
                "vulnerability-input is not valid JSON",
            ) from error
        if not isinstance(payload, Mapping):
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_SCHEMA,
                "vulnerability-input must contain one JSON object",
            )
        try:
            document = VulnerabilityInputDocument.model_validate(payload)
        except Exception as error:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_SCHEMA,
                "vulnerability-input failed schema validation",
            ) from error
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.INVALID_PATH,
                "vulnerability-input path could not be resolved safely",
            ) from error
        return VulnerabilityInputReadResult(
            document=document,
            path=resolved,
            size_bytes=len(content),
        )

    def _read_bounded(self, descriptor: int) -> bytes:
        remaining = self._max_file_size_bytes + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(_READ_CHUNK_SIZE, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > self._max_file_size_bytes:
            raise VulnerabilityInputError(
                VulnerabilityInputCode.TOO_LARGE,
                "vulnerability-input exceeds the hard file-size limit",
            )
        return content


class VulnerabilityInputAssociator:
    """Apply explicit vulnerability/CVSS records to an Assessment."""

    def __init__(self, *, cvss_adapter: CvssBaseAdapter | None = None) -> None:
        self._cvss_adapter = cvss_adapter or CvssBaseAdapter()

    def apply(
        self,
        assessment: Assessment,
        document: VulnerabilityInputDocument,
    ) -> Assessment:
        """Return an enriched Assessment without changing coverage or AgentSec risk."""

        if not isinstance(assessment, Assessment):
            raise TypeError("vulnerability association requires an Assessment")
        if not isinstance(document, VulnerabilityInputDocument):
            raise TypeError(
                "vulnerability association requires a vulnerability document"
            )

        findings = {finding.finding_id: finding for finding in assessment.findings}
        for record in document.records:
            finding = findings.get(record.finding_id)
            if finding is None:
                raise VulnerabilityInputError(
                    VulnerabilityInputCode.UNKNOWN_FINDING,
                    "vulnerability-input references an unknown Finding",
                )
            try:
                if record.vulnerability is not None:
                    finding = finding.attach_vulnerability(record.vulnerability)
                if record.cvss is not None:
                    cvss = self._cvss_adapter.adapt(
                        record.cvss.model_dump(exclude_none=True)
                    )
                    finding = cvss.attach_to_finding(finding)
            except (CvssAdapterError, TypeError, ValueError) as error:
                raise VulnerabilityInputError(
                    VulnerabilityInputCode.INVALID_CVSS,
                    "vulnerability-input CVSS association failed validation",
                ) from error
            findings[record.finding_id] = finding

        enriched = tuple(
            findings[finding.finding_id] for finding in assessment.findings
        )
        return assessment.model_copy(update={"findings": enriched})

"""Bounded, non-executing readers for Attack Path association inputs."""

from __future__ import annotations

import errno
import json
import os
import stat
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, TypeVar

from pydantic import BaseModel, ValidationError

from agentsec.attack_graph import (
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationReport,
    CapabilityAttackGraph,
)
from agentsec.domain import Finding
from agentsec.semantic.models import SemanticAnalysisResult, SemanticEvidenceChunk

MAX_ASSOCIATION_INPUT_SIZE_BYTES: Final[int] = 67_108_864
_READ_CHUNK_SIZE: Final[int] = 65_536
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class AssociationInputReadCode(StrEnum):
    """Safe failure categories for association input files."""

    MISSING = "missing"
    INVALID_PATH = "invalid_path"
    SYMBOLIC_LINK = "symbolic_link"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    INVALID_SCHEMA = "invalid_schema"
    READ_FAILED = "read_failed"


class AssociationInputReadError(RuntimeError):
    """Input failure that does not expose untrusted file content."""

    def __init__(self, code: AssociationInputReadCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class AttackPathAssociationInputReader:
    """Read only bounded regular JSON files and validate trusted contracts."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_ASSOCIATION_INPUT_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("association input file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def read_graph(self, path: Path) -> CapabilityAttackGraph:
        """Read one validated Capability Attack Graph."""

        return self._read_model(path, CapabilityAttackGraph)

    def read_association_report(
        self, path: Path
    ) -> AttackPathEvidenceAssociationReport:
        """Read one validated Attack Path Evidence Association report."""

        return self._read_model(path, AttackPathEvidenceAssociationReport)

    def read_calibration_report(
        self, path: Path
    ) -> AttackPathEvidenceCalibrationReport:
        """Read one validated Attack Path Evidence Calibration report."""

        return self._read_model(path, AttackPathEvidenceCalibrationReport)

    def read_findings(self, path: Path) -> tuple[Finding, ...]:
        """Read a JSON array of Findings or an assessment object with ``findings``."""

        payload = self._read_json(path)
        rows = payload.get("findings") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_SCHEMA,
                "Finding input must be a JSON array or an object with findings",
            )
        try:
            findings = tuple(Finding.model_validate(item) for item in rows)
        except ValidationError as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_SCHEMA,
                "Finding input failed schema validation",
            ) from error
        return findings

    def read_semantic_result(self, path: Path) -> SemanticAnalysisResult:
        """Read one validated Shadow-only Semantic Analysis Result."""

        return self._read_model(path, SemanticAnalysisResult)

    def read_semantic_evidence(self, path: Path) -> tuple[SemanticEvidenceChunk, ...]:
        """Read Semantic Evidence chunks from an array or an input-envelope object."""

        payload = self._read_json(path)
        rows = payload.get("evidence") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_SCHEMA,
                (
                    "Semantic Evidence input must be a JSON array or an object "
                    "with evidence"
                ),
            )
        try:
            chunks = tuple(SemanticEvidenceChunk.model_validate(item) for item in rows)
        except ValidationError as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_SCHEMA,
                "Semantic Evidence input failed schema validation",
            ) from error
        return chunks

    def _read_model(self, path: Path, model: type[_ModelT]) -> _ModelT:
        payload = self._read_json(path)
        try:
            return model.model_validate(payload)
        except ValidationError as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_SCHEMA,
                "association input failed schema validation",
            ) from error

    def _read_json(self, path: Path) -> Any:
        content = self._read_bytes(path)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_UTF8,
                "association input must be valid UTF-8",
            ) from error
        try:
            return json.loads(text, parse_constant=_reject_json_constant)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_JSON,
                "association input must be valid JSON",
            ) from error

    def _read_bytes(self, path: Path) -> bytes:
        if not isinstance(path, Path):
            raise TypeError("association input path must be a Path")
        if path.suffix.lower() != ".json":
            raise AssociationInputReadError(
                AssociationInputReadCode.INVALID_PATH,
                "association input must use a .json filename",
            )
        if path.is_symlink():
            raise AssociationInputReadError(
                AssociationInputReadCode.SYMBOLIC_LINK,
                "association input must not be a symbolic link",
            )

        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AssociationInputReadError(
                    AssociationInputReadCode.INVALID_PATH,
                    "association input must be a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise AssociationInputReadError(
                    AssociationInputReadCode.TOO_LARGE,
                    "association input exceeds the hard file-size limit",
                )
            return self._read_bounded(descriptor)
        except FileNotFoundError as error:
            raise AssociationInputReadError(
                AssociationInputReadCode.MISSING,
                "association input does not exist",
            ) from error
        except AssociationInputReadError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise AssociationInputReadError(
                    AssociationInputReadCode.SYMBOLIC_LINK,
                    "association input must not be a symbolic link",
                ) from error
            raise AssociationInputReadError(
                AssociationInputReadCode.READ_FAILED,
                "association input could not be read safely",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

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
            raise AssociationInputReadError(
                AssociationInputReadCode.TOO_LARGE,
                "association input exceeds the hard file-size limit",
            )
        return content


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


__all__ = [
    "MAX_ASSOCIATION_INPUT_SIZE_BYTES",
    "AssociationInputReadCode",
    "AssociationInputReadError",
    "AttackPathAssociationInputReader",
]

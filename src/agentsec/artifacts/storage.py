"""Bounded readers and restricted atomic writers for AgentSec report artifacts."""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from agentsec.change_impact import (
    CapabilityChangeImpactValidationError,
    decode_capability_change_impact_json,
)
from agentsec.manifests import (
    AgentManifest,
    AgentManifestValidationError,
    CapabilityDiffValidationError,
    decode_agent_manifest_json,
    decode_capability_diff_json,
)
from agentsec.reporting import (
    AgenticAssessmentValidationError,
    CapabilityAssessmentValidationError,
    decode_agentic_assessment_json,
    decode_capability_assessment_json,
    decode_sarif_json,
)
from agentsec.semantic import SemanticEvaluationReport, SemanticShadowPipelineReport

MAX_REPORT_ARTIFACT_SIZE_BYTES: Final[int] = 67_108_864
_READ_CHUNK_SIZE: Final[int] = 65_536


class ReportArtifactKind(StrEnum):
    """Report identities used to validate creation and safe replacement."""

    AGENT_MANIFEST = "agent_manifest"
    CAPABILITY_ASSESSMENT = "capability_assessment"
    CAPABILITY_DIFF = "capability_diff"
    CAPABILITY_CHANGE_IMPACT = "capability_change_impact"
    CAPABILITY_CI_ENFORCEMENT = "capability_ci_enforcement"
    AGENTIC_ASSESSMENT = "agentic_assessment"
    SEMANTIC_EVALUATION = "semantic_evaluation"
    SEMANTIC_SHADOW_PIPELINE = "semantic_shadow_pipeline"


class ReportArtifactFormat(StrEnum):
    """File formats supported by safe AgentSec artifact output."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


class AgentManifestReadCode(StrEnum):
    """Stable safe filesystem and validation failures for Manifest input."""

    MISSING = "missing"
    INVALID_PATH = "invalid_path"
    SYMBOLIC_LINK = "symbolic_link"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_MANIFEST = "invalid_manifest"
    READ_FAILED = "read_failed"


class AgentManifestReadError(RuntimeError):
    """Safe Manifest input failure that never includes captured JSON content."""

    def __init__(self, code: AgentManifestReadCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AgentManifestReadResult:
    """A validated Manifest plus safe local filesystem provenance."""

    manifest: AgentManifest
    path: Path
    size_bytes: int


class AgentManifestFileReader:
    """Read one regular non-symlink Manifest with a hard byte bound."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_REPORT_ARTIFACT_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("Manifest file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def read(self, path: Path) -> AgentManifestReadResult:
        """Read bounded UTF-8 JSON and validate compatibility before payload use."""

        if not isinstance(path, Path):
            raise TypeError("Manifest input path must be a Path")
        if path.suffix.lower() != ".json":
            raise AgentManifestReadError(
                AgentManifestReadCode.INVALID_PATH,
                "Agent Manifest input must use a .json filename",
            )
        if path.is_symlink():
            raise AgentManifestReadError(
                AgentManifestReadCode.SYMBOLIC_LINK,
                "Agent Manifest input must not be a symbolic link",
            )

        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AgentManifestReadError(
                    AgentManifestReadCode.INVALID_PATH,
                    "Agent Manifest input must be a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise AgentManifestReadError(
                    AgentManifestReadCode.TOO_LARGE,
                    "Agent Manifest input exceeds the hard file-size limit",
                )
            content = self._read_bounded(descriptor)
        except FileNotFoundError as error:
            raise AgentManifestReadError(
                AgentManifestReadCode.MISSING,
                "Agent Manifest input does not exist",
            ) from error
        except AgentManifestReadError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise AgentManifestReadError(
                    AgentManifestReadCode.SYMBOLIC_LINK,
                    "Agent Manifest input must not be a symbolic link",
                ) from error
            raise AgentManifestReadError(
                AgentManifestReadCode.READ_FAILED,
                "Agent Manifest input could not be read safely",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AgentManifestReadError(
                AgentManifestReadCode.INVALID_UTF8,
                "Agent Manifest input must be valid UTF-8",
            ) from error
        try:
            manifest = decode_agent_manifest_json(text)
        except AgentManifestValidationError as error:
            raise AgentManifestReadError(
                AgentManifestReadCode.INVALID_MANIFEST,
                "Agent Manifest input failed schema or compatibility validation",
            ) from error
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise AgentManifestReadError(
                AgentManifestReadCode.READ_FAILED,
                "Agent Manifest input path could not be resolved safely",
            ) from error
        return AgentManifestReadResult(
            manifest=manifest,
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
            raise AgentManifestReadError(
                AgentManifestReadCode.TOO_LARGE,
                "Agent Manifest input exceeds the hard file-size limit",
            )
        return content


class ReportArtifactWriteCode(StrEnum):
    """Stable safe output failures for Manifest and Capability reports."""

    INVALID_CONTENT = "invalid_content"
    INVALID_OUTPUT_PATH = "invalid_output_path"
    PROTECTED_OUTPUT_PATH = "protected_output_path"
    OUTPUT_EXISTS = "output_exists"
    EXISTING_OUTPUT_INVALID = "existing_output_invalid"
    OUTPUT_TOO_LARGE = "output_too_large"
    WRITE_FAILED = "write_failed"


class ReportArtifactWriteError(RuntimeError):
    """Safe report-output failure that never includes artifact content."""

    def __init__(self, code: ReportArtifactWriteCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ReportArtifactWriteResult:
    """Successful report output metadata safe for terminal or test use."""

    path: Path
    size_bytes: int
    replaced: bool


class ReportArtifactWriter:
    """Atomically write one validated Text, JSON, or supported SARIF report."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_REPORT_ARTIFACT_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("report artifact file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def write(
        self,
        content: str,
        output_path: Path,
        *,
        kind: ReportArtifactKind,
        output_format: ReportArtifactFormat,
        force: bool = False,
        protected_paths: tuple[Path, ...] = (),
    ) -> ReportArtifactWriteResult:
        """Validate and persist report output with no-follow replacement rules."""

        if not isinstance(content, str):
            raise TypeError("report artifact content must be text")
        if not isinstance(output_path, Path):
            raise TypeError("report artifact output path must be a Path")
        if not isinstance(kind, ReportArtifactKind):
            raise TypeError("report artifact kind is invalid")
        if not isinstance(output_format, ReportArtifactFormat):
            raise TypeError("report artifact format is invalid")
        if not isinstance(protected_paths, tuple) or any(
            not isinstance(path, Path) for path in protected_paths
        ):
            raise TypeError("protected report paths must be a tuple of Paths")

        self._validate_content(content, kind=kind, output_format=output_format)
        encoded = content.encode("utf-8")
        if len(encoded) > self._max_file_size_bytes:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.OUTPUT_TOO_LARGE,
                "encoded report exceeds the configured hard output limit",
            )
        target = self._prepare_target(output_path, output_format=output_format)
        self._reject_protected_target(target, protected_paths)
        replaced = self._validate_existing_target(
            target,
            kind=kind,
            output_format=output_format,
            force=force,
        )
        self._write_atomic(target, encoded, replace=replaced)
        return ReportArtifactWriteResult(
            path=target,
            size_bytes=len(encoded),
            replaced=replaced,
        )

    @staticmethod
    def _validate_content(
        content: str,
        *,
        kind: ReportArtifactKind,
        output_format: ReportArtifactFormat,
    ) -> None:
        try:
            if output_format is ReportArtifactFormat.SARIF:
                sarif_report_kinds = {
                    ReportArtifactKind.CAPABILITY_ASSESSMENT: "capability_assessment",
                    ReportArtifactKind.AGENTIC_ASSESSMENT: "agentic_assessment",
                }
                if kind not in sarif_report_kinds:
                    raise ValueError
                report = decode_sarif_json(content)
                if (
                    report.runs[0].properties.get("agentsecReportKind")
                    != (sarif_report_kinds[kind])
                ):
                    raise ValueError
                return
            if output_format is ReportArtifactFormat.JSON:
                if kind is ReportArtifactKind.AGENT_MANIFEST:
                    decode_agent_manifest_json(content)
                elif kind is ReportArtifactKind.CAPABILITY_ASSESSMENT:
                    decode_capability_assessment_json(content)
                elif kind is ReportArtifactKind.CAPABILITY_CHANGE_IMPACT:
                    decode_capability_change_impact_json(content)
                elif kind is ReportArtifactKind.AGENTIC_ASSESSMENT:
                    decode_agentic_assessment_json(content)
                elif kind is ReportArtifactKind.CAPABILITY_CI_ENFORCEMENT:
                    import json

                    from agentsec.policy.ci_enforcement import REPORT_SCHEMA_VERSION

                    payload = json.loads(content)
                    if (
                        payload.get("format") != "agentsec-capability-ci-enforcement"
                        or payload.get("schema_version") != REPORT_SCHEMA_VERSION
                    ):
                        raise ValueError
                elif kind is ReportArtifactKind.SEMANTIC_EVALUATION:
                    SemanticEvaluationReport.model_validate_json(content)
                elif kind is ReportArtifactKind.SEMANTIC_SHADOW_PIPELINE:
                    SemanticShadowPipelineReport.model_validate_json(content)
                else:
                    decode_capability_diff_json(content)
                return
            expected_titles = {
                ReportArtifactKind.AGENT_MANIFEST: {
                    "AgentSec Agent Manifest",
                    "AgentSec Agent 清单",
                },
                ReportArtifactKind.CAPABILITY_ASSESSMENT: {
                    "AgentSec Capability Assessment",
                    "AgentSec 能力评估",
                },
                ReportArtifactKind.CAPABILITY_DIFF: {
                    "AgentSec Capability Diff",
                    "AgentSec 能力 Diff",
                },
                ReportArtifactKind.CAPABILITY_CHANGE_IMPACT: {
                    "AgentSec Capability Change Impact",
                    "AgentSec 能力变化影响",
                },
                ReportArtifactKind.CAPABILITY_CI_ENFORCEMENT: {
                    "AgentSec Capability CI Enforcement",
                },
                ReportArtifactKind.AGENTIC_ASSESSMENT: {
                    "AgentSec Agentic Score",
                    "AgentSec Agentic 评分",
                },
                ReportArtifactKind.SEMANTIC_EVALUATION: {
                    "AgentSec Semantic Shadow Evaluation",
                },
                ReportArtifactKind.SEMANTIC_SHADOW_PIPELINE: {
                    "AgentSec Semantic Shadow Pipeline",
                },
            }
            first_line = content.splitlines()[0] if content.splitlines() else ""
            if first_line not in expected_titles[kind]:
                raise ValueError
        except (
            AgentManifestValidationError,
            AgenticAssessmentValidationError,
            CapabilityAssessmentValidationError,
            CapabilityDiffValidationError,
            CapabilityChangeImpactValidationError,
            ValueError,
        ) as error:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_CONTENT,
                "report output failed trusted artifact validation",
            ) from error

    @staticmethod
    def _prepare_target(
        output_path: Path,
        *,
        output_format: ReportArtifactFormat,
    ) -> Path:
        if output_path.name in ("", ".", ".."):
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_OUTPUT_PATH,
                "report output must identify a file",
            )
        expected_suffix = {
            ReportArtifactFormat.JSON: ".json",
            ReportArtifactFormat.TEXT: ".txt",
            ReportArtifactFormat.SARIF: ".sarif",
        }[output_format]
        if output_path.suffix.lower() != expected_suffix:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_OUTPUT_PATH,
                f"report output must use a {expected_suffix} filename",
            )
        try:
            output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            resolved_parent = output_path.parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.WRITE_FAILED,
                "report output directory could not be prepared safely",
            ) from error
        if not resolved_parent.is_dir():
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_OUTPUT_PATH,
                "report output parent must be a directory",
            )
        return resolved_parent / output_path.name

    @staticmethod
    def _reject_protected_target(
        target: Path,
        protected_paths: tuple[Path, ...],
    ) -> None:
        protected: set[Path] = set()
        for path in protected_paths:
            protected.add(path.absolute())
            with suppress(OSError, RuntimeError):
                protected.add(path.resolve(strict=True))
        if target in protected:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.PROTECTED_OUTPUT_PATH,
                "report output must not replace an input artifact",
            )

    def _validate_existing_target(
        self,
        target: Path,
        *,
        kind: ReportArtifactKind,
        output_format: ReportArtifactFormat,
        force: bool,
    ) -> bool:
        if target.is_symlink():
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_OUTPUT_PATH,
                "report output must not be a symbolic link",
            )
        if not target.exists():
            return False
        if not target.is_file():
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.INVALID_OUTPUT_PATH,
                "report output must be a regular file",
            )
        if not force:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.OUTPUT_EXISTS,
                "report output already exists; use --force only for the same "
                "valid AgentSec artifact",
            )
        try:
            existing = self._read_bounded(target).decode("utf-8")
            self._validate_content(
                existing,
                kind=kind,
                output_format=output_format,
            )
        except (OSError, UnicodeDecodeError, ReportArtifactWriteError) as error:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID,
                "--force may replace only the same valid AgentSec report artifact",
            ) from error
        return True

    def _read_bounded(self, path: Path) -> bytes:
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ReportArtifactWriteError(
                    ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID,
                    "existing report must remain a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise ReportArtifactWriteError(
                    ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID,
                    "existing report exceeds the hard file-size limit",
                )
            remaining = self._max_file_size_bytes + 1
            chunks: list[bytes] = []
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except ReportArtifactWriteError:
            raise
        except OSError as error:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID,
                "existing report could not be read without following links",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        content = b"".join(chunks)
        if len(content) > self._max_file_size_bytes:
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID,
                "existing report exceeds the hard file-size limit",
            )
        return content

    @staticmethod
    def _write_atomic(target: Path, content: bytes, *, replace: bool) -> None:
        descriptor = -1
        temporary_path: Path | None = None
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
            temporary_path = Path(raw_path)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(temporary_path, target)
                temporary_path = None
            else:
                try:
                    os.link(temporary_path, target)
                except FileExistsError as error:
                    raise ReportArtifactWriteError(
                        ReportArtifactWriteCode.OUTPUT_EXISTS,
                        "report output appeared during creation and was not replaced",
                    ) from error
                temporary_path.unlink()
                temporary_path = None
            ReportArtifactWriter._fsync_directory(target.parent)
        except ReportArtifactWriteError:
            raise
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise ReportArtifactWriteError(
                    ReportArtifactWriteCode.OUTPUT_EXISTS,
                    "report output already exists and was not replaced",
                ) from error
            raise ReportArtifactWriteError(
                ReportArtifactWriteCode.WRITE_FAILED,
                "report output could not be written atomically",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                with suppress(FileNotFoundError):
                    temporary_path.unlink()

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            descriptor = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

"""Restricted, atomic filesystem writes for sensitive baseline JSON."""

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

from agentsec.baselines.models import Baseline
from agentsec.baselines.validation import (
    BaselineValidationError,
    decode_baseline_json,
    encode_baseline_json,
)

DEFAULT_BASELINE_RELATIVE_PATH: Final[Path] = Path(".agentsec/baseline.json")
MAX_BASELINE_FILE_SIZE_BYTES: Final[int] = 268_435_456
_READ_CHUNK_SIZE: Final[int] = 65_536


class BaselineReadCode(StrEnum):
    """Stable safe filesystem and validation failures for Baseline reads."""

    MISSING = "missing"
    INVALID_PATH = "invalid_path"
    SYMBOLIC_LINK = "symbolic_link"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_BASELINE = "invalid_baseline"
    READ_FAILED = "read_failed"


class BaselineReadError(RuntimeError):
    """Safe Baseline input failure that never includes captured file content."""

    def __init__(self, code: BaselineReadCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class BaselineReadResult:
    """A validated Baseline plus safe filesystem provenance."""

    baseline: Baseline
    path: Path
    size_bytes: int


class BaselineFileReader:
    """Read one regular non-symlink Baseline with a hard byte bound."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_BASELINE_FILE_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("baseline file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def read(self, path: Path) -> BaselineReadResult:
        """Read bounded UTF-8 JSON and validate compatibility before payload use."""

        if path.suffix.lower() != ".json":
            raise BaselineReadError(
                BaselineReadCode.INVALID_PATH,
                "baseline input must use a .json filename",
            )
        if path.is_symlink():
            raise BaselineReadError(
                BaselineReadCode.SYMBOLIC_LINK,
                "baseline input must not be a symbolic link",
            )

        flags = os.O_RDONLY
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        flags |= no_follow
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise BaselineReadError(
                    BaselineReadCode.INVALID_PATH,
                    "baseline input must be a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise BaselineReadError(
                    BaselineReadCode.TOO_LARGE,
                    "baseline input exceeds the hard file-size limit",
                )

            content = self._read_bounded(descriptor)
        except FileNotFoundError as error:
            raise BaselineReadError(
                BaselineReadCode.MISSING,
                "baseline input does not exist",
            ) from error
        except BaselineReadError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise BaselineReadError(
                    BaselineReadCode.SYMBOLIC_LINK,
                    "baseline input must not be a symbolic link",
                ) from error
            raise BaselineReadError(
                BaselineReadCode.READ_FAILED,
                "baseline input could not be read safely",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BaselineReadError(
                BaselineReadCode.INVALID_UTF8,
                "baseline input must be valid UTF-8",
            ) from error
        try:
            baseline = decode_baseline_json(decoded)
        except BaselineValidationError as error:
            raise BaselineReadError(
                BaselineReadCode.INVALID_BASELINE,
                "baseline input failed schema or compatibility validation",
            ) from error
        try:
            resolved_path = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise BaselineReadError(
                BaselineReadCode.READ_FAILED,
                "baseline input path could not be resolved safely",
            ) from error
        return BaselineReadResult(
            baseline=baseline,
            path=resolved_path,
            size_bytes=len(content),
        )

    def _read_bounded(self, descriptor: int) -> bytes:
        """Read at most one byte beyond the configured hard limit."""

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
            raise BaselineReadError(
                BaselineReadCode.TOO_LARGE,
                "baseline input exceeds the hard file-size limit",
            )
        return content


class BaselineWriteCode(StrEnum):
    """Stable filesystem failure categories for baseline creation."""

    INVALID_OUTPUT_PATH = "invalid_output_path"
    PROTECTED_OUTPUT_PATH = "protected_output_path"
    OUTPUT_EXISTS = "output_exists"
    EXISTING_OUTPUT_INVALID = "existing_output_invalid"
    OUTPUT_TOO_LARGE = "output_too_large"
    WRITE_FAILED = "write_failed"


class BaselineWriteError(RuntimeError):
    """Safe output failure that never includes baseline content."""

    def __init__(self, code: BaselineWriteCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class BaselineWriteResult:
    """Successful baseline output metadata safe for terminal rendering."""

    path: Path
    size_bytes: int
    replaced: bool


class BaselineFileWriter:
    """Write one validated baseline with no-clobber or explicit safe replacement."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_BASELINE_FILE_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("baseline file-size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes

    def write(
        self,
        baseline: Baseline,
        output_path: Path,
        *,
        project_root: Path,
        config_path: Path | None,
        force: bool = False,
    ) -> BaselineWriteResult:
        """Persist JSON without following or overwriting unsafe targets."""

        content_bytes = encode_baseline_json(baseline).encode("utf-8")
        if len(content_bytes) > self._max_file_size_bytes:
            raise BaselineWriteError(
                BaselineWriteCode.OUTPUT_TOO_LARGE,
                "encoded baseline exceeds the configured hard output limit",
            )

        target = self._prepare_target(output_path)
        self._reject_protected_target(
            target,
            baseline=baseline,
            project_root=project_root,
            config_path=config_path,
        )
        replaced = self._validate_existing_target(target, force=force)
        self._write_atomic(target, content_bytes, replace=replaced)
        return BaselineWriteResult(
            path=target,
            size_bytes=len(content_bytes),
            replaced=replaced,
        )

    @staticmethod
    def _prepare_target(output_path: Path) -> Path:
        """Create and resolve the parent while keeping the final name non-symlinked."""

        if output_path.name in ("", ".", ".."):
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "baseline output must identify a file",
            )
        if output_path.suffix.lower() != ".json":
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "baseline output must use a .json filename",
            )

        parent = output_path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            resolved_parent = parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise BaselineWriteError(
                BaselineWriteCode.WRITE_FAILED,
                "baseline output directory could not be prepared safely",
            ) from error

        if not resolved_parent.is_dir():
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "baseline output parent must be a directory",
            )
        return resolved_parent / output_path.name

    @staticmethod
    def _reject_protected_target(
        target: Path,
        *,
        baseline: Baseline,
        project_root: Path,
        config_path: Path | None,
    ) -> None:
        """Prevent `--force` from replacing scanned assets or effective config."""

        try:
            resolved_root = project_root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "project root could not be resolved for output protection",
            ) from error

        protected: set[Path] = set()
        for asset in baseline.assets:
            logical_path = resolved_root / asset.path
            protected.add(logical_path)
            with suppress(OSError, RuntimeError):
                protected.add(logical_path.resolve(strict=True))

        if config_path is not None:
            try:
                protected.add(config_path.resolve(strict=True))
            except (OSError, RuntimeError):
                protected.add(config_path.absolute())

        if target in protected:
            raise BaselineWriteError(
                BaselineWriteCode.PROTECTED_OUTPUT_PATH,
                "baseline output must not replace a scanned asset or configuration",
            )

    def _validate_existing_target(self, target: Path, *, force: bool) -> bool:
        """Allow replacement only when an existing regular file is a valid baseline."""

        if target.is_symlink():
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "baseline output must not be a symbolic link",
            )
        if not target.exists():
            return False
        if not target.is_file():
            raise BaselineWriteError(
                BaselineWriteCode.INVALID_OUTPUT_PATH,
                "baseline output must be a regular file",
            )
        if not force:
            raise BaselineWriteError(
                BaselineWriteCode.OUTPUT_EXISTS,
                "baseline output already exists; use --force only for a valid baseline",
            )

        try:
            existing_bytes = self._read_bounded(target)
            existing_text = existing_bytes.decode("utf-8")
            decode_baseline_json(existing_text)
        except (OSError, UnicodeDecodeError, BaselineValidationError) as error:
            raise BaselineWriteError(
                BaselineWriteCode.EXISTING_OUTPUT_INVALID,
                "--force may replace only an existing valid AgentSec baseline",
            ) from error
        return True

    def _read_bounded(self, path: Path) -> bytes:
        """Read no more than one byte beyond the baseline hard limit."""

        remaining = self._max_file_size_bytes + 1
        chunks: list[bytes] = []
        with path.open("rb") as stream:
            while remaining > 0:
                chunk = stream.read(min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > self._max_file_size_bytes:
            raise BaselineWriteError(
                BaselineWriteCode.EXISTING_OUTPUT_INVALID,
                "existing baseline exceeds the hard file-size limit",
            )
        return content

    @staticmethod
    def _write_atomic(target: Path, content: bytes, *, replace: bool) -> None:
        """Commit a mode-0600 temporary file atomically in the target directory."""

        descriptor = -1
        temporary_path: Path | None = None
        try:
            descriptor, raw_temporary_path = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
            temporary_path = Path(raw_temporary_path)
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
                    raise BaselineWriteError(
                        BaselineWriteCode.OUTPUT_EXISTS,
                        "baseline output appeared during creation and was not replaced",
                    ) from error
                temporary_path.unlink()
                temporary_path = None

            BaselineFileWriter._fsync_directory(target.parent)
        except BaselineWriteError:
            raise
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise BaselineWriteError(
                    BaselineWriteCode.OUTPUT_EXISTS,
                    "baseline output already exists and was not replaced",
                ) from error
            raise BaselineWriteError(
                BaselineWriteCode.WRITE_FAILED,
                "baseline output could not be written atomically",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                with suppress(FileNotFoundError):
                    temporary_path.unlink()

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        """Best-effort durability flush after the atomic directory entry change."""

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

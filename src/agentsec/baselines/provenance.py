"""Hardened, read-only Git provenance for baseline generation."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

_GIT_TIMEOUT_SECONDS: Final[float] = 5.0
_GIT_FIXED_ARGUMENTS: Final[tuple[str, ...]] = (
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    "-c",
    "interactive.diffFilter=",
)


@dataclass(frozen=True, slots=True)
class GitProvenance:
    """Optional Git state captured without changing repository state."""

    commit: str | None
    dirty: bool | None

    def __post_init__(self) -> None:
        if (self.commit is None) != (self.dirty is None):
            raise ValueError("Git provenance fields must be present together")


class GitProvenanceProvider(Protocol):
    """Interface allowing baseline creation to obtain optional Git state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        """Return repository-local provenance or an absent value for non-Git roots."""


class GitProvenanceError(RuntimeError):
    """Safe failure raised when detected Git provenance cannot be completed."""


class SafeGitProvenanceProvider:
    """Read commit and dirty state with hooks and executable extensions disabled."""

    def __init__(
        self,
        *,
        executable: str = "git",
        timeout_seconds: float = _GIT_TIMEOUT_SECONDS,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Git timeout must be positive")
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        """Return HEAD and project-subtree dirtiness without executing repo hooks."""

        try:
            root = project_root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise GitProvenanceError(
                "Git provenance root could not be resolved"
            ) from error

        probe = self._run_text(root, "rev-parse", "--is-inside-work-tree")
        if probe is None or probe.returncode != 0:
            return GitProvenance(commit=None, dirty=None)
        if probe.stdout.strip() != "true":
            return GitProvenance(commit=None, dirty=None)

        commit_result = self._run_text(root, "rev-parse", "--verify", "HEAD")
        if commit_result is None or commit_result.returncode != 0:
            return GitProvenance(commit=None, dirty=None)
        commit = commit_result.stdout.strip()
        if len(commit) not in (40, 64) or any(
            character not in "0123456789abcdef" for character in commit
        ):
            raise GitProvenanceError("Git HEAD returned an unsupported object ID")

        exclusions = self._pathspec_exclusions(root, excluded_paths)
        tracked_result = self._run_return_code(
            root,
            "diff-index",
            "--quiet",
            "--no-ext-diff",
            "--ignore-submodules=all",
            "HEAD",
            "--",
            ".",
            *exclusions,
        )
        if tracked_result not in (0, 1):
            raise GitProvenanceError("Git tracked-file state could not be read safely")

        has_untracked = self._command_has_output(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
            "--",
            ".",
            *exclusions,
        )
        return GitProvenance(
            commit=commit,
            dirty=tracked_result == 1 or has_untracked,
        )

    @staticmethod
    def _pathspec_exclusions(
        root: Path,
        excluded_paths: tuple[Path, ...],
    ) -> tuple[str, ...]:
        """Convert selected output paths into literal project-relative exclusions."""

        exclusions: set[str] = set()
        for path in excluded_paths:
            try:
                candidate = path.resolve(strict=False)
            except (OSError, RuntimeError):
                continue
            if not candidate.is_relative_to(root):
                continue
            relative = candidate.relative_to(root).as_posix()
            if relative and relative != ".":
                exclusions.add(f":(exclude,literal){relative}")
        return tuple(sorted(exclusions))

    def _run_text(
        self,
        root: Path,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str] | None:
        """Run a fixed Git query whose successful output is intrinsically small."""

        try:
            return subprocess.run(
                self._command(root, *arguments),
                check=False,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                env=self._environment(),
                timeout=self._timeout_seconds,
            )
        except FileNotFoundError:
            return None
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GitProvenanceError("Git provenance query failed safely") from error

    def _run_return_code(self, root: Path, *arguments: str) -> int:
        """Run a no-output Git query and return its documented process code."""

        try:
            result = subprocess.run(
                self._command(root, *arguments),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self._environment(),
                timeout=self._timeout_seconds,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as error:
            raise GitProvenanceError("Git provenance query failed safely") from error
        return result.returncode

    def _command_has_output(self, root: Path, *arguments: str) -> bool:
        """Detect one output byte without buffering an attacker-sized file list."""

        try:
            process = subprocess.Popen(
                self._command(root, *arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._environment(),
            )
        except (FileNotFoundError, OSError) as error:
            raise GitProvenanceError("Git provenance query failed safely") from error

        if process.stdout is None:
            process.kill()
            process.wait()
            raise GitProvenanceError("Git provenance output was unavailable")

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + self._timeout_seconds
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GitProvenanceError("Git provenance query timed out safely")

                events = selector.select(timeout=remaining)
                if not events:
                    if process.poll() is not None:
                        break
                    continue

                chunk = os.read(process.stdout.fileno(), 1)
                if chunk:
                    self._terminate(process)
                    return True
                break

            return_code = process.wait(timeout=max(deadline - time.monotonic(), 0.001))
            if return_code != 0:
                raise GitProvenanceError("Git provenance query failed safely")
            return False
        except subprocess.TimeoutExpired as error:
            raise GitProvenanceError("Git provenance query timed out safely") from error
        finally:
            selector.close()
            process.stdout.close()
            if process.poll() is None:
                self._terminate(process)

    def _command(self, root: Path, *arguments: str) -> list[str]:
        """Build a shell-free Git command rooted at the selected project."""

        return [
            self._executable,
            *_GIT_FIXED_ARGUMENTS,
            "-C",
            str(root),
            *arguments,
        ]

    @staticmethod
    def _environment() -> dict[str, str]:
        """Remove inherited Git redirection and disable prompts and global config."""

        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        return environment

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        """Stop a bounded output probe without leaving a child process behind."""

        with suppress(ProcessLookupError):
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                process.kill()
            process.wait()

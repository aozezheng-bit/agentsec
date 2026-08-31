"""Canonical root containment and symbolic-link safety for collectors."""

from __future__ import annotations

import errno
import os
import stat
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

_MAX_SYMLINK_HOPS = 64


class PathSafetyReason(StrEnum):
    """Internal reasons that a filesystem path cannot be safely used."""

    ROOT_MISSING = "root_missing"
    ROOT_NOT_DIRECTORY = "root_not_directory"
    ROOT_UNREADABLE = "root_unreadable"
    OUTSIDE_ROOT = "outside_root"
    BROKEN_SYMLINK = "broken_symlink"
    SYMLINK_LOOP = "symlink_loop"
    UNREADABLE = "unreadable"


class SafePathKind(StrEnum):
    """Filesystem kinds needed by the static collector."""

    FILE = "file"
    DIRECTORY = "directory"
    OTHER = "other"


class PathGuardError(RuntimeError):
    """A safe path resolution failure without leaking target details."""

    def __init__(self, reason: PathSafetyReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class GuardedPath:
    """A resolved path proven to remain inside the canonical project root."""

    resolved_path: Path
    kind: SafePathKind
    is_symbolic_link: bool
    size_bytes: int | None


class PathGuard:
    """Resolve filesystem entries while enforcing one canonical root boundary."""

    def __init__(self, canonical_root: Path) -> None:
        self._canonical_root = canonical_root

    @classmethod
    def create(cls, project_root: Path) -> PathGuard:
        """Resolve an explicitly selected project root into its trust boundary."""

        try:
            canonical_root = project_root.resolve(strict=True)
        except FileNotFoundError as error:
            raise PathGuardError(PathSafetyReason.ROOT_MISSING) from error
        except RuntimeError as error:
            raise PathGuardError(PathSafetyReason.SYMLINK_LOOP) from error
        except OSError as error:
            reason = (
                PathSafetyReason.SYMLINK_LOOP
                if error.errno == errno.ELOOP
                else PathSafetyReason.ROOT_UNREADABLE
            )
            raise PathGuardError(reason) from error

        try:
            root_stat = canonical_root.stat()
        except OSError as error:
            raise PathGuardError(PathSafetyReason.ROOT_UNREADABLE) from error
        if not stat.S_ISDIR(root_stat.st_mode):
            raise PathGuardError(PathSafetyReason.ROOT_NOT_DIRECTORY)

        return cls(canonical_root)

    @property
    def root(self) -> Path:
        """Return the canonical directory that defines scan containment."""

        return self._canonical_root

    def inspect(self, candidate: Path) -> GuardedPath:
        """Resolve every link hop and prove it never leaves the project root."""

        lexical_path = Path(os.path.abspath(candidate))
        if not lexical_path.is_relative_to(self._canonical_root):
            raise PathGuardError(PathSafetyReason.OUTSIDE_ROOT)

        try:
            candidate_stat = lexical_path.lstat()
        except OSError as error:
            raise PathGuardError(PathSafetyReason.UNREADABLE) from error
        is_symbolic_link = stat.S_ISLNK(candidate_stat.st_mode)

        resolved_path = self._resolve_within_root(lexical_path)
        try:
            resolved_stat = resolved_path.stat()
        except OSError as error:
            raise PathGuardError(PathSafetyReason.UNREADABLE) from error

        if stat.S_ISREG(resolved_stat.st_mode):
            kind = SafePathKind.FILE
        elif stat.S_ISDIR(resolved_stat.st_mode):
            kind = SafePathKind.DIRECTORY
        else:
            kind = SafePathKind.OTHER

        return GuardedPath(
            resolved_path=resolved_path,
            kind=kind,
            is_symbolic_link=is_symbolic_link,
            size_bytes=resolved_stat.st_size if kind is SafePathKind.FILE else None,
        )

    def project_relative_path(self, guarded_path: GuardedPath) -> str:
        """Return the canonical target's portable path below the project root."""

        return guarded_path.resolved_path.relative_to(self._canonical_root).as_posix()

    def _resolve_within_root(self, candidate: Path) -> Path:
        """Resolve links component-by-component and reject any escaping hop."""

        relative_parts = candidate.relative_to(self._canonical_root).parts
        pending = deque(relative_parts)
        current = self._canonical_root
        seen_links: set[Path] = set()
        encountered_link = False

        while pending:
            path_part = pending.popleft()
            next_path = current / path_part
            try:
                next_stat = next_path.lstat()
            except FileNotFoundError as error:
                reason = (
                    PathSafetyReason.BROKEN_SYMLINK
                    if encountered_link
                    else PathSafetyReason.UNREADABLE
                )
                raise PathGuardError(reason) from error
            except OSError as error:
                reason = (
                    PathSafetyReason.SYMLINK_LOOP
                    if error.errno == errno.ELOOP
                    else PathSafetyReason.UNREADABLE
                )
                raise PathGuardError(reason) from error

            if not stat.S_ISLNK(next_stat.st_mode):
                current = next_path
                continue

            encountered_link = True
            if next_path in seen_links or len(seen_links) >= _MAX_SYMLINK_HOPS:
                raise PathGuardError(PathSafetyReason.SYMLINK_LOOP)
            seen_links.add(next_path)

            try:
                link_target = next_path.readlink()
            except OSError as error:
                raise PathGuardError(PathSafetyReason.UNREADABLE) from error

            expanded_target = (
                link_target if link_target.is_absolute() else current / link_target
            )
            normalized_target = Path(os.path.abspath(expanded_target))
            if not normalized_target.is_relative_to(self._canonical_root):
                raise PathGuardError(PathSafetyReason.OUTSIDE_ROOT)

            target_parts = normalized_target.relative_to(self._canonical_root).parts
            pending = deque((*target_parts, *pending))
            current = self._canonical_root

        return current

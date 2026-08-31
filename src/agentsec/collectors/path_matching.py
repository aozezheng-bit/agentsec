"""Deterministic project-relative glob matching for asset discovery."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from agentsec.config import DiscoveryConfig


class DiscoveryPathMatcher:
    """Apply root-anchored include and exclude patterns to POSIX paths.

    ``*``, ``?``, and character classes match within one path segment.
    A segment equal to ``**`` matches zero or more complete path segments.
    Matching is case-sensitive on every operating system, and excludes win.
    """

    def __init__(self, config: DiscoveryConfig) -> None:
        self._include_patterns = tuple(
            PurePosixPath(pattern).parts for pattern in config.include
        )
        self._exclude_patterns = tuple(
            PurePosixPath(pattern).parts for pattern in config.exclude
        )

    def is_included(self, relative_path: str) -> bool:
        """Return whether any include pattern selects the complete path."""

        path_parts = PurePosixPath(relative_path).parts
        return any(
            _glob_matches(pattern_parts, path_parts)
            for pattern_parts in self._include_patterns
        )

    def is_excluded(self, relative_path: str) -> bool:
        """Return whether an exclude pattern removes the complete path."""

        path_parts = PurePosixPath(relative_path).parts
        return any(
            _glob_matches(pattern_parts, path_parts)
            for pattern_parts in self._exclude_patterns
        )

    def selects_markdown_file(self, relative_path: str) -> bool:
        """Return whether a lowercase ``.md`` file is inside discovery scope."""

        path = PurePosixPath(relative_path)
        return (
            path.suffix == ".md"
            and self.is_included(relative_path)
            and not self.is_excluded(relative_path)
        )


def _glob_matches(pattern_parts: tuple[str, ...], path_parts: tuple[str, ...]) -> bool:
    """Match path segments without recursion or platform-specific semantics."""

    pattern_count = len(pattern_parts)
    states = _expand_globstars({0}, pattern_parts)

    for path_part in path_parts:
        next_states: set[int] = set()
        for pattern_index in states:
            if pattern_index == pattern_count:
                continue

            pattern_part = pattern_parts[pattern_index]
            if pattern_part == "**":
                next_states.add(pattern_index)
            elif fnmatchcase(path_part, pattern_part):
                next_states.add(pattern_index + 1)

        states = _expand_globstars(next_states, pattern_parts)
        if not states:
            return False

    return pattern_count in _expand_globstars(states, pattern_parts)


def _expand_globstars(
    states: set[int],
    pattern_parts: tuple[str, ...],
) -> set[int]:
    """Add states reachable when ``**`` consumes zero path segments."""

    expanded = set(states)
    pending = list(states)
    while pending:
        pattern_index = pending.pop()
        if (
            pattern_index < len(pattern_parts)
            and pattern_parts[pattern_index] == "**"
            and pattern_index + 1 not in expanded
        ):
            expanded.add(pattern_index + 1)
            pending.append(pattern_index + 1)
    return expanded

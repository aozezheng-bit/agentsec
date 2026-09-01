"""Tests for project-root-anchored discovery glob semantics."""

from __future__ import annotations

import pytest

from agentsec.collectors import DiscoveryPathMatcher
from agentsec.config import DiscoveryConfig


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("AGENTS.md", "AGENTS.md", True),
        ("AGENTS.md", "nested/AGENTS.md", False),
        ("**/AGENTS.md", "AGENTS.md", True),
        ("**/AGENTS.md", "one/two/AGENTS.md", True),
        ("docs/*.md", "docs/one.md", True),
        ("docs/*.md", "docs/nested/two.md", False),
        ("docs/**/*.md", "docs/one.md", True),
        ("docs/**/*.md", "docs/nested/two.md", True),
        ("docs/file?.md", "docs/file1.md", True),
        ("docs/file?.md", "docs/file10.md", False),
        ("docs/[AB].md", "docs/A.md", True),
        ("docs/[AB].md", "docs/C.md", False),
        ("agents.md", "AGENTS.md", False),
    ],
)
def test_include_patterns_are_root_anchored_and_case_sensitive(
    pattern: str,
    path: str,
    expected: bool,
) -> None:
    """Glob tokens operate on POSIX path segments with stable semantics."""

    matcher = DiscoveryPathMatcher(
        DiscoveryConfig(include=(pattern,), exclude=()),
    )

    assert matcher.is_included(path) is expected


@pytest.mark.parametrize(
    "path",
    [
        ".git",
        ".git/objects",
        ".git/objects/pack/AGENTS.md",
    ],
)
def test_subtree_exclusion_matches_directory_and_descendants(path: str) -> None:
    """A trailing globstar permits pruning at the subtree root."""

    matcher = DiscoveryPathMatcher(
        DiscoveryConfig(include=("**/*.md",), exclude=(".git/**",)),
    )

    assert matcher.is_excluded(path) is True


def test_exclude_wins_over_include_for_markdown_selection() -> None:
    """A path cannot be re-included while an exclusion still selects it."""

    matcher = DiscoveryPathMatcher(
        DiscoveryConfig(
            include=("**/*.md",),
            exclude=("private/**",),
        ),
    )

    assert matcher.selects_markdown_file("public/AGENTS.md") is True
    assert matcher.selects_markdown_file("private/AGENTS.md") is False

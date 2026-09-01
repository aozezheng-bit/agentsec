"""Tests for deterministic, non-executing Markdown asset collection."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import (
    CONFIG_SCHEMA_VERSION,
    DiscoveryConfig,
    LimitsConfig,
    ProjectConfig,
    default_project_config,
)
from agentsec.domain import AssetSource, AssetType, CoverageIssueCode


def test_discovers_only_exact_supported_names_in_stable_order(tmp_path: Path) -> None:
    """Recursive discovery is case-sensitive and ignores unrelated Markdown."""

    (tmp_path / "z-skill").mkdir()
    (tmp_path / "z-skill" / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (tmp_path / "AGENTS.override.md").write_text("override\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("agents\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("readme\n", encoding="utf-8")
    (tmp_path / "agents.md").write_text("wrong case\n", encoding="utf-8")

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert [item.asset.path for item in result.assets] == [
        "AGENTS.md",
        "AGENTS.override.md",
        "z-skill/SKILL.md",
    ]
    assert [item.asset.asset_type for item in result.assets] == [
        AssetType.AGENTS,
        AssetType.AGENTS_OVERRIDE,
        AssetType.SKILL,
    ]
    assert all(item.asset.source is AssetSource.DISCOVERED for item in result.assets)
    assert result.coverage.discovered_assets == 3
    assert result.coverage.scanned_assets == 3
    assert result.coverage.skipped_assets == 0
    assert result.coverage.complete is True


def test_records_hash_byte_size_line_count_and_content(tmp_path: Path) -> None:
    """Collected metadata is derived from the exact UTF-8 bytes on disk."""

    content = "first line\n第二行\n"
    content_bytes = content.encode()
    (tmp_path / "AGENTS.md").write_bytes(content_bytes)

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert len(result.assets) == 1
    collected = result.assets[0]
    assert collected.content == content
    assert collected.asset.sha256 == hashlib.sha256(content_bytes).hexdigest()
    assert collected.asset.size_bytes == len(content_bytes)
    assert collected.asset.line_count == 2
    assert collected.asset.encoding == "utf-8"


def test_markdown_content_is_returned_as_data_and_never_executed(
    tmp_path: Path,
) -> None:
    """Executable-looking fenced content remains inert untrusted text."""

    marker = tmp_path / "must-not-exist"
    content = (
        "# Untrusted\n\n"
        "```python\n"
        f"from pathlib import Path; Path({str(marker)!r}).touch()\n"
        "```\n"
    )
    (tmp_path / "AGENTS.md").write_text(content, encoding="utf-8")

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert result.assets[0].content == content
    assert not marker.exists()


def test_invalid_utf8_is_skipped_with_visible_coverage_issue(
    tmp_path: Path,
) -> None:
    """Malformed bytes do not crash or silently disappear from coverage."""

    (tmp_path / "AGENTS.md").write_bytes(b"valid prefix\n\xff\xfe")

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 1
    assert result.coverage.scanned_assets == 0
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert len(result.coverage.issues) == 1
    issue = result.coverage.issues[0]
    assert issue.code is CoverageIssueCode.UNSUPPORTED_ENCODING
    assert issue.asset_path == "AGENTS.md"


def test_read_failure_is_skipped_with_visible_coverage_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable matching file remains represented in coverage counts."""

    asset_path = tmp_path / "AGENTS.md"
    asset_path.write_text("content\n", encoding="utf-8")
    collector = MarkdownAssetCollector()

    def deny_asset_read(path: Path, max_bytes: int) -> bytes:
        del path, max_bytes
        raise PermissionError("simulated denial")

    monkeypatch.setattr(collector, "_read_bounded_bytes", deny_asset_read)

    result = collector.collect(tmp_path, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 1
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert result.coverage.issues[0].code is CoverageIssueCode.UNREADABLE
    assert result.coverage.issues[0].asset_path == "AGENTS.md"
    assert "simulated denial" not in result.coverage.issues[0].message


def test_external_symbolic_links_are_not_followed_and_are_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """File and directory links cannot silently extend the traversal boundary."""

    project_root = tmp_path / "project"
    outside_root = tmp_path / "outside"
    project_root.mkdir()
    (outside_root / "skills").mkdir(parents=True)
    (outside_root / "AGENTS.md").write_text("outside\n", encoding="utf-8")
    (outside_root / "skills" / "SKILL.md").write_text(
        "outside skill\n",
        encoding="utf-8",
    )
    (project_root / "AGENTS.md").symlink_to(outside_root / "AGENTS.md")
    (project_root / "linked-skills").symlink_to(
        outside_root / "skills",
        target_is_directory=True,
    )
    collector = MarkdownAssetCollector()
    original_bounded_read = collector._read_bounded_bytes

    def reject_external_read(path: Path, max_bytes: int) -> bytes:
        if path.is_relative_to(outside_root):
            raise AssertionError("external target content must not be read")
        return original_bounded_read(path, max_bytes)

    monkeypatch.setattr(collector, "_read_bounded_bytes", reject_external_read)

    result = collector.collect(project_root, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 1
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert [issue.asset_path for issue in result.coverage.issues] == [
        "AGENTS.md",
        "linked-skills",
    ]
    assert all(
        issue.code is CoverageIssueCode.EXTERNAL_SYMLINK
        for issue in result.coverage.issues
    )
    assert all(
        str(outside_root) not in issue.message for issue in result.coverage.issues
    )


@pytest.mark.parametrize("root_kind", ["missing", "file", "symlink_loop"])
def test_invalid_project_roots_return_incomplete_coverage(
    tmp_path: Path,
    root_kind: str,
) -> None:
    """Invalid roots fail closed as assessment data instead of exceptions."""

    project_root = tmp_path / "project"
    if root_kind == "file":
        project_root.write_text("not a directory\n", encoding="utf-8")
    elif root_kind == "symlink_loop":
        project_root.symlink_to(project_root, target_is_directory=True)

    result = MarkdownAssetCollector().collect(project_root, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 0
    assert result.coverage.scanned_assets == 0
    assert result.coverage.skipped_assets == 0
    assert result.coverage.complete is False
    assert len(result.coverage.issues) == 1


def test_secure_defaults_prune_dependency_build_and_cache_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default exclusions prevent reads below known generated directory names."""

    excluded_directories = (
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "src/__pycache__",
    )
    for relative_directory in excluded_directories:
        directory = tmp_path / relative_directory
        directory.mkdir(parents=True)
        (directory / "AGENTS.md").write_text("excluded\n", encoding="utf-8")

    (tmp_path / "AGENTS.md").write_text("included\n", encoding="utf-8")
    excluded_git_directory = tmp_path / ".git"
    original_iterdir = Path.iterdir

    def reject_excluded_traversal(path: Path) -> Iterator[Path]:
        if path == excluded_git_directory:
            raise AssertionError("excluded directory must be pruned")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", reject_excluded_traversal)

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert [item.asset.path for item in result.assets] == ["AGENTS.md"]
    assert result.coverage.discovered_assets == 1
    assert result.coverage.complete is True
    assert result.coverage.issues == ()


def test_custom_include_adds_explicit_markdown_assets(tmp_path: Path) -> None:
    """Configured Markdown paths are typed separately from standard assets."""

    (tmp_path / "docs" / "nested").mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("standard\n", encoding="utf-8")
    (tmp_path / "docs" / "POLICY.md").write_text("policy\n", encoding="utf-8")
    (tmp_path / "docs" / "nested" / "REVIEW.md").write_text(
        "review\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("not selected\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(
            include=("AGENTS.md", "docs/**/*.md"),
            exclude=(),
        ),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert [item.asset.path for item in result.assets] == [
        "AGENTS.md",
        "docs/POLICY.md",
        "docs/nested/REVIEW.md",
    ]
    assert [item.asset.asset_type for item in result.assets] == [
        AssetType.AGENTS,
        AssetType.EXPLICIT_MARKDOWN,
        AssetType.EXPLICIT_MARKDOWN,
    ]
    assert [item.asset.source for item in result.assets] == [
        AssetSource.DISCOVERED,
        AssetSource.EXPLICIT,
        AssetSource.EXPLICIT,
    ]


def test_exclude_patterns_win_without_creating_coverage_gaps(tmp_path: Path) -> None:
    """Intentionally excluded files and subtrees are outside scan coverage."""

    (tmp_path / "private" / "nested").mkdir(parents=True)
    (tmp_path / "public").mkdir()
    (tmp_path / "private" / "AGENTS.md").write_text("private\n", encoding="utf-8")
    (tmp_path / "private" / "nested" / "SKILL.md").write_text(
        "private skill\n",
        encoding="utf-8",
    )
    (tmp_path / "public" / "AGENTS.md").write_text("public\n", encoding="utf-8")
    (tmp_path / "public" / "ignore.md").write_text("ignored\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(
            include=("**/*.md",),
            exclude=("private/**", "**/ignore.md"),
        ),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert [item.asset.path for item in result.assets] == ["public/AGENTS.md"]
    assert result.coverage.discovered_assets == 1
    assert result.coverage.complete is True
    assert result.coverage.issues == ()


def test_custom_excludes_replace_defaults_when_operator_removes_them(
    tmp_path: Path,
) -> None:
    """Removing a default exclusion deliberately re-enters that subtree."""

    dependency_directory = tmp_path / "node_modules" / "example"
    dependency_directory.mkdir(parents=True)
    (dependency_directory / "AGENTS.md").write_text("dependency\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(
            include=("**/AGENTS.md",),
            exclude=(),
        ),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert [item.asset.path for item in result.assets] == [
        "node_modules/example/AGENTS.md"
    ]
    assert result.coverage.complete is True


def test_non_markdown_files_are_ignored_even_when_a_glob_selects_them(
    tmp_path: Path,
) -> None:
    """Phase 1 explicit includes cannot expand collection beyond Markdown."""

    (tmp_path / "instructions.txt").write_text("text\n", encoding="utf-8")
    (tmp_path / "INSTRUCTIONS.MD").write_text("uppercase\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(include=("**",), exclude=()),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert result.assets == ()
    assert result.coverage.discovered_assets == 0
    assert result.coverage.complete is True


def test_symbolic_link_project_root_is_scanned_with_canonical_containment(
    tmp_path: Path,
) -> None:
    """An explicitly selected root alias can safely expose its contained assets."""

    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "AGENTS.md").write_text("contained\n", encoding="utf-8")
    linked_root = tmp_path / "project"
    linked_root.symlink_to(target_root, target_is_directory=True)

    result = MarkdownAssetCollector().collect(linked_root, default_project_config())

    assert [item.asset.path for item in result.assets] == ["AGENTS.md"]
    assert result.assets[0].content == "contained\n"
    assert result.coverage.complete is True


def test_internal_file_symlink_is_read_under_its_logical_asset_path(
    tmp_path: Path,
) -> None:
    """Contained link content is safe to read while evidence keeps the link path."""

    target_directory = tmp_path / "targets"
    target_directory.mkdir()
    target = target_directory / "instructions.md"
    target.write_text("internal target\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").symlink_to(Path("targets/instructions.md"))

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert [item.asset.path for item in result.assets] == ["AGENTS.md"]
    assert result.assets[0].content == "internal target\n"
    assert result.coverage.complete is True


def test_internal_directory_symlink_is_traversed_without_losing_logical_paths(
    tmp_path: Path,
) -> None:
    """Contained directory aliases preserve distinct project-relative evidence."""

    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (tmp_path / "alias").symlink_to(real_directory, target_is_directory=True)

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert [item.asset.path for item in result.assets] == [
        "alias/SKILL.md",
        "real/SKILL.md",
    ]
    assert result.coverage.complete is True


def test_directory_symlink_to_ancestor_is_stopped_as_a_cycle(tmp_path: Path) -> None:
    """Canonical ancestor tracking prevents recursive directory-link loops."""

    skill_directory = tmp_path / "skills"
    skill_directory.mkdir()
    (skill_directory / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (skill_directory / "back-to-root").symlink_to(
        tmp_path,
        target_is_directory=True,
    )

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert [item.asset.path for item in result.assets] == ["skills/SKILL.md"]
    assert result.coverage.discovered_assets == 1
    assert result.coverage.skipped_assets == 0
    assert result.coverage.complete is False
    assert result.coverage.issues[0].asset_path == "skills/back-to-root"
    assert result.coverage.issues[0].code is CoverageIssueCode.EXTERNAL_SYMLINK
    assert "cycle" in result.coverage.issues[0].message.lower()


@pytest.mark.parametrize(
    ("link_kind", "expected_code", "message_fragment"),
    [
        ("broken", CoverageIssueCode.UNREADABLE, "does not exist"),
        ("cycle", CoverageIssueCode.EXTERNAL_SYMLINK, "cycle"),
    ],
)
def test_unsafe_selected_file_symlinks_are_skipped_with_coverage(
    tmp_path: Path,
    link_kind: str,
    expected_code: CoverageIssueCode,
    message_fragment: str,
) -> None:
    """Broken and cyclic asset links cannot disappear from coverage counts."""

    asset_link = tmp_path / "AGENTS.md"
    if link_kind == "broken":
        asset_link.symlink_to(tmp_path / "missing.md")
    else:
        asset_link.symlink_to(asset_link)

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 1
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert result.coverage.issues[0].code is expected_code
    assert message_fragment in result.coverage.issues[0].message.lower()


def test_internal_symlink_cannot_bypass_excluded_target_directory(
    tmp_path: Path,
) -> None:
    """Logical aliases cannot re-enter a canonically excluded subtree."""

    excluded_directory = tmp_path / ".git" / "agent"
    excluded_directory.mkdir(parents=True)
    (excluded_directory / "AGENTS.md").write_text("excluded\n", encoding="utf-8")
    (tmp_path / "git-alias").symlink_to(
        tmp_path / ".git",
        target_is_directory=True,
    )

    result = MarkdownAssetCollector().collect(tmp_path, default_project_config())

    assert result.assets == ()
    assert result.coverage.discovered_assets == 0
    assert result.coverage.complete is True
    assert result.coverage.issues == ()


def test_file_exactly_at_configured_size_limit_is_accepted(tmp_path: Path) -> None:
    """The file-size boundary is inclusive rather than off by one."""

    content = b"12345678"
    (tmp_path / "AGENTS.md").write_bytes(content)
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        limits=LimitsConfig(max_file_size_bytes=len(content)),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert len(result.assets) == 1
    assert result.assets[0].asset.size_bytes == len(content)
    assert result.coverage.complete is True


def test_oversized_file_is_skipped_before_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Known oversized files never enter the bounded content reader."""

    limit = 8
    (tmp_path / "AGENTS.md").write_bytes(b"x" * (limit + 1))
    collector = MarkdownAssetCollector()

    def reject_content_read(path: Path, max_bytes: int) -> bytes:
        del path, max_bytes
        raise AssertionError("oversized content must not be opened")

    monkeypatch.setattr(collector, "_read_bounded_bytes", reject_content_read)
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        limits=LimitsConfig(max_file_size_bytes=limit),
    )

    result = collector.collect(tmp_path, config)

    assert result.assets == ()
    assert result.coverage.discovered_assets == 1
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert result.coverage.issues[0].code is CoverageIssueCode.TOO_LARGE
    assert result.coverage.issues[0].asset_path == "AGENTS.md"
    assert str(limit) in result.coverage.issues[0].message


def test_bounded_reader_never_reads_more_than_limit_plus_one(tmp_path: Path) -> None:
    """A post-stat growth race still has a strict memory-read boundary."""

    path = tmp_path / "large.md"
    path.write_bytes(b"x" * 100)

    content = MarkdownAssetCollector._read_bounded_bytes(path, 7)

    assert content == b"x" * 8


def test_depth_limit_scans_boundary_files_and_prunes_deeper_directories(
    tmp_path: Path,
) -> None:
    """Root depth zero makes max_depth one include one child directory."""

    level_one = tmp_path / "level-one"
    level_two = level_one / "level-two"
    level_two.mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("root\n", encoding="utf-8")
    (level_one / "SKILL.md").write_text("level one\n", encoding="utf-8")
    (level_two / "AGENTS.md").write_text("too deep\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        limits=LimitsConfig(max_depth=1),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert [item.asset.path for item in result.assets] == [
        "AGENTS.md",
        "level-one/SKILL.md",
    ]
    assert result.coverage.discovered_assets == 2
    assert result.coverage.skipped_assets == 0
    assert result.coverage.complete is False
    assert result.coverage.issues[0].code is CoverageIssueCode.DEPTH_EXCEEDED
    assert result.coverage.issues[0].asset_path == "level-one/level-two"


def test_excluded_directory_does_not_trigger_depth_issue(tmp_path: Path) -> None:
    """Intentional scope pruning occurs before depth-limit accounting."""

    deep_directory = tmp_path / "allowed" / "excluded"
    deep_directory.mkdir(parents=True)
    (deep_directory / "AGENTS.md").write_text("excluded\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(
            include=("**/AGENTS.md",),
            exclude=("allowed/excluded/**",),
        ),
        limits=LimitsConfig(max_depth=1),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert result.assets == ()
    assert result.coverage.complete is True
    assert result.coverage.issues == ()


def test_asset_limit_counts_first_overflow_and_stops_globally(tmp_path: Path) -> None:
    """Stable traversal scans the limit, counts one sentinel, then stops."""

    for name in ("a.md", "b.md", "c.md", "d.md"):
        (tmp_path / name).write_text(f"{name}\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(include=("**/*.md",), exclude=()),
        limits=LimitsConfig(max_assets=2),
    )

    result = MarkdownAssetCollector().collect(tmp_path, config)

    assert [item.asset.path for item in result.assets] == ["a.md", "b.md"]
    assert result.coverage.discovered_assets == 3
    assert result.coverage.scanned_assets == 2
    assert result.coverage.skipped_assets == 1
    assert result.coverage.complete is False
    assert len(result.coverage.issues) == 1
    issue = result.coverage.issues[0]
    assert issue.code is CoverageIssueCode.ASSET_LIMIT_EXCEEDED
    assert issue.asset_path == "c.md"
    assert "2" in issue.message


def test_skipped_asset_consumes_asset_limit_capacity(tmp_path: Path) -> None:
    """Unsafe selected candidates count toward total resource consumption."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n", encoding="utf-8")
    first = project_root / "a.md"
    first.symlink_to(outside)
    (project_root / "b.md").write_text("would exceed\n", encoding="utf-8")
    config = ProjectConfig(
        version=CONFIG_SCHEMA_VERSION,
        discovery=DiscoveryConfig(include=("**/*.md",), exclude=()),
        limits=LimitsConfig(max_assets=1),
    )

    result = MarkdownAssetCollector().collect(project_root, config)

    assert result.assets == ()
    assert result.coverage.discovered_assets == 2
    assert result.coverage.scanned_assets == 0
    assert result.coverage.skipped_assets == 2
    assert [issue.code for issue in result.coverage.issues] == [
        CoverageIssueCode.EXTERNAL_SYMLINK,
        CoverageIssueCode.ASSET_LIMIT_EXCEEDED,
    ]
    assert [issue.asset_path for issue in result.coverage.issues] == ["a.md", "b.md"]

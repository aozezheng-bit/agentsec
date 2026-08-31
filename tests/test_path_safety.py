"""Tests for canonical project-root containment and symlink resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.collectors import (
    PathGuard,
    PathGuardError,
    PathSafetyReason,
    SafePathKind,
)


def test_guard_canonicalizes_an_explicit_symbolic_link_root(tmp_path: Path) -> None:
    """An operator-selected root link defines its target as the scan boundary."""

    target_root = tmp_path / "target"
    target_root.mkdir()
    linked_root = tmp_path / "project"
    linked_root.symlink_to(target_root, target_is_directory=True)

    guard = PathGuard.create(linked_root)

    assert guard.root == target_root.resolve()


def test_guard_accepts_internal_file_and_directory_links(tmp_path: Path) -> None:
    """Contained links resolve to typed paths without leaving the root."""

    project_root = tmp_path / "project"
    target_directory = project_root / "targets"
    target_directory.mkdir(parents=True)
    target_file = target_directory / "source.md"
    target_file.write_text("content\n", encoding="utf-8")
    file_link = project_root / "AGENTS.md"
    directory_link = project_root / "linked-targets"
    file_link.symlink_to(target_file)
    directory_link.symlink_to(target_directory, target_is_directory=True)
    guard = PathGuard.create(project_root)

    guarded_file = guard.inspect(file_link)
    guarded_directory = guard.inspect(directory_link)

    assert guarded_file.kind is SafePathKind.FILE
    assert guarded_file.is_symbolic_link is True
    assert guarded_file.resolved_path == target_file.resolve()
    assert guarded_directory.kind is SafePathKind.DIRECTORY
    assert guarded_directory.is_symbolic_link is True
    assert guarded_directory.resolved_path == target_directory.resolve()


def test_guard_rejects_paths_and_link_targets_outside_root(tmp_path: Path) -> None:
    """Both direct traversal and indirect symlink escape fail closed."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    outside_file = tmp_path / "outside.md"
    outside_file.write_text("outside\n", encoding="utf-8")
    external_link = project_root / "AGENTS.md"
    external_link.symlink_to(outside_file)
    guard = PathGuard.create(project_root)

    with pytest.raises(PathGuardError) as direct_error:
        guard.inspect(outside_file)
    with pytest.raises(PathGuardError) as link_error:
        guard.inspect(external_link)

    assert direct_error.value.reason is PathSafetyReason.OUTSIDE_ROOT
    assert link_error.value.reason is PathSafetyReason.OUTSIDE_ROOT


def test_guard_distinguishes_broken_and_cyclic_links(tmp_path: Path) -> None:
    """Broken targets and link-resolution loops remain diagnosable."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    broken_link = project_root / "broken.md"
    cyclic_link = project_root / "cycle.md"
    broken_link.symlink_to(project_root / "missing.md")
    cyclic_link.symlink_to(cyclic_link)
    guard = PathGuard.create(project_root)

    with pytest.raises(PathGuardError) as broken_error:
        guard.inspect(broken_link)
    with pytest.raises(PathGuardError) as cycle_error:
        guard.inspect(cyclic_link)

    assert broken_error.value.reason is PathSafetyReason.BROKEN_SYMLINK
    assert cycle_error.value.reason is PathSafetyReason.SYMLINK_LOOP


def test_guard_rejects_a_link_chain_that_temporarily_leaves_root(
    tmp_path: Path,
) -> None:
    """Final containment cannot hide an intermediate external link hop."""

    project_root = tmp_path / "project"
    outside_root = tmp_path / "outside"
    project_root.mkdir()
    outside_root.mkdir()
    target = project_root / "target.md"
    target.write_text("inside\n", encoding="utf-8")
    outside_back_link = outside_root / "back.md"
    outside_back_link.symlink_to(target)
    internal_bridge = project_root / "bridge.md"
    internal_bridge.symlink_to(outside_back_link)
    asset_link = project_root / "AGENTS.md"
    asset_link.symlink_to(internal_bridge)
    guard = PathGuard.create(project_root)

    with pytest.raises(PathGuardError) as error:
        guard.inspect(asset_link)

    assert error.value.reason is PathSafetyReason.OUTSIDE_ROOT

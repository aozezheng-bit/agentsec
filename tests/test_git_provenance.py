"""Tests for hardened read-only Git provenance collection."""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from agentsec.baselines import GitProvenance, SafeGitProvenanceProvider

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="Git executable is unavailable")


def run_git(root: Path, *arguments: str) -> str:
    """Run test-only local Git setup without network access."""

    result = subprocess.run(
        [GIT or "git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def initialize_repository(root: Path) -> str:
    """Create one committed local repository and return its full HEAD."""

    root.mkdir()
    run_git(root, "init", "--quiet")
    run_git(root, "config", "user.name", "AgentSec Tests")
    run_git(root, "config", "user.email", "agentsec-tests@example.invalid")
    (root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    run_git(root, "add", "AGENTS.md")
    run_git(root, "commit", "--quiet", "-m", "initial")
    return run_git(root, "rev-parse", "HEAD")


def test_non_git_directory_has_absent_provenance(tmp_path: Path) -> None:
    """Git is optional for ordinary project directories."""

    assert SafeGitProvenanceProvider().inspect(tmp_path) == GitProvenance(
        commit=None,
        dirty=None,
    )


def test_clean_repository_returns_full_commit_and_clean_state(tmp_path: Path) -> None:
    """A stable committed project records exact local Git provenance."""

    root = tmp_path / "repo"
    commit = initialize_repository(root)

    provenance = SafeGitProvenanceProvider().inspect(root)

    assert provenance == GitProvenance(commit=commit, dirty=False)


def test_tracked_and_untracked_changes_mark_repository_dirty(tmp_path: Path) -> None:
    """Both tracked drift and untracked project files are visible."""

    root = tmp_path / "repo"
    commit = initialize_repository(root)
    provider = SafeGitProvenanceProvider()

    (root / "AGENTS.md").write_text("changed\n", encoding="utf-8")
    assert provider.inspect(root) == GitProvenance(commit=commit, dirty=True)

    run_git(root, "checkout", "--", "AGENTS.md")
    (root / "UNTRACKED.txt").write_text("new\n", encoding="utf-8")
    assert provider.inspect(root) == GitProvenance(commit=commit, dirty=True)


def test_inherited_git_redirection_environment_is_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GIT_DIR and GIT_WORK_TREE cannot redirect provenance to another repository."""

    selected = tmp_path / "selected"
    other = tmp_path / "other"
    selected_commit = initialize_repository(selected)
    initialize_repository(other)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))

    provenance = SafeGitProvenanceProvider().inspect(selected)

    assert provenance.commit == selected_commit


def test_repository_fsmonitor_command_is_not_executed(tmp_path: Path) -> None:
    """Local Git configuration cannot turn provenance into hook execution."""

    root = tmp_path / "repo"
    commit = initialize_repository(root)
    marker = tmp_path / "fsmonitor-executed"
    monitor = tmp_path / "monitor.sh"
    monitor.write_text(
        f"#!/bin/sh\ntouch {marker!s}\nexit 0\n",
        encoding="utf-8",
    )
    monitor.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    run_git(root, "config", "core.fsmonitor", str(monitor))

    provenance = SafeGitProvenanceProvider().inspect(root)

    assert provenance.commit == commit
    assert not marker.exists()


def test_missing_git_executable_returns_absent_provenance(tmp_path: Path) -> None:
    """Baseline creation remains available for non-Git environments."""

    provider = SafeGitProvenanceProvider(
        executable=str(tmp_path / "missing-git"),
    )

    assert provider.inspect(tmp_path) == GitProvenance(commit=None, dirty=None)


def test_git_queries_do_not_create_lock_files(tmp_path: Path) -> None:
    """Read-only provenance leaves no Git index lock behind."""

    root = tmp_path / "repo"
    initialize_repository(root)

    SafeGitProvenanceProvider().inspect(root)

    assert not (root / ".git" / "index.lock").exists()


def test_unborn_repository_has_absent_provenance(tmp_path: Path) -> None:
    """A newly initialized repository without HEAD can still create a baseline."""

    root = tmp_path / "repo"
    root.mkdir()
    run_git(root, "init", "--quiet")
    (root / "AGENTS.md").write_text("safe\n", encoding="utf-8")

    assert SafeGitProvenanceProvider().inspect(root) == GitProvenance(
        commit=None,
        dirty=None,
    )


def test_generated_baseline_path_can_be_excluded_from_dirty_state(
    tmp_path: Path,
) -> None:
    """Regenerating an untracked local baseline does not taint source provenance."""

    root = tmp_path / "repo"
    commit = initialize_repository(root)
    output = root / ".agentsec" / "baseline.json"
    output.parent.mkdir()
    output.write_text("existing generated file\n", encoding="utf-8")

    provenance = SafeGitProvenanceProvider().inspect(
        root,
        excluded_paths=(output,),
    )

    assert provenance == GitProvenance(commit=commit, dirty=False)

"""P1-31 package metadata and release-script checks."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]


def test_release_metadata_exposes_the_console_script_and_alpha_status() -> None:
    """The 0.1.0 distribution metadata matches the accepted PoC surface."""

    payload = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = payload["project"]

    assert project["name"] == "agentsec"
    assert project["dynamic"] == ["version"]
    assert project["scripts"] == {"agentsec": "agentsec.cli:main"}
    assert "Development Status :: 3 - Alpha" in project["classifiers"]
    assert (REPOSITORY_ROOT / "LICENSE").is_file()


def test_sdist_manifest_includes_release_evidence() -> None:
    """The source release retains docs, Schemas, Demo, tests, and scripts."""

    manifest = (REPOSITORY_ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    for required in (
        "LICENSE",
        "CHANGELOG.md",
        "recursive-include docs *.md",
        "recursive-include .github *.yaml *.yml",
        "recursive-include policies *.json *.yaml *.yml",
        "recursive-include pilots *.json *.md *.yaml *.yml",
        "recursive-include schemas *.json *.md",
        "recursive-include demos *.json *.md *.sha256 *.toml *.txt",
        "recursive-include scripts *.py *.sh",
        "recursive-include testdata *.json *.md",
        "recursive-include tests *.md *.py",
    ):
        assert required in manifest


def test_release_scripts_are_executable() -> None:
    """The accepted build, verification, release, and Demo entry points can run."""

    for relative_path in (
        "scripts/build-release.sh",
        "scripts/verify-release-install.sh",
        "scripts/release-check.sh",
        "scripts/run-demo.sh",
        "scripts/run-capability-demo.sh",
        "scripts/demo-capability-drift.sh",
        "scripts/run-agentsec-ci.sh",
        "scripts/run-pilot.py",
        "scripts/run-rule-score-calibration.py",
        "scripts/reconcile-candidate-artifacts.py",
    ):
        mode = (REPOSITORY_ROOT / relative_path).stat().st_mode
        assert mode & os.X_OK


def test_release_scripts_derive_version_and_preserve_versioned_artifacts() -> None:
    """Phase 2 release tooling no longer hard-codes or replaces 0.1.0 files."""

    build = (REPOSITORY_ROOT / "scripts" / "build-release.sh").read_text(
        encoding="utf-8"
    )
    verify = (REPOSITORY_ROOT / "scripts" / "verify-release-install.sh").read_text(
        encoding="utf-8"
    )

    assert "PACKAGE_VERSION" in build
    assert 'release_dir="$dist_root/$release_version"' in build
    assert "agentsec-0.1.0" not in build
    assert "PACKAGE_VERSION" in verify
    assert 'release_dir="$repository_root/dist/$release_version"' in verify
    assert "agentsec-0.1.0" not in verify
    assert "--no-index" in verify
    assert "agentsec-offline-dependencies.pth" in verify
    assert "P2-13 source development is not releasable as Package 0.2.0" in build

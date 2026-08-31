"""Accepted 0.2.0 release-candidate artifact acceptance tests.

P2-13 source development is intentionally not compared byte-for-byte with the
accepted 0.2.0 candidate. Set ``AGENTSEC_VERIFY_CANDIDATE_SOURCE=1`` only during
a dedicated release review after rebuilding the candidate for the current tree.
"""

from __future__ import annotations

import hashlib
import os
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

import pytest

REPOSITORY_ROOT = Path(__file__).parents[1]
ACCEPTED_RELEASE_VERSION = "0.2.0"
VERIFY_CURRENT_SOURCE = os.environ.get("AGENTSEC_VERIFY_CANDIDATE_SOURCE") == "1"
RELEASE_DIR = REPOSITORY_ROOT / "dist" / ACCEPTED_RELEASE_VERSION
WHEEL_GLOB = f"agentsec-{ACCEPTED_RELEASE_VERSION}-*.whl"
SDIST_NAME = f"agentsec-{ACCEPTED_RELEASE_VERSION}.tar.gz"
CHECKSUM_NAME = "SHA256SUMS"


def _release_paths() -> tuple[Path, Path, Path]:
    """Return the unique local candidate files, or skip source-only checks."""

    if not RELEASE_DIR.is_dir():
        pytest.skip(
            "local release candidate is absent; scripts/release-check.sh builds and "
            "then verifies it"
        )

    wheels = sorted(RELEASE_DIR.glob(WHEEL_GLOB))
    sdists = sorted(RELEASE_DIR.glob(f"agentsec-{ACCEPTED_RELEASE_VERSION}*.tar.gz"))
    checksums = sorted(RELEASE_DIR.glob(CHECKSUM_NAME))
    assert len(wheels) == 1
    assert [path.name for path in sdists] == [SDIST_NAME]
    assert [path.name for path in checksums] == [CHECKSUM_NAME]
    assert sorted(path.name for path in RELEASE_DIR.iterdir()) == sorted(
        [wheels[0].name, SDIST_NAME, CHECKSUM_NAME]
    )
    return wheels[0], sdists[0], checksums[0]


def _archive_contains_suffix(names: set[str], suffix: str) -> bool:
    """Return whether an sdist member has the required root-relative suffix."""

    return any(name.endswith(f"/{suffix}") for name in names)


def _assert_sdist_member_matches_source(
    archive: tarfile.TarFile,
    *,
    root_name: str,
    relative_path: str,
) -> None:
    """Assert that one sdist member exists and matches the reviewed source."""

    member = archive.extractfile(f"{root_name}/{relative_path}")
    assert member is not None
    assert member.read() == (REPOSITORY_ROOT / relative_path).read_bytes()


def _reviewed_sdist_source_paths() -> tuple[Path, ...]:
    """Return every reviewed source path selected by the sdist manifest."""

    selected = {
        REPOSITORY_ROOT / name
        for name in (
            "AGENTS.md",
            "CHANGELOG.md",
            "CONTEXT.md",
            "LICENSE",
            "MANIFEST.in",
            "README.md",
            "pyproject.toml",
        )
    }
    roots_and_suffixes = (
        ("src/agentsec", {".py"}),
        ("demos", {".json", ".md", ".sha256", ".toml", ".txt"}),
        ("docs", {".md"}),
        ("schemas", {".json", ".md"}),
        ("scripts", {".py", ".sh"}),
        ("testdata", {".json", ".md"}),
        ("tests", {".md", ".py"}),
    )
    for root, suffixes in roots_and_suffixes:
        selected.update(
            path
            for path in (REPOSITORY_ROOT / root).rglob("*")
            if path.is_file() and path.suffix in suffixes
        )
    return tuple(sorted(selected))


def test_phase2_release_candidate_has_exact_artifact_set_and_checksums() -> None:
    """The preserved candidate has one wheel, one sdist, and matching digests."""

    wheel, sdist, checksum_path = _release_paths()
    entries: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, filename = line.partition("  ")
        assert separator == "  "
        assert len(digest) == 64
        assert all(character in "0123456789abcdef" for character in digest)
        assert PurePosixPath(filename).name == filename
        assert filename not in entries
        entries[filename] = digest

    assert set(entries) == {wheel.name, sdist.name}
    for artifact in (wheel, sdist):
        assert artifact.is_file()
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert actual == entries[artifact.name]


def test_phase2_wheel_metadata_entry_point_and_modules_are_complete() -> None:
    """The wheel exposes 0.2.0 and contains the integrated Phase 2 product path."""

    wheel, _, _ = _release_paths()
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_names = sorted(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        entry_point_names = sorted(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        assert len(metadata_names) == 1
        assert len(entry_point_names) == 1

        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        entry_points = archive.read(entry_point_names[0]).decode("utf-8")
        assert metadata["Name"] == "agentsec"
        assert metadata["Version"] == ACCEPTED_RELEASE_VERSION
        assert "agentsec = agentsec.cli:main" in entry_points

        required_modules = {
            "agentsec/application/agent_analysis.py",
            "agentsec/application/capability_assessment.py",
            "agentsec/application/capability_diff.py",
            "agentsec/artifacts/storage.py",
            "agentsec/capability_rules/base.py",
            "agentsec/capability_rules/builtin.py",
            "agentsec/capability_rules/pipeline.py",
            "agentsec/cli/app.py",
            "agentsec/cli/capability.py",
            "agentsec/cli/manifest.py",
            "agentsec/frameworks/codex.py",
            "agentsec/manifests/diff.py",
            "agentsec/manifests/models.py",
            "agentsec/manifests/validation.py",
            "agentsec/reporting/capability_assessment.py",
            "agentsec/reporting/capability_assessment_json.py",
            "agentsec/reporting/capability_diff.py",
            "agentsec/reporting/manifest.py",
            "agentsec/versioning.py",
        }
        assert required_modules <= names
        if VERIFY_CURRENT_SOURCE:
            for source_path in sorted(
                (REPOSITORY_ROOT / "src" / "agentsec").rglob("*.py")
            ):
                archive_name = source_path.relative_to(
                    REPOSITORY_ROOT / "src"
                ).as_posix()
                assert archive_name in names
                assert archive.read(archive_name) == source_path.read_bytes()


def test_phase2_sdist_contains_release_evidence_schemas_demos_and_scripts() -> None:
    """The sdist is independently reviewable and can replay both Demo languages."""

    _, sdist, _ = _release_paths()
    required_release_files = {
        "AGENTS.md",
        "CHANGELOG.md",
        "LICENSE",
        "MANIFEST.in",
        "README.md",
        "docs/decisions/0032-phase2-integration-release-0.2.0.md",
        f"docs/releases/{ACCEPTED_RELEASE_VERSION}.md",
        f"docs/releases/{ACCEPTED_RELEASE_VERSION}-known-limitations.md",
        f"docs/releases/{ACCEPTED_RELEASE_VERSION}-acceptance.md",
        "docs/phase2-integration-plan.md",
        "docs/phase2-scope.md",
        "schemas/manifest/agent-manifest.schema.json",
        "schemas/capability-diff/capability-diff.schema.json",
        "schemas/capability-assessment/capability-assessment.schema.json",
        "scripts/build-release.sh",
        "scripts/release-check.sh",
        "scripts/run-capability-demo.sh",
        "scripts/validate_capability_demo_outputs.py",
        "scripts/verify-release-install.sh",
        "tests/test_phase2_release_candidate.py",
    }
    required_demo_files: set[str] = set()
    for demo_name in ("capability-drift-agent", "capability-drift-agent-zh"):
        required_demo_files.update(
            {
                f"demos/{demo_name}/README.md",
                f"demos/{demo_name}/acceptance.md",
                f"demos/{demo_name}/demo-script.md",
                f"demos/{demo_name}/baseline/AGENTS.md",
                f"demos/{demo_name}/risky-drift/.codex/config.toml",
                f"demos/{demo_name}/expected/checksums.sha256",
                f"demos/{demo_name}/expected/baseline.manifest.json",
                f"demos/{demo_name}/expected/baseline.manifest.txt",
                f"demos/{demo_name}/expected/risky-drift.assessment.json",
                f"demos/{demo_name}/expected/risky-drift.assessment.txt",
                f"demos/{demo_name}/expected/risky.diff.json",
                f"demos/{demo_name}/expected/risky.diff.txt",
                f"demos/{demo_name}/expected/management-summary.json",
            }
        )

    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        root_name = f"agentsec-{ACCEPTED_RELEASE_VERSION}"
        assert root_name in names
        for relative_path in required_release_files | required_demo_files:
            assert _archive_contains_suffix(names, relative_path), relative_path
        if VERIFY_CURRENT_SOURCE:
            for relative_path in required_release_files | required_demo_files:
                _assert_sdist_member_matches_source(
                    archive,
                    root_name=root_name,
                    relative_path=relative_path,
                )
            for source_path in _reviewed_sdist_source_paths():
                relative_path = source_path.relative_to(REPOSITORY_ROOT).as_posix()
                assert f"{root_name}/{relative_path}" in names, relative_path
                _assert_sdist_member_matches_source(
                    archive,
                    root_name=root_name,
                    relative_path=relative_path,
                )

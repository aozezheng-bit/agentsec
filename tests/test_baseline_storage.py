"""Security and atomicity tests for baseline filesystem output."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.baselines import (
    Baseline,
    BaselineAsset,
    BaselineFileWriter,
    BaselineMetadata,
    BaselineWriteCode,
    BaselineWriteError,
    decode_baseline_json,
    encode_baseline_json,
)
from agentsec.domain import AssetSource, AssetType
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions


def make_baseline(content: str = "# Agent\n\nSafe.\n") -> Baseline:
    """Create one exact baseline suitable for storage tests."""

    content_bytes = content.encode("utf-8")
    versions = current_versions()
    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        metadata=BaselineMetadata(
            scanner_version=versions.package,
            config_schema_version=versions.config_schema,
            domain_schema_version=versions.domain_schema,
            rule_pack_version=versions.rule_pack,
            risk_model_version=versions.risk_model,
            collection_config_sha256="c" * 64,
            generated_at=datetime(2026, 8, 18, 13, 30, tzinfo=UTC),
            git_commit=None,
            git_dirty=None,
        ),
        assets=(
            BaselineAsset(
                path="AGENTS.md",
                asset_type=AssetType.AGENTS,
                source=AssetSource.DISCOVERED,
                sha256=hashlib.sha256(content_bytes).hexdigest(),
                size_bytes=len(content_bytes),
                line_count=len(content.splitlines()),
                content=content,
            ),
        ),
    )


def test_writer_creates_valid_mode_0600_file_atomically(tmp_path: Path) -> None:
    """A new baseline is complete, private, and leaves no temporary files."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "output" / "baseline.json"
    writer = BaselineFileWriter()

    result = writer.write(
        make_baseline(),
        output,
        project_root=project_root,
        config_path=None,
    )

    assert result.path == output.resolve()
    assert result.replaced is False
    assert result.size_bytes == output.stat().st_size
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert decode_baseline_json(output.read_text(encoding="utf-8")) == make_baseline()
    assert list(output.parent.glob(".baseline.json.*.tmp")) == []


def test_writer_does_not_overwrite_existing_file_by_default(tmp_path: Path) -> None:
    """Baseline updates require a separate explicit `--force` decision."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "baseline.json"
    original = encode_baseline_json(make_baseline("old\n"))
    output.write_text(original, encoding="utf-8")

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline("new\n"),
            output,
            project_root=project_root,
            config_path=None,
        )

    assert captured.value.code is BaselineWriteCode.OUTPUT_EXISTS
    assert output.read_text(encoding="utf-8") == original


def test_force_replaces_only_an_existing_valid_baseline(tmp_path: Path) -> None:
    """Explicit replacement preserves validation and private file permissions."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "baseline.json"
    output.write_text(encode_baseline_json(make_baseline("old\n")), encoding="utf-8")

    result = BaselineFileWriter().write(
        make_baseline("new\n"),
        output,
        project_root=project_root,
        config_path=None,
        force=True,
    )

    assert result.replaced is True
    assert decode_baseline_json(output.read_text(encoding="utf-8")) == make_baseline(
        "new\n"
    )
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_force_rejects_unrelated_existing_file_without_modifying_it(
    tmp_path: Path,
) -> None:
    """`--force` cannot be used as an arbitrary file-overwrite primitive."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "important.json"
    original = "unrelated-sensitive-placeholder\n"
    output.write_text(original, encoding="utf-8")

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
            force=True,
        )

    assert captured.value.code is BaselineWriteCode.EXISTING_OUTPUT_INVALID
    assert output.read_text(encoding="utf-8") == original


def test_writer_rejects_symbolic_link_output(tmp_path: Path) -> None:
    """Final symlinks are never followed or replaced by baseline creation."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    target = tmp_path / "target.json"
    target.write_text("keep\n", encoding="utf-8")
    output = tmp_path / "baseline.json"
    output.symlink_to(target)

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
            force=True,
        )

    assert captured.value.code is BaselineWriteCode.INVALID_OUTPUT_PATH
    assert target.read_text(encoding="utf-8") == "keep\n"
    assert output.is_symlink()


def test_writer_rejects_scanned_asset_and_config_targets(tmp_path: Path) -> None:
    """Even explicit force cannot replace input assets or effective configuration."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    asset_path = project_root / "AGENTS.md"
    asset_path.write_text("original-agent\n", encoding="utf-8")
    config_path = project_root / "config.json"
    config_path.write_text("original-config\n", encoding="utf-8")
    writer = BaselineFileWriter()

    with pytest.raises(BaselineWriteError) as asset_error:
        writer.write(
            make_baseline(),
            asset_path,
            project_root=project_root,
            config_path=config_path,
            force=True,
        )
    with pytest.raises(BaselineWriteError) as config_error:
        writer.write(
            make_baseline(),
            config_path,
            project_root=project_root,
            config_path=config_path,
            force=True,
        )

    assert asset_error.value.code is BaselineWriteCode.INVALID_OUTPUT_PATH
    assert config_error.value.code is BaselineWriteCode.PROTECTED_OUTPUT_PATH
    assert asset_path.read_text(encoding="utf-8") == "original-agent\n"
    assert config_path.read_text(encoding="utf-8") == "original-config\n"


def test_writer_enforces_hard_encoded_size_limit(tmp_path: Path) -> None:
    """A baseline exceeding the output limit creates no directory or file."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "output" / "baseline.json"
    writer = BaselineFileWriter(max_file_size_bytes=32)

    with pytest.raises(BaselineWriteError) as captured:
        writer.write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
        )

    assert captured.value.code is BaselineWriteCode.OUTPUT_TOO_LARGE
    assert not output.exists()


def test_force_rejects_oversized_existing_baseline(tmp_path: Path) -> None:
    """Existing replacement candidates are read with the same hard bound."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "baseline.json"
    output.write_bytes(b"x" * 2049)
    writer = BaselineFileWriter(max_file_size_bytes=2048)

    with pytest.raises(BaselineWriteError) as captured:
        writer.write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
            force=True,
        )

    assert captured.value.code is BaselineWriteCode.EXISTING_OUTPUT_INVALID
    assert output.read_bytes() == b"x" * 2049


def test_writer_rejects_directory_output(tmp_path: Path) -> None:
    """A directory is never recursively replaced by a baseline file."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "baseline.json"
    output.mkdir()

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
            force=True,
        )

    assert captured.value.code is BaselineWriteCode.INVALID_OUTPUT_PATH
    assert output.is_dir()


def test_no_clobber_race_preserves_competing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic link failure does not overwrite a file that appears mid-write."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "baseline.json"
    original_link = os.link

    def competing_link(source: Path, target: Path) -> None:
        output.write_text("competitor\n", encoding="utf-8")
        original_link(source, target)

    monkeypatch.setattr(os, "link", competing_link)

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
        )

    assert captured.value.code is BaselineWriteCode.OUTPUT_EXISTS
    assert output.read_text(encoding="utf-8") == "competitor\n"
    assert list(tmp_path.glob(".baseline.json.*.tmp")) == []


def test_writer_requires_json_filename(tmp_path: Path) -> None:
    """Baseline output cannot masquerade as Markdown, YAML, or another asset type."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    output = tmp_path / "AGENTS.md"

    with pytest.raises(BaselineWriteError) as captured:
        BaselineFileWriter().write(
            make_baseline(),
            output,
            project_root=project_root,
            config_path=None,
        )

    assert captured.value.code is BaselineWriteCode.INVALID_OUTPUT_PATH
    assert not output.exists()

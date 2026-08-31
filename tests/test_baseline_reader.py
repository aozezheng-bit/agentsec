"""Security tests for bounded Baseline file loading."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.baselines import (
    Baseline,
    BaselineAsset,
    BaselineFileReader,
    BaselineMetadata,
    BaselineReadCode,
    BaselineReadError,
    encode_baseline_json,
)
from agentsec.domain import AssetSource, AssetType
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions


def make_baseline(content: str = "safe\n") -> Baseline:
    """Create one exact Baseline for reader tests."""

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
            generated_at=datetime(2026, 8, 18, 16, 0, tzinfo=UTC),
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


def test_reader_loads_valid_regular_baseline(tmp_path: Path) -> None:
    """Validated content and resolved filesystem provenance are returned."""

    path = tmp_path / "baseline.json"
    baseline = make_baseline()
    path.write_text(encode_baseline_json(baseline), encoding="utf-8")

    result = BaselineFileReader().read(path)

    assert result.baseline == baseline
    assert result.path == path.resolve()
    assert result.size_bytes == path.stat().st_size


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("missing.json", BaselineReadCode.MISSING),
        ("baseline.txt", BaselineReadCode.INVALID_PATH),
    ],
)
def test_reader_rejects_missing_or_wrong_suffix(
    tmp_path: Path,
    name: str,
    code: BaselineReadCode,
) -> None:
    """Operator mistakes have stable safe failure categories."""

    path = tmp_path / name
    if path.suffix != ".json":
        path.write_text("not read\n", encoding="utf-8")

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader().read(path)

    assert captured.value.code is code


def test_reader_rejects_symbolic_link_without_following_target(tmp_path: Path) -> None:
    """An explicit Baseline path cannot redirect reads through a final symlink."""

    target = tmp_path / "target.json"
    target.write_text(encode_baseline_json(make_baseline()), encoding="utf-8")
    link = tmp_path / "baseline.json"
    link.symlink_to(target)

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader().read(link)

    assert captured.value.code is BaselineReadCode.SYMBOLIC_LINK
    assert target.is_file()


def test_reader_rejects_directory_named_json(tmp_path: Path) -> None:
    """Only regular files are accepted as Baseline inputs."""

    path = tmp_path / "baseline.json"
    path.mkdir()

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader().read(path)

    assert captured.value.code is BaselineReadCode.INVALID_PATH


def test_reader_enforces_hard_size_bound_before_json_decode(tmp_path: Path) -> None:
    """Oversized input never reaches UTF-8 or JSON parsing."""

    path = tmp_path / "baseline.json"
    path.write_bytes(b"x" * 33)

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader(max_file_size_bytes=32).read(path)

    assert captured.value.code is BaselineReadCode.TOO_LARGE


def test_reader_rejects_invalid_utf8_without_leaking_bytes(tmp_path: Path) -> None:
    """Invalid encoded content remains behind a generic safe error."""

    path = tmp_path / "baseline.json"
    path.write_bytes(b'{"schema_version":"0.1.0","secret":"\xff"}')

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader().read(path)

    assert captured.value.code is BaselineReadCode.INVALID_UTF8
    assert "secret" not in str(captured.value)


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        '{"schema_version":"0.2.0"}',
        '{"schema_version":"0.1.0","secret":"reader-secret"}',
    ],
)
def test_reader_wraps_invalid_or_incompatible_payload_safely(
    tmp_path: Path,
    content: str,
) -> None:
    """Schema diagnostics never copy rejected Baseline values."""

    path = tmp_path / "baseline.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(BaselineReadError) as captured:
        BaselineFileReader().read(path)

    assert captured.value.code is BaselineReadCode.INVALID_BASELINE
    assert "reader-secret" not in str(captured.value)


def test_reader_rejects_non_positive_limit() -> None:
    """Callers cannot disable the Baseline input bound."""

    with pytest.raises(ValueError):
        BaselineFileReader(max_file_size_bytes=0)

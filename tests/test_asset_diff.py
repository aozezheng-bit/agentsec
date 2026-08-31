"""Unit and integration tests for deterministic file-level Asset Diff."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec.application import BaselineCreationRequest, CollectionBaselineCreator
from agentsec.baselines import (
    Baseline,
    BaselineAsset,
    BaselineMetadata,
    GitProvenance,
    fingerprint_collection_config,
)
from agentsec.collectors import (
    CollectedAsset,
    CollectionResult,
    MarkdownAssetCollector,
)
from agentsec.config import default_project_config
from agentsec.diffing import (
    AssetDiffCode,
    AssetDiffError,
    DeterministicAssetDiffer,
)
from agentsec.domain import (
    AgentAsset,
    AssetSource,
    AssetType,
    ChangeType,
    CoverageIssue,
    CoverageIssueCode,
    ScanCoverage,
)
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions

CONFIG_HASH = "c" * 64


class NoGitProvenanceProvider:
    """Keep integration tests independent from the host repository state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        return GitProvenance(commit=None, dirty=None)


def make_metadata(*, config_hash: str = CONFIG_HASH) -> BaselineMetadata:
    """Create deterministic Baseline metadata for pure diff tests."""

    versions = current_versions()
    return BaselineMetadata(
        scanner_version=versions.package,
        config_schema_version=versions.config_schema,
        domain_schema_version=versions.domain_schema,
        rule_pack_version=versions.rule_pack,
        risk_model_version=versions.risk_model,
        collection_config_sha256=config_hash,
        generated_at=datetime(2026, 8, 18, 14, 0, tzinfo=UTC),
        git_commit=None,
        git_dirty=None,
    )


def make_baseline_asset(
    path: str,
    content: str,
    *,
    asset_type: AssetType = AssetType.EXPLICIT_MARKDOWN,
) -> BaselineAsset:
    """Create one exact Baseline asset."""

    content_bytes = content.encode("utf-8")
    return BaselineAsset(
        path=path,
        asset_type=asset_type,
        source=AssetSource.DISCOVERED,
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        size_bytes=len(content_bytes),
        line_count=len(content.splitlines()),
        content=content,
    )


def make_current_asset(
    path: str,
    content: str,
    *,
    asset_type: AssetType = AssetType.EXPLICIT_MARKDOWN,
    source: AssetSource = AssetSource.DISCOVERED,
) -> CollectedAsset:
    """Create one current collected asset with matching metadata."""

    content_bytes = content.encode("utf-8")
    asset = AgentAsset(
        path=path,
        asset_type=asset_type,
        source=source,
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        size_bytes=len(content_bytes),
        line_count=len(content.splitlines()),
    )
    return CollectedAsset(asset=asset, content=content)


def make_collection(*assets: CollectedAsset) -> CollectionResult:
    """Wrap current assets in complete deterministic collection coverage."""

    return CollectionResult(
        assets=assets,
        coverage=ScanCoverage(
            discovered_assets=len(assets),
            scanned_assets=len(assets),
            skipped_assets=0,
            complete=True,
        ),
    )


def make_baseline(*assets: BaselineAsset, config_hash: str = CONFIG_HASH) -> Baseline:
    """Create a valid Baseline whose assets are canonically sorted."""

    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        metadata=make_metadata(config_hash=config_hash),
        assets=tuple(sorted(assets, key=lambda asset: asset.path)),
    )


def test_identical_paths_and_hashes_produce_no_changes() -> None:
    """An unchanged asset set remains empty and explicitly scope-compatible."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "same\n"))
    current = make_current_asset("AGENTS.md", "same\n")

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(current),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert result.changes == ()
    assert result.has_changes is False
    assert result.collection_config_matches is True


def test_added_removed_and_modified_changes_include_required_hashes() -> None:
    """Every file-level state carries exactly the before/after digest it needs."""

    before_modified = make_baseline_asset("AGENTS.md", "before\n")
    before_removed = make_baseline_asset("old/SKILL.md", "removed\n")
    baseline = make_baseline(before_modified, before_removed)
    after_modified = make_current_asset("AGENTS.md", "after\n")
    after_added = make_current_asset("new/SKILL.md", "added\n")

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(after_added, after_modified),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert [change.path for change in result.changes] == [
        "AGENTS.md",
        "new/SKILL.md",
        "old/SKILL.md",
    ]
    modified, added, removed = result.changes
    assert modified.change_type is ChangeType.MODIFIED
    assert modified.before_sha256 == before_modified.sha256
    assert modified.after_sha256 == after_modified.asset.sha256
    assert added.change_type is ChangeType.ADDED
    assert added.before_sha256 is None
    assert added.after_sha256 == after_added.asset.sha256
    assert removed.change_type is ChangeType.REMOVED
    assert removed.before_sha256 == before_removed.sha256
    assert removed.after_sha256 is None


def test_current_input_order_does_not_change_output() -> None:
    """Filesystem or adapter ordering cannot affect serialized Diff order."""

    baseline = make_baseline()
    first = make_current_asset("z/SKILL.md", "z\n")
    second = make_current_asset("a/AGENTS.md", "a\n")
    differ = DeterministicAssetDiffer()

    forward = differ.compare(
        baseline=baseline,
        current_collection=make_collection(first, second),
        current_collection_config_sha256=CONFIG_HASH,
    )
    reverse = differ.compare(
        baseline=baseline,
        current_collection=make_collection(second, first),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert forward == reverse
    assert [change.path for change in forward.changes] == [
        "a/AGENTS.md",
        "z/SKILL.md",
    ]


def test_empty_sides_produce_all_added_or_all_removed() -> None:
    """Empty projects remain a well-defined set comparison."""

    asset = make_baseline_asset("AGENTS.md", "before\n")
    differ = DeterministicAssetDiffer()
    all_removed = differ.compare(
        baseline=make_baseline(asset),
        current_collection=make_collection(),
        current_collection_config_sha256=CONFIG_HASH,
    )
    all_added = differ.compare(
        baseline=make_baseline(),
        current_collection=make_collection(make_current_asset("AGENTS.md", "after\n")),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert [change.change_type for change in all_removed.changes] == [
        ChangeType.REMOVED
    ]
    assert [change.change_type for change in all_added.changes] == [ChangeType.ADDED]


def test_path_rename_is_removed_plus_added() -> None:
    """File identity is the exact project-relative path rather than content hash."""

    content = "same content\n"
    baseline = make_baseline(make_baseline_asset("old/AGENTS.md", content))
    current = make_current_asset("new/AGENTS.md", content)

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(current),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert [(change.path, change.change_type) for change in result.changes] == [
        ("new/AGENTS.md", ChangeType.ADDED),
        ("old/AGENTS.md", ChangeType.REMOVED),
    ]


def test_metadata_only_change_with_same_hash_is_not_content_drift() -> None:
    """P1-14 intentionally compares path and content hash, not capability metadata."""

    content = "same\n"
    baseline = make_baseline(
        make_baseline_asset(
            "AGENTS.md",
            content,
            asset_type=AssetType.AGENTS,
        )
    )
    current = make_current_asset(
        "AGENTS.md",
        content,
        asset_type=AssetType.SKILL,
        source=AssetSource.EXPLICIT,
    )

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(current),
        current_collection_config_sha256=CONFIG_HASH,
    )

    assert result.changes == ()


def test_collection_config_change_is_separate_from_asset_changes() -> None:
    """Scope mismatch is visible without inventing a file-level AssetChange."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "same\n"))
    current = make_current_asset("AGENTS.md", "same\n")

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(current),
        current_collection_config_sha256="d" * 64,
    )

    assert result.changes == ()
    assert result.collection_config_matches is False


@pytest.mark.parametrize("fingerprint", ["", "not-a-hash", "A" * 64, "a" * 63])
def test_invalid_current_collection_fingerprint_is_rejected(fingerprint: str) -> None:
    """Callers cannot silently omit or corrupt collection-scope provenance."""

    with pytest.raises(AssetDiffError) as captured:
        DeterministicAssetDiffer().compare(
            baseline=make_baseline(),
            current_collection=make_collection(),
            current_collection_config_sha256=fingerprint,
        )

    assert captured.value.code is AssetDiffCode.INVALID_COLLECTION_CONFIG_HASH


def test_duplicate_current_paths_fail_without_copying_content() -> None:
    """Ambiguous current identity is a safe deterministic error."""

    secret = "duplicate-current-secret"
    first = make_current_asset("AGENTS.md", secret)
    second = make_current_asset("AGENTS.md", "other\n")

    with pytest.raises(AssetDiffError) as captured:
        DeterministicAssetDiffer().compare(
            baseline=make_baseline(),
            current_collection=make_collection(first, second),
            current_collection_config_sha256=CONFIG_HASH,
        )

    assert captured.value.code is AssetDiffCode.DUPLICATE_CURRENT_PATH
    assert secret not in str(captured.value)


def test_duplicate_baseline_paths_are_defended_even_if_model_was_bypassed() -> None:
    """The differ does not rely only on callers respecting Pydantic construction."""

    asset = make_baseline_asset("AGENTS.md", "same\n")
    invalid_baseline = Baseline.model_construct(
        schema_version=BASELINE_SCHEMA_VERSION,
        metadata=make_metadata(),
        assets=(asset, asset),
    )

    with pytest.raises(AssetDiffError) as captured:
        DeterministicAssetDiffer().compare(
            baseline=invalid_baseline,
            current_collection=make_collection(),
            current_collection_config_sha256=CONFIG_HASH,
        )

    assert captured.value.code is AssetDiffCode.DUPLICATE_BASELINE_PATH


def test_diff_result_contains_hashes_but_not_asset_content() -> None:
    """File Diff remains compact evidence and cannot leak full Baseline text."""

    secret = "asset-diff-secret-content"
    baseline = make_baseline(make_baseline_asset("AGENTS.md", secret))

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=make_collection(),
        current_collection_config_sha256=CONFIG_HASH,
    )
    payload = result.changes[0].model_dump(mode="json")

    assert set(payload) == {
        "path",
        "change_type",
        "before_sha256",
        "after_sha256",
    }
    assert secret not in str(payload)


def test_real_baseline_to_current_collection_detects_three_change_types(
    tmp_path: Path,
) -> None:
    """P1-13 output and the current collector integrate through P1-14."""

    keep_directory = tmp_path / "keep"
    old_directory = tmp_path / "old"
    keep_directory.mkdir()
    old_directory.mkdir()
    (tmp_path / "AGENTS.md").write_text("before\n", encoding="utf-8")
    (keep_directory / "SKILL.md").write_text("same\n", encoding="utf-8")
    (old_directory / "SKILL.md").write_text("removed\n", encoding="utf-8")
    config = default_project_config()
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=NoGitProvenanceProvider(),
        clock=lambda: datetime(2026, 8, 18, 14, 30, tzinfo=UTC),
    )
    baseline = creator.create(
        BaselineCreationRequest(
            project_root=tmp_path,
            config=config,
            config_path=None,
            output_path=tmp_path / ".agentsec/baseline.json",
        )
    )

    (tmp_path / "AGENTS.md").write_text("after\n", encoding="utf-8")
    (old_directory / "SKILL.md").unlink()
    new_directory = tmp_path / "new"
    new_directory.mkdir()
    (new_directory / "SKILL.md").write_text("added\n", encoding="utf-8")
    current = MarkdownAssetCollector().collect(tmp_path, config)

    result = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=current,
        current_collection_config_sha256=fingerprint_collection_config(config),
    )

    assert current.coverage.complete is True
    assert [(change.path, change.change_type) for change in result.changes] == [
        ("AGENTS.md", ChangeType.MODIFIED),
        ("new/SKILL.md", ChangeType.ADDED),
        ("old/SKILL.md", ChangeType.REMOVED),
    ]
    assert result.collection_config_matches is True


def test_incomplete_current_collection_fails_instead_of_reporting_removed() -> None:
    """A skipped current asset is unknown coverage, never evidence of deletion."""

    incomplete = CollectionResult(
        assets=(),
        coverage=ScanCoverage(
            discovered_assets=1,
            scanned_assets=0,
            skipped_assets=1,
            complete=False,
            issues=(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Asset could not be read.",
                    asset_path="AGENTS.md",
                ),
            ),
        ),
    )

    with pytest.raises(AssetDiffError) as captured:
        DeterministicAssetDiffer().compare(
            baseline=make_baseline(make_baseline_asset("AGENTS.md", "before\n")),
            current_collection=incomplete,
            current_collection_config_sha256=CONFIG_HASH,
        )

    assert captured.value.code is AssetDiffCode.INCOMPLETE_CURRENT_COVERAGE
    assert "AGENTS.md" not in str(captured.value)

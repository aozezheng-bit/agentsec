"""Tests for bounded deterministic line-oriented Text Diff."""

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
    AssetDiffResult,
    DeterministicAssetDiffer,
    DeterministicTextDiffer,
    TextDiffCode,
    TextDiffError,
    TextDiffLimits,
    TextDiffLineKind,
    TextDiffStatus,
)
from agentsec.domain import (
    AgentAsset,
    AssetChange,
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
    """Keep integration tests independent from repository state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        return GitProvenance(commit=None, dirty=None)


def make_metadata() -> BaselineMetadata:
    """Create deterministic Baseline metadata."""

    versions = current_versions()
    return BaselineMetadata(
        scanner_version=versions.package,
        config_schema_version=versions.config_schema,
        domain_schema_version=versions.domain_schema,
        rule_pack_version=versions.rule_pack,
        risk_model_version=versions.risk_model,
        collection_config_sha256=CONFIG_HASH,
        generated_at=datetime(2026, 8, 18, 15, 0, tzinfo=UTC),
        git_commit=None,
        git_dirty=None,
    )


def make_baseline_asset(path: str, content: str) -> BaselineAsset:
    """Create one exact Baseline asset."""

    content_bytes = content.encode("utf-8")
    return BaselineAsset(
        path=path,
        asset_type=AssetType.EXPLICIT_MARKDOWN,
        source=AssetSource.DISCOVERED,
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        size_bytes=len(content_bytes),
        line_count=len(content.splitlines()),
        content=content,
    )


def make_collected_asset(path: str, content: str) -> CollectedAsset:
    """Create one current collected asset with matching exact content."""

    content_bytes = content.encode("utf-8")
    return CollectedAsset(
        asset=AgentAsset(
            path=path,
            asset_type=AssetType.EXPLICIT_MARKDOWN,
            source=AssetSource.DISCOVERED,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
        ),
        content=content,
    )


def make_baseline(*assets: BaselineAsset) -> Baseline:
    """Create a valid sorted Baseline."""

    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        metadata=make_metadata(),
        assets=tuple(sorted(assets, key=lambda asset: asset.path)),
    )


def make_collection(*assets: CollectedAsset) -> CollectionResult:
    """Create complete collection coverage for current assets."""

    return CollectionResult(
        assets=assets,
        coverage=ScanCoverage(
            discovered_assets=len(assets),
            scanned_assets=len(assets),
            skipped_assets=0,
            complete=True,
        ),
    )


def make_diff(
    baseline: Baseline,
    collection: CollectionResult,
) -> AssetDiffResult:
    """Generate coherent P1-14 input for Text Diff."""

    return DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=collection,
        current_collection_config_sha256=CONFIG_HASH,
    )


def test_modified_replacement_preserves_context_and_exact_line_numbers() -> None:
    """A replacement hunk retains bounded context and both original positions."""

    before = "header\nkeep-before\nold-a\nold-b\nkeep-after\ntail\n"
    after = "header\nkeep-before\nnew-a\nnew-b\nkeep-after\ntail\n"
    baseline = make_baseline(make_baseline_asset("AGENTS.md", before))
    collection = make_collection(make_collected_asset("AGENTS.md", after))

    result = DeterministicTextDiffer(TextDiffLimits(context_lines=1)).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    assert result.complete is True
    asset = result.assets[0]
    assert asset.status is TextDiffStatus.COMPLETE
    assert len(asset.hunks) == 1
    hunk = asset.hunks[0]
    assert (
        hunk.before_start_line,
        hunk.before_line_count,
        hunk.after_start_line,
        hunk.after_line_count,
    ) == (2, 4, 2, 4)
    assert [line.kind for line in hunk.lines] == [
        TextDiffLineKind.CONTEXT,
        TextDiffLineKind.REMOVED,
        TextDiffLineKind.REMOVED,
        TextDiffLineKind.ADDED,
        TextDiffLineKind.ADDED,
        TextDiffLineKind.CONTEXT,
    ]
    assert [line.before_line_number for line in hunk.lines] == [2, 3, 4, None, None, 5]
    assert [line.after_line_number for line in hunk.lines] == [2, None, None, 3, 4, 5]
    assert [line.text for line in hunk.lines] == [
        "keep-before\n",
        "old-a\n",
        "old-b\n",
        "new-a\n",
        "new-b\n",
        "keep-after\n",
    ]


def test_insertion_and_deletion_use_one_sided_line_numbers() -> None:
    """Added and removed lines retain only the source side that exists."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "a\nc\n"))
    inserted_collection = make_collection(
        make_collected_asset("AGENTS.md", "a\nb\nc\n")
    )
    inserted = DeterministicTextDiffer(TextDiffLimits(context_lines=0)).compare(
        baseline=baseline,
        current_collection=inserted_collection,
        asset_diff=make_diff(baseline, inserted_collection),
    )
    inserted_line = inserted.assets[0].hunks[0].lines[0]
    assert inserted_line.kind is TextDiffLineKind.ADDED
    assert inserted_line.before_line_number is None
    assert inserted_line.after_line_number == 2
    assert inserted_line.text == "b\n"

    removed_baseline = make_baseline(make_baseline_asset("AGENTS.md", "a\nb\nc\n"))
    removed_collection = make_collection(make_collected_asset("AGENTS.md", "a\nc\n"))
    removed = DeterministicTextDiffer(TextDiffLimits(context_lines=0)).compare(
        baseline=removed_baseline,
        current_collection=removed_collection,
        asset_diff=make_diff(removed_baseline, removed_collection),
    )
    removed_line = removed.assets[0].hunks[0].lines[0]
    assert removed_line.kind is TextDiffLineKind.REMOVED
    assert removed_line.before_line_number == 2
    assert removed_line.after_line_number is None
    assert removed_line.text == "b\n"


def test_added_and_removed_files_have_bounded_whole_file_line_evidence() -> None:
    """File-level additions and removals become one-sided unified hunks."""

    added_collection = make_collection(
        make_collected_asset("new/SKILL.md", "one\ntwo\n")
    )
    added_baseline = make_baseline()
    added = DeterministicTextDiffer().compare(
        baseline=added_baseline,
        current_collection=added_collection,
        asset_diff=make_diff(added_baseline, added_collection),
    )
    added_asset = added.assets[0]
    assert added_asset.change.change_type is ChangeType.ADDED
    assert added_asset.before_line_count == 0
    assert added_asset.after_line_count == 2
    assert [line.kind for line in added_asset.hunks[0].lines] == [
        TextDiffLineKind.ADDED,
        TextDiffLineKind.ADDED,
    ]

    removed_baseline = make_baseline(make_baseline_asset("old/SKILL.md", "one\ntwo\n"))
    removed_collection = make_collection()
    removed = DeterministicTextDiffer().compare(
        baseline=removed_baseline,
        current_collection=removed_collection,
        asset_diff=make_diff(removed_baseline, removed_collection),
    )
    removed_asset = removed.assets[0]
    assert removed_asset.change.change_type is ChangeType.REMOVED
    assert removed_asset.before_line_count == 2
    assert removed_asset.after_line_count == 0
    assert [line.kind for line in removed_asset.hunks[0].lines] == [
        TextDiffLineKind.REMOVED,
        TextDiffLineKind.REMOVED,
    ]


def test_newline_only_change_preserves_line_ending_difference() -> None:
    """Exact line evidence distinguishes final newline changes."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "line\n"))
    collection = make_collection(make_collected_asset("AGENTS.md", "line"))

    result = DeterministicTextDiffer(TextDiffLimits(context_lines=0)).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    lines = result.assets[0].hunks[0].lines
    assert [(line.kind, line.text) for line in lines] == [
        (TextDiffLineKind.REMOVED, "line\n"),
        (TextDiffLineKind.ADDED, "line"),
    ]


def test_no_asset_changes_produce_an_empty_complete_result() -> None:
    """Unchanged projects do not allocate or invent text evidence."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "same\n"))
    collection = make_collection(make_collected_asset("AGENTS.md", "same\n"))

    result = DeterministicTextDiffer().compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    assert result.assets == ()
    assert result.complete is True


def test_long_lines_are_truncated_with_original_length_visible() -> None:
    """Evidence bounds never pretend retained line text is complete."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "abcdefgh\n"))
    collection = make_collection(make_collected_asset("AGENTS.md", "abcdXfgh\n"))

    result = DeterministicTextDiffer(
        TextDiffLimits(context_lines=0, max_characters_per_line=5)
    ).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    asset = result.assets[0]
    assert asset.status is TextDiffStatus.TRUNCATED
    assert result.complete is False
    assert [line.text for line in asset.hunks[0].lines] == ["abcde", "abcdX"]
    assert [line.original_character_count for line in asset.hunks[0].lines] == [9, 9]
    assert all(line.truncated for line in asset.hunks[0].lines)


def test_hunk_line_limit_prioritizes_changed_head_and_tail_lines() -> None:
    """Large replacements retain evidence from both ends and mark omitted lines."""

    before = "".join(f"old-{index}\n" for index in range(10))
    after = "".join(f"new-{index}\n" for index in range(10))
    baseline = make_baseline(make_baseline_asset("AGENTS.md", before))
    collection = make_collection(make_collected_asset("AGENTS.md", after))

    result = DeterministicTextDiffer(
        TextDiffLimits(
            context_lines=0,
            max_lines_per_hunk=4,
        )
    ).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    hunk = result.assets[0].hunks[0]
    assert result.assets[0].status is TextDiffStatus.TRUNCATED
    assert hunk.omitted_line_count == 16
    assert [(line.kind, line.text) for line in hunk.lines] == [
        (TextDiffLineKind.REMOVED, "old-0\n"),
        (TextDiffLineKind.REMOVED, "old-1\n"),
        (TextDiffLineKind.ADDED, "new-8\n"),
        (TextDiffLineKind.ADDED, "new-9\n"),
    ]


def test_hunk_count_limit_retains_first_and_last_regions() -> None:
    """Many disjoint changes retain deterministic evidence from both file ends."""

    before_lines: list[str] = []
    after_lines: list[str] = []
    for index in range(6):
        before_lines.extend((f"old-{index}\n", f"keep-{index}\n"))
        after_lines.extend((f"new-{index}\n", f"keep-{index}\n"))
    baseline = make_baseline(make_baseline_asset("AGENTS.md", "".join(before_lines)))
    collection = make_collection(
        make_collected_asset("AGENTS.md", "".join(after_lines))
    )

    result = DeterministicTextDiffer(
        TextDiffLimits(
            context_lines=0,
            max_hunks_per_asset=2,
        )
    ).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    asset = result.assets[0]
    assert asset.status is TextDiffStatus.TRUNCATED
    assert len(asset.hunks) == 2
    assert asset.omitted_hunk_count == 4
    retained_text = [line.text for hunk in asset.hunks for line in hunk.lines]
    assert retained_text == ["old-0\n", "new-0\n", "old-5\n", "new-5\n"]


@pytest.mark.parametrize(
    "limits",
    [
        TextDiffLimits(max_input_bytes_per_side=3),
        TextDiffLimits(max_input_lines_per_side=1),
        TextDiffLimits(max_line_comparison_product=3),
    ],
)
def test_input_limits_skip_algorithm_with_visible_status(
    limits: TextDiffLimits,
) -> None:
    """Oversized or high-complexity inputs never enter unbounded matching."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "a\nb\n"))
    collection = make_collection(make_collected_asset("AGENTS.md", "c\nd\n"))

    result = DeterministicTextDiffer(limits).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    asset = result.assets[0]
    assert asset.status is TextDiffStatus.INPUT_LIMIT_EXCEEDED
    assert asset.hunks == ()
    assert result.complete is False
    assert asset.before_line_count == 2
    assert asset.after_line_count == 2


def test_incomplete_current_collection_fails_without_false_text_evidence() -> None:
    """A current scan gap cannot be interpreted as deleted lines."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "before\n"))
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
    asset_diff = AssetDiffResult(
        changes=(
            AssetChange(
                path="AGENTS.md",
                change_type=ChangeType.REMOVED,
                before_sha256=baseline.assets[0].sha256,
            ),
        ),
        collection_config_matches=True,
    )

    with pytest.raises(TextDiffError) as captured:
        DeterministicTextDiffer().compare(
            baseline=baseline,
            current_collection=incomplete,
            asset_diff=asset_diff,
        )

    assert captured.value.code is TextDiffCode.INCOMPLETE_CURRENT_COVERAGE
    assert "AGENTS.md" not in str(captured.value)


def test_incoherent_asset_change_presence_is_rejected() -> None:
    """Text Diff verifies P1-14 output against both content sets."""

    existing = make_baseline_asset("AGENTS.md", "same\n")
    baseline = make_baseline(existing)
    collection = make_collection(make_collected_asset("AGENTS.md", "same\n"))
    invalid_diff = AssetDiffResult(
        changes=(
            AssetChange(
                path="AGENTS.md",
                change_type=ChangeType.ADDED,
                after_sha256=collection.assets[0].asset.sha256,
            ),
        ),
        collection_config_matches=True,
    )

    with pytest.raises(TextDiffError) as captured:
        DeterministicTextDiffer().compare(
            baseline=baseline,
            current_collection=collection,
            asset_diff=invalid_diff,
        )

    assert captured.value.code is TextDiffCode.INCOHERENT_ASSET_CHANGE


def test_current_content_integrity_mismatch_does_not_leak_content() -> None:
    """Adapter metadata cannot authorize different captured text."""

    secret = "text-diff-integrity-secret"
    metadata_asset = make_collected_asset("AGENTS.md", "declared\n").asset
    inconsistent = CollectedAsset(asset=metadata_asset, content=secret)
    collection = make_collection(inconsistent)
    baseline = make_baseline()
    asset_diff = AssetDiffResult(
        changes=(
            AssetChange(
                path="AGENTS.md",
                change_type=ChangeType.ADDED,
                after_sha256=metadata_asset.sha256,
            ),
        ),
        collection_config_matches=True,
    )

    with pytest.raises(TextDiffError) as captured:
        DeterministicTextDiffer().compare(
            baseline=baseline,
            current_collection=collection,
            asset_diff=asset_diff,
        )

    assert captured.value.code is TextDiffCode.CONTENT_INTEGRITY_MISMATCH
    assert secret not in str(captured.value)


def test_duplicate_asset_changes_are_rejected_safely() -> None:
    """Ambiguous P1-14 input cannot duplicate or reorder line evidence."""

    current = make_collected_asset("AGENTS.md", "new\n")
    collection = make_collection(current)
    change = AssetChange(
        path="AGENTS.md",
        change_type=ChangeType.ADDED,
        after_sha256=current.asset.sha256,
    )

    with pytest.raises(TextDiffError) as captured:
        DeterministicTextDiffer().compare(
            baseline=make_baseline(),
            current_collection=collection,
            asset_diff=AssetDiffResult(
                changes=(change, change),
                collection_config_matches=True,
            ),
        )

    assert captured.value.code is TextDiffCode.DUPLICATE_ASSET_CHANGE_PATH


def test_limits_reject_zero_or_negative_values() -> None:
    """A caller cannot accidentally disable resource bounds."""

    with pytest.raises(ValueError):
        TextDiffLimits(max_hunks_per_asset=0)
    with pytest.raises(ValueError):
        TextDiffLimits(context_lines=-1)


def test_baseline_to_asset_diff_to_text_diff_integration(tmp_path: Path) -> None:
    """P1-13, P1-14, and P1-15 compose without CLI or content execution."""

    (tmp_path / "AGENTS.md").write_text(
        "# Agent\n\nRequire approval.\n",
        encoding="utf-8",
    )
    config = default_project_config()
    baseline = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=NoGitProvenanceProvider(),
        clock=lambda: datetime(2026, 8, 18, 15, 30, tzinfo=UTC),
    ).create(
        BaselineCreationRequest(
            project_root=tmp_path,
            config=config,
            config_path=None,
            output_path=tmp_path / ".agentsec/baseline.json",
        )
    )
    (tmp_path / "AGENTS.md").write_text(
        "# Agent\n\nApproval removed.\n",
        encoding="utf-8",
    )
    current = MarkdownAssetCollector().collect(tmp_path, config)
    asset_diff = DeterministicAssetDiffer().compare(
        baseline=baseline,
        current_collection=current,
        current_collection_config_sha256=fingerprint_collection_config(config),
    )

    text_diff = DeterministicTextDiffer().compare(
        baseline=baseline,
        current_collection=current,
        asset_diff=asset_diff,
    )

    assert text_diff.complete is True
    assert len(text_diff.assets) == 1
    lines = text_diff.assets[0].hunks[0].lines
    changed_lines = [
        (line.kind, line.before_line_number, line.after_line_number, line.text)
        for line in lines
        if line.kind is not TextDiffLineKind.CONTEXT
    ]
    assert changed_lines == [
        (TextDiffLineKind.REMOVED, 3, None, "Require approval.\n"),
        (TextDiffLineKind.ADDED, None, 3, "Approval removed.\n"),
    ]


def test_omitted_asset_change_is_rejected_before_text_evidence() -> None:
    """A caller cannot suppress a real modification by passing an empty Diff."""

    baseline = make_baseline(make_baseline_asset("AGENTS.md", "before\n"))
    collection = make_collection(make_collected_asset("AGENTS.md", "after\n"))

    with pytest.raises(TextDiffError) as captured:
        DeterministicTextDiffer().compare(
            baseline=baseline,
            current_collection=collection,
            asset_diff=AssetDiffResult(
                changes=(),
                collection_config_matches=True,
            ),
        )

    assert captured.value.code is TextDiffCode.INCOHERENT_ASSET_CHANGE


def test_global_asset_limit_retains_first_and_last_changed_assets() -> None:
    """Many modified files cannot create an unbounded aggregate Text Diff."""

    before_assets = tuple(
        make_baseline_asset(f"asset-{index:02d}.md", f"before-{index}\n")
        for index in range(5)
    )
    current_assets = tuple(
        make_collected_asset(f"asset-{index:02d}.md", f"after-{index}\n")
        for index in range(5)
    )
    baseline = make_baseline(*before_assets)
    collection = make_collection(*current_assets)

    result = DeterministicTextDiffer(TextDiffLimits(max_assets_per_result=2)).compare(
        baseline=baseline,
        current_collection=collection,
        asset_diff=make_diff(baseline, collection),
    )

    assert [asset.change.path for asset in result.assets] == [
        "asset-00.md",
        "asset-04.md",
    ]
    assert result.omitted_asset_count == 3
    assert result.complete is False

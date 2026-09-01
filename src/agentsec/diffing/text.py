"""Bounded deterministic line-oriented text differences for changed assets."""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from agentsec.baselines import Baseline, BaselineAsset
from agentsec.collectors import CollectedAsset, CollectionResult
from agentsec.diffing.assets import AssetDiffResult
from agentsec.domain import AssetChange, ChangeType

_DEFAULT_MAX_INPUT_BYTES_PER_SIDE: Final[int] = 1_048_576
_DEFAULT_MAX_INPUT_LINES_PER_SIDE: Final[int] = 10_000
_DEFAULT_MAX_LINE_COMPARISON_PRODUCT: Final[int] = 25_000_000
_DEFAULT_CONTEXT_LINES: Final[int] = 3
_DEFAULT_MAX_ASSETS_PER_RESULT: Final[int] = 25
_DEFAULT_MAX_HUNKS_PER_ASSET: Final[int] = 25
_DEFAULT_MAX_LINES_PER_HUNK: Final[int] = 40
_DEFAULT_MAX_CHARACTERS_PER_LINE: Final[int] = 500


@dataclass(frozen=True, slots=True)
class TextDiffLimits:
    """Hard input and evidence-output bounds for one changed asset."""

    max_input_bytes_per_side: int = _DEFAULT_MAX_INPUT_BYTES_PER_SIDE
    max_input_lines_per_side: int = _DEFAULT_MAX_INPUT_LINES_PER_SIDE
    max_line_comparison_product: int = _DEFAULT_MAX_LINE_COMPARISON_PRODUCT
    context_lines: int = _DEFAULT_CONTEXT_LINES
    max_assets_per_result: int = _DEFAULT_MAX_ASSETS_PER_RESULT
    max_hunks_per_asset: int = _DEFAULT_MAX_HUNKS_PER_ASSET
    max_lines_per_hunk: int = _DEFAULT_MAX_LINES_PER_HUNK
    max_characters_per_line: int = _DEFAULT_MAX_CHARACTERS_PER_LINE

    def __post_init__(self) -> None:
        positive_values = (
            self.max_input_bytes_per_side,
            self.max_input_lines_per_side,
            self.max_line_comparison_product,
            self.max_assets_per_result,
            self.max_hunks_per_asset,
            self.max_lines_per_hunk,
            self.max_characters_per_line,
        )
        if any(value <= 0 for value in positive_values):
            raise ValueError("text diff limits must be positive")
        if self.context_lines < 0:
            raise ValueError("text diff context_lines must be non-negative")


class TextDiffLineKind(StrEnum):
    """Unified-diff role of one retained evidence line."""

    CONTEXT = "context"
    ADDED = "added"
    REMOVED = "removed"


class TextDiffStatus(StrEnum):
    """Completeness of line evidence for one changed asset."""

    COMPLETE = "complete"
    TRUNCATED = "truncated"
    INPUT_LIMIT_EXCEEDED = "input_limit_exceeded"


@dataclass(frozen=True, slots=True)
class TextDiffLine:
    """One bounded line with its original before/after source position."""

    kind: TextDiffLineKind
    before_line_number: int | None
    after_line_number: int | None
    text: str
    original_character_count: int
    truncated: bool

    def __post_init__(self) -> None:
        if self.before_line_number is not None and self.before_line_number < 1:
            raise ValueError("before line numbers must be positive")
        if self.after_line_number is not None and self.after_line_number < 1:
            raise ValueError("after line numbers must be positive")
        if self.kind is TextDiffLineKind.CONTEXT:
            if self.before_line_number is None or self.after_line_number is None:
                raise ValueError("context lines require before and after numbers")
        elif self.kind is TextDiffLineKind.ADDED:
            if self.before_line_number is not None or self.after_line_number is None:
                raise ValueError("added lines require only an after line number")
        elif self.kind is TextDiffLineKind.REMOVED and (
            self.before_line_number is None or self.after_line_number is not None
        ):
            raise ValueError("removed lines require only a before line number")
        if self.original_character_count < len(self.text):
            raise ValueError("original character count cannot be smaller than text")
        if self.truncated != (self.original_character_count > len(self.text)):
            raise ValueError("line truncated flag must match retained text length")


@dataclass(frozen=True, slots=True)
class TextDiffHunk:
    """One bounded unified-diff region with explicit source ranges."""

    before_start_line: int
    before_line_count: int
    after_start_line: int
    after_line_count: int
    lines: tuple[TextDiffLine, ...]
    omitted_line_count: int
    truncated: bool

    def __post_init__(self) -> None:
        if self.before_start_line < 1 or self.after_start_line < 1:
            raise ValueError("hunk start lines must be positive")
        if self.before_line_count < 0 or self.after_line_count < 0:
            raise ValueError("hunk line counts cannot be negative")
        if self.omitted_line_count < 0:
            raise ValueError("omitted line count cannot be negative")
        line_truncated = any(line.truncated for line in self.lines)
        if self.truncated != (self.omitted_line_count > 0 or line_truncated):
            raise ValueError("hunk truncated flag must match omitted evidence")


@dataclass(frozen=True, slots=True)
class AssetTextDiff:
    """Bounded line evidence for one P1-14 AssetChange."""

    change: AssetChange
    status: TextDiffStatus
    before_line_count: int
    after_line_count: int
    hunks: tuple[TextDiffHunk, ...]
    omitted_hunk_count: int = 0

    def __post_init__(self) -> None:
        if self.before_line_count < 0 or self.after_line_count < 0:
            raise ValueError("asset line counts cannot be negative")
        if self.omitted_hunk_count < 0:
            raise ValueError("omitted hunk count cannot be negative")
        has_truncated_hunk = any(hunk.truncated for hunk in self.hunks)
        if self.status is TextDiffStatus.COMPLETE:
            if self.omitted_hunk_count or has_truncated_hunk:
                raise ValueError("complete text diff cannot omit evidence")
        elif self.status is TextDiffStatus.TRUNCATED:
            if self.omitted_hunk_count == 0 and not has_truncated_hunk:
                raise ValueError("truncated text diff requires omitted evidence")
        elif self.status is TextDiffStatus.INPUT_LIMIT_EXCEEDED and (
            self.hunks or self.omitted_hunk_count
        ):
            raise ValueError("input-limited text diff cannot contain hunks")


@dataclass(frozen=True, slots=True)
class TextDiffResult:
    """Stable bounded line differences for a P1-14 Asset Diff result."""

    assets: tuple[AssetTextDiff, ...]
    omitted_asset_count: int = 0

    def __post_init__(self) -> None:
        if self.omitted_asset_count < 0:
            raise ValueError("omitted asset count cannot be negative")

    @property
    def complete(self) -> bool:
        """Return whether all changed assets retain complete line evidence."""

        return self.omitted_asset_count == 0 and all(
            asset.status is TextDiffStatus.COMPLETE for asset in self.assets
        )


class TextDiffCode(StrEnum):
    """Stable safe failures for incoherent Text Diff inputs."""

    INCOMPLETE_CURRENT_COVERAGE = "incomplete_current_coverage"
    DUPLICATE_BASELINE_PATH = "duplicate_baseline_path"
    DUPLICATE_CURRENT_PATH = "duplicate_current_path"
    DUPLICATE_ASSET_CHANGE_PATH = "duplicate_asset_change_path"
    INCOHERENT_ASSET_CHANGE = "incoherent_asset_change"
    CONTENT_INTEGRITY_MISMATCH = "content_integrity_mismatch"


class TextDiffError(RuntimeError):
    """A line-diff failure that never includes paths or captured content."""

    def __init__(self, code: TextDiffCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _LineCandidate:
    kind: TextDiffLineKind
    before_line_number: int | None
    after_line_number: int | None
    text: str


@dataclass(frozen=True, slots=True)
class _PreparedSide:
    lines: tuple[str, ...]
    line_count: int


class DeterministicTextDiffer:
    """Create bounded unified line evidence without executing source content."""

    def __init__(self, limits: TextDiffLimits | None = None) -> None:
        self._limits = limits if limits is not None else TextDiffLimits()

    def compare(
        self,
        *,
        baseline: Baseline,
        current_collection: CollectionResult,
        asset_diff: AssetDiffResult,
    ) -> TextDiffResult:
        """Create stable text hunks for each coherent P1-14 AssetChange."""

        if not current_collection.coverage.complete:
            raise TextDiffError(
                TextDiffCode.INCOMPLETE_CURRENT_COVERAGE,
                "text diff requires complete current collection coverage",
            )

        before_by_path = self._index_baseline_assets(baseline.assets)
        after_by_path = self._index_current_assets(current_collection.assets)
        changes = self._index_changes(asset_diff.changes)
        self._validate_complete_change_set(
            before_by_path=before_by_path,
            after_by_path=after_by_path,
            changes=changes,
        )
        change_paths = tuple(sorted(changes))
        selected_indices = self._head_tail_indices(
            tuple(range(len(change_paths))),
            self._limits.max_assets_per_result,
        )
        selected_paths = tuple(change_paths[index] for index in selected_indices)
        assets = tuple(
            self._compare_asset(
                change=changes[path],
                before=before_by_path.get(path),
                after=after_by_path.get(path),
            )
            for path in selected_paths
        )
        return TextDiffResult(
            assets=assets,
            omitted_asset_count=len(change_paths) - len(selected_paths),
        )

    @staticmethod
    def _validate_complete_change_set(
        *,
        before_by_path: dict[str, BaselineAsset],
        after_by_path: dict[str, CollectedAsset],
        changes: dict[str, AssetChange],
    ) -> None:
        """Reject omitted or invented P1-14 changes before building evidence."""

        expected: list[AssetChange] = []
        for path in sorted(before_by_path.keys() | after_by_path.keys()):
            before = before_by_path.get(path)
            after = after_by_path.get(path)
            if before is None and after is not None:
                expected.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.ADDED,
                        after_sha256=after.asset.sha256,
                    )
                )
            elif before is not None and after is None:
                expected.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.REMOVED,
                        before_sha256=before.sha256,
                    )
                )
            elif (
                before is not None
                and after is not None
                and before.sha256 != after.asset.sha256
            ):
                expected.append(
                    AssetChange(
                        path=path,
                        change_type=ChangeType.MODIFIED,
                        before_sha256=before.sha256,
                        after_sha256=after.asset.sha256,
                    )
                )

        provided = tuple(changes[path] for path in sorted(changes))
        if provided != tuple(expected):
            raise TextDiffError(
                TextDiffCode.INCOHERENT_ASSET_CHANGE,
                "Asset Diff changes do not match Baseline and current assets",
            )

    def _compare_asset(
        self,
        *,
        change: AssetChange,
        before: BaselineAsset | None,
        after: CollectedAsset | None,
    ) -> AssetTextDiff:
        """Validate one AssetChange and produce bounded line evidence."""

        self._validate_change_identity(change=change, before=before, after=after)
        before_line_count = before.line_count if before is not None else 0
        after_line_count = after.asset.line_count if after is not None else 0

        prepared_before = self._prepare_side(before, expected_hash=change.before_sha256)
        prepared_after = self._prepare_side(after, expected_hash=change.after_sha256)
        if prepared_before is None or prepared_after is None:
            return AssetTextDiff(
                change=change,
                status=TextDiffStatus.INPUT_LIMIT_EXCEEDED,
                before_line_count=before_line_count,
                after_line_count=after_line_count,
                hunks=(),
            )
        if (
            len(prepared_before.lines) * len(prepared_after.lines)
            > self._limits.max_line_comparison_product
        ):
            return AssetTextDiff(
                change=change,
                status=TextDiffStatus.INPUT_LIMIT_EXCEEDED,
                before_line_count=prepared_before.line_count,
                after_line_count=prepared_after.line_count,
                hunks=(),
            )

        groups = tuple(
            difflib.SequenceMatcher(
                a=prepared_before.lines,
                b=prepared_after.lines,
                autojunk=True,
            ).get_grouped_opcodes(n=self._limits.context_lines)
        )
        selected_groups, omitted_hunk_count = self._bounded_groups(groups)
        hunks = tuple(
            self._build_hunk(
                group,
                before_lines=prepared_before.lines,
                after_lines=prepared_after.lines,
            )
            for group in selected_groups
        )
        truncated = omitted_hunk_count > 0 or any(hunk.truncated for hunk in hunks)
        return AssetTextDiff(
            change=change,
            status=(TextDiffStatus.TRUNCATED if truncated else TextDiffStatus.COMPLETE),
            before_line_count=prepared_before.line_count,
            after_line_count=prepared_after.line_count,
            hunks=hunks,
            omitted_hunk_count=omitted_hunk_count,
        )

    def _prepare_side(
        self,
        asset: BaselineAsset | CollectedAsset | None,
        *,
        expected_hash: str | None,
    ) -> _PreparedSide | None:
        """Validate bounded exact content or report that input limits were exceeded."""

        if asset is None:
            if expected_hash is not None:
                raise TextDiffError(
                    TextDiffCode.INCOHERENT_ASSET_CHANGE,
                    "asset change hash requires a missing content side",
                )
            return _PreparedSide(lines=(), line_count=0)

        metadata = asset if isinstance(asset, BaselineAsset) else asset.asset
        content = asset.content
        if expected_hash != metadata.sha256:
            raise TextDiffError(
                TextDiffCode.INCOHERENT_ASSET_CHANGE,
                "asset change hash does not match asset metadata",
            )
        if (
            metadata.size_bytes > self._limits.max_input_bytes_per_side
            or metadata.line_count > self._limits.max_input_lines_per_side
            or len(content) > self._limits.max_input_bytes_per_side
        ):
            return None

        try:
            content_bytes = content.encode("utf-8")
        except UnicodeEncodeError as error:
            raise TextDiffError(
                TextDiffCode.CONTENT_INTEGRITY_MISMATCH,
                "text diff content is not valid UTF-8",
            ) from error
        if len(content_bytes) > self._limits.max_input_bytes_per_side:
            return None

        lines = tuple(content.splitlines(keepends=True))
        if len(lines) > self._limits.max_input_lines_per_side:
            return None
        if (
            len(content_bytes) != metadata.size_bytes
            or len(lines) != metadata.line_count
            or hashlib.sha256(content_bytes).hexdigest() != metadata.sha256
        ):
            raise TextDiffError(
                TextDiffCode.CONTENT_INTEGRITY_MISMATCH,
                "text diff content does not match validated metadata",
            )
        return _PreparedSide(lines=lines, line_count=len(lines))

    @staticmethod
    def _validate_change_identity(
        *,
        change: AssetChange,
        before: BaselineAsset | None,
        after: CollectedAsset | None,
    ) -> None:
        """Require AssetChange presence semantics to match both content sets."""

        if change.change_type is ChangeType.ADDED:
            coherent = before is None and after is not None
        elif change.change_type is ChangeType.REMOVED:
            coherent = before is not None and after is None
        else:
            coherent = before is not None and after is not None
        if not coherent:
            raise TextDiffError(
                TextDiffCode.INCOHERENT_ASSET_CHANGE,
                "asset change does not match Baseline and current path presence",
            )

    def _bounded_groups(
        self,
        groups: tuple[list[tuple[str, int, int, int, int]], ...],
    ) -> tuple[tuple[list[tuple[str, int, int, int, int]], ...], int]:
        """Select deterministic head and tail hunks within the output bound."""

        limit = self._limits.max_hunks_per_asset
        if len(groups) <= limit:
            return groups, 0
        indices = self._head_tail_indices(tuple(range(len(groups))), limit)
        return tuple(groups[index] for index in indices), len(groups) - len(indices)

    def _build_hunk(
        self,
        group: list[tuple[str, int, int, int, int]],
        *,
        before_lines: tuple[str, ...],
        after_lines: tuple[str, ...],
    ) -> TextDiffHunk:
        """Build one bounded unified hunk while prioritizing changed lines."""

        candidates: list[_LineCandidate] = []
        for tag, before_start, before_end, after_start, after_end in group:
            if tag == "equal":
                for offset in range(before_end - before_start):
                    candidates.append(
                        _LineCandidate(
                            kind=TextDiffLineKind.CONTEXT,
                            before_line_number=before_start + offset + 1,
                            after_line_number=after_start + offset + 1,
                            text=before_lines[before_start + offset],
                        )
                    )
            elif tag == "delete":
                candidates.extend(
                    _LineCandidate(
                        kind=TextDiffLineKind.REMOVED,
                        before_line_number=index + 1,
                        after_line_number=None,
                        text=before_lines[index],
                    )
                    for index in range(before_start, before_end)
                )
            elif tag == "insert":
                candidates.extend(
                    _LineCandidate(
                        kind=TextDiffLineKind.ADDED,
                        before_line_number=None,
                        after_line_number=index + 1,
                        text=after_lines[index],
                    )
                    for index in range(after_start, after_end)
                )
            elif tag == "replace":
                candidates.extend(
                    _LineCandidate(
                        kind=TextDiffLineKind.REMOVED,
                        before_line_number=index + 1,
                        after_line_number=None,
                        text=before_lines[index],
                    )
                    for index in range(before_start, before_end)
                )
                candidates.extend(
                    _LineCandidate(
                        kind=TextDiffLineKind.ADDED,
                        before_line_number=None,
                        after_line_number=index + 1,
                        text=after_lines[index],
                    )
                    for index in range(after_start, after_end)
                )
            else:
                raise AssertionError("SequenceMatcher returned an unknown opcode")

        selected, omitted_line_count = self._bounded_candidates(tuple(candidates))
        lines = tuple(self._to_diff_line(candidate) for candidate in selected)
        first = group[0]
        last = group[-1]
        line_truncated = any(line.truncated for line in lines)
        return TextDiffHunk(
            before_start_line=first[1] + 1,
            before_line_count=last[2] - first[1],
            after_start_line=first[3] + 1,
            after_line_count=last[4] - first[3],
            lines=lines,
            omitted_line_count=omitted_line_count,
            truncated=omitted_line_count > 0 or line_truncated,
        )

    def _bounded_candidates(
        self,
        candidates: tuple[_LineCandidate, ...],
    ) -> tuple[tuple[_LineCandidate, ...], int]:
        """Retain changed lines first, then bounded context, preserving order."""

        limit = self._limits.max_lines_per_hunk
        if len(candidates) <= limit:
            return candidates, 0

        changed_indices = tuple(
            index
            for index, candidate in enumerate(candidates)
            if candidate.kind is not TextDiffLineKind.CONTEXT
        )
        if len(changed_indices) >= limit:
            selected_indices = self._head_tail_indices(changed_indices, limit)
        else:
            selected = set(changed_indices)
            context_indices = tuple(
                index
                for index, candidate in enumerate(candidates)
                if candidate.kind is TextDiffLineKind.CONTEXT
            )
            selected.update(
                self._head_tail_indices(context_indices, limit - len(selected))
            )
            selected_indices = tuple(sorted(selected))

        selected_candidates = tuple(candidates[index] for index in selected_indices)
        return selected_candidates, len(candidates) - len(selected_candidates)

    def _to_diff_line(self, candidate: _LineCandidate) -> TextDiffLine:
        """Truncate one retained line without losing its original character count."""

        original_count = len(candidate.text)
        text = candidate.text[: self._limits.max_characters_per_line]
        return TextDiffLine(
            kind=candidate.kind,
            before_line_number=candidate.before_line_number,
            after_line_number=candidate.after_line_number,
            text=text,
            original_character_count=original_count,
            truncated=len(text) < original_count,
        )

    @staticmethod
    def _head_tail_indices(indices: tuple[int, ...], limit: int) -> tuple[int, ...]:
        """Select deterministic evidence from both beginning and end."""

        if len(indices) <= limit:
            return indices
        head_count = (limit + 1) // 2
        tail_count = limit - head_count
        if tail_count == 0:
            return indices[:head_count]
        return (*indices[:head_count], *indices[-tail_count:])

    @staticmethod
    def _index_baseline_assets(
        assets: tuple[BaselineAsset, ...],
    ) -> dict[str, BaselineAsset]:
        indexed: dict[str, BaselineAsset] = {}
        for asset in assets:
            if asset.path in indexed:
                raise TextDiffError(
                    TextDiffCode.DUPLICATE_BASELINE_PATH,
                    "Baseline assets must have unique paths for text diff",
                )
            indexed[asset.path] = asset
        return indexed

    @staticmethod
    def _index_current_assets(
        assets: tuple[CollectedAsset, ...],
    ) -> dict[str, CollectedAsset]:
        indexed: dict[str, CollectedAsset] = {}
        for asset in assets:
            if asset.asset.path in indexed:
                raise TextDiffError(
                    TextDiffCode.DUPLICATE_CURRENT_PATH,
                    "current assets must have unique paths for text diff",
                )
            indexed[asset.asset.path] = asset
        return indexed

    @staticmethod
    def _index_changes(changes: tuple[AssetChange, ...]) -> dict[str, AssetChange]:
        indexed: dict[str, AssetChange] = {}
        for change in changes:
            if change.path in indexed:
                raise TextDiffError(
                    TextDiffCode.DUPLICATE_ASSET_CHANGE_PATH,
                    "Asset Diff changes must have unique paths",
                )
            indexed[change.path] = change
        return indexed

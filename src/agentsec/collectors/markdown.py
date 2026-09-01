"""Safe collector for Phase 1 Agent Markdown control assets."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from agentsec.collectors.base import CollectedAsset, CollectionResult
from agentsec.collectors.path_matching import DiscoveryPathMatcher
from agentsec.collectors.path_safety import (
    GuardedPath,
    PathGuard,
    PathGuardError,
    PathSafetyReason,
    SafePathKind,
)
from agentsec.config import LimitsConfig, ProjectConfig
from agentsec.domain import (
    AgentAsset,
    AssetSource,
    AssetType,
    CoverageIssue,
    CoverageIssueCode,
    ScanCoverage,
)

_SUPPORTED_ASSET_TYPES: Final[dict[str, AssetType]] = {
    "AGENTS.md": AssetType.AGENTS,
    "AGENTS.override.md": AssetType.AGENTS_OVERRIDE,
    "SKILL.md": AssetType.SKILL,
}
_READ_CHUNK_SIZE: Final[int] = 65_536


@dataclass(slots=True)
class _CollectionState:
    """Mutable traversal state kept private from collector consumers."""

    assets: list[CollectedAsset] = field(default_factory=list)
    issues: list[CoverageIssue] = field(default_factory=list)
    discovered_assets: int = 0
    skipped_assets: int = 0
    stop_requested: bool = False


class MarkdownAssetCollector:
    """Recursively collect configured Agent Markdown without execution.

    Include/exclude, canonical path safety, bounded reads, logical traversal
    depth, and selected-asset count limits are enforced before untrusted content
    reaches later parsing stages.
    """

    def collect(
        self,
        project_root: Path,
        config: ProjectConfig,
    ) -> CollectionResult:
        """Collect configured UTF-8 assets and visible coverage failures."""

        state = _CollectionState()
        try:
            guard = PathGuard.create(project_root)
        except PathGuardError as error:
            state.issues.append(self._root_issue(error))
            return self._build_result(state)

        matcher = DiscoveryPathMatcher(config.discovery)
        self._walk(
            guard=guard,
            directory=guard.root,
            relative_directory=None,
            depth=0,
            ancestor_directories=(guard.root,),
            matcher=matcher,
            limits=config.limits,
            state=state,
        )
        return self._build_result(state)

    def _walk(
        self,
        *,
        guard: PathGuard,
        directory: Path,
        relative_directory: PurePosixPath | None,
        depth: int,
        ancestor_directories: tuple[Path, ...],
        matcher: DiscoveryPathMatcher,
        limits: LimitsConfig,
        state: _CollectionState,
    ) -> None:
        """Walk a guarded directory in stable logical-path order."""

        if state.stop_requested:
            return

        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError:
            state.issues.append(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Directory entries could not be read.",
                    asset_path=(
                        relative_directory.as_posix()
                        if relative_directory is not None
                        else None
                    ),
                )
            )
            return

        for candidate in entries:
            if state.stop_requested:
                return

            relative = (
                PurePosixPath(candidate.name)
                if relative_directory is None
                else relative_directory / candidate.name
            )
            relative_path = relative.as_posix()
            if matcher.is_excluded(relative_path):
                continue
            asset_identity = self._asset_identity(relative_path, matcher)

            try:
                guarded_path = guard.inspect(candidate)
            except PathGuardError as error:
                selected_asset = asset_identity is not None
                if selected_asset and not self._reserve_asset(
                    relative_path=relative_path,
                    limits=limits,
                    state=state,
                ):
                    return
                if selected_asset:
                    state.skipped_assets += 1
                state.issues.append(self._path_issue(error, relative_path))
                continue

            canonical_relative_path = guard.project_relative_path(guarded_path)
            if matcher.is_excluded(canonical_relative_path):
                continue

            if guarded_path.kind is SafePathKind.DIRECTORY:
                if guarded_path.resolved_path in ancestor_directories:
                    state.issues.append(
                        CoverageIssue(
                            code=CoverageIssueCode.EXTERNAL_SYMLINK,
                            message=(
                                "Symbolic-link directory cycle was not traversed."
                            ),
                            asset_path=relative_path,
                        )
                    )
                    continue

                next_depth = depth + 1
                if next_depth > limits.max_depth:
                    state.issues.append(
                        CoverageIssue(
                            code=CoverageIssueCode.DEPTH_EXCEEDED,
                            message=(
                                "Directory depth exceeds configured maximum of "
                                f"{limits.max_depth}."
                            ),
                            asset_path=relative_path,
                        )
                    )
                    continue

                self._walk(
                    guard=guard,
                    directory=guarded_path.resolved_path,
                    relative_directory=relative,
                    depth=next_depth,
                    ancestor_directories=(
                        *ancestor_directories,
                        guarded_path.resolved_path,
                    ),
                    matcher=matcher,
                    limits=limits,
                    state=state,
                )
                continue

            if asset_identity is None:
                continue
            if not self._reserve_asset(
                relative_path=relative_path,
                limits=limits,
                state=state,
            ):
                return

            asset_type, asset_source = asset_identity
            if guarded_path.kind is not SafePathKind.FILE:
                state.skipped_assets += 1
                state.issues.append(
                    CoverageIssue(
                        code=CoverageIssueCode.UNREADABLE,
                        message="Supported asset path is not a regular file.",
                        asset_path=relative_path,
                    )
                )
                continue

            collected = self._read_asset(
                guard=guard,
                guarded_path=guarded_path,
                relative_path=relative_path,
                asset_type=asset_type,
                asset_source=asset_source,
                max_file_size_bytes=limits.max_file_size_bytes,
                state=state,
            )
            if collected is not None:
                state.assets.append(collected)

    def _read_asset(
        self,
        *,
        guard: PathGuard,
        guarded_path: GuardedPath,
        relative_path: str,
        asset_type: AssetType,
        asset_source: AssetSource,
        max_file_size_bytes: int,
        state: _CollectionState,
    ) -> CollectedAsset | None:
        """Revalidate and read at most the configured number of file bytes."""

        try:
            revalidated_path = guard.inspect(guarded_path.resolved_path)
        except PathGuardError as error:
            state.skipped_assets += 1
            state.issues.append(self._path_issue(error, relative_path))
            return None

        if revalidated_path.kind is not SafePathKind.FILE:
            state.skipped_assets += 1
            state.issues.append(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Supported asset changed before it could be read.",
                    asset_path=relative_path,
                )
            )
            return None

        if (
            revalidated_path.size_bytes is not None
            and revalidated_path.size_bytes > max_file_size_bytes
        ):
            self._record_too_large(
                relative_path=relative_path,
                max_file_size_bytes=max_file_size_bytes,
                state=state,
            )
            return None

        try:
            content_bytes = self._read_bounded_bytes(
                revalidated_path.resolved_path,
                max_file_size_bytes,
            )
        except OSError:
            state.skipped_assets += 1
            state.issues.append(
                CoverageIssue(
                    code=CoverageIssueCode.UNREADABLE,
                    message="Supported asset bytes could not be read.",
                    asset_path=relative_path,
                )
            )
            return None

        if len(content_bytes) > max_file_size_bytes:
            self._record_too_large(
                relative_path=relative_path,
                max_file_size_bytes=max_file_size_bytes,
                state=state,
            )
            return None

        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            state.skipped_assets += 1
            state.issues.append(
                CoverageIssue(
                    code=CoverageIssueCode.UNSUPPORTED_ENCODING,
                    message="Supported asset is not valid UTF-8.",
                    asset_path=relative_path,
                )
            )
            return None

        asset = AgentAsset(
            path=relative_path,
            asset_type=asset_type,
            source=asset_source,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
            encoding="utf-8",
        )
        return CollectedAsset(asset=asset, content=content)

    @staticmethod
    def _read_bounded_bytes(path: Path, max_bytes: int) -> bytes:
        """Read no more than one byte beyond the configured file maximum."""

        remaining = max_bytes + 1
        chunks: list[bytes] = []
        with path.open("rb") as stream:
            while remaining > 0:
                chunk = stream.read(min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _reserve_asset(
        *,
        relative_path: str,
        limits: LimitsConfig,
        state: _CollectionState,
    ) -> bool:
        """Reserve one deterministic asset slot or stop at the first overflow."""

        if state.discovered_assets >= limits.max_assets:
            state.discovered_assets += 1
            state.skipped_assets += 1
            state.stop_requested = True
            state.issues.append(
                CoverageIssue(
                    code=CoverageIssueCode.ASSET_LIMIT_EXCEEDED,
                    message=(
                        "Asset count exceeds configured maximum of "
                        f"{limits.max_assets}; remaining paths were not scanned."
                    ),
                    asset_path=relative_path,
                )
            )
            return False

        state.discovered_assets += 1
        return True

    @staticmethod
    def _record_too_large(
        *,
        relative_path: str,
        max_file_size_bytes: int,
        state: _CollectionState,
    ) -> None:
        """Record an oversized selected asset without exposing its content."""

        state.skipped_assets += 1
        state.issues.append(
            CoverageIssue(
                code=CoverageIssueCode.TOO_LARGE,
                message=(
                    f"Asset exceeds configured maximum of {max_file_size_bytes} bytes."
                ),
                asset_path=relative_path,
            )
        )

    @staticmethod
    def _asset_identity(
        relative_path: str,
        matcher: DiscoveryPathMatcher,
    ) -> tuple[AssetType, AssetSource] | None:
        """Classify an included Markdown file without reading its content."""

        if not matcher.selects_markdown_file(relative_path):
            return None

        name = PurePosixPath(relative_path).name
        asset_type = _SUPPORTED_ASSET_TYPES.get(name)
        if asset_type is not None:
            return asset_type, AssetSource.DISCOVERED
        return AssetType.EXPLICIT_MARKDOWN, AssetSource.EXPLICIT

    @staticmethod
    def _root_issue(error: PathGuardError) -> CoverageIssue:
        """Translate guarded-root failures into safe coverage output."""

        messages = {
            PathSafetyReason.ROOT_MISSING: "Project root does not exist.",
            PathSafetyReason.ROOT_NOT_DIRECTORY: "Project root is not a directory.",
            PathSafetyReason.ROOT_UNREADABLE: (
                "Project root could not be resolved or read."
            ),
            PathSafetyReason.SYMLINK_LOOP: (
                "Project root contains a symbolic-link cycle."
            ),
        }
        message = messages.get(error.reason, "Project root is not safe to scan.")
        code = (
            CoverageIssueCode.EXTERNAL_SYMLINK
            if error.reason is PathSafetyReason.SYMLINK_LOOP
            else CoverageIssueCode.UNREADABLE
        )
        return CoverageIssue(code=code, message=message)

    @staticmethod
    def _path_issue(error: PathGuardError, relative_path: str) -> CoverageIssue:
        """Translate path-guard reasons without revealing external targets."""

        if error.reason is PathSafetyReason.OUTSIDE_ROOT:
            return CoverageIssue(
                code=CoverageIssueCode.EXTERNAL_SYMLINK,
                message="Symbolic link resolves outside the project root.",
                asset_path=relative_path,
            )
        if error.reason is PathSafetyReason.BROKEN_SYMLINK:
            return CoverageIssue(
                code=CoverageIssueCode.UNREADABLE,
                message="Symbolic link target does not exist.",
                asset_path=relative_path,
            )
        if error.reason is PathSafetyReason.SYMLINK_LOOP:
            return CoverageIssue(
                code=CoverageIssueCode.EXTERNAL_SYMLINK,
                message="Symbolic-link cycle was not followed.",
                asset_path=relative_path,
            )
        return CoverageIssue(
            code=CoverageIssueCode.UNREADABLE,
            message="Filesystem entry could not be safely resolved.",
            asset_path=relative_path,
        )

    @staticmethod
    def _build_result(state: _CollectionState) -> CollectionResult:
        """Freeze mutable traversal state into deterministic public output."""

        assets = tuple(sorted(state.assets, key=lambda item: item.asset.path))
        issues = tuple(
            sorted(
                state.issues,
                key=lambda issue: (
                    issue.asset_path or "",
                    issue.code.value,
                    issue.message,
                ),
            )
        )
        scanned_assets = len(assets)
        coverage = ScanCoverage(
            discovered_assets=state.discovered_assets,
            scanned_assets=scanned_assets,
            skipped_assets=state.skipped_assets,
            complete=not issues and state.skipped_assets == 0,
            issues=issues,
        )
        return CollectionResult(assets=assets, coverage=coverage)

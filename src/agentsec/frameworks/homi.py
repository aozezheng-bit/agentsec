"""Safe static discovery for the Homi Agent workspace contract.

P2-HOMI-01 intentionally keeps Homi-specific file roles in the adapter layer.
The neutral FrameworkAsset model can therefore be reused without pretending that
Homi persona, identity, user-profile, tool-note, and heartbeat semantics are
already part of the versioned Agent Manifest. P2-HOMI-02 owns that precedence
and Manifest vocabulary decision.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final

from agentsec.collectors.path_safety import (
    GuardedPath,
    PathGuard,
    PathGuardError,
    PathSafetyReason,
    SafePathKind,
)
from agentsec.frameworks.base import (
    FrameworkAdapterError,
    FrameworkAdapterMetadata,
    FrameworkAsset,
    FrameworkAssetFormat,
    FrameworkAssetLocator,
    FrameworkAssetRecord,
    FrameworkAssetRole,
    FrameworkAssetScope,
    FrameworkInspectionIssue,
    FrameworkInspectionIssueCode,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.parsers import MarkdownItParser, ParsedMarkdown

_READ_CHUNK_SIZE: Final[int] = 65_536
_HOMI_ROOT_ID: Final[str] = "project"
_HOMI_DISCOVERY_RANK: Final[int] = 100
HOMI_ADAPTER_VERSION = "0.2.0"
_TEMPLATE_MARKERS: Final[tuple[str, ...]] = (
    "what goes here",
    "examples",
    "why separate",
    "add whatever helps",
    "this is your cheat sheet",
)
_HEARTBEAT_TEMPLATE_MARKERS: Final[tuple[str, ...]] = (
    "keep this file empty",
    "skip heartbeat api calls",
    "add tasks below",
    "when you want the agent to check something periodically",
    "heartbeat config",
)
_MARKDOWN_LINK_ONLY = re.compile(r"^[-*+]?\s*\[[^\]]+\]\([^)]+\)\s*$")


class HomiFileRole(StrEnum):
    """Homi-specific semantic role for one standard workspace file."""

    WORKSPACE_POLICY = "workspace_policy"
    PERSONA = "persona"
    IDENTITY = "identity"
    USER_PROFILE = "user_profile"
    TOOL_NOTES = "tool_notes"
    HEARTBEAT_SCHEDULE = "heartbeat_schedule"


_HOMI_FILE_ORDER: Final[tuple[tuple[str, HomiFileRole], ...]] = (
    ("AGENTS.md", HomiFileRole.WORKSPACE_POLICY),
    ("SOUL.md", HomiFileRole.PERSONA),
    ("IDENTITY.md", HomiFileRole.IDENTITY),
    ("USER.md", HomiFileRole.USER_PROFILE),
    ("TOOLS.md", HomiFileRole.TOOL_NOTES),
    ("HEARTBEAT.md", HomiFileRole.HEARTBEAT_SCHEDULE),
)


class HomiFileState(StrEnum):
    """Safe state of one expected Homi workspace file."""

    PRESENT = "present"
    EMPTY = "empty"
    EXAMPLE_ONLY = "example_only"
    MISSING = "missing"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class HomiWorkspaceFile:
    """Value-minimized state for one expected Homi file."""

    name: str
    role: HomiFileRole
    state: HomiFileState
    locator: FrameworkAssetLocator | None = None
    content_sha256: str | None = None
    size_bytes: int | None = None
    line_count: int | None = None
    issue_codes: tuple[FrameworkInspectionIssueCode, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or Path(self.name).name != self.name:
            raise ValueError("Homi workspace file name must be a single filename")
        if not isinstance(self.role, HomiFileRole):
            raise TypeError("Homi workspace file role must be HomiFileRole")
        if not isinstance(self.state, HomiFileState):
            raise TypeError("Homi workspace file state must be HomiFileState")
        if self.state is HomiFileState.MISSING and any(
            value is not None
            for value in (self.locator, self.content_sha256, self.size_bytes)
        ):
            raise ValueError("missing Homi file cannot contain source metadata")
        if self.content_sha256 is not None and (
            len(self.content_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.content_sha256
            )
        ):
            raise ValueError("Homi file digest must be lowercase SHA-256")
        if self.size_bytes is not None and self.size_bytes < 0:
            raise ValueError("Homi file size must not be negative")
        if self.line_count is not None and self.line_count < 0:
            raise ValueError("Homi file line count must not be negative")
        if self.issue_codes != tuple(
            sorted(set(self.issue_codes), key=lambda item: item.value)
        ):
            raise ValueError("Homi file issue codes must be sorted and unique")


@dataclass(frozen=True, slots=True)
class HomiWorkspaceInspection:
    """Homi-specific classification plus the neutral Framework result."""

    files: tuple[HomiWorkspaceFile, ...]
    framework_result: FrameworkInspectionResult
    all_standard_files_present: bool

    def __post_init__(self) -> None:
        expected_names = tuple(name for name, _ in _HOMI_FILE_ORDER)
        actual_names = tuple(item.name for item in self.files)
        if actual_names != expected_names:
            raise ValueError("Homi workspace files must use the standard order")
        if not isinstance(self.framework_result, FrameworkInspectionResult):
            raise TypeError("framework_result must be FrameworkInspectionResult")
        if self.all_standard_files_present != all(
            item.state is not HomiFileState.MISSING for item in self.files
        ):
            raise ValueError("Homi standard-file presence must match file states")

    @property
    def complete(self) -> bool:
        """Return parser/coverage completeness, independent of missing optionals."""

        return self.framework_result.complete


@dataclass(frozen=True, slots=True)
class _HomiCandidate:
    name: str
    role: HomiFileRole
    path: Path
    relative_path: str


@dataclass(slots=True)
class _HomiState:
    records: list[FrameworkAssetRecord] = field(default_factory=list)
    issues: list[FrameworkInspectionIssue] = field(default_factory=list)
    discovered_assets: int = 0
    skipped_assets: int = 0
    stop_requested: bool = False


class HomiAdapter:
    """Discover Homi's six standard files without executing their content."""

    metadata = FrameworkAdapterMetadata(
        framework_id="homi",
        display_name="Homi",
        adapter_version=HOMI_ADAPTER_VERSION,
    )

    def __init__(self) -> None:
        self._markdown_parser = MarkdownItParser()

    def inspect(self, request: FrameworkInspectionRequest) -> FrameworkInspectionResult:
        """Return the neutral inspection result required by FrameworkAdapter."""

        return self.inspect_workspace(request).framework_result

    def inspect_workspace(
        self, request: FrameworkInspectionRequest
    ) -> HomiWorkspaceInspection:
        """Classify and safely parse the six standard Homi workspace files."""

        if not isinstance(request, FrameworkInspectionRequest):
            raise TypeError("request must be FrameworkInspectionRequest")
        try:
            guard = PathGuard.create(request.project_root)
        except PathGuardError as error:
            raise FrameworkAdapterError(
                "Homi workspace root could not be inspected safely."
            ) from error

        state = _HomiState()
        classified: dict[str, HomiWorkspaceFile] = {}
        for name, role_value in _HOMI_FILE_ORDER:
            role = role_value
            candidate = _HomiCandidate(
                name=name,
                role=role,
                path=guard.root / name,
                relative_path=name,
            )
            classified[name] = self._inspect_candidate(
                candidate,
                guard=guard,
                request=request,
                state=state,
            )
            if state.stop_requested:
                for remaining_name, remaining_role_value in _HOMI_FILE_ORDER:
                    if remaining_name not in classified:
                        classified[remaining_name] = HomiWorkspaceFile(
                            name=remaining_name,
                            role=remaining_role_value,
                            state=HomiFileState.SKIPPED,
                            issue_codes=(
                                FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED,
                            ),
                        )
                break

        files = tuple(classified[name] for name, _ in _HOMI_FILE_ORDER)
        issues = tuple(sorted(state.issues, key=lambda issue: issue._sort_key()))
        records = tuple(sorted(state.records, key=lambda record: record.asset.locator))
        framework_result = FrameworkInspectionResult(
            metadata=self.metadata,
            assets=records,
            issues=issues,
            discovered_assets=state.discovered_assets,
            skipped_assets=state.skipped_assets,
            complete=state.skipped_assets == 0 and not issues,
        )
        return HomiWorkspaceInspection(
            files=files,
            framework_result=framework_result,
            all_standard_files_present=all(
                item.state is not HomiFileState.MISSING for item in files
            ),
        )

    def _inspect_candidate(
        self,
        candidate: _HomiCandidate,
        *,
        guard: PathGuard,
        request: FrameworkInspectionRequest,
        state: _HomiState,
    ) -> HomiWorkspaceFile:
        try:
            candidate.path.lstat()
        except FileNotFoundError:
            return HomiWorkspaceFile(
                name=candidate.name,
                role=candidate.role,
                state=HomiFileState.MISSING,
            )
        except OSError:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.UNREADABLE,
            )

        if state.stop_requested:
            return HomiWorkspaceFile(
                name=candidate.name,
                role=candidate.role,
                state=HomiFileState.SKIPPED,
                issue_codes=(FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED,),
            )
        if state.discovered_assets >= request.limits.max_assets:
            state.stop_requested = True
            state.discovered_assets += 1
            self._add_issue(
                state,
                FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED,
                candidate.relative_path,
            )
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED,
                reserve=False,
            )
        state.discovered_assets += 1

        try:
            guarded = guard.inspect(candidate.path)
        except PathGuardError as error:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=self._path_error_code(error),
                reserve=False,
            )
        if guarded.kind is not SafePathKind.FILE:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.UNREADABLE,
                reserve=False,
            )
        if (
            guarded.size_bytes is not None
            and guarded.size_bytes > request.limits.max_file_size_bytes
        ):
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.TOO_LARGE,
                reserve=False,
            )

        try:
            revalidated = guard.inspect(guarded.resolved_path)
            content_bytes = self._read_bounded_bytes(
                revalidated,
                request.limits.max_file_size_bytes,
            )
        except (OSError, PathGuardError):
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.UNREADABLE,
                reserve=False,
            )
        if len(content_bytes) > request.limits.max_file_size_bytes:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.TOO_LARGE,
                reserve=False,
            )
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.UNSUPPORTED_ENCODING,
                reserve=False,
            )

        try:
            document = self._markdown_parser.parse(content)
        except Exception:
            return self._skip_candidate(
                candidate,
                state=state,
                issue_code=FrameworkInspectionIssueCode.PARSE_ERROR,
                reserve=False,
            )

        digest = hashlib.sha256(content_bytes).hexdigest()
        record = FrameworkAssetRecord(
            asset=FrameworkAsset(
                locator=FrameworkAssetLocator(
                    scope=FrameworkAssetScope.PROJECT,
                    root_id=_HOMI_ROOT_ID,
                    path=candidate.relative_path,
                ),
                format=FrameworkAssetFormat.MARKDOWN,
                # Homi semantic roles are intentionally exposed by
                # HomiWorkspaceFile. The neutral role remains instruction data
                # until P2-HOMI-02 defines Manifest role vocabulary.
                roles=frozenset({FrameworkAssetRole.AGENT_INSTRUCTIONS}),
                content_sha256=digest,
                size_bytes=len(content_bytes),
                line_count=document.source_line_count,
                precedence_rank=_HOMI_DISCOVERY_RANK,
            ),
            document=document,
        )
        state.records.append(record)
        file_state = self._classify(candidate.role, content, document)
        return HomiWorkspaceFile(
            name=candidate.name,
            role=candidate.role,
            state=file_state,
            locator=record.asset.locator,
            content_sha256=digest,
            size_bytes=len(content_bytes),
            line_count=document.source_line_count,
        )

    @staticmethod
    def _classify(
        role: HomiFileRole,
        content: str,
        document: ParsedMarkdown,
    ) -> HomiFileState:
        if _is_empty_homi_content(role, content, document):
            return HomiFileState.EMPTY
        if role is HomiFileRole.HEARTBEAT_SCHEDULE and (
            _looks_like_heartbeat_template(content)
        ):
            return HomiFileState.EXAMPLE_ONLY
        if role is HomiFileRole.TOOL_NOTES and _looks_like_template(content):
            return HomiFileState.EXAMPLE_ONLY
        return HomiFileState.PRESENT

    @staticmethod
    def _skip_candidate(
        candidate: _HomiCandidate,
        *,
        state: _HomiState,
        issue_code: FrameworkInspectionIssueCode,
        reserve: bool = True,
    ) -> HomiWorkspaceFile:
        if reserve:
            state.discovered_assets += 1
        state.skipped_assets += 1
        HomiAdapter._add_issue(state, issue_code, candidate.relative_path)
        return HomiWorkspaceFile(
            name=candidate.name,
            role=candidate.role,
            state=HomiFileState.SKIPPED,
            issue_codes=(issue_code,),
        )

    @staticmethod
    def _add_issue(
        state: _HomiState,
        code: FrameworkInspectionIssueCode,
        path: str,
    ) -> None:
        issue = FrameworkInspectionIssue(
            code=code,
            root_id=_HOMI_ROOT_ID,
            path=path,
        )
        if issue not in state.issues:
            state.issues.append(issue)

    @staticmethod
    def _path_error_code(error: PathGuardError) -> FrameworkInspectionIssueCode:
        if error.reason in {
            PathSafetyReason.OUTSIDE_ROOT,
            PathSafetyReason.SYMLINK_LOOP,
        }:
            return FrameworkInspectionIssueCode.EXTERNAL_SYMLINK
        return FrameworkInspectionIssueCode.UNREADABLE

    @staticmethod
    def _read_bounded_bytes(guarded: GuardedPath, max_bytes: int) -> bytes:
        if guarded.kind is not SafePathKind.FILE:
            raise OSError("Homi asset is not a regular file")
        remaining = max_bytes + 1
        chunks: list[bytes] = []
        with guarded.resolved_path.open("rb") as stream:
            while remaining > 0:
                chunk = stream.read(min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        return b"".join(chunks)


def _is_empty_homi_content(
    role: HomiFileRole,
    content: str,
    document: ParsedMarkdown,
) -> bool:
    """Recognize blank/comment-only Homi content without executing Markdown."""

    if not content.strip():
        return True
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("<!--") and stripped.endswith("-->"):
            continue
        if role is HomiFileRole.HEARTBEAT_SCHEDULE and (
            stripped.startswith("#") or stripped in {"\\", "\\\\"}
        ):
            continue
        return False
    del document
    return True


def _looks_like_template(content: str) -> bool:
    """Conservatively identify the shipped TOOLS.md documentation template."""

    lowered = content.casefold()
    return sum(marker in lowered for marker in _TEMPLATE_MARKERS) >= 4


def _looks_like_heartbeat_template(content: str) -> bool:
    """Recognize documentation-only Heartbeat scaffolding without tasks."""

    lowered = content.casefold()
    if sum(marker in lowered for marker in _HEARTBEAT_TEMPLATE_MARKERS) < 2:
        return False
    in_fence = False
    fence_marker = ""
    for raw in content.splitlines():
        stripped = raw.strip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            continue
        if in_fence or not stripped:
            continue
        folded = stripped.casefold()
        if stripped.startswith("#") or stripped in {"---", "\\", "\\\\"}:
            continue
        if stripped.startswith("<!--") and stripped.endswith("-->"):
            continue
        if _MARKDOWN_LINK_ONLY.fullmatch(stripped):
            continue
        if any(marker in folded for marker in _HEARTBEAT_TEMPLATE_MARKERS):
            continue
        return False
    return True


__all__ = [
    "HomiAdapter",
    "HOMI_ADAPTER_VERSION",
    "HomiFileRole",
    "HomiFileState",
    "HomiWorkspaceFile",
    "HomiWorkspaceInspection",
]

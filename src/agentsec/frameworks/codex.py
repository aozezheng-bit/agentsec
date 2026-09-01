"""Safe static discovery and parsing for Codex control assets."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
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
    ParsedFrameworkDocument,
)
from agentsec.parsers import (
    MarkdownItParser,
    McpConfigurationParser,
    ParsedMcpConfiguration,
    PrefixRulesParser,
    TomlStructuredParser,
)

_READ_CHUNK_SIZE: Final[int] = 65_536
_PROJECT_INSTRUCTION_BASE_RANK: Final[int] = 100
_PROJECT_CONFIG_BASE_RANK: Final[int] = 200
_USER_BASE_RANK: Final[int] = 50


@dataclass(frozen=True, slots=True)
class _InspectionRoot:
    """One explicitly bounded root used only during Adapter inspection."""

    root_id: str
    scope: FrameworkAssetScope
    guard: PathGuard


@dataclass(frozen=True, slots=True)
class _AssetCandidate:
    """One logical Codex asset selected before safe reading and parsing."""

    source_root: _InspectionRoot
    absolute_path: Path
    relative_path: str
    format: FrameworkAssetFormat
    roles: frozenset[FrameworkAssetRole]
    precedence_rank: int


@dataclass(slots=True)
class _InspectionState:
    """Private mutable state for deterministic coverage accounting."""

    assets: list[FrameworkAssetRecord] = field(default_factory=list)
    issues: list[FrameworkInspectionIssue] = field(default_factory=list)
    discovered_assets: int = 0
    skipped_assets: int = 0
    stop_requested: bool = False


class CodexAdapter:
    """Discover Codex Agent, Skill, Rules, and MCP assets without execution."""

    metadata = FrameworkAdapterMetadata(
        framework_id="codex",
        display_name="Codex",
        adapter_version="0.1.0",
    )

    def __init__(self, *, codex_home: Path | None = None) -> None:
        if codex_home is not None and not isinstance(codex_home, Path):
            raise TypeError("codex_home must be a Path when provided")
        self._codex_home = codex_home
        self._markdown_parser = MarkdownItParser()
        self._rules_parser = PrefixRulesParser()
        self._toml_parser = TomlStructuredParser()
        self._mcp_parser = McpConfigurationParser()

    def inspect(
        self,
        request: FrameworkInspectionRequest,
    ) -> FrameworkInspectionResult:
        """Inspect only reviewed Codex paths under explicitly bounded roots."""

        if not isinstance(request, FrameworkInspectionRequest):
            raise TypeError("request must be FrameworkInspectionRequest")

        project_root = self._required_root(request.project_root)
        working_directory = self._working_directory(
            project_root.guard,
            request.project_root,
            request.working_directory or request.project_root,
        )
        state = _InspectionState()

        self._discover_project_assets(
            project_root,
            working_directory=working_directory,
            request=request,
            state=state,
        )
        if not state.stop_requested:
            self._discover_user_assets(request=request, state=state)

        return self._build_result(state)

    @staticmethod
    def _required_root(project_root: Path) -> _InspectionRoot:
        try:
            guard = PathGuard.create(project_root)
        except PathGuardError as error:
            raise FrameworkAdapterError(
                "Codex project root could not be inspected safely."
            ) from error
        return _InspectionRoot(
            root_id="project",
            scope=FrameworkAssetScope.PROJECT,
            guard=guard,
        )

    @staticmethod
    def _working_directory(
        guard: PathGuard,
        project_root: Path,
        requested: Path,
    ) -> Path:
        lexical_project_root = Path.absolute(project_root)
        lexical_requested = Path.absolute(requested)
        if lexical_requested.is_relative_to(lexical_project_root):
            relative = lexical_requested.relative_to(lexical_project_root)
            guarded_candidate = guard.root.joinpath(*relative.parts)
        elif lexical_requested.is_relative_to(guard.root):
            guarded_candidate = lexical_requested
        else:
            raise FrameworkAdapterError(
                "Codex working directory must be inside the project root."
            )
        try:
            guarded = guard.inspect(guarded_candidate)
        except PathGuardError as error:
            raise FrameworkAdapterError(
                "Codex working directory must be inside the project root."
            ) from error
        if guarded.kind is not SafePathKind.DIRECTORY:
            raise FrameworkAdapterError(
                "Codex working directory must be inside the project root."
            )
        return guarded.resolved_path

    def _discover_project_assets(
        self,
        project_root: _InspectionRoot,
        *,
        working_directory: Path,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        relative_working_directory = working_directory.relative_to(
            project_root.guard.root
        )
        chain = [project_root.guard.root]
        current = project_root.guard.root
        for part in relative_working_directory.parts:
            current /= part
            chain.append(current)

        allowed_chain = chain[: request.limits.max_depth + 1]
        if len(allowed_chain) < len(chain):
            first_omitted = chain[len(allowed_chain)]
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.DEPTH_EXCEEDED,
                root_id=project_root.root_id,
                path=first_omitted.relative_to(project_root.guard.root).as_posix(),
            )

        for depth, directory in enumerate(allowed_chain):
            if state.stop_requested:
                return
            relative_directory = directory.relative_to(project_root.guard.root)
            self._discover_instruction_files(
                project_root,
                directory=directory,
                relative_directory=relative_directory,
                depth=depth,
                request=request,
                state=state,
            )
            if state.stop_requested:
                return
            self._discover_codex_directory(
                project_root,
                directory=directory,
                relative_directory=relative_directory,
                depth=depth,
                request=request,
                state=state,
            )
            if state.stop_requested:
                return
            self._discover_skills_directory(
                project_root,
                directory=directory,
                relative_directory=relative_directory,
                depth=depth,
                precedence_rank=_PROJECT_CONFIG_BASE_RANK + (depth * 10),
                request=request,
                state=state,
            )

    def _discover_user_assets(
        self,
        *,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        user_root = self._optional_root(
            request.user_home,
            root_id="user_home",
            scope=FrameworkAssetScope.USER,
            missing_is_issue=True,
            state=state,
        )

        codex_root: _InspectionRoot | None
        if self._codex_home is not None:
            codex_root = self._optional_root(
                self._codex_home,
                root_id="codex_home",
                scope=FrameworkAssetScope.USER,
                missing_is_issue=True,
                state=state,
            )
        elif user_root is not None:
            codex_root = self._contained_optional_root(
                user_root,
                relative_path=PurePosixPath(".codex"),
                root_id="codex_home",
                state=state,
            )
        else:
            codex_root = None

        if codex_root is not None and not state.stop_requested:
            self._discover_instruction_files(
                codex_root,
                directory=codex_root.guard.root,
                relative_directory=Path(),
                depth=0,
                request=request,
                state=state,
                user_scope=True,
            )
            if state.stop_requested:
                return
            self._discover_user_codex_configuration(
                codex_root,
                request=request,
                state=state,
            )

        if user_root is not None and not state.stop_requested:
            self._discover_skills_directory(
                user_root,
                directory=user_root.guard.root,
                relative_directory=Path(),
                depth=0,
                precedence_rank=_USER_BASE_RANK,
                request=request,
                state=state,
            )

    @staticmethod
    def _optional_root(
        path: Path | None,
        *,
        root_id: str,
        scope: FrameworkAssetScope,
        missing_is_issue: bool,
        state: _InspectionState,
    ) -> _InspectionRoot | None:
        if path is None:
            return None
        try:
            guard = PathGuard.create(path)
        except PathGuardError as error:
            if missing_is_issue or error.reason is not PathSafetyReason.ROOT_MISSING:
                CodexAdapter._add_issue(
                    state,
                    code=CodexAdapter._path_error_code(error),
                    root_id=root_id,
                    path=None,
                )
            return None
        return _InspectionRoot(root_id=root_id, scope=scope, guard=guard)

    @staticmethod
    def _contained_optional_root(
        parent: _InspectionRoot,
        *,
        relative_path: PurePosixPath,
        root_id: str,
        state: _InspectionState,
    ) -> _InspectionRoot | None:
        candidate = parent.guard.root.joinpath(*relative_path.parts)
        try:
            candidate.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            CodexAdapter._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=parent.root_id,
                path=relative_path.as_posix(),
            )
            return None
        try:
            guarded = parent.guard.inspect(candidate)
        except PathGuardError as error:
            CodexAdapter._add_issue(
                state,
                code=CodexAdapter._path_error_code(error),
                root_id=parent.root_id,
                path=relative_path.as_posix(),
            )
            return None
        if guarded.kind is not SafePathKind.DIRECTORY:
            CodexAdapter._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=parent.root_id,
                path=relative_path.as_posix(),
            )
            return None
        return _InspectionRoot(
            root_id=root_id,
            scope=FrameworkAssetScope.USER,
            guard=PathGuard(guarded.resolved_path),
        )

    def _discover_instruction_files(
        self,
        source_root: _InspectionRoot,
        *,
        directory: Path,
        relative_directory: Path,
        depth: int,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
        user_scope: bool = False,
    ) -> None:
        ranks = (
            ("AGENTS.md", FrameworkAssetRole.AGENT_INSTRUCTIONS, 10, 0),
            ("AGENTS.override.md", FrameworkAssetRole.INSTRUCTION_OVERRIDE, 20, 5),
        )
        for name, role, user_rank, project_offset in ranks:
            if state.stop_requested:
                return
            rank = (
                user_rank
                if user_scope
                else _PROJECT_INSTRUCTION_BASE_RANK + (depth * 10) + project_offset
            )
            self._inspect_fixed_candidate(
                _AssetCandidate(
                    source_root=source_root,
                    absolute_path=directory / name,
                    relative_path=self._relative_path(relative_directory, name),
                    format=FrameworkAssetFormat.MARKDOWN,
                    roles=frozenset({role}),
                    precedence_rank=rank,
                ),
                request=request,
                state=state,
            )

    def _discover_codex_directory(
        self,
        source_root: _InspectionRoot,
        *,
        directory: Path,
        relative_directory: Path,
        depth: int,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        codex_relative = relative_directory / ".codex"
        if not self._depth_allows_directory(
            source_root,
            directory / ".codex",
            relative_path=codex_relative,
            depth=depth + 1,
            request=request,
            state=state,
        ):
            return
        codex_directory = self._inspect_optional_directory(
            source_root,
            directory / ".codex",
            relative_path=codex_relative,
            state=state,
        )
        if codex_directory is None:
            return

        precedence_rank = _PROJECT_CONFIG_BASE_RANK + (depth * 10)
        self._inspect_fixed_candidate(
            _AssetCandidate(
                source_root=source_root,
                absolute_path=codex_directory / "config.toml",
                relative_path=self._relative_path(codex_relative, "config.toml"),
                format=FrameworkAssetFormat.TOML,
                roles=frozenset({FrameworkAssetRole.FRAMEWORK_CONFIG}),
                precedence_rank=precedence_rank,
            ),
            request=request,
            state=state,
        )
        if state.stop_requested:
            return
        rules_relative = codex_relative / "rules"
        if not self._depth_allows_directory(
            source_root,
            codex_directory / "rules",
            relative_path=rules_relative,
            depth=depth + 2,
            request=request,
            state=state,
        ):
            return
        self._discover_rules_directory(
            source_root,
            directory=codex_directory / "rules",
            relative_directory=rules_relative,
            precedence_rank=precedence_rank,
            request=request,
            state=state,
        )

    def _discover_user_codex_configuration(
        self,
        source_root: _InspectionRoot,
        *,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        self._inspect_fixed_candidate(
            _AssetCandidate(
                source_root=source_root,
                absolute_path=source_root.guard.root / "config.toml",
                relative_path="config.toml",
                format=FrameworkAssetFormat.TOML,
                roles=frozenset({FrameworkAssetRole.FRAMEWORK_CONFIG}),
                precedence_rank=_USER_BASE_RANK,
            ),
            request=request,
            state=state,
        )
        if state.stop_requested:
            return
        if not self._depth_allows_directory(
            source_root,
            source_root.guard.root / "rules",
            relative_path=Path("rules"),
            depth=1,
            request=request,
            state=state,
        ):
            return
        self._discover_rules_directory(
            source_root,
            directory=source_root.guard.root / "rules",
            relative_directory=Path("rules"),
            precedence_rank=_USER_BASE_RANK,
            request=request,
            state=state,
        )

    def _discover_rules_directory(
        self,
        source_root: _InspectionRoot,
        *,
        directory: Path,
        relative_directory: Path,
        precedence_rank: int,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        guarded_directory = self._inspect_optional_directory(
            source_root,
            directory,
            relative_path=relative_directory,
            state=state,
        )
        if guarded_directory is None:
            return
        try:
            entries = sorted(guarded_directory.iterdir(), key=lambda path: path.name)
        except OSError:
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=source_root.root_id,
                path=self._path_text(relative_directory),
            )
            return
        for entry in entries:
            if state.stop_requested:
                return
            if not entry.name.endswith(".rules"):
                continue
            self._inspect_fixed_candidate(
                _AssetCandidate(
                    source_root=source_root,
                    absolute_path=entry,
                    relative_path=self._relative_path(
                        relative_directory,
                        entry.name,
                    ),
                    format=FrameworkAssetFormat.RULES,
                    roles=frozenset({FrameworkAssetRole.PREFIX_RULES}),
                    precedence_rank=precedence_rank,
                ),
                request=request,
                state=state,
            )

    def _discover_skills_directory(
        self,
        source_root: _InspectionRoot,
        *,
        directory: Path,
        relative_directory: Path,
        depth: int,
        precedence_rank: int,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        agents_relative = relative_directory / ".agents"
        if not self._depth_allows_directory(
            source_root,
            directory / ".agents",
            relative_path=agents_relative,
            depth=depth + 1,
            request=request,
            state=state,
        ):
            return
        agents_directory = self._inspect_optional_directory(
            source_root,
            directory / ".agents",
            relative_path=agents_relative,
            state=state,
        )
        if agents_directory is None:
            return

        skills_relative = agents_relative / "skills"
        if not self._depth_allows_directory(
            source_root,
            agents_directory / "skills",
            relative_path=skills_relative,
            depth=depth + 2,
            request=request,
            state=state,
        ):
            return
        skills_directory = self._inspect_optional_directory(
            source_root,
            agents_directory / "skills",
            relative_path=skills_relative,
            state=state,
        )
        if skills_directory is None:
            return
        try:
            entries = sorted(skills_directory.iterdir(), key=lambda path: path.name)
        except OSError:
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=source_root.root_id,
                path=self._path_text(skills_relative),
            )
            return

        for entry in entries:
            if state.stop_requested:
                return
            skill_relative = skills_relative / entry.name
            if not self._depth_allows_directory(
                source_root,
                entry,
                relative_path=skill_relative,
                depth=depth + 3,
                request=request,
                state=state,
            ):
                continue
            skill_directory = self._inspect_optional_directory(
                source_root,
                entry,
                relative_path=skill_relative,
                state=state,
                non_directory_is_issue=False,
            )
            if skill_directory is None:
                continue
            self._inspect_fixed_candidate(
                _AssetCandidate(
                    source_root=source_root,
                    absolute_path=skill_directory / "SKILL.md",
                    relative_path=self._relative_path(skill_relative, "SKILL.md"),
                    format=FrameworkAssetFormat.MARKDOWN,
                    roles=frozenset({FrameworkAssetRole.SKILL}),
                    precedence_rank=precedence_rank,
                ),
                request=request,
                state=state,
            )

    def _depth_allows_directory(
        self,
        source_root: _InspectionRoot,
        directory: Path,
        *,
        relative_path: Path,
        depth: int,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> bool:
        if depth <= request.limits.max_depth:
            return True
        try:
            directory.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=source_root.root_id,
                path=self._path_text(relative_path),
            )
            return False
        self._add_issue(
            state,
            code=FrameworkInspectionIssueCode.DEPTH_EXCEEDED,
            root_id=source_root.root_id,
            path=self._path_text(relative_path),
        )
        return False

    def _inspect_optional_directory(
        self,
        source_root: _InspectionRoot,
        directory: Path,
        *,
        relative_path: Path,
        state: _InspectionState,
        non_directory_is_issue: bool = True,
    ) -> Path | None:
        try:
            directory.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=source_root.root_id,
                path=self._path_text(relative_path),
            )
            return None
        try:
            guarded = source_root.guard.inspect(directory)
        except PathGuardError as error:
            self._add_issue(
                state,
                code=self._path_error_code(error),
                root_id=source_root.root_id,
                path=self._path_text(relative_path),
            )
            return None
        if guarded.kind is not SafePathKind.DIRECTORY:
            if non_directory_is_issue:
                self._add_issue(
                    state,
                    code=FrameworkInspectionIssueCode.UNREADABLE,
                    root_id=source_root.root_id,
                    path=self._path_text(relative_path),
                )
            return None
        return guarded.resolved_path

    def _inspect_fixed_candidate(
        self,
        candidate: _AssetCandidate,
        *,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> None:
        try:
            candidate.absolute_path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            if not self._reserve_candidate(candidate, request=request, state=state):
                return
            state.skipped_assets += 1
            self._add_issue(
                state,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                root_id=candidate.source_root.root_id,
                path=candidate.relative_path,
            )
            return

        if not self._reserve_candidate(candidate, request=request, state=state):
            return
        record = self._read_and_parse(candidate, request=request, state=state)
        if record is not None:
            state.assets.append(record)

    @staticmethod
    def _reserve_candidate(
        candidate: _AssetCandidate,
        *,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> bool:
        if state.stop_requested:
            return False
        if state.discovered_assets >= request.limits.max_assets:
            state.discovered_assets += 1
            state.skipped_assets += 1
            state.stop_requested = True
            CodexAdapter._add_issue(
                state,
                code=FrameworkInspectionIssueCode.ASSET_LIMIT_EXCEEDED,
                root_id=candidate.source_root.root_id,
                path=candidate.relative_path,
            )
            return False
        state.discovered_assets += 1
        return True

    def _read_and_parse(
        self,
        candidate: _AssetCandidate,
        *,
        request: FrameworkInspectionRequest,
        state: _InspectionState,
    ) -> FrameworkAssetRecord | None:
        try:
            guarded = candidate.source_root.guard.inspect(candidate.absolute_path)
        except PathGuardError as error:
            return self._skip_candidate(
                candidate,
                code=self._path_error_code(error),
                state=state,
            )
        if guarded.kind is not SafePathKind.FILE:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                state=state,
            )
        if (
            guarded.size_bytes is not None
            and guarded.size_bytes > request.limits.max_file_size_bytes
        ):
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.TOO_LARGE,
                state=state,
            )

        try:
            revalidated = candidate.source_root.guard.inspect(guarded.resolved_path)
        except PathGuardError as error:
            return self._skip_candidate(
                candidate,
                code=self._path_error_code(error),
                state=state,
            )
        if revalidated.kind is not SafePathKind.FILE:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                state=state,
            )
        if (
            revalidated.size_bytes is not None
            and revalidated.size_bytes > request.limits.max_file_size_bytes
        ):
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.TOO_LARGE,
                state=state,
            )

        try:
            content_bytes = self._read_bounded_bytes(
                revalidated,
                request.limits.max_file_size_bytes,
            )
        except OSError:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.UNREADABLE,
                state=state,
            )
        if len(content_bytes) > request.limits.max_file_size_bytes:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.TOO_LARGE,
                state=state,
            )
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.UNSUPPORTED_ENCODING,
                state=state,
            )

        try:
            document, roles, mcp_configuration = self._parse_candidate(
                candidate,
                content,
            )
        except Exception:
            return self._skip_candidate(
                candidate,
                code=FrameworkInspectionIssueCode.PARSE_ERROR,
                state=state,
            )

        asset = FrameworkAsset(
            locator=FrameworkAssetLocator(
                scope=candidate.source_root.scope,
                root_id=candidate.source_root.root_id,
                path=candidate.relative_path,
            ),
            format=candidate.format,
            roles=roles,
            content_sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
            precedence_rank=candidate.precedence_rank,
        )
        return FrameworkAssetRecord(
            asset=asset,
            document=document,
            mcp_configuration=mcp_configuration,
        )

    def _parse_candidate(
        self,
        candidate: _AssetCandidate,
        content: str,
    ) -> tuple[
        ParsedFrameworkDocument,
        frozenset[FrameworkAssetRole],
        ParsedMcpConfiguration | None,
    ]:
        if candidate.format is FrameworkAssetFormat.MARKDOWN:
            return self._markdown_parser.parse(content), candidate.roles, None
        if candidate.format is FrameworkAssetFormat.RULES:
            return self._rules_parser.parse(content), candidate.roles, None
        if candidate.format is FrameworkAssetFormat.TOML:
            document = self._toml_parser.parse(content)
            mcp_configuration = self._mcp_parser.parse(document)
            if not mcp_configuration.servers:
                return document, candidate.roles, None
            return (
                document,
                frozenset(
                    {
                        FrameworkAssetRole.FRAMEWORK_CONFIG,
                        FrameworkAssetRole.MCP_CONFIG,
                    }
                ),
                mcp_configuration,
            )
        raise FrameworkAdapterError("Codex Adapter selected an unsupported format.")

    @staticmethod
    def _read_bounded_bytes(guarded: GuardedPath, max_bytes: int) -> bytes:
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

    @staticmethod
    def _skip_candidate(
        candidate: _AssetCandidate,
        *,
        code: FrameworkInspectionIssueCode,
        state: _InspectionState,
    ) -> None:
        state.skipped_assets += 1
        CodexAdapter._add_issue(
            state,
            code=code,
            root_id=candidate.source_root.root_id,
            path=candidate.relative_path,
        )
        return None

    @staticmethod
    def _path_error_code(error: PathGuardError) -> FrameworkInspectionIssueCode:
        if error.reason in {
            PathSafetyReason.OUTSIDE_ROOT,
            PathSafetyReason.SYMLINK_LOOP,
        }:
            return FrameworkInspectionIssueCode.EXTERNAL_SYMLINK
        return FrameworkInspectionIssueCode.UNREADABLE

    @staticmethod
    def _add_issue(
        state: _InspectionState,
        *,
        code: FrameworkInspectionIssueCode,
        root_id: str,
        path: str | None,
    ) -> None:
        issue = FrameworkInspectionIssue(code=code, root_id=root_id, path=path)
        if issue not in state.issues:
            state.issues.append(issue)

    @staticmethod
    def _relative_path(directory: Path, name: str) -> str:
        path = directory / name
        return CodexAdapter._path_text(path)

    @staticmethod
    def _path_text(path: Path) -> str:
        rendered = path.as_posix()
        return rendered[2:] if rendered.startswith("./") else rendered

    def _build_result(self, state: _InspectionState) -> FrameworkInspectionResult:
        assets = tuple(sorted(state.assets, key=lambda record: record.asset.locator))
        issues = tuple(sorted(state.issues, key=lambda issue: issue._sort_key()))
        return FrameworkInspectionResult(
            metadata=self.metadata,
            assets=assets,
            issues=issues,
            discovered_assets=state.discovered_assets,
            skipped_assets=state.skipped_assets,
            complete=state.skipped_assets == 0 and not issues,
        )

"""CommonMark, safe frontmatter, and reference extraction for AgentSec."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

import yaml
from markdown_it import MarkdownIt
from markdown_it.token import Token
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agentsec.parsers.base import (
    FrontmatterField,
    FrontmatterIssueCode,
    FrontmatterStatus,
    MarkdownBlock,
    MarkdownBlockKind,
    MarkdownFrontmatter,
    MarkdownParseError,
    MarkdownReference,
    ObfuscationAnalyzer,
    ParsedMarkdown,
    ReferenceKind,
    ReferenceTargetKind,
)
from agentsec.parsers.obfuscation import DeterministicObfuscationAnalyzer

_LIST_OPEN_TYPES = {"bullet_list_open", "ordered_list_open"}
_LIST_CLOSE_TYPES = {"bullet_list_close", "ordered_list_close"}
_ALLOWED_SCALAR_TAGS = {
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:str",
}
_WINDOWS_ABSOLUTE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class _FrontmatterExtraction:
    """Frontmatter result plus same-line-count Markdown parser input."""

    frontmatter: MarkdownFrontmatter | None
    markdown_content: str


class _FrontmatterValidationError(ValueError):
    """Internal typed validation failure for non-fatal frontmatter issues."""

    def __init__(self, issue_code: FrontmatterIssueCode) -> None:
        self.issue_code = issue_code
        super().__init__(issue_code.value)


class _AnalysisMarkdownIt(MarkdownIt):
    """Retain dangerous URI schemes as analyzable data instead of rendering."""

    def validateLink(self, url: str) -> bool:
        """Accept every syntactic destination because AgentSec never renders it."""

        del url
        return True


class MarkdownItParser:
    """Parse CommonMark, frontmatter, and targets without dereferencing data."""

    def __init__(
        self,
        *,
        obfuscation_analyzer: ObfuscationAnalyzer | None = None,
    ) -> None:
        self._parser = _AnalysisMarkdownIt("commonmark", {"html": False})
        self._obfuscation_analyzer = (
            obfuscation_analyzer
            if obfuscation_analyzer is not None
            else DeterministicObfuscationAnalyzer()
        )

    def parse(self, content: str) -> ParsedMarkdown:
        """Return deterministic structures with 1-based inclusive source ranges."""

        try:
            extracted = self._extract_frontmatter(content)
            environment: dict[str, Any] = {}
            tokens = self._parser.parse(extracted.markdown_content, environment)
            document = self._build_document(
                content,
                tokens,
                environment,
                extracted.frontmatter,
            )
            return replace(
                document,
                indicators=self._obfuscation_analyzer.analyze(content, document),
            )
        except MarkdownParseError:
            raise
        except Exception as error:
            raise MarkdownParseError("Markdown parsing failed safely.") from error

    def _build_document(
        self,
        content: str,
        tokens: list[Token],
        environment: dict[str, Any],
        frontmatter: MarkdownFrontmatter | None,
    ) -> ParsedMarkdown:
        """Adapt parser tokens into the smaller Phase 1 vocabulary."""

        source_lines = content.splitlines(keepends=True)
        source_line_count = len(content.splitlines())
        blocks: list[MarkdownBlock] = []
        references: list[MarkdownReference] = []
        heading_stack: list[tuple[int, str]] = []
        list_stack: list[bool] = []
        list_item_depth = 0

        for index, token in enumerate(tokens):
            if token.type in _LIST_OPEN_TYPES:
                list_stack.append(token.type == "ordered_list_open")
                continue
            if token.type in _LIST_CLOSE_TYPES:
                if not list_stack:
                    raise MarkdownParseError("Markdown list token nesting is invalid.")
                list_stack.pop()
                continue

            if token.type == "list_item_open":
                if not list_stack:
                    raise MarkdownParseError("Markdown list item has no parent list.")
                text = self._list_item_text(tokens, index, token.level)
                blocks.append(
                    self._make_block(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        kind=MarkdownBlockKind.LIST_ITEM,
                        text=text,
                        heading_path=self._heading_path(heading_stack),
                        ordered=list_stack[-1],
                        list_depth=len(list_stack),
                    )
                )
                list_item_depth += 1
                continue
            if token.type == "list_item_close":
                if list_item_depth < 1:
                    raise MarkdownParseError("Markdown list item nesting is invalid.")
                list_item_depth -= 1
                continue

            if token.type == "heading_open":
                inline = self._following_inline(tokens, index)
                text = self._inline_text(inline)
                heading_level = self._heading_level(token)
                while heading_stack and heading_stack[-1][0] >= heading_level:
                    heading_stack.pop()
                heading_stack.append((heading_level, text))
                blocks.append(
                    self._make_block(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        kind=MarkdownBlockKind.HEADING,
                        text=text,
                        heading_path=self._heading_path(heading_stack),
                        heading_level=heading_level,
                    )
                )
                continue

            if token.type == "paragraph_open" and list_item_depth == 0:
                inline = self._following_inline(tokens, index)
                blocks.append(
                    self._make_block(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        kind=MarkdownBlockKind.PARAGRAPH,
                        text=self._inline_text(inline),
                        heading_path=self._heading_path(heading_stack),
                    )
                )
                continue

            if token.type == "inline":
                references.extend(
                    self._inline_references(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        heading_path=self._heading_path(heading_stack),
                    )
                )
                continue

            if token.type == "fence":
                blocks.append(
                    self._make_block(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        kind=MarkdownBlockKind.FENCED_CODE,
                        text=token.content,
                        heading_path=self._heading_path(heading_stack),
                        fence_info=token.info.strip() or None,
                    )
                )
                continue

            if token.type == "code_block":
                blocks.append(
                    self._make_block(
                        token=token,
                        source_lines=source_lines,
                        source_line_count=source_line_count,
                        kind=MarkdownBlockKind.INDENTED_CODE,
                        text=token.content,
                        heading_path=self._heading_path(heading_stack),
                    )
                )

        if list_stack or list_item_depth:
            raise MarkdownParseError("Markdown list tokens did not close cleanly.")

        references.extend(
            self._definition_references(
                environment=environment,
                source_lines=source_lines,
                source_line_count=source_line_count,
                blocks=blocks,
            )
        )
        references.sort(
            key=lambda reference: (reference.start_line, reference.end_line)
        )

        return ParsedMarkdown(
            blocks=tuple(blocks),
            source_line_count=source_line_count,
            frontmatter=frontmatter,
            references=tuple(references),
        )

    def _extract_frontmatter(self, content: str) -> _FrontmatterExtraction:
        """Detect first-line frontmatter and mask it from CommonMark parsing."""

        source_lines = content.splitlines(keepends=True)
        if not source_lines or not self._is_frontmatter_marker(
            source_lines[0],
            first_line=True,
        ):
            return _FrontmatterExtraction(frontmatter=None, markdown_content=content)

        closing_index = next(
            (
                index
                for index, line in enumerate(source_lines[1:], start=1)
                if self._is_frontmatter_closer(line)
            ),
            None,
        )
        if closing_index is None:
            frontmatter = MarkdownFrontmatter(
                status=FrontmatterStatus.MALFORMED,
                start_line=1,
                end_line=len(content.splitlines()),
                raw_text=content,
                issue_code=FrontmatterIssueCode.UNCLOSED,
            )
            masked_lines = list(source_lines)
            masked_lines[0] = self._blank_line(masked_lines[0])
            return _FrontmatterExtraction(
                frontmatter=frontmatter,
                markdown_content="".join(masked_lines),
            )

        end_line = closing_index + 1
        raw_text = "".join(source_lines[: closing_index + 1])
        body = "".join(source_lines[1:closing_index])
        try:
            fields = self._parse_frontmatter_fields(
                body=body,
                source_lines=source_lines,
                closing_index=closing_index,
            )
            frontmatter = MarkdownFrontmatter(
                status=FrontmatterStatus.VALID,
                start_line=1,
                end_line=end_line,
                raw_text=raw_text,
                fields=fields,
            )
        except _FrontmatterValidationError as error:
            frontmatter = MarkdownFrontmatter(
                status=FrontmatterStatus.MALFORMED,
                start_line=1,
                end_line=end_line,
                raw_text=raw_text,
                issue_code=error.issue_code,
            )

        masked_lines = list(source_lines)
        for index in range(closing_index + 1):
            masked_lines[index] = self._blank_line(masked_lines[index])
        return _FrontmatterExtraction(
            frontmatter=frontmatter,
            markdown_content="".join(masked_lines),
        )

    def _parse_frontmatter_fields(
        self,
        *,
        body: str,
        source_lines: list[str],
        closing_index: int,
    ) -> tuple[FrontmatterField, ...]:
        """Safely load a top-level YAML mapping into immutable field values."""

        try:
            for token in yaml.scan(body, Loader=yaml.SafeLoader):
                if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                    raise _FrontmatterValidationError(FrontmatterIssueCode.UNSAFE_YAML)
            node = yaml.compose(body, Loader=yaml.SafeLoader)
            loaded = yaml.safe_load(body)
        except _FrontmatterValidationError:
            raise
        except yaml.YAMLError as error:
            raise _FrontmatterValidationError(
                FrontmatterIssueCode.INVALID_YAML
            ) from error

        if node is None and loaded is None:
            return ()
        if not isinstance(node, MappingNode) or not isinstance(loaded, dict):
            raise _FrontmatterValidationError(FrontmatterIssueCode.NON_MAPPING)

        self._validate_yaml_node(node)
        if any(not isinstance(key, str) or not key for key in loaded):
            raise _FrontmatterValidationError(FrontmatterIssueCode.UNSUPPORTED_VALUE)

        key_nodes = [key_node for key_node, _ in node.value]
        fields: list[FrontmatterField] = []
        for index, key_node in enumerate(key_nodes):
            if not isinstance(key_node, ScalarNode):
                raise _FrontmatterValidationError(
                    FrontmatterIssueCode.UNSUPPORTED_VALUE
                )
            name = key_node.value
            start_line = key_node.start_mark.line + 2
            end_line = (
                key_nodes[index + 1].start_mark.line + 1
                if index + 1 < len(key_nodes)
                else closing_index
            )
            fields.append(
                FrontmatterField(
                    name=name,
                    value=self._freeze_yaml_value(loaded[name]),
                    start_line=start_line,
                    end_line=end_line,
                    raw_text="".join(source_lines[start_line - 1 : end_line]),
                )
            )
        return tuple(fields)

    def _validate_yaml_node(self, node: Node) -> None:
        """Reject duplicate keys and YAML-specific value types recursively."""

        if isinstance(node, ScalarNode):
            if node.tag not in _ALLOWED_SCALAR_TAGS:
                raise _FrontmatterValidationError(
                    FrontmatterIssueCode.UNSUPPORTED_VALUE
                )
            return
        if isinstance(node, SequenceNode):
            for child in node.value:
                self._validate_yaml_node(child)
            return
        if isinstance(node, MappingNode):
            seen_keys: set[str] = set()
            for key_node, value_node in node.value:
                if (
                    not isinstance(key_node, ScalarNode)
                    or key_node.tag != "tag:yaml.org,2002:str"
                    or not key_node.value
                ):
                    raise _FrontmatterValidationError(
                        FrontmatterIssueCode.UNSUPPORTED_VALUE
                    )
                if key_node.value in seen_keys:
                    raise _FrontmatterValidationError(
                        FrontmatterIssueCode.DUPLICATE_KEY
                    )
                seen_keys.add(key_node.value)
                self._validate_yaml_node(value_node)
            return
        raise _FrontmatterValidationError(FrontmatterIssueCode.UNSUPPORTED_VALUE)

    def _freeze_yaml_value(self, value: object) -> object:
        """Convert SafeLoader output into deterministic immutable JSON-like data."""

        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise _FrontmatterValidationError(
                    FrontmatterIssueCode.UNSUPPORTED_VALUE
                )
            return value
        if isinstance(value, list):
            return tuple(self._freeze_yaml_value(item) for item in value)
        if isinstance(value, dict):
            if any(not isinstance(key, str) or not key for key in value):
                raise _FrontmatterValidationError(
                    FrontmatterIssueCode.UNSUPPORTED_VALUE
                )
            return tuple(
                (key, self._freeze_yaml_value(item)) for key, item in value.items()
            )
        raise _FrontmatterValidationError(FrontmatterIssueCode.UNSUPPORTED_VALUE)

    @classmethod
    def _inline_references(
        cls,
        *,
        token: Token,
        source_lines: list[str],
        source_line_count: int,
        heading_path: tuple[str, ...],
    ) -> tuple[MarkdownReference, ...]:
        """Extract link and image targets from one inline token without fetching."""

        if token.children is None:
            return ()
        start_index, end_index = cls._line_map(token, source_line_count)
        raw_text = "".join(source_lines[start_index:end_index])
        references: list[MarkdownReference] = []

        for index, child in enumerate(token.children):
            if child.type == "image":
                target = cls._string_attr(child, "src")
                references.append(
                    MarkdownReference(
                        kind=ReferenceKind.IMAGE,
                        target_kind=cls._classify_target(target),
                        target=target,
                        label=child.content or None,
                        title=cls._string_attr(child, "title") or None,
                        start_line=start_index + 1,
                        end_line=end_index,
                        raw_text=raw_text,
                        heading_path=heading_path,
                    )
                )
            elif child.type == "link_open":
                target = cls._string_attr(child, "href")
                label = cls._link_label(token.children, index)
                references.append(
                    MarkdownReference(
                        kind=ReferenceKind.LINK,
                        target_kind=cls._classify_target(target),
                        target=target,
                        label=label or None,
                        title=cls._string_attr(child, "title") or None,
                        start_line=start_index + 1,
                        end_line=end_index,
                        raw_text=raw_text,
                        heading_path=heading_path,
                    )
                )
        return tuple(references)

    @staticmethod
    def _string_attr(token: Token, name: str) -> str:
        """Return one markdown-it attribute as deterministic text."""

        value = token.attrGet(name)
        return "" if value is None else str(value)

    @classmethod
    def _definition_references(
        cls,
        *,
        environment: dict[str, Any],
        source_lines: list[str],
        source_line_count: int,
        blocks: list[MarkdownBlock],
    ) -> tuple[MarkdownReference, ...]:
        """Extract reference definitions, including definitions never used inline."""

        raw_references = environment.get("references", {})
        if not isinstance(raw_references, dict):
            raise MarkdownParseError("Markdown reference environment is invalid.")

        references: list[MarkdownReference] = []
        for label, payload in raw_references.items():
            if not isinstance(label, str) or not isinstance(payload, dict):
                raise MarkdownParseError("Markdown reference definition is invalid.")
            target = payload.get("href", "")
            title = payload.get("title")
            line_map = payload.get("map")
            if (
                not isinstance(target, str)
                or title is not None
                and not isinstance(title, str)
                or not isinstance(line_map, list)
                or len(line_map) != 2
                or not all(isinstance(value, int) for value in line_map)
            ):
                raise MarkdownParseError("Markdown reference definition is invalid.")
            start_index, end_index = line_map
            if not 0 <= start_index < end_index <= source_line_count:
                raise MarkdownParseError(
                    "Markdown reference definition range is invalid."
                )
            references.append(
                MarkdownReference(
                    kind=ReferenceKind.DEFINITION,
                    target_kind=cls._classify_target(target),
                    target=target,
                    label=label,
                    title=title or None,
                    start_line=start_index + 1,
                    end_line=end_index,
                    raw_text="".join(source_lines[start_index:end_index]),
                    heading_path=cls._heading_path_for_line(blocks, start_index + 1),
                )
            )
        return tuple(references)

    @classmethod
    def _link_label(cls, children: list[Token], start_index: int) -> str:
        """Return normalized visible text inside one link-open/link-close pair."""

        depth = 1
        enclosed: list[Token] = []
        for child in children[start_index + 1 :]:
            if child.type == "link_open":
                depth += 1
            elif child.type == "link_close":
                depth -= 1
                if depth == 0:
                    break
            if depth >= 1:
                enclosed.append(child)
        return cls._children_text(enclosed)

    @classmethod
    def _children_text(cls, children: list[Token]) -> str:
        """Flatten inline child tokens into visible text."""

        parts: list[str] = []
        for child in children:
            if child.type in {"text", "code_inline", "html_inline"}:
                parts.append(child.content)
            elif child.type in {"softbreak", "hardbreak"}:
                parts.append("\n")
            elif child.type == "image":
                parts.append(child.content)
        return "".join(parts)

    @staticmethod
    def _classify_target(target: str) -> ReferenceTargetKind:
        """Classify a target string without opening, resolving, or requesting it."""

        if not target:
            return ReferenceTargetKind.EMPTY
        if target.startswith("#"):
            return ReferenceTargetKind.ANCHOR
        if _WINDOWS_ABSOLUTE_PATTERN.match(target) or target.startswith("\\"):
            return ReferenceTargetKind.ABSOLUTE_PATH

        try:
            parsed = urlsplit(target)
        except ValueError:
            return ReferenceTargetKind.URI
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"} or parsed.netloc:
            return ReferenceTargetKind.EXTERNAL_URL
        if target.startswith("/"):
            return ReferenceTargetKind.ABSOLUTE_PATH
        if scheme == "mailto":
            return ReferenceTargetKind.EMAIL
        if scheme == "file":
            return ReferenceTargetKind.ABSOLUTE_PATH
        if scheme:
            return ReferenceTargetKind.URI
        return ReferenceTargetKind.RELATIVE_PATH

    @staticmethod
    def _is_frontmatter_marker(line: str, *, first_line: bool) -> bool:
        """Recognize a column-zero delimiter with optional trailing whitespace."""

        candidate = line.rstrip("\r\n").rstrip(" \t")
        if first_line:
            candidate = candidate.removeprefix("\ufeff")
        return candidate == "---"

    @classmethod
    def _is_frontmatter_closer(cls, line: str) -> bool:
        """Recognize supported YAML document terminators at column zero."""

        candidate = line.rstrip("\r\n").rstrip(" \t")
        return candidate in {"---", "..."}

    @staticmethod
    def _blank_line(line: str) -> str:
        """Mask source text while preserving its exact line count and endings."""

        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        return " " * len(content) + ending

    @classmethod
    def _make_block(
        cls,
        *,
        token: Token,
        source_lines: list[str],
        source_line_count: int,
        kind: MarkdownBlockKind,
        text: str,
        heading_path: tuple[str, ...],
        heading_level: int | None = None,
        ordered: bool | None = None,
        list_depth: int | None = None,
        fence_info: str | None = None,
    ) -> MarkdownBlock:
        """Create one validated block from a token's half-open line map."""

        start_index, end_index = cls._line_map(token, source_line_count)
        return MarkdownBlock(
            kind=kind,
            start_line=start_index + 1,
            end_line=end_index,
            raw_text="".join(source_lines[start_index:end_index]),
            text=text,
            heading_path=heading_path,
            heading_level=heading_level,
            ordered=ordered,
            list_depth=list_depth,
            fence_info=fence_info,
        )

    @staticmethod
    def _line_map(token: Token, source_line_count: int) -> tuple[int, int]:
        """Validate markdown-it's zero-based half-open source line map."""

        if token.map is None or len(token.map) != 2:
            raise MarkdownParseError("Markdown block has no source line range.")
        start_index, end_index = token.map
        if not 0 <= start_index < end_index <= source_line_count:
            raise MarkdownParseError("Markdown block source line range is invalid.")
        return start_index, end_index

    @staticmethod
    def _following_inline(tokens: list[Token], index: int) -> Token:
        """Return the inline token belonging to a heading or paragraph open."""

        inline_index = index + 1
        if inline_index >= len(tokens) or tokens[inline_index].type != "inline":
            raise MarkdownParseError("Markdown text block has no inline content.")
        return tokens[inline_index]

    @classmethod
    def _inline_text(cls, token: Token) -> str:
        """Produce plain analysis text while retaining raw source separately."""

        if token.children is None:
            return token.content
        return cls._children_text(token.children)

    @classmethod
    def _list_item_text(
        cls,
        tokens: list[Token],
        start_index: int,
        item_level: int,
    ) -> str:
        """Collect direct item text without duplicating nested list content."""

        parts: list[str] = []
        nested_list_depth = 0
        for token in tokens[start_index + 1 :]:
            if token.type == "list_item_close" and token.level == item_level:
                break
            if token.type in _LIST_OPEN_TYPES:
                nested_list_depth += 1
                continue
            if token.type in _LIST_CLOSE_TYPES:
                nested_list_depth -= 1
                if nested_list_depth < 0:
                    raise MarkdownParseError("Markdown nested-list tokens are invalid.")
                continue
            if token.type == "inline" and nested_list_depth == 0:
                text = cls._inline_text(token)
                if text:
                    parts.append(text)
        return "\n\n".join(parts)

    @staticmethod
    def _heading_level(token: Token) -> int:
        """Extract a validated heading level from markdown-it's tag."""

        if len(token.tag) != 2 or token.tag[0] != "h" or not token.tag[1].isdigit():
            raise MarkdownParseError("Markdown heading level is invalid.")
        level = int(token.tag[1])
        if not 1 <= level <= 6:
            raise MarkdownParseError("Markdown heading level is invalid.")
        return level

    @staticmethod
    def _heading_path(heading_stack: list[tuple[int, str]]) -> tuple[str, ...]:
        """Return the current heading hierarchy as normalized text."""

        return tuple(text for _, text in heading_stack)

    @staticmethod
    def _heading_path_for_line(
        blocks: list[MarkdownBlock],
        line: int,
    ) -> tuple[str, ...]:
        """Return the last heading context established before a source line."""

        heading_path: tuple[str, ...] = ()
        for block in blocks:
            if block.start_line > line:
                break
            if block.kind is MarkdownBlockKind.HEADING:
                heading_path = block.heading_path
        return heading_path

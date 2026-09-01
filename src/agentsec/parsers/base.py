"""Interfaces and immutable structures for non-executing Markdown parsing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class MarkdownBlockKind(StrEnum):
    """Phase 1 Markdown block kinds needed by deterministic rules."""

    HEADING = "heading"
    PARAGRAPH = "paragraph"
    LIST_ITEM = "list_item"
    FENCED_CODE = "fenced_code"
    INDENTED_CODE = "indented_code"


class FrontmatterStatus(StrEnum):
    """Whether a detected frontmatter region was safely decoded."""

    VALID = "valid"
    MALFORMED = "malformed"


class FrontmatterIssueCode(StrEnum):
    """Non-fatal reasons detected frontmatter could not be structured."""

    UNCLOSED = "unclosed"
    INVALID_YAML = "invalid_yaml"
    NON_MAPPING = "non_mapping"
    UNSAFE_YAML = "unsafe_yaml"
    DUPLICATE_KEY = "duplicate_key"
    UNSUPPORTED_VALUE = "unsupported_value"


class ReferenceKind(StrEnum):
    """Markdown constructs that declare a target reference."""

    LINK = "link"
    IMAGE = "image"
    DEFINITION = "definition"


class ReferenceTargetKind(StrEnum):
    """Static target classification that never dereferences the target."""

    EXTERNAL_URL = "external_url"
    EMAIL = "email"
    ANCHOR = "anchor"
    RELATIVE_PATH = "relative_path"
    ABSOLUTE_PATH = "absolute_path"
    URI = "uri"
    EMPTY = "empty"


class ObfuscationKind(StrEnum):
    """Deterministic text anomalies that require later security interpretation."""

    BASE64_LIKE = "base64_like"
    LONG_LINE = "long_line"
    LONG_BLOCK = "long_block"
    ZERO_WIDTH = "zero_width"
    BIDI_CONTROL = "bidi_control"
    CONTROL_CHARACTER = "control_character"
    MIXED_SCRIPT_CONFUSABLE = "mixed_script_confusable"


@dataclass(frozen=True, slots=True)
class MarkdownBlock:
    """One source-backed Markdown block with normalized analysis text."""

    kind: MarkdownBlockKind
    start_line: int
    end_line: int
    raw_text: str
    text: str
    heading_path: tuple[str, ...] = ()
    heading_level: int | None = None
    ordered: bool | None = None
    list_depth: int | None = None
    fence_info: str | None = None

    def __post_init__(self) -> None:
        """Keep line and kind-specific metadata coherent."""

        _validate_line_range(self.start_line, self.end_line, "Markdown block")

        if self.kind is MarkdownBlockKind.HEADING:
            if self.heading_level is None or not 1 <= self.heading_level <= 6:
                raise ValueError("heading block requires a level from 1 through 6")
        elif self.heading_level is not None:
            raise ValueError("heading_level is valid only for heading blocks")

        if self.kind is MarkdownBlockKind.LIST_ITEM:
            if self.ordered is None or self.list_depth is None or self.list_depth < 1:
                raise ValueError("list item requires order and positive depth metadata")
        elif self.ordered is not None or self.list_depth is not None:
            raise ValueError("list metadata is valid only for list-item blocks")

        if (
            self.kind is not MarkdownBlockKind.FENCED_CODE
            and self.fence_info is not None
        ):
            raise ValueError("fence_info is valid only for fenced-code blocks")


@dataclass(frozen=True, slots=True)
class FrontmatterField:
    """One immutable top-level frontmatter field with source evidence."""

    name: str
    value: object
    start_line: int
    end_line: int
    raw_text: str

    def __post_init__(self) -> None:
        """Require a named field and coherent source range."""

        if not self.name:
            raise ValueError("frontmatter field name must not be empty")
        _validate_line_range(self.start_line, self.end_line, "Frontmatter field")


@dataclass(frozen=True, slots=True)
class MarkdownFrontmatter:
    """Detected YAML frontmatter, valid or safely preserved as malformed."""

    status: FrontmatterStatus
    start_line: int
    end_line: int
    raw_text: str
    fields: tuple[FrontmatterField, ...] = ()
    issue_code: FrontmatterIssueCode | None = None

    def __post_init__(self) -> None:
        """Keep valid and malformed representations unambiguous."""

        _validate_line_range(self.start_line, self.end_line, "Frontmatter")
        if self.status is FrontmatterStatus.VALID:
            if self.issue_code is not None:
                raise ValueError("valid frontmatter cannot contain an issue code")
        else:
            if self.issue_code is None:
                raise ValueError("malformed frontmatter requires an issue code")
            if self.fields:
                raise ValueError("malformed frontmatter cannot expose partial fields")


@dataclass(frozen=True, slots=True)
class MarkdownReference:
    """A source-backed target declaration that has not been dereferenced."""

    kind: ReferenceKind
    target_kind: ReferenceTargetKind
    target: str
    start_line: int
    end_line: int
    raw_text: str
    label: str | None = None
    title: str | None = None
    heading_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require coherent source location and non-empty optional labels."""

        _validate_line_range(self.start_line, self.end_line, "Markdown reference")
        if self.label is not None and not self.label:
            raise ValueError("reference label must be non-empty when present")
        if self.title is not None and not self.title:
            raise ValueError("reference title must be non-empty when present")
        if self.target_kind is ReferenceTargetKind.EMPTY and self.target:
            raise ValueError("empty target kind requires an empty target")
        if self.target_kind is not ReferenceTargetKind.EMPTY and not self.target:
            raise ValueError("non-empty target kind requires a target")


@dataclass(frozen=True, slots=True)
class ObfuscationIndicator:
    """Source-backed anomaly metadata kept separate from security findings."""

    kind: ObfuscationKind
    start_line: int
    end_line: int
    character_count: int | None = None
    codepoints: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()
    heading_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require deterministic, non-secret explanatory evidence."""

        _validate_line_range(self.start_line, self.end_line, "Obfuscation indicator")
        if self.character_count is not None and self.character_count < 1:
            raise ValueError("indicator character_count must be positive")
        if self.codepoints != tuple(sorted(set(self.codepoints))):
            raise ValueError("indicator codepoints must be sorted and unique")
        if self.scripts != tuple(sorted(set(self.scripts))):
            raise ValueError("indicator scripts must be sorted and unique")
        if (
            self.kind is ObfuscationKind.MIXED_SCRIPT_CONFUSABLE
            and len(self.scripts) < 2
        ):
            raise ValueError("mixed-script indicator requires at least two scripts")


@dataclass(frozen=True, slots=True)
class ParsedMarkdown:
    """A deterministic flat Markdown AST with frontmatter and references."""

    blocks: tuple[MarkdownBlock, ...]
    source_line_count: int
    frontmatter: MarkdownFrontmatter | None = None
    references: tuple[MarkdownReference, ...] = ()
    indicators: tuple[ObfuscationIndicator, ...] = ()

    def __post_init__(self) -> None:
        """Require every source range to fit the source document."""

        if self.source_line_count < 0:
            raise ValueError("source_line_count must not be negative")

        previous_start = 0
        for block in self.blocks:
            _validate_within_source(
                block.start_line,
                block.end_line,
                self.source_line_count,
                "Markdown block",
            )
            if block.start_line < previous_start:
                raise ValueError("Markdown blocks must be ordered by source position")
            previous_start = block.start_line

        if self.frontmatter is not None:
            _validate_within_source(
                self.frontmatter.start_line,
                self.frontmatter.end_line,
                self.source_line_count,
                "Frontmatter",
            )
            for field in self.frontmatter.fields:
                _validate_within_source(
                    field.start_line,
                    field.end_line,
                    self.source_line_count,
                    "Frontmatter field",
                )

        previous_reference_start = 0
        for reference in self.references:
            _validate_within_source(
                reference.start_line,
                reference.end_line,
                self.source_line_count,
                "Markdown reference",
            )
            if reference.start_line < previous_reference_start:
                raise ValueError(
                    "Markdown references must be ordered by source position"
                )
            previous_reference_start = reference.start_line

        previous_indicator_start = 0
        for indicator in self.indicators:
            _validate_within_source(
                indicator.start_line,
                indicator.end_line,
                self.source_line_count,
                "Obfuscation indicator",
            )
            if indicator.start_line < previous_indicator_start:
                raise ValueError(
                    "Obfuscation indicators must be ordered by source position"
                )
            previous_indicator_start = indicator.start_line


class MarkdownParser(Protocol):
    """Deep-module interface for parsing bounded, decoded Markdown text."""

    def parse(self, content: str) -> ParsedMarkdown:
        """Parse untrusted Markdown as data without rendering or execution."""


class ObfuscationAnalyzer(Protocol):
    """Interface for deterministic anomaly extraction from parsed Markdown."""

    def analyze(
        self,
        content: str,
        document: ParsedMarkdown,
    ) -> tuple[ObfuscationIndicator, ...]:
        """Return indicators without assigning finding severity."""


class MarkdownParseError(RuntimeError):
    """Safe parser failure that never includes untrusted source text."""


def _validate_line_range(start_line: int, end_line: int, label: str) -> None:
    """Validate one 1-based inclusive line range."""

    if start_line < 1 or end_line < start_line:
        raise ValueError(f"{label} requires a coherent 1-based line range")


def _validate_within_source(
    start_line: int,
    end_line: int,
    source_line_count: int,
    label: str,
) -> None:
    """Require a validated range to fit the complete source document."""

    if end_line > source_line_count:
        raise ValueError(f"{label} range exceeds source line count")

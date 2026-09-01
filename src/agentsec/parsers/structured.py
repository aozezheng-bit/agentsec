"""Deep-module interface and immutable output for structured configuration parsing."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime, time
from enum import StrEnum
from typing import Protocol


class StructuredDataFormat(StrEnum):
    """Supported P2-01 structured configuration syntaxes."""

    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


class StructuredNodeKind(StrEnum):
    """Normalized data kinds shared by JSON, YAML, and TOML adapters."""

    OBJECT = "object"
    ARRAY = "array"
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    NULL = "null"
    DATETIME = "datetime"
    DATE = "date"
    TIME = "time"


class StructuredParseIssueCode(StrEnum):
    """Stable safe failure categories for structured input."""

    MALFORMED = "malformed"
    DUPLICATE_KEY = "duplicate_key"
    UNSAFE_TAG = "unsafe_tag"
    ALIAS_NOT_ALLOWED = "alias_not_allowed"
    UNSUPPORTED_KEY = "unsupported_key"
    UNSUPPORTED_VALUE = "unsupported_value"
    DEPTH_EXCEEDED = "depth_exceeded"
    NODE_LIMIT_EXCEEDED = "node_limit_exceeded"
    SCALAR_TOO_LARGE = "scalar_too_large"


type StructuredPathSegment = str | int
type StructuredPath = tuple[StructuredPathSegment, ...]
type StructuredScalar = str | int | float | bool | None | datetime | date | time

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class StructuredParseLimits:
    """Parser-local work limits applied after collector byte limits."""

    max_depth: int = 64
    max_nodes: int = 10_000
    max_scalar_characters: int = 65_536

    def __post_init__(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be positive")
        if self.max_nodes < 1:
            raise ValueError("max_nodes must be positive")
        if self.max_scalar_characters < 1:
            raise ValueError("max_scalar_characters must be positive")


@dataclass(frozen=True, slots=True)
class StructuredNode:
    """One normalized value or container with an exact source line range."""

    path: StructuredPath
    kind: StructuredNodeKind
    start_line: int
    end_line: int
    value: StructuredScalar = None

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("structured node requires a coherent line range")
        for segment in self.path:
            if isinstance(segment, bool) or not isinstance(segment, (str, int)):
                raise TypeError("structured path segments must be strings or integers")
            if isinstance(segment, int) and segment < 0:
                raise ValueError("structured array indexes must not be negative")
        self._validate_value()

    def _validate_value(self) -> None:
        if self.kind in {StructuredNodeKind.OBJECT, StructuredNodeKind.ARRAY}:
            if self.value is not None:
                raise ValueError("structured containers cannot contain scalar values")
            return
        if self.kind is StructuredNodeKind.NULL:
            if self.value is not None:
                raise ValueError("null structured nodes require value None")
            return
        if self.kind is StructuredNodeKind.STRING:
            valid = isinstance(self.value, str)
        elif self.kind is StructuredNodeKind.INTEGER:
            valid = isinstance(self.value, int) and not isinstance(self.value, bool)
        elif self.kind is StructuredNodeKind.FLOAT:
            valid = isinstance(self.value, float) and math.isfinite(self.value)
        elif self.kind is StructuredNodeKind.BOOLEAN:
            valid = isinstance(self.value, bool)
        elif self.kind is StructuredNodeKind.DATETIME:
            valid = isinstance(self.value, datetime)
        elif self.kind is StructuredNodeKind.DATE:
            valid = type(self.value) is date
        elif self.kind is StructuredNodeKind.TIME:
            valid = isinstance(self.value, time)
        else:  # pragma: no cover - exhaustive enum defense
            valid = False
        if not valid:
            raise TypeError(
                f"invalid scalar value for structured kind {self.kind.value}"
            )


@dataclass(frozen=True, slots=True)
class StructuredDocument:
    """A deterministic flat tree shared by structured parser adapters."""

    format: StructuredDataFormat
    source_line_count: int
    nodes: tuple[StructuredNode, ...]

    def __post_init__(self) -> None:
        if self.source_line_count < 0:
            raise ValueError("source_line_count must not be negative")
        if not self.nodes:
            return

        paths: set[StructuredPath] = set()
        previous_start = 0
        for node in self.nodes:
            if node.path in paths:
                raise ValueError("structured node paths must be unique")
            paths.add(node.path)
            if node.end_line > self.source_line_count:
                raise ValueError("structured node range exceeds source line count")
            if node.start_line < previous_start:
                raise ValueError("structured nodes must be source ordered")
            previous_start = node.start_line

        if () not in paths:
            raise ValueError("non-empty structured documents require a root node")
        node_by_path = {node.path: node for node in self.nodes}
        for node in self.nodes:
            if not node.path:
                continue
            parent = node_by_path.get(node.path[:-1])
            if parent is None:
                raise ValueError("structured node parent path is missing")
            segment = node.path[-1]
            expected = (
                StructuredNodeKind.ARRAY
                if isinstance(segment, int)
                else StructuredNodeKind.OBJECT
            )
            if parent.kind is not expected:
                raise ValueError("structured node path conflicts with parent kind")

    def node_at(self, path: StructuredPath) -> StructuredNode | None:
        """Return one node by normalized path without exposing implementation maps."""

        return next((node for node in self.nodes if node.path == path), None)


class StructuredParser(Protocol):
    """Deep-module interface for bounded, decoded structured configuration text."""

    @property
    def format(self) -> StructuredDataFormat:
        """Return the syntax handled by this parser adapter."""

    def parse(self, content: str) -> StructuredDocument:
        """Parse untrusted text as data without interpolation or execution."""


class StructuredParseError(RuntimeError):
    """Safe structured parser failure that never copies untrusted source text."""

    def __init__(
        self,
        code: StructuredParseIssueCode,
        *,
        line: int | None = None,
    ) -> None:
        self.code = code
        self.line = line
        super().__init__(f"Structured parsing failed safely: {code.value}.")


def format_structured_path(path: StructuredPath) -> str:
    """Render one normalized path in deterministic JSONPath-like notation."""

    rendered = "$"
    for segment in path:
        if isinstance(segment, int):
            rendered += f"[{segment}]"
        elif _IDENTIFIER_PATTERN.fullmatch(segment):
            rendered += f".{segment}"
        else:
            rendered += f"[{json.dumps(segment, ensure_ascii=False)}]"
    return rendered


def source_line_count(content: str) -> int:
    """Return the same physical-line convention used by existing parsers."""

    return len(content.splitlines())


def make_structured_document(
    *,
    format: StructuredDataFormat,
    content: str,
    nodes: list[StructuredNode],
) -> StructuredDocument:
    """Sort trusted adapter output and build the common immutable document."""

    ordered = tuple(
        sorted(
            nodes,
            key=lambda node: (
                node.start_line,
                len(node.path),
                format_structured_path(node.path),
            ),
        )
    )
    return StructuredDocument(
        format=format,
        source_line_count=source_line_count(content),
        nodes=ordered,
    )

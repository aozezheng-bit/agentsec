"""Location-preserving deterministic JSON parser for P2-01."""

from __future__ import annotations

import bisect
import json
import math
import re
from dataclasses import dataclass, field
from typing import NoReturn

from agentsec.parsers.structured import (
    StructuredDataFormat,
    StructuredDocument,
    StructuredNode,
    StructuredNodeKind,
    StructuredParseError,
    StructuredParseIssueCode,
    StructuredParseLimits,
    StructuredPath,
    StructuredScalar,
    make_structured_document,
)

_NUMBER_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_JSON_WHITESPACE = " \t\r\n"
_JSON_DECODER = json.JSONDecoder()


@dataclass(slots=True)
class _JsonNodeDraft:
    path: StructuredPath
    kind: StructuredNodeKind
    start_index: int
    end_index: int
    value: StructuredScalar = None
    children: list[_JsonNodeDraft] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _LineMap:
    content: str
    starts: tuple[int, ...]

    @classmethod
    def create(cls, content: str) -> _LineMap:
        starts = [0]
        starts.extend(index + 1 for index, char in enumerate(content) if char == "\n")
        return cls(content=content, starts=tuple(starts))

    def line_for(self, index: int, *, exclusive_end: bool = False) -> int:
        if not self.content:
            return 1
        bounded = min(max(index, 0), len(self.content))
        if exclusive_end and bounded > 0:
            bounded -= 1
        return bisect.bisect_right(self.starts, bounded)


class JsonStructuredParser:
    """Parse JSON into a bounded flat tree with exact field line locations."""

    def __init__(self, limits: StructuredParseLimits | None = None) -> None:
        self._limits = limits if limits is not None else StructuredParseLimits()

    @property
    def format(self) -> StructuredDataFormat:
        return StructuredDataFormat.JSON

    def parse(self, content: str) -> StructuredDocument:
        """Parse one complete JSON value without using hooks or object callbacks."""

        reader = _JsonReader(content, self._limits)
        draft = reader.parse()
        line_map = _LineMap.create(content)
        nodes: list[StructuredNode] = []
        self._flatten(draft, line_map, nodes)
        return make_structured_document(
            format=self.format,
            content=content,
            nodes=nodes,
        )

    def _flatten(
        self,
        draft: _JsonNodeDraft,
        line_map: _LineMap,
        nodes: list[StructuredNode],
    ) -> None:
        nodes.append(
            StructuredNode(
                path=draft.path,
                kind=draft.kind,
                start_line=line_map.line_for(draft.start_index),
                end_line=line_map.line_for(draft.end_index, exclusive_end=True),
                value=draft.value,
            )
        )
        for child in draft.children:
            self._flatten(child, line_map, nodes)


class _JsonReader:
    """Small JSON recursive-descent implementation retaining source offsets."""

    def __init__(self, content: str, limits: StructuredParseLimits) -> None:
        self._content = content
        self._limits = limits
        self._position = 0
        self._node_count = 0
        self._line_map = _LineMap.create(content)

    def parse(self) -> _JsonNodeDraft:
        self._skip_whitespace()
        if self._position >= len(self._content):
            self._raise(StructuredParseIssueCode.MALFORMED)
        root = self._parse_value((), depth=0)
        self._skip_whitespace()
        if self._position != len(self._content):
            self._raise(StructuredParseIssueCode.MALFORMED)
        return root

    def _parse_value(
        self,
        path: StructuredPath,
        *,
        depth: int,
        location_start: int | None = None,
    ) -> _JsonNodeDraft:
        self._require_capacity(depth)
        self._skip_whitespace()
        if self._position >= len(self._content):
            self._raise(StructuredParseIssueCode.MALFORMED)
        actual_start = self._position
        source_start = actual_start if location_start is None else location_start
        char = self._content[self._position]
        if char == "{":
            return self._parse_object(path, depth=depth, source_start=source_start)
        if char == "[":
            return self._parse_array(path, depth=depth, source_start=source_start)
        if char == '"':
            value, end = self._parse_string()
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.STRING,
                start_index=source_start,
                end_index=end,
                value=value,
            )
        if self._content.startswith("true", self._position):
            self._position += 4
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.BOOLEAN,
                start_index=source_start,
                end_index=self._position,
                value=True,
            )
        if self._content.startswith("false", self._position):
            self._position += 5
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.BOOLEAN,
                start_index=source_start,
                end_index=self._position,
                value=False,
            )
        if self._content.startswith("null", self._position):
            self._position += 4
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.NULL,
                start_index=source_start,
                end_index=self._position,
            )
        match = _NUMBER_PATTERN.match(self._content, self._position)
        if match is not None:
            token = match.group(0)
            self._position = match.end()
            try:
                value = json.loads(token)
            except ValueError:
                # Python 3.11+ raises a bare ValueError (not JSONDecodeError)
                # for integer literals beyond the int-string conversion limit.
                self._raise(
                    StructuredParseIssueCode.UNSUPPORTED_VALUE, index=source_start
                )
            if isinstance(value, float) and not math.isfinite(value):
                self._raise(
                    StructuredParseIssueCode.UNSUPPORTED_VALUE, index=source_start
                )
            return _JsonNodeDraft(
                path=path,
                kind=(
                    StructuredNodeKind.FLOAT
                    if isinstance(value, float)
                    else StructuredNodeKind.INTEGER
                ),
                start_index=source_start,
                end_index=self._position,
                value=value,
            )
        self._raise(StructuredParseIssueCode.MALFORMED)

    def _parse_object(
        self,
        path: StructuredPath,
        *,
        depth: int,
        source_start: int,
    ) -> _JsonNodeDraft:
        self._position += 1
        children: list[_JsonNodeDraft] = []
        keys: set[str] = set()
        self._skip_whitespace()
        if self._consume("}"):
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.OBJECT,
                start_index=source_start,
                end_index=self._position,
            )

        while True:
            self._skip_whitespace()
            key_start = self._position
            if self._peek() != '"':
                self._raise(StructuredParseIssueCode.MALFORMED)
            key, _ = self._parse_string()
            if key in keys:
                self._raise(
                    StructuredParseIssueCode.DUPLICATE_KEY,
                    index=key_start,
                )
            keys.add(key)
            self._skip_whitespace()
            if not self._consume(":"):
                self._raise(StructuredParseIssueCode.MALFORMED)
            children.append(
                self._parse_value(
                    path + (key,),
                    depth=depth + 1,
                    location_start=key_start,
                )
            )
            self._skip_whitespace()
            if self._consume("}"):
                break
            if not self._consume(","):
                self._raise(StructuredParseIssueCode.MALFORMED)

        return _JsonNodeDraft(
            path=path,
            kind=StructuredNodeKind.OBJECT,
            start_index=source_start,
            end_index=self._position,
            children=children,
        )

    def _parse_array(
        self,
        path: StructuredPath,
        *,
        depth: int,
        source_start: int,
    ) -> _JsonNodeDraft:
        self._position += 1
        children: list[_JsonNodeDraft] = []
        self._skip_whitespace()
        if self._consume("]"):
            return _JsonNodeDraft(
                path=path,
                kind=StructuredNodeKind.ARRAY,
                start_index=source_start,
                end_index=self._position,
            )

        index = 0
        while True:
            children.append(self._parse_value(path + (index,), depth=depth + 1))
            index += 1
            self._skip_whitespace()
            if self._consume("]"):
                break
            if not self._consume(","):
                self._raise(StructuredParseIssueCode.MALFORMED)

        return _JsonNodeDraft(
            path=path,
            kind=StructuredNodeKind.ARRAY,
            start_index=source_start,
            end_index=self._position,
            children=children,
        )

    def _parse_string(self) -> tuple[str, int]:
        quote_index = self._position
        try:
            value, end = _JSON_DECODER.raw_decode(self._content, quote_index)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise StructuredParseError(
                StructuredParseIssueCode.MALFORMED,
                line=self._line_map.line_for(quote_index),
            ) from error
        if not isinstance(value, str):
            self._raise(
                StructuredParseIssueCode.MALFORMED,
                index=quote_index,
            )
        if len(value) > self._limits.max_scalar_characters:
            self._raise(
                StructuredParseIssueCode.SCALAR_TOO_LARGE,
                index=quote_index,
            )
        self._position = end
        return value, end

    def _require_capacity(self, depth: int) -> None:
        if depth > self._limits.max_depth:
            self._raise(StructuredParseIssueCode.DEPTH_EXCEEDED)
        self._node_count += 1
        if self._node_count > self._limits.max_nodes:
            self._raise(StructuredParseIssueCode.NODE_LIMIT_EXCEEDED)

    def _skip_whitespace(self) -> None:
        while (
            self._position < len(self._content)
            and self._content[self._position] in _JSON_WHITESPACE
        ):
            self._position += 1

    def _peek(self) -> str | None:
        if self._position >= len(self._content):
            return None
        return self._content[self._position]

    def _consume(self, expected: str) -> bool:
        if self._peek() != expected:
            return False
        self._position += 1
        return True

    def _raise(
        self,
        code: StructuredParseIssueCode,
        *,
        index: int | None = None,
    ) -> NoReturn:
        location = self._position if index is None else index
        raise StructuredParseError(
            code,
            line=self._line_map.line_for(location),
        )

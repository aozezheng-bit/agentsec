"""Location-preserving TOML parser built on validated standard-library data."""

from __future__ import annotations

import math
import re
import tomllib
from datetime import date, datetime, time
from typing import Any

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

type _LineRange = tuple[int, int]

_TOML_ERROR_LINE_PATTERN = re.compile(r"\bat line (?P<line>[1-9][0-9]*), column\b")


class TomlStructuredParser:
    """Parse TOML values and map table/key paths back to physical source lines."""

    def __init__(self, limits: StructuredParseLimits | None = None) -> None:
        self._limits = limits if limits is not None else StructuredParseLimits()
        self._node_count = 0

    @property
    def format(self) -> StructuredDataFormat:
        return StructuredDataFormat.TOML

    def parse(self, content: str) -> StructuredDocument:
        """Parse TOML without interpolation, includes, custom decoders, or I/O."""

        normalized = content.replace("\r\n", "\n")
        try:
            data = tomllib.loads(normalized)
        except RecursionError as error:
            raise StructuredParseError(
                StructuredParseIssueCode.DEPTH_EXCEEDED
            ) from error
        except tomllib.TOMLDecodeError as error:
            code = self._toml_error_code(error)
            raise StructuredParseError(
                code, line=self._toml_error_line(error)
            ) from error

        if not data:
            return make_structured_document(
                format=self.format,
                content=content,
                nodes=[],
            )

        try:
            locations, root_range = _TomlLocationScanner(normalized, data).scan()
            self._node_count = 0
            nodes: list[StructuredNode] = []
            self._flatten(
                data,
                (),
                depth=0,
                locations=locations,
                inherited_range=root_range,
                nodes=nodes,
            )
            return make_structured_document(
                format=self.format,
                content=content,
                nodes=nodes,
            )
        except StructuredParseError:
            raise
        except RecursionError as error:
            raise StructuredParseError(
                StructuredParseIssueCode.DEPTH_EXCEEDED
            ) from error
        except Exception as error:
            raise StructuredParseError(StructuredParseIssueCode.MALFORMED) from error

    def _flatten(
        self,
        value: object,
        path: StructuredPath,
        *,
        depth: int,
        locations: dict[StructuredPath, _LineRange],
        inherited_range: _LineRange,
        nodes: list[StructuredNode],
    ) -> None:
        self._require_capacity(depth, inherited_range[0])
        line_range = locations.get(path, inherited_range)
        kind, scalar = self._kind_and_scalar(value, line=line_range[0])
        nodes.append(
            StructuredNode(
                path=path,
                kind=kind,
                start_line=line_range[0],
                end_line=line_range[1],
                value=scalar,
            )
        )
        if isinstance(value, dict):
            for key, child in value.items():
                self._flatten(
                    child,
                    path + (key,),
                    depth=depth + 1,
                    locations=locations,
                    inherited_range=line_range,
                    nodes=nodes,
                )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self._flatten(
                    child,
                    path + (index,),
                    depth=depth + 1,
                    locations=locations,
                    inherited_range=line_range,
                    nodes=nodes,
                )

    def _kind_and_scalar(
        self,
        value: object,
        *,
        line: int,
    ) -> tuple[StructuredNodeKind, StructuredScalar]:
        if isinstance(value, dict):
            return StructuredNodeKind.OBJECT, None
        if isinstance(value, list):
            return StructuredNodeKind.ARRAY, None
        if isinstance(value, bool):
            return StructuredNodeKind.BOOLEAN, value
        if isinstance(value, int):
            return StructuredNodeKind.INTEGER, value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise StructuredParseError(
                    StructuredParseIssueCode.UNSUPPORTED_VALUE,
                    line=line,
                )
            return StructuredNodeKind.FLOAT, value
        if isinstance(value, datetime):
            return StructuredNodeKind.DATETIME, value
        if type(value) is date:
            return StructuredNodeKind.DATE, value
        if isinstance(value, time):
            return StructuredNodeKind.TIME, value
        if isinstance(value, str):
            if len(value) > self._limits.max_scalar_characters:
                raise StructuredParseError(
                    StructuredParseIssueCode.SCALAR_TOO_LARGE,
                    line=line,
                )
            return StructuredNodeKind.STRING, value
        raise StructuredParseError(
            StructuredParseIssueCode.UNSUPPORTED_VALUE,
            line=line,
        )

    def _require_capacity(self, depth: int, line: int) -> None:
        if depth > self._limits.max_depth:
            raise StructuredParseError(
                StructuredParseIssueCode.DEPTH_EXCEEDED,
                line=line,
            )
        self._node_count += 1
        if self._node_count > self._limits.max_nodes:
            raise StructuredParseError(
                StructuredParseIssueCode.NODE_LIMIT_EXCEEDED,
                line=line,
            )

    @staticmethod
    def _toml_error_code(error: tomllib.TOMLDecodeError) -> StructuredParseIssueCode:
        message = str(error).lower()
        if "cannot overwrite" in message or "cannot declare" in message:
            return StructuredParseIssueCode.DUPLICATE_KEY
        return StructuredParseIssueCode.MALFORMED

    @staticmethod
    def _toml_error_line(error: tomllib.TOMLDecodeError) -> int | None:
        line = getattr(error, "lineno", None)
        if isinstance(line, int):
            return line
        match = _TOML_ERROR_LINE_PATTERN.search(str(error))
        if match is None:
            return None
        return int(match.group("line"))


class _TomlLocationScanner:
    """Map validated TOML statements to normalized data paths and line ranges."""

    def __init__(self, content: str, data: dict[str, Any]) -> None:
        self._content = content
        self._data = data
        self._lines = content.splitlines(keepends=True)
        self._locations: dict[StructuredPath, _LineRange] = {}
        self._current_header: StructuredPath = ()
        self._array_counts: dict[StructuredPath, int] = {}
        self._first_statement_line: int | None = None
        self._last_statement_line = 1

    def scan(self) -> tuple[dict[StructuredPath, _LineRange], _LineRange]:
        line_index = 0
        while line_index < len(self._lines):
            line = self._lines[line_index]
            stripped = line.lstrip(" \t")
            if not stripped or stripped.startswith("\n") or stripped.startswith("#"):
                line_index += 1
                continue
            start_line = line_index + 1
            if stripped.startswith("["):
                is_array = stripped.startswith("[[")
                key_text = self._header_key_text(stripped, is_array=is_array)
                raw_path = self._parse_key_path(key_text)
                self._current_header = self._materialize_header_path(
                    raw_path,
                    is_array=is_array,
                )
                self._record_prefixes(
                    self._current_header,
                    (start_line, start_line),
                )
                self._record_statement(start_line, start_line)
                line_index += 1
                continue

            key_text = self._assignment_key_text(stripped)
            raw_key_path = self._parse_key_path(key_text)
            end_index = self._assignment_end(line_index)
            end_line = end_index + 1
            full_path = self._current_header + raw_key_path
            self._record_prefixes(full_path, (start_line, end_line))
            self._record_statement(start_line, end_line)
            line_index = end_index + 1

        if self._first_statement_line is None:
            return {}, (1, max(1, len(self._content.splitlines())))
        root_range = (self._first_statement_line, self._last_statement_line)
        self._locations[()] = root_range
        return self._locations, root_range

    def _assignment_end(self, start_index: int) -> int:
        for end_index in range(start_index, len(self._lines)):
            snippet = "".join(self._lines[start_index : end_index + 1])
            try:
                tomllib.loads(snippet)
            except tomllib.TOMLDecodeError:
                continue
            return end_index
        raise StructuredParseError(
            StructuredParseIssueCode.MALFORMED,
            line=start_index + 1,
        )

    def _materialize_header_path(
        self,
        raw_path: tuple[str, ...],
        *,
        is_array: bool,
    ) -> StructuredPath:
        current: object = self._data
        materialized: list[str | int] = []
        for index, key in enumerate(raw_path):
            if not isinstance(current, dict) or key not in current:
                raise StructuredParseError(StructuredParseIssueCode.MALFORMED)
            current = current[key]
            materialized.append(key)
            if isinstance(current, list):
                list_path = tuple(materialized)
                if is_array and index == len(raw_path) - 1:
                    selected = self._array_counts.get(list_path, 0)
                    self._array_counts[list_path] = selected + 1
                else:
                    selected = self._array_counts.get(list_path, 0) - 1
                    selected = max(selected, 0)
                if selected >= len(current):
                    raise StructuredParseError(StructuredParseIssueCode.MALFORMED)
                materialized.append(selected)
                current = current[selected]
        return tuple(materialized)

    def _record_prefixes(self, path: StructuredPath, line_range: _LineRange) -> None:
        for length in range(1, len(path) + 1):
            self._locations.setdefault(path[:length], line_range)
        self._locations[path] = line_range

    def _record_statement(self, start_line: int, end_line: int) -> None:
        if self._first_statement_line is None:
            self._first_statement_line = start_line
        self._last_statement_line = max(self._last_statement_line, end_line)

    @staticmethod
    def _assignment_key_text(line: str) -> str:
        quote: str | None = None
        escaped = False
        for index, char in enumerate(line):
            if quote == '"':
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if quote == "'":
                if char == quote:
                    quote = None
                continue
            if char in {'"', "'"}:
                quote = char
                continue
            if char == "=":
                key = line[:index].strip()
                if key:
                    return key
                break
        raise StructuredParseError(StructuredParseIssueCode.MALFORMED)

    @staticmethod
    def _header_key_text(line: str, *, is_array: bool) -> str:
        offset = 2 if is_array else 1
        quote: str | None = None
        escaped = False
        index = offset
        while index < len(line):
            char = line[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if quote == "'":
                if char == quote:
                    quote = None
                index += 1
                continue
            if char in {'"', "'"}:
                quote = char
                index += 1
                continue
            closing = "]]" if is_array else "]"
            if line.startswith(closing, index):
                key = line[offset:index].strip()
                if key:
                    return key
                break
            index += 1
        raise StructuredParseError(StructuredParseIssueCode.MALFORMED)

    @staticmethod
    def _parse_key_path(key_text: str) -> tuple[str, ...]:
        try:
            parsed = tomllib.loads(f"{key_text} = 0\n")
        except tomllib.TOMLDecodeError as error:
            raise StructuredParseError(StructuredParseIssueCode.MALFORMED) from error
        path: list[str] = []
        current: object = parsed
        while isinstance(current, dict) and len(current) == 1:
            key, current = next(iter(current.items()))
            path.append(key)
        if current != 0 or not path:
            raise StructuredParseError(StructuredParseIssueCode.MALFORMED)
        return tuple(path)

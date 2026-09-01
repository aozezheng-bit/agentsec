"""Safe location-preserving YAML parser for P2-01."""

from __future__ import annotations

import bisect
import math
from datetime import date, datetime, time

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

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

_ALLOWED_YAML_TAGS = {
    "tag:yaml.org,2002:map",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:timestamp",
}


class YamlStructuredParser:
    """Parse one safe YAML document without aliases, tags, or constructors."""

    def __init__(self, limits: StructuredParseLimits | None = None) -> None:
        self._limits = limits if limits is not None else StructuredParseLimits()
        self._node_count = 0
        self._content = ""
        self._line_starts: tuple[int, ...] = (0,)

    @property
    def format(self) -> StructuredDataFormat:
        return StructuredDataFormat.YAML

    def parse(self, content: str) -> StructuredDocument:
        """Parse YAML as an inert node graph with deterministic source locations."""

        self._node_count = 0
        self._content = content
        starts = [0]
        starts.extend(index + 1 for index, char in enumerate(content) if char == "\n")
        self._line_starts = tuple(starts)
        self._reject_unsafe_tokens(content)

        loader = yaml.SafeLoader(content)
        try:
            node = loader.get_single_node()
            if node is None:
                return make_structured_document(
                    format=self.format,
                    content=content,
                    nodes=[],
                )
            nodes: list[StructuredNode] = []
            self._walk(node, loader, (), depth=0, nodes=nodes)
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
        except yaml.YAMLError as error:
            line = self._yaml_error_line(error)
            raise StructuredParseError(
                StructuredParseIssueCode.MALFORMED,
                line=line,
            ) from error
        except Exception as error:
            raise StructuredParseError(StructuredParseIssueCode.MALFORMED) from error
        finally:
            loader.dispose()

    def _reject_unsafe_tokens(self, content: str) -> None:
        try:
            for token in yaml.scan(content, Loader=yaml.SafeLoader):
                if isinstance(token, (AliasToken, AnchorToken)):
                    raise StructuredParseError(
                        StructuredParseIssueCode.ALIAS_NOT_ALLOWED,
                        line=token.start_mark.line + 1,
                    )
                if isinstance(token, TagToken):
                    raise StructuredParseError(
                        StructuredParseIssueCode.UNSAFE_TAG,
                        line=token.start_mark.line + 1,
                    )
        except StructuredParseError:
            raise
        except yaml.YAMLError as error:
            raise StructuredParseError(
                StructuredParseIssueCode.MALFORMED,
                line=self._yaml_error_line(error),
            ) from error

    def _walk(
        self,
        node: Node,
        loader: yaml.SafeLoader,
        path: StructuredPath,
        *,
        depth: int,
        nodes: list[StructuredNode],
        start_override: int | None = None,
    ) -> None:
        self._require_capacity(depth, node.start_mark.line + 1)
        if node.tag not in _ALLOWED_YAML_TAGS:
            raise StructuredParseError(
                StructuredParseIssueCode.UNSAFE_TAG,
                line=node.start_mark.line + 1,
            )
        start_index = (
            node.start_mark.index if start_override is None else start_override
        )
        start_line = self._line_for(start_index)
        end_line = self._line_for(node.end_mark.index, exclusive_end=True)

        if isinstance(node, MappingNode):
            nodes.append(
                StructuredNode(
                    path=path,
                    kind=StructuredNodeKind.OBJECT,
                    start_line=start_line,
                    end_line=end_line,
                )
            )
            keys: set[str] = set()
            for key_node, value_node in node.value:
                key = self._mapping_key(key_node, loader)
                if key in keys:
                    raise StructuredParseError(
                        StructuredParseIssueCode.DUPLICATE_KEY,
                        line=key_node.start_mark.line + 1,
                    )
                keys.add(key)
                self._walk(
                    value_node,
                    loader,
                    path + (key,),
                    depth=depth + 1,
                    nodes=nodes,
                    start_override=key_node.start_mark.index,
                )
            return

        if isinstance(node, SequenceNode):
            nodes.append(
                StructuredNode(
                    path=path,
                    kind=StructuredNodeKind.ARRAY,
                    start_line=start_line,
                    end_line=end_line,
                )
            )
            for index, child in enumerate(node.value):
                self._walk(
                    child,
                    loader,
                    path + (index,),
                    depth=depth + 1,
                    nodes=nodes,
                )
            return

        if not isinstance(node, ScalarNode):
            raise StructuredParseError(
                StructuredParseIssueCode.UNSUPPORTED_VALUE,
                line=start_line,
            )
        value = self._construct_scalar(node, loader)
        kind = self._scalar_kind(value, line=start_line)
        if isinstance(value, str) and len(value) > self._limits.max_scalar_characters:
            raise StructuredParseError(
                StructuredParseIssueCode.SCALAR_TOO_LARGE,
                line=start_line,
            )
        nodes.append(
            StructuredNode(
                path=path,
                kind=kind,
                start_line=start_line,
                end_line=end_line,
                value=value,
            )
        )

    def _mapping_key(self, node: Node, loader: yaml.SafeLoader) -> str:
        if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:str":
            raise StructuredParseError(
                StructuredParseIssueCode.UNSUPPORTED_KEY,
                line=node.start_mark.line + 1,
            )
        value = self._construct_scalar(node, loader)
        if not isinstance(value, str):
            raise StructuredParseError(
                StructuredParseIssueCode.UNSUPPORTED_KEY,
                line=node.start_mark.line + 1,
            )
        if len(value) > self._limits.max_scalar_characters:
            raise StructuredParseError(
                StructuredParseIssueCode.SCALAR_TOO_LARGE,
                line=node.start_mark.line + 1,
            )
        return value

    def _construct_scalar(
        self,
        node: ScalarNode,
        loader: yaml.SafeLoader,
    ) -> StructuredScalar:
        try:
            value = loader.construct_object(node, deep=False)
        except Exception as error:
            raise StructuredParseError(
                StructuredParseIssueCode.UNSUPPORTED_VALUE,
                line=node.start_mark.line + 1,
            ) from error
        if value is not None and not isinstance(
            value, (str, int, float, bool, datetime, date, time)
        ):
            raise StructuredParseError(
                StructuredParseIssueCode.UNSUPPORTED_VALUE,
                line=node.start_mark.line + 1,
            )
        return value

    def _scalar_kind(
        self,
        value: StructuredScalar,
        *,
        line: int,
    ) -> StructuredNodeKind:
        if value is None:
            return StructuredNodeKind.NULL
        if isinstance(value, bool):
            return StructuredNodeKind.BOOLEAN
        if isinstance(value, int):
            return StructuredNodeKind.INTEGER
        if isinstance(value, float):
            if not math.isfinite(value):
                raise StructuredParseError(
                    StructuredParseIssueCode.UNSUPPORTED_VALUE,
                    line=line,
                )
            return StructuredNodeKind.FLOAT
        if isinstance(value, datetime):
            return StructuredNodeKind.DATETIME
        if type(value) is date:
            return StructuredNodeKind.DATE
        if isinstance(value, time):
            return StructuredNodeKind.TIME
        if isinstance(value, str):
            return StructuredNodeKind.STRING
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

    def _line_for(self, index: int, *, exclusive_end: bool = False) -> int:
        if not self._content:
            return 1
        bounded = min(max(index, 0), len(self._content))
        if exclusive_end and bounded > 0:
            bounded -= 1
        return bisect.bisect_right(self._line_starts, bounded)

    @staticmethod
    def _yaml_error_line(error: yaml.YAMLError) -> int | None:
        mark = getattr(error, "problem_mark", None)
        line = getattr(mark, "line", None)
        if isinstance(line, int):
            return line + 1
        return None

"""Shared immutable provenance wrappers for specialized configuration parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from agentsec.parsers.structured import StructuredPath


@dataclass(frozen=True, slots=True)
class SourceBackedValue[T]:
    """One trusted parsed value bound to a structured field and source range."""

    value: T = field(repr=False)
    path: StructuredPath
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("source-backed value requires a coherent line range")


@dataclass(frozen=True, slots=True)
class UnknownDeclarationField:
    """One unrecognized field retained without copying its potentially secret value."""

    path: StructuredPath
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("unknown declaration field requires a non-root path")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("unknown field requires a coherent line range")

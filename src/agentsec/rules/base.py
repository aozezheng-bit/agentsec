"""Stable, deterministic Rule seam for Phase 1 Markdown analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from agentsec.domain import (
    AgentAsset,
    AssetType,
    Evidence,
    EvidenceSource,
    FindingCategory,
)
from agentsec.parsers import ParsedMarkdown

_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")


class RuleTarget(StrEnum):
    """Parsed Markdown structures a deterministic rule declares it examines."""

    DOCUMENT = "document"
    MARKDOWN_BLOCK = "markdown_block"
    FRONTMATTER = "frontmatter"
    REFERENCE = "reference"
    OBFUSCATION_INDICATOR = "obfuscation_indicator"


@dataclass(frozen=True, slots=True)
class RuleScope:
    """Explicit applicability metadata used before invoking a rule."""

    asset_types: frozenset[AssetType]
    targets: frozenset[RuleTarget]

    def __post_init__(self) -> None:
        """Require immutable, non-empty, typed scope declarations."""

        if not isinstance(self.asset_types, frozenset):
            raise TypeError("Rule scope asset_types must be a frozenset")
        if not isinstance(self.targets, frozenset):
            raise TypeError("Rule scope targets must be a frozenset")
        if not self.asset_types:
            raise ValueError("Rule scope requires at least one asset type")
        if not self.targets:
            raise ValueError("Rule scope requires at least one analysis target")
        if any(not isinstance(item, AssetType) for item in self.asset_types):
            raise TypeError("Rule scope contains an invalid asset type")
        if any(not isinstance(item, RuleTarget) for item in self.targets):
            raise TypeError("Rule scope contains an invalid analysis target")

    def applies_to(self, asset_type: AssetType) -> bool:
        """Return whether an asset belongs to this rule's declared scope."""

        return asset_type in self.asset_types

    @classmethod
    def all_markdown(cls, *targets: RuleTarget) -> RuleScope:
        """Create a scope covering every Phase 1 Markdown asset type."""

        return cls(
            asset_types=frozenset(AssetType),
            targets=frozenset(targets),
        )


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Immutable identity and explanation shared by every result from a rule."""

    rule_id: str
    title: str
    description: str
    category: FindingCategory
    recommendations: tuple[str, ...]
    scope: RuleScope
    deterministic: Literal[True] = True

    def __post_init__(self) -> None:
        """Protect Rule ID meaning and deterministic Phase 1 behavior."""

        if _RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise ValueError("Rule ID must use FAMILY-TOPIC-NNN uppercase format")
        _require_non_empty(self.title, "Rule title")
        _require_non_empty(self.description, "Rule description")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Rule category must be a FindingCategory")
        if not isinstance(self.recommendations, tuple):
            raise TypeError("Rule recommendations must be a tuple")
        if not self.recommendations:
            raise ValueError("Rule metadata requires at least one recommendation")
        for recommendation in self.recommendations:
            _require_non_empty(recommendation, "Rule recommendation")
        if len(set(self.recommendations)) != len(self.recommendations):
            raise ValueError("Rule recommendations must be unique")
        if self.deterministic is not True:
            raise ValueError("Phase 1 rules must be deterministic")


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Bounded, coherent, data-only input available to one Markdown rule.

    The context deliberately excludes project roots, open files, environment
    variables, command runners, network clients, import hooks, Skills, and MCP
    connections. Both ``content`` and ``document`` remain untrusted data and are
    hidden from the generated representation to reduce accidental disclosure.
    """

    asset: AgentAsset = dataclass_field(repr=False)
    content: str = dataclass_field(repr=False)
    document: ParsedMarkdown = dataclass_field(repr=False)
    _source_lines: tuple[str, ...] = dataclass_field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Bind parsed content to authoritative asset size and hash metadata."""

        if not isinstance(self.content, str):
            raise TypeError("Rule context content must be decoded text")
        if not isinstance(self.document, ParsedMarkdown):
            raise TypeError("Rule context document must be ParsedMarkdown")
        try:
            content_bytes = self.content.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Rule context content must be UTF-8 encodable") from None

        source_lines = tuple(self.content.splitlines(keepends=True))
        line_count = len(self.content.splitlines())
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()

        if content_sha256 != self.asset.sha256:
            raise ValueError("Rule context SHA-256 does not match the asset")
        if len(content_bytes) != self.asset.size_bytes:
            raise ValueError("Rule context byte size does not match the asset")
        if line_count != self.asset.line_count:
            raise ValueError("Rule context line count does not match the asset")
        if self.document.source_line_count != line_count:
            raise ValueError(
                "Rule context parsed document line count does not match the asset"
            )

        object.__setattr__(self, "_source_lines", source_lines)

    def source_text(self, start_line: int, end_line: int) -> str:
        """Return an exact 1-based inclusive source slice with line endings."""

        if start_line < 1 or end_line < start_line:
            raise RuleContractError("Candidate evidence has an invalid line range")
        if end_line > self.asset.line_count:
            raise RuleContractError("Candidate evidence line range exceeds the source")
        return "".join(self._source_lines[start_line - 1 : end_line])


@dataclass(frozen=True, slots=True)
class RuleEvidenceCandidate:
    """Local source evidence proposed by a rule before provenance is bound."""

    start_line: int
    end_line: int
    excerpt: str | None = dataclass_field(default=None, repr=False)
    field: str | None = dataclass_field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Require coherent local coordinates without accepting path identity."""

        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("Candidate evidence requires a coherent line range")
        if self.excerpt is not None:
            _require_non_empty(self.excerpt, "Candidate evidence excerpt")
        if self.field is not None:
            _require_non_empty(self.field, "Candidate evidence field")

    def materialize(self, context: RuleContext) -> Evidence:
        """Bind authoritative path/hash provenance and verify the source excerpt."""

        source_text = context.source_text(self.start_line, self.end_line)
        if self.excerpt is not None and self.excerpt not in source_text:
            raise RuleContractError(
                "Candidate evidence excerpt is not contained in its source range"
            )

        try:
            return Evidence(
                source_type=EvidenceSource.FILE,
                asset_path=context.asset.path,
                start_line=self.start_line,
                end_line=self.end_line,
                field=self.field,
                excerpt=self.excerpt,
                content_sha256=context.asset.sha256,
            )
        except Exception:
            raise RuleContractError(
                "Candidate evidence could not be materialized safely"
            ) from None

    def _sort_key(self) -> tuple[int, int, str, str]:
        """Return a deterministic key used only for contract validation."""

        return (
            self.start_line,
            self.end_line,
            self.field or "",
            self.excerpt or "",
        )


@dataclass(frozen=True, slots=True)
class RuleFindingCandidate:
    """Unscored finding candidate backed by one or more local evidence items."""

    evidence: tuple[RuleEvidenceCandidate, ...]

    def __post_init__(self) -> None:
        """Require immutable, source-ordered, unique evidence."""

        if not isinstance(self.evidence, tuple):
            raise TypeError("Rule finding candidate evidence must be a tuple")
        if not self.evidence:
            raise ValueError("Rule finding candidate requires evidence")
        if any(not isinstance(item, RuleEvidenceCandidate) for item in self.evidence):
            raise TypeError("Rule finding candidate contains invalid evidence")

        keys = tuple(item._sort_key() for item in self.evidence)
        if keys != tuple(sorted(keys)):
            raise ValueError("Rule candidate evidence must be in source order")
        if len(set(keys)) != len(keys):
            raise ValueError("Rule candidate evidence must be unique")

    def materialize_evidence(self, context: RuleContext) -> tuple[Evidence, ...]:
        """Return validated Domain Evidence bound to the current asset."""

        return tuple(item.materialize(context) for item in self.evidence)

    def _sort_key(self) -> tuple[tuple[int, int, str, str], ...]:
        """Return the complete deterministic evidence identity for ordering."""

        return tuple(item._sort_key() for item in self.evidence)


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """Deterministic output from evaluating one Rule against one context."""

    candidates: tuple[RuleFindingCandidate, ...] = ()

    def __post_init__(self) -> None:
        """Require immutable, source-ordered, unique candidate output."""

        if not isinstance(self.candidates, tuple):
            raise TypeError("Rule evaluation candidates must be a tuple")
        if any(not isinstance(item, RuleFindingCandidate) for item in self.candidates):
            raise TypeError("Rule evaluation contains an invalid candidate")

        keys = tuple(item._sort_key() for item in self.candidates)
        if keys != tuple(sorted(keys)):
            raise ValueError("Rule evaluation candidates must be in source order")
        if len(set(keys)) != len(keys):
            raise ValueError("Rule evaluation candidates must be unique")


@runtime_checkable
class Rule(Protocol):
    """Deep-module interface implemented by deterministic Phase 1 rules.

    Implementations must be pure over ``RuleContext``. They must not read or
    write the filesystem, inspect environment secrets, execute code or shell
    commands, import scanned project modules, access the network, invoke Skills,
    or connect to MCP servers. The future rule runner invokes and isolates each
    Rule independently at this seam.
    """

    @property
    def metadata(self) -> RuleMetadata:
        """Return stable immutable identity, explanation, and applicability."""

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Return deterministic unscored candidates without side effects."""


class RuleContractError(ValueError):
    """A safe failure indicating incoherent Rule input or candidate output."""


class RuleEvaluationError(RuntimeError):
    """Expected rule failure with a fixed message safe for isolation/reporting."""

    def __init__(self) -> None:
        super().__init__("Rule evaluation failed safely.")


def _require_non_empty(value: str, label: str) -> None:
    """Validate public rule text without copying it into an error message."""

    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value.strip():
        raise ValueError(f"{label} must not be empty")

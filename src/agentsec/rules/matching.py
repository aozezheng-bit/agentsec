"""Bounded deterministic keyword, safe-regex, and context matching rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Protocol

from agentsec.parsers import MarkdownBlockKind
from agentsec.rules.base import (
    RuleContext,
    RuleEvaluation,
    RuleEvaluationError,
    RuleEvidenceCandidate,
    RuleFindingCandidate,
    RuleMetadata,
    RuleTarget,
)

MAX_KEYWORDS_PER_CONDITION = 32
MAX_REGEX_PATTERNS_PER_CONDITION = 16
MAX_KEYWORD_CHARACTERS = 128
MAX_REGEX_PATTERN_CHARACTERS = 256
MAX_CONTEXT_WINDOW_LINES = 20
MAX_CANDIDATES_PER_RULE = 256
MAX_EVIDENCE_EXCERPT_CHARACTERS = 512
MAX_KEYWORD_LINE_CHARACTERS = 65_536
MAX_REGEX_LINE_CHARACTERS = 65_536
_MAX_BOUNDED_REPETITION = 64
_MAX_VARIABLE_REPETITION = 32
_LINE_ENDING_CHARACTERS = "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"


class MatchMode(StrEnum):
    """How multiple trusted patterns combine inside one condition."""

    ANY = "any"
    ALL = "all"


@dataclass(frozen=True, slots=True, order=True)
class _Span:
    """One private character range that never enters reports directly."""

    start: int
    end: int


@dataclass(frozen=True, slots=True, order=True)
class _LineSpan:
    """One private source-line match used to assemble candidate evidence."""

    line_number: int
    span: _Span


class _TextCondition(Protocol):
    """Internal seam shared by keyword and safe-regex conditions."""

    @property
    def mode(self) -> MatchMode:
        """Return whether any or all configured patterns are required."""

    @property
    def pattern_count(self) -> int:
        """Return the stable number of configured patterns."""

    def first_matches(self, line: str) -> tuple[_Span | None, ...]:
        """Return the first match for every configured pattern."""


@dataclass(frozen=True, slots=True)
class KeywordCondition:
    """A finite literal-text condition with optional word boundaries."""

    keywords: tuple[str, ...]
    mode: MatchMode = MatchMode.ANY
    case_sensitive: bool = False
    whole_word: bool = False
    _compiled: tuple[re.Pattern[str], ...] = dataclass_field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Compile escaped literal patterns under strict finite limits."""

        _validate_condition_options(
            self.mode,
            case_sensitive=self.case_sensitive,
            whole_word=self.whole_word,
        )
        _validate_string_tuple(
            self.keywords,
            label="keyword",
            maximum_items=MAX_KEYWORDS_PER_CONDITION,
            maximum_characters=MAX_KEYWORD_CHARACTERS,
            case_sensitive=self.case_sensitive,
        )
        flags = 0 if self.case_sensitive else re.IGNORECASE
        compiled = tuple(
            re.compile(re.escape(keyword), flags) for keyword in self.keywords
        )
        object.__setattr__(self, "_compiled", compiled)

    @property
    def pattern_count(self) -> int:
        """Return the number of literal conditions."""

        return len(self.keywords)

    def first_matches(self, line: str) -> tuple[_Span | None, ...]:
        """Return the first valid occurrence of every keyword on one line."""

        if len(line) > MAX_KEYWORD_LINE_CHARACTERS:
            raise RuleEvaluationError()
        matches: list[_Span | None] = []
        for pattern in self._compiled:
            selected: _Span | None = None
            for match in pattern.finditer(line):
                if self.whole_word and not _has_word_boundaries(
                    line,
                    match.start(),
                    match.end(),
                ):
                    continue
                selected = _Span(match.start(), match.end())
                break
            matches.append(selected)
        return tuple(matches)


@dataclass(frozen=True, slots=True)
class RegexCondition:
    """A finite condition compiled from AgentSec's conservative regex dialect."""

    patterns: tuple[str, ...]
    mode: MatchMode = MatchMode.ANY
    case_sensitive: bool = False
    _compiled: tuple[re.Pattern[str], ...] = dataclass_field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Validate and compile patterns without exposing rejected expressions."""

        _validate_condition_options(
            self.mode,
            case_sensitive=self.case_sensitive,
        )
        _validate_string_tuple(
            self.patterns,
            label="regex pattern",
            maximum_items=MAX_REGEX_PATTERNS_PER_CONDITION,
            maximum_characters=MAX_REGEX_PATTERN_CHARACTERS,
            case_sensitive=True,
        )
        flags = 0 if self.case_sensitive else re.IGNORECASE
        compiled: list[re.Pattern[str]] = []
        for pattern in self.patterns:
            _validate_safe_regex(pattern)
            try:
                candidate = re.compile(pattern, flags)
            except re.error:
                raise ValueError("regex pattern is not valid safe syntax") from None
            if candidate.search("") is not None:
                raise ValueError("regex pattern must not match empty text")
            compiled.append(candidate)
        object.__setattr__(self, "_compiled", tuple(compiled))

    @property
    def pattern_count(self) -> int:
        """Return the number of safe regex conditions."""

        return len(self.patterns)

    def first_matches(self, line: str) -> tuple[_Span | None, ...]:
        """Return the first match of each safe pattern on a bounded line."""

        if len(line) > MAX_REGEX_LINE_CHARACTERS:
            raise RuleEvaluationError()
        matches: list[_Span | None] = []
        for pattern in self._compiled:
            match = pattern.search(line)
            matches.append(None if match is None else _Span(match.start(), match.end()))
        return tuple(matches)


@dataclass(frozen=True, slots=True)
class ContextWindow:
    """One bounded supporting condition around a primary source-line match."""

    condition: KeywordCondition | RegexCondition
    before_lines: int = 0
    after_lines: int = 0
    include_match_line: bool = True

    def __post_init__(self) -> None:
        """Reject invalid or unbounded context expansion."""

        if not isinstance(self.condition, (KeywordCondition, RegexCondition)):
            raise TypeError("context condition must be keyword or regex")
        if type(self.before_lines) is not int:
            raise TypeError("context window before_lines must be an integer")
        if type(self.after_lines) is not int:
            raise TypeError("context window after_lines must be an integer")
        if type(self.include_match_line) is not bool:
            raise TypeError("context window include_match_line must be boolean")
        if not 0 <= self.before_lines <= MAX_CONTEXT_WINDOW_LINES:
            raise ValueError("context window before_lines exceeds the safe limit")
        if not 0 <= self.after_lines <= MAX_CONTEXT_WINDOW_LINES:
            raise ValueError("context window after_lines exceeds the safe limit")
        if (
            not self.include_match_line
            and self.before_lines == 0
            and self.after_lines == 0
        ):
            raise ValueError("context window must include at least one source line")


class _DeterministicTextRule:
    """Shared physical-line implementation behind public Rule adapters."""

    def __init__(
        self,
        metadata: RuleMetadata,
        trigger: _TextCondition,
        *,
        context: ContextWindow | None,
        block_kinds: frozenset[MarkdownBlockKind],
    ) -> None:
        if not isinstance(metadata, RuleMetadata):
            raise TypeError("text rules require RuleMetadata")
        if RuleTarget.MARKDOWN_BLOCK not in metadata.scope.targets:
            raise ValueError("text rules require RuleTarget.MARKDOWN_BLOCK")
        if context is not None and not isinstance(context, ContextWindow):
            raise TypeError("text rule context must be ContextWindow")
        if not isinstance(block_kinds, frozenset):
            raise TypeError("block_kinds must be a frozenset")
        if not block_kinds:
            raise ValueError("text rules require at least one Markdown block kind")
        if any(not isinstance(item, MarkdownBlockKind) for item in block_kinds):
            raise TypeError("block_kinds contains an invalid Markdown block kind")
        self._metadata = metadata
        self._trigger = trigger
        self._context = context
        self._block_kinds = block_kinds

    @property
    def metadata(self) -> RuleMetadata:
        """Return stable metadata required by the Rule Protocol."""

        return self._metadata

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Evaluate selected physical source lines with bounded supporting context."""

        if not self.metadata.scope.applies_to(context.asset.asset_type):
            return RuleEvaluation()

        candidates: list[RuleFindingCandidate] = []
        for line_number in self._selected_line_numbers(context):
            line = _source_line(context, line_number)
            primary_spans = _primary_spans(self._trigger, line)
            if not primary_spans:
                continue

            supporting = self._supporting_matches(context, line_number)
            if supporting is None:
                continue

            line_spans: dict[int, list[_Span]] = {line_number: list(primary_spans)}
            for match in supporting:
                line_spans.setdefault(match.line_number, []).append(match.span)

            evidence = tuple(
                RuleEvidenceCandidate(
                    start_line=evidence_line,
                    end_line=evidence_line,
                    excerpt=_bounded_excerpt(
                        _source_line(context, evidence_line),
                        tuple(sorted(set(spans))),
                    ),
                )
                for evidence_line, spans in sorted(line_spans.items())
            )
            candidates.append(RuleFindingCandidate(evidence=evidence))
            if len(candidates) > MAX_CANDIDATES_PER_RULE:
                raise RuleEvaluationError()

        ordered_candidates = tuple(
            sorted(
                set(candidates),
                key=lambda candidate: candidate._sort_key(),
            )
        )
        return RuleEvaluation(candidates=ordered_candidates)

    def _selected_line_numbers(self, context: RuleContext) -> tuple[int, ...]:
        """Return each selected physical line once despite overlapping blocks."""

        line_numbers: set[int] = set()
        for block in context.document.blocks:
            if block.kind not in self._block_kinds:
                continue
            line_numbers.update(range(block.start_line, block.end_line + 1))
        return tuple(sorted(line_numbers))

    def _supporting_matches(
        self,
        context: RuleContext,
        primary_line: int,
    ) -> tuple[_LineSpan, ...] | None:
        """Find the nearest required support for every context pattern."""

        if self._context is None:
            return ()

        start = max(1, primary_line - self._context.before_lines)
        end = min(context.asset.line_count, primary_line + self._context.after_lines)
        line_numbers = [
            line_number
            for line_number in range(start, end + 1)
            if self._context.include_match_line or line_number != primary_line
        ]
        ordered = sorted(
            line_numbers,
            key=lambda line_number: (abs(line_number - primary_line), line_number),
        )
        return _window_matches(self._context.condition, context, ordered)


class KeywordRule(_DeterministicTextRule):
    """Rule adapter for finite literal keyword conditions."""

    def __init__(
        self,
        metadata: RuleMetadata,
        keywords: tuple[str, ...],
        *,
        mode: MatchMode = MatchMode.ANY,
        case_sensitive: bool = False,
        whole_word: bool = False,
        context: ContextWindow | None = None,
        block_kinds: frozenset[MarkdownBlockKind] = frozenset(MarkdownBlockKind),
    ) -> None:
        super().__init__(
            metadata,
            KeywordCondition(
                keywords=keywords,
                mode=mode,
                case_sensitive=case_sensitive,
                whole_word=whole_word,
            ),
            context=context,
            block_kinds=block_kinds,
        )


class RegexRule(_DeterministicTextRule):
    """Rule adapter for AgentSec's conservative bounded regex dialect."""

    def __init__(
        self,
        metadata: RuleMetadata,
        patterns: tuple[str, ...],
        *,
        mode: MatchMode = MatchMode.ANY,
        case_sensitive: bool = False,
        context: ContextWindow | None = None,
        block_kinds: frozenset[MarkdownBlockKind] = frozenset(MarkdownBlockKind),
    ) -> None:
        super().__init__(
            metadata,
            RegexCondition(
                patterns=patterns,
                mode=mode,
                case_sensitive=case_sensitive,
            ),
            context=context,
            block_kinds=block_kinds,
        )


def _primary_spans(condition: _TextCondition, line: str) -> tuple[_Span, ...]:
    """Apply ANY/ALL semantics to one physical source line."""

    matches = condition.first_matches(line)
    present = tuple(match for match in matches if match is not None)
    if condition.mode is MatchMode.ANY:
        return () if not present else (min(present),)
    if len(present) != condition.pattern_count:
        return ()
    return tuple(sorted(set(present)))


def _window_matches(
    condition: _TextCondition,
    context: RuleContext,
    ordered_line_numbers: list[int],
) -> tuple[_LineSpan, ...] | None:
    """Apply condition mode across a proximity-ordered bounded line window."""

    by_pattern: list[_LineSpan | None] = [None] * condition.pattern_count
    all_matches: list[_LineSpan] = []

    for line_number in ordered_line_numbers:
        line = _source_line(context, line_number)
        for index, span in enumerate(condition.first_matches(line)):
            if span is None:
                continue
            line_span = _LineSpan(line_number, span)
            all_matches.append(line_span)
            if by_pattern[index] is None:
                by_pattern[index] = line_span

    if condition.mode is MatchMode.ANY:
        if not all_matches:
            return None
        proximity_rank = {
            line_number: rank for rank, line_number in enumerate(ordered_line_numbers)
        }
        selected = min(
            all_matches,
            key=lambda item: (
                proximity_rank[item.line_number],
                item.span.start,
                item.span.end,
            ),
        )
        return (selected,)

    if any(item is None for item in by_pattern):
        return None
    return tuple(sorted({item for item in by_pattern if item is not None}))


def _source_line(context: RuleContext, line_number: int) -> str:
    """Return one exact logical line without its line-ending sequence."""

    return context.source_text(line_number, line_number).rstrip(_LINE_ENDING_CHARACTERS)


def _bounded_excerpt(line: str, spans: tuple[_Span, ...]) -> str:
    """Retain an exact bounded source substring containing every selected span."""

    if len(line) <= MAX_EVIDENCE_EXCERPT_CHARACTERS:
        return line

    start_match = min(span.start for span in spans)
    end_match = max(span.end for span in spans)
    match_width = end_match - start_match
    remaining = MAX_EVIDENCE_EXCERPT_CHARACTERS - match_width
    left_context = min(start_match, max(0, remaining // 2))
    start = start_match - left_context
    end = start + MAX_EVIDENCE_EXCERPT_CHARACTERS
    if end > len(line):
        end = len(line)
        start = end - MAX_EVIDENCE_EXCERPT_CHARACTERS
    return line[start:end]


def _has_word_boundaries(line: str, start: int, end: int) -> bool:
    """Apply Unicode-aware identifier boundaries without regex lookaround."""

    left_ok = start == 0 or not _is_word_character(line[start - 1])
    right_ok = end == len(line) or not _is_word_character(line[end])
    return left_ok and right_ok


def _is_word_character(character: str) -> bool:
    """Match Python's practical alphanumeric/underscore identifier boundary."""

    return character.isalnum() or character == "_"


def _validate_condition_options(
    mode: MatchMode,
    *,
    case_sensitive: bool,
    whole_word: bool | None = None,
) -> None:
    """Require explicit enum and boolean matcher options."""

    if not isinstance(mode, MatchMode):
        raise TypeError("match mode must be MatchMode")
    if type(case_sensitive) is not bool:
        raise TypeError("case_sensitive must be boolean")
    if whole_word is not None and type(whole_word) is not bool:
        raise TypeError("whole_word must be boolean")


def _validate_string_tuple(
    values: tuple[str, ...],
    *,
    label: str,
    maximum_items: int,
    maximum_characters: int,
    case_sensitive: bool,
) -> None:
    """Validate immutable finite pattern configuration without echoing values."""

    if not isinstance(values, tuple):
        raise TypeError(f"{label}s must be a tuple")
    if not values or len(values) > maximum_items:
        raise ValueError(f"{label}s require a bounded non-empty tuple")

    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{label} must be text")
        if not value.strip():
            raise ValueError(f"{label} must not be empty")
        if len(value) > maximum_characters:
            raise ValueError(f"{label} exceeds the safe length limit")
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise ValueError(f"{label} must not contain line breaks or NUL")
        normalized.append(value if case_sensitive else value.casefold())
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label}s must be unique")


def _validate_safe_regex(pattern: str) -> None:
    """Accept a conservative regex subset with bounded repetition only."""

    index = 0
    group_depth = 0
    previous_atom = False
    previous_group = False
    previous_quantifier = False
    variable_quantifiers = 0

    while index < len(pattern):
        character = pattern[index]

        if character == "\\":
            if index + 1 >= len(pattern):
                raise ValueError("regex pattern ends with an invalid escape")
            escaped = pattern[index + 1]
            if escaped.isdigit() and escaped != "0":
                raise ValueError("regex backreferences are not supported")
            if escaped in {"g", "k"}:
                raise ValueError("regex backreferences are not supported")
            previous_atom = escaped not in {"A", "Z", "b", "B"}
            previous_group = False
            previous_quantifier = False
            index += 2
            continue

        if character == "[":
            index = _consume_character_class(pattern, index)
            previous_atom = True
            previous_group = False
            previous_quantifier = False
            continue

        if character == "(":
            if not pattern.startswith("(?:", index):
                raise ValueError("regex supports non-capturing groups only")
            group_depth += 1
            previous_atom = False
            previous_group = False
            previous_quantifier = False
            index += 3
            continue

        if character == ")":
            if group_depth < 1 or not previous_atom:
                raise ValueError("regex group structure is invalid")
            group_depth -= 1
            previous_atom = False
            previous_group = True
            previous_quantifier = False
            index += 1
            continue

        if character == "|":
            if not previous_atom and not previous_group:
                raise ValueError("regex alternatives must not be empty")
            previous_atom = False
            previous_group = False
            previous_quantifier = False
            index += 1
            continue

        if character in {"*", "+", "."}:
            raise ValueError("regex contains unsupported unbounded syntax")

        if character == "?":
            if not previous_atom or previous_group or previous_quantifier:
                raise ValueError("regex quantifier placement is invalid")
            variable_quantifiers += 1
            previous_atom = True
            previous_group = False
            previous_quantifier = True
            index += 1
            continue

        if character == "{":
            end = pattern.find("}", index + 1)
            if end == -1:
                raise ValueError("regex bounded repetition is malformed")
            if not previous_atom or previous_group or previous_quantifier:
                raise ValueError("regex quantifier placement is invalid")
            body = pattern[index + 1 : end]
            parts = body.split(",")
            if len(parts) == 1 and parts[0].isdigit():
                lower = upper = int(parts[0])
            elif len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                lower = int(parts[0])
                upper = int(parts[1])
                variable_quantifiers += int(lower != upper)
            else:
                raise ValueError("regex repetition requires a finite upper bound")
            if lower > upper or upper > _MAX_BOUNDED_REPETITION:
                raise ValueError("regex repetition exceeds the safe limit")
            if lower != upper and upper > _MAX_VARIABLE_REPETITION:
                raise ValueError("regex variable repetition exceeds the safe limit")
            previous_atom = True
            previous_group = False
            previous_quantifier = True
            index = end + 1
            continue

        if character in {"}", "]"}:
            raise ValueError("regex delimiter structure is invalid")

        if character in {"^", "$"}:
            previous_atom = False
            previous_group = False
            previous_quantifier = False
            index += 1
            continue

        previous_atom = True
        previous_group = False
        previous_quantifier = False
        index += 1

    if group_depth != 0:
        raise ValueError("regex group structure is invalid")
    if variable_quantifiers > 1:
        raise ValueError("regex contains too many variable repetitions")


def _consume_character_class(pattern: str, start: int) -> int:
    """Return the index after one non-empty, escaped character class."""

    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    content_characters = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                raise ValueError("regex character class has an invalid escape")
            content_characters += 1
            index += 2
            continue
        if character == "]":
            if content_characters == 0:
                raise ValueError("regex character class must not be empty")
            return index + 1
        content_characters += 1
        index += 1
    raise ValueError("regex character class is not closed")

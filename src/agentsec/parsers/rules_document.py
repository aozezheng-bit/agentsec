"""Non-executing parser for Codex `.rules` prefix declarations."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from agentsec.parsers.declarations import SourceBackedValue


class PrefixRuleDecision(StrEnum):
    """Supported Codex prefix-rule decisions."""

    ALLOW = "allow"
    PROMPT = "prompt"
    FORBIDDEN = "forbidden"


class RulesParseIssueCode(StrEnum):
    """Stable safe failure categories for `.rules` input."""

    MALFORMED = "malformed"
    UNSUPPORTED_STATEMENT = "unsupported_statement"
    UNSUPPORTED_EXPRESSION = "unsupported_expression"
    DUPLICATE_FIELD = "duplicate_field"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_PATTERN = "missing_pattern"
    INVALID_PATTERN = "invalid_pattern"
    INVALID_DECISION = "invalid_decision"
    LIMIT_EXCEEDED = "limit_exceeded"


type PrefixPatternElement = str | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RulesParseLimits:
    """Bound `.rules` AST size and literal materialization."""

    max_source_characters: int = 1_048_576
    max_rules: int = 1_000
    max_pattern_elements: int = 64
    max_examples_per_rule: int = 128
    max_literal_characters: int = 4_096

    def __post_init__(self) -> None:
        for value in (
            self.max_source_characters,
            self.max_rules,
            self.max_pattern_elements,
            self.max_examples_per_rule,
            self.max_literal_characters,
        ):
            if value < 1:
                raise ValueError("rules parser limits must be positive")


@dataclass(frozen=True, slots=True)
class PrefixRuleDeclaration:
    """One inert source-backed `prefix_rule` declaration."""

    pattern: SourceBackedValue[tuple[PrefixPatternElement, ...]]
    decision: SourceBackedValue[PrefixRuleDecision]
    justification: SourceBackedValue[str] | None
    match_examples: tuple[SourceBackedValue[str], ...]
    non_match_examples: tuple[SourceBackedValue[str], ...]
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if not self.pattern.value:
            raise ValueError("prefix rule requires a non-empty pattern")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("prefix rule requires a coherent line range")


@dataclass(frozen=True, slots=True)
class ParsedRulesDocument:
    """Ordered inert `.rules` declarations with no executable AST retained."""

    rules: tuple[PrefixRuleDeclaration, ...]
    source_line_count: int

    def __post_init__(self) -> None:
        if self.source_line_count < 0:
            raise ValueError("rules source_line_count must not be negative")
        previous_start = 0
        for rule in self.rules:
            if rule.end_line > self.source_line_count:
                raise ValueError("prefix rule range exceeds source line count")
            if rule.start_line < previous_start:
                raise ValueError("prefix rules must be source ordered")
            previous_start = rule.start_line


class RulesParseError(RuntimeError):
    """Safe `.rules` failure that never copies untrusted source text."""

    def __init__(
        self,
        code: RulesParseIssueCode,
        *,
        line: int | None = None,
    ) -> None:
        self.code = code
        self.line = line
        super().__init__(f"Rules parsing failed safely: {code.value}.")


class PrefixRulesParser:
    """Parse the reviewed literal `prefix_rule(...)` subset without execution."""

    _ALLOWED_FIELDS = {
        "pattern",
        "decision",
        "justification",
        "match",
        "not_match",
    }

    def __init__(self, limits: RulesParseLimits | None = None) -> None:
        self._limits = limits if limits is not None else RulesParseLimits()

    def parse(self, content: str) -> ParsedRulesDocument:
        """Parse declarations as AST data and reject every executable construct."""

        if len(content) > self._limits.max_source_characters:
            raise RulesParseError(RulesParseIssueCode.LIMIT_EXCEEDED)
        try:
            module = ast.parse(content, mode="exec")
        except (SyntaxError, ValueError, RecursionError) as error:
            line = getattr(error, "lineno", None)
            raise RulesParseError(
                RulesParseIssueCode.MALFORMED,
                line=line if isinstance(line, int) else None,
            ) from error

        if len(module.body) > self._limits.max_rules:
            raise RulesParseError(RulesParseIssueCode.LIMIT_EXCEEDED)

        rules: list[PrefixRuleDeclaration] = []
        for statement in module.body:
            rules.append(self._parse_statement(statement, len(rules)))
        return ParsedRulesDocument(
            rules=tuple(rules),
            source_line_count=len(content.splitlines()),
        )

    def _parse_statement(
        self,
        statement: ast.stmt,
        rule_index: int,
    ) -> PrefixRuleDeclaration:
        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, ast.Call
        ):
            self._raise(
                RulesParseIssueCode.UNSUPPORTED_STATEMENT,
                line=getattr(statement, "lineno", None),
            )
        call = statement.value
        if (
            not isinstance(call.func, ast.Name)
            or call.func.id != "prefix_rule"
            or call.args
        ):
            self._raise(
                RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
                line=getattr(call, "lineno", None),
            )

        fields: dict[str, ast.expr] = {}
        for keyword in call.keywords:
            name = keyword.arg
            if name is None:
                self._raise(
                    RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
                    line=keyword.value.lineno,
                )
            if name not in self._ALLOWED_FIELDS:
                self._raise(
                    RulesParseIssueCode.UNKNOWN_FIELD,
                    line=keyword.value.lineno,
                )
            if name in fields:
                self._raise(
                    RulesParseIssueCode.DUPLICATE_FIELD,
                    line=keyword.value.lineno,
                )
            fields[name] = keyword.value

        pattern_node = fields.get("pattern")
        if pattern_node is None:
            self._raise(
                RulesParseIssueCode.MISSING_PATTERN,
                line=call.lineno,
            )
        pattern = self._parse_pattern(pattern_node)
        decision_node = fields.get("decision")
        if decision_node is None:
            decision = SourceBackedValue(
                value=PrefixRuleDecision.ALLOW,
                path=("prefix_rule", rule_index, "decision"),
                start_line=call.lineno,
                end_line=call.lineno,
            )
        else:
            raw_decision = self._string_literal(decision_node)
            try:
                parsed_decision = PrefixRuleDecision(raw_decision)
            except ValueError as error:
                raise RulesParseError(
                    RulesParseIssueCode.INVALID_DECISION,
                    line=decision_node.lineno,
                ) from error
            decision = self._source_value(
                parsed_decision,
                decision_node,
                path=("prefix_rule", rule_index, "decision"),
            )

        justification_node = fields.get("justification")
        justification = (
            None
            if justification_node is None
            else self._source_value(
                self._string_literal(justification_node),
                justification_node,
                path=("prefix_rule", rule_index, "justification"),
            )
        )
        if justification is not None and not justification.value.strip():
            self._raise(
                RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
                line=justification.start_line,
            )

        return PrefixRuleDeclaration(
            pattern=self._source_value(
                pattern,
                pattern_node,
                path=("prefix_rule", rule_index, "pattern"),
            ),
            decision=decision,
            justification=justification,
            match_examples=self._parse_examples(
                fields.get("match"),
                rule_index=rule_index,
                field="match",
            ),
            non_match_examples=self._parse_examples(
                fields.get("not_match"),
                rule_index=rule_index,
                field="not_match",
            ),
            start_line=call.lineno,
            end_line=call.end_lineno or call.lineno,
        )

    def _parse_pattern(self, node: ast.expr) -> tuple[PrefixPatternElement, ...]:
        if not isinstance(node, ast.List):
            self._raise(RulesParseIssueCode.INVALID_PATTERN, line=node.lineno)
        if not node.elts or len(node.elts) > self._limits.max_pattern_elements:
            self._raise(RulesParseIssueCode.INVALID_PATTERN, line=node.lineno)

        result: list[PrefixPatternElement] = []
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                result.append(self._validated_literal(element.value, element.lineno))
                continue
            if isinstance(element, ast.List):
                if not element.elts:
                    self._raise(
                        RulesParseIssueCode.INVALID_PATTERN,
                        line=element.lineno,
                    )
                alternatives = tuple(
                    self._string_literal(item) for item in element.elts
                )
                if len(set(alternatives)) != len(alternatives):
                    self._raise(
                        RulesParseIssueCode.INVALID_PATTERN,
                        line=element.lineno,
                    )
                result.append(alternatives)
                continue
            self._raise(RulesParseIssueCode.INVALID_PATTERN, line=element.lineno)
        return tuple(result)

    def _parse_examples(
        self,
        node: ast.expr | None,
        *,
        rule_index: int,
        field: str,
    ) -> tuple[SourceBackedValue[str], ...]:
        if node is None:
            return ()
        if not isinstance(node, ast.List):
            self._raise(RulesParseIssueCode.UNSUPPORTED_EXPRESSION, line=node.lineno)
        if len(node.elts) > self._limits.max_examples_per_rule:
            self._raise(RulesParseIssueCode.LIMIT_EXCEEDED, line=node.lineno)
        values: list[SourceBackedValue[str]] = []
        for index, element in enumerate(node.elts):
            value = self._string_literal(element)
            values.append(
                self._source_value(
                    value,
                    element,
                    path=("prefix_rule", rule_index, field, index),
                )
            )
        return tuple(values)

    def _string_literal(self, node: ast.expr) -> str:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            self._raise(
                RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
                line=node.lineno,
            )
        return self._validated_literal(node.value, node.lineno)

    def _validated_literal(self, value: str, line: int) -> str:
        if not value or len(value) > self._limits.max_literal_characters:
            self._raise(RulesParseIssueCode.LIMIT_EXCEEDED, line=line)
        return value

    @staticmethod
    def _source_value[T](
        value: T,
        node: ast.expr,
        *,
        path: tuple[str | int, ...],
    ) -> SourceBackedValue[T]:
        return SourceBackedValue(
            value=value,
            path=path,
            start_line=node.lineno,
            end_line=node.end_lineno or node.lineno,
        )

    @staticmethod
    def _raise(
        code: RulesParseIssueCode,
        *,
        line: int | None,
    ) -> NoReturn:
        raise RulesParseError(code, line=line)

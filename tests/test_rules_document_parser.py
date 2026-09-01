"""P2-02 non-executing Codex `.rules` parser tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.parsers import (
    PrefixRuleDecision,
    PrefixRulesParser,
    RulesParseError,
    RulesParseIssueCode,
    RulesParseLimits,
)


def test_rules_parser_extracts_literal_prefix_rules_and_source_lines() -> None:
    content = """# GitHub CLI rules
prefix_rule(
    pattern = ["gh", ["pr", "issue"], "view"],
    decision = "prompt",
    justification = "Viewing GitHub records may contact a remote service.",
    match = ["gh pr view 123", "gh issue view 456"],
    not_match = ["gh repo view"],
)

prefix_rule(pattern = ["git", "status"])
"""

    document = PrefixRulesParser().parse(content)

    assert document.source_line_count == 10
    assert len(document.rules) == 2
    first, second = document.rules
    assert first.pattern.value == ("gh", ("pr", "issue"), "view")
    assert first.pattern.start_line == 3
    assert first.decision.value is PrefixRuleDecision.PROMPT
    assert first.justification is not None
    assert first.justification.start_line == 5
    assert tuple(item.value for item in first.match_examples) == (
        "gh pr view 123",
        "gh issue view 456",
    )
    assert tuple(item.value for item in first.non_match_examples) == ("gh repo view",)
    assert first.start_line == 2
    assert first.end_line == 8
    assert second.decision.value is PrefixRuleDecision.ALLOW
    assert second.pattern.value == ("git", "status")


def test_rules_parser_accepts_all_reviewed_decisions() -> None:
    content = """
prefix_rule(pattern=["git", "status"], decision="allow")
prefix_rule(pattern=["git", "push"], decision="prompt")
prefix_rule(pattern=["rm", "-rf"], decision="forbidden")
"""

    document = PrefixRulesParser().parse(content)

    assert tuple(rule.decision.value for rule in document.rules) == (
        PrefixRuleDecision.ALLOW,
        PrefixRuleDecision.PROMPT,
        PrefixRuleDecision.FORBIDDEN,
    )


def test_rules_parser_rejects_non_literal_or_executable_expressions(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "must-not-exist"
    content = f'prefix_rule(pattern=[__import__("pathlib").Path("{marker}").touch()])\n'

    with pytest.raises(RulesParseError) as captured:
        PrefixRulesParser().parse(content)

    assert captured.value.code is RulesParseIssueCode.INVALID_PATTERN
    assert not marker.exists()
    assert str(marker) not in str(captured.value)


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("import os\n", RulesParseIssueCode.UNSUPPORTED_STATEMENT),
        ("value = 1\n", RulesParseIssueCode.UNSUPPORTED_STATEMENT),
        (
            'other_rule(pattern=["git"])\n',
            RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
        ),
        (
            'prefix_rule(["git"])\n',
            RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
        ),
        (
            'prefix_rule(pattern=["git"], unknown="x")\n',
            RulesParseIssueCode.UNKNOWN_FIELD,
        ),
        (
            'prefix_rule(decision="allow")\n',
            RulesParseIssueCode.MISSING_PATTERN,
        ),
        (
            'prefix_rule(pattern="git")\n',
            RulesParseIssueCode.INVALID_PATTERN,
        ),
        (
            'prefix_rule(pattern=["git"], decision="sometimes")\n',
            RulesParseIssueCode.INVALID_DECISION,
        ),
        (
            "prefix_rule(pattern=[name])\n",
            RulesParseIssueCode.INVALID_PATTERN,
        ),
        (
            'prefix_rule(pattern=["git"], match=[build_command()])\n',
            RulesParseIssueCode.UNSUPPORTED_EXPRESSION,
        ),
    ],
)
def test_rules_parser_rejects_every_unreviewed_construct(
    content: str,
    code: RulesParseIssueCode,
) -> None:
    with pytest.raises(RulesParseError) as captured:
        PrefixRulesParser().parse(content)

    assert captured.value.code is code


def test_rules_parser_rejects_duplicate_union_alternatives_and_empty_literals() -> None:
    parser = PrefixRulesParser()

    with pytest.raises(RulesParseError) as duplicate:
        parser.parse('prefix_rule(pattern=["gh", ["pr", "pr"]])\n')
    assert duplicate.value.code is RulesParseIssueCode.INVALID_PATTERN

    with pytest.raises(RulesParseError) as empty:
        parser.parse('prefix_rule(pattern=[""])\n')
    assert empty.value.code is RulesParseIssueCode.LIMIT_EXCEEDED


def test_rules_parser_enforces_source_rule_pattern_example_and_literal_limits() -> None:
    with pytest.raises(RulesParseError) as source:
        PrefixRulesParser(RulesParseLimits(max_source_characters=10)).parse(
            'prefix_rule(pattern=["git"])\n'
        )
    assert source.value.code is RulesParseIssueCode.LIMIT_EXCEEDED

    with pytest.raises(RulesParseError) as rules:
        PrefixRulesParser(RulesParseLimits(max_rules=1)).parse(
            'prefix_rule(pattern=["git"])\nprefix_rule(pattern=["gh"])\n'
        )
    assert rules.value.code is RulesParseIssueCode.LIMIT_EXCEEDED

    with pytest.raises(RulesParseError) as pattern:
        PrefixRulesParser(RulesParseLimits(max_pattern_elements=1)).parse(
            'prefix_rule(pattern=["git", "status"])\n'
        )
    assert pattern.value.code is RulesParseIssueCode.INVALID_PATTERN

    with pytest.raises(RulesParseError) as examples:
        PrefixRulesParser(RulesParseLimits(max_examples_per_rule=1)).parse(
            'prefix_rule(pattern=["git"], match=["git a", "git b"])\n'
        )
    assert examples.value.code is RulesParseIssueCode.LIMIT_EXCEEDED

    with pytest.raises(RulesParseError) as literal:
        PrefixRulesParser(RulesParseLimits(max_literal_characters=3)).parse(
            'prefix_rule(pattern=["long"])\n'
        )
    assert literal.value.code is RulesParseIssueCode.LIMIT_EXCEEDED


def test_rules_parser_is_deterministic_and_empty_files_are_valid() -> None:
    parser = PrefixRulesParser()
    content = 'prefix_rule(pattern=["git", "status"], decision="allow")\n'

    assert parser.parse(content) == parser.parse(content)
    assert parser.parse("# comments only\n").rules == ()

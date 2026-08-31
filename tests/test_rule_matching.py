"""Behavior and safety tests for P1-18 deterministic text matching rules."""

from __future__ import annotations

import builtins
import hashlib
import socket
import subprocess

import pytest

from agentsec.domain import AgentAsset, AssetSource, AssetType, FindingCategory
from agentsec.parsers import MarkdownBlockKind, MarkdownItParser
from agentsec.rules import (
    MAX_CONTEXT_WINDOW_LINES,
    MAX_EVIDENCE_EXCERPT_CHARACTERS,
    MAX_KEYWORD_LINE_CHARACTERS,
    MAX_REGEX_LINE_CHARACTERS,
    ContextWindow,
    KeywordCondition,
    KeywordRule,
    MatchMode,
    RegexCondition,
    RegexRule,
    Rule,
    RuleContext,
    RuleEvaluationError,
    RuleMetadata,
    RuleScope,
    RuleTarget,
)


def make_context(
    content: str,
    *,
    asset_type: AssetType = AssetType.AGENTS,
) -> RuleContext:
    """Build one coherent parsed context for matcher tests."""

    content_bytes = content.encode("utf-8")
    return RuleContext(
        asset=AgentAsset(
            path="AGENTS.md",
            asset_type=asset_type,
            source=AssetSource.DISCOVERED,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
        ),
        content=content,
        document=MarkdownItParser().parse(content),
    )


def make_metadata(
    *,
    rule_id: str = "MD-EXEC-001",
    asset_types: frozenset[AssetType] = frozenset(AssetType),
) -> RuleMetadata:
    """Build metadata scoped to parsed Markdown blocks."""

    return RuleMetadata(
        rule_id=rule_id,
        title="Potential command execution declaration",
        description="Matches a bounded deterministic text condition.",
        category=FindingCategory.CODE_EXECUTION,
        recommendations=("Review the declaration and require approval.",),
        scope=RuleScope(
            asset_types=asset_types,
            targets=frozenset({RuleTarget.MARKDOWN_BLOCK}),
        ),
    )


def test_keyword_rule_matches_case_insensitively_with_exact_line_evidence() -> None:
    """Keyword adapters satisfy Rule and retain authoritative source evidence."""

    context = make_context("# Controls\n\nRun the SHELL command only after approval.\n")
    rule = KeywordRule(
        make_metadata(),
        keywords=("shell command",),
    )

    evaluation = rule.evaluate(context)
    evidence = evaluation.candidates[0].materialize_evidence(context)

    assert isinstance(rule, Rule)
    assert len(evaluation.candidates) == 1
    assert (evidence[0].start_line, evidence[0].end_line) == (3, 3)
    assert evidence[0].excerpt == "Run the SHELL command only after approval."
    assert evidence[0].content_sha256 == context.asset.sha256


def test_keyword_modes_and_word_boundaries_are_deterministic() -> None:
    """ANY, ALL, and whole-word options have explicit non-substring semantics."""

    context = make_context(
        "Executioner is harmless here.\n\nExecute a production release.\n"
    )
    whole_word = KeywordRule(
        make_metadata(),
        keywords=("execute",),
        whole_word=True,
    )
    all_terms = KeywordRule(
        make_metadata(rule_id="MD-EXEC-002"),
        keywords=("execute", "production"),
        mode=MatchMode.ALL,
        whole_word=True,
    )

    assert [
        candidate.evidence[0].start_line
        for candidate in whole_word.evaluate(context).candidates
    ] == [3]
    assert [
        candidate.evidence[0].start_line
        for candidate in all_terms.evaluate(context).candidates
    ] == [3]


def test_keyword_rule_respects_asset_scope_and_selected_block_kinds() -> None:
    """Applicability and block selection avoid evaluating unrelated structures."""

    content = "Paragraph says shell.\n\n```bash\nshell deploy\n```\n"
    skill_context = make_context(content, asset_type=AssetType.SKILL)
    agents_only = KeywordRule(
        make_metadata(asset_types=frozenset({AssetType.AGENTS})),
        keywords=("shell",),
    )
    fenced_only = KeywordRule(
        make_metadata(rule_id="MD-EXEC-002"),
        keywords=("shell",),
        block_kinds=frozenset({MarkdownBlockKind.FENCED_CODE}),
    )

    assert agents_only.evaluate(skill_context).candidates == ()
    assert [
        candidate.evidence[0].start_line
        for candidate in fenced_only.evaluate(skill_context).candidates
    ] == [4]


def test_regex_rule_accepts_safe_bounded_syntax_and_preserves_line_number() -> None:
    """The safe regex dialect supports useful bounded patterns without raw regex I/O."""

    context = make_context("# Deployment\n\nDEPLOY    token to production.\n")
    rule = RegexRule(
        make_metadata(rule_id="MD-SECRET-001"),
        patterns=(r"\bdeploy\s{1,8}token\b",),
    )

    evaluation = rule.evaluate(context)
    evidence = evaluation.candidates[0].materialize_evidence(context)

    assert evidence[0].start_line == 3
    assert evidence[0].excerpt == "DEPLOY    token to production."


@pytest.mark.parametrize(
    "pattern",
    [
        r".*token",
        r"token+",
        r"(token)",
        r"(?:to|token)+",
        r"(?=token)",
        r"(?!safe)token",
        r"(token)\1",
        r"(?i)token",
        r"token{1,}",
        r"a{0,8}b{0,8}",
        r"^$",
        "token\nsecret",
    ],
)
def test_regex_condition_rejects_unsafe_or_empty_matching_syntax(
    pattern: str,
) -> None:
    """Trusted rule authors cannot configure catastrophic or ambiguous regexes."""

    with pytest.raises(ValueError, match="regex"):
        RegexCondition(patterns=(pattern,))


def test_keyword_and_regex_conditions_require_bounded_unique_tuples() -> None:
    """Pattern configuration is immutable, finite, and unambiguous."""

    with pytest.raises(TypeError, match="tuple"):
        KeywordCondition(keywords=["shell"])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unique"):
        KeywordCondition(keywords=("Shell", "shell"))
    with pytest.raises(ValueError, match="line breaks"):
        KeywordCondition(keywords=("shell\ncommand",))
    with pytest.raises(ValueError, match="unique"):
        RegexCondition(patterns=(r"\bshell\b", r"\bshell\b"))
    with pytest.raises(TypeError, match="MatchMode"):
        KeywordCondition(
            keywords=("shell",),
            mode="any",  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="boolean"):
        RegexCondition(
            patterns=(r"\bshell\b",),
            case_sensitive=1,  # type: ignore[arg-type]
        )


def test_context_window_requires_nearby_support_and_emits_both_lines() -> None:
    """A primary match is accepted only with source-backed context in the window."""

    content = (
        "# Release\n"
        "Production target.\n"
        "Execute deployment now.\n"
        "Human approval is required.\n"
        "Unrelated trailing text.\n"
    )
    context = make_context(content)
    rule = KeywordRule(
        make_metadata(),
        keywords=("execute",),
        whole_word=True,
        context=ContextWindow(
            condition=KeywordCondition(
                keywords=("approval",),
                whole_word=True,
            ),
            before_lines=0,
            after_lines=1,
        ),
    )

    evaluation = rule.evaluate(context)
    evidence = evaluation.candidates[0].materialize_evidence(context)

    assert [(item.start_line, item.excerpt) for item in evidence] == [
        (3, "Execute deployment now."),
        (4, "Human approval is required."),
    ]

    outside_window = KeywordRule(
        make_metadata(rule_id="MD-EXEC-002"),
        keywords=("execute",),
        context=ContextWindow(
            condition=KeywordCondition(keywords=("approval",)),
            before_lines=0,
            after_lines=0,
            include_match_line=True,
        ),
    )
    assert outside_window.evaluate(context).candidates == ()


def test_context_all_mode_can_be_satisfied_across_multiple_lines() -> None:
    """ALL context terms may be supported by separate lines in one bounded window."""

    context = make_context(
        "Approval is disabled.\nExecute release.\nProduction environment is selected.\n"
    )
    rule = KeywordRule(
        make_metadata(),
        keywords=("execute",),
        context=ContextWindow(
            condition=KeywordCondition(
                keywords=("approval", "production"),
                mode=MatchMode.ALL,
            ),
            before_lines=1,
            after_lines=1,
            include_match_line=False,
        ),
    )

    evidence = rule.evaluate(context).candidates[0].materialize_evidence(context)

    assert [item.start_line for item in evidence] == [1, 2, 3]


def test_regex_context_condition_is_supported() -> None:
    """Keyword and regex conditions can be composed across the bounded window."""

    context = make_context(
        "Send the result.\nDestination: https://external.example/hook\n"
    )
    rule = KeywordRule(
        make_metadata(rule_id="MD-NET-001"),
        keywords=("send",),
        context=ContextWindow(
            condition=RegexCondition(
                patterns=(r"https://[A-Za-z0-9.-]{1,32}/hook",),
            ),
            after_lines=1,
            include_match_line=False,
        ),
    )

    assert [
        evidence.start_line
        for evidence in rule.evaluate(context)
        .candidates[0]
        .materialize_evidence(context)
    ] == [1, 2]


def test_symmetric_context_deduplicates_identical_candidates() -> None:
    """Matcher-local duplicates are removed before the P1-19 Finding pipeline."""

    context = make_context("Execute first.\nExecute second.\n")
    rule = KeywordRule(
        make_metadata(),
        keywords=("execute",),
        context=ContextWindow(
            condition=KeywordCondition(keywords=("execute",)),
            before_lines=1,
            after_lines=1,
            include_match_line=False,
        ),
    )

    evaluation = rule.evaluate(context)

    assert len(evaluation.candidates) == 1
    assert [item.start_line for item in evaluation.candidates[0].evidence] == [1, 2]


def test_evidence_excerpt_is_bounded_around_the_actual_match() -> None:
    """Very long source lines do not create unbounded candidate excerpts."""

    line = "x" * 2_000 + " shell command " + "y" * 2_000
    context = make_context(f"{line}\n")
    rule = KeywordRule(
        make_metadata(),
        keywords=("shell command",),
    )

    candidate = rule.evaluate(context).candidates[0]
    excerpt = candidate.materialize_evidence(context)[0].excerpt

    assert excerpt is not None
    assert len(excerpt) == MAX_EVIDENCE_EXCERPT_CHARACTERS
    assert "shell command" in excerpt
    assert excerpt in line


def test_candidate_limit_and_regex_line_limit_fail_safely() -> None:
    """Match amplification and oversized regex subjects never truncate silently."""

    many_matches = make_context("\n".join("shell" for _ in range(257)) + "\n")
    keyword_rule = KeywordRule(make_metadata(), keywords=("shell",))

    with pytest.raises(RuleEvaluationError) as candidate_error:
        keyword_rule.evaluate(many_matches)
    assert str(candidate_error.value) == "Rule evaluation failed safely."

    long_keyword_line = "x" * MAX_KEYWORD_LINE_CHARACTERS + " shell"
    keyword_context = make_context(f"{long_keyword_line}\n")
    with pytest.raises(RuleEvaluationError):
        keyword_rule.evaluate(keyword_context)

    long_line = "x" * MAX_REGEX_LINE_CHARACTERS + " token"
    regex_context = make_context(f"{long_line}\n")
    regex_rule = RegexRule(
        make_metadata(rule_id="MD-SECRET-001"),
        patterns=(r"\btoken\b",),
    )

    with pytest.raises(RuleEvaluationError) as regex_error:
        regex_rule.evaluate(regex_context)
    assert "token" not in str(regex_error.value)


def test_context_window_limit_is_explicit() -> None:
    """Rule authors cannot create unbounded source context expansion."""

    condition = KeywordCondition(keywords=("approval",))

    with pytest.raises(ValueError, match="context window"):
        ContextWindow(
            condition=condition,
            before_lines=MAX_CONTEXT_WINDOW_LINES + 1,
        )
    with pytest.raises(ValueError, match="at least one source line"):
        ContextWindow(
            condition=condition,
            include_match_line=False,
        )
    with pytest.raises(TypeError, match="integer"):
        ContextWindow(condition=condition, before_lines=True)


def test_repeated_evaluation_is_identical_and_has_no_external_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Matching is deterministic and does not touch shell, files, or network."""

    context = make_context("Execute shell command after approval.\n")
    rule = RegexRule(
        make_metadata(),
        patterns=(r"\bexecute\s{1,8}shell\b",),
        context=ContextWindow(
            condition=KeywordCondition(keywords=("approval",)),
            include_match_line=True,
        ),
    )
    expected = rule.evaluate(context)

    def prohibited(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("matcher attempted a prohibited side effect")

    monkeypatch.setattr(builtins, "open", prohibited)
    monkeypatch.setattr(subprocess, "run", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)

    assert rule.evaluate(context) == expected
    assert rule.evaluate(context) == expected


def test_rule_constructor_rejects_incompatible_scope_and_block_configuration() -> None:
    """Text rules require a Markdown-block target and immutable block kinds."""

    incompatible = RuleMetadata(
        rule_id="MD-EXEC-001",
        title="Invalid target",
        description="Used only to test constructor validation.",
        category=FindingCategory.CODE_EXECUTION,
        recommendations=("Use the Markdown block target.",),
        scope=RuleScope(
            asset_types=frozenset({AssetType.AGENTS}),
            targets=frozenset({RuleTarget.REFERENCE}),
        ),
    )

    with pytest.raises(ValueError, match="MARKDOWN_BLOCK"):
        KeywordRule(incompatible, keywords=("shell",))

    with pytest.raises(TypeError, match="frozenset"):
        KeywordRule(
            make_metadata(),
            keywords=("shell",),
            block_kinds={MarkdownBlockKind.PARAGRAPH},  # type: ignore[arg-type]
        )

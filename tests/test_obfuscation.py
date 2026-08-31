"""Tests for deterministic, non-finding obfuscation indicators."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Never

import pytest

from agentsec.parsers import (
    BASE64_MIN_CHARACTERS,
    LONG_BLOCK_CHARACTERS,
    LONG_LINE_CHARACTERS,
    MarkdownItParser,
    MarkdownParseError,
    ObfuscationIndicator,
    ObfuscationKind,
    ParsedMarkdown,
)


def test_risky_fixture_produces_source_backed_obfuscation_indicators() -> None:
    """The corpus covers encoded, invisible and mixed-script signals."""

    path = (
        Path(__file__).parents[1]
        / "testdata"
        / "risky"
        / "obfuscated-instructions"
        / "AGENTS.md"
    )

    document = MarkdownItParser().parse(path.read_text(encoding="utf-8"))

    assert [indicator.kind for indicator in document.indicators] == [
        ObfuscationKind.BASE64_LIKE,
        ObfuscationKind.ZERO_WIDTH,
        ObfuscationKind.MIXED_SCRIPT_CONFUSABLE,
    ]
    encoded, zero_width, mixed = document.indicators
    assert (encoded.start_line, encoded.end_line) == (3, 3)
    assert encoded.character_count == 100
    assert encoded.heading_path == ("Obfuscated Instruction Example",)
    assert zero_width.codepoints == ("U+200B",)
    assert (zero_width.start_line, zero_width.end_line) == (4, 4)
    assert mixed.scripts == ("CYRILLIC", "LATIN")
    assert (mixed.start_line, mixed.end_line) == (5, 5)


def test_base64_heuristic_supports_urlsafe_and_rejects_hex_or_low_entropy() -> None:
    """Decodability and entropy reduce obvious hash and repeated-text noise."""

    urlsafe = base64.urlsafe_b64encode(bytes(range(64))).decode().rstrip("=")
    hex_digest = "a1" * 32
    repeated = "A" * BASE64_MIN_CHARACTERS
    content = f"{urlsafe}\n{hex_digest}\n{repeated}\n"

    document = MarkdownItParser().parse(content)

    indicators = [
        indicator
        for indicator in document.indicators
        if indicator.kind is ObfuscationKind.BASE64_LIKE
    ]
    assert len(indicators) == 1
    assert indicators[0].start_line == 1
    assert indicators[0].character_count == len(urlsafe)


def test_long_line_threshold_is_inclusive() -> None:
    """Exactly the documented threshold is visible while one less is not."""

    content = f"{'x' * (LONG_LINE_CHARACTERS - 1)}\n{'y' * LONG_LINE_CHARACTERS}\n"

    document = MarkdownItParser().parse(content)

    long_lines = [
        indicator
        for indicator in document.indicators
        if indicator.kind is ObfuscationKind.LONG_LINE
    ]
    assert [
        (indicator.start_line, indicator.character_count) for indicator in long_lines
    ] == [(2, LONG_LINE_CHARACTERS)]


def test_long_multiline_block_is_detected_without_long_individual_lines() -> None:
    """Large paragraphs remain visible even when split below the line threshold."""

    line = "z" * 800
    content = "\n".join([line] * 5) + "\n"
    assert len(content) >= LONG_BLOCK_CHARACTERS
    assert len(line) < LONG_LINE_CHARACTERS

    document = MarkdownItParser().parse(content)

    assert [indicator.kind for indicator in document.indicators] == [
        ObfuscationKind.LONG_BLOCK
    ]
    assert document.indicators[0].start_line == 1
    assert document.indicators[0].end_line == 5
    assert document.indicators[0].character_count == len(content)


def test_invisible_bidi_and_control_characters_are_grouped_by_line() -> None:
    """Indicators expose safe codepoint labels without copying source text."""

    content = "\ufeff# Heading\nzero\u200b\u200b bidi\u202e control\x07\n"

    document = MarkdownItParser().parse(content)

    assert [indicator.kind for indicator in document.indicators] == [
        ObfuscationKind.BIDI_CONTROL,
        ObfuscationKind.CONTROL_CHARACTER,
        ObfuscationKind.ZERO_WIDTH,
    ]
    bidi, control, zero_width = document.indicators
    assert bidi.codepoints == ("U+202E",)
    assert control.codepoints == ("U+0007",)
    assert zero_width.codepoints == ("U+200B",)
    assert zero_width.character_count == 2
    assert all(indicator.start_line == 2 for indicator in document.indicators)
    assert all(
        "U+FEFF" not in indicator.codepoints for indicator in document.indicators
    )


def test_mixed_script_requires_latin_with_cyrillic_or_greek_in_one_token() -> None:
    """Common multilingual prose is not flagged unless one word mixes scripts."""

    content = (
        "English 中文 separated\nкириллица only\nаpproval mixed\nalphα mixed-greek\n"
    )

    document = MarkdownItParser().parse(content)

    mixed = [
        indicator
        for indicator in document.indicators
        if indicator.kind is ObfuscationKind.MIXED_SCRIPT_CONFUSABLE
    ]
    assert [(indicator.start_line, indicator.scripts) for indicator in mixed] == [
        (3, ("CYRILLIC", "LATIN")),
        (4, ("GREEK", "LATIN")),
    ]


def test_base64_inside_code_is_an_indicator_but_never_executed(tmp_path: Path) -> None:
    """Code context does not suppress an encoding signal or execute decoded bytes."""

    marker = tmp_path / "must-not-exist"
    payload = base64.b64encode(
        f"touch {marker}; harmless test payload with enough diversity".encode()
    ).decode()
    content = f"```text\n{payload}\n```\n"

    document = MarkdownItParser().parse(content)

    assert not marker.exists()
    assert any(
        indicator.kind is ObfuscationKind.BASE64_LIKE
        for indicator in document.indicators
    )


def test_indicators_do_not_store_the_suspicious_token() -> None:
    """Evidence uses location and metrics rather than duplicating potential secrets."""

    payload = base64.b64encode(
        b"harmless but secret-shaped placeholder text for indicator testing"
    ).decode()

    document = MarkdownItParser().parse(payload)

    indicator = document.indicators[0]
    assert indicator.kind is ObfuscationKind.BASE64_LIKE
    assert not hasattr(indicator, "raw_text")
    assert not hasattr(indicator, "text")
    assert payload not in repr(indicator)


def test_indicator_model_rejects_incoherent_metadata() -> None:
    """Mixed-script and codepoint evidence must remain deterministic."""

    with pytest.raises(ValueError, match="at least two scripts"):
        ObfuscationIndicator(
            kind=ObfuscationKind.MIXED_SCRIPT_CONFUSABLE,
            start_line=1,
            end_line=1,
            scripts=("LATIN",),
        )

    with pytest.raises(ValueError, match="sorted and unique"):
        ObfuscationIndicator(
            kind=ObfuscationKind.ZERO_WIDTH,
            start_line=1,
            end_line=1,
            codepoints=("U+200D", "U+200B"),
        )


def test_analyzer_failure_is_wrapped_as_safe_parser_error() -> None:
    """A detector bug cannot leak source text or escape parser isolation."""

    class FailingAnalyzer:
        def analyze(
            self,
            content: str,
            document: ParsedMarkdown,
        ) -> Never:
            del document
            raise RuntimeError(f"must-not-leak: {content}")

    parser = MarkdownItParser(obfuscation_analyzer=FailingAnalyzer())

    with pytest.raises(MarkdownParseError) as error:
        parser.parse("obfuscation-secret-marker")

    assert str(error.value) == "Markdown parsing failed safely."
    assert "obfuscation-secret-marker" not in str(error.value)

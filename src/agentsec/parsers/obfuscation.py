"""Deterministic, non-executing obfuscation indicators for Markdown text."""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter

from agentsec.parsers.base import (
    MarkdownBlock,
    MarkdownBlockKind,
    ObfuscationIndicator,
    ObfuscationKind,
    ParsedMarkdown,
)

BASE64_MIN_CHARACTERS = 40
BASE64_MIN_DECODED_BYTES = 24
BASE64_MIN_ENTROPY = 3.5
LONG_LINE_CHARACTERS = 1_000
LONG_BLOCK_CHARACTERS = 4_000
MIXED_SCRIPT_MIN_LETTERS = 4

_BASE64_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{{{BASE64_MIN_CHARACTERS},}}={{0,2}})"
    r"(?![A-Za-z0-9+/_=-])"
)
_WORD_PATTERN = re.compile(r"\w+", re.UNICODE)
_HEX_PATTERN = re.compile(r"[A-Fa-f0-9]+")
_ZERO_WIDTH_CODEPOINTS = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}
_BIDI_CONTROL_CODEPOINTS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


class DeterministicObfuscationAnalyzer:
    """Flag explainable anomalies without interpreting them as instructions."""

    def analyze(
        self,
        content: str,
        document: ParsedMarkdown,
    ) -> tuple[ObfuscationIndicator, ...]:
        """Return stable indicators ordered by source range and kind."""

        indicators: list[ObfuscationIndicator] = []
        for line_number, source_line in enumerate(content.splitlines(), start=1):
            line = source_line
            if line_number == 1 and line.startswith("\ufeff"):
                line = line[1:]
            heading_path = self._heading_path_for_line(document.blocks, line_number)

            if len(line) >= LONG_LINE_CHARACTERS:
                indicators.append(
                    ObfuscationIndicator(
                        kind=ObfuscationKind.LONG_LINE,
                        start_line=line_number,
                        end_line=line_number,
                        character_count=len(line),
                        heading_path=heading_path,
                    )
                )

            indicators.extend(
                self._character_indicators(
                    line=line,
                    line_number=line_number,
                    heading_path=heading_path,
                )
            )
            indicators.extend(
                self._base64_indicators(
                    line=line,
                    line_number=line_number,
                    heading_path=heading_path,
                )
            )
            indicators.extend(
                self._mixed_script_indicators(
                    line=line,
                    line_number=line_number,
                    heading_path=heading_path,
                )
            )

        for block in document.blocks:
            if len(block.raw_text) >= LONG_BLOCK_CHARACTERS:
                indicators.append(
                    ObfuscationIndicator(
                        kind=ObfuscationKind.LONG_BLOCK,
                        start_line=block.start_line,
                        end_line=block.end_line,
                        character_count=len(block.raw_text),
                        heading_path=block.heading_path,
                    )
                )
        if (
            document.frontmatter is not None
            and len(document.frontmatter.raw_text) >= LONG_BLOCK_CHARACTERS
        ):
            indicators.append(
                ObfuscationIndicator(
                    kind=ObfuscationKind.LONG_BLOCK,
                    start_line=document.frontmatter.start_line,
                    end_line=document.frontmatter.end_line,
                    character_count=len(document.frontmatter.raw_text),
                )
            )

        return tuple(
            sorted(
                set(indicators),
                key=lambda indicator: (
                    indicator.start_line,
                    indicator.end_line,
                    indicator.kind.value,
                    indicator.character_count or 0,
                    indicator.codepoints,
                    indicator.scripts,
                    indicator.heading_path,
                ),
            )
        )

    @staticmethod
    def _character_indicators(
        *,
        line: str,
        line_number: int,
        heading_path: tuple[str, ...],
    ) -> tuple[ObfuscationIndicator, ...]:
        """Aggregate invisible and control code points by category per line."""

        zero_width: list[str] = []
        bidi: list[str] = []
        controls: list[str] = []

        for character in line:
            if character in _ZERO_WIDTH_CODEPOINTS:
                zero_width.append(character)
            elif character in _BIDI_CONTROL_CODEPOINTS:
                bidi.append(character)
            elif unicodedata.category(character) in {"Cc", "Cf"}:
                controls.append(character)

        indicators: list[ObfuscationIndicator] = []
        for kind, characters in (
            (ObfuscationKind.ZERO_WIDTH, zero_width),
            (ObfuscationKind.BIDI_CONTROL, bidi),
            (ObfuscationKind.CONTROL_CHARACTER, controls),
        ):
            if characters:
                indicators.append(
                    ObfuscationIndicator(
                        kind=kind,
                        start_line=line_number,
                        end_line=line_number,
                        character_count=len(characters),
                        codepoints=tuple(
                            sorted({_format_codepoint(value) for value in characters})
                        ),
                        heading_path=heading_path,
                    )
                )
        return tuple(indicators)

    @staticmethod
    def _base64_indicators(
        *,
        line: str,
        line_number: int,
        heading_path: tuple[str, ...],
    ) -> tuple[ObfuscationIndicator, ...]:
        """Flag long, decodable, high-entropy Base64 and URL-safe Base64 tokens."""

        indicators: list[ObfuscationIndicator] = []
        for match in _BASE64_PATTERN.finditer(line):
            candidate = match.group(1)
            if _looks_like_base64(candidate):
                indicators.append(
                    ObfuscationIndicator(
                        kind=ObfuscationKind.BASE64_LIKE,
                        start_line=line_number,
                        end_line=line_number,
                        character_count=len(candidate),
                        heading_path=heading_path,
                    )
                )
        return tuple(indicators)

    @staticmethod
    def _mixed_script_indicators(
        *,
        line: str,
        line_number: int,
        heading_path: tuple[str, ...],
    ) -> tuple[ObfuscationIndicator, ...]:
        """Flag Latin mixed with Cyrillic or Greek inside one word-like token."""

        indicators: list[ObfuscationIndicator] = []
        for match in _WORD_PATTERN.finditer(line):
            token = match.group(0)
            scripts = tuple(
                sorted(
                    {
                        script
                        for character in token
                        if character.isalpha()
                        for script in [_character_script(character)]
                        if script is not None
                    }
                )
            )
            letter_count = sum(character.isalpha() for character in token)
            if (
                letter_count >= MIXED_SCRIPT_MIN_LETTERS
                and "LATIN" in scripts
                and any(script in scripts for script in ("CYRILLIC", "GREEK"))
            ):
                indicators.append(
                    ObfuscationIndicator(
                        kind=ObfuscationKind.MIXED_SCRIPT_CONFUSABLE,
                        start_line=line_number,
                        end_line=line_number,
                        character_count=letter_count,
                        scripts=scripts,
                        heading_path=heading_path,
                    )
                )
        return tuple(indicators)

    @staticmethod
    def _heading_path_for_line(
        blocks: tuple[MarkdownBlock, ...],
        line_number: int,
    ) -> tuple[str, ...]:
        """Return heading context active at one source line."""

        heading_path: tuple[str, ...] = ()
        for block in blocks:
            if block.start_line > line_number:
                break
            if block.kind is MarkdownBlockKind.HEADING:
                heading_path = block.heading_path
        return heading_path


def _looks_like_base64(candidate: str) -> bool:
    """Return whether one token passes deterministic Base64 heuristics."""

    unpadded = candidate.rstrip("=")
    if _HEX_PATTERN.fullmatch(unpadded):
        return False
    character_classes = sum(
        (
            any(character.islower() for character in unpadded),
            any(character.isupper() for character in unpadded),
            any(character.isdigit() for character in unpadded),
            any(character in "+/_-" for character in unpadded),
        )
    )
    if character_classes < 2 or _shannon_entropy(unpadded) < BASE64_MIN_ENTROPY:
        return False

    normalized = unpadded.replace("-", "+").replace("_", "/")
    if len(normalized) % 4 == 1:
        return False
    normalized += "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= BASE64_MIN_DECODED_BYTES


def _shannon_entropy(value: str) -> float:
    """Calculate character entropy without decoding or retaining token content."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _character_script(character: str) -> str | None:
    """Return one of the confusable script families used by the heuristic."""

    name = unicodedata.name(character, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    return None


def _format_codepoint(character: str) -> str:
    """Return a non-secret, stable Unicode code point label."""

    return f"U+{ord(character):04X}"

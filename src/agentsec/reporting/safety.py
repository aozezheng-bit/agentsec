"""Deterministic secret redaction and control-character escaping for outputs."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

_REDACTED: Final[str] = "<redacted>"
_UNSAFE_UNICODE_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"Cc", "Cf", "Cs", "Zl", "Zp"}
)
_LINE_ENDINGS: Final[tuple[str, ...]] = (
    "\r\n",
    "\n",
    "\r",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)

_SENSITIVE_KEY_PATTERN: Final[str] = r"""
(?:[A-Z0-9]+[_.-])*
(?:
    API[_.\-\s]*KEY
  | SECRET[_.\-\s]*ACCESS[_.\-\s]*KEY
  | ACCESS[_.\-\s]*(?:KEY|TOKEN)
  | AUTH(?:ENTICATION)?[_.\-\s]*TOKEN
  | REFRESH[_.\-\s]*TOKEN
  | ID[_.\-\s]*TOKEN
  | SESSION[_.\-\s]*TOKEN
  | BEARER[_.\-\s]*TOKEN
  | CLIENT[_.\-\s]*SECRET
  | CONSUMER[_.\-\s]*SECRET
  | SIGNING[_.\-\s]*SECRET
  | WEBHOOK[_.\-\s]*SECRET
  | PRIVATE[_.\-\s]*KEY
  | SECRET[_.\-\s]*KEY
  | CONNECTION[_.\-\s]*STRING
  | DATABASE[_.\-\s]*(?:URL|URI)
  | PASSWORD
  | PASSPHRASE
  | PASSWD
  | CREDENTIALS?
  | TOKEN
  | SECRET
)
(?:[_.-](?:DEV|TEST|STAGING|PROD|PRODUCTION))?
"""

_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    rf"""
    (?<![A-Z0-9_?&#])
    (?P<prefix>
        (?:(?:export|set)\s+)?
        (?:\$env:)?
        ["']?
        {_SENSITIVE_KEY_PATTERN}
        ["']?
        \s*(?::=|=>|:|=)\s*
    )
    (?P<value>.*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_AUTHORIZATION_PATTERN = re.compile(
    r"""
    (?P<prefix>
        (?<![A-Z0-9_-])
        (?:proxy[_.\-\s]*)?authorization\s*:\s*
        (?:(?:bearer|basic|token|api[_.-]?key)\s+)?
    )
    (?P<value>.*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SECRET_HEADER_PATTERN = re.compile(
    r"""
    (?P<prefix>
        (?<![A-Z0-9_-])
        (?:x[_.-])?
        (?:api[_.-]?key|auth[_.-]?token|access[_.-]?token|session[_.-]?token)
        \s*:\s*
    )
    (?P<value>.*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_COOKIE_HEADER_PATTERN = re.compile(
    r"""
    (?P<prefix>
        (?<![A-Z0-9_-])
        (?:set[_.-])?cookie\s*:\s*
    )
    (?P<value>.*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_CLI_SECRET_OPTION_PATTERN = re.compile(
    rf"""
    (?P<prefix>
        (?<![A-Z0-9_-])
        --{_SENSITIVE_KEY_PATTERN}
        (?:\s*=\s*|\s+)
    )
    (?P<value>.*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_URL_CREDENTIAL_PATTERN = re.compile(
    r"(?P<prefix>://[^/\s:@]+:)(?P<value>[^@\s/]+)(?P<suffix>@)",
    re.IGNORECASE,
)
_URL_SECRET_PARAMETER_PATTERN = re.compile(
    rf"""
    (?P<prefix>
        [?&#;]
        {_SENSITIVE_KEY_PATTERN}
        \s*=\s*
    )
    (?P<value>[^&#;\s]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"""
    -----BEGIN\s+
    (?P<label>[A-Z0-9 -]*PRIVATE[_.\-\s]*KEY[A-Z0-9 -]*)
    -----
    .*?
    -----END\s+(?P=label)-----
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
_PRIVATE_KEY_BEGIN_PATTERN = re.compile(
    r"""
    -----BEGIN\s+
    [A-Z0-9 -]*PRIVATE[_.\-\s]*KEY[A-Z0-9 -]*
    -----
    """,
    re.IGNORECASE | re.VERBOSE,
)

_CONTEXT_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    _SENSITIVE_ASSIGNMENT_PATTERN,
    _AUTHORIZATION_PATTERN,
    _SECRET_HEADER_PATTERN,
    _COOKIE_HEADER_PATTERN,
    _CLI_SECRET_OPTION_PATTERN,
)
_EXACT_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    _URL_CREDENTIAL_PATTERN,
    _URL_SECRET_PARAMETER_PATTERN,
)
_KNOWN_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b"),
    re.compile(r"\bsk-(?:(?:proj|svcacct|ant)-)?[A-Za-z0-9_-]{12,255}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{20,255}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_MULTILINE_VALUE_MARKERS: Final[frozenset[str]] = frozenset(
    {
        "",
        "|",
        "|-",
        "|+",
        ">",
        ">-",
        ">+",
        "\\",
        "{",
        "[",
        '"""',
        "'''",
        '"',
        "'",
    }
)


class SecretRedactor:
    """Remove common credential forms without retaining secret values."""

    def redact(self, text: str) -> str:
        """Return deterministic redacted text while preserving safe line endings."""

        private_key_safe = _redact_private_key_material(text)
        rendered: list[str] = []
        for line in private_key_safe.splitlines(keepends=True):
            body, ending = _split_line_ending(line)
            redacted_body, redact_remaining = _redact_line(body)
            rendered.append(redacted_body + ending)
            if redact_remaining:
                break
        if not rendered and private_key_safe:
            redacted_body, _ = _redact_line(private_key_safe)
            return redacted_body
        return "".join(rendered)


def escape_untrusted_text(text: str) -> str:
    """Escape terminal controls, bidi/zero-width format chars, and backslashes."""

    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif unicodedata.category(character) in _UNSAFE_UNICODE_CATEGORIES:
            if codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def sanitize_untrusted_text(
    text: str,
    *,
    redactor: SecretRedactor | None = None,
) -> str:
    """Redact secrets first, then escape output-significant characters."""

    effective_redactor = redactor if redactor is not None else SecretRedactor()
    return escape_untrusted_text(effective_redactor.redact(text))


def _redact_private_key_material(text: str) -> str:
    shadow, mapping = _detection_view(text)
    complete_spans = [
        _original_span(mapping, *match.span())
        for match in _PRIVATE_KEY_BLOCK_PATTERN.finditer(shadow)
    ]
    spans = list(complete_spans)
    final_ending = _final_line_ending(text)
    safe_end = len(text) - len(final_ending)
    for match in _PRIVATE_KEY_BEGIN_PATTERN.finditer(shadow):
        start, _ = _original_span(mapping, *match.span())
        if any(
            existing_start <= start < existing_end
            for existing_start, existing_end in complete_spans
        ):
            continue
        spans.append((start, safe_end))
    return _apply_redactions(text, spans)


def _redact_line(body: str) -> tuple[str, bool]:
    shadow, mapping = _detection_view(body)
    spans: list[tuple[int, int]] = []

    for pattern in _CONTEXT_VALUE_PATTERNS:
        for match in pattern.finditer(shadow):
            value = match.group("value")
            if _requires_remaining_redaction(value):
                prefix_end = _original_end(mapping, match.end("prefix"), len(body))
                return body[:prefix_end] + _REDACTED, True
            spans.append(_original_span(mapping, *match.span("value")))

    for pattern in _EXACT_VALUE_PATTERNS:
        for match in pattern.finditer(shadow):
            if match.start("value") != match.end("value"):
                spans.append(_original_span(mapping, *match.span("value")))

    for pattern in _KNOWN_SECRET_PATTERNS:
        spans.extend(
            _original_span(mapping, *match.span()) for match in pattern.finditer(shadow)
        )

    return _apply_redactions(body, spans), False


def _requires_remaining_redaction(value: str) -> bool:
    stripped = value.strip()
    if stripped in _MULTILINE_VALUE_MARKERS:
        return True
    if stripped.startswith(("|", ">")):
        return True
    if stripped.endswith(("\\", "{", "[")):
        return True
    for quote in ('"""', "'''"):
        if stripped.startswith(quote) and stripped.count(quote) < 2:
            return True
    for quote in ('"', "'"):
        if stripped.startswith(quote) and not stripped.endswith(quote):
            return True
    return False


def _detection_view(text: str) -> tuple[str, tuple[int, ...]]:
    characters: list[str] = []
    original_indexes: list[int] = []
    for index, character in enumerate(text):
        if unicodedata.category(character) in _UNSAFE_UNICODE_CATEGORIES:
            continue
        for normalized in unicodedata.normalize("NFKC", character):
            if unicodedata.category(normalized) in _UNSAFE_UNICODE_CATEGORIES:
                continue
            characters.append(normalized)
            original_indexes.append(index)
    return "".join(characters), tuple(original_indexes)


def _original_span(
    mapping: tuple[int, ...],
    start: int,
    end: int,
) -> tuple[int, int]:
    if start >= end or not mapping:
        raise ValueError("redaction span must contain detected text")
    return mapping[start], mapping[end - 1] + 1


def _original_end(
    mapping: tuple[int, ...],
    normalized_end: int,
    original_length: int,
) -> int:
    if normalized_end <= 0 or not mapping:
        return 0
    if normalized_end > len(mapping):
        return original_length
    return mapping[normalized_end - 1] + 1


def _apply_redactions(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if start >= end:
            continue
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    rendered = text
    for start, end in reversed(merged):
        rendered = rendered[:start] + _REDACTED + rendered[end:]
    return rendered


def _split_line_ending(text: str) -> tuple[str, str]:
    for ending in _LINE_ENDINGS:
        if text.endswith(ending):
            return text[: -len(ending)], ending
    return text, ""


def _final_line_ending(text: str) -> str:
    _, ending = _split_line_ending(text)
    return ending

"""Security regression tests for P1-26 hardened secret redaction."""

from __future__ import annotations

import pytest

from agentsec.reporting import SecretRedactor, sanitize_untrusted_text


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'export OPENAI_API_KEY = "short-value"\n',
            "export OPENAI_API_KEY = <redacted>\n",
        ),
        ("$env:CLIENT_SECRET = 'x'\n", "$env:CLIENT_SECRET = <redacted>\n"),
        ("process.env.ACCESS_TOKEN=low\n", "process.env.ACCESS_TOKEN=<redacted>\n"),
        (
            "DATABASE_URL=postgres://user:pass@example.invalid/db\n",
            "DATABASE_URL=<redacted>\n",
        ),
        ('"refresh_token": "refresh-value",\n', '"refresh_token": <redacted>\n'),
        ("credential: credential-value\n", "credential: <redacted>\n"),
        ("password := p\n", "password := <redacted>\n"),
    ],
)
def test_sensitive_assignments_redact_values_regardless_of_length(
    source: str,
    expected: str,
) -> None:
    """Contextual key names protect short and non-token-shaped credentials."""

    assert SecretRedactor().redact(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "Proxy-Authorization: Basic dXNlcjpwYXNz\n",
            "Proxy-Authorization: Basic <redacted>\n",
        ),
        ("X-API-Key: key-value\n", "X-API-Key: <redacted>\n"),
        ("X-Auth-Token: auth-value\n", "X-Auth-Token: <redacted>\n"),
        ("Cookie: session=session-value\n", "Cookie: <redacted>\n"),
        ("Set-Cookie: session=session-value\n", "Set-Cookie: <redacted>\n"),
        (
            "curl --client-secret cli-value --verbose\n",
            "curl --client-secret <redacted>\n",
        ),
        (
            "https://user:url-password@example.invalid/path\n",
            "https://user:<redacted>@example.invalid/path\n",
        ),
        (
            "https://example.invalid/hook?access_token=query-value&mode=test\n",
            "https://example.invalid/hook?access_token=<redacted>&mode=test\n",
        ),
    ],
)
def test_headers_cli_options_and_url_credentials_are_redacted(
    source: str,
    expected: str,
) -> None:
    """Common transport contexts do not require a known provider token shape."""

    assert SecretRedactor().redact(source) == expected


def test_zero_width_controls_and_fullwidth_keys_cannot_bypass_detection() -> None:
    """A normalized detection view maps replacements back to original text."""

    first_secret = "zero-width-value"
    second_secret = "control-value"
    third_secret = "fullwidth-value"
    source = (
        f"TO\u200bKEN={first_secret}\n"
        f"A\x1bPI_KEY={second_secret}\n"
        f"ＴＯＫＥＮ＝{third_secret}\n"
    )

    redacted = SecretRedactor().redact(source)
    sanitized = sanitize_untrusted_text(source)

    for secret in (first_secret, second_secret, third_secret):
        assert secret not in redacted
        assert secret not in sanitized
    assert redacted == (
        "TO\u200bKEN=<redacted>\nA\x1bPI_KEY=<redacted>\nＴＯＫＥＮ＝<redacted>\n"
    )
    assert "\\u200b" in sanitized
    assert "\\u001b" in sanitized


def test_provider_and_structured_token_shapes_are_redacted_without_context() -> None:
    """Recognized provider tokens and JWTs are removed wherever they appear."""

    tokens = (
        "AKIA" + "A" * 16,
        "ghp_" + "B" * 30,
        "github_pat_" + "C" * 30,
        "glpat-" + "D" * 30,
        "xoxb-" + "E" * 24,
        "sk_live_" + "F" * 24,
        "sk-proj-" + "G" * 24,
        "AIza" + "H" * 35,
        "npm_" + "I" * 24,
        "pypi-" + "J" * 24,
        "eyJ" + "K" * 10 + "." + "L" * 12 + "." + "M" * 12,
    )
    source = "prefix " + " middle ".join(tokens) + " suffix\n"

    redacted = SecretRedactor().redact(source)

    for token in tokens:
        assert token not in redacted
    assert redacted.startswith("prefix <redacted>")
    assert redacted.endswith("<redacted> suffix\n")


def test_complete_and_unterminated_private_key_material_fail_closed() -> None:
    """Private key bodies never survive complete or malformed PEM-style blocks."""

    complete_body = "private-line-one\nprivate-line-two"
    complete = (
        "before\n"
        "-----BEGIN PRIVATE KEY-----\n"
        f"{complete_body}\n"
        "-----END PRIVATE KEY-----\n"
        "after\n"
    )
    unterminated_body = "unterminated-private-material"
    unterminated = (
        "before\n"
        "-----BEGIN OPENSSH PRIVATE\u200bKEY-----\n"
        f"{unterminated_body}\n"
        "still-private\n"
    )

    complete_redacted = SecretRedactor().redact(complete)
    unterminated_redacted = SecretRedactor().redact(unterminated)

    assert complete_redacted == "before\n<redacted>\nafter\n"
    assert complete_body not in complete_redacted
    assert unterminated_redacted == "before\n<redacted>\n"
    assert unterminated_body not in unterminated_redacted
    assert "still-private" not in unterminated_redacted


@pytest.mark.parametrize(
    "source",
    [
        "token: |\n  yaml-secret\nnext: safe\n",
        'password = """\nmultiline-secret\n"""\nafter\n',
        "--access-token \\\ncontinued-secret\nafter\n",
        "Authorization: Bearer \ncontinued-secret\nafter\n",
    ],
)
def test_multiline_sensitive_values_redact_the_remaining_input(source: str) -> None:
    """Ambiguous continuation syntax fails closed instead of leaking later lines."""

    redacted = SecretRedactor().redact(source)

    assert redacted.endswith("<redacted>\n")
    assert "secret" not in redacted
    assert "after" not in redacted
    assert "next: safe" not in redacted


def test_unicode_line_separators_are_preserved_then_escaped() -> None:
    """Unicode line separators cannot hide a following secret or split output."""

    source = "token=first-value\u2028password=second-value\u2029"

    redacted = SecretRedactor().redact(source)
    sanitized = sanitize_untrusted_text(source)

    assert redacted == "token=<redacted>\u2028password=<redacted>\u2029"
    assert sanitized == "token=<redacted>\\u2028password=<redacted>\\u2029"
    assert "first-value" not in sanitized
    assert "second-value" not in sanitized


def test_redaction_is_idempotent_and_preserves_mixed_line_endings() -> None:
    """Repeated rendering is stable and does not normalize safe line separators."""

    source = "token=first\r\nX-API-Key: second\rpassword=third\n"
    redactor = SecretRedactor()

    first = redactor.redact(source)
    second = redactor.redact(first)

    assert first == "token=<redacted>\r\nX-API-Key: <redacted>\rpassword=<redacted>\n"
    assert second == first


def test_non_secret_security_documentation_is_not_over_redacted() -> None:
    """Names, counts, policies, hashes, and public keys remain reviewable."""

    sha256 = "a" * 64
    source = (
        "token_count=5\n"
        "password_policy: strong\n"
        "api_key_name: OPENAI_API_KEY\n"
        "Authorization is required for production.\n"
        f"sha256={sha256}\n"
        "-----BEGIN PUBLIC KEY-----\n"
        "PUBLIC-MATERIAL\n"
        "-----END PUBLIC KEY-----\n"
    )

    assert SecretRedactor().redact(source) == source

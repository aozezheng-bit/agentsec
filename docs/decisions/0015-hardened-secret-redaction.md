# ADR-0015: Hardened Deterministic Secret Redaction

- Status: Accepted
- Date: 2026-08-19
- Task: P1-26

## Context

Phase 1 requires that reports never expose full secret values. P1-16, P1-24,
and P1-25 already route Diff Text/JSON and Assessment Text/JSON through one
`SecretRedactor`, but its initial implementation was intentionally narrow.

The initial redactor processed an input mostly as one line and could miss:

- a sensitive assignment embedded in multiline text;
- zero-width or control characters inserted into a key name;
- fullwidth key names or delimiters;
- provider tokens not covered by the original small pattern set;
- API-key, cookie, Proxy-Authorization, CLI-option, and URL-query contexts;
- complete or unterminated multiline private-key material;
- YAML, shell, or quoted multiline values whose secret appeared on a later line;
- Unicode line and paragraph separators that could affect output consumers.

Matching after output escaping would preserve disguised secret bytes. Mutating
text into a normalized representation before rendering would destroy useful
source context and make Evidence harder to review.

## Decision

Adopt these P1-26 decisions:

1. Keep one shared `SecretRedactor` for Diff Text, Diff JSON, Assessment Text,
   and Assessment JSON.
2. Keep the public `redact(text) -> str` and
   `sanitize_untrusted_text(text) -> str` interfaces unchanged.
3. Build an internal detection view using Unicode NFKC normalization.
4. Remove control, format, surrogate, line-separator, and paragraph-separator
   characters from the detection view so they cannot split a sensitive key or
   token.
5. Retain an index mapping from each normalized detection character to its
   original source position.
6. Detect on the normalized view but replace spans in the original text. This
   preserves safe prefixes, source spelling, and line endings while removing
   the actual secret-bearing range.
7. Process normal secret contexts one physical line at a time and preserve LF,
   CRLF, CR, NEL, vertical-tab, form-feed, file/group/record separators, and
   Unicode line/paragraph separators until output escaping.
8. Redact exact or vendor-prefixed sensitive assignments for API keys, access
   keys/tokens, authentication/refresh/ID/session/bearer tokens, client,
   consumer, signing and webhook secrets, private/secret keys, connection
   strings, database URLs, passwords, passphrases, credentials, generic tokens,
   and generic secrets.
9. Support assignment forms used by environment variables, JSON, YAML, shell,
   PowerShell, and common programming-language expressions, including quoted
   keys, `export`, `set`, `$env:`, namespace prefixes, `=`, `:`, `:=`, and `=>`.
10. Redact Authorization and Proxy-Authorization values, API/auth/access/session
    headers, Cookie and Set-Cookie values, sensitive long CLI options, URL
    user-info passwords, and sensitive URL query/fragment parameters.
11. Redact recognized standalone AWS access-key IDs, GitHub tokens, GitLab
    tokens, Slack tokens, Stripe-style keys, OpenAI/Anthropic-style keys, Google
    API keys, npm tokens, PyPI tokens, and JWT-shaped values.
12. Redact complete private-key blocks as one placeholder.
13. Treat an unclosed private-key begin marker as sensitive through the end of
    the input.
14. Fail closed for an assignment, header, or CLI option whose value begins a
    multiline or ambiguous continuation. Keep the safe key/prefix, emit one
    placeholder, and omit the remaining input value.
15. Merge overlapping secret spans and replace each merged range with the fixed
    literal `<redacted>`.
16. Make redaction idempotent: redacting already-redacted output produces the
    same result.
17. Preserve hashes, counts, policy names, public-key blocks, and ordinary
    security documentation when they do not occur in a sensitive value context.
18. Do not use generic entropy, arbitrary Base64, or arbitrary hexadecimal
    redaction in Phase 1 because Domain reports intentionally contain SHA-256
    hashes and encoded-looking evidence indicators.
19. Continue to redact before output escaping.
20. Extend output escaping to Unicode line and paragraph separators in addition
    to existing control, format, surrogate, bidi, and zero-width characters.
21. Keep redaction deterministic and free of filesystem, environment, shell,
    network, scanned import, Skill, MCP, randomness, or LLM dependencies.
22. Do not return the detected secret, a secret hash, a partial prefix/suffix,
    entropy score, provider account identifier, or reversible token.
23. Keep Config Schema, Domain Schema, Baseline Schema, Diff Output, Assessment
    Output, Rule Pack, and Risk Model versions unchanged. P1-26 hardens the
    existing “never output full secrets” contract without changing serialized
    structure, rule meaning, score meaning, or policy meaning.

## Consequences

### Positive

- All current report formats share one stronger and testable safety boundary.
- Zero-width, control-character, and fullwidth-key evasions no longer preserve
  the secret value.
- Multiline private keys and ambiguous multiline assignments fail closed.
- Short credentials are protected when a trusted context identifies them as a
  secret, without requiring a high-entropy token shape.
- Known provider tokens can be removed even when no key name is present.
- Original safe prefixes and line endings remain useful for review.
- Fixed placeholders reveal neither secret length nor retained prefix/suffix.
- Idempotence supports repeated rendering and downstream sanitization.

### Negative

- Contextual redaction intentionally over-matches some benign values, especially
  cookies, credential assignments, and ambiguous multiline content.
- A fail-closed multiline match may omit safe text after the sensitive key.
- Provider pattern lists will never cover every proprietary secret format.
- Generic unlabelled low-entropy secrets remain impossible to identify reliably
  without excessive false positives.
- Unicode confusables from unrelated scripts are not converted into ASCII key
  names; P1-26 covers compatibility forms and invisible/control splitting, not a
  universal confusable-language engine.
- Redaction proves only that recognized output forms were removed. It does not
  prove that the scanned Agent has no secret access capability.

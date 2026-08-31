# Hardened Secret Redaction

- Task: `P1-26`
- Status: Complete
- Decision date: 2026-08-19
- Decision record: `docs/decisions/0015-hardened-secret-redaction.md`

## 1. Purpose

AgentSec treats every repository-derived report string as potentially sensitive.
P1-26 hardens the shared `SecretRedactor` used by:

```text
Diff Text Reporter
Diff JSON Reporter
Assessment Rich Text Reporter
Assessment JSON Reporter
```

The public interfaces remain:

```python
from agentsec.reporting import SecretRedactor, sanitize_untrusted_text

redacted = SecretRedactor().redact(text)
safe_output = sanitize_untrusted_text(text)
```

`redact()` removes recognized secrets while retaining safe context.
`sanitize_untrusted_text()` always performs redaction first and output escaping
second.

## 2. Detection view and source replacement

P1-26 separates detection from output:

```text
Original untrusted text
→ NFKC detection view
→ remove invisible/control/output-separator characters from detection view
→ detect sensitive spans
→ map spans back to original source positions
→ replace original spans with <redacted>
→ escape remaining output-significant characters
```

The normalized view is never returned. It is used only to prevent bypasses such
as:

```text
TO<zero-width>KEN=value
A<ESC>PI_KEY=value
ＴＯＫＥＮ＝value
```

The output preserves the original safe key spelling and line ending, but the
value is removed.

## 3. Contextual sensitive keys

The assignment detector supports exact or vendor-prefixed forms of:

```text
API_KEY
ACCESS_KEY
SECRET_ACCESS_KEY
ACCESS_TOKEN
AUTH_TOKEN
AUTHENTICATION_TOKEN
REFRESH_TOKEN
ID_TOKEN
SESSION_TOKEN
BEARER_TOKEN
CLIENT_SECRET
CONSUMER_SECRET
SIGNING_SECRET
WEBHOOK_SECRET
PRIVATE_KEY
SECRET_KEY
CONNECTION_STRING
DATABASE_URL
DATABASE_URI
PASSWORD
PASSPHRASE
PASSWD
CREDENTIAL / CREDENTIALS
TOKEN
SECRET
```

Vendor and namespace examples include:

```text
OPENAI_API_KEY
AWS_SECRET_ACCESS_KEY
process.env.ACCESS_TOKEN
$env:CLIENT_SECRET
my-service-token
```

Supported delimiters and prefixes include:

```text
export TOKEN=value
set TOKEN=value
$env:TOKEN = value
"token": "value"
token := value
token => value
```

The detector does not redact suffix-only documentation names such as:

```text
token_count
password_policy
api_key_name
```

## 4. Transport contexts

P1-26 redacts values in:

- `Authorization` and `Proxy-Authorization` headers;
- API-key, auth-token, access-token, and session-token headers;
- `Cookie` and `Set-Cookie` headers;
- sensitive long CLI options such as `--token` and `--client-secret`;
- URL user-info passwords such as `https://user:password@host`;
- sensitive URL query and fragment parameters.

The key or header remains visible where safe, while its value becomes:

```text
<redacted>
```

## 5. Recognized standalone token shapes

Without requiring an assignment key, P1-26 recognizes common shapes for:

- AWS access-key IDs;
- GitHub classic and fine-grained tokens;
- GitLab personal-access tokens;
- Slack tokens;
- Stripe-style secret/restricted keys;
- OpenAI/Anthropic-style secret keys;
- Google API keys;
- npm tokens;
- PyPI tokens;
- JWT-shaped values.

Fixtures use synthetic values only. AgentSec tests must never include real
credentials.

P1-26 intentionally does not redact every long Base64 or hexadecimal value.
Assessment reports contain SHA-256 hashes, and obfuscation indicators may
contain encoded-looking text. Generic entropy-only replacement would destroy
important evidence and create excessive false positives.

## 6. Private keys

Complete private-key blocks are replaced as one value:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

This includes prefixed labels such as RSA, EC, OpenSSH, encrypted, or test-only
private-key blocks.

If a private-key begin marker is present without a matching end marker, AgentSec
redacts from the marker through the end of the input. It never prints the
unterminated material while attempting recovery.

Public-key blocks are not private-key matches and remain visible.

## 7. Multiline fail-closed behavior

Sensitive values may begin with YAML blocks, shell continuations, object/list
openers, or unterminated quotes:

```text
token: |
  value

password = """
value
"""

--access-token \
value
```

When a sensitive context begins an ambiguous multiline value, the redactor:

1. retains the safe key or option prefix;
2. emits `<redacted>`;
3. omits the remaining input value.

This may hide later benign text, but it prevents a multiline secret from leaking
through a format the output layer does not parse.

## 8. Line endings and output escaping

Redaction preserves recognized line separators until escaping:

```text
LF
CRLF
CR
vertical tab
form feed
file/group/record separators
NEL
Unicode line separator U+2028
Unicode paragraph separator U+2029
```

`sanitize_untrusted_text()` renders output-significant characters as visible
escapes, including:

```text
\n
\r
\t
\u001b
\u200b
\u2028
\u2029
```

This keeps terminal and JSON output from interpreting source-controlled layout
or control data.

## 9. Determinism and idempotence

For identical input and implementation version:

```text
redact(input) == redact(input)
redact(redact(input)) == redact(input)
```

Overlapping matches are merged before replacement. The placeholder is fixed and
does not expose original length, a hash, prefix, suffix, or provider account.

The redactor performs no filesystem reads, environment inspection, shell
execution, network access, scanned imports, Skill/MCP calls, randomness, or LLM
analysis.

## 10. Version decision

P1-26 changes no serialized structure or risk meaning:

```text
CONFIG_SCHEMA_VERSION = 0.1.0
DOMAIN_SCHEMA_VERSION = 0.3.0
BASELINE_SCHEMA_VERSION = 0.1.0
DIFF_OUTPUT_VERSION = 0.1.0
ASSESSMENT_OUTPUT_VERSION = 0.1.0
RULE_PACK_VERSION = 0.2.0
RISK_MODEL_VERSION = 0.4.0
```

The change is a security hardening of the existing invariant that reports do not
output full secret values.

P1-27 later increments Assessment Output to `0.2.0` for required Coverage summary
fields; this does not change P1-26 redaction semantics.

## 11. Residual limitations

The redactor cannot reliably identify every possible secret. In particular:

- an unlabelled low-entropy value may look like ordinary text;
- proprietary provider formats may be unknown;
- a secret split using cross-script homoglyphs may not normalize to the expected
  ASCII key;
- encrypted or transformed values may not match a known shape;
- a benign value in a sensitive context may be intentionally over-redacted.

Upstream code must still avoid placing unnecessary source content in Findings,
errors, or logs. P1-26 is defense in depth, not permission to retain arbitrary
repository text.

## 12. Verification coverage

P1-26 tests cover:

- vendor-prefixed and namespace-prefixed assignments;
- short values identified only by context;
- JSON, YAML, shell, PowerShell, and expression delimiters;
- Authorization, Proxy-Authorization, API headers, cookies, CLI options, URL
  user-info, and URL parameters;
- zero-width, ANSI/control, and fullwidth-key bypass attempts;
- AWS, GitHub, GitLab, Slack, Stripe, OpenAI/Anthropic, Google, npm, PyPI, and JWT
  token shapes;
- complete and unterminated private-key blocks;
- multiline YAML, quoted, shell-continuation, and header values;
- LF, CRLF, CR, and Unicode separator preservation and escaping;
- idempotence;
- safe non-secret hashes, counters, policy names, and public keys;
- shared hardened behavior in Diff Text and JSON;
- existing Assessment Text and JSON secret-safety regressions.

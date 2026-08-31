# ADR-0019: Static `.rules` and MCP Specialized Parsers

- Status: Accepted
- Date: 2026-08-20
- Task: P2-02

## Context

P2-01 normalizes JSON, YAML, and TOML syntax but intentionally assigns no
framework meaning. P2-02 needs two specialized interpretations used by current
Codex projects:

1. `.rules` files contain experimental `prefix_rule(...)` declarations for
   command decisions and optional inline examples.
2. Codex MCP configuration uses `mcp_servers` tables for STDIO, Streamable HTTP,
   and plugin-bundled server declarations, environment references, authentication,
   tool filters, approval modes, and timeouts.

Both inputs are untrusted. Evaluating `.rules` as Python/Starlark, expanding
variables, launching a configured MCP command, resolving a URL, or copying
static secret/header values into a general report would violate AgentSec's
non-execution and secret-handling invariants.

Official syntax references reviewed for this decision:

```text
https://developers.openai.com/codex/rules
https://developers.openai.com/codex/mcp
https://developers.openai.com/codex/config-reference
```

## Decision

### `.rules` Parser

Create `PrefixRulesParser` with a data-only interface:

```python
ParsedRulesDocument = parser.parse(content)
```

The implementation uses Python AST parsing only as a tokenizer/tree builder. It
never compiles or executes the AST. Accept exactly top-level calls of:

```text
prefix_rule(
    pattern=[literal strings or literal string-union lists],
    decision="allow" | "prompt" | "forbidden",
    justification="optional literal",
    match=[optional literal command examples],
    not_match=[optional literal command examples],
)
```

Reject imports, assignments, variables, positional arguments, unknown calls,
attributes, comprehensions, f-strings, nested calls, unpacking, and every
non-literal expression. Preserve declaration and field line ranges. Default an
omitted decision to `allow`, matching the documented rule semantics.

Inline `match` and `not_match` values are retained as inert test strings. The
Parser does not evaluate whether a command matches; that belongs to a later
policy module.

### MCP Parser

Create `McpConfigurationParser` over a P2-01 `StructuredDocument`. Recognize:

```text
mcp_servers.<server>
plugins.<plugin>.mcp_servers.<server>
```

Extract static declarations for:

- STDIO `command`, `args`, `cwd`, and environment names/references;
- Streamable HTTP sanitized endpoint, bearer-token environment name, auth mode,
  OAuth resource/scopes, static header names, and environment-backed headers;
- enabled/required state;
- enabled/disabled tools;
- startup and tool timeouts;
- default and per-tool approval mode;
- experimental environment selection;
- plugin-bundled server declarations;
- unknown direct server fields with source locations but without copied values.

Transport is inferred deterministically:

```text
command only  → stdio
url only      → streamable_http
plugin bundled with neither → plugin_bundled
command + url → conflicting_fields
```

The endpoint model omits username/password, query values, and fragments. It
retains only scheme, lowercased host, optional port, path, a boolean indicating
query/fragment presence, and whether the host is local. No DNS or HTTP request is
performed.

Static `env` and `http_headers` values are intentionally omitted from the MCP
specialized model; only their names and source locations are retained. Exact
arguments and other values are wrapped in `SourceBackedValue` with `repr=False`
to prevent accidental logging, but downstream reporting must still apply the
shared redaction policy.

### Limits and errors

Both Parsers enforce trusted limits and expose stable safe error codes without
copying source text. `.rules` limits cover source characters, declarations,
pattern elements, examples, and literal length. MCP limits cover server count,
list items, and map entries.

Neither Parser receives a filesystem path, environment accessor, command runner,
network client, MCP client, model client, Skill, Hook, or plugin loader.

## Version impact

P2-02 adds Python-only specialized declaration models. It does not change the
AgentSec production Rule Pack; Codex `.rules` declarations are scanned input,
not AgentSec detector implementations. No new fields are serialized into Domain,
Baseline, Diff, or Assessment output.

```text
CONFIG_SCHEMA_VERSION       unchanged
DOMAIN_SCHEMA_VERSION       unchanged
BASELINE_SCHEMA_VERSION     unchanged
DIFF_OUTPUT_VERSION         unchanged
ASSESSMENT_OUTPUT_VERSION   unchanged
RULE_PACK_VERSION           unchanged at 0.3.0
RISK_MODEL_VERSION          unchanged
```

Collector integration, new Asset types, serialized Agent Manifest fields, or
policy enforcement require later Version Impact Review.

## Consequences

### Positive

- Codex Rules and MCP declarations become source-backed inert facts.
- Prompt-like or executable expressions in `.rules` cannot gain control.
- MCP commands and endpoints are never launched or contacted.
- Static secret/header values are not copied into the specialized MCP model.
- Unknown server fields remain visible for forward compatibility.
- Later Framework Adapters receive typed declarations rather than raw parser
  library objects.

### Negative

- `.rules` support intentionally accepts only the current literal
  `prefix_rule(...)` subset and rejects broader Starlark/Python syntax.
- Inline rule examples are parsed but not semantically validated in P2-02.
- MCP static arguments remain available internally and may contain sensitive
  values; all later serialization must redact them.
- Static HTTP header values are omitted, so later capability logic knows a
  header exists but not its literal content.
- P2-02 does not discover `.rules` or `config.toml` files and does not make them
  visible to `agentsec scan` yet.

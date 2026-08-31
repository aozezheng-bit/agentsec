# AgentSec Rules and MCP Specialized Parsers

- Task: `P2-02`
- Status: Complete
- Decision date: 2026-08-20
- Decision: `docs/decisions/0019-static-rules-and-mcp-parsers.md`

## 1. Purpose

P2-02 interprets two security-relevant configuration shapes without executing
or connecting to them:

- Codex `.rules` `prefix_rule(...)` declarations;
- Codex `mcp_servers` configuration normalized by P2-01.

P2-02 is still Parser-only. File discovery and `agentsec scan` integration are
part of later Framework Adapter tasks.

## 2. `.rules` usage

```python
from agentsec.parsers import PrefixRulesParser

rules = PrefixRulesParser().parse(
    """
    prefix_rule(
        pattern=["gh", ["pr", "issue"], "view"],
        decision="prompt",
        justification="Remote access requires review.",
        match=["gh pr view 123"],
        not_match=["gh repo view"],
    )
    """
)
```

The result retains:

```text
pattern
allow / prompt / forbidden decision
optional justification
optional match examples
optional non-match examples
field and declaration line ranges
```

An omitted decision becomes `allow`.

## 3. `.rules` security policy

The Parser uses `ast.parse` only to construct an inert syntax tree. It rejects:

```text
import
assignment
variable references
function results
attributes
comprehensions
f-strings
positional arguments
**unpacking
unknown function calls
non-literal patterns or examples
```

For example, this expression is rejected and never executed:

```python
prefix_rule(pattern=[__import__("os").system("touch marker")])
```

P2-02 does not decide whether an arbitrary command matches a declaration. It
only parses the declaration and inline test strings.

## 4. MCP usage

```python
from agentsec.parsers import McpConfigurationParser, TomlStructuredParser

document = TomlStructuredParser().parse(config_toml)
mcp = McpConfigurationParser().parse(document)
```

Recognized roots:

```text
mcp_servers.<server>
plugins.<plugin>.mcp_servers.<server>
```

## 5. STDIO declarations

Representative input:

```toml
[mcp_servers.docs]
command = "npx"
args = ["-y", "@example/docs-server"]
cwd = "/workspace"
enabled = true
required = false
env = { EXAMPLE_TOKEN = "sensitive literal" }
env_vars = ["HOME", { name = "REMOTE_TOKEN", source = "remote" }]
```

The Parser records command, arguments, working directory, control state,
environment names, and source lines. It never runs `npx`, reads `HOME`, or copies
the static environment value into `McpServerDeclaration`.

## 6. Streamable HTTP declarations

Representative input:

```toml
[mcp_servers.api]
url = "https://api.example.invalid/mcp?token=sensitive"
bearer_token_env_var = "MCP_BEARER_TOKEN"
auth = "oauth"
scopes = ["tools.read"]
http_headers = { "X-Static-Key" = "sensitive literal" }
env_http_headers = { "Authorization" = "MCP_AUTH_HEADER" }
```

The endpoint output retains:

```text
scheme
host
optional port
path
query_or_fragment_present boolean
is_local boolean
```

It omits URL credentials, query values, and fragments and performs no DNS or
network request. Static header values are omitted; header names and
environment-variable references remain source-backed.

## 7. Tool and approval policy

Recognized controls include:

```text
enabled_tools
disabled_tools
default_tools_approval_mode
tools.<tool>.approval_mode
enabled
required
startup_timeout_sec / startup_timeout_ms
tool_timeout_sec / tool_timeout_ms
experimental_environment
```

Timeout aliases are normalized to seconds. Defining both second and millisecond
forms for the same timeout is a conflict.

## 8. Plugin-bundled MCP

A server under:

```text
plugins.<plugin>.mcp_servers.<server>
```

may omit `command` and `url`; it is represented as `plugin_bundled`. The Parser
does not load or install the plugin.

## 9. Unknown fields

Unknown direct server fields are retained as:

```text
path
start_line
end_line
```

Their values are not copied. This allows later adapters to report incomplete or
unknown interpretation without exposing a new sensitive field.

## 10. Limits and failure codes

`.rules` failures include:

```text
malformed
unsupported_statement
unsupported_expression
duplicate_field
unknown_field
missing_pattern
invalid_pattern
invalid_decision
limit_exceeded
```

MCP failures include:

```text
invalid_root
invalid_server
invalid_field
conflicting_fields
missing_transport
invalid_endpoint
limit_exceeded
```

Error strings contain only stable codes and optional line numbers.

## 11. Official syntax references

- `https://developers.openai.com/codex/rules`
- `https://developers.openai.com/codex/mcp`
- `https://developers.openai.com/codex/config-reference`

These references define current Codex syntax. AgentSec retains its own stricter
non-execution, secret-handling, resource, provenance, and versioning policy.

## 12. Current integration boundary

P2-02 does not yet:

- discover `.rules` files;
- discover user or project `config.toml`;
- enumerate real MCP tools;
- connect to a server;
- evaluate command-prefix policy;
- create Agent Manifest records;
- assign capability risk;
- emit these declarations in Text/JSON reports;
- change CI policy.

P2-03 defines the Framework Adapter interface. P2-04 now uses that interface to
locate Codex Agent, Skill, Rules, and MCP assets and bind these parser outputs to
portable project/user provenance. See `docs/codex-adapter.md`.

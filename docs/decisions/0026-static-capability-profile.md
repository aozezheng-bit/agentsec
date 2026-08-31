# ADR-0026: Static Permission, Control, and Runtime Identity Extraction

- Status: Accepted
- Date: 2026-08-20
- Task: P2-09
- Agent Manifest Schema: `0.3.0` (unchanged)

## Context

P2-08 creates a source-backed inventory of Skills, MCP servers, and static MCP
tool declarations. The project now needs a first Capability Profile that
separates three concepts:

1. a static permission declaration or potential side effect;
2. a configured guardrail or approval control;
3. a credential-free runtime identity hypothesis.

The profile must remain useful for security review without claiming that a
process has started, that a permission is effective, or that an environment
variable contains a usable credential.

## Decision

### 1. Extraction boundary

Add:

```python
CapabilityExtractor.extract(manifest, inspection) -> AgentManifest
```

The extractor first verifies/refreshes P2-08 associations from the same
`FrameworkInspectionResult`, then consumes only parser-backed normalized facts.
It never reads files a second time, executes commands, contacts MCP, reads
environment values, or calls an LLM.

### 2. Permission mapping

Every known static `ManifestTool.side_effects` value becomes a permission fact.
The permission effect is `unknown` unless an explicit `.rules` decision provides
an allow/prompt/deny effect. Availability remains a separate Tool field and is
not converted into an authorization effect.

| Tool side effect | Permission action | Resource |
|---|---|---|
| `read` | `read` | `tool` |
| `write` | `write` | `tool` |
| `execute` on MCP server | `execute` | `shell` |
| `network` | `network` | `network` |
| `secret_access` | `secret_access` | `secret_store` |
| `privileged` | `admin` | `other` |
| `destructive` / `unknown` | `unknown` | `tool` |

For Streamable HTTP servers, non-local sanitized endpoints produce
`resource_scope=external`; local endpoints remain `unknown` rather than being
mistaken for a project authorization boundary.

Static MCP environment/header references add an `environment`/
`secret_access` permission with unknown effect. The value of the variable or
header is never read or stored.

### 3. Prefix Rules

Each parsed `.rules` declaration creates:

```text
permission.action   = execute
permission.resource = shell
permission.effect   = allow / prompt / deny
control.kind        = prefix_rule
control.state       = allow / prompt / deny
```

The rule target is a stable hash of the portable source identity and rule index;
patterns and justifications are not copied into the Manifest. Exact pattern and
decision field paths plus line ranges remain as provenance.

P2-09 does not evaluate a command against a prefix pattern.

### 4. MCP controls

Static MCP fields become source-backed controls:

```text
enabled / disabled / missing  → enablement control
defined required state        → required control
approval mode                 → human_approval control
enabled/disabled tool filters → tool_filter control
endpoint                     → network_policy control
timeouts                     → timeout control
environment/header references → secret_handling control
```

Missing declarations are represented as `unknown` controls where the distinction
is security-relevant. Approval modes are controls, not permission effects for
all possible tool actions. `writes` and similar conditional modes remain
conservative `prompt` controls.

### 5. Runtime identity

Each static MCP server gets a credential-free `ManifestRuntimeIdentity`:

| Evidence | Principal | Authentication |
|---|---|---|
| explicit OAuth | `oauth_session` | `oauth` |
| explicit ChatGPT auth | `chatgpt` | `chatgpt` |
| bearer token/env HTTP header reference | `api_client` | `environment` |
| plugin-bundled server | `plugin` | `unknown` |
| no reviewed auth evidence | `unknown` | `unknown` |

Operational environment is:

```text
stdio            → local
local HTTP       → local
remote HTTP      → external
plugin-bundled   → unknown
```

`privileged` remains `null` unless future reviewed evidence proves it. No
principal, token, OAuth value, cookie, header value, or environment value is
stored.

### 6. Resolution status

A profile with relevant declaration sources is:

```text
resolved → all visible facts are deterministic and no uncertainty remains
partial  → Coverage is incomplete or an unsupported/unknown fact remains
```

A relevant source with no currently recognized fact remains `partial` rather
than silently becoming `resolved` or `unknown`. Profiles with no declaration
sources preserve their existing `unknown` state.

## Security boundary

P2-09 never:

- executes a Skill, command, hook, plugin, or MCP process;
- connects to URLs or enumerates runtime MCP tools;
- reads environment-variable values, static header values, or credentials;
- evaluates Rules against a command;
- treats a static permission as an authorization grant;
- treats a runtime identity hypothesis as attestation;
- emits risk Findings, CI blocking decisions, or LLM authorization;
- imports scanned project code.

Severity, evidence confidence, and static capability facts remain separate
layers. Deterministic rules continue to own formal CI decisions.

## Version impact

P2-09 populates existing `ManifestPermission`, `ManifestControl`, and
`ManifestRuntimeIdentity` fields. No serialized field or enum is added, so:

```text
AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
```

remains unchanged.

## Consequences

### Positive

- Read/write/execute/network/secret/admin potential is visible in one stable
  source-backed model.
- Explicit `.rules` decisions remain distinguishable from inferred tool effects.
- Approval, enablement, filtering, timeout, network, and secret controls are
  auditable without runtime actions.
- Runtime identity output is useful for triage while clearly preserving
  uncertainty.

### Negative

- An unknown effect is not proof of absence or safety.
- MCP tool behavior remains unknown until a reviewed tool catalog or later
  semantic analysis is available.
- Static environment references indicate potential access, not successful
  credential resolution.
- The current Manifest remains outside the Phase 1 CLI and risk pipeline.

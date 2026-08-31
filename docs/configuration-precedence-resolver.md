# AgentSec Configuration Precedence Resolver

- Task: `P2-07`
- Status: Complete
- Agent Manifest Schema version: `0.3.0`
- Decision: `docs/decisions/0024-configuration-precedence-resolver.md`

## 1. Purpose

`ConfigurationResolver` orders static Codex configuration sources without
reading or interpreting their values.

```python
from agentsec.manifests import ConfigurationResolver

resolved_manifest = ConfigurationResolver().resolve(manifest)
```

The input Manifest remains immutable. The Resolver returns a new validated
Manifest.

## 2. Configuration kinds

A configuration candidate may carry one or more kinds:

```text
framework_config
prefix_rules
mcp_config
```

Examples:

| Source | Kinds |
|---|---|
| `.codex/config.toml` without MCP | `framework_config` |
| `.codex/config.toml` with MCP | `framework_config`, `mcp_config` |
| `.codex/rules/default.rules` | `prefix_rules` |

A source is represented once even when it has multiple kinds.

## 3. Source-level order

Configuration order is:

```text
1. User scope before Project scope
2. Lower Adapter precedence rank before higher rank
3. root_id
4. portable source path
5. chain key and configuration kinds
```

For a Project chain this normally means:

```text
Project root config/rules
nested project config/rules
```

The order describes source application precedence. It does not mean that a
higher-precedence file replaces all lower-precedence fields.

## 4. Output fields

`ManifestConfigurationProfile` contains:

```text
resolution
candidates
effective_sources
effective_order
resolution_trace
```

### `candidates`

Source-level configuration declarations with:

```text
source
kinds
precedence_rank
chain_key
```

### `effective_sources`

Canonical, unique, locator-sorted source references.

### `effective_order`

The actual source-level configuration application order.

### `resolution_trace`

One entry per candidate:

```text
source
kinds
action
reason
precedence_rank
chain_key
```

Actions are:

```text
selected
conflict
```

Reasons include:

```text
user_scope
project_root
nested_project
same_precedence
incomplete_coverage
```

## 5. Resolution status

| Condition | Status |
|---|---|
| Candidates and complete Coverage | `resolved` |
| Candidates and incomplete Coverage | `partial` |
| No candidates | `unknown` |
| Ambiguous candidate identity | `conflict` |

Coverage is never converted to a Finding or permission.

## 6. Field-level boundary

P2-07 intentionally does not:

- merge individual TOML fields;
- evaluate `.rules` decisions;
- select active MCP servers;
- enumerate MCP tools;
- read environment values;
- resolve URLs;
- determine effective authentication;
- assign side effects or permissions;
- make CI or authorization decisions.

Those operations require later source-backed extraction and capability modeling.

## 7. Security guarantees

The Resolver performs no:

```text
filesystem reads
source-value reads
command execution
Rules evaluation
Skill loading
Plugin loading
MCP connection
network access
environment lookup
scanned-code import
LLM call
```

## 8. Schema and versioning

P2-07 adds the required `configuration` profile to the Manifest and increments:

```text
AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
```

The change is recorded in ADR-0024. Phase 1 Domain, Baseline, Diff,
Assessment, Rule Pack, and Risk Model versions remain unchanged.

## 9. Next step

P2-08 consumes ordered configuration sources together with parsed source
records to associate Skills, MCP servers, MCP tools, and other tool declarations.

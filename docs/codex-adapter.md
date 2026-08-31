# AgentSec Codex Adapter

- Task: `P2-04`
- Status: Complete
- Decision date: 2026-08-20
- Decision: `docs/decisions/0021-codex-adapter.md`

## 1. Purpose

`CodexAdapter` is the first production implementation of the P2-03
`FrameworkAdapter` seam. It discovers reviewed Codex control-asset locations,
reads each selected file through existing path and resource guards, and binds the
result to the safe Markdown, TOML, `.rules`, and MCP Parsers.

The Adapter is a Python API in P2-04. It does not yet change the Phase 1
`agentsec scan` CLI, build an Agent Manifest, resolve the effective
configuration, or assign capability risk.

## 2. Interface

```python
from pathlib import Path

from agentsec.frameworks import (
    CodexAdapter,
    FrameworkInspectionRequest,
)

result = CodexAdapter().inspect(
    FrameworkInspectionRequest(
        project_root=Path("/workspace/project"),
        working_directory=Path("/workspace/project/services/api"),
        user_home=Path("/Users/example"),
    )
)
```

`working_directory` is optional. When omitted, it is the project root. When
provided, it must resolve through a safe path wholly inside the selected project
root and must be a directory.

The Adapter does not call `Path.home()` and does not read `CODEX_HOME` or any
other environment variable. A non-default Codex home must be supplied explicitly:

```python
CodexAdapter(codex_home=Path("/managed/codex-home"))
```

## 3. Discovery scope

### 3.1 Project chain

For every directory from the canonical project root through the selected working
directory, in root-to-leaf order, the Adapter checks:

```text
AGENTS.md
AGENTS.override.md
.codex/config.toml
.codex/rules/*.rules
.agents/skills/*/SKILL.md
```

The Adapter retains both `AGENTS.md` and `AGENTS.override.md` when both are
present. This is intentional for drift and security diagnosis. P2-06/P2-07 will
decide which instructions are effective instead of P2-04 silently discarding
one source.

### 3.2 User scope

When `user_home` is supplied, the Adapter checks:

```text
<user_home>/.codex/AGENTS.md
<user_home>/.codex/AGENTS.override.md
<user_home>/.codex/config.toml
<user_home>/.codex/rules/*.rules
<user_home>/.agents/skills/*/SKILL.md
```

The default `<user_home>/.codex` path must remain contained within the explicit
user-home boundary. An external symbolic-link target is rejected. An explicitly
provided `codex_home` is a separate operator-selected root.

### 3.3 Deferred Codex scopes

P2-04 does not implicitly inspect:

```text
/etc/codex/skills
system-bundled Skills
admin-managed Skills or configuration
profile-specific <profile>.config.toml files
plugin installation directories
```

These scopes require additional explicit roots, active-profile or installation
context, and separate policy decisions.

## 4. Neutral mapping

| Codex asset | Format | Neutral role |
|---|---|---|
| `AGENTS.md` | Markdown | `agent_instructions` |
| `AGENTS.override.md` | Markdown | `instruction_override` |
| `SKILL.md` | Markdown | `skill` |
| `*.rules` | Rules | `prefix_rules` |
| `config.toml` without MCP servers | TOML | `framework_config` |
| `config.toml` with one or more MCP servers | TOML | `framework_config`, `mcp_config` |

A TOML file receives the `mcp_config` role only when static MCP server
declarations are successfully parsed. Invalid structured or MCP declarations
make the selected file a `parse_error` Coverage failure rather than a partial,
misleading record.

## 5. Portable locators

Project assets use:

```text
scope=project
root_id=project
path=<project-relative POSIX path>
```

User Codex assets use:

```text
scope=user
root_id=codex_home
path=<Codex-home-relative POSIX path>
```

User Skills use:

```text
scope=user
root_id=user_home
path=.agents/skills/<skill>/SKILL.md
```

Absolute host paths are used only internally while enforcing containment. They
are not stored in `FrameworkAssetLocator` or Coverage Issues.

## 6. Precedence hints

P2-04 records deterministic hints only. Larger values mean higher framework
precedence.

| Asset | Rank |
|---|---:|
| User `AGENTS.md` | 10 |
| User `AGENTS.override.md` | 20 |
| User config, Rules, or Skill | 50 |
| Project-root `AGENTS.md` | 100 |
| Project-root `AGENTS.override.md` | 105 |
| Nested project `AGENTS.md` | `100 + depth × 10` |
| Nested project `AGENTS.override.md` | `105 + depth × 10` |
| Project config, Rules, or Skill | `200 + directory depth × 10` |

A rank does not itself select, merge, or authorize an asset. Effective
inheritance and Override resolution remain P2-06/P2-07 work.

## 7. Safe read and parse pipeline

Every selected asset follows this sequence:

```text
logical Codex path
→ PathGuard containment and symlink validation
→ regular-file check
→ pre-read size check
→ path and size revalidation
→ bounded binary read of at most limit + 1 bytes
→ strict UTF-8 decode
→ reviewed non-executing Parser
→ portable FrameworkAssetRecord
```

The Adapter enforces:

- maximum file bytes;
- logical directory depth;
- maximum selected assets with one deterministic overflow sentinel;
- no external symbolic links;
- deterministic path ordering;
- explicit skipped counts and Coverage Issues.

Internal symbolic links are accepted only after `PathGuard` proves that every
link hop remains within the selected source root.

## 8. Coverage behavior

Per-asset failures use stable P2-03 codes:

```text
unreadable
unsupported_encoding
too_large
depth_exceeded
asset_limit_exceeded
external_symlink
parse_error
```

A directory-level discovery gap, such as an external `.codex` link or an
unreadable `rules` directory, produces an Issue even when the Adapter cannot
know how many assets were hidden below it. Selected files that fail reading or
parsing increment both `discovered_assets` and `skipped_assets`.

`complete=true` only when there are no Issues and no skipped assets.

## 9. Non-execution guarantees

P2-04 never:

- interprets AGENTS instructions as commands;
- imports or loads a Skill;
- evaluates a `.rules` declaration against a command;
- runs an MCP `command` or its arguments;
- connects to an MCP endpoint;
- reads an environment-variable value;
- loads a plugin;
- follows an include or reference;
- imports scanned project code;
- sends scanned content to an LLM;
- performs network access.

MCP commands, endpoints, environment-variable names, and tool policy remain
inert parsed declarations. Static MCP environment and HTTP-header values remain
excluded from the specialized MCP model as decided in P2-02.

## 10. Current boundary and next step

P2-04 proves deterministic Codex discovery and parser binding. It does not yet:

- normalize assets into an Agent Manifest;
- resolve effective instructions or configuration;
- decide whether project Rules are active for a trusted project;
- decide whether a declared capability exists at runtime;
- expose structured assets through the current CLI reports;
- add capability or combination-risk findings;
- add LLM analysis.

P2-05 now consumes `FrameworkInspectionResult` through `AgentManifestBuilder`
and produces Agent Manifest Schema `0.3.0` source provenance, instruction and
configuration candidates, explicit resolution states, Coverage, and future
capability placeholders. P2-06 resolves effective instructions; P2-07 resolves
source-level Framework, Rules, and MCP configuration precedence.

## 11. Codex references reviewed

- `AGENTS.md`: `https://learn.chatgpt.com/codex/agent-configuration/agents-md`
- Skills: `https://developers.openai.com/codex/skills`
- Rules: `https://developers.openai.com/codex/rules`
- Configuration: `https://developers.openai.com/codex/config-reference`
- MCP: `https://developers.openai.com/codex/mcp`

AgentSec deliberately keeps a stricter explicit-root and non-execution policy
than a runtime Codex installation.

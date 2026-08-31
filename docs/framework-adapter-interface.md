# AgentSec Framework Adapter Interface

- Task: `P2-03`
- Status: Complete
- Decision date: 2026-08-20
- Decision: `docs/decisions/0020-framework-adapter-seam.md`

## 1. Purpose

The Framework Adapter seam isolates framework-specific asset locations,
filenames, configuration conventions, parser selection, and precedence hints
from the common AgentSec pipeline.

P2-03 defines the interface and neutral output. P2-04 provides the Codex
Adapter behind that interface.

## 2. Interface

```python
from agentsec.frameworks import FrameworkAdapter


class FrameworkAdapter(Protocol):
    @property
    def metadata(self) -> FrameworkAdapterMetadata: ...

    def inspect(
        self,
        request: FrameworkInspectionRequest,
    ) -> FrameworkInspectionResult: ...
```

The interface deliberately has one behavior method. A caller does not need to
know how the Adapter traverses paths, selects Parsers, or maps framework files to
neutral roles.

## 3. Request

```python
FrameworkInspectionRequest(
    project_root=Path("/workspace/project"),
    user_home=Path("/Users/example"),
    working_directory=Path("/workspace/project/services/api"),
    limits=FrameworkInspectionLimits(
        max_file_size_bytes=1_048_576,
        max_depth=20,
        max_assets=1_000,
    ),
)
```

`user_home` is optional and explicit. A concrete Adapter must not silently infer
or inspect unrelated user directories when the caller does not provide it.

`working_directory` was added by P2-04 because Codex instruction and Skill
discovery depends on the root-to-current-directory chain. It is optional and
defaults to `project_root`; a concrete Adapter must keep it inside the project
root.

The request contains no executable dependencies.

## 4. Portable asset locator

```python
FrameworkAssetLocator(
    scope=FrameworkAssetScope.PROJECT,
    root_id="project",
    path=".codex/rules/default.rules",
)
```

The locator stores:

```text
scope
root_id
relative POSIX path
```

It rejects absolute paths and `..` traversal and does not expose an absolute host
path in Adapter output.

## 5. Neutral roles

```text
agent_instructions
instruction_override
skill
prefix_rules
framework_config
mcp_config
```

Roles describe why an asset matters without naming Codex-specific files. A
structured configuration file can carry both `framework_config` and
`mcp_config`.

## 6. Formats and parser coherence

| Format | Required parser result |
|---|---|
| `markdown` | `ParsedMarkdown` |
| `rules` | `ParsedRulesDocument` |
| `json` | JSON `StructuredDocument` |
| `yaml` | YAML `StructuredDocument` |
| `toml` | TOML `StructuredDocument` |

An asset with the `mcp_config` role must also provide
`ParsedMcpConfiguration`.

The record validates parser format, line count, role family, and MCP-role
coherence before a result can be constructed.

## 7. Precedence

Every asset has a non-negative `precedence_rank`.

```text
larger rank = higher framework precedence
```

P2-03 only preserves the hint. It does not merge instructions or select the
final effective value. P2-06 and P2-07 implement inheritance and Override
resolution.

## 8. Coverage

Coverage Issues are restricted to stable codes:

```text
unreadable
unsupported_encoding
too_large
depth_exceeded
asset_limit_exceeded
external_symlink
unsupported_format
parse_error
unknown
```

A complete result requires:

```text
skipped_assets = 0
issues = empty
```

Asset and Issue tuples must be deterministically sorted and unique.

## 9. Safety invariants for concrete Adapters

A Framework Adapter may read bounded configuration assets, but it may not:

- execute a discovered command;
- load a discovered Skill, Hook, plugin, or script;
- connect to a discovered MCP Server;
- resolve or call a discovered URL;
- inspect environment-variable values;
- follow an external symlink;
- interpolate templates or variables;
- import code from the scanned project;
- send content to an LLM;
- copy untrusted source into safe error messages.

Per-asset failures become Coverage Issues. A catastrophic implementation failure
may raise `FrameworkAdapterError` with a fixed trusted message.

## 10. Rule-engine separation

The output of `FrameworkAdapter.inspect()` is intended for the future Agent
Manifest builder. It is not passed directly to the Phase 1 `RuleContext`.

This keeps framework-specific discovery and configuration outside:

```text
Markdown Rule matching
Risk scoring
Evidence Confidence
Hard Gates
CI policy
```

Later capability rules operate on normalized Manifest/Capability structures
rather than Codex paths or parser-library objects.

## 11. Production implementation

P2-03 verifies two independent fake Adapters through the same Protocol. Both
produce `FrameworkInspectionResult` without changing the caller. This confirmed
the seam later used by the P2-04 production Codex Adapter.

P2-04 now provides `CodexAdapter`, which discovers bounded project and user
Agent, Skill, Rules, TOML, and MCP assets. See `docs/codex-adapter.md` and
ADR-0021.

## 12. Current boundary

The interface itself does not:

- inspect user configuration unless an explicit root is supplied;
- resolve final Codex precedence;
- build Agent Manifest;
- resolve effective instructions;
- emit structured Assets in CLI reports;
- change current scanning behavior.

P2-05 now builds the versioned Agent Manifest source inventory from Adapter
output. P2-06 resolves instruction state and P2-07 resolves source-level
configuration precedence without merging raw values.

# ADR-0020: Deep Framework Adapter Seam and Neutral Inspection Result

- Status: Accepted
- Date: 2026-08-20
- Task: P2-03

## Context

P2-01 and P2-02 can parse Markdown, JSON, YAML, TOML, Codex `.rules`, and MCP
configuration, but they do not know which files a particular Agent framework
uses, where user/project/plugin scopes live, or how framework precedence is
expressed. Letting framework-specific paths, filenames, parser selection, and
MCP layout spread into the application or rule engine would make every future
framework addition a cross-cutting change.

The project needs a real seam before implementing the Codex Adapter. The
interface must be small, hide filesystem and parser-selection complexity, expose
explicit Coverage, retain source provenance, and stop before Agent Manifest and
risk interpretation.

## Decision

Create the `agentsec.frameworks` module with one deep `FrameworkAdapter`
interface:

```python
@runtime_checkable
class FrameworkAdapter(Protocol):
    @property
    def metadata(self) -> FrameworkAdapterMetadata: ...

    def inspect(
        self,
        request: FrameworkInspectionRequest,
    ) -> FrameworkInspectionResult: ...
```

The interface has one behavior method. Callers provide only:

```text
project_root
optional user_home
optional working_directory
trusted filesystem limits
```

`working_directory` was added by P2-04/ADR-0021 after the first concrete Codex
Adapter proved that framework discovery needs root-to-current-directory context.
It defaults to the project root and cannot escape that root.

They do not provide shell, environment, network, MCP, model, plugin, Hook, Skill,
or command execution dependencies.

### Neutral asset vocabulary

Adapters return `FrameworkAssetRecord` values using framework-neutral fields:

```text
portable source locator
format
one or more neutral roles
content SHA-256
byte size
line count
precedence rank
parsed document
optional parsed MCP declarations
```

Scopes are:

```text
project
user
plugin
```

Formats are:

```text
markdown
rules
json
yaml
toml
```

Roles are:

```text
agent_instructions
instruction_override
skill
prefix_rules
framework_config
mcp_config
```

A single structured configuration file may have both `framework_config` and
`mcp_config` roles. Roles from incompatible format families cannot be combined.

`FrameworkAssetLocator` contains a named root and a safe relative POSIX path. It
never serializes an absolute host path. `precedence_rank` is non-negative; larger
values represent higher framework precedence, but actual inheritance and
Override resolution remains P2-06/P2-07 work.

### Parsed records

The Adapter output may contain these already-reviewed parser documents:

```text
ParsedMarkdown
ParsedRulesDocument
StructuredDocument
ParsedMcpConfiguration
```

Format and parser result must agree. An MCP role requires a parsed MCP
configuration. Exact source content is not duplicated into the framework result.

This result is input to the future Agent Manifest builder. It is not a
`RuleContext`, and deterministic Phase 1 Markdown rules do not receive framework
paths or framework-specific configuration.

### Coverage

`FrameworkInspectionResult` records:

```text
assets
issues
discovered_assets
skipped_assets
complete
```

It enforces:

```text
len(assets) + skipped_assets == discovered_assets
complete == (skipped_assets == 0 and issues is empty)
```

Assets and issues must be unique and deterministically ordered. Per-asset
failures become structured Issues. `FrameworkAdapterError` is reserved for a
catastrophic Adapter failure and must not copy scanned source text.

### Resource and safety policy

Every Adapter must enforce file-size, depth, and asset-count limits. Concrete
Adapters must retain the existing path containment, symlink, bounded read,
UTF-8, non-execution, no-network, and secret-reporting invariants.

## Version impact

P2-03 adds a Python interface and internal neutral inspection values. No
Framework Adapter output is serialized in the current Assessment, Baseline, or
Diff formats, and no Rule or risk meaning changes.

```text
CONFIG_SCHEMA_VERSION       unchanged
DOMAIN_SCHEMA_VERSION       unchanged
BASELINE_SCHEMA_VERSION     unchanged
DIFF_OUTPUT_VERSION         unchanged
ASSESSMENT_OUTPUT_VERSION   unchanged
RULE_PACK_VERSION           unchanged at 0.3.0
RISK_MODEL_VERSION          unchanged
```

P2-05 Agent Manifest serialization and any integration of structured Assets into
Assessment/Baseline/Diff require a new Version Impact Review.

## Consequences

### Positive

- Framework discovery and parser selection have one real seam.
- Codex and future Adapters can return the same neutral inspection result.
- Framework-specific paths do not leak into the deterministic rule engine.
- Portable locators avoid embedding absolute user paths.
- Parse result/format/role coherence is validated once.
- Coverage and resource-limit semantics are explicit before the first concrete
  Adapter.

### Negative

- P2-03 originally added models without a production Adapter; P2-04 now provides
  the first concrete implementation.
- Parsed documents remain format-aware, so the future Manifest builder still
  needs normalization logic.
- Precedence rank is only recorded; effective configuration resolution is not
  implemented here.
- User and plugin assets require carefully selected source roots in the Codex
  Adapter and must not bypass path containment.

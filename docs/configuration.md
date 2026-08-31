# AgentSec Project Configuration

- Tasks: `P1-03`, `P1-06`, `P1-08`
- Status: Complete
- Schema version: `0.1.0`

## Precedence

AgentSec selects configuration in this order:

1. an explicit `--config PATH` passed to `scan`, `baseline create`, or `diff`;
2. `<project-root>/.agentsec/config.yaml`;
3. built-in secure defaults.

There is no global user configuration in Phase 1. Environment-variable
interpolation and LLM model configuration are intentionally not supported.

For `agentsec diff`, and for configured/default `agentsec scan` output, format
precedence is:

```text
--format text|json
→ output.format from the effective config
→ text default
```

P2-25 additionally permits the explicit CLI-only override
`agentsec scan --format sarif`. SARIF is intentionally not added to Config
Schema `0.1.0`; a project configuration file must still use `text` or `json`.

The CLI format override changes rendering only and does not change the
collection-configuration fingerprint.

## Example

```yaml
version: "0.1.0"

discovery:
  include:
    - AGENTS.md
    - AGENTS.override.md
    - SKILL.md
    - "**/AGENTS.md"
    - "**/AGENTS.override.md"
    - "**/SKILL.md"
  exclude:
    - ".git/**"
    - ".venv/**"
    - "node_modules/**"
    - "dist/**"
    - "build/**"

limits:
  max_file_size_bytes: 1048576
  max_depth: 20
  max_assets: 1000

output:
  format: text
  redact_secrets: true
```

## Discovery pattern semantics

P1-06 applies discovery patterns using deterministic project-relative POSIX
semantics:

- matching is anchored at the selected project root;
- matching is case-sensitive on every operating system;
- `*`, `?`, and character classes such as `[ab]` match inside one path
  segment only;
- a complete `**` segment matches zero or more directory segments;
- exclude patterns take precedence over include patterns;
- an excluded directory is pruned before its metadata or descendants are read;
- intentionally excluded paths do not create coverage issues;
- Phase 1 explicit includes can add lowercase `.md` files only;
- standard filenames remain `discovered` assets, while additional Markdown
  files are marked `explicit`;
- supplying an `include` or `exclude` list replaces that list's defaults rather
  than merging with them.

For example, `AGENTS.md` selects only the root file,
`**/AGENTS.md` selects root and nested files, and `docs/**/*.md` selects
Markdown files directly or recursively below `docs/`.

To scan a normally excluded subtree, the operator must remove the corresponding
pattern from `discovery.exclude`. Adding an include alone does not override an
existing exclude.

## Resource-limit semantics

P1-08 enforces all fields under `limits`:

- `max_file_size_bytes` is inclusive; a file exactly at the limit is accepted;
- asset content is read with a hard bound of `max_file_size_bytes + 1` bytes;
- the project root has depth `0`, so `max_depth: 1` permits files in the root
  and immediate child directories;
- directories below the depth boundary are not traversed and produce
  `depth_exceeded`;
- selected assets, including assets later skipped for another reason, consume
  `max_assets` capacity;
- the first asset beyond `max_assets` is counted as discovered and skipped,
  receives `asset_limit_exceeded`, and stops collection globally.

Every triggered resource limit makes coverage incomplete and maps to CLI exit
code `2`. Full rationale and counting examples are documented in
`docs/resource-limits.md` and ADR-0003.

## Security rules

- YAML is decoded with `yaml.safe_load` only.
- Configuration must be UTF-8 and no larger than 256 KiB.
- Existing files must contain an explicit schema version.
- Unknown fields are rejected.
- Include and exclude patterns must remain project-relative.
- Duplicate patterns are rejected.
- Secret redaction cannot be disabled in Phase 1.
- P1-26 redaction behavior and residual limitations are documented in
  `docs/secret-redaction.md`.
- Automatically discovered config symlinks cannot resolve outside the project
  root.
- Explicit config paths are treated as deliberate user input and may live
  outside the target root.
- Configuration does not execute tags, expressions, environment variables or
  project code.

## Defaults

When no file exists, AgentSec uses versioned defaults equivalent to the example
above. The loader records `ConfigSource.DEFAULT` and no config path.

## Deferred fields

The Phase 1 schema does not include:

- LLM provider or model;
- API keys;
- MCP connection settings;
- runtime identities;
- organization policy, persistent fail-on thresholds, or waivers;
- persistent SARIF or HTML output configuration.

P2-25 implements explicit CLI-only SARIF selection without changing this Schema.
Other fields are introduced only by the tasks that implement them.

## P2-26 CLI-only fail-on

`scan --fail-on high|critical` is intentionally not part of Config Schema
`0.1.0`. It must be supplied explicitly for each invocation. P2-27 will define
the independently versioned organization Policy contract.

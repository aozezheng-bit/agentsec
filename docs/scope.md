# AgentSec PoC Scope

- Task: `P0-01`
- Status: Complete
- Decision date: 2026-08-18
- Scope owner: AgentSec project owner
- Applies to: Phase 1 — Markdown static scanning PoC

## 1. Purpose

The Phase 1 PoC validates whether a safe, evidence-backed CLI can discover Agent instruction files, detect meaningful textual changes, apply a small deterministic rule set, and produce explainable findings.

The PoC is not intended to determine whether an Agent is globally safe. It establishes the interfaces, evidence model, test corpus, and engineering constraints required by later phases.

## 2. Primary user outcome

A developer can run:

```bash
agentsec scan <project-root>
```

and receive a deterministic report that answers:

1. Which supported Agent Markdown files were discovered?
2. Which files could not be scanned, and why?
3. Which configured rules matched?
4. What exact file, line range, and text supports each finding?
5. What preliminary likelihood, impact, severity, and evidence confidence were assigned?

A developer can also create a trusted snapshot and compare the project against it:

```bash
agentsec baseline create <project-root>
agentsec diff <project-root>
```

## 3. In-scope inputs

### 3.1 Automatically discovered files

Phase 1 automatically discovers these exact filenames:

- `AGENTS.md`
- `AGENTS.override.md`
- `SKILL.md`

Discovery is recursive within the selected project root, subject to configured exclusions and resource limits.

### 3.2 Explicitly included Markdown

Users may explicitly include additional `.md` files through project configuration or CLI options. These files are treated as supplementary Agent instruction assets, not automatically trusted files.

### 3.3 Repository context

When the target is a Git working tree, the PoC may read:

- current commit identifier;
- working-tree status;
- file paths and file hashes;
- previous content needed for a local diff.

The PoC does not modify Git state.

## 4. In-scope behavior

### 4.1 Asset discovery

The PoC will:

- recursively discover supported Markdown assets;
- apply include and exclude patterns;
- enforce maximum file size and traversal depth;
- detect unsupported encodings and unreadable files;
- record skipped files as coverage issues;
- calculate a SHA-256 content hash;
- preserve the project-relative path.

### 4.2 Safe Markdown parsing

The PoC will extract, without executing content:

- headings;
- paragraphs;
- list items;
- fenced code blocks;
- YAML frontmatter;
- links and file references;
- source line ranges;
- indicators for unusually long, encoded, or obfuscated text.

### 4.3 Baseline and text diff

The PoC will support:

- creation of a versioned local baseline;
- detection of added, removed, and modified supported assets;
- line-oriented text diff;
- preservation of before/after evidence;
- comparison of scanner, baseline-schema, and rule-pack versions.

### 4.4 Deterministic rules

The PoC will implement 10–15 deterministic Markdown rules using keyword, regular-expression, and limited context-window matching.

The initial rule categories are:

- instruction override or instruction bypass;
- weakened or removed human approval;
- shell, command, or dynamic code execution;
- external network access;
- secret, token, credential, or environment access;
- production or administrator access;
- destructive, deployment, or publishing actions;
- persistent memory;
- self-modification;
- hidden, encoded, or obfuscated instructions;
- external tools or executable-script references.

A rule match is evidence of a potentially risky declaration. It is not proof that the Agent can successfully perform the action.

### 4.5 Preliminary risk output

Each finding will include:

- rule identifier;
- risk category;
- title and description;
- NIST-style likelihood level;
- NIST-style impact level;
- preliminary severity and numeric mapping;
- evidence-confidence grade;
- source file and line range;
- matched excerpt;
- recommended follow-up.

Phase 1 uses a preliminary scoring model only. Full CVSS/AIVSS-compatible agentic uplift, drift risk, governance risk, and runtime evidence are Phase 2 or later work.

### 4.6 Reports

The PoC will output:

- human-readable terminal text;
- machine-readable JSON conforming to a versioned schema;
- coverage issues and incomplete-scan warnings;
- tool, schema, baseline, and rule-pack versions.

## 5. Supported commands

The Phase 1 target command surface is:

```text
agentsec version
agentsec scan <project-root>
agentsec baseline create <project-root>
agentsec diff <project-root>
agentsec rules list
```

Command naming may be refined before the CLI interface is declared stable, but behavior must remain represented by these five operations.

## 6. Security boundaries and invariants

The PoC must satisfy all of the following:

1. It never executes scanned code, code blocks, scripts, hooks, skills, or commands.
2. It never connects to an MCP server discovered in scanned content.
3. It performs no external network access by default.
4. It does not follow a symbolic link outside the selected project root by default.
5. It treats all scanned text as untrusted data.
6. It does not interpolate scanned text into an executable shell command.
7. It does not log or report full secret values.
8. It enforces file-size, traversal-depth, and resource limits.
9. A malformed file or failed rule does not silently terminate the complete scan.
10. Incomplete coverage is visible in the final report.
11. Every High or Critical result includes direct source evidence.
12. Evidence confidence is reported independently from severity.
13. Deterministic output is reproducible for identical input and versioned configuration.

## 7. Explicit non-goals

Phase 1 will not:

- parse TOML, general YAML, JSON, `.rules`, MCP manifests, or plugin manifests;
- calculate the final effective configuration across multiple file formats;
- generate a complete Agent Manifest;
- prove that a declared capability is available at runtime;
- connect to or enumerate tools from an MCP server;
- inspect OAuth scopes or production identities;
- run an LLM for semantic analysis;
- implement natural-language semantic diff;
- build a general capability attack graph;
- execute dynamic prompt-injection or red-team tests;
- automatically remediate scanned files;
- block CI by default;
- support every Agent framework;
- provide a Web administration console;
- claim that a keyword match is a confirmed vulnerability;
- provide financial loss estimates.

## 8. Default exclusions

Unless explicitly overridden, discovery excludes:

- `.git/`
- `.venv/`
- `venv/`
- `node_modules/`
- `vendor/`
- `dist/`
- `build/`
- generated coverage or cache directories

Explicit inclusion does not bypass path-safety or resource-limit enforcement.

## 9. Deliverables

Phase 1 is expected to produce:

1. installable `agentsec` CLI package;
2. versioned project configuration schema;
3. versioned Asset, Evidence, Finding, ScanResult, and Baseline schemas;
4. safe Markdown collector and parser;
5. baseline and text-diff implementation;
6. deterministic rule interface and initial rule pack;
7. preliminary NIST-style scoring and evidence confidence;
8. Text and JSON reporters;
9. 30–50 safe, risky, malformed, and prompt-injection test fixtures;
10. README and PoC usage documentation.

## 10. Acceptance criteria

P0-01 is complete when:

- the Phase 1 supported inputs are explicit;
- Phase 1 behavior is separated from Phase 2 and Phase 3 behavior;
- security invariants are explicit and testable;
- non-goals prevent scope expansion;
- required commands and deliverables are named;
- downstream tasks can implement against this document without inventing missing product scope.

The Phase 1 PoC itself may exit only when:

- all target commands are implemented;
- 10–15 deterministic Markdown rules have positive and negative tests;
- every finding contains evidence;
- Text and JSON outputs are schema-tested;
- 30–50 test fixtures exist;
- no scanned project code is executed;
- incomplete coverage is reported;
- CI blocking remains disabled by default.

## 11. Deferred decisions

The following decisions are intentionally deferred to later tasks or ADRs:

- exact CLI configuration syntax and precedence;
- final public Python package name;
- whether rules are authored only in Python or also in declarative YAML;
- long-term plugin architecture;
- final Agent Manifest field set;
- full NIST/CVSS/AIVSS scoring implementation;
- LLM provider and model selection;
- runtime verification architecture;
- support for non-Codex Agent frameworks.

## 12. Phase 1 release status

P1-31 completed the Phase 1 command surface and local PoC release on
2026-08-19:

```text
agentsec version
agentsec scan <project-root>
agentsec baseline create <project-root>
agentsec diff <project-root>
agentsec rules list
```

All ten deliverables are present. The release remains report-only, performs no
external network access by default, and does not execute scanned content.
Accepted limitations are recorded in
`docs/releases/0.1.0-known-limitations.md`.

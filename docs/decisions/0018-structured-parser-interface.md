# ADR-0018: Deep Structured Parser Interface and Source Location Model

- Status: Accepted
- Date: 2026-08-20
- Task: P2-01

## Context

Phase 2 needs JSON, YAML, and TOML facts before Framework Adapters can build an
Agent Manifest. Passing dependency-specific trees directly to every Adapter
would create three shallow interfaces, duplicate traversal and limit logic, and
make rules depend on parser libraries. Parsing untrusted configuration also
creates risks from YAML object construction, aliases, duplicate keys, extreme
nesting, large scalar values, and later accidental execution of declared tools.

The interface must preserve enough source provenance for future Evidence while
remaining smaller than the format-specific implementations. It must not change
Phase 1 `AgentAsset`, Baseline, Assessment, Diff, Rule, or Risk schemas before
structured files are integrated into collection and reporting.

## Decision

Create one deep `StructuredParser` module interface:

```python
class StructuredParser(Protocol):
    @property
    def format(self) -> StructuredDataFormat: ...

    def parse(self, content: str) -> StructuredDocument: ...
```

`StructuredDocument` contains a source-ordered tuple of immutable
`StructuredNode` values. Every node has:

```text
normalized path
normalized kind
1-based inclusive start line
1-based inclusive end line
optional typed scalar value
```

Paths use string object keys and non-negative integer array indexes. The root
path is empty and renders as `$`; examples include `$.tools[0].name` and
`$["agent.config"].enabled`.

Adopt these format decisions:

1. JSON uses a bounded recursive-descent implementation so duplicate keys and
   exact field locations remain visible. It uses no object hook or executable
   decoder.
2. YAML uses `SafeLoader` node composition, rejects anchors, aliases, explicit
   tags, non-string mapping keys, multiple documents, duplicate keys, and
   non-finite floats, and constructs only reviewed scalar tags.
3. TOML uses Python 3.12 `tomllib` as the authoritative syntax and type parser.
   A separate deterministic statement mapper assigns table, key, multiline,
   and array-of-table line ranges without using private `tomllib` interfaces.
4. Inline TOML descendants inherit the containing assignment range when the
   syntax does not expose a smaller reviewed location.
5. Parsers receive bounded decoded strings. Filesystem collection, encoding,
   symlink policy, and byte-size limits remain outside this interface.
6. Parser-local limits bound tree depth, node count, and decoded scalar length.
7. `StructuredParseError` exposes a stable issue code and optional line but never
   copies source text or dependency exception details.
8. Empty YAML and TOML documents produce an empty node tuple. Empty JSON is
   malformed because JSON requires one value.
9. The parser modules perform no interpolation, includes, imports, reference
   resolution, environment lookup, filesystem I/O, network access, tool calls,
   command execution, MCP connection, model call, or rendering.

## Version impact

P2-01 adds a Python interface and internal immutable parser structures but does
not add or change serialized production fields. Therefore:

```text
CONFIG_SCHEMA_VERSION       unchanged
DOMAIN_SCHEMA_VERSION       unchanged
BASELINE_SCHEMA_VERSION     unchanged
DIFF_OUTPUT_VERSION         unchanged
ASSESSMENT_OUTPUT_VERSION   unchanged
RULE_PACK_VERSION           unchanged
RISK_MODEL_VERSION          unchanged
```

A later task that adds structured Asset types, serializes nodes, includes them in
Baselines, or emits them in reports must perform a new Version Impact Review and
may require Schema increments.

## Consequences

### Positive

- Framework Adapters learn one interface rather than three parser libraries.
- Source path and line evidence are available before capability interpretation.
- Duplicate and unsupported configuration does not silently become trusted.
- JSON, YAML, and TOML share limits, error categories, node kinds, and tests.
- Parser implementations remain replaceable behind a stable seam.

### Negative

- YAML anchors and explicit tags are rejected even when a specific use could be
  benign.
- TOML inline child nodes share the parent assignment range rather than exact
  columns.
- The normalized tree does not retain comments, formatting trivia, or raw text.
- Parser-local limits apply after the syntax library has tokenized YAML or TOML;
  collector byte limits remain necessary for outer resource control.
- P2-01 alone does not make structured files visible to `agentsec scan`.

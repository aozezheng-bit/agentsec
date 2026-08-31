# AgentSec Structured Parsers

- Task: `P2-01`
- Status: Complete
- Decision date: 2026-08-20
- Decision: `docs/decisions/0018-structured-parser-interface.md`

## 1. Purpose

The structured Parser module converts bounded decoded JSON, YAML, or TOML text
into one deterministic flat tree for future Framework Adapters. It does not
assign Agent capabilities, Findings, risk, or policy.

## 2. Interface

```python
from agentsec.parsers import (
    JsonStructuredParser,
    TomlStructuredParser,
    YamlStructuredParser,
)

json_document = JsonStructuredParser().parse(json_text)
yaml_document = YamlStructuredParser().parse(yaml_text)
toml_document = TomlStructuredParser().parse(toml_text)
```

Every adapter satisfies:

```python
class StructuredParser(Protocol):
    @property
    def format(self) -> StructuredDataFormat: ...

    def parse(self, content: str) -> StructuredDocument: ...
```

## 3. Normalized nodes

Given:

```json
{
  "agent": {
    "tools": ["shell"]
  }
}
```

representative paths are:

```text
$                    object
$.agent              object
$.agent.tools        array
$.agent.tools[0]     string = "shell"
```

Each node retains a 1-based inclusive source range. Object-field nodes begin at
the key line so a future Finding can cite the controlling field rather than only
the value token.

Kinds are:

```text
object
array
string
integer
float
boolean
null
datetime
date
time
```

JSON supports the JSON subset. YAML and TOML may produce date/time kinds when
the syntax defines them.

## 4. Default limits

| Limit | Default |
|---|---:|
| Maximum depth | 64 |
| Maximum nodes | 10,000 |
| Maximum decoded scalar characters | 65,536 |

Customize only through trusted caller configuration:

```python
from agentsec.parsers import JsonStructuredParser, StructuredParseLimits

parser = JsonStructuredParser(
    StructuredParseLimits(
        max_depth=32,
        max_nodes=2_000,
        max_scalar_characters=16_384,
    )
)
```

Collector byte-size and asset-count limits remain separate outer controls.

## 5. Safe errors

`StructuredParseError` exposes:

```text
code
line | None
```

Stable codes include:

```text
malformed
duplicate_key
unsafe_tag
alias_not_allowed
unsupported_key
unsupported_value
depth_exceeded
node_limit_exceeded
scalar_too_large
```

The exception string contains only the stable code and never source text.

## 6. JSON policy

The JSON adapter:

- accepts one complete JSON value;
- preserves object, array, scalar, key, and element locations;
- rejects duplicate object keys;
- rejects trailing content and non-standard `NaN`/`Infinity` values;
- uses no object hooks or custom decoders;
- enforces limits during recursive descent.

## 7. YAML policy

The YAML adapter:

- accepts one YAML document;
- permits standard map, sequence, null, bool, int, float, string, and timestamp
  tags created by `SafeLoader`;
- requires string mapping keys;
- rejects duplicate keys;
- rejects anchors and aliases;
- rejects every explicit tag, including Python object tags;
- rejects multiple documents;
- rejects non-finite floating-point values;
- never calls an unsafe constructor.

Example rejected input:

```yaml
!!python/object/apply:os.system
- echo unsafe
```

It is rejected as `unsafe_tag`; it is never executed.

## 8. TOML policy

The TOML adapter:

- uses Python 3.12 `tomllib` for authoritative syntax and typed values;
- supports standard tables, dotted/quoted keys, arrays, inline tables, arrays of
  tables, multiline strings, dates, times, and datetimes;
- maps statements back to physical source lines;
- rejects duplicate definitions through `tomllib` validation;
- rejects non-finite floats from the normalized model;
- assigns inline descendants the containing statement range.

## 9. Determinism and ordering

Nodes are ordered by:

```text
source start line
parent before child on the same line
normalized path
```

Paths are unique and every non-root node must have a container parent consistent
with its final string key or integer index.

## 10. Integration boundary

P2-01 is parser-only. Current `agentsec scan` discovery still selects Phase 1
Markdown Assets. Later tasks will add Framework Adapters, structured Asset
collection, Agent Manifest mapping, Effective Capability resolution, Baseline
compatibility, and Capability Diff.

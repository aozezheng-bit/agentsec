# Capability Change Impact and Finding Delta

- Task: P2-13
- Status: Complete
- Output version: `0.1.0`
- Development package line: `0.2.0` (P2-13 is not yet released)
- Policy: report-only

## Purpose

P2-13 turns normalized Capability Diff into a reviewable impact story:

```text
before Manifest + after Manifest
→ canonical Capability Diff
→ safe Tool/Permission/Control before/after state
→ deterministic exposure direction
→ before/after Capability Rule evaluation
→ Finding Delta
```

## Command

```bash
agentsec capability impact \
  --before baseline.manifest.json \
  --after risky.manifest.json \
  --format text
```

Chinese presentation:

```bash
agentsec capability impact \
  --before baseline.manifest.json \
  --after risky.manifest.json \
  --language zh
```

JSON artifact:

```bash
agentsec capability impact \
  --before baseline.manifest.json \
  --after risky.manifest.json \
  --format json \
  --output capability-impact.json
```

## Semantic state

Only reviewed normalized fields are exposed:

| Dimension | Fields |
|---|---|
| Tool | `kind`, `availability`, `side_effects`, `parent_tool_id` |
| Permission | `action`, `effect`, `resource`, `scope`, `target` |
| Control | `kind`, `state`, `target` |

Source values, Commands, arguments, endpoints, Headers, environment values,
credentials, memory content, and Tool display names are excluded.

## Change Impact

Each assessed change has:

```text
impact_id
dimension and stable item_id
added / removed / modified
normalized before state
normalized after state
exposure direction
stable reason codes
related Finding Delta IDs
```

Directions are:

```text
increased_exposure
reduced_exposure
mixed
neutral
uncertain
```

Direction is not a new risk score or authorization decision. Unknown state is
classified as `uncertain`.

## Finding Delta

Findings are matched by stable logical identity:

```text
rule_id + sorted related_ids
```

Statuses:

| Status | Meaning |
|---|---|
| `added` | Only the after Manifest matches |
| `resolved` | Only the before Manifest matches |
| `changed` | Same logical Finding, changed risk or evidence snapshot |
| `unchanged` | Same complete Finding snapshot |

Every snapshot keeps Severity and Evidence Confidence independent. The summary
reports highest before/after Severity and added/resolved High/Critical counts;
Findings are never averaged.

## Completeness and exit codes

```text
0  complete report-only result, including added High Findings
2  incomplete Manifest Coverage or before/after Rule execution
4  invalid/incompatible input or unsafe output artifact
5  required impact analysis failed safely
```

## Security boundary

P2-13 does not:

- execute scanned content;
- connect to MCP or network targets;
- read environment, credential, Header, or memory values;
- expose raw before/after source values;
- prove runtime capability or exploitation;
- enable Hard Gates, `--fail-on`, or CI blocking;
- call an LLM.

See ADR-0033 for the version and model decision.

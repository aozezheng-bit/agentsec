# ADR-0104: Attack Path Evidence Association CLI

- Date: 2026-08-31
- Status: Accepted
- Scope: P3-AG-06

## Decision

Add a dedicated top-level command:

```text
agentsec attack-graph-associate
```

The command accepts exactly one validated graph artifact (`--graph`) or one
project root (`--project`), plus optional Finding and Shadow Semantic Evidence
artifacts. It invokes the P3-AG-05 associator and emits the frozen association
report as Text or JSON.

## Rationale

The existing `agentsec attack-graph PROJECT` command is already a stable
path-report command. Converting it into a Typer command group would break its
existing positional interface and accepted automation. A dedicated command
preserves backward compatibility while making association input boundaries
explicit.

## Input safety

All JSON inputs are read through a bounded `O_NOFOLLOW` reader and validated
against strict Pydantic contracts before correlation. The CLI does not execute
scanned project assets, invoke a Provider, open MCP connections, or accept
model-authored source locations.

## Output safety

The output is always report-only. It contains locators and digests only; it
never copies source excerpts or secret values. `ReportArtifactWriter` validates
JSON and restricts `--force` to an existing valid artifact of the same kind.

## Consequences

- Existing `agentsec attack-graph PROJECT` behavior remains unchanged.
- Artifact mode can be used in CI as an evidence-producing step, but valid
  `unmatched` results do not block CI.
- A future policy task may consume the report as evidence, but this command
  itself cannot make a risk, authorization, or enforcement decision.

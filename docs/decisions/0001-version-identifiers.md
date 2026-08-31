# ADR-0001: Independent Version Identifiers

- Status: Accepted
- Date: 2026-08-18

## Context

AgentSec produces several artifacts that evolve at different rates: the CLI,
configuration, public domain schemas, baselines, rules, and risk scores. Using
only the package version would make it impossible to determine whether two
reports or baselines have compatible meaning.

## Decision

Maintain independent identifiers for package, config schema, domain schema,
baseline schema, rule pack, and risk model. Centralize them in
`agentsec.versioning`. Use PEP 440 for the package and exact semantic versions
for serialized interfaces.

Before 1.0, minor interface versions are potentially incompatible. At and
after 1.0, compatibility follows the same-major, supported-minor policy defined
in `docs/versioning.md`.

## Consequences

- Reports contain more metadata but become reproducible.
- Rule and risk changes cannot be hidden inside a package patch release.
- Consumers must reject unsupported versions explicitly.
- Future migration tooling can reason about each artifact independently.

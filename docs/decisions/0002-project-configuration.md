# ADR-0002: Strict Project-Local YAML Configuration

- Status: Accepted
- Date: 2026-08-18

## Context

Phase 1 needs predictable discovery limits and output defaults before the
collector is implemented. Configuration files may be committed by untrusted
contributors, so loading must not execute YAML tags, interpolate environment
variables, or silently accept unknown security-sensitive fields.

## Decision

Use a versioned project-local YAML document loaded with `yaml.safe_load` and
validated by strict Pydantic models. Precedence is explicit CLI path,
project-local `.agentsec/config.yaml`, then built-in secure defaults.

Reject unknown fields, unsupported versions, unsafe glob paths, oversized
files, invalid UTF-8, empty documents, and discovered config symlinks that
escape the project root. Secret redaction cannot be disabled in Phase 1.

## Consequences

- Configuration behavior is deterministic and testable.
- Future schema additions require a config-schema version change.
- Users cannot configure LLMs or environment interpolation before those
  features have a reviewed implementation.
- YAML aliases within the bounded file remain supported by PyYAML, but loading
  never constructs arbitrary Python objects.

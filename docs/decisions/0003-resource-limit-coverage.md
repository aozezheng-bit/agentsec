# ADR-0003: Explicit Resource-Limit Coverage Semantics

- Status: Accepted
- Date: 2026-08-18

## Context

P1-08 enforces configured limits for file bytes, logical traversal depth, and
the total number of selected assets. Existing coverage codes already represent
oversized files and excessive depth, but there is no precise code for a scan
that stops after reaching `max_assets`.

Using `unknown` would hide a deterministic and policy-relevant cause. Reusing
`too_large` or `depth_exceeded` would give machine consumers incorrect
semantics. Adding an enum value changes the public Domain Schema and therefore
requires an explicit version decision.

## Decision

Add `CoverageIssueCode.ASSET_LIMIT_EXCEEDED` with serialized value
`asset_limit_exceeded`.

Increment the Domain Schema version from `0.1.0` to `0.2.0`. AgentSec treats
pre-1.0 minor schema versions as potentially incompatible, so consumers that
support only `0.1.x` must reject `0.2.0` rather than silently discard the new
coverage reason.

Resource-limit coverage uses these codes:

- file exceeds `max_file_size_bytes`: `too_large`;
- directory exceeds `max_depth`: `depth_exceeded`;
- selected asset exceeds `max_assets`: `asset_limit_exceeded`.

The first asset beyond `max_assets` is counted as discovered and skipped, then
collection stops globally. This preserves the invariant
`scanned + skipped == discovered` while proving that the configured capacity
was exceeded.

## Consequences

- Automation can distinguish all three configured limits.
- Reports cannot represent an asset-limit stop as complete coverage.
- Domain Schema consumers need an explicit `0.2.0` compatibility update.
- The schema and version tests must include the new enum value.
- Later reporters can provide limit-specific remediation without parsing
  human-readable messages.

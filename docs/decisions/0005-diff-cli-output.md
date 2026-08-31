# ADR-0005: Versioned Safe Diff CLI Output

- Status: Accepted
- Date: 2026-08-18
- Task: P1-16

## Context

P1-16 exposes Baseline, Asset Diff, and Text Diff through terminal and JSON
interfaces. Both paths carry attacker-controlled file paths and retained line
evidence. A raw renderer could leak credentials, execute terminal control
sequences, hide text with Unicode format controls, or leave automation unable
to determine whether an output structure is compatible.

The public Domain Schema does not yet contain Text Diff delivery objects, and
P1-25 remains responsible for the general Assessment JSON Reporter. Coupling the
Diff CLI format to Domain Schema would force unrelated report-model changes to
alter the Diff interface.

## Decision

Create an independent `DIFF_OUTPUT_VERSION`, initially `0.1.0`, in
`agentsec.versioning`. Include it in `VersionSet` and in every successful or
error JSON Diff document as `format_version`.

The P1-16 delivery contract is:

1. Text and JSON use the same deterministic application result.
2. Secret redaction occurs before control-character escaping.
3. Raw TextDiffLine content is never rendered directly.
4. C0 controls, ANSI ESC, surrogate characters, zero-width characters, and bidi
   format controls are emitted as visible escape sequences.
5. Paths receive the same redaction and escaping treatment as line text.
6. JSON uses sorted keys, two-space indentation, UTF-8 Unicode, and one trailing
   newline.
7. JSON errors use the same `agentsec-diff` format and contain stable error and
   exit codes.
8. Asset changes do not fail solely because they exist; risk policy remains a
   later task.
9. Collection scope mismatch is rendered and maps to Baseline Error `4`.
10. Incomplete current coverage or incomplete Text Diff evidence maps to `2`.
11. Diff output version evolves independently from Domain Schema, Baseline
    Schema, rule-pack, and risk-model versions.

The initial JSON representation is a versioned Diff CLI interface. P1-25 may
reuse or wrap it when implementing the general JSON Reporter, but must not
silently change the meaning of version `0.1.x` fields.

## Consequences

- Automation can reject unknown Diff output versions.
- Terminal and JSON share the same security treatment.
- P1-16 does not require a Domain Schema increment.
- `VersionSet` gains one field and all version-vector tests must cover it.
- Redaction may intentionally remove benign text that resembles a credential.
- Sanitized JSON line values contain visible escape sequences rather than raw
  line-ending or format-control characters.

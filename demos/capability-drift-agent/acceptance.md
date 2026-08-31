# Capability Drift Demo Acceptance

- Task: P2I-05
- Date: 2026-08-20
- Status: Accepted
- Audiences: developers and management

## Common acceptance

| Criterion | Result |
|---|---|
| Uses production Manifest/Capability CLI | Pass |
| English and Chinese presenter tracks | Pass |
| Live and offline modes | Pass |
| Frozen expected artifacts with SHA-256 | Pass |
| No real credential, internal endpoint, or personal data | Pass |
| No scanned execution, MCP connection, network, environment read, or LLM | Pass |
| Report-only and runtime boundary visible | Pass |
| Complete and incomplete Coverage examples | Pass |

## Story acceptance

| State | Expected | Result |
|---|---|---|
| Baseline | Complete, 0 Findings | Pass |
| Risky drift | Complete, 17 Findings, 16 Rule IDs, highest High | Pass |
| Capability Diff | Visible normalized additions/removals with provenance | Pass |
| Incomplete | Exit `2`, no clean-pass interpretation | Pass |
| Remediated | Complete, 0 Findings | Pass |
| Remediation Diff | Risky capabilities visibly removed | Pass |

## Developer acceptance

A developer can identify:

1. the Tool, Permission, Control, Identity, Relationship, and Unknown changes;
2. the Rule ID and deterministic correlation used for each Finding;
3. the portable source path, field, line range, and content hash;
4. why Evidence Confidence is separate from Severity;
5. why incomplete Coverage returns `2`;
6. how remediation removes the current combination Findings;
7. how to consume canonical JSON artifacts.

## Management acceptance

A management viewer can explain:

1. the Agent gained execution, credential, external-network, delegation, and
   persistence declarations;
2. the highest reported risk is High;
3. 17 Findings cover 16 deterministic Rule meanings;
4. the potential blast radius includes release integrity and external systems;
5. the human recommendation is to hold release until remediation;
6. AgentSec remains report-only and did not block CI;
7. static analysis does not prove runtime exploitability or global safety.

## Verification

The live English and Chinese automated runners and offline presenter tracks pass.
The final repository quality-gate result is recorded in the P2I-05 completion
update after the full suite runs.

## Final quality gate

```text
Ruff: passed
Ruff Format: passed — 415 files
Mypy strict: passed — 172 source files
Pytest: 820 passed
English live CLI Demo: passed
Chinese live CLI Demo: passed
English/Chinese offline checksum fallback: passed
```

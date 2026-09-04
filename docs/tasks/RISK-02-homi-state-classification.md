# RISK-02：Homi Template / Latent / Active / Runtime State Classification

- Status: Complete (local implementation)
- Date: 2026-09-03
- Scope: Homi static report state classification
- Depends on: RISK-01 Operation Context Contract

## Objective

Separate the fact that an Homi asset contains a non-template declaration from the
claim that the Agent has a reachable runtime capability. The classification is
an evidence label used by later context extraction and scoring; it is not a
permission, authentication, CI, or Hard Gate decision.

## State definitions

| State | Meaning | Static builder can emit |
|---|---|---:|
| `template` | Empty, shipped example, placeholder, or documentation-only content | Yes |
| `latent` | Intent or persona behavior is expressed, but no concrete operation path is established | Yes |
| `active` | A concrete non-template static declaration is present; runtime reachability remains unverified | Yes |
| `runtime_attested` | Independent, reproducible runtime attestation proves the path | No; reserved for a future attestation adapter |
| `unknown` | Source coverage or classification is insufficient, including missing/skipped files | Yes |

`unknown` is deliberately not mapped to `active`, `latent`, or “safe”. It is a
coverage state that tells downstream consumers to avoid overclaiming.

## Delivered

- `src/agentsec/frameworks/homi_risk_state.py`
  - versioned `HomiRiskStateReport` contract;
  - file-level classification for all six standard Homi files;
  - capability/persona signal classification;
  - deterministic source Pilot digest binding;
  - value-minimized rationale codes and evidence paths;
  - strict report-only and runtime-authority invariants;
  - JSON encoder and schema exporter.
- `schemas/risk/homi-risk-state.schema.json`
- `homi report` and `DeterministicHomiReportOnlyPilot.run_and_write()` now emit:
  `homi-risk-state.json`.
- Provenance registry and Homi implementation digest include the new contract.
- `tests/test_homi_risk_state.py` covers template, latent, active, unknown,
  missing-file coverage, deterministic encoding, schema export, and rejection of
  forged runtime attestation.

## Deterministic mapping

### Files

- `EMPTY` or `EXAMPLE_ONLY` → `template`;
- `PRESENT` → `active` as a static file declaration only;
- `MISSING` or `SKIPPED` → `unknown`.

### Signals

- `EXAMPLE_ONLY` or template evidence → `template`;
- structurally absent capability → `template`;
- `UNKNOWN` or runtime-unverified evidence → `unknown`;
- persona signals, identity/self-evolution language, and memory/persistence
  intent without concrete operation evidence → `latent`;
- other `PRESENT` / `CONDITIONAL` static declarations → `active`.

This mapping intentionally prevents the following shortcuts:

- Internet declaration does not itself become a high-risk Finding;
- personality, identity initialization, or long-term-memory intent does not become
  an active operation;
- a tool note does not grant runtime tool authority;
- static `active` does not become `runtime_attested`.

## Output and authority boundary

The report is bound to the exact `homi-pilot-report.json` SHA-256 and contains no
raw source text, credential, URL, IP, avatar, or secret value. It always emits:

```json
{
  "report_only": true,
  "runtime_verified": false,
  "ci_blocked": false
}
```

The contract does not calculate risk scores. RISK-03 extracts Operation Context,
RISK-04 evaluates context-aware rules, and RISK-05 calculates residual risk.

## Verification

```text
RISK-02 tests: 4 passed
Homi Pilot / Operationality / Provenance targeted tests: 18 passed
Schema export: passed
Ruff check and format: passed for affected files
```

## Follow-up

- RISK-03：从 Adapter、Manifest、Diff 和安全边界证据提取 Operation Context；
- RISK-04：按 action、target、data、trigger、authorization、controls 和 impact
  组合确定性识别风险；
- RISK-05：将潜在影响、当前态势、控制有效性和漂移合成为可审计风险分。

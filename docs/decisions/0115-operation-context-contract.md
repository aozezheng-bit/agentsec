# ADR-0115：Operation Context Contract（RISK-01）

- Status: Accepted for `RISK-01`
- Date: 2026-09-03
- Scope: static, versioned operation-context input contract
- Supersedes: none
- Depends on: baseline Evidence/Confidence contracts and existing Homi report-only boundary

## Context

AgentSec must distinguish a capability declaration from a risky operation. Internet
access, long-term memory, persona text, and a Markdown file change are not
independent proof of a security problem. Risk depends on the operation's action,
target, data scope, trigger, purpose, authorization, controls, reversibility, and
scope.

The existing risk modules already provide Finding Confidence and NIST-style
Likelihood/Impact mapping, but they do not yet expose one strict input contract
for the operation context that later rules and scoring work will consume.

## Decision

Introduce a strict, immutable `OperationContext` contract under
`agentsec.risk.context` and a bounded `OperationContextSet` envelope.

The contract records:

- action (`read`, `write`, `send`, `execute`, `delete`, `schedule`, `store`,
  `modify_policy`, `modify_identity`, or `unknown`);
- target class (public web, external service, local/workspace/control file, user
  profile/mailbox, credential/secret, production system, tool/MCP registry, or
  `unknown`);
- data classification, sharing scope, and retention class;
- trigger/autonomy class and declared purpose;
- authorization and approval state;
- reversibility, blast-radius scope, and frequency;
- named control states for approval, consent, allowlisting, audit, retention,
  redaction, and rate limiting;
- value-minimized source Evidence with safe relative paths, optional line/field
  locations, content SHA-256, extraction method, and independent Evidence
  Confidence;
- explicit `complete`, `partial`, `needs_context`, or `unknown` status.

The contract is evidence input only. Its serialized authority fields are fixed to
`report_only=true`, `runtime_verified=false`, and `runtime_authority=false`.
It does not calculate a risk score, grant a runtime permission, call a Provider,
or execute any scanned content.

## Validation rules

1. `complete` cannot contain an unknown primary dimension: action, target, data
   classification, trigger, purpose, or authorization state.
2. `needs_context` and `unknown` must identify at least one unknown primary
   dimension.
3. Evidence paths are project-relative and never contain raw source excerpts.
4. Evidence IDs are deterministically bound to source path, optional field/line
   range, content digest, and extraction method.
5. Evidence rows and Operation Context rows are sorted and unique for stable
   serialization.
6. Approval fields cannot contradict the authorization state.
7. Confidence is preserved independently from future Severity or Risk Score.
8. Unknown is not normalized to absent and cannot be used as a safety pass.

## Consequences

### Positive

- Later rules can evaluate operations rather than merely seeing capability words.
- A public-web read, controlled preference store, scheduled mailbox read, and
  autonomous Secret send can be represented distinctly.
- Homi template/latent/active classification and later Drift scoring have a
  stable input seam.
- Snapshot/Diff code can use canonical Operation Context hashes without storing
  source secrets.
- Historical reports remain unchanged because RISK-01 adds a new versioned
  contract only.

### Trade-offs

- RISK-01 does not infer context from Markdown; RISK-03 owns extraction.
- A caller must explicitly mark incomplete context instead of silently filling
  unknown values.
- The contract has no numeric score yet; RISK-05 owns score semantics.

## Rejected alternatives

- **Capability name as risk:** rejects the required context distinction and
  causes template/beneficial-use false positives.
- **Free-form dictionaries:** make schemas, deterministic replay, and safe
  consumer validation unreliable.
- **Confidence-based score discounting:** could hide a severe consequence; keep
  Confidence separate from Severity and Score.
- **LLM-authored authority fields:** violates the established LLM evidence-only
  boundary.

## Follow-up

- `RISK-02` maps Homi files and signals to `template`, `latent`, and `active`.
- `RISK-03` extracts `OperationContext` from trusted Adapter/Manifest evidence.
- `RISK-04` consumes this contract in deterministic context-aware Rules.
- `RISK-05` calculates residual and drift risk without rewriting this input
  contract.

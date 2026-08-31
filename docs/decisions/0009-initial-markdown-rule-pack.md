# ADR-0009: Initial 15-Rule Markdown Pack and Rule Pack 0.2.0

- Status: Accepted
- Date: 2026-08-19
- Task: P1-20

## Context

Phase 1 requires 10–15 deterministic Markdown rules with positive and negative
tests. P1-17 through P1-19 established the Rule interface, bounded matchers,
per-rule isolation, Evidence materialization, and unscored Finding pipeline, but
the production Rule Pack remained empty.

The first pack must cover the scoped instruction, approval, execution, network,
secret, privilege, destructive, deployment, memory, self-modification,
obfuscation, and external-tooling signals. It must not execute referenced code,
decode suspicious content, access a URL, invent risk scores, or claim that a
static phrase proves runtime capability.

Adding concrete Rule IDs changes the meaning of `RULE_PACK_VERSION`. Existing
baselines and reports that record an empty `0.1.x` pack must be distinguishable
from assessments using the first real detection set.

## Decision

Publish 15 built-in Phase 1 Markdown Rules through
`builtin_markdown_rules()`:

```text
MD-INSTR-001
MD-INSTR-002
MD-APPROVAL-001
MD-EXEC-001
MD-EXEC-002
MD-NET-001
MD-SECRET-001
MD-PRIV-001
MD-PRIV-002
MD-DESTRUCT-001
MD-DEPLOY-001
MD-MEMORY-001
MD-SELF-001
MD-OBFUSC-001
MD-TOOL-001
```

Adopt these controls:

1. Export a canonical sorted `BUILTIN_MARKDOWN_RULE_IDS` tuple and count.
2. Construct a fresh immutable Rule tuple and verify it matches the canonical ID
   list exactly.
3. Use phrase-oriented case-insensitive Keyword rules rather than broad
   single-word matching where possible.
4. Use only the already approved bounded Regex dialect for dynamic execution and
   destructive-command patterns.
5. Let instruction, approval, memory, and self-modification rules inspect prose
   blocks; let capability/action rules also inspect code blocks.
6. Compose direct and URL-supported transfer delegates under one `MD-NET-001`
   identity without network access.
7. Map Base64-like, zero-width, bidi, control, and mixed-script parser indicators
   to `MD-OBFUSC-001`; exclude long-line and long-block indicators.
8. Do not decode or copy suspicious obfuscated tokens into rule evidence.
9. Match external-tool phrases and executable file extensions for
   `MD-TOOL-001` without dereferencing, importing, downloading, or executing the
   target.
10. Keep different Rule IDs separate even when they match the same source line.
11. Require every Rule ID to have a positive and negative test plus direct
    Evidence assertions.
12. Align existing testdata manifests to stable expected Rule IDs and require the
    `rule_ids` field in the fixture schema.
13. Preserve unscored output; likelihood, impact, severity, confidence, and hard
    gates remain later tasks.
14. Do not wire final Findings into `agentsec scan` until real scoring and
    confidence can satisfy the existing Domain Finding contract.
15. Document phrase-based false-positive and false-negative boundaries and never
    present a match as proof of exploitability.

Increment:

```text
RULE_PACK_VERSION: 0.1.0 → 0.2.0
```

Keep Domain Schema and Risk Model versions unchanged.

## Consequences

### Positive

- AgentSec now has a complete, explainable initial detection set.
- Every in-scope risk category has at least one production Rule ID.
- Existing risky and prompt-injection fixtures produce stable expected IDs.
- Safe fixtures remain clean under the full pack.
- Obfuscation and executable references use parser evidence without executing
  untrusted content.
- Baseline provenance can distinguish the empty pack from the first production
  pack.

### Negative

- Phrase matching can flag quoted, prohibited, or educational examples.
- Physical-line matching misses paraphrases and phrases split by markup or line
  breaks.
- Production, secret, deployment, and command documentation can require human
  triage.
- The pack does not analyze structured configuration formats or runtime
  permissions.
- `agentsec scan` still cannot emit final scored Findings until P1-21 through
  P1-23 are complete.
- Because this is pre-1.0, consumers supporting only Rule Pack `0.1.x` must treat
  `0.2.0` as potentially incompatible.

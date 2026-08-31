# ADR-0017: Bilingual Chinese/English Markdown Rule Pack 0.3.0

- Status: Accepted
- Date: 2026-08-20
- Task: M1-01

## Context

AgentSec 0.1.0 shipped Rule Pack 0.2.0 with 15 stable Markdown Rule IDs. The
implementation contained a small number of Chinese trigger phrases, but the
reviewed positive/negative suite, corpus, release story, and inventory output
were predominantly English. This made Chinese Agent projects difficult to
evaluate and made the Demo less representative for Chinese-speaking users.

Adding Chinese phrases to existing Rule IDs expands their trigger set without
changing the underlying risk meaning. It can change Findings for identical
Chinese Markdown, so the behavior must not continue to identify itself as Rule
Pack 0.2.0.

The extension must remain deterministic. It must not add language detection,
translation services, an LLM, network access, execution, or runtime capability
claims. Chinese prohibitions and quotations remain subject to the same known
lexical false-positive boundary as English content.

## Decision

1. Preserve the existing 15 Rule IDs and their risk meanings.
2. Expand their reviewed phrase sets with common Simplified Chinese expressions
   for instruction override, safety bypass, approval weakening, execution,
   network, secret, privilege, destructive action, deployment, memory,
   self-modification, and external tooling.
3. Continue using parser indicators rather than language-specific text for
   `MD-OBFUSC-001`.
4. Add one Chinese positive and one Chinese benign negative regression for every
   Rule ID.
5. Add five inert Chinese corpus Cases, keeping the total bounded at 45 Cases.
6. Add a Chinese Release Agent Demo with the same accepted result shape as the
   English story: 2 modified Assets, 10 Findings, 9 unique Rule IDs, highest
   High, report-only exit `0`, incomplete Coverage exit `2`, and zero Findings
   after remediation.
7. Add `agentsec rules list --language zh` as display-only localization. Stable
   Rule IDs, categories, risk mappings, Finding metadata, and serialized schemas
   remain unchanged.
8. Keep English as the default inventory language and preserve the accepted
   English Demo and frozen 0.1.0 artifacts.
9. Increment:

```text
RULE_PACK_VERSION: 0.2.0 → 0.3.0
```

10. Keep Package, Config Schema, Domain Schema, Baseline Schema, Diff Output,
    Assessment Output, and Risk Model versions unchanged. The local source tree
    is post-0.1.0 work; existing `dist/` files remain the frozen 0.1.0 release
    until a separate release task rebuilds them.

## Consequences

### Positive

- All 15 Rules have explicit Chinese source-backed positive coverage.
- Chinese users can inspect a localized Rule inventory without changing stable
  IDs or machine-readable output.
- The Chinese Demo presents direct Chinese file and line Evidence.
- English detection and the report-only/non-execution policy remain unchanged.
- Rule Pack provenance distinguishes pre-localization and bilingual results.

### Negative

- Phrase-based Chinese detection still misses paraphrases and implicit meaning.
- Chinese negative, quoted, or educational text containing a direct trigger may
  require human triage.
- Finding titles, descriptions, recommendations, and JSON metadata remain the
  canonical English values; only the inventory display and Demo narration are
  localized in this maintenance task.
- Existing 0.1.0 wheel and sdist do not contain this source extension and must
  not be represented as Rule Pack 0.3.0 artifacts.

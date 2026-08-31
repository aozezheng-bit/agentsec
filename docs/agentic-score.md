# Integrated Agentic Score CLI and Report

- Task: `P2-EXIT-03`
- Status: Complete
- Completion date: 2026-08-25
- Package: `0.3.0 → 0.4.0.dev0` (development line toward the 0.4.0 Phase 3
  Ready Candidate)
- Agentic Assessment Output: `0.1.0` (`agentsec-agentic-assessment`)
- Score Context Schema: `0.1.0` (`agentsec-score-context`)

## Purpose

P2-18 through P2-23 delivered the Agentic Factor, Threat/Mitigation,
Technical, Drift, Governance, and Overall scoring engines, and P2-24 made the
chain replayable. P2-EXIT-03 exposes the complete chain through one additive
CLI command without changing existing command semantics:

```bash
agentsec score PROJECT --before BEFORE-MANIFEST.json [--context CONTEXT.json] \
  [--agent-id ID] [--format text|json|sarif] [--language en|zh]
```

- `agentsec capability assess` and all other commands keep their current
  behavior (Option B from the P2-EXIT plan);
- the score is report-only: it never gains CI authority and never changes
  exit-code policy beyond the standard incomplete-coverage fail-closed
  behavior.

## Explicit inputs (no fabrication)

Drift and Governance semantics must come from reviewed evidence. They are
never inferred:

| Input | Source | Required |
|---|---|---|
| before-state Manifest | `--before` validated Manifest JSON | yes |
| after-state Manifest | live analysis of `PROJECT` (same pipeline) | yes |
| change source / approval status / approval reference / deployment scope / baseline trust | `--context` drift block | no (default: conservative `unknown`) |
| review status / policy owner / approval owner / waiver counts | `--context` governance block | no (default: conservative `unknown`) |
| CVSS base vector | `--context` cvss block | no |
| accepted deterministic Gate matches | `--context` gate_matches block | no |

`--context` accepts `agentsec-score-context` `0.1.0` JSON:

```json
{
  "format": "agentsec-score-context",
  "schema_version": "0.1.0",
  "drift": {
    "change_source": "reviewed_change",
    "approval_status": "approved",
    "approval_reference": "approval-2026-001",
    "deployment_scope": "development",
    "baseline_trust": "hash_only"
  },
  "governance": {
    "review_status": "reviewed",
    "policy_owner": "security-team",
    "approval_owner": "release-owner",
    "waiver_count": 1,
    "expired_waiver_count": 0
  },
  "cvss": {"vector": "CVSS:4.0/..."},
  "gate_matches": [
    {
      "gate_id": "HG-CAPCHAIN-001",
      "floor": "critical",
      "source": "capability",
      "evidence_ids": ["capability-finding-sha256:..."],
      "confidence": "A",
      "rationale": ["Reviewed chain evidence."]
    }
  ]
}
```

Validation is strict: unknown fields, duplicate JSON keys, symlinks,
oversized files, invalid digests/enums, D-confidence Gate matches, and
malformed CVSS vectors fail closed with exit `3`.

## Scoring chain

```text
Manifest analysis (Codex pipeline)
→ Agentic Factor extraction
→ Threat / Mitigation evaluation
→ optional CVSS base high-water mark
→ Capability Diff (before vs after)
→ Drift Score (explicit drift context)
→ Governance Score (explicit governance context)
→ Overall Score = high-water base, plus qualified Hard Gate floor
```

Gate floors are accepted deterministic matches only (qualification
`accepted`, confidence A/B/C; D-confidence evidence is rejected). Floors
raise the Overall score report-only; they never block CI.

## Reports

`agentsec-agentic-assessment` `0.1.0` JSON records:

- agent identity and before/after Manifest SHA-256;
- context provenance (`supplied`, `sha256`);
- Coverage completeness and relevant Unknown count;
- complete Factor vector, Threat/Mitigation vector, and all component
  assessments (technical/drift/governance/overall) with model versions;
- CVSS assessment and accepted Gate matches;
- policy block: `report_only=true`, `ci_blocking_enabled=false`,
  `score_ci_authority=false`;
- boundary block and the complete product version vector.

Text output is bilingual (en/zh); SARIF output is SARIF 2.1.0 with
`agentsecReportKind: agentic_assessment` and report-only invocation
properties. Artifacts written with `--output` go through the restricted
atomic writer (`ReportArtifactKind.AGENTIC_ASSESSMENT`).

Frozen Schemas:

```text
schemas/agentic-assessment/agentic-assessment.schema.json
schemas/score-context/score-context.schema.json
```

## Exit codes

| Condition | Exit |
|---|---:|
| Scoring completed (complete analysis) | `0` |
| Analysis coverage incomplete (score still rendered conservatively) | `2` |
| Context invalid, bad CVSS vector, D-confidence Gate match | `3` |
| `--before` Manifest missing/invalid or incompatible with after Manifest | `4` |
| Required analysis failure | `5` |

## Boundaries

- LLM output plays no role; runtime capability is not verified;
- scanned content is never executed; context loading is bounded, no-follow,
  UTF-8, duplicate-key-safe JSON;
- the Overall score and floors are evidence for humans and Policy review,
  not CI authority (P2-EXIT-08 keeps enforcement on the deterministic
  Policy/Gate path);
- replay semantics are unchanged: the frozen scoring replay suite was
  re-baselined only for the package-version provenance change, consistent
  with the P2-32 precedent.

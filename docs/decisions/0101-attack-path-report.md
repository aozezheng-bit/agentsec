# ADR-0101: Attack Path Report

- Status: Accepted
- Date: 2026-08-31
- Task: P3-AG-04
- Scope: value-free Text/JSON reporting of matched static Attack Paths

## Context

P3-AG-01 (ADR-0093) froze the graph contract, P3-AG-02 (ADR-0097) built it
from Manifests, and P3-AG-03 (ADR-0099) matched seven static Attack Path
patterns. The roadmap erratum requires the next step: a Text/JSON attack
path report that shows the paths, their evidence, risk, and limitations
without ever claiming runtime exploitability.

The report sits at the trust hand-off between the deterministic graph chain
and human reviewers or, later, the Semantic/Deterministic Evidence
Association (P3-AG-05). A careless design could smuggle node labels,
Manifest references, or raw scanned values into the report, or let a
consumer treat a matched path as a Finding with severity and CI power.

## Decision

1. Add the frozen `agentsec-attack-path-report` `0.1.0` contract
   (`agentsec.attack_graph.report`, `ATTACK_PATH_REPORT_VERSION`):
   - every entry is `(path_id, pattern_id, path_kind, node/edge counts,
     node kind sequence, node content-addressed IDs)` with fixed
     `runtime_verified=false`, `reachability=not_proven`,
     `exploitability=not_proven`; entry-level cross-field coherence
     (counts vs sequence lengths) is enforced by validator;
   - the report header binds to the source of truth via
     `manifest_schema_version`, `manifest_sha256`,
     `canonical_attack_graph_sha256(graph)`, the exact
     `pattern_library_version`, `path_count == len(entries)`, and
     entries sorted by unique `path_id`; non-empty reports must carry
     disclosed `limitations`.
2. `build_attack_path_report(graph)` is the only producer: fails closed on
   non-`CapabilityAttackGraph` input and derives every field from the
   validated graph rather than trusting caller-supplied data.
3. Rendering:
   - `render_attack_path_report_text(report)` prints the header, one
     bounded line per path (`pattern_id` plus the node-kind chain), and
     fixed boundary lines; no node labels, Manifest references, asset
     digests, or excerpts appear in the text;
   - `encode_attack_path_report_json(report)` emits canonical
     deterministic JSON (`sort_keys`, indent 2) that round-trips through
     `AttackPathReport.model_validate`.
4. Export the frozen JSON Schema
   (`schemas/attack-graph/attack-path-report.schema.json`) and register
   ownership in `schema_file_ownership()`; the report entry joins the
   provenance registry in the report family with
   `ATTACK_PATH_REPORT_VERSION`.
5. Fixed authority booleans on the report: `report_only=true`,
   `blocks=false`, `finding_authority=false`,
   `rule_publication_authority=false`, `policy_authority=false`,
   `ci_authority=false`, `hard_gate_authority=false`,
   `release_authority=false`, `runtime_verified=false`, and a dedicated
   `exploitability_claimed=false` literal.
6. The report intentionally omits severity, likelihood, confidence,
   recommendations, and Evidence line ranges: those are P3-AG-05/07
   concerns and would start this report down the path of competing with
   deterministic Findings, which it must never do.

## Authority boundary

A matched Attack Path, and any report over it, is deterministic evidence
about disclosed static declarations. It remains:

```text
report_only=true, blocks=false
finding/rule/policy/ci/hard-gate/release authority=false
runtime_verified=false
exploitability_claimed=false
```

## Consequences

### Positive

- Consumers get a stable, reviewable Text/JSON surface with the boundary
  always rendered first alongside a fixed limitations block.
- Binding via manifest and graph digests lets a reviewer re-derive the
  full graph and re-run the matcher to verify the entry list.
- The same graph yields byte-identical report JSON, enabling graph-to-
  graph diffing during remediation reviews.
- Value-free entries mean the report can be archived without
  declassification or secret-review concerns.

### Trade-offs

- No severity or confidence in this report: deliberately deferred to
  Finding-level integration (P3-AG-05/07) after review.
- Node labels and Manifest references are absent; reviewers must keep
  the source graph JSON alongside the report to resolve identity.
- The 256-entry cap follows the graph's path bound and is enforced
  upstream by ADR-0099's fail-closed bounds.

## Rejected alternatives

- Include severity/risk scoring in the report: rejected; the roadmap
  requires findings/severity only as a later reviewed association, and
  in-surface scoring would tempt readers to treat this as a risk
  assessment rather than a structural disclosure.
- Reuse semantic report templates: rejected; this is a deterministic
  graph artifact and needs its own contract.
- Emit node labels or Manifest references: rejected; risk of
  over-disclosure at the trust boundary (report-only artifact).
- Allow caller-supplied entries without revalidation: rejected; the builder
  path is the only way to guarantee graph-entry consistency.

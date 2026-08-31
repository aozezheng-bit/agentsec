# ADR-0057: Organization-Level YAML Policy 0.1.0

- Status: Accepted
- Date: 2026-08-25
- Task: P2-27

## Context

P2-26 requires operators to repeat `--fail-on`, while P2-15B uses a separate
Capability JSON Policy. P2-27 requires one organization Policy that can
configure deterministic Rules and qualified Gates without allowing project
content, LLM output, or runtime-unverified claims to control CI.

## Decision

1. Add explicit `agentsec-organization-policy` YAML Schema `0.1.0`.
2. Require explicit `--policy`; never auto-discover Policy from the scanned
   project.
3. Configure Scan `high|critical` plus optional blocking Rule IDs. Rule scope
   affects blocking only, never Finding generation.
4. Configure Capability qualified Gate IDs and adapt them to the existing
   Qualification-aware enforcement engine.
5. Reject `scan --policy` combined with `--fail-on`.
6. Require complete Coverage. Unknown-free Capability behavior remains explicit.
7. Reject aliases, anchors, tags, duplicate keys, unknown fields/IDs, symlinks,
   non-YAML suffixes, oversized files, invalid UTF-8, and unsafe authority.
8. Record Policy ID/version/source SHA-256 in JSON, SARIF, and Capability CI
   provenance.
9. Add `agentsec-organization-policy-assessment` Output `0.1.0` with strict
   recomputation validation.
10. Advance SARIF Reporter `0.2.0 → 0.3.0` and Capability CI Report Output
    `0.1.0 → 0.2.0`.
11. Keep Config, Domain, Assessment, Rule Pack, Risk Model, Fail-On, CVSS, and
    Capability Rule/Gate meanings unchanged.
12. Defer waivers to P2-28.

## Consequences

Organizations can keep one reviewable Policy file for Scan and Capability CI.
Default/report-only mode remains available, and a Policy cannot suppress
Findings. The trade-off is that P2-27 supports only local explicit YAML and one
currently qualified Capability Gate; broader policy distribution and waivers
remain separate tasks.

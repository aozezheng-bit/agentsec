# AgentSec Organization Policy

- Task: `P2-27`
- Status: Complete
- Completion date: 2026-08-25
- Policy Schema: `0.3.0`
- Assessment Report Output: `0.3.0`
- Decision: `docs/decisions/0057-organization-policy-yaml.md`;
  `docs/decisions/0062-trusted-policy-and-qualification-root.md`
  (P2-EXIT-01/P2-EXIT-02 trust amendments)

## Purpose

P2-27 adds one explicit organization-level YAML Policy shared by Scan and
Capability CI enforcement. It configures blocking scope without disabling
Findings or changing Rule behavior.

```bash
agentsec scan PROJECT --policy policies/organization-policy.yaml
agentsec capability enforce PROJECT \
  --policy policies/organization-policy.yaml
```

No organization Policy is discovered from scanned project content. The file
must be supplied explicitly. `scan --policy` and `scan --fail-on` are mutually
exclusive.

## YAML contract

```yaml
format: agentsec-organization-policy
schema_version: "0.3.0"
policy_id: org-default-agentsec
policy_version: "0.1.0"
enabled: true
enforcement_mode: enforce
scan:
  fail_on: high
  blocking_rule_ids:
    - MD-EXEC-001
    - MD-SECRET-001
capability:
  qualified_gates:
    - HG-CAPCHAIN-001
  qualification:
    registry_path: ../calibration/p2-15a-capchain-40/human-evidence/qualified-gate-registry.yaml
    registry_sha256: "19cc7f19b63b01b4479ecdd92da53c6bc5d3dae2a0985b5903bd77f4e4bfabfd"
coverage:
  require_complete: true
  require_unknown_free: true
safety:
  allow_llm_authority: false
  allow_runtime_unverified_authority: false
```

`blocking_rule_ids: []` means every built-in Markdown Rule is eligible for the
selected threshold. A non-empty list narrows CI blocking only; it never disables
detection or removes Findings from reports.

Only built-in stable Rule IDs and currently supported qualified Gate IDs are
accepted. Unknown or duplicate IDs fail before analysis with exit `3`.

## Scan decisions

```text
enabled=false or mode=report_only → report matches, exit 0
mode=enforce + configured threshold/rule match → exit 1
complete + no eligible match → exit 0
incomplete Coverage → exit 2, never overridden
```

Policy thresholds remain `high|critical` and use AgentSec Finding Severity.
Confidence, SARIF level, CVSS, LLM output, and runtime state have no authority.

JSON output uses:

```text
format = agentsec-organization-policy-assessment
format_version = 0.1.0
```

It embeds the normalized Policy plus source SHA-256, a recomputable decision,
and the canonical sanitized Assessment. Tampered decisions are rejected.

SARIF Reporter `0.4.0` records Policy ID/version/hash, threshold, Rule scope,
decision, exit code, matched Finding IDs, and per-Result match state.

## Capability integration

`capability enforce --policy` accepts either:

```text
agentsec-capability-ci-policy JSON 0.2.0
organization-level YAML Policy 0.3.0
```

Since P2-EXIT-02, the organization YAML Schema `0.3.0` carries the same
`capability.qualification` registry binding as the JSON Capability Policy
(see the YAML contract above). Organization Policies that list Capability
Gates without this binding fail closed at policy load with exit `3`. Both
paths verify Gate authority through the full evidence-binding chain: policy
digest pin, registry digest pin, qualification report digest pin, and
recomputed artifact IDs. Gates cannot bypass Human Qualification,
Coverage/Unknown requirements, or the allow-list of supported Gates.

Capability CI Report Output is `0.5.0` and records Policy source format,
schema version, SHA-256, qualification registry provenance, and CI trust
provenance. See `docs/trusted-ci.md` for `--trust-root` and
`--expect-policy-sha256` / `--expect-registry-sha256`.

## Safe loading

Organization Policy input is:

- explicit `.yaml`/`.yml` only;
- bounded to 2 MiB;
- regular-file and no-follow read;
- strict UTF-8;
- exactly one YAML mapping;
- aliases, anchors, explicit tags, duplicate keys, unknown fields, unsafe
  authority, unknown Rules, and unknown Gates are rejected;
- no environment interpolation, network retrieval, or scanned-code execution.

Frozen Schemas:

```text
schemas/policy/organization-policy.schema.json
schemas/policy/organization-assessment-report.schema.json
```

Examples:

```text
policies/organization-policy.yaml
policies/organization-policy-enforce-example.yaml
```

## Deferred

P2-27 does not implement waivers, Owner/reason/expiry, branch-specific Policy,
remote Policy retrieval, CVSS thresholds, Overall Score thresholds, or runtime
verification. P2-28 now adds expiring Owner/Reason/Expiry Waivers; see `docs/risk-waivers.md`.

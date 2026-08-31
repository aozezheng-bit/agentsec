# AgentSec Deterministic Capability Rules

- Tasks: `P2I-02`, `P2-14`
- Status: Complete through P2-14 in source tree
- Completion date: 2026-08-20
- Capability Rule Pack: `0.2.0`
- Capability Risk Model: `0.1.0`
- Decisions:
  - `docs/decisions/0029-capability-rule-pack-risk-model.md`
  - `docs/decisions/0034-capability-rule-pack-0.2.0.md`
- Release boundary: source development; not included in accepted `dist/0.2.0`

## 1. Purpose

The Capability Rule layer evaluates the finalized Agent Manifest with
framework-neutral deterministic rules. It detects security-relevant combinations
of normalized tools, permissions, controls, identities, relationships, Coverage,
and Unknowns without reading source files again.

```text
AgentAnalysisPipeline
→ final AgentManifest
→ CapabilityRuleContext
→ DeterministicCapabilityRuleRunner
→ CapabilityRuleFinding / safe Rule failures
```

The Rule layer is separate from the Phase 1 Markdown `RuleContext`. It does not
change `agentsec scan`, and it does not require an LLM.

## 2. Public API

```python
from agentsec.capability_rules import (
    DeterministicCapabilityRuleRunner,
    builtin_capability_rules,
)

result = DeterministicCapabilityRuleRunner(builtin_capability_rules()).run(
    final_manifest
)

findings = result.findings
failures = result.failures
complete = result.complete
```

The runner consumes only a strict `AgentManifest`. It has no project-root
reader, command runner, environment reader, network client, MCP client,
memory-store client, import hook, or LLM dependency.

## 3. Context indexes

`CapabilityRuleContext.from_manifest()` creates immutable deterministic indexes:

```text
tools_by_id
permissions_by_target
controls_by_target
identities_by_tool
child_tools_by_parent
relations_by_kind
unknowns_by_dimension
sources_by_locator
```

Child tools inherit parent controls only for correlation. The context never
opens or dereferences the path represented by a Manifest source locator.

## 4. Correlation policy

Correlation prevents unrelated capabilities from being combined blindly:

| Correlation | Meaning | Confidence | Static likelihood |
|---|---|---|---|
| `same_target` | Facts use one Tool or policy target | B | Moderate |
| `parent_child` | Facts belong to one MCP parent/child family | C | Moderate |
| `same_source` | Facts share one reviewed declaration source | C | Moderate |
| `explicit_relation` | A typed Manifest relationship joins facts | C | Moderate |
| `agent_wide` | Facts coexist but reachability is unverified | D | Low |
| `incomplete_coverage` | Coverage or a relevant dimension is unresolved | D | Low |

P2-14 uses same-target, parent/child, explicit-relation, Agent-wide, and
incomplete correlations. Agent-wide combination Rules emit one bounded candidate
rather than a global Cartesian product.

Confidence is not multiplied into score or Severity. Correlation selects the
reviewed static likelihood because it represents a reachability precondition;
Confidence remains an independent evidence-quality statement.

## 5. Risk calculation

Each Rule has a trusted impact vector. Overall impact is the maximum dimension,
never an average:

```text
Impact = max(confidentiality, integrity, availability,
             safety, business/compliance, downstream blast radius)
```

The engine continues to use:

```text
NIST SP 800-30 Rev. 1 likelihood-impact matrix
FIPS 199 high-water-mark principle adapted to AgentSec impact
AgentSec representative 0–10 scores
FIRST CVSS v4.0 qualitative Severity ranges
```

The independent version remains:

```text
CAPABILITY_RISK_MODEL_VERSION = 0.1.0
```

No Finding is averaged with another Finding. A High result cannot be diluted by
many lower-severity Findings.

## 6. Rule Pack 0.2.0 inventory

The pack contains 29 stable Rules: the original six plus 23 P2-14 additions.

### 6.1 Core combination and coverage Rules

| Rule ID | Deterministic condition |
|---|---|
| `CAP-APPROVAL-001` | State-changing permission without prompt or deny approval |
| `CAP-CHAIN-001` | Execute + secret access + external network |
| `CAP-COVERAGE-001` | High-impact permission/relation under incomplete Coverage or relevant Unknown |
| `CAP-DELEGATE-001` | Delegation + powerful unapproved capability |
| `CAP-EXTERNAL-001` | Enabled required external MCP + credentialed identity |
| `CAP-PERSIST-001` | Persistent memory + sensitive capability |

### 6.2 Production and external-scope Rules

| Rule ID | Deterministic condition |
|---|---|
| `CAP-PRODWRITE-001` | Production-scoped write permission |
| `CAP-PRODEXEC-001` | Production-scoped execute permission |
| `CAP-PRODADMIN-001` | Production-scoped admin permission |
| `CAP-SECRETPROD-001` | Production-scoped secret access |
| `CAP-PRODIDENTITY-001` | Production state change + external/session-backed identity |
| `CAP-EXTERNALWRITE-001` | External-scoped write permission |
| `CAP-EXTERNALEXEC-001` | External-scoped execute permission |

### 6.3 Approval and guardrail Rules

| Rule ID | Deterministic condition |
|---|---|
| `CAP-AUTOSECRET-001` | Secret access with effective allow approval state |
| `CAP-AUTONETWORK-001` | Network access with effective allow approval state |
| `CAP-AUTOPROD-001` | Production state change with effective allow approval state |
| `CAP-NOSANDBOX-001` | High-impact capability without configured/enabled sandbox |
| `CAP-NONETWORKPOLICY-001` | External network permission without configured network policy |
| `CAP-NOSECRET-001` | Secret access without configured secret-handling control |
| `CAP-REQUIREDNOTIMEOUT-001` | Enabled required MCP without timeout control |
| `CAP-REQUIREDNOFILTER-001` | Enabled required MCP family without tool filter |

A missing control is a review signal, not proof that a runtime guardrail is
absent. Explicit safe states suppress the corresponding gap Rule; absent,
disabled, or Unknown states remain visible.

### 6.4 External identity Rules

| Rule ID | Deterministic condition |
|---|---|
| `CAP-EXTERNALUNVERIFIED-001` | External MCP identity/availability still requires runtime verification |
| `CAP-EXTERNALPRIVILEGED-001` | External MCP identity has `privileged=true` |

These Rules do not inspect OAuth scopes, active sessions, credential values, or
runtime grants.

### 6.5 Memory, delegation, and relationship Rules

| Rule ID | Deterministic condition |
|---|---|
| `CAP-MEMORYSECRET-001` | Memory read/write/persist relation + secret access |
| `CAP-MEMORYNETWORK-001` | Memory read/write/persist relation + network access |
| `CAP-MEMORYPROD-001` | Memory relation + production write/admin/deploy/publish |
| `CAP-DELEGATEPERSIST-001` | Delegation + persistent memory |
| `CAP-DELEGATEEXTERNAL-001` | Delegation + external network/write/execute/admin |
| `CAP-RELATIONUNKNOWN-001` | Unknown high-impact delegation or memory relation |

When no exact relationship-to-permission target match exists, these combination
Rules use one Agent-wide D-confidence Finding with an explicit reachability
limitation.

## 7. Finding evidence

Capability Findings contain value-free evidence only:

```text
scope
root_id
relative path
field_path
start_line / end_line
content_sha256
```

The source hash is resolved from `AgentManifest.sources`; Rules cannot choose a
hash or absolute host path. Finding IDs hash Rule ID, correlation, related IDs,
and evidence locators without plaintext source values.

## 8. Localization

Every Rule contains trusted English and Simplified Chinese:

```text
title
description
recommendations
```

Localization affects presentation only. Rule conditions, Finding identity,
impact, likelihood, Confidence, score, and Severity remain identical.

## 9. Failure and determinism

The runner:

- validates and sorts the trusted Rule registry;
- rejects duplicate Rule IDs;
- validates bounded, sorted, unique candidates;
- materializes one Rule atomically;
- isolates a failed Rule without discarding other Findings;
- exposes only the stable failed Rule ID;
- produces deterministic Finding and failure ordering;
- emits no partial Findings from a failed Rule.

`result.complete=false` means at least one registered Rule failed. It is separate
from Manifest Coverage completeness.

## 10. Report-only boundary

Rule Pack `0.2.0` always produces:

```text
deterministic=true
hard_gate=false
CI blocking=false
runtime capability verified=false
```

P2-14 does not add `--fail-on`, CI risk blocking, production authorization,
waivers, runtime Tool/OAuth/Permission verification, LLM analysis, automatic
Rule publication, or runtime vulnerability proof. P2-15 owns the next reviewed
report-only Capability Hard Gate design.

## 11. Security boundary

Capability Rules never:

- open a Manifest source path;
- execute a Command, Hook, Skill, plugin, Sub-Agent, Rule, or MCP server;
- contact an endpoint;
- read environment, Header, token, credential, or memory values;
- serialize parsed Command or URL values into evidence;
- call an LLM;
- change Phase 1 Rule Pack, Risk Model, or enforcement behavior.

## 12. Verification

`tests/test_capability_rules.py` covers:

- Rule Pack `0.2.0`, 29 stable unique IDs, and bilingual metadata;
- same-target, parent/child, explicit-relation, Agent-wide, and incomplete
  correlations;
- production, external, approval, control-gap, identity, memory, delegation,
  and relationship-Unknown examples;
- benign no-capability behavior and explicit safe control states;
- value-free hash-backed evidence and secret/endpoint omission;
- deterministic ordering and bounded Agent-wide combinations;
- per-Rule and atomic materialization failure isolation;
- report-only behavior and Severity/Confidence separation.

The English and Chinese Capability Drift Demo fixtures are regenerated with Rule
Pack `0.2.0`. The risky scenario now produces 17 Findings across 16 Rule IDs,
while baseline and remediated scenarios remain at zero Findings.

## 13. Release boundary and next task

The accepted local `dist/0.2.0` artifacts remain frozen with Rule Pack `0.1.0`
and six Rules. P2-14 is source-tree development and must ship only after a new
Package release review.

Next: `P2-CAL-01～04` calibrates false positives, false negatives, and
Evidence Confidence. Only calibrated candidates may enter `P2-15A` Report-only
Capability Hard Gates. `P2-15B` Policy-controlled CI Enforcement remains a later,
default-off track after Pilot and waiver/policy acceptance.

# P2-21：CVSS Temporal / Environmental / Threat / Supplemental

- Task: `P2-21`
- Status: Complete for source development
- CVSS Adapter: `0.3.0`
- Domain Schema: `0.6.0`
- Assessment Output: `0.5.0`
- Depends on: `P2-20`
- ADR: `docs/decisions/0044-cvss-extended-metrics.md`

## 1. Scope

P2-21 extends the CVSS adapter beyond Base Metrics while keeping the Base Score
and the effective extended score visibly separate.

Supported extensions:

```text
CVSS v3.1:
  Temporal Metrics
  Environmental Metrics

CVSS v4.0:
  Threat Metrics
  Environmental Metrics
  Supplemental Metrics
```

The adapter still accepts one canonical vector and calculates all applicable
score views locally.

## 2. Score views

`CvssBaseAssessment` now exposes:

```text
base_score
severity                 Base Severity
effective_score          highest applicable extended score
effective_severity      Severity of effective_score
score_type               base / temporal / environmental / threat / environmental_threat
```

Examples:

```text
Base only                         score_type=base
v3.1 E/RL/RC                     score_type=temporal
v3.1 modified/environmental     score_type=environmental
v4.0 E                           score_type=threat
v4.0 modified metrics            score_type=environmental
v4.0 modified metrics + E       score_type=environmental_threat
v4.0 Supplemental only           score_type=base
```

The Base Score is never overwritten. If an extended score is present, it is
reported as `effective_score`.

## 3. CVSS v3.1

Supported optional metrics:

```text
E RL RC
CR IR AR
MAV MAC MPR MUI MS MC MI MA
```

The adapter calculates:

- Base Score from Base Metrics;
- Temporal Score when Temporal Metrics are supplied;
- Environmental Score when Environmental Metrics are supplied;
- combined Environmental Score includes the Temporal multipliers when present.

Explicit `X` values use the CVSS unspecified/default semantics.

## 4. CVSS v4.0

Supported optional metrics:

```text
Threat:
  E

Environmental:
  CR IR AR
  MAV MAC MAT MPR MUI
  MVC MVI MVA MSC MSI MSA

Supplemental:
  S AU R V RE U
```

Threat and Environmental inputs are passed through the local v4.0 MacroVector
calculator. Supplemental Metrics are preserved as validated report data but do
not change the numeric score in this task.

The v4.0 Base-only defaults remain:

```text
E  = A
CR = H
IR = H
AR = H
```

## 5. Input contract

The JSON/Mapping accepts:

```json
{
  "vector": "CVSS:4.0/.../E:P/MVC:L",
  "base_score": 9.3,
  "base_severity": "critical",
  "score": 8.9,
  "severity": "high"
}
```

`base_score` / `base_severity` verify the Base view. `score` / `severity` verify
the effective extended view. All values are optional because the adapter
calculates them locally.

A mismatch fails closed with a stable adapter error.

## 6. Finding and Report integration

The existing nested Finding object now carries:

```text
cvss.base_score
cvss.base_severity
cvss.effective_score
cvss.effective_severity
cvss.score_type
cvss.metrics
```

Text Reports add these rows for extended scores:

```text
CVSS Effective      8.9 (HIGH)
CVSS Score Type     threat
```

JSON Reports retain the complete normalized metrics and score provenance under:

```text
assessment.findings[].cvss
```

## 7. Safety and non-goals

P2-21:

- performs no network access;
- executes no scanned code;
- does not call an LLM, MCP, or runtime Agent;
- does not infer metrics from untrusted text;
- does not change AgentSec score, Severity, Confidence, or Hard Gate;
- does not activate CVSS-driven CI Blocking;
- does not implement CVE/CWE database lookup;
- does not implement runtime exploitability verification.

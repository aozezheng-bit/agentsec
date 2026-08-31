# P2-17 CVSS Base Input Adapter

- Task: `P2-17`
- Status: Complete for source development
- Adapter version: `0.3.0`
- Scope: CVSS Base input normalization and validation

## 1. Purpose

The adapter lets AgentSec reuse a conventional vulnerability's CVSS Base
result without pretending that CVSS is the same thing as the AgentSec
NIST-style static Agent risk score.

The boundary is explicit:

```text
external CVSS Base input
→ strict vector and score validation
→ CvssBaseAssessment
```

The output is an independent assessment. It is not written into
`RiskAssessment.score`, is not averaged with the AgentSec score, and does not
change Capability Risk Model `0.1.0`.

## 2. Supported input contract

The adapter accepts either a Python mapping, `CvssBaseInput`, or one JSON object:

```json
{
  "version": "3.1",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "base_score": 9.8,
  "base_severity": "CRITICAL"
}
```

`vector` is required. `version` is optional and, when present, must match the
vector prefix. `base_score` and `base_severity` are optional for CVSS v3.1;
when omitted, the adapter calculates the v3.1 Base Score and derives Severity.

The accepted Base vector forms are:

- CVSS v3.1: `AV/AC/PR/UI/S/C/I/A`;
- CVSS v4.0: `AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA`.

Only Base Metrics are accepted. CVSS v3.1 Temporal/Environmental metrics and
CVSS v4.0 Threat/Environmental/Supplemental metrics are rejected because this
task does not silently reinterpret a non-Base score as a Base score.

## 3. Verification semantics

### CVSS v3.1

The adapter implements the FIRST CVSS v3.1 Base Score formula. A provided score
must equal the calculated score, and a provided Severity must match the score
range. The result has:

```text
score_verification = "calculated"
```

### CVSS v4.0

The adapter now implements the CVSS v4.0 Base Score MacroVector calculation
locally. It validates the complete Base vector, applies the v4.0 Base defaults
for omitted scoring-only metrics, calculates the score, and checks any supplied
upstream score against the local result. The result has:

```text
score_verification = "calculated"
```

P2-21 adds v3.1 Temporal/Environmental and v4.0 Threat/Environmental/Supplemental
metrics. Supplemental metrics are retained as report data and do not alter the
numeric score.

## 4. Public Python interface

```python
from agentsec.risk import CvssBaseAdapter

assessment = CvssBaseAdapter().adapt(
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
)

assert assessment.base_score == 9.8
assert assessment.severity.value == "critical"
assert assessment.score_verification.value == "calculated"
```

Useful public types are:

- `CvssBaseInput` — bounded input object and strict JSON/mapping loader;
- `CvssBaseAdapter` — deterministic parser and validator;
- `CvssBaseAssessment` — normalized independent CVSS result;
- `CvssAdapterError` / `CvssAdapterCode` — stable safe failures;
- `CvssVersion`, `CvssMetric`, and `CvssScoreVerification` — normalized enums and
  values.

`CvssBaseAssessment.to_dict()` produces a report-ready shape containing the
version, canonical vector, score, Severity, metrics, verification status, and
mapping basis. It intentionally does not contain AgentSec `likelihood`,
`impact`, `confidence`, or Hard Gate fields.

## 5. Safety and non-goals

The adapter:

- never executes or imports input content;
- performs no filesystem, shell, network, LLM, MCP, or runtime operation;
- rejects unknown input fields and malformed metrics;
- enforces a bounded ASCII vector length;
- rejects non-finite, out-of-range, or over-precise scores;
- never echoes the full rejected payload in an error;
- does not enable CI blocking or a production Hard Gate;
- does not claim that a CVSS Base score proves exploitability in the current
  Agent runtime;
- does not merge CVSS with the AgentSec score by averaging.

Runtime reachability, actual tool/OAuth/permission verification, and
Agentic-Uplift or environmental adjustments remain separate future work.

## 6. Standards and policy basis

The vector syntax, v3.1 Base calculation, and qualitative score ranges are
based on FIRST's CVSS specifications:

- FIRST, [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)
- FIRST, [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document)

The independent-source and no-averaging boundary is AgentSec policy. CVSS Base
and AgentSec Base Risk are two views that may be displayed together, but neither
is silently substituted for the other.

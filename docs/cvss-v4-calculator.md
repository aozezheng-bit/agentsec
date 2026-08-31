# P2-20：CVSS v4.0 本地 Base Score 计算

- Task: `P2-20`
- Status: Complete for source development
- CVSS Adapter: `0.2.0`
- Depends on: `P2-17`
- ADR: `docs/decisions/0043-cvss-v4-local-base-calculator.md`

## 1. Scope

P2-20 adds a deterministic local CVSS v4.0 Base Score calculator to the
existing `CvssBaseAdapter`.

```text
CVSS v4.0 Base Vector
→ strict Base Metric parsing
→ MacroVector
→ official v4.0 lookup/interpolation
→ Base Score and Severity
→ optional supplied-score consistency check
```

Only the 11 Base Metrics are accepted:

```text
AV AC AT PR UI VC VI VA SC SI SA
```

For a Base-only vector, the calculator uses the CVSS v4.0 defaults for scoring
metrics not present in the Base Vector:

```text
E  = A
CR = H
IR = H
AR = H
```

## 2. Public behavior

```python
from agentsec.risk import CvssBaseAdapter

assessment = CvssBaseAdapter().adapt(
    {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}
)

assert assessment.base_score == 9.3
assert assessment.score_verification.value == "calculated"
```

If an upstream score is supplied, it must match the local calculation:

```python
assessment = CvssBaseAdapter().adapt(
    {
        "vector": "...",
        "base_score": 9.3,
        "base_severity": "critical",
    }
)
```

A mismatch fails closed with:

```text
CvssAdapterCode.SCORE_MISMATCH
```

The result uses:

```text
CVSS_ADAPTER_VERSION = 0.2.0
score_verification = calculated
```

## 3. Algorithm boundary

The implementation includes:

- CVSS v4.0 Base Metric value maps;
- EQ1–EQ6 MacroVector derivation;
- lower MacroVector lookup values;
- maximum-severity vector selection;
- normalized distance interpolation;
- one-decimal CVSS rounding;
- None / Low / Medium / High / Critical mapping through the existing adapter.

The lookup table is checked in as bounded static data. The calculator performs
no network access and does not import or execute scanned project content.

## 4. Verification

Tests cover:

- all-impact critical vector → `10.0`;
- vulnerable-system-only critical vector → `9.3`;
- no-impact vector → `0.0`;
- supplied Score and Severity consistency;
- mismatch rejection;
- v3.1 regression behavior;
- deterministic repeated calculation;
- report propagation of `score_verification=calculated`.

## 5. Non-goals

P2-20 does not implement:

- CVSS Temporal metrics;
- CVSS Environmental metrics;
- CVSS v4.0 Threat metrics;
- CVSS v4.0 Supplemental metrics;
- CVE/CWE database lookup;
- runtime exploitability verification;
- CVSS-driven Hard Gates or CI Blocking.

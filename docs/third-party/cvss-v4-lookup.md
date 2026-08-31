# CVSS v4.0 Lookup Attribution

AgentSec includes a bounded CVSS v4.0 MacroVector lookup table in:

```text
src/agentsec/risk/cvss_v40.py
```

The table and maximum-vector data are derived from the Red Hat Product Security
CVSS v4 reference implementation, which attributes the CVSS v4.0 calculator to
FIRST.ORG and contributors:

- Source: `https://github.com/RedHatProductSecurity/cvss/blob/master/cvss/constants4.py`
- Specification: `https://www.first.org/cvss/v4-0/specification-document`

The reference implementation's lookup data is distributed under BSD-2-Clause
terms. AgentSec retains source attribution in the module docstring and this
notice. The checked-in table is data only; it does not execute external code or
perform network access.

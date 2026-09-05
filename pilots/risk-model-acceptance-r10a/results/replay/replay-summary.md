# AgentSec RISK-09 回放结果

- 场景：16，通过：16
- 全部通过：是
- 权限：report_only=true；runtime_verified=false；ci_blocked=false

| 场景 | 预期规则 | 实际规则 | 风险 | 漂移 | 漂移风险 | 结果 |
|---|---|---|---|---|---|---|
| scenario-01 | — | — | 0.0 (none) | verified | 0.0 | ✅ |
| scenario-02 | — | — | 0.0 (none) | verified | 0.0 | ✅ |
| scenario-03 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-04 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-05 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-06 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-07 | CTX-RISK-007 | CTX-RISK-007 | 8.0 (high) | drifted | 8.0 | ✅ |
| scenario-08 | CTX-RISK-002 | CTX-RISK-002 | 8.0 (high) | drifted | 8.0 | ✅ |
| scenario-09 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-10 | CTX-RISK-008 | CTX-RISK-008 | 5.5 (medium) | drifted | 5.5 | ✅ |
| scenario-11 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-12 | CTX-RISK-003, CTX-RISK-006 | CTX-RISK-003, CTX-RISK-006 | 8.0 (high) | drifted | 8.0 | ✅ |
| scenario-13 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |
| scenario-14 | CTX-RISK-003, CTX-RISK-006 | CTX-RISK-003, CTX-RISK-006 | 8.0 (high) | drifted | 8.0 | ✅ |
| scenario-15 | — | — | 0.0 (none) | verified | 0.0 | ✅ |
| scenario-16 | — | — | 0.0 (none) | drifted | 0.0 | ✅ |

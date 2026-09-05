# Report Interpretation

## Severity versus evidence confidence

Severity describes the potential impact of a finding. Evidence confidence describes how directly the available evidence supports the finding. A high-severity finding may still have indirect or incomplete evidence and must be presented with both values.

## Static capability limits

A static report can show that an instruction or configuration expresses a capability, policy, or workflow. It does not prove that the runtime has the required credentials, tool binding, network route, OAuth grant, or execution reachability.

## Drift summary

For a baseline comparison, report:

- added assets and capabilities;
- removed assets and capabilities;
- changed instructions or control signals;
- findings whose evidence changed;
- whether the baseline or current scan is incomplete.

Do not describe an unknown state as safe.

## Recommended Chinese summary

```text
结论：<complete/partial/failed>
最高风险：<Critical/High findings>
能力变化：<added/removed/changed>
证据：<path and evidence location>
限制：<missing files, unknown reachability, or incomplete coverage>
权限边界：仅报告，不证明运行时可达，不自动修改、不阻断 CI。
```

## Directional Risk Drift

Treat content drift and risk drift separately. `risk_direction=increased` requires
added/increased Context Finding, upward Residual Risk, or risk-relevant control
weakening. `decreased`, `resolved`, `unknown`, and benign Context changes do not
produce positive Drift Score.

Show these fields independently:

```text
increased_finding_ids
decreased_finding_ids
resolved_finding_ids
control_weakening_count
control_strengthening_count
```

Never describe `unknown` as high risk or clean. Never use file-change count,
persona change, or capability count alone as risk direction.

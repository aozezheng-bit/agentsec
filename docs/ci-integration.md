# AgentSec CI Integration

- Task: `P2-29`
- Status: Complete source example
- Date: 2026-08-25
- Dependencies: P2-25 SARIF, P2-26 `--fail-on`, P2-27 Organization Policy,
  P2-28 Risk Waivers

## Purpose

P2-29 provides an executable CI composition around the existing deterministic
Organization Policy contract. It does not create a new risk decision engine.
The trusted decision remains the exit code produced by:

```bash
agentsec scan PROJECT --policy POLICY
```

The checked-in Runner preserves both a JSON decision report and a SARIF review
report, verifies that the two report formats return the same decision code, and
then returns that code unchanged.

## Included examples

```text
.github/workflows/agentsec.yml
scripts/run-agentsec-ci.sh
docs/examples/ci/gitlab-ci.yml
policies/ci/organization-policy-active-waiver.yaml
policies/ci/organization-policy-expired-waiver.yaml
scripts/validate-ci-examples.py
```

The GitHub Actions workflow runs for pull requests and manual dispatch. The
repository default scans the inert safe Demo so the source example can be
replayed before P2-30 pilot adoption. A consuming repository should set:

```text
AGENTSEC_PROJECT_ROOT repository variable → real Agent project root
AGENTSEC_POLICY_PATH repository variable  → reviewed Organization Policy path
```

Do not leave the Demo project root configured when adopting AgentSec in a real
repository. Selecting and onboarding a real pilot target is P2-30.

## GitHub Actions control flow

The workflow deliberately separates **capture** from **enforcement**:

1. install the local AgentSec package;
2. run `scripts/run-agentsec-ci.sh` without a shell pipe;
3. capture the exact process exit code into a step output;
4. upload JSON/SARIF artifacts with `if: always()`;
5. upload non-empty SARIF to GitHub code scanning when permissions permit;
6. execute a final `if: always()` step that maps the preserved code back to a
   failing or successful job.

The workflow does not use `continue-on-error`. The capture step exits zero only
so report-upload steps can run; the final enforcement step must remain present.
Deleting or weakening that final step converts the example into report-only
behavior.

Fork pull requests still receive downloadable build artifacts, but the example
skips code-scanning SARIF upload when the fork token cannot be trusted for the
base repository. This does not change the AgentSec decision or final job result.

## Exit-code contract

| Exit | Meaning | CI treatment |
|---:|---|---|
| `0` | Organization Policy allows the result | Pass |
| `1` | Deterministic risk meets enforced Policy | Fail PR |
| `2` | Coverage is incomplete | Fail closed |
| `3` | Policy or configuration is invalid | Fail configuration |
| `4` | Required artifact operation failed | Fail infrastructure |
| `5` | Required analysis failed | Fail infrastructure |
| `64` | CLI usage is invalid | Fail configuration |

SARIF `level`, Evidence Confidence, CVSS, LLM output, and runtime-unverified
claims do not authorize or suppress the CI decision. SARIF is a review surface;
the deterministic AgentSec Policy exit code is the blocking authority.

## Local replay

Run the same matrix used by the acceptance test:

```bash
.venv/bin/python scripts/validate-ci-examples.py \
  --agentsec .venv/bin/agentsec
```

The replay covers:

| Scenario | Expected exit |
|---|---:|
| Safe complete Agent | `0` |
| Risky Agent under enforcing Policy | `1` |
| Malformed/incomplete Agent | `2` |
| Invalid Organization Policy | `3` |
| Risk covered by active reviewed Waiver | `0` |
| Same risk with expired Waiver | `1` |

The active-Waiver Policy uses `2099-12-31` only as a deterministic test fixture.
Production Waivers require a real owner, reviewed reason, and intentionally
short expiry. The expired fixture uses `2000-01-01` to prove automatic
reactivation of blocking.

## Run the CI wrapper directly

```bash
scripts/run-agentsec-ci.sh \
  demos/release-agent/risky-drift \
  policies/organization-policy-enforce-example.yaml \
  .agentsec-ci
rc=$?
echo "AgentSec exit: $rc"
```

Generated files:

```text
.agentsec-ci/agentsec-assessment.json
.agentsec-ci/agentsec-results.sarif
.agentsec-ci/agentsec-exit-code.txt
```

The output directory is ignored by Git. The Runner rejects a symbolic-link
output directory and never executes scanned Agent content.

## GitLab

`docs/examples/ci/gitlab-ci.yml` runs the same Runner and uses
`artifacts: when: always` so JSON, SARIF, and the recorded exit code remain
available when policy enforcement fails the job. It intentionally does not
translate SARIF into a second authorization decision.

## Security boundaries

- scanned Markdown and structured assets remain untrusted data;
- no scanned code, script, Hook, Skill, command, plugin, Sub-Agent, or MCP server
  is executed;
- no network connection is derived from scanned content;
- Organization Policy is supplied explicitly and is not auto-discovered from
  the target Agent;
- reports remain secret-redacted;
- Waivers remove blocking authority only and never remove Findings;
- incomplete Coverage has precedence over matched or waived risk;
- LLM output has no CI authority;
- P2-29 does not claim that a remote workflow has run in this non-Git workspace.

## P2-30 handoff

P2-30 should choose a real pilot repository, configure the two repository
variables, install the reviewed Organization Policy and ownership process, run
safe/risky/incomplete pull-request trials, and retain remote workflow evidence.
P2-29 supplies the tested pipeline composition but does not claim pilot rollout.

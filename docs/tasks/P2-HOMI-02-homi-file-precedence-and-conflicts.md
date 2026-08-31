# P2-HOMI-02: Homi File Role / Precedence Model

- Status: Complete
- Date: 2026-08-25
- ADR: `docs/decisions/0069-homi-file-precedence-and-conflicts.md`
- Depends on: P2-HOMI-01

## Delivered

```text
src/agentsec/frameworks/homi_policy.py
src/agentsec/frameworks/__init__.py
tests/test_homi_adapter.py
```

The new `HomiWorkspacePolicyResolver` resolves static security authority for:

```text
AGENTS.md
SOUL.md
IDENTITY.md
USER.md
TOOLS.md
HEARTBEAT.md
```

## Security authority precedence

```text
AGENTS.md       100  workspace safety/startup/operation policy
HEARTBEAT.md    90   scheduler definition only
TOOLS.md        80   private environment binding notes
USER.md         70   main-session user context only
SOUL.md         60   persona only
IDENTITY.md     50   public identity presentation only
```

These are security-resolution ranks, not a claim about Homi's runtime loading
order. Every policy has `runtime_authority=false`.

## Visibility boundaries

```text
AGENTS.md      all contexts
SOUL.md        all contexts, persona only
IDENTITY.md    public identity surface
USER.md        main session only
TOOLS.md       private runtime binding only
HEARTBEAT.md   scheduler only
```

## Conflict and boundary observations

The resolver emits bounded, source-located observations without source excerpts:

```text
startup_read_policy_conflict
control_plane_self_modification
heartbeat_activation_path
tools_not_authority
user_profile_main_session_only
identity_not_runtime_authority
empty_heartbeat_disabled
```

Resolution states:

```text
resolved  complete static coverage and no conflict observation
partial   missing/skipped/incomplete coverage
conflict  at least one deterministic cross-file conflict
```

Examples:

```text
AGENTS.md says not to reread provided startup context,
SOUL.md says to read the files every session
→ conflict observation; workspace safety policy wins

AGENTS.md permits editing HEARTBEAT.md,
HEARTBEAT.md is empty
→ latent activation observation; no task is enabled

TOOLS.md exists
→ tool-notes boundary; no runtime tool authority

USER.md exists
→ main-session-only boundary; no shared-context authorization
```

## API

```python
from agentsec.frameworks import HomiAdapter, HomiWorkspacePolicyResolver

inspection = HomiAdapter().inspect_workspace(request)
resolution = HomiWorkspacePolicyResolver().resolve(inspection)
```

The result is adapter-local and report-oriented. It does not change the current
Manifest Schema or authorize any runtime capability.

## Verification

```text
P2-HOMI adapter/policy tests: 13 passed
Framework Adapter regression tests: passed
Ruff: passed
Mypy: passed
Full Pytest: pending final task gate
```

## Deferred work

```text
P2-HOMI-04 Cross-file Combination Rules
P2-HOMI-06 Homi Real-project Report-only Pilot
P2-HOMI-07 Homi CLI Packaging
```

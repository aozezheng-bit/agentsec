# P2-HOMI-01: Homi Workspace Adapter

- Status: Complete
- Date: 2026-08-25
- ADR: `docs/decisions/0068-homi-workspace-adapter.md`
- Depends on: existing Framework Adapter seam and safe Markdown parser

## Delivered

```text
src/agentsec/frameworks/homi.py
src/agentsec/frameworks/__init__.py
tests/test_homi_adapter.py
```

The Adapter discovers exactly these project-root files:

```text
AGENTS.md
SOUL.md
IDENTITY.md
USER.md
TOOLS.md
HEARTBEAT.md
```

It returns the neutral `FrameworkInspectionResult` required by the existing
`FrameworkAdapter` Protocol and exposes `inspect_workspace()` for Homi-specific
classification:

```text
workspace_policy
persona
identity
user_profile
tool_notes
heartbeat_schedule
```

States:

```text
present
empty
example_only
missing
skipped
```

## Safety behavior

- no execution of Markdown, commands, skills, hooks, or MCP;
- no network or runtime tool access;
- bounded regular-file reads;
- strict UTF-8 decoding;
- SHA-256 and portable project-relative locators;
- external symlinks become safe coverage issues;
- max-assets and max-file-size limits are enforced;
- missing optional files are represented explicitly, not fabricated;
- empty/comment-only Heartbeat is classified as disabled static configuration;
- the documentation-style TOOLS template is classified as `example_only`;
- Homi semantic roles remain adapter-local until P2-HOMI-02 defines Manifest
  precedence and schema vocabulary;
- generic records use the neutral `agent_instructions` role for compatibility,
  but `HomiWorkspaceInspection.files` retains the semantic Homi role.

## API

```python
from agentsec.frameworks import HomiAdapter, FrameworkInspectionRequest

result = HomiAdapter().inspect_workspace(
    FrameworkInspectionRequest(project_root=project_root)
)
```

`result.framework_result` can be passed to the existing Manifest builder or
`AgentAnalysisPipeline(adapter=HomiAdapter())`; this proves the Adapter reuses
the existing core without adding a second analysis engine.

## Verification

Required checks:

```text
Homi Adapter unit tests
Framework Adapter regression tests
Ruff
Mypy
Full Pytest
```

## Deferred work

```text
P2-HOMI-02 File Role / Precedence Model — Complete 2026-08-25
P2-HOMI-03 Homi Capability Profile — Complete 2026-08-25
P2-HOMI-04 Cross-file Combination Rules — Complete 2026-08-25
P2-HOMI-05 Homi Safe Simulation — Complete 2026-08-25
P2-HOMI-06 Homi Real-project Report-only Pilot
P2-HOMI-07 Homi CLI Packaging
```

## P2-EXIT-06-03A calibration amendment

ADR-0079 upgrades the Homi Adapter to `0.2.0`. `HEARTBEAT.md` now distinguishes
comment-only `empty`, documentation `example_only`, concrete-task `present`, and
missing/skipped states. Fenced examples and Related links cannot activate a
schedule; adding a real task outside the template produces `present`.

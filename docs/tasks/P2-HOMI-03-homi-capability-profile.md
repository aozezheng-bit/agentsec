# P2-HOMI-03: Homi Capability Profile

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-HOMI-01, P2-HOMI-02
- ADR: `docs/decisions/0070-homi-capability-profile.md`

## Objective

Build a deterministic, value-minimized capability and behavior profile from the
six Homi workspace control files. The profile is an analysis artifact only: it
must not execute scanned content, grant runtime permissions, fetch remote
avatars, connect to tools, or make CI decisions.

## Delivered

```text
src/agentsec/frameworks/homi_profile.py
tests/test_homi_profile.py
src/agentsec/frameworks/__init__.py
```

Public entry point:

```python
from agentsec.frameworks import (
    HomiAdapter,
    HomiCapabilityProfileBuilder,
)

inspection = HomiAdapter().inspect_workspace(request)
profile = HomiCapabilityProfileBuilder().build(inspection)
```

## Profile dimensions

### Capability profile

The profile contains a canonical, stable list of capability dimensions:

```text
workspace_read
workspace_write
memory_read
memory_write
persistent_memory
external_network_read
external_message_send
shell_execution
ssh_access
mcp_access
oauth_access
secret_access
camera_access
tts_output
heartbeat_schedule
cron_schedule
skill_tool_discovery
group_chat_participation
control_file_self_modification
persona_self_modification
identity_self_modification
user_profile_persistence
```

Each capability has a bounded state:

```text
present       static declaration found
conditional   declaration is gated by approval or a boundary
example_only  found only in a shipped/local-note template example
absent        structurally disabled, currently used for empty HEARTBEAT.md
unknown       file is missing, skipped, or no deterministic declaration exists
```

`TOOLS.md` remains an environment-notes file. Its declarations are never
converted to runtime authority. SSH example detection is conservative and
recognizes explicit SSH wording or the standard `home-server` example shape;
IP addresses, usernames, and other secret-like values are not copied to the
profile.

### Persona profile

`SOUL.md` produces only behavioral signals, including resourcefulness,
anti-sycophancy, privacy boundaries, external-action approval, group-chat
non-proxy behavior, and self-evolution. Persona signals are not permissions.

### Identity profile

`IDENTITY.md` produces presence flags for name/creature/vibe/emoji, a bounded
avatar kind (`none`, workspace-relative, remote URL, data URI, or unknown), an
identity-disclosure signal, and a self-assignment signal. Avatar URLs are
classified but never fetched.

### User privacy profile

`USER.md` produces file state, template presence, observed field names, and a
persistence signal. The static policy is always `main_session_only=true` and
`shared_context_allowed=false`; this is a privacy boundary, not runtime
attestation.

### Tool binding profile

`TOOLS.md` produces bounded signals for camera, SSH, TTS, MCP, OAuth, and
secret-like notes. The profile always sets `runtime_authority=false` and does
not execute or connect to any declared tool.

### Heartbeat profile

`HEARTBEAT.md` produces:

- `absent` with structural confidence B when the file is blank/comment-only;
- `present` with static confidence D when task text exists;
- `unknown` when the file is missing/skipped or coverage is incomplete.

`runtime_verified` is always false. A non-empty file is not proof that a
scheduler actually runs.

## Evidence contract

Static profile signals use the existing evidence-confidence contract:

```text
B  structural file state, such as an empty HEARTBEAT.md
D  lexical/template/static declaration or runtime-unverified state
A  never emitted by this static builder
```

Every signal includes a stable signal ID, method, source locator when available,
and `runtime_verified=false`. Unknown and absent states cannot be labeled as
`static_declaration`; they use `runtime_unverified` or a structural method.
Severity and evidence confidence remain separate concepts.

## Completeness and policy propagation

The builder consumes the P2-HOMI-02 resolution when provided. If omitted, it
resolves the workspace itself. Conflict, missing-file, skipped-file, and
boundary observations are preserved unchanged in the profile. `complete` is
true only when the resolution status is `resolved`.

## Security invariants

- Homi source files are untrusted input and are never executed.
- No MCP, network, SSH, camera, TTS, OAuth, shell, or scheduler connection is
  attempted.
- No raw user profile values, tool credentials, IP addresses, or avatar bytes
  are copied into the profile.
- Static analysis never claims runtime verification or runtime authority.
- The profile does not update Manifest schema or create findings by itself.
- Later deterministic combination rules own risk interpretation and CI gates.

## Verification

```text
.venv/bin/pytest -q tests/test_homi_profile.py
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
```

All commands pass for the P2-HOMI-03 implementation.

## Deferred work

```text
P2-HOMI-06 Homi Real-project Report-only Pilot
P2-HOMI-07 Homi CLI Packaging
```

## P2-EXIT-06-03A calibration amendment

`HOMI_PROFILE_MODEL_VERSION=0.2.0` adds an `example_only` Heartbeat profile:
`tasks_present=false`, `api_calls_enabled_by_file=false`, Confidence D, and
`static_template_classification`. Empty remains structural Confidence B;
concrete tasks remain static `present`; missing/skipped remains `unknown`.

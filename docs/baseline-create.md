# AgentSec Baseline Create

- Task: `P1-13`
- Status: Complete
- Decision date: 2026-08-18
- Depends on: P1-12 Baseline Schema `0.1.0`

## 1. Purpose

`agentsec baseline create` creates an explicit trusted snapshot from the same
bounded Markdown collection and parsing scope used by `scan`. The command never
executes scanned code, hooks, skills, links, or MCP servers.

A successful file is input for P1-14 Asset Diff and P1-15 Text Diff. Creating a
baseline does not prove that the captured Agent is safe and does not sign or
approve the captured content.

## 2. Command

Default output:

```bash
agentsec baseline create <project-root>
```

writes:

```text
<project-root>/.agentsec/baseline.json
```

Explicit output and configuration:

```bash
agentsec baseline create <project-root> \
  --config path/to/agentsec.yaml \
  --output path/to/baseline.json
```

Explicit replacement of an existing valid AgentSec baseline:

```bash
agentsec baseline create <project-root> \
  --output path/to/baseline.json \
  --force
```

`--output` may be outside the selected project root so the documented demo can
store a trusted baseline beside the scanned source tree. The filename must end
in `.json`.

## 3. Creation pipeline

The command performs these stages in order:

1. load explicit, discovered, or default project configuration;
2. collect assets with configured path and resource limits;
3. require complete collection coverage;
4. parse every collected Markdown asset as untrusted data;
5. fail closed if any parser raises;
6. calculate the canonical collection-configuration SHA-256;
7. obtain optional hardened local Git provenance;
8. build and validate the Baseline Schema model;
9. encode deterministic JSON;
10. enforce the 256 MiB hard output limit;
11. validate output-path and overwrite policy;
12. write a mode-`0600` temporary file in the destination directory;
13. flush the file and atomically publish it;
14. best-effort flush the destination directory.

No output file is created when an earlier stage fails.

## 4. Complete coverage requirement

A baseline is created only when:

```text
coverage.complete = true
skipped_assets = 0
all selected assets parse successfully
```

Examples that block creation include:

- missing or unreadable project root;
- external symbolic-link asset;
- invalid UTF-8;
- oversized selected asset;
- depth or asset-count limit exceeded;
- parser exception.

These failures use exit code `4` rather than creating a partial trusted
snapshot. Errors never include rejected asset content.

## 5. Collection configuration fingerprint

`collection_config_sha256` is SHA-256 over canonical compact JSON containing:

```text
config schema version
discovery.include
discovery.exclude
limits.max_file_size_bytes
limits.max_depth
limits.max_assets
```

Object keys are sorted and JSON uses UTF-8 with compact separators. Reporter
settings such as text versus JSON output do not affect this fingerprint because
they cannot change the collected asset set.

P1-14 uses the fingerprint to expose collection-scope compatibility separately
from file-level changes.

## 6. Git provenance

When the selected root belongs to a repository with a valid HEAD, metadata
stores:

```text
git_commit
git_dirty
```

Non-Git directories, environments without a Git executable, and newly
initialized repositories without HEAD store both fields as `null`.

Git commands are local, fixed, shell-free, read-only, and bounded by a five
second timeout. The provider:

- removes inherited `GIT_*` redirection variables;
- disables system and global Git configuration;
- disables terminal prompts and optional locks;
- overrides `core.hooksPath` with the platform null device;
- disables `core.fsmonitor`;
- disables external diff and interactive diff filters;
- ignores submodule state;
- does not buffer the complete untracked-file list;
- excludes the selected Baseline output path from dirty-state calculation.

The output-path exclusion prevents an existing generated baseline from making
its own source snapshot appear dirty during regeneration. Other project files,
including an in-project configuration file, still affect dirty state.

Git metadata is provenance only. It is not an approval signature or attestation.

## 7. Output and overwrite policy

### New file

A new file uses an atomic no-clobber operation. If another process creates the
same target during the race window, AgentSec fails without replacing it.

### Existing file

Without `--force`, any existing target is rejected.

With `--force`, AgentSec replaces the target only when all conditions hold:

- the target is a regular file;
- the target is not a symbolic link;
- the existing file is within the 256 MiB hard limit;
- the existing file is valid UTF-8 JSON;
- the existing payload is a compatible, valid AgentSec Baseline;
- the target is not a scanned source asset;
- the target is not the effective project configuration.

Consequently, `--force` cannot be used as a general arbitrary-file overwrite
primitive. A corrupted or unrelated target must be reviewed and removed
manually before a new baseline can be created at that path.

### Permissions and atomicity

The new temporary file is explicitly mode `0600`. Publishing occurs in the same
directory so the final rename or hard-link operation remains on one filesystem.
Temporary files are removed on failure.

## 8. Stable outcomes

| Scenario | Exit code |
|---|---:|
| Baseline created or valid baseline replaced | `0` |
| Invalid project configuration | `3` |
| Incomplete collection, parser failure or Git provenance failure | `4` |
| Invalid, unsafe, existing or oversized output | `4` |
| Invalid CLI syntax | `64` through the installed entry point |

Success output contains only:

- created/replaced state;
- asset count;
- encoded byte count;
- escaped output path.

It never prints asset content.

## 9. Public implementation seams

```python
from agentsec.application import (
    BaselineCreationRequest,
    BaselineCreator,
    CollectionBaselineCreator,
)
from agentsec.baselines import (
    BaselineFileWriter,
    GitProvenanceProvider,
    SafeGitProvenanceProvider,
    fingerprint_collection_config,
)
```

Construction and filesystem delivery are separate interfaces. Tests can inject
a parser, Git provider, clock, creator, or writer without invoking scanned code.

## 10. Residual limitations

- Baseline content is sensitive plaintext JSON.
- SHA-256 does not establish approver identity or authenticity.
- There is no cross-process lock around `--force`; atomic replacement prevents
  partial files, but a hostile concurrent writer remains a residual race.
- The collector holds bounded asset content in memory, and JSON encoding creates
  another in-memory representation before the 256 MiB output check.
- Git provenance is unavailable when Git is missing, the repository has no HEAD,
  or the selected root is not a Git working tree.
- The generation timestamp, asset reads, and Git state are not a filesystem-wide
  transactional snapshot; files can still change concurrently.
- Signatures, independent approval and remote trusted storage remain future work.

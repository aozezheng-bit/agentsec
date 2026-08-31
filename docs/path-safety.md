# AgentSec Collector Path Safety

- Task: `P1-07`
- Status: Complete
- Decision date: 2026-08-18

## Security objective

Every filesystem object used by the collector must resolve inside the
canonically selected project root. Include patterns cannot expand this trust
boundary, and exclude patterns cannot be bypassed through an internal alias.

## Project-root policy

The project root is explicit operator input. AgentSec resolves it with
`strict=True` before traversal:

- a real directory is accepted;
- a symbolic link to a real directory is accepted, and its canonical target
  becomes the containment boundary;
- a missing, unreadable, non-directory, or cyclic root produces incomplete
  coverage and no traversal.

Accepting an explicitly selected root link does not authorize links found
inside that root to escape the canonical boundary.

## Entry and symbolic-link policy

For every non-excluded directory entry, the collector:

1. checks that its lexical location is below the canonical root;
2. reads link metadata without following the link;
3. resolves the final target with `strict=True`;
4. verifies that the resolved target is still below the canonical root;
5. classifies the resolved target as a regular file, directory, or other type;
6. revalidates a selected file immediately before reading it.

Results:

| Path condition | Behavior |
|---|---|
| Normal contained file or directory | Scan normally |
| Internal file link | Read canonical target, preserve logical link path as evidence |
| Internal directory link | Traverse canonical target using logical link-relative paths |
| External link | Do not read; emit `external_symlink` coverage issue |
| Broken link | Do not read; emit `unreadable` coverage issue |
| Link-resolution loop | Do not follow; emit a visible coverage issue |
| Non-regular selected asset | Skip with `unreadable` coverage issue |

External target paths are not copied into issue messages or terminal output.

## Directory-cycle prevention

Traversal carries the canonical path of every ancestor directory. Before an
internal directory link is followed, its canonical target is compared against
that ancestor chain. A target already in the chain is not traversed, preventing
links such as `child/back-to-root -> project-root` from recursing forever.

Different non-cyclic logical aliases to the same internal directory may still
be scanned independently because their Agent instruction scope can differ by
logical path. P1-08 bounds this work with depth and asset limits.

## Include/exclude interaction

Exclusions are checked twice:

1. against the logical project-relative path before metadata resolution;
2. against the canonical target's project-relative path after resolution.

This prevents an included alias such as `git-alias -> .git` from bypassing the
default `.git/**` exclusion. Excluded paths are intentional scope reductions
and do not create coverage issues.

## Residual risk

The implementation revalidates files before reading, but ordinary path APIs
cannot completely eliminate a malicious concurrent filesystem race between the
last validation and the operating-system open operation. The Phase 1 threat
model records this as residual risk. Stronger descriptor-relative traversal,
platform-specific `openat`/`O_NOFOLLOW` controls, or an immutable scan snapshot
can be introduced if hostile concurrent mutation enters the deployment model.

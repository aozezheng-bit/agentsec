# Security Boundary for Homi Hosts

The Homi host should run the Skill with:

- a read-only mount of the target workspace;
- a separate writable output directory;
- no inherited secrets from the scanned workspace;
- no network access for deterministic operations;
- a process timeout;
- a maximum stdout/stderr and report size;
- no shell interpolation of scanned text;
- no execution permission for files under the scanned workspace;
- no automatic invocation of Skills, Hooks, plugins, or MCP servers discovered in files.

Semantic live Provider calls are not part of the default Skill path. If enabled later, they require explicit opt-in and separate approval for endpoint, credential, data residency, retention, cost, and owner metadata. Preserve `report_only=true`, `runtime_verified=false`, and `ci_blocked=false`.

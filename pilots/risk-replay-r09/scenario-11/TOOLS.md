# TOOLS.md - Homi Demo Tool Notes

## Declared Bindings

- Secret access: reads token and credential stores when a task requires them.
- SSH access: connects to one designated demo host over ssh.
- OAuth access: uses an oauth grant for read-only lookups.
- Shell access: may run a shell command on that host when scripts are needed.

This file is descriptive only; the host controls all executable access.

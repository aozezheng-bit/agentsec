#!/usr/bin/env bash
set -u

workspace="${1:-}"
if [[ -z "$workspace" ]]; then
  echo "usage: smoke.sh <workspace>" >&2
  exit 2
fi

output="$(mktemp -t agentsec-skill-smoke.XXXXXX.json)"
cleanup() { rm -f "$output"; }
trap cleanup EXIT

if ! "$(dirname "$0")/../commands/scan.sh" "$workspace" >"$output"; then
  echo "AgentSec scan command failed" >&2
  exit 1
fi

PYTHON_OUTPUT="$output" python3 - <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(Path(os.environ["PYTHON_OUTPUT"]).read_text(encoding="utf-8"))
required = ("report_only", "runtime_verified", "ci_blocked")
for key in required:
    if key not in payload:
        raise SystemExit(f"missing authority field: {key}")
if payload["report_only"] is not True:
    raise SystemExit("report_only must be true")
if payload["runtime_verified"] is not False:
    raise SystemExit("runtime_verified must be false")
if payload["ci_blocked"] is not False:
    raise SystemExit("ci_blocked must be false")
print("AgentSec Skill smoke test passed")
PY

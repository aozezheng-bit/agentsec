#!/usr/bin/env bash
set -u

workspace="${1:-}"
if [[ -z "$workspace" ]]; then
  echo "usage: smoke.sh <workspace>" >&2
  exit 2
fi
if [[ ! -d "$workspace" ]]; then
  echo "workspace does not exist or is not a directory" >&2
  exit 2
fi

output_dir="$(mktemp -d -t agentsec-skill-smoke.XXXXXX)"
scan_output="$output_dir/scan.json"
cleanup() { rm -rf "$output_dir"; }
trap cleanup EXIT

if ! "$(dirname "$0")/../commands/scan.sh" "$workspace" >"$scan_output"; then
  echo "AgentSec scan command failed" >&2
  exit 1
fi

report_status=0
"$(dirname "$0")/../commands/report.sh" "$workspace" "$output_dir/report" \
  >"$output_dir/report.log" 2>&1 || report_status=$?
if [[ "$report_status" -ne 0 && "$report_status" -ne 2 ]]; then
  echo "AgentSec report command failed" >&2
  exit 1
fi

if [[ ! -f "$output_dir/report/homi-pilot-report.json" || \
      ! -f "$output_dir/report/homi-pilot-report.md" || \
      ! -f "$output_dir/report/homi-pilot-report.html" ]]; then
  echo "AgentSec report command did not produce JSON/Markdown/HTML" >&2
  exit 1
fi

"$(dirname "$0")/../commands/homi-diff.sh" \
  "$output_dir/report/homi-pilot-report.json" \
  "$output_dir/report/homi-pilot-report.json" \
  json \
  "$output_dir/diff.json" >/dev/null

PYTHON_OUTPUT="$scan_output" REPORT_OUTPUT="$output_dir/report/homi-pilot-report.json" \
DIFF_OUTPUT="$output_dir/diff.json" python3 - <<'PY'
import json
import os
from pathlib import Path

scan = json.loads(Path(os.environ["PYTHON_OUTPUT"]).read_text(encoding="utf-8"))
report = json.loads(Path(os.environ["REPORT_OUTPUT"]).read_text(encoding="utf-8"))
diff = json.loads(Path(os.environ["DIFF_OUTPUT"]).read_text(encoding="utf-8"))
for payload in (scan, report, diff):
    authority = payload.get("authority", payload)
    for key, expected in (
        ("report_only", True),
        ("runtime_verified", False),
        ("ci_blocked", False),
    ):
        if authority.get(key) is not expected:
            raise SystemExit(f"{key} authority invariant failed")
if diff["format"] != "agentsec-homi-capability-diff":
    raise SystemExit("unexpected Homi diff format")
print("AgentSec Skill smoke test passed")
PY

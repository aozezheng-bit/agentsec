#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
output_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/agentsec-demo.XXXXXX")}"

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi

mkdir -p "$output_dir"
rm -f "$output_dir/live-baseline.json"

agentsec=("$python_executable" -m agentsec)
baseline_root="$repository_root/demos/release-agent/baseline"
risky_root="$repository_root/demos/release-agent/risky-drift"
injection_root="$repository_root/demos/release-agent/prompt-injection"
malformed_root="$repository_root/demos/release-agent/malformed"
remediated_root="$repository_root/demos/release-agent/remediated"

"${agentsec[@]}" scan "$baseline_root" --format json \
  > "$output_dir/baseline-scan.json"
"${agentsec[@]}" baseline create "$baseline_root" \
  --output "$output_dir/live-baseline.json" \
  > "$output_dir/baseline-create.txt"
"${agentsec[@]}" diff "$risky_root" \
  --baseline "$output_dir/live-baseline.json" \
  --format json \
  > "$output_dir/risky-diff.json"
"${agentsec[@]}" scan "$risky_root" --format json \
  > "$output_dir/risky-findings.json"
"${agentsec[@]}" scan "$injection_root" --format json \
  > "$output_dir/injection-findings.json"

set +e
"${agentsec[@]}" scan "$malformed_root" --format json \
  > "$output_dir/malformed-scan.json"
malformed_exit=$?
set -e
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "Malformed Demo expected exit 2, received $malformed_exit" >&2
  exit 1
fi

"${agentsec[@]}" scan "$remediated_root" --format json \
  > "$output_dir/remediated-scan.json"

PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/validate_demo_outputs.py" "$output_dir"

echo "Demo output directory: $output_dir"
echo "AgentSec remains report-only; the human release recommendation is not a CLI block."

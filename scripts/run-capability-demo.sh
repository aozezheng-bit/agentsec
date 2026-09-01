#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
language="en"
output_dir=""

usage() {
  cat <<'USAGE'
Usage: scripts/run-capability-demo.sh [OPTIONS]

Run and validate the complete P2I-05 Capability Drift Demo through the real CLI.

Options:
  --language L       Demo language/assets: en or zh (default: en).
  --output-dir DIR   Preserve artifacts in a new or empty directory.
  --python PATH      Use a specific Python 3.12 executable.
  -h, --help         Show this help message.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --language)
      [[ $# -ge 2 ]] || { echo "Missing value for --language" >&2; exit 2; }
      language="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --output-dir" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || { echo "Missing value for --python" >&2; exit 2; }
      python_executable="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$language" != "en" && "$language" != "zh" ]]; then
  echo "Unsupported language: $language (expected en or zh)" >&2
  exit 2
fi
if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi
if [[ -z "$output_dir" ]]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-capability-demo.XXXXXX")"
elif [[ -d "$output_dir" ]]; then
  if [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Output directory must be empty: $output_dir" >&2
    exit 2
  fi
else
  mkdir -p "$output_dir"
fi

if [[ "$language" == "zh" ]]; then
  demo_root="$repository_root/demos/capability-drift-agent-zh"
else
  demo_root="$repository_root/demos/capability-drift-agent"
fi
agentsec=("$python_executable" -m agentsec)
agent_id="release-agent"

run_expected() {
  local expected_exit="$1"
  shift
  set +e
  "$@"
  local actual_exit=$?
  set -e
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "Unexpected exit code: expected $expected_exit, got $actual_exit" >&2
    exit 1
  fi
}

generate_case() {
  local case_name="$1"
  local expected_exit="$2"
  local case_root="$demo_root/$case_name"

  run_expected "$expected_exit" \
    "${agentsec[@]}" manifest "$case_root" --agent-id "$agent_id" \
    --format json --output "$output_dir/$case_name.manifest.json"
  run_expected "$expected_exit" \
    "${agentsec[@]}" manifest "$case_root" --agent-id "$agent_id" \
    --format text --language "$language" \
    --output "$output_dir/$case_name.manifest.txt"
  run_expected "$expected_exit" \
    "${agentsec[@]}" capability assess "$case_root" --agent-id "$agent_id" \
    --format json --output "$output_dir/$case_name.assessment.json"
  run_expected "$expected_exit" \
    "${agentsec[@]}" capability assess "$case_root" --agent-id "$agent_id" \
    --format text --language "$language" \
    --output "$output_dir/$case_name.assessment.txt"
}

generate_case baseline 0
generate_case risky-drift 0
generate_case incomplete 2
generate_case remediated 0

run_expected 0 \
  "${agentsec[@]}" capability diff \
  --before "$output_dir/baseline.manifest.json" \
  --after "$output_dir/risky-drift.manifest.json" \
  --format json --output "$output_dir/risky.diff.json"
run_expected 0 \
  "${agentsec[@]}" capability diff \
  --before "$output_dir/baseline.manifest.json" \
  --after "$output_dir/risky-drift.manifest.json" \
  --format text --language "$language" \
  --output "$output_dir/risky.diff.txt"
run_expected 0 \
  "${agentsec[@]}" capability diff \
  --before "$output_dir/risky-drift.manifest.json" \
  --after "$output_dir/remediated.manifest.json" \
  --format json --output "$output_dir/remediation.diff.json"
run_expected 0 \
  "${agentsec[@]}" capability diff \
  --before "$output_dir/risky-drift.manifest.json" \
  --after "$output_dir/remediated.manifest.json" \
  --format text --language "$language" \
  --output "$output_dir/remediation.diff.txt"
run_expected 0 \
  "${agentsec[@]}" capability impact \
  --before "$output_dir/baseline.manifest.json" \
  --after "$output_dir/risky-drift.manifest.json" \
  --format json --output "$output_dir/risky.impact.json"
run_expected 0 \
  "${agentsec[@]}" capability impact \
  --before "$output_dir/baseline.manifest.json" \
  --after "$output_dir/risky-drift.manifest.json" \
  --format text --language "$language" \
  --output "$output_dir/risky.impact.txt"
run_expected 0 \
  "${agentsec[@]}" capability impact \
  --before "$output_dir/risky-drift.manifest.json" \
  --after "$output_dir/remediated.manifest.json" \
  --format json --output "$output_dir/remediation.impact.json"
run_expected 0 \
  "${agentsec[@]}" capability impact \
  --before "$output_dir/risky-drift.manifest.json" \
  --after "$output_dir/remediated.manifest.json" \
  --format text --language "$language" \
  --output "$output_dir/remediation.impact.txt"

PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/validate_capability_demo_outputs.py" "$output_dir"

printf 'Capability Drift Demo output directory: %s\n' "$output_dir"
printf '%s\n' 'AgentSec remains static and report-only; no runtime exploit or CI block is claimed.'

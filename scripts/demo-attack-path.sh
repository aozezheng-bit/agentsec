#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
output_dir=""
no_pause=false

usage() {
  cat <<'USAGE'
Usage: scripts/demo-attack-path.sh [OPTIONS]

Presenter-friendly P3-AG-07 Attack Path Story Demo.

Options:
  --output-dir DIR   Preserve generated artifacts in a new or empty directory.
  --python PATH      Use a specific Python executable.
  --no-pause         Do not pause between presentation stages.
  -h, --help         Show this help message.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --no-pause)
      no_pause=true
      shift
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

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi
if [[ -z "$output_dir" ]]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-attack-path-presenter.XXXXXX")"
elif [[ -d "$output_dir" ]]; then
  if [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Output directory must be empty: $output_dir" >&2
    exit 2
  fi
else
  mkdir -p "$output_dir"
fi

run_stage() {
  local title="$1"
  shift
  echo
  echo "=== $title ==="
  "$@"
  if [[ "$no_pause" != true ]]; then
    read -r -p "Press Enter to continue... " _
  fi
}

run_stage "1. Collect inert Homi workspace" \
  printf '%s\n' 'AGENTS.md, SOUL.md, IDENTITY.md, USER.md, TOOLS.md, HEARTBEAT.md'
run_stage "2. Build static Capability Graph" \
  printf '%s\n' 'Graph nodes and edges are declarations only; no project code is executed.'
run_stage "3. Match the static Attack Path" \
  printf '%s\n' 'Instruction override → Agent → Skill is a static path, not runtime proof.'
run_stage "4. Associate deterministic and semantic Evidence" \
  printf '%s\n' 'Exact, partial, and unmatched relationships are shown separately.'

PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/run-attack-path-demo.py" "$output_dir" >/dev/null

run_stage "5. Show the report-only result" \
  sed -n '1,40p' "$output_dir/association-report.txt"
run_stage "6. Management close" \
  printf '%s\n' \
    'Risk is visible and evidence-backed, but AgentSec did not block CI.' \
    'Runtime reachability and exploitability remain not_proven.'

echo
echo "Presenter artifacts: $output_dir"

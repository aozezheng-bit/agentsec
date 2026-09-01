#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
output_dir=""

usage() {
  cat <<'USAGE'
Usage: scripts/run-attack-path-demo.sh [OPTIONS]

Run the P3-AG-07 Attack Path Story Demo and preserve all artifacts.

Options:
  --output-dir DIR   Use a new or empty output directory.
  --python PATH      Use a specific Python executable.
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
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-attack-path-demo.XXXXXX")"
elif [[ -d "$output_dir" ]]; then
  if [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Output directory must be empty: $output_dir" >&2
    exit 2
  fi
else
  mkdir -p "$output_dir"
fi

PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/run-attack-path-demo.py" "$output_dir"

echo "Attack Path Story Demo output directory: $output_dir"
echo "AgentSec remains report-only; static paths do not prove runtime behavior."

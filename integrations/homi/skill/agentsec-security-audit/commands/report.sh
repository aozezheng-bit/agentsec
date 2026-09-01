#!/usr/bin/env bash
set -u

workspace="${1:-}"
output_dir="${2:-}"
if [[ -z "$workspace" || -z "$output_dir" ]]; then
  echo "usage: report.sh <workspace> <output-dir>" >&2
  exit 2
fi
if [[ ! -d "$workspace" ]]; then
  echo "workspace does not exist or is not a directory" >&2
  exit 2
fi

exec agentsec homi report "$workspace" --output-dir "$output_dir" --language zh --force

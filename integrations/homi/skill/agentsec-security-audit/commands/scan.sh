#!/usr/bin/env bash
set -u

workspace="${1:-}"
if [[ -z "$workspace" ]]; then
  echo "usage: scan.sh <workspace>" >&2
  exit 2
fi
if [[ ! -d "$workspace" ]]; then
  echo "workspace does not exist or is not a directory" >&2
  exit 2
fi

exec agentsec homi scan "$workspace" --format json --language zh

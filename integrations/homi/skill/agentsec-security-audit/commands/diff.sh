#!/usr/bin/env bash
set -u

workspace="${1:-}"
baseline="${2:-}"
if [[ -z "$workspace" || -z "$baseline" ]]; then
  echo "usage: diff.sh <workspace> <baseline>" >&2
  exit 2
fi
if [[ ! -d "$workspace" || ! -f "$baseline" ]]; then
  echo "workspace or baseline does not exist" >&2
  exit 2
fi

exec agentsec diff "$workspace" --baseline "$baseline" --format json

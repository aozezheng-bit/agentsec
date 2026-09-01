#!/usr/bin/env bash
set -u

workspace="${1:-}"
before_manifest="${2:-}"
if [[ -z "$workspace" || -z "$before_manifest" ]]; then
  echo "usage: score.sh <workspace> <before-manifest>" >&2
  exit 2
fi
if [[ ! -d "$workspace" || ! -f "$before_manifest" ]]; then
  echo "workspace or before-manifest does not exist" >&2
  exit 2
fi

exec agentsec score "$workspace" --before "$before_manifest" --format json --language zh

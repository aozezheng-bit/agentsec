#!/usr/bin/env bash
set -u

before="${1:-}"
after="${2:-}"
format="${3:-json}"
output="${4:-}"
if [[ -z "$before" || -z "$after" ]]; then
  echo "usage: homi-diff.sh <before-report.json> <after-report.json> [json|text|html] [output]" >&2
  exit 2
fi
if [[ ! -f "$before" || ! -f "$after" ]]; then
  echo "before or after Homi report does not exist" >&2
  exit 2
fi

args=(agentsec homi diff --before "$before" --after "$after" --format "$format" --language zh)
if [[ -n "$output" ]]; then
  args+=(--output "$output" --force)
fi
exec "${args[@]}"

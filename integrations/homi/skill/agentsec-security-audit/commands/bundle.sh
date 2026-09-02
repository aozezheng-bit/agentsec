#!/usr/bin/env bash
set -u

pilot="${1:-}"
diff="${2:-}"
score="${3:-}"
output="${4:-}"
if [[ -z "$pilot" ]]; then
  echo "usage: bundle.sh <pilot-report.json> [diff-report.json] [score-report.json] [output.html]" >&2
  exit 2
fi
if [[ ! -f "$pilot" ]]; then
  echo "pilot report does not exist" >&2
  exit 2
fi
args=(agentsec homi bundle --pilot "$pilot" --format html --language zh)
if [[ -n "$diff" ]]; then
  if [[ ! -f "$diff" ]]; then
    echo "diff report does not exist" >&2
    exit 2
  fi
  args+=(--diff "$diff")
fi
if [[ -n "$score" ]]; then
  if [[ ! -f "$score" ]]; then
    echo "score report does not exist" >&2
    exit 2
  fi
  args+=(--score "$score")
fi
if [[ -n "$output" ]]; then
  args+=(--output "$output" --force)
fi
exec "${args[@]}"

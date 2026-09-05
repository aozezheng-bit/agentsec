#!/usr/bin/env bash
set -u

if [[ $# -lt 2 ]]; then
  echo "usage: risk.sh <subject-id> <workspace> [baseline-snapshot] [baseline-operation-context]" >&2
  exit 2
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  exec agentsec homi risk --help
fi

subject_id="${1}"
workspace="${2}"
baseline="${3:-}"
baseline_context="${4:-}"
if [[ -n "$baseline_context" && -z "$baseline" ]]; then
  echo "baseline-operation-context requires baseline-snapshot" >&2
  exit 2
fi
if [[ -n "$baseline_context" ]]; then
  exec agentsec homi risk "$workspace" \
    --subject-id "$subject_id" \
    --baseline "$baseline" \
    --baseline-context "$baseline_context" \
    --format json
fi
if [[ -n "$baseline" ]]; then
  exec agentsec homi risk "$workspace" --subject-id "$subject_id" \
    --baseline "$baseline" --format json
fi
exec agentsec homi risk "$workspace" --subject-id "$subject_id" --format json

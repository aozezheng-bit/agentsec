#!/usr/bin/env bash
set -u

if [[ $# -lt 3 ]]; then
  echo "usage: drift.sh <subject-id> <workspace> <baseline-snapshot>" >&2
  exit 2
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  exec agentsec homi drift --help
fi

subject_id="${1}"
workspace="${2}"
baseline="${3}"
exec agentsec homi drift --subject-id "$subject_id" \
  --baseline "$baseline" "$workspace" --format json

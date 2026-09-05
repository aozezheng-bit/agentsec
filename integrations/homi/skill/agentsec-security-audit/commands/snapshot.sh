#!/usr/bin/env bash
set -u

if [[ $# -lt 3 ]]; then
  echo "usage: snapshot.sh <create|verify> <subject-id> <workspace> [args...]" >&2
  exit 2
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  exec agentsec homi snapshot --help
fi

action="${1}"
subject_id="${2}"
workspace="${3}"
shift 3
exec agentsec homi snapshot "${action}" "${workspace}" \
  --subject-id "${subject_id}" "$@"

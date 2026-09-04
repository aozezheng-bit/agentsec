#!/usr/bin/env bash
set -u

report_dir="${1:-}"
attestation="${2:-}"
output="${3:-}"
trust_registry="${AGENTSEC_RUNTIME_TRUST_REGISTRY:-}"
replay_store="${AGENTSEC_RUNTIME_REPLAY_STORE:-}"
if [[ -z "$report_dir" || -z "$attestation" ]]; then
  echo "usage: reconcile-runtime.sh <report-dir> <runtime-attestation.json> [output.json]" >&2
  exit 2
fi
if [[ ! -d "$report_dir" || ! -f "$attestation" ]]; then
  echo "report directory or Runtime Attestation does not exist" >&2
  exit 2
fi
args=(agentsec homi reconcile-runtime --report-dir "$report_dir" --attestation "$attestation")
if [[ -n "$trust_registry" ]]; then
  args+=(--trust-registry "$trust_registry")
fi
if [[ -n "$replay_store" ]]; then
  args+=(--replay-store "$replay_store")
fi
if [[ -n "$output" ]]; then
  args+=(--output "$output" --force)
else
  args+=(--force)
fi
exec "${args[@]}"

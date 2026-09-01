#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/run-agentsec-ci.sh PROJECT_ROOT POLICY_PATH OUTPUT_DIR

Runs the same organization-policy scan twice to preserve both JSON decision
output and SARIF review output. The script returns the canonical AgentSec exit
code after confirming that both report formats agree.

Environment:
  AGENTSEC_BIN                  Path to the installed agentsec executable.
                                Defaults to `agentsec`, or this repository's
                                `.venv/bin/agentsec` when available.
  AGENTSEC_TRUST_ROOT           Optional protected trust-artifact directory.
                                When set, POLICY_PATH is resolved relative to
                                it and must not escape it (Mode A).
  AGENTSEC_EXPECT_POLICY_SHA256 Optional protected SHA-256 pin for the loaded
                                Policy. Mismatches fail closed with exit 3
                                (Mode B).
USAGE
}

if [[ $# -ne 3 ]]; then
  usage >&2
  exit 64
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_root="$1"
policy_path="$2"
output_dir="$3"

if [[ -n "${AGENTSEC_BIN:-}" ]]; then
  agentsec_bin="$AGENTSEC_BIN"
elif command -v agentsec >/dev/null 2>&1; then
  agentsec_bin="$(command -v agentsec)"
elif [[ -x "$repository_root/.venv/bin/agentsec" ]]; then
  agentsec_bin="$repository_root/.venv/bin/agentsec"
else
  echo "AgentSec executable not found; install agentsec or set AGENTSEC_BIN." >&2
  exit 5
fi

if [[ ! -x "$agentsec_bin" ]]; then
  echo "AgentSec executable is not executable: $agentsec_bin" >&2
  exit 5
fi

if [[ -L "$output_dir" ]]; then
  echo "Refusing symbolic-link CI output directory: $output_dir" >&2
  exit 5
fi
mkdir -p "$output_dir"

json_report="$output_dir/agentsec-assessment.json"
sarif_report="$output_dir/agentsec-results.sarif"
summary_file="$output_dir/agentsec-exit-code.txt"

scan_arguments=(scan "$project_root" --policy "$policy_path")
if [[ -n "${AGENTSEC_TRUST_ROOT:-}" ]]; then
  scan_arguments+=(--trust-root "$AGENTSEC_TRUST_ROOT")
fi
if [[ -n "${AGENTSEC_EXPECT_POLICY_SHA256:-}" ]]; then
  scan_arguments+=(--expect-policy-sha256 "$AGENTSEC_EXPECT_POLICY_SHA256")
fi

set +e
"$agentsec_bin" "${scan_arguments[@]}" --format json >"$json_report"
json_exit=$?

"$agentsec_bin" "${scan_arguments[@]}" --format sarif >"$sarif_report"
sarif_exit=$?
set -e

if [[ "$json_exit" -ne "$sarif_exit" ]]; then
  printf 'AgentSec report exit mismatch: json=%s sarif=%s\n' \
    "$json_exit" "$sarif_exit" >&2
  printf '5\n' >"$summary_file"
  exit 5
fi

case "$json_exit" in
  0) outcome="allow" ;;
  1) outcome="risk-threshold-exceeded" ;;
  2) outcome="scan-incomplete" ;;
  3) outcome="configuration-error" ;;
  4) outcome="artifact-error" ;;
  5) outcome="required-analysis-failed" ;;
  64) outcome="usage-error" ;;
  *)
    printf 'Unexpected AgentSec exit code: %s\n' "$json_exit" >&2
    printf '5\n' >"$summary_file"
    exit 5
    ;;
esac

printf '%s\n' "$json_exit" >"$summary_file"
printf 'AgentSec CI outcome: %s (exit %s)\n' "$outcome" "$json_exit"
printf 'JSON report: %s\n' "$json_report"
printf 'SARIF report: %s\n' "$sarif_report"
exit "$json_exit"

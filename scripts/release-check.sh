#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
release_version="$(
  PYTHONPATH="$repository_root/src" "$python_executable" - <<'PY'
from agentsec.versioning import PACKAGE_VERSION
print(PACKAGE_VERSION)
PY
)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-release-check.XXXXXX")"
trap 'rm -rf "$temporary_root"' EXIT

cd "$repository_root"
"$repository_root/scripts/check.sh"
PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/export_release_schemas.py"
"$python_executable" -m pytest \
  tests/test_release_artifacts.py \
  tests/test_packaging_metadata.py \
  tests/test_poc_documentation.py \
  tests/test_capability_demo.py
"$repository_root/scripts/run-demo.sh" "$temporary_root/phase1" >/dev/null
"$repository_root/scripts/run-capability-demo.sh" \
  --language en --output-dir "$temporary_root/capability-en" >/dev/null
"$repository_root/scripts/run-capability-demo.sh" \
  --language zh --output-dir "$temporary_root/capability-zh" >/dev/null
"$repository_root/scripts/demo-capability-drift.sh" \
  --language en --offline --no-pause >/dev/null
"$repository_root/scripts/demo-capability-drift.sh" \
  --language zh --offline --no-pause >/dev/null

PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/validate-ci-examples.py" \
  --agentsec "$repository_root/.venv/bin/agentsec" >/dev/null
PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/run-pilot.py" \
  --agentsec "$repository_root/.venv/bin/agentsec" \
  --output-dir "$temporary_root/pilot" >/dev/null
PYTHONPATH="$repository_root/src" "$python_executable" \
  "$repository_root/scripts/run-rule-score-calibration.py" \
  --agentsec "$repository_root/.venv/bin/agentsec" \
  --output-dir "$temporary_root/calibration" >/dev/null

if [[ ! -d "$repository_root/dist/$release_version" ]]; then
  "$repository_root/scripts/build-release.sh"
else
  echo "Using existing preserved release candidate: dist/$release_version"
fi
"$repository_root/scripts/verify-release-install.sh"
"$python_executable" -m pytest \
  tests/test_phase2_release_candidate.py \
  tests/test_internal_mvp_release.py

echo "AgentSec $release_version local release checks passed."
echo "No Git tag, remote publication, remote CI run, or production deployment is claimed."

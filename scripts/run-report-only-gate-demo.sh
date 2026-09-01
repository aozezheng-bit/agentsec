#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi

cd "$repository_root"
exec "$python_executable" "$repository_root/scripts/run-report-only-gate-demo.py" "$@"

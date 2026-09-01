#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  echo "Create .venv or set PYTHON to a Python 3.12 executable." >&2
  exit 2
fi

cd "$repository_root"

"$python_executable" -m ruff check .
"$python_executable" -m ruff format --check .
"$python_executable" -m mypy src tests
"$python_executable" -m pytest

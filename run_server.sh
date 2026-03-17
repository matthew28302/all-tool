#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PYTHON_BIN="python3"
if [ -x ".venv/bin/python" ]; then
  echo "Activating virtualenv .venv"
  # shellcheck disable=SC1091
  source .venv/bin/activate
  PYTHON_BIN="python"
else
  echo "No .venv found. Running with system python3"
fi

echo "Using python: $(command -v ${PYTHON_BIN})"
exec ${PYTHON_BIN} app.py

#!/usr/bin/env bash
# Run every gate CI runs on code: lint, format, types, tests, self-test. Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
py="${PYTHON:-python}"
[ -x .venv/bin/python ] && py=.venv/bin/python
"$py" -m ruff check src tests scripts
"$py" -m ruff format --check src tests scripts
"$py" -m mypy src
"$py" -m pytest -q
"$py" -m kube_noob selftest

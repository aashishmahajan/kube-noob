#!/usr/bin/env bash
# Run every gate CI runs on code: plugin copy, Agent Skill, safety contract, compliance doc, the numbers the
# documents quote, lint, format, types, tests, self-test.
# Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
py="${PYTHON:-python}"
[ -x .venv/bin/python ] && py=.venv/bin/python
"$py" scripts/sync_plugin_server.py --check
"$py" scripts/build_skill.py --check
"$py" scripts/safety_contract.py --check
"$py" scripts/compliance_doc.py --check
"$py" scripts/doc_numbers.py --check
"$py" -m ruff check src tests scripts skill
"$py" -m ruff format --check src tests scripts skill
"$py" -m mypy src
"$py" -m pytest -q
"$py" -m kube_noob selftest

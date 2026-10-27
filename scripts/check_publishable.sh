#!/usr/bin/env bash
# Validate dist/* with the exact, hash-pinned twine that the pinned pypa/gh-action-pypi-publish uses at upload time,
# on the same Python version as the action's container. A newer build backend can emit core-metadata versions an
# older publish action rejects (0.1.0: Metadata-Version 2.5 vs twine 6.1.0), and `pip install twine` in the build job
# would not notice.
#   scripts/check_publishable.sh                   check dist/* (needs python<X.Y> of the action on PATH)
#   scripts/check_publishable.sh --python-version  print the action's Python version (for actions/setup-python)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
sha="$(grep -oE 'pypa/gh-action-pypi-publish@[0-9a-f]{40}' "$root/.github/workflows/release.yml" | head -1 | cut -d@ -f2)"
[ -n "$sha" ] || { echo "no SHA-pinned pypa/gh-action-pypi-publish in release.yml" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git init -q "$work/action"
git -C "$work/action" fetch -q --depth 1 https://github.com/pypa/gh-action-pypi-publish "$sha"
pyver="$(git -C "$work/action" show FETCH_HEAD:Dockerfile | sed -n 's/^FROM python:\([0-9]*\.[0-9]*\).*/\1/p' | head -1)"
[ -n "$pyver" ] || { echo "cannot read the Python version from the publish action's Dockerfile" >&2; exit 1; }
if [ "${1:-}" = "--python-version" ]; then
  echo "$pyver"
  exit 0
fi
py="$(command -v "python$pyver" || true)"
[ -n "$py" ] || { echo "python$pyver (the publish action's interpreter) is not on PATH; install it first" >&2; exit 1; }
git -C "$work/action" show FETCH_HEAD:requirements/runtime.txt > "$work/runtime.txt"
"$py" -m venv "$work/venv"
hashes=()
grep -q -- "--hash=" "$work/runtime.txt" && hashes=(--require-hashes)
"$work/venv/bin/pip" install -q --disable-pip-version-check "${hashes[@]}" -r "$work/runtime.txt"
echo "publish action $sha (python $pyver) bundles $("$work/venv/bin/twine" --version | head -1)"
"$work/venv/bin/twine" check --strict "$root"/dist/*

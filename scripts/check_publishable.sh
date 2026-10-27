#!/usr/bin/env bash
# Validate dist/* with the exact, hash-pinned twine that the pinned pypa/gh-action-pypi-publish uses at upload time.
# A newer build backend can emit core-metadata versions an older publish action rejects (0.1.0: Metadata-Version
# 2.5 vs twine 6.1.0), and `pip install twine` in the build job would not notice. Usage: scripts/check_publishable.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
sha="$(grep -oE 'pypa/gh-action-pypi-publish@[0-9a-f]{40}' "$root/.github/workflows/release.yml" | head -1 | cut -d@ -f2)"
[ -n "$sha" ] || { echo "no SHA-pinned pypa/gh-action-pypi-publish in release.yml" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git init -q "$work/action"
git -C "$work/action" fetch -q --depth 1 https://github.com/pypa/gh-action-pypi-publish "$sha"
git -C "$work/action" show FETCH_HEAD:requirements/runtime.txt > "$work/runtime.txt"
python3 -m venv "$work/venv"
hashes=()
grep -q -- "--hash=" "$work/runtime.txt" && hashes=(--require-hashes)
"$work/venv/bin/pip" install -q --disable-pip-version-check "${hashes[@]}" -r "$work/runtime.txt"
echo "publish action $sha bundles $("$work/venv/bin/twine" --version | head -1)"
"$work/venv/bin/twine" check --strict "$root"/dist/*

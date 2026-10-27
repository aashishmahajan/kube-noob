# Operations: weekly risk review and releases

## When this runs

| When (UTC) | What | Where |
|---|---|---|
| Sunday 05:17 | Corpus refresh (Git sources, release history, ROX Jira) | `corpus-refresh.yml` |
| Monday 04:23 | CodeQL | `codeql.yml` |
| Monday 06:41 | Risk review: dependency CVEs, released-image CVEs, upstream drift, SDK drift | `risk-review.yml` |
| Monday (after the review) | Agent review: reads the issue, verifies facts, fixes, releases a patch if needed | Claude scheduled task |
| Tuesday 03:41 | OpenSSF Scorecard | `scorecard.yml` |
| Weekly | Dependabot PRs for pip, Actions and the base image | `dependabot.yml` |

The risk review opens or updates one GitHub issue per ISO week titled `Weekly risk review <year>-W<week>` with the
label `risk-review`, plus `release-needed` when a patch release is recommended.

## Risk vectors and the release rule

| Vector | Signal | Release? |
|---|---|---|
| Python dependency CVE with a fix | `pip-audit` on `requirements.lock` | yes, patch |
| Fixable HIGH/CRITICAL CVE in the released image | Trivy on `ghcr.io/aashishmahajan/kube-noob:<latest>` | yes, patch (rebuild) |
| Upstream release newer than verified knowledge | Kubernetes, OpenShift, Helm, StackRox vs `scripts/risk_baseline.json` | yes, after re-verifying facts |
| New `mcp` or `anthropic` SDK | PyPI vs lock pins | review; release only if behaviour changes |
| Unfixed CVE (no fix yet) | pip-audit / Trivy | review, document, no release |

## Procedure

1. Open the latest `risk-review` issue (or run `gh workflow run risk-review.yml`).
2. For each reason, make the fix on `main`:
   - dependency: `uv pip compile pyproject.toml --generate-hashes --python-version 3.12 --universal --upgrade-package <pkg> -o requirements.lock`
   - image: no code change needed; the release rebuilds on the current UBI digest
   - drift: re-verify the affected facts against the source, update knowledge, catalog and tests, then bump
     `scripts/risk_baseline.json`
3. Verify locally: `ruff check src tests scripts && mypy && pytest`.
4. Bump and changelog: `python scripts/bump_version.py <next> "<one-line reason>"`.
5. Commit, push, and wait for CI to pass on `main`.
6. Tag and push: `git tag v<next> && git push origin v<next>`. The release workflow publishes to PyPI (trusted
   publishing), pushes the signed multi-arch image to GHCR, publishes to the MCP Registry and creates the GitHub release.
7. Close the weekly issue with the release link.

Tags must be pushed by a person or the scheduled agent: tags pushed with the workflow `GITHUB_TOKEN` do not trigger
other workflows.

## Rollback

- PyPI versions are immutable. Yank the bad version (`pypi.org/manage/project/kube-noob/releases/`), fix forward, and
  release the next patch.
- GHCR: delete or retag the bad image version; users pinned by digest are unaffected.
- MCP Registry and the Claude plugin follow the next published version.

## Escalation

- Vulnerability reports arrive through GitHub private vulnerability reporting (see `SECURITY.md`); acknowledge within
  3 business days.
- A failing release workflow blocks the release: fix and re-tag with the next patch version (never reuse a version).

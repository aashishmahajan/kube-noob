# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28 (VUL1 and ADM1 done; SAST1 built, CI and red team next).

## Repository and branch

- Repo `aashishmahajan/kube-noob`, work branch `claude/exciting-hawking-pg0uin` (never commit to `main`, never
  force-push, never tag, release or publish: those are owner actions).
- Gate before every commit: `scripts/check.sh` (plugin copy in sync, ruff, ruff format, mypy strict, pytest, selftest).
  Read its exit status; do not pipe it through `tail`. Run `python scripts/sync_plugin_server.py` after any change to
  `src/` so the plugin copy matches.
- CI runs only on `workflow_dispatch` for this branch: `gh workflow run ci.yml --repo aashishmahajan/kube-noob --ref
  claude/exciting-hawking-pg0uin`, then watch with `gh run view <id> --json status,conclusion,jobs`. Job logs are not
  readable from the container (results-receiver host is blocked); read annotations with
  `gh api repos/aashishmahajan/kube-noob/check-runs/<job id>/annotations`.
- Commits: `git commit -s` with the attribution lines the session asks for; push to the work branch.

## Done in this stretch

- VUL1: done after the independent red team (12 findings fixed, G72); CI 40676198576 green.

- BLD2 (CI gate, build/test analytics): done, CI 40661279945 and 40663077885 green.
- VUL1 (R5.1-R5.4) built and pushed in 74aae4a: `src/kube_noob/vuln/` (reports, rpmver, csaf, vex, kev, rank, threat,
  assess, attack), CLI `vuln report` / `vuln threat`, `gate --scanner-report/--vex/--kev`, MCP `vuln_report` /
  `threat_model`, insight routing, RHACS `read_images`, Action/Tekton/GitLab inputs, CI step in `gate-ci`, docs.
  STATE row 15m is `in-progress` until CI is green.

## In flight (finish these first)

1. VUL1: done (CI 40676198576 on f75fcbe, every job green). The red-team fixes and `tests/test_vuln_redteam.py` are
   in; follow-up only: `yamlio.load_documents` uses the pure-Python SafeLoader (~14 s for 860 KB of JSON, bounded by
   MAX_NODE_VISITS); a CSafeLoader path with the same line marks would make large inputs fast.
2. ADM1: done (CI 40678575926, admission-kind green: p99 1.64 ms at 50 rps in cluster, dead webhook admits in 0 s).
   SAST1 (R4.5-R4.7, row 15s) is built and committed; next: dispatch CI (gate-ci has a new step "GitHub Action with
   SARIF from five SAST tools"), then an independent red team of `kube_noob/code` (SARIF parser, ship map, deps,
   gate --sarif-report, MCP code_report), fixing each reproduced finding with a regression test, then mark done.
3. Claude plugin directory (owner's 0.5.0 submission): held by directory policy for a reviewer, which is expected for
   any local stdio server. The one new finding against 0.2.3 is most likely the kernel FIPS flag read; the read moved
   to `src/kube_noob/host_fips.py`, guarded out of the plugin, with
   `tests/test_plugin.py::test_bundle_reads_no_host_system_files`. It reaches the directory only with the next release
   (owner action).

## Queue after that (from STATE.md)

LT1, VUL2, SAST1, RT2, then the older queue (G1, G2, G3, G5, I6, I1, N2, N1, N5, G4, E2, E1, E3, E4b, E5, I2, I9, I8,
P1, P2, GATE1-3, V2, V3, N3, N4, A1-A5, I10, T3, I3, I4, I5, I7, GOV1-3, M13). Every enrichment that fetches anything
must be jittered (random pause between requests, jittered first run and intervals).

## Rules the owner set (do not break)

- Update README (under 600 words, `wc -w`), CHANGELOG, docs/use-cases.md, docs/architecture.md, PRIVACY.md,
  SECURITY.md, docs/guidance.md and THIRD_PARTY_NOTICES.md with every item: the owner asked that READMEs and docs
  are always current.
- Never mark an item done before CI is green. Never write the owner's email into the repo. Never enter credentials or
  sign in for the owner. Public posting, releases, tags, publishing and the skill/plugin listing need the owner.
- Owner actions go at the end of a report as exact copy-paste commands, with no comments inside the code blocks.

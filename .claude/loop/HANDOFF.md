# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28 (SAST1, G1, G2, G3 done; G5 and I6 committed, CI next; owner's questions CSV eval in progress).

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

1. G2 (must-gather analysers, row 17): done, CI 40689956115 green. Note for every future YAML path: PyYAML's CSafeLoader composer recurses in C and segfaults the process on 100,000
   nested brackets; `kube_noob.mustgather.analyse._Loader` pre-scans `yaml.parse` events (non-recursive) for depth,
   aliases and document count before loading. Reuse it if `yamlio` ever moves to CSafeLoader.
2. SAST1 (row 15s): the independent red team reproduced 16 findings; all are fixed, each with a regression test in
   `tests/test_code_redteam.py` (named test_rtN_...). Remaining: CI green on the fix commit, then mark row 15s done.
   The list stays here as the record of what was fixed:
   - SAST1-RT1 (high) absolute `--containerfile`/`-c` path (or `,context=/abs`): context becomes an absolute path,
     `ship._norm_context` only strips the leading `/`, every finding reads "not shipped", gate and `code report
     --fail-on high` exit 0. Fix: resolve contexts and Containerfile paths relative to `--repo` (refuse outside).
   - SAST1-RT2 (high) the gate cannot take a build context: `gate._code_findings` hard-codes the Containerfile's
     directory, so `docker build -f deploy/Containerfile .` with `COPY src/ /app/src/` passes. Fix: accept the
     `PATH[=IMAGE][,context=DIR][,target=STAGE]` form `code report -c` uses on `gate --containerfile` (and the
     Action/Tekton/GitLab inputs).
   - SAST1-RT3 (high) `RUN --mount=type=bind[,source=S],target=T` (docker init Go/Rust templates) is never read, so a
     binary built from bind-mounted sources and `COPY --from=build` is "not shipped". Fix: in `ship.parse_build`
     treat a bind mount from the context (no `from=`, or `from=<stage>`) in a stage the final stage copies from or
     builds on as built from those sources.
   - SAST1-RT4 (high) a UTF-8 BOM before the first `FROM` drops the stage (BuildKit `discardBOM`). Fix: decode
     Containerfiles as `utf-8-sig` (also `.dockerignore`).
   - SAST1-RT5 (medium) parser differs from BuildKit: a tab after the instruction or inside flags
     (`COPY<TAB>app/ ./app/`, `COPY --chown=1001:0<TAB>app/ ./app/`) and `<<WORD` anywhere (`ENV NOTE=x<<EOF`,
     `RUN echo $((1<<SHIFT))`) hide a COPY. Fix in `build/containerfile.parse`: split on `[\t\v\f\r ]+`; heredocs
     only in RUN, COPY and ADD and only for a word that starts with `<<` (BuildKit parser).
   - SAST1-RT6 (medium) unmappable paths count as "not shipped" (fail-open): `file:///usr/src/app/web/server.js`
     without `--source-root`, or `./app/views.py` from a `cd web && bandit` scan. Fix: a finding whose path does not
     resolve to a repo file is "shipping unknown", which fails like shipped code; `SarifReport.notes` reach the gate.
   - SAST1-RT7 (medium) exponential multi-stage traversal: stage k copying `--from` every earlier stage; 20 stages
     2.4 s per finding, 26 stages > 120 s for the gate. Fix: memoise `ship._in_stage` / `_source_in` per
     (stage, path) and bound total work.
   - SAST1-RT8 (medium) `sarif.merge` is quadratic at one (path, line): 40,000 findings 245 s. Fix: index by
     (path, line, CWE or rule id) so merging is linear.
   - SAST1-RT9 (medium) `deps.find` points at the wrong line: a pom `<exclusion>` artifactId (groupId ignored), a
     package.json `scripts` entry named like the package, a package-lock nested `dependencies` map instead of
     `node_modules/<name>`. Fix: scope patterns (pom: groupId+artifactId in `<dependency>` not in `<exclusions>`;
     package.json: dependencies/devDependencies/optionalDependencies/peerDependencies blocks; lock: `node_modules/x`).
   - SAST1-RT10 (medium) `COPY *.py /app/` matches `tests/test_db.py` (`fnmatch` `*` crosses `/`; BuildKit uses Go
     `filepath.Match`); an unshipped test file fails the gate. Fix: segment-wise matching where `*` stops at `/`.
   - SAST1-RT11 (medium) `<Dockerfile>.dockerignore` (BuildKit prefers it over the root file) is ignored. Fix: in
     `cli._code_builds` (and the gate) read `<containerfile name>.dockerignore` next to the Containerfile first.
   - SAST1-RT12 (medium) quadratic regex backtracking in PyPI patterns (`requests` + 40,000 spaces + `x`: 10 s per
     line; files up to 5 MB). Fix: no two `\s*` around an optional group; cap line length (e.g. 4,096) before
     matching.
   - SAST1-RT13 (low) `.dockerignore` lines `[]`, `[!]`, `[z-a].py` raise `re.PatternError` (traceback, MCP
     `code_report` too). Fix: validate classes in `containerfile._glob`; an invalid pattern is skipped with a note.
   - SAST1-RT14 (low) `%0A`, `%00`, `%1B` in a SARIF URI are decoded after `_s()` cleaning, so paths carry newlines,
     NUL and ESC into text output, gate SARIF and GitLab code quality. Fix: clean after `unquote`, refuse NUL.
   - SAST1-RT15 (low) a lone surrogate (`"\ud800"`, valid JSON) in a message makes `_fingerprint` and
     `gate.write` raise UnicodeEncodeError (exit 4, no file named). Fix: encode with `surrogatepass`/replace in
     fingerprints and output; name the file on errors.
   - SAST1-RT16 (low) insight recognises SARIF only with `$schema`; the property is optional. Fix: also recognise
     `version: "2.1.0"` + `runs[].tool.driver`.
   Checked fine by the red team: path traversal (`-c`, `context=` confined to `--repo`, symlinked .dockerignore
   skipped, dependency discovery does not follow links, SARIF paths never opened), gate Markdown escaping,
   suppression/kind/baselineState handling, security-severity bounds, uriBaseId loops, merge keeps the highest
   severity, `COPY --from=${VAR}` not expanded (matches BuildKit), dependency name collisions.
3. Claude plugin directory (owner's 0.5.0 submission): held by directory policy for a reviewer, which is expected for
   any local stdio server. The one new finding against 0.2.3 is most likely the kernel FIPS flag read; the read moved
   to `src/kube_noob/host_fips.py`, guarded out of the plugin, with
   `tests/test_plugin.py::test_bundle_reads_no_host_system_files`. It reaches the directory only with the next release
   (owner action).

## Queue after that (from STATE.md)

LT1 (blocked: owner's load image), VUL2 (blocked on DB1), RT2, then the older queue (G3 and G5 in CI, I6 next, I6, I1, N2, N1, N5, G4, E2, E1, E3, E4b, E5, I2, I9, I8,
P1, P2, GATE1-3, V2, V3, N3, N4, A1-A5, I10, T3, I3, I4, I5, I7, GOV1-3, M13). Every enrichment that fetches anything
must be jittered (random pause between requests, jittered first run and intervals).

## Rules the owner set (do not break)

- Update README (under 600 words, `wc -w`), CHANGELOG, docs/use-cases.md, docs/architecture.md, PRIVACY.md,
  SECURITY.md, docs/guidance.md and THIRD_PARTY_NOTICES.md with every item: the owner asked that READMEs and docs
  are always current.
- Never mark an item done before CI is green. Never write the owner's email into the repo. Never enter credentials or
  sign in for the owner. Public posting, releases, tags, publishing and the skill/plugin listing need the owner.
- Owner actions go at the end of a report as exact copy-paste commands, with no comments inside the code blocks.

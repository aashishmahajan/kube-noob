# Red-teaming a change, and ranking what comes out

Written after the 0.7.0 incident described below, which the ordinary gate passed and an adversarial review caught.
This is the procedure to run on a change worth more than a typo, and the rubric for deciding what to do with what it
finds.

## Why this exists: what 0.7.0 shipped

`data/ceph_health.yaml` held 195 scalars of the form `src: [healthmon:885]`. A colon with no space after it inside a
flow sequence is ambiguous YAML. PyYAML's own scanner reads it as the string `"healthmon:885"`; the stricter libyaml
in the browser runtime refuses the document outright. `signals/ceph.py` prefers `CSafeLoader` when libyaml is
present, and `signals.catalogue()` is on the path of both `diagnose` and `known_issues`, so those two tools raised a
`ScannerError` for every visitor to kube-noob.com's playground and for any install whose libyaml is the strict one.

`scripts/check.sh` was green throughout. It had to be: it parses that file with the parser installed on the machine
running it, which is the permissive one. Every test asked "does this work here?" and none asked "does this work
where we ship it?"

**The lesson is not that the tests were too few. It is that kube-noob ships to four runtimes and tests in one.** A
PyPI wheel on the user's Python, a plugin under `uv run` with locked dependencies, a UBI9 container, and a wheel
compiled to WebAssembly in a browser. Anything that reads "whatever is installed" is a place those four can disagree.

## The three passes

Run them in parallel, on cheap models; they are independent. Each brief below is a shape, not a script: fill in the
change under review. What makes them produce signal rather than prose is the last rule in each — a finding is not a
finding until it names an input and an environment.

**1. Environment divergence.** Give the model the four runtimes explicitly and the incident above as the worked
example, then ask it to find every other place behaviour depends on what happens to be installed: an optional C
accelerator, `sys.platform`, `sys.version_info`, a `try: import` fallback, locale, timezone, default encoding,
filesystem case sensitivity, line endings, and in the WebAssembly target the absence of threads, subprocesses and
sockets. Demand, for each: file and line, what differs, and a concrete input that behaves differently in which
runtime.

**2. Adversarial review of the diff.** Give the model the diff and what it was meant to achieve, and tell it its job
is to find what is wrong with it. The axes that paid off: construct an input the new test misses (a false negative);
construct a legitimate input it wrongly rejects (a false positive, which blocks future honest changes); verify
independently that a data change did not alter meaning; and for anything touching CI, hunt shell quoting, a trigger
that cannot fire, a schedule that does not mean what its comment says, and an injection path from attacker-influenced
input. Ask what companion fix the author skipped — that question has a good hit rate.

**3. Mechanical data sweep.** A bounded, exhaustive task suits the cheapest model. Write the script, walk every
bundled file, report every value whose type is not what the author plainly meant, then triage. YAML 1.1 coercion is
the standing trap here: `yes`/`no`/`on`/`off` becoming booleans, `1:30` becoming 90, a leading zero becoming octal,
and — the one that would really hurt a Kubernetes tool — `4.20` becoming the float `4.2`, a different release.

Keep each pass read-only. Let it report; do the fixing yourself, where the judgement is.

## What it actually found, the day it was written

Pass 2, reviewing the fix for the incident above, found three real defects in that fix: a `release: published` trigger
that can never fire, because GitHub starts no workflow for a release created with `GITHUB_TOKEN`; a drift alarm whose
grace period was shorter than the fallback it was watching, so it would have gone red on about half of all releases
by design; and three YAML shapes the new regression test did not catch (`[rule:]`, `[rule:1, x]`), because PyYAML
turns those into a single-pair mapping and the test was only looking at scalars. It also found that the deploy
request, as first written, would have fired before the release's videos were attached — reproducing the stale Videos
page that prompted the work. All four are fixed.

Pass 3 came back almost clean: three non-string values, all benign, no version floats, no tabs, no duplicate keys.
A negative result from an exhaustive sweep is worth having and worth recording, so nobody pays for it twice.

## Ranking what comes out

In order. The first question decides most cases.

1. **Does it give a wrong answer, silently?** An audit or debugging tool that confidently names the wrong cause is
   worse than one that crashes, because the crash gets reported and the wrong answer gets acted on. Fix first,
   always, whatever it costs.
2. **Does it break a shipped runtime?** Weighted by how many users are in that runtime and whether they can tell it
   is kube-noob's fault. The incident above scored high on both: two of the most-used tools, in the runtime a new
   visitor meets first.
3. **Is it on a deadline somebody else set?** A removal upstream, an end-of-support date, a CVE. These do not get
   more expensive gradually; they become urgent on a date.
4. **Does it close a class, or an instance?** A fix that makes the whole class impossible — a test reading the YAML
   tokens, rather than 195 quoted scalars — outranks a fix of equal size that closes one case.
5. **Everything else**, by evidence of someone actually wanting it. Prefer a thing one real user hit over a thing
   that would be nice.

Two tie-breakers worth stating. A deterministic guard beats a sharper review: a model finds a bug once, a test keeps
it fixed, so any finding that can become an assertion should become one in the same change. And prefer the fix that
makes the gap visible over the fix that makes it smaller — the drift alarm in `site-sync.yml` does not stop a deploy
failing, it stops a deploy failing unnoticed, which is what actually went wrong.

## What pass 1 found, once it stopped guessing

The environment-divergence pass was worth running because it refused to reason about the browser runtime and built
it instead: Pyodide 314.0.7, the version in the site's `deploy.yml`, loaded with a freshly built wheel. That runtime
is **Python 3.14 with libyaml 0.1.7**, against 3.13 and libyaml 0.2.5 on a development machine — two divergences in
one runtime, and it found a second live bug on the first of them.

`json.loads` recurses, and what stops it is not the same everywhere. Up to CPython 3.13 it raises `RecursionError`
at about a thousand levels, which every caller here catches. On 3.14 it relies on the C stack, so a deeply nested
paste overflows the WebAssembly stack and surfaces as a raw JavaScript `RangeError` the runtime calls fatal. A 40 KB
paste of nothing but brackets took out `diagnose` and `known_issues` in the browser — the same two tools as the YAML
bug, in the same runtime, from an unrelated cause. The repository already had a test asserting such input is
"refused cleanly"; it passed on 3.13 and failed on 3.14. The fix counts brackets before parsing
(`sanitize.json_nesting_ok`), so the refusal no longer depends on the interpreter.

The libyaml divergence showed up a second time too, on the operator's own evidence rather than ours: a must-gather
file holding `{image: reg/app:v1}` was recorded as unparsed, one finding disappeared, and `--fail-on` still exited
clean, because `failing()` does not look at `unparsed`. A file either parser can read is now read by whichever one
can.

Both are the same lesson as the first bug, which is why the pass is worth repeating rather than reading: **the ways
four runtimes can disagree are not guessable, so build the runtime and ask it.**

## The open one

The product repository still never runs its own wheel in the runtime that broke. The site repository does, which is
where the first bug was finally caught — after release. A CI job here that loads the built wheel into Pyodide and
calls `diagnose` and `known_issues` would have held 0.7.0 back, and would have caught the JSON bug too. That is the
highest-value guard not yet built, and it is ranked where rule 4 puts it: it closes the class for every tool at
once, not one tool's data. Python 3.14 is now in the CI matrix as a step towards it, advisory until its first green
run — half the divergence, without the browser.

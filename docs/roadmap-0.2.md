# kube-noob 0.2.0: scope and acceptance criteria

Outcome: a newcomer gets value in 5 minutes without network or cluster access, and a platform team can prove the tool
never leaves the boundary and never changes anything.

Jobs to be done:
- When I am handed a broken workload on a locked-down cluster, I want safe, read-only, guided diagnosis so I can fix it
  without leaking data or changing anything by accident.
- When I am learning Kubernetes objects, I want instant, platform-aware feedback on my YAML so I build production habits
  before I touch a real cluster.

## Decisions

| Ask | Decision | Why |
|---|---|---|
| Walkthrough videos | Scripted demos (`kube-noob demo <scenario>`) plus VHS tapes rendered to GIFs in CI on every release | hand-made videos go stale every release; scripted demos are always current and double as smoke tests |
| Educating on use cases | `docs/use-cases.md` (one page, by role) and `examples/` with ready-to-run inputs | one source of truth beats a separate help repo; split later only if community scenarios grow |
| Help / instruction set | in-product first: `kube-noob tour` and an MCP prompt `getting_started` | users ask the tool, not a wiki |
| Training case | `docs/learning.md`: a flight simulator for Kubernetes objects (offline, graded, credited) | the deterministic grader is the differentiator over reading docs |
| No egress by default | add an admin lock (`offline: true` / `KUBE_NOOB_OFFLINE=1`) that overrides `webEnabled`; web stays HTTPS GET-only, allowlisted, text content types only, size-capped, never written to disk, never executed; `kube-noob doctor` proves the posture | "off by default" protects users; an enforced lock protects platform teams |
| Diagnose before change | every playbook splits read-only checks from changes; diagnose/debug output lists read-only next steps first and labels changes "requires approval"; `kube-noob bundle` collects a redacted read-only evidence bundle | makes the safe path the default path, not a prompt instruction |
| Learning from context | local, upgrade-safe learning file in the data dir: profile (platform, versions, conventions), confirmed notes (symptom, cause, fix) and aggregate counters; never raw logs or manifests; notes are searchable and cited as `kn:local-...` | learning must not leak data or turn guesses into truth; explicit confirmation plus derived facts only |

## Status

Delivered in 0.2.0. Each criterion below is enforced by the tests listed in [guidance.md](guidance.md) (G02-G04,
G06-G09, G16, G20-G21).

## Acceptance criteria

1. Offline lock
   - With `KUBE_NOOB_OFFLINE=1`, `webEnabled: true` is ignored, `web_fetch` is not registered and `corpus --online`
     exits non-zero.
   - Web responses with non-text content types (archives, binaries) are rejected; nothing fetched is written to disk.
   - `kube-noob doctor` reports network, cluster, model and data-dir posture and exits non-zero if the posture
     contradicts the lock.
2. Diagnose before change
   - A test fails if any playbook lists a mutating command (`apply`, `create`, `delete`, `patch`, `edit`, `scale`,
     `rollout restart`, `adm`) in its read-only checks.
   - `diagnose` and `cluster_debug_workload` return `readOnlyNextSteps` before `proposedChanges`, and every proposed
     change carries `requiresApproval: true`.
   - `kube-noob bundle <kind/name> -n <ns>` writes a Markdown + JSON bundle using read-only calls only, with Secrets
     refused and values redacted.
3. Learning file
   - Stored at `<dataDir>/learning.json` with `schemaVersion`; a file written by an older version loads after upgrade.
   - Notes containing credential patterns are rejected; raw manifests and logs are never stored.
   - Confirmed notes appear in `search_knowledge` as `origin: local` and are citable.
4. Demos and education
   - `kube-noob demo --list` shows at least 5 offline scenarios; each runs in under 10 seconds without network.
   - The release workflow renders one GIF per scenario from VHS tapes and attaches them to the GitHub release.
   - `docs/use-cases.md`, `docs/learning.md` and `examples/` exist; the README links them in one line each.

## Riskiest assumptions and cheapest tests

| Assumption | Test |
|---|---|
| People will try a demo before installing anything else | put one GIF at the top of the README; watch PyPI installs and plugin installs in the launch week |
| Auto-learned context helps more than it harms | ship explicit, confirmed notes first; add automatic capture only of counters |
| Platform teams need an enforced lock, not just defaults | ask two OpenShift admins during launch; the lock is cheap to keep either way |

Set aside for later: a hosted demo environment, an operator/CRD, OAuth for remote MCP, embeddings.

# Architecture

kube-noob has no model inside. The server, the CLI and the plugin run deterministic code: rules, schemas, playbooks,
a BM25 index and graders. A model appears only on the client side (Claude, Lightspeed, any MCP client) or in the
optional `kube-noob ask` agent, which calls the same toolkit.

```mermaid
flowchart LR
  subgraph Clients
    A[Claude / Cursor / VS Code<br/>MCP client]
    B[kube-noob CLI]
    C[Optional agent: kube-noob ask<br/>a model you configure]
    D[Sidecar app in the same pod]
  end
  subgraph Server["kube-noob (stdio or streamable HTTP)"]
    T[Toolkit<br/>one tool surface]
    P[7-step protocol]
    E[Audit engine<br/>rules + schemas + red team]
    F[Fixer / Generator / Helm]
    G[Debug playbooks]
    K[Knowledge store BM25<br/>built-in docs + corpus]
    L[Learning: tracks, exercises, quizzes, credits]
    R[Reward / grader<br/>enforcer + credit system]
  end
  subgraph Optional["Opt-in, guarded"]
    W[web_fetch<br/>webEnabled + domain allowlist]
    X[Read-only cluster<br/>kubectl / oc / in-cluster SA<br/>no Secrets, redaction]
  end
  subgraph Offline["Maintainer / CI (corpus-refresh)"]
    S1[Git docs with license provenance]
    S2[Release history from tags]
    S3[Red Hat Jira copy via REST API<br/>1 req/s, PII scrubbed, local only]
  end
  A & B & C & D --> T
  T --> P --> E & F & K
  T --> G & L & R
  T -.-> W & X
  S1 & S2 & S3 --> K
  R --> DS[(SFT / GRPO datasets)]
```

## Request flow (run_protocol)

1. **Clarify** - platform/version inference (blueprint > explicit > request text > manifest API groups), blocking
   questions vs stated assumptions.
2. **Validate** - strict JSON schema (Kubernetes 1.35 + CRDs), apiVersion/kind catalog, removed APIs per target version,
   selector/port wiring.
3. **Research** - BM25 over local knowledge; results carry chunk ids, source URLs and licenses.
4. **Audit** - security, RBAC, network exposure, storage access modes vs provisioner capabilities.
5. **Calibrate** - probes, resources, replicas, PDBs, topology spread, HPA prerequisites.
6. **Generate** - deterministic generator (blueprints) or mechanical fixer (existing YAML) with a change log.
7. **Red Team** - nine adversarial scenarios evaluated on the final output; remaining HIGH/CRITICAL findings mark the
   result `blocked`.

## Trust boundaries

- MCP clients and model output are untrusted input: every tool validates with Pydantic, YAML is size/alias bounded.
  Text that came from outside is untrusted on the way out too: `kube_noob.sanitize` cleans every MCP result (invisible
  characters, role and tool-call markers, instruction phrases, exfiltrating Markdown) and flags it `untrusted`.
  Pasted payloads are data too: an Alertmanager payload is read as JSON only (2 MB, 500 alerts, 64 labels, 2,000
  characters per value, control characters dropped), and only an OpenShift release label sets the version.
- The HTTP transport authenticates with a bearer token (constant time) unless bound to loopback (sidecar).
- Outbound HTTP only through `kube_noob.net`: web purpose requires `webEnabled` and allowlisted HTTPS hosts on every
  hop, GET only; `web_fetch` refuses non-text content types before reading the body. LLM and in-cluster API clients
  are separate, explicit purposes.
- The admin lock (`offline: true`) is applied at config load and only tightens: it disables web, refuses corpus
  downloads and allows only loopback or `*.svc` model endpoints. `kube-noob doctor` reports the result.
- Cluster access is read-only, allowlisted per resource, never Secrets, and redacts values before they reach a model.
  Diagnoses list read-only steps first; commands that execute or change state are labelled as needing approval.
- Anything beyond reading is a capability tier (`kube_noob.tiers`: probe, dry-run, external writes, gate forwarding),
  off by default. Code that changes something is a `Writer` that cannot be built while its tier is off, and each
  action needs a person's `Approval` for that action, unexpired and used once. The read-only backends have no write
  method; tier RBAC renders only when the tier is on.
- A memory repository (`kube_noob.memory`) is the team's own Git content: kube-noob reads it locally, writes only on
  `memory init`, `add`, `outcome` and `migrate-learning` (new files created exclusively, rewrites atomic), never runs
  git, and never bundles, publishes or exports it. Entries are untrusted input until `memory validate` passes:
  bounded YAML, content rules, and the verifier on every fix (validate, audit and red team on patches; privileged
  SCC, cluster-admin, hostPath and wildcard RBAC grants fail without a recorded risk acceptance). In the chart the
  repository is mounted read-only; the git source is cloned by an init container (no credentials in the URL, a
  deploy key from a Secret, strict host keys), with egress only to the git host's CIDRs and, under the offline
  lock, only from an in-cluster host.
- The Red Hat Jira copy is local data that is not redistributable. Each sync appends status, resolution and
  fix-version changes to `jira/changes.jsonl` (owner-only, atomic, capped); reconciliation reads it and the ticket
  index offline. A snapshot (`corpus jira-snapshot`) is owner-only; `corpus import` validates its file names,
  sizes, checksums and that it comes from the same Jira before copying anything. `serve` imports a seed from
  `<dataDir>/seed/` only when there is no copy, and the chart mounts the seed read-only (an init container copies it
  from a pinned image, or a read-only claim). The scheduled main copy leaves the runner only encrypted.
- A sealed Jira seed is opened in the server container only, with the key file from a Secret; the init container
  that copies it never sees the key. The plaintext is written to a temporary folder next to the data, imported
  through the same validation as any snapshot, and removed; a wrong key leaves the data folder untouched.
- The public `kube-noob-db` bundle is the only data kube-noob publishes. It is built from redistributable sources
  only, checked by `corpus db-check` (allow-listed licenses, no Jira data, every file listed and checksummed), and
  shipped in an image the chart pins by digest. The init container copies the archive into a scratch volume that the
  server mounts read-only; `serve` validates the whole archive and imports it only when it is newer than the copy
  it has. Trust boundary: the image registry and its signature, checked by the operator with `cosign verify`.
- The attack-path scan (`posture scan`, tools `posture_scan` and `cluster_posture_scan`) reads RBAC objects (who may do what, no credentials) and the objects that expose and run pods; Secret objects in a bundle are dropped before analysis, and the live allowlist refuses Secrets. It reports paths and fixes and changes nothing.
- Build insight (`kube_noob.build`) reads text and files the user gives it and runs nothing: logs are split into steps by each CI system's own markers and classified by bounded patterns; the Containerfile audit parses without running a shell; the OCI layout reader opens blobs only by validated digest, refuses symlinks, checks every blob's sha256, reads layers as tar streams in memory with byte, file and layer budgets, and reports credentials by kind and location only (never their value). Trust boundary: the files on disk.
- The RHACS comparison (`kube_noob.rhacs`) reads a policy export as data and changes nothing. Reading Central goes through `net.Purpose.RHACS`: on only with `rhacs.enabled`, GET only, https to the configured host and port only, no redirects, the token from `$ROX_API_TOKEN` (or the KUBE_NOOB_* variable `rhacs.tokenEnv` names) in the Authorization header and never in an error; `kube_noob.rhacs_central` is the only code that reads it, and the Claude plugin does not ship it, Central's CA from `rhacs.caFile`; under the offline lock only a loopback or `*.svc` Central with no proxy from the environment. Trust boundary: Central and the token's role.
- Drift snapshots and reports (`kube_noob.drift`) are local files, owner-only, with hashes and names only: a snapshot cannot be turned back into configuration. The daily job reads through the same read-only allowlist.
- `policy generate` (CLI and the read-only `policy_generate` tool) only writes YAML: it applies nothing, reads no
  cluster and fetches nothing. What the policies do is decided by the person who applies them; enforce mode refuses
  requests, so the default is audit. The CEL reads only the admitted object and the requester's name, never other
  objects, and exempts platform namespaces and operators so a cluster upgrade is never blocked by a generated policy.
- `<dataDir>/learning.json` holds user-confirmed summaries, the user's profile and id counters only. Notes are indexed
  as `origin: local`, are never redistributable and never exported as training data.

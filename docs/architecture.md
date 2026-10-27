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
    S3[Jira ROX jittered pull<br/>PII scrubbed]
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
- The HTTP transport authenticates with a bearer token (constant time) unless bound to loopback (sidecar).
- Outbound HTTP only through `kube_noob.net`: web purpose requires `webEnabled` and allowlisted HTTPS hosts on every
  hop, GET only; `web_fetch` refuses non-text content types before reading the body. LLM and in-cluster API clients
  are separate, explicit purposes.
- The admin lock (`offline: true`) is applied at config load and only tightens: it disables web, refuses corpus
  downloads and allows only loopback or `*.svc` model endpoints. `kube-noob doctor` reports the result.
- Cluster access is read-only, allowlisted per resource, never Secrets, and redacts values before they reach a model.
  Diagnoses list read-only steps first; commands that execute or change state are labelled as needing approval.
- `<dataDir>/learning.json` holds user-confirmed summaries, the user's profile and id counters only. Notes are indexed
  as `origin: local`, are never redistributable and never exported as training data.

# Changelog

## 0.1.0 - 2026-10-27

First release.
- MCP server (stdio + authenticated streamable HTTP), CLI, Claude plugin with 7 skills, Helm chart and sidecar example.
- 7-step protocol (Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team).
- 60 deterministic audit rules plus strict schema validation (Kubernetes 1.35, Route, SCC, EgressFirewall, Gateway
  API, StackRox CRDs), 9 red-team scenarios, safe auto-fix, RHACS policy mapping.
- Generator for kubernetes / openshift / rosa-classic / rosa-hcp manifests and Helm charts.
- 33 debugging playbooks and read-only live cluster evidence (kubectl/oc or in-cluster ServiceAccount).
- 28 fact-checked knowledge docs (OCP 4.22 = Kubernetes 1.35, Helm 4, RHACS 4.11 -> 5.0, ROSA HCP architecture).
- Learning tracks with graded exercises, quizzes and credits.
- Corpus builder (Git docs with license provenance, release history, jittered Jira pulls), deterministic reward with
  TRL adapter, held-out benchmark, SFT/GRPO export.
- Hardened before release after an independent red-team review: assertion-gated, negation-aware reward with citation
  relevance; config never read implicitly from the working directory; LLM key/endpoint restrictions; redaction of
  credentials in every cluster string; duplicate-key and nesting-depth checks; fixer output that the API server
  accepts (privileged containers, root containers, null securityContexts, duplicate EgressFirewalls).

# kube-noob plugin

Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox expertise as tools for Claude. **No AI inside:** Claude does
the thinking; kube-noob supplies the audit rules, read-only-first troubleshooting steps, cited docs and graded
exercises, and runs on your computer. Design and review requests follow a 7-step protocol: Clarify, Validate,
Research, Audit, Calibrate, Generate, Red Team.

## Install

```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```

Runs in Claude Code and Cowork. Requires [uv](https://docs.astral.sh/uv/).

## How to use it

Ask Claude in your own words; the skills route the work to kube-noob's tools.

- "Review this Deployment for OpenShift 4.22" and paste the YAML: findings with line numbers, fixes and the RHACS
  policy each one would trip.
- "My pod is in CrashLoopBackOff" and paste `oc describe pod` or the events: the likely cause, then read-only checks
  first; anything that changes the cluster comes last and needs your approval.
- "Write manifests for orders-api on ROSA HCP with shared storage": audited YAML through the 7-step protocol.
- "Teach me Services" or "give me an exercise": lessons and graded exercises.

Commands in an answer are for you to run: the skills tell Claude to hand them to you rather than run them, and
kube-noob itself never changes your cluster.

## How it runs

The server is the readable Python source in `server/`, a copy of the
[kube-noob repository](https://github.com/aashishmahajan/kube-noob)'s `src/kube_noob`. Claude Code starts it with
`uv run --frozen`, which installs its dependencies from PyPI at the exact versions and hashes in `uv.lock`, into the
plugin's data folder, and runs Python isolated (`-I`), so nothing from your working directory or `PYTHONPATH` is
imported. If no Python 3.11 or later is installed, uv downloads its managed CPython once. Nothing else is downloaded,
and no LLM SDK is installed.

## What it accesses

- Network: none. Web lookups and cluster access are off in `.mcp.json`; the server never calls a model.
- Files: stores learning progress and `learning.json` (your platform, versions, conventions and the fixes you
  confirmed; never logs, manifests or secrets) in `~/.local/share/kube-noob`, which survives plugin upgrades.
- To let it read your cluster (read-only, never Secrets), set `KUBE_NOOB_CLUSTER_ENABLED=true` in `.mcp.json`. To
  allow HTTPS reads from allowlisted documentation sites, set `KUBE_NOOB_WEB_ENABLED=true`.
- No telemetry and no accounts. Details: [PRIVACY.md](https://github.com/aashishmahajan/kube-noob/blob/main/PRIVACY.md).

## Skills

kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

Docs: https://github.com/aashishmahajan/kube-noob

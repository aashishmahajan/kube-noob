# kube-noob plugin

Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox expertise as tools for Claude. **No AI inside:** Claude does
the thinking; kube-noob supplies the audit rules, read-only-first troubleshooting steps, cited docs and graded
exercises, and runs on your computer. Design and review requests follow a 7-step protocol: Clarify, Validate,
Research, Audit, Calibrate, Generate, Red Team.

## Install

In Claude Code:

```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```

In claude.ai or the Claude desktop app: **Customize > Plugins > Add > Add marketplace**, enter
`aashishmahajan/kube-noob`, then add **kube-noob** from the list. It is saved to your account and also reaches
Claude Code.

The tools run on your computer, so they work in Claude Code and in Cowork sessions on your computer; in a chat
conversation only the skills load. The server needs [uv](https://docs.astral.sh/uv/) (`brew install uv` or
`pipx install uv`).

## How to use it

Ask Claude in your own words; the skills route the work to kube-noob's tools.

- "Review this Deployment for OpenShift 4.22" and paste the YAML: findings with line numbers, fixes and the RHACS
  policy each one would trip.
- "My pod is in CrashLoopBackOff" and paste `oc describe pod` or the events: the likely cause, then read-only checks
  first; anything that changes the cluster comes last and needs your approval.
- "Write manifests for orders-api on ROSA HCP with shared storage": audited YAML through the 7-step protocol.
- "Is this a known bug?" with an OpenShift error: the matching issue from the release notes, its link, the version
  that fixes it and the workaround.
- "Why was this denied?" with a Kyverno, Gatekeeper, Pod Security, SCC, quota or RBAC error, or "can frontend
  reach orders-api on 8080?": the policy and rule that decided it, the field that failed and the fix.
- "Teach me Services" or "give me an exercise": lessons and graded exercises.

Commands in an answer are for you to run: the skills tell Claude to hand them to you rather than run them, and
kube-noob itself never changes your cluster.

## How it runs

The server is readable Python source in `server/`: the modules of the
[kube-noob repository](https://github.com/aashishmahajan/kube-noob)'s `src/kube_noob` that the stdio MCP server
imports, copied unchanged. The CLI, the optional model agent, the HTTP service and REST routes, the web client, Helm
rendering and the cluster backends are not included, so nothing in the plugin reads a credential, opens a connection
or starts another program. Claude Code starts it with `uv run --frozen --isolated`, which
installs the dependencies from PyPI at the exact versions and hashes in `uv.lock` into a throwaway environment in uv's
cache, and runs Python isolated (`-I`), so nothing from your working directory or `PYTHONPATH` is imported. If no
Python 3.11 or later is installed, uv downloads its managed CPython once. Nothing else is downloaded, and no LLM SDK
is installed.

## What it accesses

- Network: none of its own. The plugin has no web client and no cluster access, and the server never calls a model;
  uv's one-time install of the pinned dependencies is the only download.
- Files: stores learning progress and `learning.json` (your platform, versions, conventions and the fixes you
  confirmed; never logs, manifests or secrets) in `~/.local/share/kube-noob`, which survives plugin upgrades.
- To read your cluster (read-only, never Secrets) or allowlisted documentation sites, use the kube-noob CLI
  (`pipx install kube-noob`) or the in-cluster service; the plugin stays offline.
- No telemetry and no accounts. Details: [PRIVACY.md](https://github.com/aashishmahajan/kube-noob/blob/main/PRIVACY.md).

## Skills

kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

Docs: https://github.com/aashishmahajan/kube-noob

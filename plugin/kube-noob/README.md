# kube-noob plugin

Skills and an MCP server to learn, audit and debug Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox, offline
by default. Design and review requests follow a 7-step protocol: Clarify, Validate, Research, Audit, Calibrate,
Generate, Red Team.

## Install

```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```

Requires [uv](https://docs.astral.sh/uv/); the server runs as `uvx --from kube-noob==0.2.0 kube-noob mcp`.

## What it accesses

- Network: none by default. `KUBE_NOOB_WEB_ENABLED=true` allows HTTPS reads from allowlisted documentation domains only.
- Cluster: none by default. `KUBE_NOOB_CLUSTER_ENABLED=true` allows read-only `oc`/`kubectl` get and logs with your
  current context; it never writes, never reads Secrets and redacts credentials.
- Files: reads the manifests you give it; stores learning progress and `learning.json` (your profile and confirmed
  notes; never logs, manifests or secrets) in `~/.local/share/kube-noob`, which survives plugin upgrades.
- Admins can lock it offline with `KUBE_NOOB_OFFLINE=1`; `kube-noob doctor` shows the effective posture.
- No telemetry, no collected credentials; the server never calls an LLM.

Both switches live in the `env` block of `.mcp.json` and take precedence over config files.

## Skills

kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

Docs: https://github.com/aashishmahajan/kube-noob

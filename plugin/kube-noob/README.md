# kube-noob plugin

Skills + MCP server for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox: learn, audit (7-step SRE protocol)
and debug - offline by default.

## Install
```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```
The MCP server runs with `uvx kube-noob mcp` (requires [uv](https://docs.astral.sh/uv/)). Web access and live-cluster
access are disabled; enable them by setting `KUBE_NOOB_WEB_ENABLED=true` / `KUBE_NOOB_CLUSTER_ENABLED=true` in the
`env` block of `.mcp.json`, or `webEnabled: true` in `kube-noob.yaml`.

## Skills
kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

# kube-noob plugin

Skills + MCP server for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox: learn, audit (7-step SRE protocol)
and debug - offline by default.

## Install
```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```
The MCP server runs with `uvx kube-noob mcp` (requires [uv](https://docs.astral.sh/uv/)). Web access and live-cluster
access are disabled and pinned by the `env` block of `.mcp.json`; enable them by changing `KUBE_NOOB_WEB_ENABLED` /
`KUBE_NOOB_CLUSTER_ENABLED` to `"true"` there. Environment variables take precedence over any config file
(`~/.config/kube-noob/config.yaml`), so a config-file `webEnabled: true` alone does not override the plugin's pin.

## Skills
kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

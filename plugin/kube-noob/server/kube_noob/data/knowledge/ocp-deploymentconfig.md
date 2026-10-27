---
id: ocp-deploymentconfig
title: Moving from DeploymentConfig to Deployment
tags: [openshift, deploymentconfig, deployments, migration]
platforms: [openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "OpenShift 4.14 release notes: DeploymentConfig deprecation", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/release_notes/ocp-4-14-release-notes", license: CC-BY-SA-3.0}
  - {title: "OpenShift: Triggering updates on image stream changes", url: "https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/images/triggering-updates-on-imagestream-changes", license: CC-BY-SA-3.0}
---
# DeploymentConfig to Deployment

`DeploymentConfig` (`apps.openshift.io/v1`) has been deprecated since OpenShift 4.14. Use `apps/v1` Deployments for
new work and migrate existing ones.

| DeploymentConfig feature | Deployment equivalent |
|---|---|
| ImageChange trigger | annotation `image.openshift.io/triggers` on the Deployment (`oc set triggers deploy/<name> --from-image=<stream>:<tag> -c <container>`) |
| ConfigChange trigger | built in: any pod template change rolls out |
| Rolling and Recreate strategies | same `strategy.type` values |
| Lifecycle hooks (pre, mid, post) | init containers, or a Job run by your pipeline |
| `oc rollout latest` | `oc rollout restart deployment/<name>` |
| Custom deployer pods | not available; use your CI/CD system |

Migration steps: create the Deployment with the same pod template and a new selector, scale it up, move the
Service selector (or keep labels identical), then scale the DeploymentConfig to zero and delete it. `kube-noob audit` flags every remaining DeploymentConfig.

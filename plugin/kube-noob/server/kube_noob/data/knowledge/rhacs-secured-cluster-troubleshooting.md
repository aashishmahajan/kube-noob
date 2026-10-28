---
id: rhacs-secured-cluster-troubleshooting
title: RHACS secured cluster troubleshooting
tags: [rhacs, stackrox, securedcluster, sensor, collector, scanner, scanner-v4, uninstall, collections]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rhacs, stackrox, roxctl, acs, central, sensor, collector, scanner, securedcluster]
sources:
  - {title: "RHACS docs: Secured cluster services", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/acs-secured-cluster-services-overview.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Understanding admission controller enforcement", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/understand-admission-controller-enforcement.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Resolve Collector connection failures to Sensor", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/unable-to-connect-to-the-sensor.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Retrieving the Collector logs with oc or kubectl", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/retrieving-the-logs-with-the-oc-or-kubectl-command.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Common Scanner warning messages", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/common-scanner-warning-messages.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Viewing the Central logs", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/viewing-the-logs.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Checking image scan results", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/checking-image-scan-results.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Deleting global resources", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/delete-acs-global-resources.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Migration of access scopes to collections", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/migrate-scope-collections.adoc", license: Apache-2.0}
---
# RHACS secured cluster: components and common problems

Commands below use `oc`; on Kubernetes use `kubectl` with the same arguments. The secured cluster components run
in the `stackrox` namespace in these examples.

## Secured cluster services: what Sensor, the admission controller, Collector and Scanner V4 do

- **Sensor** analyzes and monitors the cluster. It watches the Kubernetes or OpenShift API and the events Collector
  sends, raises deploy-time and runtime violations, and does every cluster-side action: applying network policies,
  starting policy reprocessing, talking to the admission controller.
- **Admission controller**: stops users from creating workloads that violate RHACS policies. The API server sends
  each matching request to the RHACS validating webhooks, which ask the admission controller; with enforcement on,
  a violating request is rejected.
- **Collector** runs on the nodes and gathers container runtime and network activity, which it sends to Sensor.
- **Scanner V4** is the default scanner; it fetches, indexes and scans images. Its **Indexer** takes an image and
  registry credentials, pulls the image, finds the base operating system (if any) and the packages, and stores an
  index report (this used to be called image analysis). **Scanner V4 DB** stores Scanner V4 data such as index
  reports; give it a persistent volume claim for best performance.
- **StackRox Scanner** (Scanner-slim) is optional on Kubernetes. On OpenShift RHACS installs it on every secured
  cluster to scan images in the integrated registry, and optionally other registries. **Scanner-DB** holds its data.
- When the secured cluster services go into the same cluster and namespace as Central, they do not deploy Scanner V4;
  the Scanner V4 that comes with Central is used.

## Collector: Unable to connect to Sensor at 'sensor.stackrox.svc:9998'

```
[INFO    2023/05/13 12:21:13]  Connected to Sensor?       false
[FATAL   2023/05/13 12:21:13] Unable to connect to Sensor at 'sensor.stackrox.svc:9998'.
```

Collector gets the kernel drivers and the CIDR blocks it needs for network events from Sensor, so it cannot start
without it. Either Sensor did not start properly, or Collector is configured with the wrong Sensor address.

```sh
oc -n stackrox get pod <collector_pod_name> -o jsonpath='{.spec.containers[0].env[?(@.name=="GRPC_SERVER")].value}'
oc -n stackrox get service sensor
oc -n stackrox get pods -l app=sensor
```

1. The first command prints the Sensor endpoint Collector uses (for example `sensor.stackrox.svc:443`). Its host
   name, namespace and port must match the `sensor` Service.
2. The Sensor pod must be `Running` with `1/1` in `READY`. If it is not, find out why from its events and logs and
   fix that first.
3. If the endpoint does not match the Service, redeploy the secured cluster resources with the right Sensor address.
4. Restart Collector with `oc -n stackrox delete pods -l app=collector`, then check that the startup diagnostics
   in `oc logs -n stackrox <collector_pod_name> collector` now say `Connected to Sensor?` `true` (add `--previous`
   to read a restarting pod's earlier run).

## Scanner warning: CVE DATA MAY BE INACCURATE (Stale OS CVE data and similar messages)

The warning means Scanner could not get complete CVE information for the operating system or other packages in the
image. The detail message says why:

| Message | Meaning |
|---|---|
| `Unable to retrieve the OS CVE data, only Language CVE data is available` | Scanner does not officially support the image's base OS, so it reports no CVEs for OS-level packages |
| `Stale OS CVE data` | The base OS is end-of-life (Debian 8 and 9 are the examples given) and its vendor no longer updates the vulnerability data |
| `Failed to get the base OS information` | The image was scanned, but no base OS was found in it |
| `Failed to retrieve metadata from the registry` | The registry could not be reached; see the next section |
| `Image out of scope for Red Hat Vulnerability Scanner Certification` | The image is old and outside the scope of Red Hat Scanner Certification; for Red Hat images, use a base image newer than June 2020 |

For `Stale OS CVE data`, the OS-level results of that image cannot get newer data while it stays on the end-of-life
release; only an image built on a release its vendor still updates gets current OS CVE data.

## Scanner: Failed to retrieve metadata from the registry

The registry holding the image cannot be reached. Two causes are named: a firewall blocks the network path (for
example to `docker.io`), or authentication fails.

- The component that pulls the image needs a network path to the registry: the Scanner V4 Indexer pulls images
  with the registry credentials it is given, and on OpenShift the Scanner-slim on each secured cluster scans images
  in the integrated registry.
- For a private registry or repository, create a registry integration with its credentials in RHACS (see
  "Integrating with image registries" in the RHACS docs).
- Read the Central logs for the underlying error: `oc logs -n stackrox <central_pod>`.
- Then fetch the result again without Central's cache: `roxctl image scan --image <image_name> --force`.

## Uninstall RHACS: delete global resources (error: the server doesn't have a resource type "psp")

```sh
oc get clusterrole,clusterrolebinding,role,rolebinding,psp -o name | grep stackrox | xargs oc delete --wait
oc delete scc -l "app.kubernetes.io/name=stackrox"
oc delete ValidatingWebhookConfiguration stackrox
```

On Kubernetes: `kubectl get clusterrole,clusterrolebinding,role,rolebinding,psp -o name | grep stackrox | xargs kubectl delete --wait`
and `kubectl delete ValidatingWebhookConfiguration stackrox` (there is no SCC step).

- `error: the server doesn't have a resource type "psp"` is expected with RHACS 4.4 and later: PodSecurityPolicy
  was deprecated and Kubernetes 1.25 removed it, so only clusters on older Kubernetes still have the `psp` type.
  On Kubernetes 1.25 or later, leave `psp` out of the resource list to avoid the error.
- `No resources found` from the SCC step is also expected on RHACS 4.4 and later, which no longer uses custom SCCs
  with that label.

## Central PostgreSQL migration: access scopes to collections, only the IN operator migrates

When Central moves from RocksDB to PostgreSQL (Technology Preview from 3.74, generally available in 4.0), access
scopes used by vulnerability reports are converted to collections: one or more
`System-generated embedded collection <number> for the scope` collections that reproduce the scope's cluster and
namespace selection, plus a `System-generated root collection for the scope` that attaches them and is set on the
report configurations.

Known limitation: a scope with cluster or namespace label selectors migrates only if its selectors use the `IN`
operator (the portal's default). Scopes using `NOT_IN`, `EXISTS` or `NOT_EXISTS` are not migrated, and the
migration logs:

```
Failed to create collections for scope <scope-name>: Unsupported operator NOT_IN in scope's label selectors. Only operator 'IN' is supported.
```

The message lists the report configurations that use the scope. Create an equivalent collection by hand and edit
those report configurations to use it; the reports do not work until a collection is attached. Vulnerability
Management -> Reporting shows each report's configuration, and a report's page says when it needs a collection. The
original access scopes are kept; delete any you created only to filter reports.

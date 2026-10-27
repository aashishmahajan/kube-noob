# Third-party notices and attribution

kube-noob bundles derived data and links to public sources. Licenses were verified from each upstream LICENSE file on
2026-10-27.

## Bundled in the package

| Material | Upstream | License | Where |
|---|---|---|---|
| Kubernetes v1.35.0 JSON schema definitions (made strict, descriptions removed) | yannh/kubernetes-json-schema (generated from kubernetes/kubernetes OpenAPI) | Apache-2.0 | `src/kube_noob/schemas/data/kubernetes-v1.35.0-definitions-*.json` |
| Route, SecurityContextConstraints schemas | datreeio/CRDs-catalog @3eb90d47 (from openshift/api) | MIT (catalog), Apache-2.0 (openshift/api) | `schemas/data/crds/` |
| HTTPRoute, Gateway schemas | datreeio/CRDs-catalog @3eb90d47 (from kubernetes-sigs/gateway-api) | MIT, Apache-2.0 | `schemas/data/crds/` |
| EgressFirewall schema | openshift/cluster-network-operator @a1b26444 | Apache-2.0 | `schemas/data/crds/` |
| Central, SecuredCluster schemas | stackrox/stackrox @3373dee4 | Apache-2.0 | `schemas/data/crds/` |
| RHACS default policy names (references only) | stackrox/stackrox `pkg/defaults/policies/files` | Apache-2.0 | `audit/rules.py` |

Exact source URLs and upstream SHA-256 digests: `src/kube_noob/schemas/data/PROVENANCE.json`.

## Knowledge base

The built-in knowledge docs (`src/kube_noob/data/knowledge/`) are original text (Apache-2.0) that summarise and cite:
Kubernetes documentation (CC BY 4.0, (c) The Kubernetes Authors), Red Hat OpenShift / ROSA documentation
(docs.redhat.com, CC BY-SA 3.0; source repository openshift/openshift-docs, Apache-2.0), Red Hat Cloud Experts
(rh-mobb/documentation, Apache-2.0), openshift/hypershift and openshift/rosa (Apache-2.0), Helm documentation
(helm/helm-www, MIT, (c) 2017 Microsoft Corporation), and stackrox/stackrox (Apache-2.0).

## Corpus sources (downloaded by the user / CI, not bundled)

See `src/kube_noob/sources/registry.py`. Sources with non-commercial (ramitsurana/awesome-kubernetes, CC BY-NC 4.0),
copyleft (ansible-collections/kubernetes.core, GPL-3.0) or no license (magnologan/awesome-k8s-security) terms are never
redistributed; Red Hat Jira issue content is used for local retrieval and evaluation only.

## Trademarks

Kubernetes and Helm are trademarks of The Linux Foundation. Red Hat, OpenShift, Red Hat Advanced Cluster Security and
StackRox are trademarks of Red Hat, Inc. AWS and ROSA-related names are trademarks of Amazon.com, Inc. or its
affiliates. kube-noob is an independent project, not affiliated with or endorsed by these organizations.

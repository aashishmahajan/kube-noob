# Gap review, October 2026: CVE signatures, Helm, validation

Compared with the Kubernetes CVE feed (the `official-cve-feed` issues of kubernetes/kubernetes, read 2026-10-29), the
Helm and Argo CD security advisories, the Helm best practices, and the checks of kube-score, Polaris, kube-linter,
Checkov and the Kyverno policy library. Only signatures a manifest or a chart directory shows are candidates; every
CVE id and fixed release below is from the advisory linked in `kube_noob.catalog.SOURCES`.

Value: H high, M medium, L low. Decision: **add** (in this change), **extend** (an existing rule), **covered**,
**later** (real, not in this batch), **no** (not a manifest signature, or not a real problem).

## CVE signatures

| Candidate | Covered by | Value | Decision |
|---|---|---|---|
| CVE-2023-3676 kubelet runs a Windows `subPath` through PowerShell (fixed v1.24.17, v1.25.13, v1.26.8, v1.27.5, v1.28.1; fix in `subpath_windows.go`) | missing | H | add KN-S025 |
| CVE-2023-3955 PowerShell injection on Windows nodes (fix in mount-utils format parameters) | missing | M | no: the fix names no pod field we could verify |
| CVE-2023-3893 kubernetes-csi-proxy | missing | L | no: a node component, no manifest field |
| CVE-2023-5528 Windows in-tree storage: PersistentVolume `local.path` with special characters (fixed v1.25.16, v1.26.11, v1.27.8, v1.28.4) | missing | H | add KN-ST006 |
| CVE-2026-3864 / CVE-2026-3865 NFS / SMB CSI `subDir` traversal (`../` in `volumeHandle`; fixed csi-driver-nfs v4.13.1, csi-driver-smb v1.20.1) | missing | H | add KN-ST006 |
| CVE-2026-24512 ingress-nginx `rules.http.paths.path` injection; the advisory's mitigation rejects `ImplementationSpecific` paths (fixed v1.13.7, v1.14.3) | KN-S024 (image only) | H | add KN-N011 |
| CVE-2026-2270 write on StatefulSets and ControllerRevisions creates pods in other namespaces (kube-controller-manager fixed v1.34.12, v1.35.9, v1.36.5, v1.37.1) | KN-S017 (StatefulSets only) | H | extend KN-S017 |
| CVE-2024-3177 / CVE-2023-2728 mountable-secrets bypass (envFrom, ephemeral containers) | missing | L | no: CVSS 2.7, needs the deprecated `enforce-mountable-secrets` annotation |
| CVE-2024-9486 / CVE-2024-9594 / CVE-2025-7342 Image Builder default credentials | n/a | - | no: VM images, not manifests |
| CVE-2025-0426 kubelet checkpoint DoS (read-only port) | n/a | - | no: kubelet configuration |
| CVE-2024-9042 Windows `nodes/*/logs/query` injection | KN-S017 (nodes/proxy) | L | no: kubelet version, no manifest field |
| CVE-2026-76654 Windows `subPath` symlink to a UNC path | n/a | M | no: the link is inside the volume, not in the manifest |
| CVE-2024-7646, CVE-2025-1974 family (ingress-nginx) | KN-S024, KN-N009, KN-N010 | - | covered |
| Helm CVE-2025-53547 `Chart.lock` symlink written by `helm dependency update` (fixed 3.17.4, 3.18.4) | missing | H | add (helm-audit) |
| Helm CVE-2024-25620 / CVE-2026-35206 chart name with a path or `.`/`..` (fixed 3.14.1; 3.20.2, 4.1.4) | missing | M | add (helm-audit) |
| Helm CVE-2023-25165 `getHostByName` sends names to DNS while rendering (fixed 3.11.1) | missing | L | add (helm-audit) |
| Helm CVE-2025-32387 JSON schema stack overflow, schemas over 10 MiB (fixed 3.17.3) | missing | L | add (helm-audit) |
| Argo CD CVE-2026-45738 `link.argocd.argoproj.io/*` annotation with a `javascript:` URL (fixed 3.2.12, 3.3.10, 3.4.2) | missing | M | later: needs the Argo CD Application kind in the admission targets and the kind test CRDs |

## Helm (helm-audit and the chart generator)

| Candidate | Covered by | Value | Decision |
|---|---|---|---|
| no `values.schema.json`; `latest` image tag; SemVer `version`; quoted `appVersion` | `lint_chart_metadata` | - | covered |
| resources, probes, `latest` tags in the rendered output | the full audit of `helm template` | - | covered |
| CRDs in `templates/` instead of `crds/` (deleted with the release, and every custom resource with them) | missing | M | add |
| `lookup` in templates: `helm template` always returns an empty result, so helm-audit sees another render than install | missing | M | add |
| dependency repository over plain `http://` | missing | M | add |
| dependency version ranges (`~1.2.3`) | n/a | - | no: Helm's best practices recommend ranges |
| hooks without `helm.sh/hook-delete-policy` | n/a | - | no: `before-hook-creation` is the default |
| generated chart sets `replicas` while its HPA is enabled | the generator | H | fix (the `helm create` pattern) |
| `tpl` on values; missing `kubeVersion`; NOTES.txt | missing | L | later |

## Validation and best practices

| Candidate | Covered by | Value | Decision |
|---|---|---|---|
| PDB maxUnavailable 0 / minAvailable = replicas | KN-C009 | - | covered |
| Service targetPort name not declared | KN-V012 | - | covered |
| automountServiceAccountToken; hostPort; wildcard RBAC; cluster-admin bindings | KN-S014, KN-S011, KN-S015, KN-S016 | - | covered |
| credentials in a ConfigMap (Helm values rendered into ConfigMaps, `application.properties`) | missing | H | add KN-S026 |
| legacy ServiceAccount token Secret (non-expiring token) | skipped by KN-S018 | H | add KN-S027 |
| binding to `system:unauthenticated`, `system:anonymous`, `system:authenticated`, `system:serviceaccounts` | missing | H | add KN-S028 |
| NetworkPolicy whose podSelector selects no pod (a dead policy satisfies KN-N001) | missing | M | add KN-N012 |
| HPA target also sets `spec.replicas` (every apply resets the count; `replicas: 0` deactivates the HPA) | missing | M | add KN-C014 |
| HPA min > max | n/a | - | no: the API server refuses it |
| HPA target missing from the bundle; Ingress host collisions | missing | L | later |
| CronJob without `startingDeadlineSeconds` (over 100 missed schedules stop it) | missing | M | later |
| topologySpreadConstraints without a labelSelector (counts no pods) | KN-C010 accepts it | M | later |
| duplicate env names (the last wins; the API server only warns) | missing | M | later |
| Pod Security baseline: AppArmor Unconfined, SELinux type/user/role, Windows HostProcess, unsafe sysctls, restricted volume types | missing | H | later: next batch, one rule per control |
| probes on a sidecar's port; imagePullPolicy with digests; `system:masters` subjects | n/a | L | no |

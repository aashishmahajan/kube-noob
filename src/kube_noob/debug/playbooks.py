"""Offline troubleshooting playbooks.

Each playbook maps observable signals (event reasons, status strings, log lines, CLI errors) to root causes, ordered
read-only checks, and fixes. ``{ns}``, ``{name}``, ``{pod}``, ``{pvc}`` placeholders are filled by the diagnoser when
it can parse them from the input. ``oc`` and ``kubectl`` are interchangeable for every check unless marked [OCP].
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Playbook:
    pid: str
    title: str
    signals: tuple[str, ...]  # case-insensitive regexes
    root_causes: tuple[str, ...]
    checks: tuple[str, ...]
    fixes: tuple[str, ...]
    platforms: tuple[str, ...] = ("kubernetes", "openshift", "rosa-classic", "rosa-hcp")
    related_rules: tuple[str, ...] = ()
    knowledge: tuple[str, ...] = ()
    weight: float = 1.0
    tags: tuple[str, ...] = field(default=())


PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        "DBG-CRASHLOOP",
        "Container keeps crashing (CrashLoopBackOff)",
        (r"CrashLoopBackOff", r"Back-off restarting failed container", r"restartCount:\s*[1-9]\d*"),
        (
            "The process exits right after start (bad config, missing env/secret, failed migration, wrong command).",
            "Liveness probe kills a slow-starting app (look for 'Liveness probe failed' before each restart).",
            "OOMKilled at startup (see lastState.terminated.reason).",
            "On OpenShift: the image expects root or a fixed UID and cannot write its directories under the "
            "random restricted-v2 UID.",
        ),
        (
            "oc logs {pod} -n {ns} --previous            # output of the crashed attempt",
            "oc get pod {pod} -n {ns} -o jsonpath='{{.status.containerStatuses[*].lastState.terminated}}'",
            "oc describe pod {pod} -n {ns}               # Events: probe failures, OOMKilled, exit codes",
            "oc get events -n {ns} --field-selector involvedObject.name={pod} --sort-by=.lastTimestamp",
        ),
        (
            "Fix the error shown by `logs --previous` (most common: missing env var, wrong DB URL, bad flag).",
            "Exit 137 = SIGKILL/OOM -> raise memory limit or fix the leak; 1 = app error; 126/127 = command not "
            "executable / not found; 139 = segfault; 143 = SIGTERM (often a liveness kill).",
            "Slow start -> add a startupProbe instead of loosening liveness.",
            "OpenShift arbitrary UID -> make writable dirs group-0 owned and group-writable "
            "(chgrp -R 0 /app && chmod -R g=u /app) in the image.",
        ),
        related_rules=("KN-C003", "KN-C005"),
        knowledge=("k8s-debug-pods", "ocp-arbitrary-uid"),
        weight=0.9,  # a symptom, not a cause: a specific cause (OOM, probe, UID) with equal evidence ranks first
    ),
    Playbook(
        "DBG-IMAGEPULL",
        "Image cannot be pulled (ImagePullBackOff / ErrImagePull)",
        (
            r"ImagePullBackOff",
            r"ErrImagePull",
            r"manifest unknown",
            r"pull access denied",
            r"unauthorized: authentication required",
            r"toomanyrequests",
            r"Failed to pull image",
            r"repository does not exist",
            r"not found: manifest",
        ),
        (
            "Typo in image name or tag; tag was deleted or never pushed.",
            "Private registry without an imagePullSecret linked to the pod's ServiceAccount.",
            "Docker Hub anonymous rate limit (toomanyrequests).",
            "Registry TLS not trusted by the nodes (x509) or the registry is unreachable from the node network "
            "(egress/proxy restrictions; on ROSA private clusters check NAT/VPC endpoints).",
            "Architecture mismatch is a different error ('exec format error' after pull).",
        ),
        (
            "oc describe pod {pod} -n {ns}   # exact pull error in Events",
            "oc get pod {pod} -n {ns} -o jsonpath='{{.spec.containers[*].image}}'",
            "oc get sa {sa} -n {ns} -o jsonpath='{{.imagePullSecrets}}'",
            "skopeo inspect docker://<image>   # from a workstation with the same credentials",
        ),
        (
            "Correct the image reference; prefer digests.",
            "oc create secret docker-registry <name> --docker-server=<registry> --docker-username=... "
            "--docker-password=... -n {ns} && oc secrets link {sa} <name> --for=pull -n {ns}",
            "Mirror public images to a private registry (Quay, ECR) to avoid rate limits.",
            "[OCP] add the registry CA via image.config.openshift.io/cluster additionalTrustedCA.",
        ),
        related_rules=("KN-S012", "KN-C013"),
        knowledge=("k8s-images",),
        weight=0.9,  # a symptom with several causes: a playbook that names the cause ranks first on equal evidence
    ),
    Playbook(
        # kubelet emits FailedToRetrieveImagePullSecret when a name in imagePullSecrets is not found in the pod's own
        # namespace and the pull then fails (pkg/kubelet/kubelet.go, getPullSecretsForPod in kubelet_pods.go);
        # imagePullSecrets are LocalObjectReferences (staging/src/k8s.io/api/core/v1/types.go). OpenShift options:
        # openshift-docs modules/images-allow-pods-to-reference-images-across-projects.adoc and
        # modules/images-update-global-pull-secret.adoc (enterprise-4.21).
        "DBG-PULLSECRET",
        "Pull secret not found in the pod's namespace (FailedToRetrieveImagePullSecret)",
        (
            r"FailedToRetrieveImagePullSecret",
            r"Unable to retrieve some image pull secrets",
            r"pull[- ]?secrets?\b[^.\n]{0,40}\b(?:in|from)\s+(?:a\s+|an\s+)?(?:different|another|other)\s+"
            r"(?:namespace|project)",
            r"(?:different|another|other)\s+(?:namespace|project)[^.\n]{0,60}\bpull[- ]?secret",
            r"(?:copy|share|use|reuse)\s+(?:a\s+|the\s+)?pull[- ]?secrets?\s+(?:across|between)\s+"
            r"(?:namespaces|projects)",
        ),
        (
            "imagePullSecrets name Secrets in the pod's own namespace only (they are LocalObjectReferences): kubelet "
            "looks up {secret} in {ns}, and a Secret of that name in any other namespace is never used.",
            "The Secret exists in the namespace under another name, or the pod's ServiceAccount links a name that is "
            "missing (the ServiceAccount's imagePullSecrets are also looked up in its own namespace).",
            "[OCP] The image is in the internal registry of another project: no pull secret is needed, the pod's "
            "ServiceAccount needs the system:image-puller role in that project.",
        ),
        (
            "oc describe pod {pod} -n {ns}   # FailedToRetrieveImagePullSecret names the secret kubelet could not find",
            "oc get pod {pod} -n {ns} -o jsonpath='{{.spec.imagePullSecrets}} {{.spec.serviceAccountName}}'",
            "oc get sa {sa} -n {ns} -o jsonpath='{{.imagePullSecrets}}'",
            "oc get secrets -n {ns} --field-selector type=kubernetes.io/dockerconfigjson -o name   # names only",
            "oc get secrets -A --field-selector metadata.name={secret} "
            "-o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name   # where it really is",
        ),
        (
            "[OCP] Create the pull secret in {ns} and link it to the ServiceAccount: oc create secret "
            "docker-registry {secret} --docker-server=<registry> --docker-username=<user> --docker-password=<token> "
            "-n {ns} && oc secrets link {sa} {secret} --for=pull -n {ns}",
            "[K8S] Create the pull secret in {ns} and add it to the ServiceAccount: kubectl create secret "
            "docker-registry {secret} --docker-server=<registry> --docker-username=<user> --docker-password=<token> "
            "-n {ns} && kubectl patch serviceaccount {sa} -n {ns} -p "
            '\'{{"imagePullSecrets": [{{"name": "{secret}"}}]}}\'',
            "Keep one source of truth instead of hand-made copies: sync the Secret into each namespace that needs it "
            "with the External Secrets Operator or your secret manager.",
            "[OCP] A registry the whole cluster uses: add it to the global pull secret (cluster-admin; rolls out to "
            "every node): oc set data secret/pull-secret -n openshift-config --from-file=.dockerconfigjson=<file>. "
            "On hosted control planes (ROSA with HCP 4.20.6 or later) use secret/additional-pull-secret in "
            "kube-system.",
            "[OCP] An image in another project's internal registry: oc policy add-role-to-user system:image-puller "
            "system:serviceaccount:{ns}:{sa} --namespace=<image-project>",
        ),
        related_rules=("KN-C013",),
        knowledge=("k8s-images",),
        weight=2.0,  # one named cause: ranks above the image-pull symptom that matches the same events
    ),
    Playbook(
        "DBG-OOM",
        "Container killed for exceeding memory (OOMKilled / exit 137)",
        (
            r"OOMKilled",
            r"exit code:?\s*137",
            r"exitCode:\s*137",
            r"Memory cgroup out of memory",
            r"oom-kill",
            r"OOMKilling",
        ),
        (
            "Memory limit lower than the working set (JVM/Node heaps sized for the host, not the container).",
            "Memory leak or unbounded cache.",
            "Node-level OOM (OOMKilling event on the node) caused by pods without limits.",
        ),
        (
            "oc describe pod {pod} -n {ns}   # Last State: Terminated, Reason: OOMKilled",
            "oc adm top pod {pod} -n {ns} --containers",
            "oc get events -A --field-selector reason=OOMKilling",
        ),
        (
            "Set limits from observed p99 usage plus headroom; keep requests ~= steady-state usage.",
            "JVM: -XX:MaxRAMPercentage=75 (container-aware); Node.js: --max-old-space-size below the limit.",
            "Add memory limits to every pod so one leak cannot take the node down.",
        ),
        related_rules=("KN-C004", "KN-C005"),
        knowledge=("k8s-resources",),
    ),
    Playbook(
        "DBG-CONFIGERR",
        "Container cannot be created (CreateContainerConfigError)",
        (
            r"CreateContainerConfigError",
            r"secret \"?[\w.-]+\"? not found",
            r"configmap \"?[\w.-]+\"? not found",
            r"couldn't find key [\w.-]+ in (Secret|ConfigMap)",
            r"CreateContainerError",
        ),
        (
            "Referenced Secret/ConfigMap or key does not exist in the pod's namespace.",
            "runAsNonRoot conflict (see DBG-RUNASROOT).",
            "Invalid volume subPath or mount of a missing key.",
        ),
        (
            "oc describe pod {pod} -n {ns}",
            "oc get secret,configmap -n {ns}",
            "oc get pod {pod} -n {ns} -o jsonpath='{{.spec.containers[*].envFrom}}{{.spec.containers[*].env}}'",
        ),
        (
            "Create the missing object/key in the same namespace (Secrets are namespaced), or mark the "
            "reference optional: true if the app tolerates absence.",
        ),
        knowledge=("k8s-debug-pods",),
    ),
    Playbook(
        "DBG-RUNASROOT",
        "Pod refuses to start because the image runs as root",
        (
            r"container has runAsNonRoot and image will run as root",
            r"image has non-numeric user .* cannot verify user is non-root",
            r"runAsNonRoot and image has non-numeric user",
        ),
        ("runAsNonRoot: true but the image's USER is root (0) or a user name instead of a numeric UID.",),
        (
            "oc describe pod {pod} -n {ns}",
            "skopeo inspect --config docker://<image> | jq .config.User",
        ),
        (
            "Rebuild with a numeric non-root USER (e.g. USER 1001) or use an unprivileged image variant.",
            "Vanilla Kubernetes: set securityContext.runAsUser to a non-zero UID the image supports.",
            "[OCP] restricted-v2 injects a namespace-range UID; do not set runAsUser - just make the image work "
            "as an arbitrary UID in group 0.",
        ),
        related_rules=("KN-S003", "KN-S004"),
        knowledge=("ocp-arbitrary-uid", "k8s-pss"),
    ),
    Playbook(
        "DBG-SCC",
        "Pod rejected by SecurityContextConstraints",
        (
            r"unable to validate against any security context constraint",
            r"forbidden: unable to validate against any security context",
            r"provider restricted(-v2)?: .*not allowed",
            r"Invalid value: \d+: must be in the ranges",
            r"Forbidden: not usable by user or serviceaccount",
        ),
        (
            "The pod asks for something restricted-v2 forbids: fixed runAsUser/fsGroup outside the namespace range, "
            "privileged, hostPath, hostNetwork, added capabilities, allowPrivilegeEscalation: true.",
            "The ServiceAccount was never granted the more permissive SCC the workload genuinely needs.",
        ),
        (
            "oc get events -n {ns} --field-selector reason=FailedCreate",
            "oc describe rs -n {ns} -l <app-label>      # FailedCreate message lists every SCC tried",
            "oc get ns {ns} -o jsonpath='{{.metadata.annotations.openshift\\.io/sa\\.scc\\.uid-range}}'",
            "oc adm policy scc-subject-review -f <manifest.yaml>   # [OCP] which SCC would admit it",
        ),
        (
            "Remove runAsUser/runAsGroup/fsGroup and keep runAsNonRoot: true (preferred).",
            "Drop privileged/host settings; use a Service instead of hostPort; PVCs instead of hostPath.",
            "Only if truly required: oc adm policy add-scc-to-user nonroot-v2 -z {sa} -n {ns} (least permissive SCC "
            "that fits; never 'privileged' for app workloads).",
        ),
        platforms=("openshift", "rosa-classic", "rosa-hcp"),
        related_rules=("KN-S001", "KN-S004", "KN-S009", "KN-S010"),
        knowledge=("ocp-scc",),
        weight=1.3,
    ),
    Playbook(
        "DBG-PSA",
        "Pod blocked by Pod Security Admission",
        (r"violates PodSecurity", r"would violate PodSecurity", r"pod-security\.kubernetes\.io"),
        (
            "Namespace enforces the baseline/restricted Pod Security Standard and the pod spec violates it "
            "(missing seccompProfile, capabilities not dropped, allowPrivilegeEscalation not false, runAsNonRoot).",
        ),
        (
            "oc get ns {ns} --show-labels   # pod-security.kubernetes.io/enforce",
            "oc get events -n {ns} --field-selector reason=FailedCreate",
        ),
        (
            "Add the restricted securityContext: runAsNonRoot: true, allowPrivilegeEscalation: false, "
            "capabilities.drop: [ALL], seccompProfile.type: RuntimeDefault (`kube-noob fix` does this).",
        ),
        related_rules=("KN-S002", "KN-S003", "KN-S006", "KN-S008"),
        knowledge=("k8s-pss",),
    ),
    Playbook(
        "DBG-PENDING-RESOURCES",
        "Pod Pending: insufficient CPU/memory",
        (
            r"Insufficient (cpu|memory|nvidia\.com/gpu|ephemeral-storage)",
            r"0/\d+ nodes are available",
            r"FailedScheduling",
            r"Too many pods",
        ),
        (
            "Requests exceed the free allocatable capacity on every node.",
            "Requests are far larger than needed (copied defaults).",
            "Cluster autoscaler / machine autoscaling disabled or at max size.",
        ),
        (
            "oc describe pod {pod} -n {ns}   # FailedScheduling details per node",
            "oc describe nodes | grep -A8 'Allocated resources'",
            "oc get machineautoscaler,clusterautoscaler -A   # [OCP]",
            "rosa list machinepools -c <cluster>   # [ROSA] autoscaling min/max",
        ),
        (
            "Right-size requests from real usage; scale the node pool / enable autoscaling.",
            "[ROSA] rosa edit machinepool -c <cluster> <pool> --enable-autoscaling --min-replicas N --max-replicas M",
        ),
        related_rules=("KN-C004",),
        knowledge=("k8s-resources",),
    ),
    Playbook(
        "DBG-PENDING-PLACEMENT",
        "Pod Pending: taints, node selectors or affinity",
        (
            r"had untolerated taint",
            r"didn't match Pod's node affinity",
            r"node\(s\) didn't match node selector",
            r"didn't match pod (anti-)?affinity rules",
            r"didn't match pod topology spread constraints",
            r"volume node affinity conflict",
        ),
        (
            "nodeSelector/affinity targets labels no schedulable node has.",
            "Nodes are tainted (infra, GPU, control-plane) and the pod has no toleration.",
            "Required (DoNotSchedule) topology spread or anti-affinity cannot be satisfied with current nodes.",
            "Zonal volume exists in a zone with no eligible node ('volume node affinity conflict').",
        ),
        (
            "oc describe pod {pod} -n {ns}",
            "oc get nodes -L topology.kubernetes.io/zone,node-role.kubernetes.io/worker",
            "oc get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints",
        ),
        (
            "Fix labels/tolerations; prefer whenUnsatisfiable: ScheduleAnyway for spread constraints.",
            "For zonal volumes use volumeBindingMode: WaitForFirstConsumer and keep nodes in every zone.",
        ),
        related_rules=("KN-C010", "KN-ST003"),
        knowledge=("k8s-topology-spread",),
    ),
    Playbook(
        "DBG-PVC-PENDING",
        "PersistentVolumeClaim stuck in Pending",
        (
            r"unbound immediate PersistentVolumeClaims",
            r"ProvisioningFailed",
            r"waiting for a volume to be created",
            r"no persistent volumes available for this claim",
            r"storageclass\.storage\.k8s\.io \"?[\w.-]+\"? not found",
            r"waiting for first consumer to be created before binding",
            r"ExternalProvisioning",
            r"access mode .* not supported",
            r"failed to provision volume",
            r"(?i)\b(?:pvcs?|persistentvolumeclaims?|volume claims?)\b[^\n]{0,40}"
            r"\b(?:stuck|pending|not bound|unbound)\b",
            r"(?i)\b(?:stuck|pending)\b[^\n]{0,20}\b(?:pvcs?|persistentvolumeclaims?)\b",
        ),
        (
            "Access mode unsupported by the class: ReadWriteMany on EBS (gp3-csi/gp2-csi) or Ceph RBD filesystem.",
            "StorageClass name does not exist or there is no default StorageClass.",
            "WaitForFirstConsumer: normal until a pod using the claim is scheduled.",
            "CSI driver not installed (e.g. EFS CSI Driver Operator on ROSA) or lacks cloud permissions.",
        ),
        (
            "oc describe pvc {pvc} -n {ns}   # Events show the provisioner error",
            "oc get storageclass",
            "oc get csidriver",
            "oc get pods -n openshift-cluster-csi-drivers   # [OCP]",
        ),
        (
            "RWX on AWS/ROSA: install the AWS EFS CSI Driver Operator, create an EFS StorageClass "
            "(provisioningMode: efs-ap, fileSystemId) and use it; on ODF use ocs-storagecluster-cephfs.",
            "Recreate the PVC with a valid storageClassName (the field is immutable).",
        ),
        related_rules=("KN-ST001", "KN-ST004", "KN-ST005"),
        knowledge=("storage-access-modes", "rosa-efs"),
        weight=1.2,
    ),
    Playbook(
        "DBG-MULTIATTACH",
        "Volume Multi-Attach error",
        (
            r"Multi-Attach error for volume",
            r"Volume is already exclusively attached to one node",
            r"Volume is already used by pod",
        ),
        (
            "A ReadWriteOnce volume is mounted by pods on different nodes: several replicas sharing one claim, or a "
            "RollingUpdate surge pod scheduled to another node.",
            "The previous node died and the attachment has not been released yet (VolumeAttachment still present).",
        ),
        (
            "oc describe pod {pod} -n {ns}",
            "oc get volumeattachment | grep <pv-name>",
            "oc get pods -n {ns} -o wide   # which nodes hold pods using the claim",
        ),
        (
            "Use a StatefulSet with volumeClaimTemplates (one RWO volume per replica) or strategy: Recreate with "
            "replicas: 1, or a genuine RWX class if the app supports concurrent writers.",
            "After a node loss, wait for detach (~6 min) or delete the stale VolumeAttachment only once the node is "
            "confirmed down.",
        ),
        related_rules=("KN-ST002",),
        knowledge=("storage-access-modes",),
        weight=1.3,
    ),
    Playbook(
        "DBG-MOUNT",
        "Volume mount failures (FailedMount / permission denied)",
        (
            r"FailedMount",
            r"MountVolume\.SetUp failed",
            r"Unable to attach or mount volumes",
            r"timed out waiting for the condition",
            r"MountVolume\.\w+ failed .*permission denied",
            r"Read-only file system",
        ),
        (
            "Referenced Secret/ConfigMap volume missing.",
            "Filesystem ownership does not match the container UID/GID (fsGroup missing on vanilla Kubernetes; "
            "arbitrary UID on OpenShift).",
            "readOnlyRootFilesystem: true while the app writes outside its mounted emptyDir paths.",
            "NFS/EFS mount blocked by security groups (TCP 2049) or missing mount targets in the node's subnet.",
        ),
        (
            "oc describe pod {pod} -n {ns}",
            "oc rsh -n {ns} {pod} ls -ln <mount-path>   # numeric owner vs `id`",
        ),
        (
            "Vanilla Kubernetes: set pod securityContext.fsGroup; OpenShift assigns fsGroup from the namespace range.",
            "Mount an emptyDir at every path the app writes when using a read-only root filesystem.",
            "[ROSA/EKS + EFS] allow NFS (2049/tcp) from worker node security groups to the EFS mount targets.",
        ),
        related_rules=("KN-S007",),
        knowledge=("ocp-arbitrary-uid",),
    ),
    Playbook(
        "DBG-PROBE",
        "Readiness/liveness probe failures",
        (
            r"Readiness probe failed",
            r"Liveness probe failed",
            r"Startup probe failed",
            r"probe failed:.*connection refused",
            r"Client\.Timeout exceeded while awaiting headers",
            r"HTTP probe failed with statuscode",
        ),
        (
            "Probe port/path does not match what the app serves (wrong port name, /healthz vs /health).",
            "App listens on 127.0.0.1 instead of 0.0.0.0, so the kubelet cannot reach it.",
            "timeoutSeconds too low or the health endpoint checks slow dependencies.",
            "App needs more startup time (use startupProbe).",
        ),
        (
            "oc describe pod {pod} -n {ns}   # probe definition and failure message",
            "oc rsh -n {ns} {pod} curl -sv localhost:<port><path>",
            "oc logs {pod} -n {ns}",
        ),
        (
            "Align probe port/path with the container; bind to 0.0.0.0.",
            "Liveness must only check the process itself; readiness may check dependencies.",
            "Add startupProbe (failureThreshold x periodSeconds >= worst-case startup).",
        ),
        related_rules=("KN-C001", "KN-C002", "KN-C003"),
        knowledge=("k8s-probes",),
    ),
    Playbook(
        "DBG-ROUTE-503",
        "Route returns 503 'Application is not available'",
        (
            r"Application is not available",
            r"503 Service Unavailable",
            r"The application is currently not serving",
            r"router .* no endpoints",
            r"Route .* not admitted",
            r"HostAlreadyClaimed",
        ),
        (
            "The Service behind the Route has no ready endpoints (selector mismatch or pods not ready).",
            "Route port.targetPort does not name a Service port.",
            "Wrong TLS termination: edge Route to an HTTPS-only backend (use reencrypt/passthrough) or reencrypt to a "
            "plain HTTP backend.",
            'NetworkPolicy blocks the router: allow namespaceSelector policy-group.network.openshift.io/ingress: "".',
            "Route not admitted: host already claimed by another namespace (HostAlreadyClaimed).",
        ),
        (
            "oc get route {name} -n {ns} -o yaml   # status.ingress[].conditions",
            "oc get endpointslices -n {ns} -l kubernetes.io/service-name={name}",
            "oc get pods -n {ns} --show-labels",
            "oc get networkpolicy -n {ns}",
        ),
        (
            "Fix the Service selector / readiness so endpoints exist.",
            "Match tls.termination to the backend protocol.",
            "Add the router allow NetworkPolicy (see `kube-noob generate` output).",
        ),
        platforms=("openshift", "rosa-classic", "rosa-hcp"),
        related_rules=("KN-V011", "KN-V012", "KN-N001", "KN-N002"),
        knowledge=("ocp-routes",),
        weight=1.2,
    ),
    Playbook(
        "DBG-NO-ENDPOINTS",
        "Service has no endpoints",
        (
            r"no endpoints available for service",
            r"Endpoints:\s*<none>",
            r"endpoints \"[\w.-]+\" not found",
            r"connection refused",
        ),
        (
            "Service selector does not match pod labels.",
            "Pods are not Ready (readiness failing), so they are excluded.",
            "targetPort names a port the container does not declare.",
        ),
        (
            "oc describe svc {name} -n {ns}",
            "oc get endpointslices -n {ns} -l kubernetes.io/service-name={name} -o wide",
            "oc get pods -n {ns} -l <selector> -o wide",
        ),
        (
            "Align spec.selector with pod template labels; fix readiness; use numeric targetPort or declare the "
            "named containerPort.",
        ),
        related_rules=("KN-V011", "KN-V012"),
        knowledge=("k8s-services",),
    ),
    Playbook(
        "DBG-RBAC",
        "API request forbidden (RBAC)",
        (
            r"is forbidden: User \"[^\"]+\" cannot \w+ resource",
            r"cannot (get|list|watch|create|update|patch|delete) "
            r"resource",
            r"Forbidden \(403\)",
            r"system:serviceaccount:[\w-]+:[\w-]+ cannot",
        ),
        (
            "The ServiceAccount/user lacks a Role/ClusterRole granting the verb on that resource and API group.",
            "RoleBinding is in a different namespace than the resource.",
            "Wrong apiGroup in the Role (e.g. '' vs 'apps').",
        ),
        (
            "oc auth can-i {verb} {resource} -n {ns} --as={subject}",
            "oc get rolebinding,clusterrolebinding -A -o wide | grep -- '{subject}'",
        ),
        (
            "Grant the minimum: a Role with the exact apiGroups/resources/verbs plus a RoleBinding in the target "
            "namespace. Never bind cluster-admin to app ServiceAccounts.",
        ),
        related_rules=("KN-S015", "KN-S016", "KN-S017"),
        knowledge=("k8s-rbac",),
    ),
    Playbook(
        "DBG-WEBHOOK",
        "Admission webhook denied or failed",
        (
            r"admission webhook \"[^\"]+\" denied the request",
            r"failed calling webhook",
            r"Internal error occurred: "
            r"failed calling webhook",
            r"context deadline exceeded.*webhook",
        ),
        (
            "A policy engine (RHACS/StackRox, Gatekeeper, Kyverno) rejected the object - the message names the policy.",
            "The webhook service is down/unreachable and failurePolicy is Fail, blocking all matching requests.",
        ),
        (
            "oc get validatingwebhookconfigurations,mutatingwebhookconfigurations",
            "oc get validatingwebhookconfiguration <name> -o jsonpath='{{.webhooks[*].failurePolicy}}'",
        ),
        (
            "Fix the manifest to satisfy the named policy (run `kube-noob audit` first - rules map to RHACS policies).",
            "If the webhook backend is down: restore it; do not delete the webhook configuration in production "
            "without the owning team.",
        ),
        knowledge=("stackrox-admission",),
    ),
    Playbook(
        "DBG-STACKROX-ADMISSION",
        "RHACS / StackRox admission controller blocked a deployment",
        (
            r"policyeval\.stackrox\.io",
            r"stackrox",
            r"Red Hat Advanced Cluster Security",
            r"violated .* polic(y|ies)",
            r"The attempted operation violated \d+ enforced polic",
        ),
        (
            "A RHACS policy with deploy-time enforcement matched (e.g. Privileged Container, Latest tag, "
            "No resource requests or limits, root user).",
            "Admission controller enforcement is enabled for the cluster (secured cluster admissionControl.enforce, "
            "the 4.9+ setting replacing enforceOnCreates/enforceOnUpdates).",
        ),
        (
            "Read the policy names in the denial message.",
            "roxctl deployment check --file=<manifest.yaml> -e <central:443>   # same evaluation, offline from apply",
            "oc get validatingwebhookconfiguration stackrox -o yaml",
        ),
        (
            "Remediate the manifest (kube-noob rules list the matching RHACS policy for each finding).",
            "If a justified exception is needed, add a scoped policy exclusion in Central - do not disable "
            "enforcement cluster-wide.",
        ),
        related_rules=("KN-S001", "KN-S012", "KN-C004", "KN-S003"),
        knowledge=("stackrox-admission",),
        weight=1.4,
    ),
    Playbook(
        "DBG-HELM-LOCK",
        "Helm: another operation is in progress",
        (
            r"another operation \(install/upgrade/rollback\) is in progress",
            r"has no deployed releases",
            r"pending-(install|upgrade|rollback)",
        ),
        ("A previous helm install/upgrade was interrupted, leaving the release in a pending-* state.",),
        (
            "helm history <release> -n {ns}",
            "helm status <release> -n {ns}",
        ),
        (
            "If the last good revision is deployed: helm rollback <release> <last-good-revision> -n {ns}.",
            "If the first install failed: helm uninstall <release> -n {ns} and install again.",
            "Use --atomic / --wait --timeout in CI so failed upgrades roll back automatically.",
        ),
        knowledge=("helm-troubleshooting",),
        weight=1.3,
    ),
    Playbook(
        "DBG-HELM-OWNERSHIP",
        "Helm: resource exists and is not managed by this release",
        (
            r"rendered manifests contain a resource that already exists",
            r"invalid ownership metadata",
            r"meta\.helm\.sh/release-name",
            r"cannot be imported into the current release",
        ),
        ("The object was created outside Helm (kubectl apply, operator, other release).",),
        ("oc get <kind> <name> -n {ns} -o jsonpath='{{.metadata.labels}}{{.metadata.annotations}}'",),
        (
            "Adopt it deliberately: label app.kubernetes.io/managed-by=Helm and annotate "
            "meta.helm.sh/release-name=<release>, meta.helm.sh/release-namespace={ns}; or rename/delete the stray "
            "object.",
        ),
        knowledge=("helm-troubleshooting",),
        weight=1.3,
    ),
    Playbook(
        "DBG-NO-MATCHES-KIND",
        "API kind not found (no matches for kind / removed API)",
        (
            r"no matches for kind \"\w+\" in version \"[\w./]+\"",
            r"ensure CRDs are installed first",
            r"the server could not find the requested resource",
            r"resource mapping not found",
        ),
        (
            "The apiVersion was removed in this Kubernetes/OpenShift version (e.g. policy/v1beta1 PDB in 1.25).",
            "The CRD is not installed (operator missing) or the kind belongs to another platform (Route on vanilla "
            "Kubernetes).",
            "Wrong group for the kind (Route is route.openshift.io/v1, not apps.openshift.io/v1).",
        ),
        (
            "oc api-resources | grep -i <kind>",
            "oc version   # server Kubernetes version",
            "kube-noob audit -f <manifest.yaml> --platform <platform> --version <ocp-or-k8s-version>",
        ),
        ("Migrate apiVersions (`kube-noob fix` handles mechanical migrations) or install the operator/CRDs first.",),
        related_rules=("KN-V002", "KN-V003", "KN-V004", "KN-V005"),
        knowledge=("k8s-deprecations",),
        weight=1.3,
    ),
    Playbook(
        "DBG-EVICTED",
        "Pods evicted (node pressure)",
        (
            r"\bEvicted\b",
            r"The node was low on resource",
            r"DiskPressure",
            r"MemoryPressure",
            r"ephemeral local storage usage exceeds",
        ),
        (
            "Node ran out of memory or disk; BestEffort/Burstable pods exceeding requests are evicted first.",
            "Container writes logs/temp files to the container filesystem (ephemeral-storage) without limits.",
        ),
        (
            "oc get pods -n {ns} --field-selector status.phase=Failed",
            "oc describe node <node> | grep -A5 Conditions",
        ),
        (
            "Set requests/limits including ephemeral-storage; send logs to stdout; size emptyDir with sizeLimit.",
            "Clean up evicted pods: oc delete pod -n {ns} --field-selector status.phase=Failed",
        ),
        related_rules=("KN-C004", "KN-C005"),
        knowledge=("k8s-resources",),
    ),
    Playbook(
        "DBG-DNS",
        "DNS resolution failures inside pods",
        (
            r"no such host",
            r"Temporary failure in name resolution",
            r"server misbehaving",
            r"lookup [\w.-]+ on [\d.:]+: (read udp|dial udp).*i/o timeout",
            r"NXDOMAIN",
            r"(?i)\b(?:dns|name resolution)\b[^\n]{0,30}\b(?:issues?|problems?|not (?:working|resolving)|"
            r"fail(?:s|ed|ing|ure)?|broken|timeouts?)\b",
        ),
        (
            "Egress NetworkPolicy blocks DNS (OpenShift DNS listens on 5353 in openshift-dns; CoreDNS on 53 in "
            "kube-system).",
            "Wrong service name/namespace (use <svc>.<ns>.svc.cluster.local).",
            "Upstream resolver/VPC DNS issue for external names (ROSA private clusters: VPC DNS hostnames/resolution "
            "must be enabled).",
        ),
        (
            "oc rsh -n {ns} {pod} getent hosts kubernetes.default.svc",
            "oc get networkpolicy -n {ns} -o yaml | grep -B3 -A10 egress",
            "oc get pods -n openshift-dns   # [OCP]",
        ),
        (
            "Allow egress to the cluster DNS pods (port 5353 TCP/UDP to namespace openshift-dns on OpenShift; 53 to "
            "kube-system elsewhere).",
        ),
        knowledge=("k8s-networkpolicy",),
    ),
    Playbook(
        "DBG-NETPOL",
        "Traffic blocked between pods / to the internet",
        (
            r"i/o timeout",
            r"connection timed out",
            r"dial tcp [\d.:]+: (connect: )?connection timed out",
            r"EgressFirewall",
            r"context deadline exceeded",
        ),
        (
            "A default-deny NetworkPolicy without an allow rule for this source/port.",
            "[OCP] EgressFirewall denies the destination (rules are first-match; a leading Deny 0.0.0.0/0 blocks "
            "everything after it).",
            "Cloud security groups / firewall outside the cluster.",
        ),
        (
            "oc get networkpolicy -n {ns}",
            "oc get egressfirewall -n {ns} -o yaml   # [OCP]",
            "oc rsh -n {ns} {pod} curl -sv --max-time 5 <target>",
        ),
        (
            "Add explicit allow rules (podSelector/namespaceSelector + ports).",
            "Order EgressFirewall rules: specific Allow first, catch-all Deny last; the object must be named "
            "'default'.",
        ),
        related_rules=("KN-N006", "KN-V015", "KN-N001"),
        knowledge=("k8s-networkpolicy", "ocp-egressfirewall"),
        weight=0.8,
    ),
    Playbook(
        "DBG-X509-CLIENT",
        "oc / kubectl cannot verify the API server's certificate",
        (
            r"Unable to connect to the server: (x509|tls)",
            r"Unable to connect to the server: .*certificate",
            r"error: x509: certificate signed by unknown authority",
        ),
        (
            "The kubeconfig does not trust the CA that signed the API server certificate (new cluster, rotated "
            "certificate, or a corporate proxy that re-signs TLS).",
            "The kubeconfig points at the wrong server, or the machine clock is skewed.",
        ),
        (
            "oc config view --minify -o jsonpath='{{.clusters[0].cluster.server}}'   # which API server you call",
            "openssl s_client -connect <api-host>:6443 -servername <api-host> </dev/null | openssl x509 -noout "
            "-issuer -subject -dates",
            "date -u   # clock skew breaks certificate validity",
        ),
        (
            "Log in again with the right CA: `oc login <api-url> --certificate-authority=<ca.crt>` (ROSA and "
            "OpenShift Dedicated serve a publicly trusted certificate unless you changed it). Behind a TLS-inspecting "
            "proxy, add the proxy's CA to the system trust store. Avoid --insecure-skip-tls-verify outside "
            "throwaway clusters.",
        ),
        knowledge=("k8s-tls-x509",),
        weight=1.4,
    ),
    Playbook(
        "DBG-X509",
        "TLS / certificate errors",
        (
            r"x509: certificate has expired or is not yet valid",
            r"x509: certificate signed by unknown authority",
            r"x509: certificate is valid for",
            r"tls: failed to verify certificate",
            r"certificate verify failed",
        ),
        (
            "Expired certificate (check notAfter), clock skew, or the client does not trust the issuing CA.",
            "Hostname mismatch (SAN does not include the host being called).",
        ),
        (
            "oc get events -n {ns} --sort-by=.lastTimestamp   # which component reports the x509 error",
            "oc get route -n {ns} -o wide                     # TLS termination per Route",
            "openssl s_client -connect <host>:443 -servername <host> </dev/null | openssl x509 -noout -dates "
            "-subject -ext subjectAltName",
        ),
        (
            "Renew/rotate the certificate (cert-manager, OpenShift service CA); add the CA to the client trust bundle "
            "(OpenShift: config map with label config.openshift.io/inject-trusted-cabundle=true).",
        ),
        knowledge=("ocp-routes",),
    ),
    Playbook(
        "DBG-EXEC-FORMAT",
        "exec format error (wrong CPU architecture)",
        (r"exec format error", r"exec user process caused", r"no match for platform in manifest"),
        (
            "The image was built for another architecture (arm64 image on amd64 nodes or vice versa), or the "
            "entrypoint script lacks a shebang.",
        ),
        (
            "skopeo inspect --raw docker://<image> | jq '.manifests[].platform'",
            "oc get nodes -L kubernetes.io/arch",
        ),
        (
            "Build multi-arch images (docker buildx --platform linux/amd64,linux/arm64) or schedule onto matching "
            "nodes with nodeSelector kubernetes.io/arch.",
        ),
        knowledge=("k8s-images",),
        weight=1.3,
    ),
    Playbook(
        "DBG-QUOTA",
        "Rejected by ResourceQuota / LimitRange",
        (
            r"exceeded quota",
            r"must specify limits\.(cpu|memory)",
            r"must specify requests\.(cpu|memory)",
            r"maximum (cpu|memory) usage per Container is",
            r"is forbidden: failed quota",
        ),
        ("Namespace quota exhausted, or the quota covers limits/requests and the pod does not set them.",),
        (
            "oc describe quota -n {ns}",
            "oc describe limitrange -n {ns}",
        ),
        ("Set requests and limits on every container; ask the namespace owner to raise the quota.",),
        related_rules=("KN-C004", "KN-C005"),
        knowledge=("k8s-resources",),
    ),
    Playbook(
        "DBG-PDB-DRAIN",
        "Node drain / upgrade blocked by PodDisruptionBudget",
        (
            r"Cannot evict pod as it would violate the pod's disruption budget",
            r"disruptionsAllowed:\s*0",
            r"PodDisruptionBudgetAtLimit",
            r"error when evicting pods",
        ),
        ("PDB allows zero disruptions (minAvailable == replicas, maxUnavailable: 0) or the workload is unhealthy.",),
        (
            "oc get pdb -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,"
            "ALLOWED:.status.disruptionsAllowed",
        ),
        (
            "Use maxUnavailable: 1 with replicas >= 2; fix unhealthy replicas so disruptions are allowed.",
            "[ROSA] managed upgrades respect PDBs up to a grace period, then force-drain - fix PDBs before upgrading.",
        ),
        related_rules=("KN-C009",),
        knowledge=("k8s-pdb",),
        weight=1.3,
    ),
    Playbook(
        "DBG-HPA",
        "HorizontalPodAutoscaler shows <unknown> / does not scale",
        (
            r"<unknown>/\d+%",
            r"failed to get cpu utilization",
            r"missing request for cpu",
            r"FailedGetResourceMetric",
            r"unable to get metrics for resource",
        ),
        (
            "Target containers lack CPU requests, or the metrics API (metrics-server / OpenShift monitoring) is "
            "unavailable.",
        ),
        (
            "oc describe hpa {name} -n {ns}",
            "oc get apiservice v1beta1.metrics.k8s.io",
        ),
        ("Set CPU requests on every container in the target; make sure the metrics API is healthy.",),
        related_rules=("KN-C012",),
        knowledge=("k8s-resources",),
    ),
    Playbook(
        "DBG-JOB",
        "Job failed (BackoffLimitExceeded / DeadlineExceeded)",
        (r"BackoffLimitExceeded", r"DeadlineExceeded", r"Job has reached the specified backoff limit"),
        ("The job's pod exits non-zero repeatedly or exceeds activeDeadlineSeconds.",),
        (
            "oc get pods -n {ns} -l job-name={name}",
            "oc logs -n {ns} -l job-name={name} --tail=100",
        ),
        ("Fix the job's command/config; tune backoffLimit and activeDeadlineSeconds; make jobs idempotent.",),
        knowledge=("k8s-debug-pods",),
    ),
    Playbook(
        "DBG-CLUSTEROPERATOR",
        "OpenShift ClusterOperator degraded/unavailable",
        (
            r"ClusterOperator\w* .*Degraded",
            r"Degraded\s+True",
            # an `oc get co` row (NAME VERSION AVAILABLE PROGRESSING DEGRADED) with Degraded True or Available False
            r"\b[a-z][a-z0-9-]{1,62}\s+4\.\d{1,2}\.\d{1,3}\S*\s+(?:True|False|Unknown)\s+(?:True|False|Unknown)\s+True\b",
            r"\b[a-z][a-z0-9-]{1,62}\s+4\.\d{1,2}\.\d{1,3}\S*\s+False\s+(?:True|False|Unknown)\s+(?:True|False|Unknown)\b",
            r"\b[A-Z][A-Za-z]{2,60}ControllerDegraded\b",  # library-go operator condition reasons
            r"Available\s+False",
            r"clusteroperator",
            r"ClusterVersion.*(Failing|Progressing)",
        ),
        (
            "A platform component (ingress, authentication, image-registry, monitoring, storage) is unhealthy; "
            "upgrades stall until it recovers.",
        ),
        (
            "oc get clusteroperators",
            "oc describe clusteroperator <name>",
            "oc get clusterversion -o yaml",
        ),
        (
            "Follow the operator's condition message; on ROSA the platform operators are SRE-managed - open a "
            "support case rather than editing openshift-* namespaces.",
        ),
        platforms=("openshift", "rosa-classic", "rosa-hcp"),
        knowledge=("ocp-operators",),
    ),
    # Sources (checked 2026-10-28): etcd FAQ (disk latency is part of leader liveness; WAL fsync p99 < 10 ms,
    # backend commit p99 < 25 ms; CPU starvation) https://etcd.io/docs/v3.5/faq/ ; etcd maintenance guide (space
    # quota, NOSPACE alarm, compact, defrag, alarm disarm) https://etcd.io/docs/v3.5/op-guide/maintenance/ ; log and
    # error strings: server/storage/wal/wal.go ("slow fdatasync"), server/etcdserver/raft.go ("leader failed to send
    # out heartbeat on time"), server/etcdserver/txn/util.go ("apply request took too long"),
    # api/v3rpc/rpctypes/error.go ("etcdserver: leader changed", "mvcc: database space exceeded") in etcd-io/etcd;
    # alert names in kube_noob/data/signals.yaml; OpenShift commands from openshift-docs modules/etcd-defrag.adoc,
    # restore-determine-state-etcd-member.adoc and recommended-etcd-practices.adoc (enterprise-4.21); kubeadm static
    # pod labels (component=etcd) from cmd/kubeadm/app/util/staticpod/utils.go.
    Playbook(
        "DBG-ETCD",
        "etcd is slow or unstable (leader changes, slow disk, no leader, database space)",
        (
            r"etcdHighNumberOfLeaderChanges",
            r"etcdNoLeader",
            r"etcd(MembersDown|InsufficientMembers)",
            r"etcdHigh(Fsync|Commit)Durations",
            r"etcdGRPC(Read|Write)?RequestsSlow",
            r"etcd(DatabaseQuotaLowSpace|ExcessiveDatabaseGrowth|DatabaseHighFragmentationRatio)",
            r"etcdserver: (leader changed|no leader|request timed out)",
            r"mvcc: database space exceeded",
            r"apply request took too long",
            r"slow fdatasync",
            r"failed to send out heartbeat on time",
            r"\betcd\b[^\n]{0,60}\bleader (changed|changes|election)",
        ),
        (
            "Slow disk under etcd: every write is persisted before it is acknowledged, so disk latency is part of "
            "leader liveness. A WAL fsync p99 above 10 ms or a backend commit p99 above 25 ms makes the leader miss "
            "heartbeats, members hold elections, and the API server times out.",
            "CPU starvation on the control-plane nodes, the second most common cause of missed heartbeats.",
            "Slow or lossy network between control-plane nodes (high round-trip time between zones).",
            "The database reached its space quota: etcd raises a NOSPACE alarm and accepts only reads and deletes "
            "(`mvcc: database space exceeded`) until it is compacted, defragmented and the alarm is cleared.",
            "A member is down or its node is NotReady; with too few members the cluster loses quorum and has no "
            "leader.",
            "A product bug that adds control-plane I/O: check the reported issues listed for your version.",
        ),
        (
            "oc get co etcd kube-apiserver   # [OCP] Degraded or Progressing, and since when",
            "oc describe co etcd   # [OCP] the operator's messages name the failing member or check",
            "oc get pods -n openshift-etcd -l k8s-app=etcd -o wide   # [OCP] one per control-plane node, restarts",
            "kubectl get pods -n kube-system -l component=etcd -o wide   # [K8S] kubeadm runs etcd as a static pod",
            "oc get nodes -l node-role.kubernetes.io/master   # [OCP] control-plane nodes Ready?",
            "kubectl get nodes -l node-role.kubernetes.io/control-plane   # [K8S] control-plane nodes Ready?",
            "oc adm top nodes -l node-role.kubernetes.io/master   # [OCP] CPU and memory pressure",
            "kubectl top nodes -l node-role.kubernetes.io/control-plane   # [K8S] CPU and memory pressure",
            "In Observe > Metrics (or Prometheus), graph histogram_quantile(0.99, "
            "rate(etcd_disk_wal_fsync_duration_seconds_bucket[5m])) (healthy under 0.01 s), histogram_quantile(0.99, "
            "rate(etcd_disk_backend_commit_duration_seconds_bucket[5m])) (under 0.025 s) and "
            "changes(etcd_server_is_leader[10m]).",
            "oc rsh -n openshift-etcd etcd-<control-plane-node> etcdctl endpoint status --cluster -w table   # [OCP] "
            "leader, database size and raft index of every member",
            "oc rsh -n openshift-etcd etcd-<control-plane-node> etcdctl alarm list   # [OCP] NOSPACE means the "
            "database hit its quota",
        ),
        (
            "Give etcd fast, dedicated storage: Red Hat asks for a block device that writes at least 50 IOPS of 8 KB "
            "sequentially, including fdatasync, in under 10 ms, prefers NVMe in production and rules out network "
            "file systems and spinning disks. Move other I/O off the control-plane disks.",
            "Relieve CPU pressure on control-plane nodes: keep workloads off them and size them up.",
            "If a reported issue below matches your version, update to the release that fixes it before changing "
            "hardware.",
            "NOSPACE alarm: find what grows (events, custom resources, secrets), then defragment one member at a "
            "time, starting with a member that is not the leader, and clear the alarm (`etcdctl defrag`, "
            "`etcdctl alarm disarm`) following OpenShift's 'Defragmenting etcd data' procedure. Defragmenting "
            "blocks reads and writes on that member while it runs.",
            "Member down or no leader: fix the node first (NotReady, disk full, network); replace a member only by "
            "following OpenShift's 'Replacing an unhealthy etcd member' procedure, never removing members below "
            "quorum.",
        ),
        platforms=("kubernetes", "openshift"),
    ),
    Playbook(
        "DBG-ROSA-HCP-NODES",
        "ROSA HCP: machine pool nodes not joining / not ready",
        (
            r"machine ?pool",
            r"NodePool",
            r"rosa (list|describe) machinepools?",
            r"nodes? (not ready|NotReady)",
            r"PrivateLink",
            r"vpc endpoint",
        ),
        (
            "Worker subnets cannot reach the hosted control plane endpoint (route tables, security groups, VPC "
            "endpoint for private clusters).",
            "Subnets out of IP addresses or not tagged/associated as required.",
            "Instance type unavailable in the AZ or EC2 quota reached.",
        ),
        (
            "rosa describe cluster -c <cluster>",
            "rosa list machinepools -c <cluster>",
            "rosa describe machinepool -c <cluster> <pool>",
            "oc get nodes -o wide",
        ),
        (
            "Fix VPC networking for the worker subnets; free IPs or add subnets; request EC2 quota increases.",
            "Node configuration on HCP is done through machine pools (rosa edit machinepool), not MachineConfig.",
        ),
        platforms=("rosa-hcp",),
        related_rules=("KN-V017",),
        knowledge=("rosa-hcp",),
    ),
    Playbook(
        "DBG-ARBITRARY-UID",
        "Permission denied writing files on OpenShift",
        (
            r"mkdir: cannot create directory .*Permission denied",
            r"mkdir\(\) \S+ failed \(13: Permission denied\)",
            r"open\(\) \S+ failed \(13: Permission denied\)",
            r"EACCES",
            r"Permission denied",
            r"cannot open .* for writing",
            r"chown: changing ownership .* Operation not permitted",
        ),
        (
            "OpenShift runs containers with a random UID (from the namespace range) and GID 0; image directories "
            "owned by a specific user are not writable.",
        ),
        (
            "oc get pod {pod} -n {ns} -o jsonpath='{{.metadata.annotations.openshift\\.io/scc}}'   # admitting SCC",
            "oc get namespace {ns} -o jsonpath='{{.metadata.annotations.openshift\\.io/sa\\.scc\\.uid-range}}'",
            "oc logs {pod} -n {ns} --previous   # 'Permission denied' on a path shows which directory",
            "oc rsh -n {ns} {pod} id",
            "oc rsh -n {ns} {pod} ls -ld <dir>",
        ),
        (
            "In the Dockerfile: RUN chgrp -R 0 <dirs> && chmod -R g=u <dirs>; write only to mounted volumes or "
            "emptyDir; never chown at runtime.",
        ),
        platforms=("openshift", "rosa-classic", "rosa-hcp"),
        related_rules=("KN-S004",),
        knowledge=("ocp-arbitrary-uid",),
        weight=0.9,
    ),
    Playbook(
        "DBG-IMMUTABLE-SELECTOR",
        "Workload selector cannot change ('field is immutable')",
        (
            r"spec\.selector.*field is immutable",
            r"field is immutable.*selector",
            r"LabelSelector.*field is immutable",
        ),
        (
            "In apps/v1 the label selector of a Deployment, StatefulSet or DaemonSet is fixed at creation; the new "
            "manifest changes it (often a renamed `app` label).",
        ),
        (
            "oc get deployment -n {ns} -o custom-columns=NAME:.metadata.name,SELECTOR:.spec.selector.matchLabels",
            "oc get pods -n {ns} --show-labels",
        ),
        (
            "Keep the existing selector and only add new pod labels.",
            "Or create the workload under a new name, move the Service to it, then delete the old one.",
        ),
        knowledge=("k8s-common-errors",),
        weight=1.3,
    ),
    Playbook(
        "DBG-NS-TERMINATING",
        "Namespace stuck in Terminating",
        (
            r"Namespace(DeletionDiscoveryFailure|FinalizersRemaining|ContentRemaining|DeletionContentFailure)",
            r"namespace\s+\S+\s+.*\bTerminating\b",
            r"namespace .* stuck",
        ),
        (
            "An aggregated APIService is unavailable, so the namespace controller cannot list every resource type.",
            "Objects in the namespace carry finalizers whose controller is gone or failing.",
        ),
        (
            "oc get namespace {ns} -o yaml   # status.conditions name the blocker",
            "oc get apiservice   # any Available=False blocks namespace deletion",
            "oc api-resources --verbs=list --namespaced -o name"
            " | xargs -n 1 oc get --show-kind --ignore-not-found -n {ns}",
        ),
        (
            "Fix or remove the unavailable APIService (for example a removed metrics adapter).",
            "Fix the controller that owns the remaining finalizers so it can finish its cleanup.",
            "Removing finalizers by hand skips that cleanup (cloud load balancers, volumes); do it only knowingly.",
        ),
        knowledge=("k8s-common-errors",),
        weight=1.2,
    ),
    Playbook(
        "DBG-POD-TERMINATING",
        "Pod stuck in Terminating",
        (
            r"pod\s+\S+\s+.*stuck.*Terminating",
            r"stuck in Terminating",
            r"\bTerminating\b.*\b(\d+[hd]|[2-9]\d+m)\b",
        ),
        (
            "A finalizer on the pod is waiting for a controller that is gone.",
            "The node is NotReady or gone, so the kubelet cannot confirm the container stopped.",
        ),
        (
            "oc get pod {pod} -n {ns} -o jsonpath='{{.metadata.finalizers}}'",
            "oc get pod {pod} -n {ns} -o wide",
            "oc get nodes",
        ),
        (
            "Recover or remove the node; the pod then finishes terminating.",
            "Force deletion (--grace-period=0 --force) only removes the API object; never do it for StatefulSet pods "
            "unless the node is confirmed down.",
        ),
        knowledge=("k8s-common-errors",),
    ),
    Playbook(
        "DBG-EGRESSIP",
        "EgressIP not assigned to any node",
        (
            r"egress ?ip.*(no|not) assigned",
            r"egress ?ip.*unassigned",
            r"EgressIP .* (no assigned node|not assigned)",
            r"egress-assignable",
        ),
        (
            "No worker node carries the label k8s.ovn.org/egress-assignable.",
            "The IP is outside the subnets of the labelled nodes.",
            "The labelled nodes have no free IP capacity (AWS limits IPs per instance type).",
        ),
        (
            "oc get egressip -o wide",
            "oc get nodes -l k8s.ovn.org/egress-assignable= -o wide",
            "oc get nodes -l k8s.ovn.org/egress-assignable= -o yaml | grep egress-ipconfig",
        ),
        (
            "[ROSA] label a machine pool: rosa edit machinepool -c <cluster> <pool> "
            "--labels k8s.ovn.org/egress-assignable= (this replaces the pool's labels; repeat the ones you need).",
            "Pick egress IPs inside the worker subnets and spread them across zones.",
        ),
        platforms=("openshift", "rosa-classic", "rosa-hcp"),
        knowledge=("ocp-egressip",),
        weight=1.3,
    ),
)

EXIT_CODES: dict[int, str] = {
    0: "completed successfully (restarting because restartPolicy is Always - the process must not exit)",
    1: "application error (check logs --previous)",
    2: "misuse of shell builtin / invalid arguments",
    126: "command found but not executable (permissions, wrong architecture)",
    127: "command not found (wrong command/args or missing binary in image)",
    128: "invalid exit argument",
    130: "terminated by Ctrl-C (SIGINT)",
    134: "abort (SIGABRT) - often an assertion or JVM crash",
    137: "killed with SIGKILL - OOMKilled or forced kill after grace period",
    139: "segmentation fault (SIGSEGV)",
    143: "terminated with SIGTERM - normal shutdown, or killed by a failing liveness probe",
}

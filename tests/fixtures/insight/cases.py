# ruff: noqa: E501  (fixture lines are the real width of the tool output they copy)
"""Labelled inputs for the insight recogniser (INS1): realistic shapes of every kind, generated deterministically.

Each case is (text, expected kinds). Synthetic: written from the formats the tools print (kubectl/oc, kubelet events,
Alertmanager, Jira and ServiceNow exports, buildah/BuildKit/Tekton/GitHub Actions/Jenkins logs, Trivy/Grype/SARIF,
SPDX/CycloneDX, tcpdump, must-gather layouts), varied by seeded random names. Never tuned case by case.
"""

from __future__ import annotations

import json
import random

NS = ["shop", "payments", "orders", "openshift-monitoring", "team-a", "prod"]
APPS = ["web", "api", "worker", "cart", "auth", "billing", "search"]
REASONS = [
    ("Warning", "BackOff", "Back-off restarting failed container {c} in pod {p}"),
    ("Warning", "FailedScheduling", "0/3 nodes are available: 3 Insufficient memory."),
    ("Warning", "Failed", "Error: ImagePullBackOff"),
    ("Warning", "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 503"),
    ("Warning", "FailedMount", 'MountVolume.SetUp failed for volume "data" : secret "tls" not found'),
    ("Normal", "Pulled", 'Container image "quay.io/acme/{c}:1.2" already present on machine'),
]


def _pod(r: random.Random) -> tuple[str, str, str]:
    app = r.choice(APPS)
    return r.choice(NS), app, f"{app}-{r.randrange(16**9):09x}-{r.randrange(36**5):05d}"[:24]


def events(r: random.Random) -> str:
    _ns, app, pod = _pod(r)
    rows = []
    for _ in range(r.randint(2, 6)):
        t, reason, msg = r.choice(REASONS)
        rows.append(
            f"  {t:8} {reason:20} {r.randint(1, 59)}s (x{r.randint(1, 9)} over 2m)  kubelet  "
            + msg.format(c=app, p=pod)
        )
    if r.random() < 0.5:
        return (
            "Events:\n  Type     Reason   Age   From   Message\n  ----     ------   ----  ----   -------\n"
            + "\n".join(rows)
        )
    lines = [
        f"{r.randint(1, 50)}m  {t:7} {reason:16} pod/{pod}  {msg.format(c=app, p=pod)}"
        for t, reason, msg in (r.choice(REASONS) for _ in range(3))
    ]
    return "LAST SEEN   TYPE      REASON             OBJECT           MESSAGE\n" + "\n".join(lines)


def event_json(r: random.Random) -> str:
    ns, app, pod = _pod(r)
    t, reason, msg = r.choice(REASONS)
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "EventList",
            "items": [
                {
                    "type": t,
                    "reason": reason,
                    "message": msg.format(c=app, p=pod),
                    "involvedObject": {"kind": "Pod", "name": pod, "namespace": ns},
                }
            ],
        }
    )


def describe_pod(r: random.Random) -> str:
    ns, app, pod = _pod(r)
    state = r.choice(
        ["Waiting\n      Reason:       CrashLoopBackOff", "Waiting\n      Reason:       ImagePullBackOff", "Running"]
    )
    return (
        f"Name:             {pod}\nNamespace:        {ns}\nNode:             worker-{r.randint(1, 9)}/10.0.0.{r.randint(2, 250)}\n"
        f"Status:           Running\nContainers:\n  {app}:\n    Image:          quay.io/acme/{app}:1.2\n"
        f"    State:          {state}\n    Last State:     Terminated\n      Reason:       OOMKilled\n"
        f"      Exit Code:    137\n    Restart Count:  {r.randint(1, 30)}\n"
        "Events:\n  Type     Reason   Age   From     Message\n  ----     ------   ----  ----     -------\n"
        f"  Warning  BackOff  {r.randint(1, 59)}s   kubelet  Back-off restarting failed container {app} in pod {pod}"
    )


def pod_yaml(r: random.Random) -> str:
    ns, app, pod = _pod(r)
    return (
        f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: {pod}\n  namespace: {ns}\nspec:\n  containers:\n"
        f"  - name: {app}\n    image: quay.io/acme/{app}:1.2\nstatus:\n  phase: Pending\n  containerStatuses:\n"
        f"  - name: {app}\n    ready: false\n    restartCount: {r.randint(0, 9)}\n    state:\n      waiting:\n"
        '        reason: CreateContainerConfigError\n        message: configmap "cfg" not found\n'
    )


def logs(r: random.Random) -> str:
    style = r.randrange(6)
    n = r.randint(3, 8)
    if style == 0:
        return "\n".join(
            f"E1028 10:{i:02d}:0{r.randint(0, 9)}.12345{i} 1 reflector.go:147] failed to list *v1.Pod: "
            "context deadline exceeded"
            for i in range(n)
        )
    if style == 1:
        return "\n".join(
            f"2026-10-28T10:{i:02d}:11.120Z ERROR db connection refused host=postgres port=5432" for i in range(n)
        )
    if style == 2:
        return "\n".join(
            f'time="2026-10-28T10:00:{i:02d}Z" level=error msg="upstream timeout" route=/api/v1/orders'
            for i in range(n)
        )
    if style == 3:
        return "\n".join(
            json.dumps({"level": "error", "ts": 1761645600 + i, "msg": "token expired", "user": "svc"})
            for i in range(n)
        )
    if style == 4:
        return (
            'Traceback (most recent call last):\n  File "/app/main.py", line 42, in <module>\n    run()\n'
            '  File "/app/db.py", line 7, in run\n    conn = psycopg2.connect(dsn)\n'
            "psycopg2.OperationalError: could not connect to server: Connection refused"
        )
    return (
        'Exception in thread "main" java.lang.OutOfMemoryError: Java heap space\n'
        "\tat java.util.Arrays.copyOf(Arrays.java:3236)\n\tat com.acme.Cache.put(Cache.java:88)\n"
        "\tat com.acme.Main.main(Main.java:21)"
    )


def ticket(r: random.Random) -> str:
    style = r.randrange(4)
    key = f"OCPBUGS-{r.randint(1000, 90000)}"
    if style == 0:
        return (
            f"{key}: Router pods crash after certificate rotation\nStatus: New | Priority: Major\n"
            "Description: after rotating the default ingress certificate the router restarts in a loop."
        )
    if style == 1:
        return json.dumps(
            {"issues": [{"key": key, "fields": {"summary": "etcd slow after upgrade", "status": {"name": "New"}}}]}
        )
    if style == 2:
        return json.dumps(
            {
                "result": [
                    {
                        "number": f"INC{r.randint(1000000, 9999999)}",
                        "short_description": "pods OOMKilled in orders",
                        "state": "6",
                    }
                ]
            }
        )
    return f"Issue key,Summary,Status,Resolution\n{key},Pods Pending on worker pool,Closed,Done\n"


def manifests(r: random.Random) -> str:
    ns, app, _ = _pod(r)
    docs = [
        f"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {app}\n  namespace: {ns}\nspec:\n  replicas: 2\n"
        f"  selector:\n    matchLabels: {{app: {app}}}\n  template:\n    metadata:\n      labels: {{app: {app}}}\n"
        f"    spec:\n      containers:\n      - name: {app}\n        image: quay.io/acme/{app}:1.2\n"
    ]
    if r.random() < 0.5:
        docs.append(
            f"apiVersion: v1\nkind: Service\nmetadata:\n  name: {app}\n  namespace: {ns}\nspec:\n"
            f"  selector: {{app: {app}}}\n  ports:\n  - port: 8080\n"
        )
    if r.random() < 0.3:
        docs.append(
            f"apiVersion: route.openshift.io/v1\nkind: Route\nmetadata:\n  name: {app}\n  namespace: {ns}\n"
            f"spec:\n  to: {{kind: Service, name: {app}}}\n"
        )
    return "---\n".join(docs)


def helm(r: random.Random) -> str:
    app = r.choice(APPS)
    if r.random() < 0.5:
        return f"apiVersion: v2\nname: {app}\ndescription: A Helm chart\ntype: application\nversion: 0.1.{r.randint(0, 9)}\n"
    return (
        'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ include "' + app + '.fullname" . }}\n'
        "spec:\n  replicas: {{ .Values.replicaCount }}\n  template:\n    spec:\n      containers:\n"
        '      - name: {{ .Chart.Name }}\n        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"\n'
    )


def denial(r: random.Random) -> str:
    ns, app, pod = _pod(r)
    return r.choice(
        [
            f"Error from server: admission webhook \"validate.kyverno.svc-fail\" denied the request: resource Deployment/{ns}/{app} was blocked due to the following policies\nrequire-labels:\n  check-team: label 'team' is required",
            f'Error from server (Forbidden): error when creating "deploy.yaml": pods "{pod}" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false',
            f'Warning  FailedCreate  replicaset-controller  Error creating: pods "{pod}" is forbidden: unable to validate against any security context constraint: [provider "anyuid": Forbidden: not usable by user or serviceaccount]',
            f'Error from server (Forbidden): pods "{pod}" is forbidden: exceeded quota: compute-resources, requested: limits.memory=2Gi, used: limits.memory=7Gi, limited: limits.memory=8Gi',
            f'Error from server (Forbidden): deployments.apps is forbidden: User "system:serviceaccount:{ns}:ci" cannot create resource "deployments" in API group "apps" in the namespace "{ns}"',
            'Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [denied by k8srequiredlabels] you must provide labels: {"owner"}',
        ]
    )


def build_log(r: random.Random) -> str:
    style = r.randrange(5)
    if style == 0:
        return (
            "STEP 1/6: FROM registry.access.redhat.com/ubi9/python-311\nSTEP 2/6: COPY . /app\n"
            "STEP 3/6: RUN pip install -r requirements.txt\nERROR: Could not find a version that satisfies the "
            'requirement acme-sdk==9.9\nerror building image: error building at STEP "RUN pip install": exit status 1'
        )
    if style == 1:
        return (
            '#5 [build 3/7] RUN npm ci\n#5 12.31 npm ERR! code ERESOLVE\n#5 ERROR: process "/bin/sh -c npm ci" '
            "did not complete successfully: exit code: 1"
        )
    if style == 2:
        return (
            "[step-build] + mvn -B package\n[step-build] [ERROR] Failed to execute goal on project api: Could not "
            "resolve dependencies\n[step-build] Error: exit status 1"
        )
    if style == 3:
        return (
            "Run actions/checkout@v4\n##[group]Run make test\n##[error]Process completed with exit code 2.\n"
            "FAIL github.com/acme/api/orders 0.412s"
        )
    return (
        "[Pipeline] stage\n[Pipeline] { (Build)\n[Pipeline] sh\n+ ./gradlew build\nFAILURE: Build failed with an "
        "exception.\n[Pipeline] }\nERROR: script returned exit code 1"
    )


def containerfile(r: random.Random) -> str:
    base = r.choice(["registry.access.redhat.com/ubi9/ubi-minimal:9.4", "node:20-alpine", "python:3.12-slim"])
    return (
        "# syntax=docker/dockerfile:1\n" if r.random() < 0.3 else ""
    ) + f'FROM {base}\nWORKDIR /app\nCOPY . .\nRUN make build\nUSER 1001\nEXPOSE 8080\nENTRYPOINT ["/app/run"]\n'


def sbom(r: random.Random) -> str:
    if r.random() < 0.5:
        return json.dumps(
            {"spdxVersion": "SPDX-2.3", "name": "acme-web", "packages": [{"name": "openssl", "versionInfo": "3.0.7"}]}
        )
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "log4j-core", "version": "2.14.1"}]}
    )


def scanner(r: random.Random) -> str:
    style = r.randrange(3)
    if style == 0:
        return json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "quay.io/acme/web:1.2",
                "Results": [
                    {"Target": "web", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-3094", "Severity": "CRITICAL"}]}
                ],
            }
        )
    if style == 1:
        return json.dumps({"matches": [{"vulnerability": {"id": "CVE-2023-44487"}}], "descriptor": {"name": "grype"}})
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}],
        }
    )


def tcpdump(r: random.Random) -> str:
    lines = []
    for i in range(r.randint(3, 6)):
        lines.append(
            f"10:00:{i:02d}.{r.randint(100000, 999999)} IP 10.128.2.{r.randint(2, 250)}.{r.randint(30000, 60000)} "
            f"> 172.30.0.10.53: {r.randint(1000, 9999)}+ A? db.shop.svc.cluster.local. (45)"
            if r.random() < 0.5
            else f"10:00:{i:02d}.{r.randint(100000, 999999)} IP 10.128.2.5.44312 > 10.131.0.9.8080: Flags [S], seq {r.randint(1, 10**9)}, win 64240, length 0"
        )
    return "\n".join(lines)


def must_gather(r: random.Random) -> str:
    sha = "".join(r.choice("0123456789abcdef") for _ in range(12))
    return (
        f"must-gather.local.{r.randint(10**9, 10**10)}/quay-io-openshift-release-dev-ocp-v4-0-art-dev-sha256-{sha}/\n"
        "  cluster-scoped-resources/config.openshift.io/clusteroperators.yaml\n"
        "  namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log\n"
    )


def question(r: random.Random) -> str:
    return r.choice(
        [
            "why does my pod stay Pending?",
            "how do I expose a service with a Route and TLS?",
            "what does exit code 137 mean",
            "Can a pod in namespace a reach a pod in namespace b?",
            "is OVN-Kubernetes the default on OpenShift 4.20?",
            "x509: certificate signed by unknown authority",
            "ImagePullBackOff when the pull secret sits in a different namespace from the pod",
            "helm upgrade failed: another operation (install/upgrade/rollback) is in progress",
            "Should I set CPU limits on my pods?",
            "my route returns 503 application is not available",
            "does RHACS block privileged containers by default?",
            "How to rotate the default ingress certificate",
        ]
    )


GENERATORS = {
    "alert-payload": None,
    "events": events,
    "pod-status": describe_pod,
    "logs": logs,
    "ticket": ticket,
    "manifests": manifests,
    "helm-chart": helm,
    "policy-denial": denial,
    "build-log": build_log,
    "containerfile": containerfile,
    "sbom": sbom,
    "scanner-report": scanner,
    "packet-capture": tcpdump,
    "must-gather": must_gather,
    "question": question,
}


def alert(r: random.Random) -> str:
    names = ["etcdHighNumberOfLeaderChanges", "KubePodCrashLooping", "KubeNodeNotReady", "ClusterOperatorDegraded"]
    body = {
        "version": "4",
        "status": "firing",
        "receiver": "kube-noob",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": r.choice(names), "severity": "warning", "namespace": r.choice(NS)},
                "annotations": {"summary": "something is wrong"},
                "startsAt": "2026-10-28T10:00:00Z",
            }
        ],
    }
    return json.dumps(body)


GENERATORS["alert-payload"] = alert

# Ceph health output (CEPH1), in the shapes Ceph prints at ceph/ceph eb3b634b: `ceph health detail` text
# (HealthMonitor.cc: "[WRN] CODE: summary", four-space detail lines), `ceph status` (Monitor.cc: summaries under
# "health:"), `ceph health` (summaries joined by "; ") and the JSON of health_check_t (health_check.h).
CEPH_CHECKS = [
    ("WRN", "OSD_DOWN", "{n} osds down", "osd.{i} (root=default,host={host}) is down"),
    ("WRN", "PG_DEGRADED", "Degraded data redundancy: {a}/{b} objects degraded (3.125%), {n} pgs degraded", None),
    ("WRN", "PG_AVAILABILITY", "Reduced data availability: {n} pgs inactive", "pg {pg} is stuck inactive for 3m"),
    ("ERR", "OSD_SCRUB_ERRORS", "{n} scrub errors", None),
    ("ERR", "PG_DAMAGED", "Possible data damage: {n} pg inconsistent", "pg {pg} is active+clean+inconsistent"),
    ("WRN", "MON_CLOCK_SKEW", "clock skew detected on mon.{m}", None),
    ("WRN", "RECENT_CRASH", "{n} daemons have recently crashed", "osd.{i} crashed on host {host}"),
    ("WRN", "MDS_SLOW_REQUEST", "{n} MDSs report slow requests", "mds.fs-a(mds.0): 7 slow requests are blocked"),
    ("WRN", "OSD_NEARFULL", "{n} nearfull osd(s)", "osd.{i} is near full"),
    ("WRN", "POOL_NEARFULL", "{n} pool(s) nearfull", "pool 'ocs-storagecluster-cephblockpool' is nearfull"),
]


def ceph_health(r: random.Random) -> str:
    picked = r.sample(CEPH_CHECKS, r.randint(1, 3))
    host = f"worker-{r.randint(0, 5)}"
    values = {"n": r.randint(1, 40), "a": r.randint(10, 99), "b": r.randint(100, 999), "i": r.randint(0, 11)}
    values |= {"pg": f"{r.randint(1, 12)}.{r.randrange(16**2):x}", "m": r.choice("abc"), "host": host}
    checks = [(sev, code, summary.format(**values), (d or "").format(**values)) for sev, code, summary, d in picked]
    status = "HEALTH_ERR" if any(sev == "ERR" for sev, *_ in checks) else "HEALTH_WARN"
    shape = r.randrange(5)
    if shape == 0:
        lines = [f"{status} " + "; ".join(s for _, _, s, _ in checks)]
        for sev, code, summary, detail in checks:
            lines.append(f"[{sev}] {code}: {summary}")
            lines += [f"    {detail}"] if detail else []
        return "\n".join(lines) + "\n"
    if shape == 1:
        body = "\n".join(f"            {s}" for _, _, s, _ in checks)
        return (
            f"  cluster:\n    id:     477e46f1-ae41-4e43-9c8f-{r.randrange(16**12):012x}\n    health: {status}\n{body}\n\n"
            "  services:\n    mon: 3 daemons, quorum a,b,c (age 3h)\n    osd: 12 osds: 11 up (since 2m), 12 in\n"
        )
    if shape == 2:
        return f"{status} " + "; ".join(s for _, _, s, _ in checks)
    report = {
        code: {"severity": f"HEALTH_{'WARN' if sev == 'WRN' else 'ERR'}", "summary": {"message": s, "count": 1}}
        for sev, code, s, _ in checks
    }
    doc = {"status": status, "checks": report, "mutes": []}
    return json.dumps(doc if shape == 3 else {"fsid": "477e46f1", "health": doc, "election_epoch": 8})


# Kinds added after the original 15 are generated after the mixed pastes, so the earlier cases stay the same.
LATER_GENERATORS = {"ceph-health": ceph_health}


def cases(per_kind: int = 22, seed: int = 28) -> list[tuple[str, set[str]]]:
    r = random.Random(seed)
    out: list[tuple[str, set[str]]] = []
    for kind, gen in GENERATORS.items():
        for i in range(per_kind):
            if kind == "events" and i % 4 == 3:
                out.append((event_json(r), {"events"}))
                continue
            if kind == "pod-status" and i % 3 == 2:
                out.append((pod_yaml(r), {"pod-status", "manifests"}))
                continue
            text = gen(r)  # type: ignore[misc]
            expect = {kind}
            if kind == "pod-status":
                expect.add("events")  # describe output carries its Events section
            if kind == "policy-denial" and "FailedCreate" in text:
                expect.add("events")
            out.append((text, expect))
    for _ in range(30):  # mixed pastes: events and a denial, logs and a ticket, a manifest and events
        a, b = r.sample(["events", "logs", "policy-denial", "ticket-text"], 2)
        parts, expect = [], set()
        for k in (a, b):
            if k == "ticket-text":
                parts.append(f"OCPBUGS-{r.randint(1000, 9000)}: pods crash\nStatus: New")
                expect.add("ticket")
            else:
                gen = GENERATORS[k]
                parts.append(gen(r))  # type: ignore[misc]
                expect.add(k)
                if k == "policy-denial" and "FailedCreate" in parts[-1]:
                    expect.add("events")
        out.append(("\n\n".join(parts), expect))
    for kind, later in LATER_GENERATORS.items():
        out += [(later(r), {kind}) for _ in range(per_kind)]
    return out

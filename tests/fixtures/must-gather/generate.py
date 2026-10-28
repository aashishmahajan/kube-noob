"""A small synthetic must-gather in the layout ``oc adm must-gather`` and ``oc adm inspect`` write (see
``kube_noob.mustgather.ingest`` for the source), for the safe-ingest tests and the analysers built on it.

``python tests/fixtures/must-gather/generate.py <dir>`` writes ``<dir>/must-gather.local.<...>/`` and
``<dir>/must-gather.tar.gz`` (the same tree, as ``tar cvaf`` makes it). Secrets in it hold the marker
``KN-PLANTED-SECRET``, which must never appear in anything kube-noob keeps or prints.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

TOP = "must-gather.local.5d3c2b1a.20261028T100000Z.482910"
IMAGE = "quay-io-openshift-release-dev-ocp-v4-0-art-dev-sha256-" + "1f" * 32
MARKER = "KN-PLANTED-SECRET"


def _yaml_list(items: list[str]) -> str:
    return "apiVersion: v1\nitems:\n" + "".join(items) + 'kind: List\nmetadata:\n  resourceVersion: ""\n'


def _crashing_pod(name: str, restarts: int) -> str:
    return (
        f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\n  namespace: shop\n  ownerReferences:\n"
        "  - apiVersion: apps/v1\n    kind: ReplicaSet\n    name: web-6b8f9\nstatus:\n  phase: Running\n"
        f"  containerStatuses:\n  - name: web\n    restartCount: {restarts}\n    state:\n      waiting:\n"
        "        reason: CrashLoopBackOff\n        message: back-off 5m0s restarting failed container\n"
        "    lastState:\n      terminated:\n        reason: Error\n        exitCode: 1\n"
    )


FILES: dict[str, str] = {
    "timestamp": "2026-10-28 10:00:00.123456789 +0000 UTC m=+0.04\n2026-10-28 10:04:12.5 +0000 UTC m=+252.5\n",
    "must-gather.logs": (
        "[must-gather      ] OUT Using must-gather plug-in image: quay.io/openshift-release-dev/ocp-v4.0\n"
    ),
    f"{IMAGE}/version": "openshift/must-gather\n4.20.3\n",
    f"{IMAGE}/timestamp": "2026-10-28 10:00:05.1 +0000 UTC m=+0.03\n",
    f"{IMAGE}/gather.logs": "+ oc adm inspect ns/openshift-cluster-version\n",
    f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml": (
        "apiVersion: config.openshift.io/v1\nkind: ClusterVersion\nmetadata:\n  name: version\nspec:\n"
        "  channel: stable-4.20\nstatus:\n  desired:\n    version: 4.20.4\n  history:\n  - state: Partial\n"
        "    version: 4.20.4\n    startedTime: '2026-10-28T08:00:00Z'\n  - state: Completed\n    version: 4.20.3\n"
        "  conditions:\n"
        '  - type: Failing\n    status: "True"\n    reason: ClusterOperatorDegraded\n'
        "    message: Cluster operator authentication is degraded\n"
        '  - type: Progressing\n    status: "True"\n'
        '    message: "Working towards 4.20.4: 690 of 873 done (79% complete)"\n'
        '  - type: Upgradeable\n    status: "False"\n    reason: AdminAckRequired\n'
        "    message: Kubernetes 1.34 removes several APIs that require an administrator acknowledgment\n"
    ),
    f"{IMAGE}/cluster-scoped-resources/config.openshift.io/infrastructures/cluster.yaml": (
        "apiVersion: config.openshift.io/v1\nkind: Infrastructure\nmetadata:\n  name: cluster\nstatus:\n"
        "  controlPlaneTopology: HighlyAvailable\n  platformStatus:\n    type: AWS\n"
    ),
    f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusteroperators/image-registry.yaml": (
        "apiVersion: config.openshift.io/v1\nkind: ClusterOperator\nmetadata:\n  name: image-registry\nstatus:\n"
        '  conditions:\n  - type: Available\n    status: "False"\n    reason: NoReplicasAvailable\n'
        "    message: The deployment does not have available replicas\n"
        "  versions:\n  - name: operator\n    version: 4.20.3\n"
    ),
    f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusteroperators/authentication.yaml": (
        "apiVersion: config.openshift.io/v1\nkind: ClusterOperator\nmetadata:\n  name: authentication\nstatus:\n"
        '  conditions:\n  - type: Degraded\n    status: "True"\n'
        "    reason: OAuthServerRouteEndpointAccessibleController_SyncError\n"
        '  - type: Available\n    status: "True"\n'
    ),
    f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusteroperators/etcd.yaml": (
        "apiVersion: config.openshift.io/v1\nkind: ClusterOperator\nmetadata:\n  name: etcd\nstatus:\n"
        '  conditions:\n  - type: Degraded\n    status: "False"\n  - type: Available\n    status: "True"\n'
    ),
    f"{IMAGE}/cluster-scoped-resources/core/nodes/master-0.yaml": (
        "apiVersion: v1\nkind: Node\nmetadata:\n  name: master-0\n  labels:\n"
        '    node-role.kubernetes.io/control-plane: ""\n    node-role.kubernetes.io/master: ""\nstatus:\n'
        "  conditions:\n  - type: Ready\n"
        '    status: "True"\n  - type: DiskPressure\n    status: "False"\n'
    ),
    f"{IMAGE}/cluster-scoped-resources/core/nodes/worker-1.yaml": (
        "apiVersion: v1\nkind: Node\nmetadata:\n  name: worker-1\n  labels:\n"
        '    node-role.kubernetes.io/worker: ""\nspec:\n  unschedulable: true\nstatus:\n  conditions:\n'
        '  - type: Ready\n    status: "False"\n    reason: KubeletNotReady\n'
        "    message: container runtime network not ready\n"
        '  - type: MemoryPressure\n    status: "True"\n    reason: KubeletHasInsufficientMemory\n'
    ),
    f"{IMAGE}/cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml": (
        "apiVersion: machineconfiguration.openshift.io/v1\nkind: MachineConfigPool\nmetadata:\n  name: worker\n"
        'status:\n  conditions:\n  - type: Degraded\n    status: "True"\n    message: \'Node worker-1 is reporting: '
        '"unexpected on-disk state"\'\n  - type: NodeDegraded\n    status: "True"\n    reason: 1 nodes are reporting '
        'degraded status on sync\n  - type: Updating\n    status: "True"\n'
        "  machineCount: 3\n  updatedMachineCount: 2\n  readyMachineCount: 2\n  unavailableMachineCount: 1\n"
        "  degradedMachineCount: 1\n"
    ),
    f"{IMAGE}/namespaces/openshift-etcd/openshift-etcd.yaml": (
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: openshift-etcd\n"
    ),
    f"{IMAGE}/namespaces/openshift-etcd/core/events.yaml": _yaml_list(
        [
            "- apiVersion: v1\n  kind: Event\n  metadata:\n    name: etcd-master-0.1\n    namespace: openshift-etcd\n"
            "  reason: Unhealthy\n  type: Warning\n  message: 'Readiness probe failed'\n"
        ]
    ),
    f"{IMAGE}/namespaces/openshift-etcd/core/secrets.yaml": _yaml_list(
        [f"- apiVersion: v1\n  kind: Secret\n  metadata:\n    name: etcd-client\n  data:\n    tls.key: {MARKER}\n"]
    ),
    f"{IMAGE}/namespaces/openshift-etcd/pods/etcd-master-0/etcd-master-0.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: etcd-master-0\n  namespace: openshift-etcd\nstatus:\n"
        "  phase: Running\n"
    ),
    f"{IMAGE}/namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log": (
        '2026-10-28T09:58:01.1Z {"level":"warn","msg":"apply request took too long","took":"312ms"}\n'
        '2026-10-28T09:58:09.4Z {"level":"warn","msg":"slow fdatasync","took":"1.2s"}\n'
        '2026-10-28T09:58:10.0Z {"level":"info","msg":"raft.node: 8e9e05c52164694d elected leader 91bc3c398fb3c146'
        ' at term 5"}\n'
        '2026-10-28T09:58:20.0Z {"level":"info","msg":"raft.node: 8e9e05c52164694d lost leader 91bc3c398fb3c146'
        ' at term 5"}\n'
        '2026-10-28T09:58:21.0Z {"level":"info","msg":"raft.node: 8e9e05c52164694d changed leader from'
        ' 91bc3c398fb3c146 to fd422379fda50e48 at term 6"}\n'
        '2026-10-28T09:58:22.0Z {"level":"warn","msg":"leader failed to send out heartbeat on time; took too long,'
        ' leader is overloaded likely from slow disk"}\n'
    ),
    f"{IMAGE}/namespaces/shop/shop.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shop\n",
    f"{IMAGE}/namespaces/shop/core/secrets/db-creds.yaml": (
        f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-creds\ndata:\n  password: {MARKER}\n"
    ),
    f"{IMAGE}/namespaces/shop/pods/web-7d9f/web-7d9f.yaml": _crashing_pod("web-7d9f", 14),
    f"{IMAGE}/namespaces/shop/pods/web-k2x8p/web-k2x8p.yaml": _crashing_pod("web-k2x8p", 9),
    f"{IMAGE}/namespaces/shop/pods/cart-0/cart-0.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: cart-0\n  namespace: shop\nstatus:\n  phase: Pending\n"
        '  conditions:\n  - type: PodScheduled\n    status: "False"\n    reason: Unschedulable\n'
        "    message: '0/3 nodes are available: 3 Insufficient memory.'\n"
    ),
    f"{IMAGE}/namespaces/shop/pods/api-5c6d/api-5c6d.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: api-5c6d\n  namespace: shop\nstatus:\n  phase: Pending\n"
        "  containerStatuses:\n  - name: api\n    restartCount: 0\n    state:\n      waiting:\n"
        "        reason: ImagePullBackOff\n        message: Back-off pulling image quay.io/shop/api:v9\n"
    ),
    f"{IMAGE}/namespaces/openshift-monitoring/pods/prometheus-k8s-0/prometheus-k8s-0.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: prometheus-k8s-0\n  namespace: openshift-monitoring\n"
        "status:\n  phase: Running\n  containerStatuses:\n  - name: prometheus\n    restartCount: 3\n"
        "    state:\n      running: {}\n    lastState:\n      terminated:\n        reason: OOMKilled\n"
        "        exitCode: 137\n"
    ),
    f"{IMAGE}/namespaces/shop/core/events.yaml": _yaml_list(
        [
            "- apiVersion: v1\n  kind: Event\n  metadata:\n    name: web-7d9f.1\n    namespace: shop\n"
            "  involvedObject:\n    kind: Pod\n    name: web-7d9f\n  reason: BackOff\n  type: Warning\n"
            "  count: 37\n  lastTimestamp: '2026-10-28T09:59:00Z'\n"
            "  message: Back-off restarting failed container web in pod web-7d9f_shop\n",
            "- apiVersion: v1\n  kind: Event\n  metadata:\n    name: cart-0.1\n    namespace: shop\n"
            "  involvedObject:\n    kind: Pod\n    name: cart-0\n  reason: FailedScheduling\n  type: Warning\n"
            "  series:\n    count: 12\n  message: '0/3 nodes are available: 3 Insufficient memory.'\n",
            "- apiVersion: v1\n  kind: Event\n  metadata:\n    name: api-5c6d.1\n    namespace: shop\n"
            "  involvedObject:\n    kind: Pod\n    name: api-5c6d\n  reason: Pulled\n  type: Normal\n"
            "  message: Successfully pulled image\n",
            "- apiVersion: v1\n  kind: Event\n  metadata:\n    name: shop-db.1\n    namespace: shop\n"
            "  involvedObject:\n    kind: Deployment\n    name: shop-db\n  reason: QuotaNearlyExhausted\n"
            "  type: Warning\n  message: quota nearly used\n",
        ]
    ),
    f"{IMAGE}/namespaces/shop/pods/web-7d9f/web/web/logs/previous.log": (
        "Starting web\nError: connect ECONNREFUSED 10.0.0.5:5432\n"
    ),
    f"{IMAGE}/namespaces/openshift-operator-lifecycle-manager/operators.coreos.com/clusterserviceversions.yaml": (
        _yaml_list(
            [
                "- apiVersion: operators.coreos.com/v1alpha1\n  kind: ClusterServiceVersion\n  metadata:\n"
                "    name: rhacs-operator.v4.6.0\n    namespace: rhacs-operator\n  status:\n    phase: Failed\n"
                "    reason: InstallCheckFailed\n    message: install timeout\n"
            ]
        )
    ),
    f"{IMAGE}/namespaces/shop/operators.coreos.com/clusterserviceversions/rhacs-operator.v4.6.0.yaml": (
        "apiVersion: operators.coreos.com/v1alpha1\nkind: ClusterServiceVersion\nmetadata:\n"
        "  name: rhacs-operator.v4.6.0\n  namespace: shop\nstatus:\n  phase: Failed\n  reason: Copied\n"
    ),
    f"{IMAGE}/host_service_logs/masters/kubelet_service.log": "Oct 28 09:59:00 master-0 kubelet[2001]: E1028 ...\n",
}
NESTED = {f"{IMAGE}/audit_logs/kube-apiserver/master-0-audit-2026-10-28T09-00-00.000.log.gz": b"\x1f\x8b\x08\x00"}


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    root = out / TOP
    for rel, text in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    for rel, data in NESTED.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    with tarfile.open(out / "must-gather.tar.gz", "w:gz") as tf:
        for rel in sorted([*FILES, *NESTED]):
            data = FILES[rel].encode() if rel in FILES else NESTED[rel]
            info = tarfile.TarInfo(f"{TOP}/{rel}")
            info.size = len(data)
            info.mtime = 1_793_181_600
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    main(Path(sys.argv[1]))

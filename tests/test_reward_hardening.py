"""Regression tests for reward-hacking attempts found in the red-team review (all must score low) and the matching
correct answers (must score high)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.evals.checks import GATE_CAP, evaluate, get_values
from kube_noob.evals.reward import grade_by_id
from kube_noob.knowledge.store import get_store
from kube_noob.sources.corpus import write_shard

EGRESS_GOOD = """```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata: {name: default, namespace: etl}
spec:
  egress:
  - type: Allow
    to: {dnsName: s3.amazonaws.com}
  - type: Allow
    to: {cidrSelector: 172.16.0.0/12}
  - type: Deny
    to: {cidrSelector: 0.0.0.0/0}
```
Rules are evaluated in order, so the Deny-all must be last [kn:ocp-egressfirewall#0]."""

EGRESS_ALLOW_ALL = """```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata: {name: default, namespace: etl}
spec:
  egress:
  - type: Allow
    to: {cidrSelector: 0.0.0.0/0}
```"""

RBAC = """```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {{name: auditor, namespace: sec}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {{name: auditor}}
rules:
- apiGroups: [""]
  resources: [pods, events]
  verbs: {verbs}
- apiGroups: [apps]
  resources: {apps_resources}
  verbs: {verbs}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {{name: auditor}}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: auditor}}
subjects: [{{kind: ServiceAccount, name: auditor, namespace: sec}}]
```"""

RWX_GOOD = (
    "gp3-csi is the default ROSA StorageClass and it is AWS EBS block storage, which only supports ReadWriteOnce "
    "(RWO), so a ReadWriteMany claim can never be provisioned and stays Pending [kn:storage-access-modes#0]. "
    "Install the AWS EFS CSI driver operator, create an efs-sc StorageClass with provisioner efs.csi.aws.com "
    "and recreate the PVC with storageClassName efs-sc [kn:rosa-efs#0]."
)


def test_path_fanout_and_negative_index() -> None:
    obj = {"spec": {"egress": [{"type": "Allow"}, {"type": "Deny"}]}, "rules": [{"verbs": ["get"]}, {"verbs": ["x"]}]}
    assert get_values(obj, "spec.egress[-1].type") == ["Deny"]
    assert get_values(obj, "rules[*].verbs") == [["get"], ["x"]]
    assert get_values(obj, "spec.egress[7]") == [] and get_values(obj, "spec.egress[-3]") == []


def test_egress_allow_all_is_capped_and_correct_answer_scores_full() -> None:
    assert grade_by_id("bench-egress", EGRESS_GOOD).task == 1.0
    bad = grade_by_id("bench-egress", EGRESS_ALLOW_ALL)
    assert bad.task <= GATE_CAP and bad.reward < 0.5


def test_readonly_rbac_requires_read_verbs_only() -> None:
    good = RBAC.format(verbs="[get, list, watch]", apps_resources="[deployments]")
    assert grade_by_id("bench-rbac-readonly", good).task == 1.0
    writer = RBAC.format(verbs="[get, list, watch, delete]", apps_resources="[deployments]")
    assert grade_by_id("bench-rbac-readonly", writer).task <= GATE_CAP
    broader = RBAC.format(verbs="[get, list, watch]", apps_resources="[deployments, replicasets]")
    assert grade_by_id("bench-rbac-readonly", broader).task <= GATE_CAP


@pytest.mark.parametrize(
    ("task_id", "answer"),
    [
        ("bench-qa-rwx-gp3", "EBS RWO EFS efs-sc [kn:kubernetes#0]"),
        ("bench-qa-rwx-gp3", "Not EBS. Not RWO. Not EFS. Never use efs-sc. [kn:helm#0]"),
        ("bench-qa-rhacs-next", "Yes, there is a 4.12. 5.0 is not planned; 4.12 ships next. [kn:stackrox#0]"),
        (
            "bench-qa-rwx-gp3",
            "EBS volumes work fine here because gp3-csi supports ReadWriteMany; EFS and efs-sc are only needed for "
            "Windows nodes, so keep the claim as RWO-compatible and retry later [kn:storage-access-modes#0].",
        ),
    ],
)
def test_qa_gaming_attempts_score_low(task_id: str, answer: str) -> None:
    g = grade_by_id(task_id, answer)
    assert g.task <= 0.25 and g.reward <= 0.3, g.as_dict()


def test_qa_correct_answers_score_high() -> None:
    g = grade_by_id("bench-qa-rwx-gp3", RWX_GOOD)
    assert g.task == 1.0 and g.credit == 1.0 and g.reward == pytest.approx(1.0)
    rhacs = (
        "After RHACS 4.11 the next minor release is 5.0. There is no 4.12: the planned 4.12 line was renamed to 5.0, "
        "so plan the upgrade from 4.11 straight to 5.0 [kn:stackrox#0]."
    )
    assert grade_by_id("bench-qa-rhacs-next", rhacs).task == 1.0


def test_irrelevant_valid_citation_earns_no_credit() -> None:
    off_topic = RWX_GOOD.replace("[kn:storage-access-modes#0]", "[kn:helm#0]").replace("[kn:rosa-efs#0]", "[kn:helm#0]")
    g = grade_by_id("bench-qa-rwx-gp3", off_topic)
    assert g.task == 1.0 and g.credit == 0.0 and not g.penalties
    assert g.details["attribution"]["irrelevant"] == ["kn:helm#0"]


def test_unknown_rwx_storage_class_is_flagged() -> None:
    pvc = (
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: w, namespace: g}\n"
        "spec: {accessModes: [ReadWriteMany], storageClassName: totally-made-up,\n"
        "  resources: {requests: {storage: 1Gi}}}\n"
    )
    ev = evaluate(pvc, {"platform": "rosa-hcp", "forbidRules": ["KN-ST001"]})
    assert not ev.passed and ev.score <= GATE_CAP
    static = pvc.replace("totally-made-up", '""')
    assert evaluate(static, {"platform": "rosa-hcp", "forbidRules": ["KN-ST001"]}).passed


def test_grader_credits_corpus_citations_via_toolkit(tmp_path: Path) -> None:
    write_shard(
        tmp_path,
        "jira-rox",
        [
            {
                "id": "jira-ROX-1",
                "title": "ROX-1: scanner crash",
                "text": "## Problem\n\nThe scanner pod crashes with an out-of-memory error after upgrading to 4.10. "
                * 5,
                "sourceId": "jira:ROX",
                "license": "proprietary-public",
                "redistributable": False,
            }
        ],
    )
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    cid = next(h["chunkId"] for h in kit.search(tk.SearchIn(query="scanner crash out-of-memory"))["results"])
    answer = f"The scanner pod crashes with an out-of-memory error after the 4.10 upgrade [{cid}]."
    g = kit.grade(
        tk.GradeIn(completion=answer, task={"id": "t", "type": "qa", "requireCitations": True, "minWords": 1})
    )
    assert g["components"]["credit"] == 1.0 and not g["penalties"]
    # one cache slot per corpus state: grading must not evict the toolkit's store
    assert get_store(tmp_path) is kit.store()


def test_citation_to_the_right_doc_but_wrong_chunk_earns_no_credit() -> None:
    from kube_noob.evals.reward import benchmark, grade

    task = benchmark()["bench-qa-hcp-machineconfig"]
    answer = (
        "On ROSA with HCP the Machine Config Operator does not run in the hosted cluster, so MachineConfig objects are "
        "not a supported lever {c}. Tune the kubelet with `rosa create kubeletconfig` and change nodes through "
        "machine pools {c}."
    )
    right = grade(task, answer.format(c="[kn:rosa-hcp#2]"))
    wrong = grade(task, answer.format(c="[kn:rosa-hcp#3]"))
    assert right.credit == 1.0 and wrong.credit == 0.0
    assert right.reward > wrong.reward

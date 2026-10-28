"""QA6: gaps the golden set found (tests/fixtures/golden, `gap` on each miss), closed with content checked against the
official page the grader named. Each test uses text written for this file, not the golden question, so the golden
items stay a separate check (scripts/eval_golden.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import diagnose


@pytest.fixture(scope="module")
def kit(tmp_path_factory: pytest.TempPathFactory) -> tk.Toolkit:
    return tk.Toolkit(
        load_settings(overrides={"dataDir": str(tmp_path_factory.mktemp("qa6")), "learningEnabled": False})
    )


def _top(kit: tk.Toolkit, text: str, platform: str | None = None) -> list[str]:
    out = kit.insight(tk.InsightIn(text=text, platform=platform))
    return [str(f["id"]) for f in out["findings"] if f["source"] in ("playbook", "doc", "reported-issue", "policy")]


def _diag(text: str, platform: str | None = None) -> dict[str, object]:
    return diagnose(text, platform=platform).as_dict()["diagnoses"][0]  # type: ignore[no-any-return]


def _changes(d: dict[str, object]) -> str:
    return " ".join(str(c["change"]) for c in d["proposedChanges"])  # type: ignore[attr-defined,index]


def _causes(d: dict[str, object]) -> str:
    return " ".join(d["rootCauses"])  # type: ignore[arg-type]


# Kubernetes: kubernetes/website ed70e31 (troubleshoot-kubectl, deployment, persistent-volumes, debug-running-pod,
# pod-lifecycle, troubleshooting-kubeadm, dns-debugging-resolution).


def test_an_unreachable_api_server_is_not_called_a_network_policy() -> None:
    for text in (
        "Unable to connect to the server: dial tcp 172.31.4.9:6443: i/o timeout",
        "Unable to connect to the server: dial tcp 10.1.1.1:443: connect: no route to host",
        "The connection to the server api.lab.example:6443 was refused - did you specify the right host or port?",
    ):
        d = _diag(text, platform="kubernetes")
        assert d["id"] == "DBG-APISERVER-UNREACHABLE", text
        assert "VPN" in _causes(d) and "use-context" in _changes(d)
    assert _diag("dial tcp 10.0.0.7:5432: i/o timeout from my app pod")["id"] == "DBG-NETPOL"


def test_a_stalled_rollout_names_the_progress_deadline() -> None:
    d = _diag('error: deployment "api" exceeded its progress deadline', platform="kubernetes")
    assert d["id"] == "DBG-PROGRESS-DEADLINE"
    assert "rollout undo" in _changes(d) and "readiness" in _causes(d).lower()
    assert _diag("Progressing False ProgressDeadlineExceeded")["id"] == "DBG-PROGRESS-DEADLINE"


def test_a_pvc_stuck_terminating_names_the_protection_finalizer() -> None:
    for text in (
        "kubectl delete pvc data-0 hangs and the PVC stays Terminating, Finalizers: [kubernetes.io/pvc-protection]",
        "my persistentvolumeclaim is stuck in Terminating for an hour",
    ):
        d = _diag(text, platform="kubernetes")
        assert d["id"] == "DBG-PVC-TERMINATING", text
        assert "still uses" in _causes(d)
    assert _diag("pod web-1 is stuck in Terminating for 2h")["id"] == "DBG-POD-TERMINATING"


def test_exec_into_an_image_without_a_shell_points_at_kubectl_debug() -> None:
    d = _diag(
        'OCI runtime exec failed: exec failed: unable to start container process: exec: "sh": executable '
        "file not found in $PATH: unknown"
    )
    assert d["id"] == "DBG-ENTRYPOINT-NOT-FOUND"
    assert "kubectl debug -it" in _changes(d) and "--target" in _changes(d)


def test_crashloop_and_dns_playbooks_carry_the_documented_steps() -> None:
    crash = _diag("Back-off restarting failed container web in pod web-7")
    assert "300" in _causes(crash) or "300" in str(crash["readOnlyNextSteps"])
    dns = _diag("nslookup: can't resolve 'kubernetes.default'", platform="kubernetes")
    assert dns["id"] == "DBG-DNS" and "k8s-app=kube-dns" in str(dns["readOnlyNextSteps"])
    assert "system:coredns" in _causes(dns)
    from kube_noob.debug.playbooks import PLAYBOOKS

    checks = " ".join(next(p for p in PLAYBOOKS if p.pid == "DBG-DNS").checks)
    assert "/etc/resolv.conf" in checks  # needs a pod name, so it is listed once one is known


def test_a_kubeconfig_from_before_kubeadm_reset_is_explained() -> None:
    d = _diag(
        "Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "
        '"crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")'
    )
    assert d["id"] == "DBG-X509-CLIENT"
    assert "kubeadm reset" in _causes(d) and "/etc/kubernetes/admin.conf" in _changes(d)


def test_kubeadm_and_rollout_documents_answer_their_questions(kit: tk.Toolkit) -> None:
    assert _top(kit, "after kubeadm init the coredns pods stay Pending, why?")[0].startswith(
        "kn:k8s-kubeadm-troubleshooting#"
    )
    assert _top(kit, "kubeadm init says flag: malformed pair, expect string=string")[0].startswith(
        "kn:k8s-kubeadm-troubleshooting#"
    )
    assert _top(kit, "how do I roll my deployment back to revision 3 and see the rollout history?")[0].startswith(
        "kn:k8s-deployment-rollouts#"
    )
    assert not [d for d in _top(kit, "how do I scale my deployment to 5 replicas?") if "rollouts" in d]


# Helm 3: helm/helm-www e5a4c62, versioned_docs/version-3.


def test_helm_errors_with_their_own_playbooks() -> None:
    d = _diag("Error: repository name (bitnami) already exists, please specify a different name")
    assert d["id"] == "DBG-HELM-REPO-EXISTS" and "--force-update" in _changes(d)
    d = _diag(
        "Error: UPGRADE FAILED: current release manifest contains removed kubernetes api(s) for this kubernetes "
        "version and it is therefore unable to build the kubernetes objects for performing the diff. error from "
        'kubernetes: unable to recognize "": no matches for kind "Ingress" in version "extensions/v1beta1"'
    )
    assert d["id"] == "DBG-HELM-REMOVED-API" and "mapkubeapis" in _changes(d)
    d = _diag(
        "Error: INSTALLATION FAILED: YAML parse error on web/templates/deployment.yaml: error converting YAML to "
        "JSON: yaml: line 14: did not find expected key"
    )
    assert d["id"] == "DBG-HELM-YAML" and "{{-" in _causes(d) + _changes(d)
    own = _diag(
        "Error: rendered manifests contain a resource that already exists. Unable to continue with install: "
        'Service "web" in namespace "shop" exists and cannot be imported into the current release'
    )
    assert own["id"] == "DBG-HELM-OWNERSHIP" and "--take-ownership" in _changes(own)


@pytest.mark.parametrize(
    ("text", "doc"),
    [
        ('helm --set with a dot in the key: nodeSelector "kubernetes.io/os" ends up nested', "helm-cli-operations"),
        ("how do I push my helm chart to an OCI registry like Harbor?", "helm-cli-operations"),
        ("helm rollback fails: Error: no Secret with the name found after a failed upgrade", "helm-cli-operations"),
        ("Helm on a read-only home directory: where does helm keep its cache and config?", "helm-cli-operations"),
        ("does helm upgrade my CRDs in the chart crds/ directory?", "helm-chart-authoring"),
        ("helm pre-install hook job failed and the release failed; hook-delete-policy?", "helm-chart-authoring"),
        ("Error: library charts are not installable: helm install of my common chart", "helm-chart-authoring"),
        ("a # comment in my helm template still runs required and fails the render", "helm-chart-authoring"),
    ],
)
def test_helm_usage_documents(kit: tk.Toolkit, text: str, doc: str) -> None:
    got = _top(kit, text)
    # A failed hook Job also names the Job playbook (BackoffLimitExceeded), which may rank first.
    window = got[:2] if "hook" in text else got[:1]
    assert any(g.startswith(f"kn:{doc}#") for g in window), got


def test_other_products_that_share_helm_words_are_left_alone(kit: tk.Toolkit) -> None:
    for text in (
        "Flux HelmRelease shows install retries exhausted in helm-controller; which spec fields to change?",
        "My Chart.js line chart in Vue does not update when the values array changes",
        "helmfile sync uses the wrong environment values file",
        "AWS Lambda in the ROSA account times out after 3 seconds; how do I raise the timeout?",
    ):
        assert _top(kit, text) == [], text


def test_qa6_documents_are_well_formed() -> None:
    from kube_noob.knowledge.store import builtin_chunks

    docs = {c.doc_id: c for c in builtin_chunks()}
    names = ("k8s-kubeadm-troubleshooting", "k8s-deployment-rollouts", "helm-cli-operations", "helm-chart-authoring")
    for name in names:
        assert name in docs and docs[name].extra.get("requires"), name
    root = Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "data" / "knowledge"
    for name in ("helm-cli-operations", "helm-chart-authoring"):
        assert "https://helm.sh/docs/v3/" in (root / f"{name}.md").read_text()


def test_new_documents_do_not_make_more_words_rare_for_the_bug_matcher() -> None:
    # The reported-issue matcher and the ticket correlation count a word as rare only if it appears in at most
    # GENERAL_MAX_CHUNKS sections of the bundled docs. A share of sections would drift as documents are added: words
    # in three sections became "rare" when QA6 added four documents, and four community rows that pointed at the
    # right bug started naming an unrelated one.
    from kube_noob import known_issues as ki
    from kube_noob import tickets
    from kube_noob.knowledge.store import Chunk, KnowledgeStore

    def chunk(n: int, text: str) -> Chunk:
        return Chunk(
            chunk_id=f"d{n}#0",
            doc_id=f"d{n}",
            title="t",
            heading="",
            text=text,
            url="",
            license="Apache-2.0",
            origin="test",
            source_id="test",
        )

    small = KnowledgeStore([chunk(i, "zebra quagga" if i < 3 else "filler") for i in range(10)])
    big = KnowledgeStore([chunk(i, "zebra quagga" if i < 3 else "filler") for i in range(500)])
    assert small.doc_count("zebra") == big.doc_count("zebra") == 3
    assert ki.GENERAL_MAX_CHUNKS == tickets.GENERAL_MAX_CHUNKS == 2
    assert not hasattr(ki, "GENERAL_SHARE") and not hasattr(tickets, "GENERAL_SHARE")


def test_helm_repo_list_is_a_read_and_repo_add_a_change() -> None:
    from kube_noob.debug.steps import classify_step

    assert classify_step("helm repo list") == "read"
    assert classify_step("helm repo add bitnami https://charts.bitnami.com/bitnami --force-update") == "change"
    assert classify_step("helm repo update") == "change"

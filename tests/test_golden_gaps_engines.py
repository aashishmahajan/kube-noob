"""QA6: golden gaps for the admission policy engines, OpenShift, ROSA HCP and RHACS, closed with content checked
against the official page each grader named (kubernetes/website ed70e31, kyverno/website b013152, gatekeeper
e492e24, openshift-docs 1649577 and rhacs-docs-main 801ccd0, stackrox 69fc953). The questions here were written for
these tests, not taken from the golden set, so the golden items stay a separate check."""

from __future__ import annotations

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import diagnose

ANSWERS = ("playbook", "doc", "reported-issue", "policy")


@pytest.fixture(scope="module")
def kit(tmp_path_factory: pytest.TempPathFactory) -> tk.Toolkit:
    return tk.Toolkit(
        load_settings(overrides={"dataDir": str(tmp_path_factory.mktemp("qa6e")), "learningEnabled": False})
    )


def _top(kit: tk.Toolkit, text: str, platform: str | None = None) -> list[str]:
    out = kit.insight(tk.InsightIn(text=text, platform=platform))
    return [str(f["id"]) for f in out["findings"] if f["source"] in ANSWERS]


def _hit(got: list[str], want: str, window: int = 1) -> bool:
    return any(g == want or g.startswith(f"kn:{want}#") for g in got[:window])


# Admission policy engines.

POLICY_DOCS = [
    (
        "We plan to enforce baseline on every namespace. Can I see which running pods would break without changing any "
        "namespace labels yet?",
        "k8s-pss",
    ),
    (
        "kubectl apply on my Deployment printed a PodSecurity restricted warning and said it was created, but it never "
        "gets any pods. Why?",
        "k8s-pss",
    ),
    (
        "How can my ValidatingAdmissionPolicy only warn users and record failures for a few weeks before it starts "
        "rejecting requests?",
        "k8s-validating-admission-policy",
    ),
    (
        "kubectl get validatingadmissionpolicy shows status.typeChecking expressionWarnings undefined field "
        "'replicas'. Is the policy still enforced?",
        "k8s-validating-admission-policy",
    ),
    (
        "Our Kyverno ValidatingPolicy rejects one legacy Deployment we cannot fix this quarter. How do I let only that "
        "Deployment through? My PolicyException seems ignored.",
        "kyverno-troubleshooting",
    ),
    (
        "How do we run our Kyverno policies against each pull request's manifests in GitHub Actions?",
        "kyverno-troubleshooting",
    ),
    (
        "How do I make the Gatekeeper admission webhook skip kube-system so the API server never calls it for that "
        "namespace?",
        "gatekeeper-enforcement",
    ),
    (
        "Gatekeeper was down for an hour and pods that break our constraints were created anyway. What happens if we "
        "make the Gatekeeper webhook fail closed?",
        "gatekeeper-enforcement",
    ),
    (
        "On OpenShift the nonroot-v2 SCC admits my pod but the namespace Pod Security level still rejects it. Why is "
        "the SCC not enough?",
        "ocp-scc",
    ),
    (
        "How can I make an OpenShift Deployment always run under my own SCC instead of a higher-priority one?",
        "ocp-scc",
    ),
]


@pytest.mark.parametrize(("text", "doc"), POLICY_DOCS)
def test_policy_engine_documents(kit: tk.Toolkit, text: str, doc: str) -> None:
    got = _top(kit, text)
    assert _hit(got, doc, 2), got


def test_a_vap_denial_has_its_own_playbook_and_owner_guidance() -> None:
    text = (
        "deployments.apps \"checkout\" is forbidden: ValidatingAdmissionPolicy 'replica-cap.example' with binding "
        "'replica-cap-staging' denied request: failed expression: object.spec.replicas <= 4"
    )
    out = diagnose(text).as_dict()
    assert out["diagnoses"][0]["id"] == "DBG-VAP"
    from kube_noob.debug.policy import explain

    den = explain(text)["denials"][0]
    owner = " ".join(c["change"] for c in den["proposedChanges"] if c.get("needsPolicyOwner"))
    assert "messageExpression" in owner and "[Warn, Audit]" in owner


def test_webhook_and_scc_playbooks_carry_the_engine_fixes() -> None:
    gke = diagnose(
        'Internal error occurred: failed calling webhook "mutate.kyverno.svc-fail": Post '
        '"https://kyverno-svc.kyverno.svc:443/mutate/fail?timeout=10s": context deadline exceeded'
    ).as_dict()["diagnoses"]
    web = next(d for d in gke if d["id"] == "DBG-WEBHOOK")
    changes = " ".join(c["change"] for c in web["proposedChanges"])
    assert "9443" in changes and "hostNetwork" in changes and "enforcementAction: dryrun" in changes
    scc = diagnose(
        'pods "agent-x" is forbidden: unable to validate against any security context constraint: '
        "[provider restricted-v2: .containers[0].privileged: Invalid value: true: Privileged containers are not "
        "allowed]",
        platform="openshift",
    ).as_dict()["diagnoses"]
    d = next(x for x in scc if x["id"] == "DBG-SCC")
    assert any("ServiceAccount" in c for c in d["rootCauses"])
    assert any("Never edit the default SCCs" in c["change"] for c in d["proposedChanges"])


def test_policy_documents_keep_to_their_engine(kit: tk.Toolkit) -> None:
    for text in (
        "How do I let traffic from the monitoring namespace through my default-deny NetworkPolicy?",
        "Pods Pending: 0/3 nodes are available: 3 node(s) didn't match pod topology spread constraints. How to relax?",
    ):
        got = _top(kit, text)
        assert not [
            g
            for g in got
            if g.startswith(
                ("kn:kyverno-troubleshooting#", "kn:gatekeeper-enforcement#", "kn:k8s-validating-admission")
            )
        ], (text, got)


# OpenShift (openshift-docs 1649577, enterprise-4.22).

OCP_CASES = [
    (
        'Every build of my BuildConfig now ends with "error: build error: Failed to push image: denied: requested '
        'access to the resource is denied". Nothing changed in the pipeline.',
        "DBG-BUILD-IMAGE-QUOTA",
    ),
    (
        "Nodes never get Ready: container runtime network not ready: NetworkReady=false "
        "reason:NetworkPluginNotReady message:Network plugin returns error: Missing CNI default network",
        "DBG-OCP-CNI-NOT-READY",
    ),
    (
        "InstallPlan message: attenuated service account query failed - more than one operator group(s) are managing "
        "this namespace count=2",
        "DBG-OLM-OPERATORGROUP",
    ),
    (
        "oc adm prune images --confirm fails: error: error communicating with registry: Get "
        "https://10.1.2.3:5000/healthz: http: server gave HTTP response to HTTPS client",
        "DBG-PRUNE-REGISTRY",
    ),
    (
        "Failed to create pod sandbox: rpc error: failed to mount container 9f2c: error recreating the missing "
        "symlinks: open /var/lib/containers/storage/overlay/9f2c/link: no such file or directory",
        "DBG-CRIO-STORAGE",
    ),
    ("How do I make the etcd database bigger with backendQuotaGiB, and what sizes can I set?", "ocp-etcd-db-size"),
    (
        "My Service has service.beta.openshift.io/serving-cert-generation-error saying the secret references a "
        "serviceUID that does not match. How do I get a fresh certificate?",
        "ocp-service-serving-certs",
    ),
    (
        "I added two bare metal workers to my UPI cluster but oc get nodes lists only the masters. Is there a CSR "
        "step I'm missing?",
        "ocp-install-troubleshooting",
    ),
    (
        "The PodSecurityViolation alert keeps firing. Which namespaces and pods are behind it?",
        "ocp-pod-security-admission",
    ),
    (
        "The cluster update has said Working towards 4.22.3 for five hours. Which operator is holding it up?",
        "ocp-cluster-update-status",
    ),
    (
        "How do I follow the bootkube.service journal on the bootstrap node during install?",
        "ocp-install-troubleshooting",
    ),
    (
        "oc get co shows monitoring with DEGRADED True but AVAILABLE True. Are my applications down?",
        "ocp-cluster-update-status",
    ),
]


@pytest.mark.parametrize(("text", "want"), OCP_CASES)
def test_openshift_gaps(kit: tk.Toolkit, text: str, want: str) -> None:
    got = _top(kit, text, platform="openshift")
    assert _hit(got, want, 1 if want.startswith("DBG-") else 2), got


def test_openshift_look_alikes_go_elsewhere(kit: tk.Toolkit) -> None:
    pull = _top(
        kit,
        "docker pull myorg/app fails: pull access denied for myorg/app, repository does not exist or may require "
        "'docker login': denied: requested access to the resource is denied",
        platform="openshift",
    )
    assert pull[0] == "DBG-IMAGEPULL" and "DBG-BUILD-IMAGE-QUOTA" not in pull
    x509 = _top(kit, "Unable to connect to the server: x509: certificate signed by unknown authority")
    assert "DBG-PRUNE-REGISTRY" not in x509
    plain = _top(kit, "kubeadm node says container runtime network not ready, Missing CNI default network")
    assert "DBG-OCP-CNI-NOT-READY" not in plain  # an OpenShift playbook needs OpenShift context (G83)


# ROSA HCP (openshift-docs 1649577).

ROSA_CASES = [
    (
        "Creating a ROSA HCP cluster in ap-southeast-2 failed with code OCM5011. Are my roles or my VPC wrong?",
        "DBG-ROSA-OCM5011-CAPACITY",
    ),
    (
        "rosa create cluster --hosted-cp stopped and the cluster shows error OCM5010. We brought our own VPC.",
        "DBG-ROSA-OCM5010-SUBNET-TAGS",
    ),
    (
        "First ROSA cluster in a new AWS account fails: not authorized to perform iam:CreateServiceLinkedRole on "
        "arn:aws:iam::111122223333:role/aws-service-role/elasticloadbalancing.amazonaws.com/"
        "AWSServiceRoleForElasticLoadBalancing",
        "DBG-ROSA-ELB-SERVICE-ROLE",
    ),
    (
        'rosa delete cluster -c demo: "Failed to delete cluster 1q2w: sts_user_role is not linked to your account"',
        "DBG-ROSA-USER-ROLE-UNLINKED",
    ),
    (
        'Every rosa command on our CI runner stops with "Can\'t get tokens: ..." since this week.',
        "DBG-ROSA-EXPIRED-TOKEN",
    ),
    (
        'Karpenter on ROSA HCP creates no nodes: the default ec2nodeclass has SubnetsReady = False, "SubnetSelector '
        'did not match any Subnets".',
        "DBG-ROSA-KARPENTER-DISCOVERY-TAG",
    ),
    (
        "CloudTrail logs CreateTags failing with Client.UnauthorizedOperation for our "
        "mycluster-kube-system-control-plane-operator role (Karpenter on ROSA HCP).",
        "DBG-ROSA-KARPENTER-CREATETAGS",
    ),
    (
        "My ROSA cluster has been installing for over an hour. How do I follow the installer, and could AWS quota in "
        "my region be the reason?",
        "rosa-troubleshooting",
    ),
    (
        "How do I schedule the ROSA HCP control plane upgrade for Saturday 02:00, and in which time zone?",
        "rosa-hcp-lifecycle",
    ),
    ("Which tags do the private and public subnets of my VPC need for a ROSA HCP install?", "rosa-hcp-lifecycle"),
    (
        "Our ROSA HCP cluster uses an external OIDC provider that is down. How do I get an emergency cluster-admin "
        "kubeconfig with rosa?",
        "rosa-hcp-lifecycle",
    ),
    (
        "rosa describe cluster says ready but the web console of our ROSA HCP cluster will not load. Why?",
        "rosa-hcp-lifecycle",
    ),
    (
        "On ROSA a pod cannot reach our route through the private NLB when it runs on the same node as a router pod.",
        "rosa-troubleshooting",
    ),
]


@pytest.mark.parametrize(("text", "want"), ROSA_CASES)
def test_rosa_hcp_gaps(kit: tk.Toolkit, text: str, want: str) -> None:
    got = _top(kit, text, platform="rosa-hcp")
    assert _hit(got, want, 1 if want.startswith("DBG-") else 2), got


def test_rosa_look_alikes_go_elsewhere(kit: tk.Toolkit) -> None:
    oc = _top(kit, 'oc get pods: "error: You must be logged in to the server (Unauthorized)"', platform="rosa-hcp")
    assert "DBG-ROSA-EXPIRED-TOKEN" not in oc
    ipi = _top(
        kit,
        "Self-managed OpenShift IPI install on AWS hangs waiting for bootstrap to complete. How do I gather logs?",
        platform="openshift",
    )
    assert not [g for g in ipi if g.startswith(("DBG-ROSA-", "kn:rosa-troubleshooting#", "kn:rosa-hcp-lifecycle#"))]


# RHACS (rhacs-docs-main 801ccd0, stackrox 69fc953).

RHACS_CASES = [
    (
        "RHACS keeps rejecting our hotfix rollout. Can I put admission.stackrox.io/break-glass on the deployment, and "
        "what happens afterwards?",
        "DBG-RHACS-BREAK-GLASS",
    ),
    (
        'The RHACS image page for quay.example.net/pay/api:7.2 only says "Failed to retrieve metadata from the '
        'registry". The image pulls fine on the nodes.',
        "DBG-RHACS-SCANNER-REGISTRY",
    ),
    (
        'Internal error occurred: failed calling webhook "policyeval.stackrox.io": failed to call webhook: Post '
        '"https://admission-control.stackrox.svc:443/validate?timeout=10s": context deadline exceeded',
        "DBG-RHACS-WEBHOOK-FAILURE-POLICY",
    ),
    (
        "Our debian:9 image shows CVE DATA MAY BE INACCURATE in RHACS with Stale OS CVE data. Can we trust it?",
        "DBG-RHACS-SCANNER-CVE-DATA",
    ),
    (
        "collector pods restart; the last log line is Unable to connect to Sensor at 'sensor.stackrox.svc:443'.",
        "DBG-RHACS-COLLECTOR-SENSOR",
    ),
    (
        "roxctl image check --image=registry.example.org/shop/cart:3.1 exits 1: ERROR: failed policies found: 1 "
        'policies violated that are failing the check, policy "Fixable Severity at least Important".',
        "DBG-RHACS-IMAGE-CHECK-FAILED",
    ),
    (
        "In a GitLab pipeline I want roxctl deployment check to write a JUnit report. Which environment variables "
        "tell roxctl where Central is and which token to use?",
        "rhacs-roxctl-ci",
    ),
    (
        "What is the difference between soft and hard enforcement in RHACS? Does Sensor remove the pods, or does the "
        "API server refuse the deployment?",
        "rhacs-enforcement",
    ),
    (
        "How do I stop an RHACS policy from firing in every namespace whose name begins with test-? Does the "
        "exclusion take a regular expression?",
        "rhacs-policy-rules-scope",
    ),
    (
        "I set an RHACS policy for privileged containers but such deployments are still admitted. What must be "
        "switched on before it blocks them?",
        "rhacs-enforcement",
    ),
    (
        "My RHACS custom policy has two rules: does it alert when either matches or only when both do? How are "
        "criteria inside one rule combined?",
        "rhacs-policy-rules-scope",
    ),
    (
        "Which roxctl sensor generate option makes a bundle whose admission controller enforces no policies?",
        "rhacs-enforcement",
    ),
    (
        "What does Scanner V4 do in an RHACS secured cluster, and what is the admission controller for?",
        "rhacs-secured-cluster-troubleshooting",
    ),
    (
        "We rescanned the image but roxctl image check still shows last week's vulnerabilities. How do I make roxctl "
        "skip Central's cached result?",
        "rhacs-roxctl-ci",
    ),
]


@pytest.mark.parametrize(("text", "want"), RHACS_CASES)
def test_rhacs_gaps(kit: tk.Toolkit, text: str, want: str) -> None:
    got = _top(kit, text)
    assert _hit(got, want, 1 if want.startswith("DBG-") else 2), got


def test_rhacs_content_keeps_to_rhacs(kit: tk.Toolkit) -> None:
    for text in (
        "My Kyverno ClusterPolicy should skip every namespace named test-something. How do I write the exclude block?",
        'admission webhook "validation.gatekeeper.sh" denied the request: [must-have-owner] you must provide labels: '
        '{"owner"}',
    ):
        got = _top(kit, text)
        assert not [g for g in got if g.startswith(("DBG-RHACS-", "kn:rhacs-"))], (text, got)


def test_a_document_can_say_which_named_products_it_works_with() -> None:
    # The named-product gate keeps a question about GitLab from a doc that never names GitLab; a doc whose commands
    # run in any CI system declares that with worksWith instead of naming every CI product in its text.
    from kube_noob.knowledge.store import builtin_chunks, works_with

    assert works_with(None) == []
    assert works_with(["GitLab", "github actions"]) == ["gitlab", "github actions"]
    for bad in ("gitlab", [""], [3], {"a": "b"}):
        with pytest.raises(ValueError, match="worksWith"):
            works_with(bad)
    roxctl = next(c for c in builtin_chunks() if c.doc_id == "rhacs-roxctl-ci")
    assert "gitlab" in roxctl.extra["worksWith"]


def test_an_rhacs_webhook_that_could_not_be_called_is_not_a_denial() -> None:
    from kube_noob.debug.policy import explain

    timeout = (
        'Internal error occurred: failed calling webhook "policyeval.stackrox.io": failed to call webhook: Post '
        '"https://admission-control.stackrox.svc:443/validate?timeout=10s": context deadline exceeded'
    )
    assert not [d for d in explain(timeout)["denials"] if d["engine"] == "rhacs"]
    denied = (
        'admission webhook "policyeval.stackrox.io" denied the request: The attempted operation violated 1 enforced'
    )
    assert [d for d in explain(denied)["denials"] if d["engine"] == "rhacs"]

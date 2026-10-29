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
        "az aro create fails with MissingSubscriptionRegistration; ROSA is the AWS version, what do I register?",
    ):
        assert _top(kit, text) == [], text


def test_aws_security_hub_is_another_product() -> None:
    # Measured on the train half: a question about the CIS benchmark version AWS Security Hub checks drew the RHACS
    # release history (shared words: latest, release, version). No bundled document mentions Security Hub.
    from kube_noob.insight import _DocFit
    from kube_noob.knowledge.store import get_store

    fit = _DocFit("Which CIS benchmark version does AWS Security Hub check?", None)
    assert fit.tools == {"securityhub"}
    chunk = get_store().get("kn:stackrox#4")
    assert chunk is not None and not fit(chunk, {"latest", "release", "version"})


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
    # right bug started naming an unrelated one. A count of documents was measured too: it made more words rare and,
    # on the community test half, 22 rows that had no answer named an unrelated bug.
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


def test_insight_findings_carry_the_cause_and_fix_that_fit_the_text(kit: tk.Toolkit) -> None:
    out = kit.insight(
        tk.InsightIn(
            text="Built shop:latest locally on my laptop, kubectl apply on minikube: ErrImagePull, pull access denied "
            "for shop, repository does not exist"
        )
    )
    top = out["findings"][0]
    assert top["id"] == "DBG-IMAGEPULL"
    assert "in no registry" in top["cause"] and "minikube image load" in top["fix"]
    psa = kit.insight(
        tk.InsightIn(
            text='Error creating: pods "web-1" is forbidden: violates PodSecurity "restricted:latest": '
            'allowPrivilegeEscalation != false (container "web" must set '
            "securityContext.allowPrivilegeEscalation=false)"
        )
    )
    pol = next(f for f in psa["findings"] if f["source"] == "policy")
    assert "allowPrivilegeEscalation: false" in pol["fix"]
    import contextlib
    import io

    from kube_noob.cli import _print_insight

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_insight(out)
    assert "fix: " in buf.getvalue()


def test_every_pod_security_violation_is_read_even_with_prose_after_the_message() -> None:
    from kube_noob.debug.policy import explain

    text = (
        'pods "api-1" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false '
        '(container "api" must set securityContext.allowPrivilegeEscalation=false), runAsNonRoot != true (pod or '
        'container "api" must set securityContext.runAsNonRoot=true). How do I fix the pod spec?'
    )
    den = explain(text)["denials"][0]
    assert [v["check"] for v in den["details"]["violations"]] == [
        "allowPrivilegeEscalation != false",
        "runAsNonRoot != true",
    ]
    assert "breaks 2 of its checks" in den["meaning"]


def test_the_bug_matcher_counts_each_word_once() -> None:
    # Measured on the train half of the owner's answered rows: 55 reported-bug answers changed, all 55 were wrong
    # before, and 10 now point at the bug the report itself names (the original of a clone).
    from kube_noob.known_issues import _distinct

    assert _distinct(["item", "items", "visible"]) == ["items", "visible"]
    assert _distinct(["openshift-etcd", "etcd", "leader"]) == ["leader", "openshift-etcd"]
    assert _distinct(["values.yaml", "values", "yaml"]) == ["values.yaml"]
    assert _distinct([]) == []
    key = "service.beta.openshift.io/serving-cert-secret-name"
    assert _distinct([key, "serving-cert-secret-name", "hotloop"]) == ["hotloop", key]


def test_a_prefixed_name_also_counts_as_the_bare_name() -> None:
    # People write an annotation or label without its prefix ("serving-cert-secret-name"); release notes and docs
    # write it in full ("service.beta.openshift.io/serving-cert-secret-name"). The hyphenated name after the last
    # slash is its own term, so both spellings share it.
    from kube_noob.knowledge.store import tokenize

    toks = tokenize("service.beta.openshift.io/serving-cert-secret-name: secret")
    assert "service.beta.openshift.io/serving-cert-secret-name" in toks and "serving-cert-secret-name" in toks
    assert "ubi-minimal" in tokenize("registry.access.redhat.com/ubi9/ubi-minimal")
    assert "quay.io" not in tokenize("quay.io/org/img")  # only hyphenated names: a registry host is not one
    assert tokenize("route.openshift.io/v1").count("v1") == 1


def test_oc_adm_prune_without_confirm_is_a_preview() -> None:
    # openshift-docs pruning-images-running-operation.adoc: nothing is deleted until --confirm is added.
    from kube_noob.debug.steps import classify_step

    assert classify_step("oc adm prune images --keep-tag-revisions=3") == "read"
    assert classify_step("oc adm prune images --keep-tag-revisions=3 --confirm") == "change"
    assert classify_step("oc adm prune deployments --confirm=true") == "change"
    assert classify_step("oc adm prune builds --confirm=false") == "read"


def test_aws_cli_reads_are_reads() -> None:
    from kube_noob.debug.steps import classify_step

    assert classify_step('aws iam get-role --role-name "AWSServiceRoleForElasticLoadBalancing"') == "read"
    assert classify_step("aws ec2 describe-subnets --subnet-ids subnet-1") == "read"
    assert classify_step("aws iam list-roles") == "read"
    assert classify_step("aws ec2 create-tags --resources subnet-1 --tags Key=a,Value=1") == "change"
    assert classify_step("aws iam put-role-policy --role-name r --policy-name p --policy-document file://x") == "change"


def test_a_question_after_a_template_snippet_is_still_a_question(kit: tk.Toolkit) -> None:
    # Golden helm-006: a one-paragraph post that quotes a template call and ends by asking was read only as a Helm
    # template, so no document was searched. The last sentence asks, so it is also a question.
    from kube_noob.insight import recognise

    text = (
        "Our shared labels helper has worked for months in other charts, but in this new chart it prints an empty "
        'chart name and version. I render it with {{ template "web.labels" }} in the Deployment metadata, and '
        "helm template --debug shows chart: and version: with no values at all, while the rest of the manifest "
        "renders fine. Why is .Chart.Name empty there?"
    )
    assert {k.kind for k in recognise(text)} >= {"helm-chart", "question"}
    assert any(g.startswith("kn:helm-templates-values#") for g in _top(kit, text)[:2])
    assert "question" not in {k.kind for k in recognise('{{ template "web.labels" . }}\nname: web')}


def test_helm_releases_missing_after_helm_2_point_at_namespaces(kit: tk.Toolkit) -> None:
    # Golden helm-010: "although" counted as a word the knowledge had never seen, which raised the bar for every
    # document, and the namespace note was one bullet among command changes. Helm 3 keeps releases per namespace
    # (helm-www e5a4c62 faq/changes_since_helm2.md "Release Names are now scoped to the Namespace").
    text = "Since we moved from Helm 2 to Helm 3, helm list is empty although the apps still run. Where did they go?"
    assert _top(kit, text)[:1] == ["kn:helm-templates-values#6"]  # "helm list is empty or shows few releases"


def test_a_comment_inside_a_code_block_is_not_a_heading() -> None:
    # Golden ocp-011 and pol-018: the required-scc section was cut in three at the "# ..." comments of its YAML
    # example, so its first chunk lost the example, the "SCC must exist" rule and the check command.
    from kube_noob.knowledge.store import _split_markdown, get_store

    body = (
        "## Real\n\ntext\n\n```sh\n# list pods\nkubectl get pods\n```\n\nmore\n\n"
        "~~~yaml\n# ...\nkind: Pod\n~~~\n\n## Next\n\nx"
    )
    assert [h for h, _ in _split_markdown(body)] == ["Real", "Next"]
    chunk = get_store().get("kn:ocp-scc#4")
    assert chunk is not None and chunk.heading.startswith("openshift.io/required-scc")
    assert "openshift\\.io\\/scc" in chunk.text and "unless the SCC exists" in chunk.text


# QA6 regrade gaps closed from the cited pages: kubernetes/website a4c4bc29 (determine-reason-pod-failure.md,
# manage-resources-containers.md), helm-www e5a4c62 (topics/advanced.md), openshift-docs 1400f2c (enterprise-4.22:
# rosa-hcp-classic-comparison.adoc, storage-multi-attach-error.adoc).


def test_termination_message_and_limit_enforcement_have_sections(kit: tk.Toolkit) -> None:
    exited = (
        "The container dies with exit code 1 and kubectl describe shows no reason. How do I get its last log lines "
        "into the termination message?"
    )
    assert _top(kit, exited)[:1] == ["kn:k8s-debug-pods#1"]
    body = tk_chunk("kn:k8s-debug-pods#1")
    assert "FallbackToLogsOnError" in body and "2048 bytes or 80 lines" in body and "lastState.terminated" in body
    limits = (
        "One pod just runs slowly at its CPU limit, another was OOMKilled above its memory limit. Are the two limits "
        "enforced the same way?"
    )
    assert "kn:k8s-resources#2" in _top(kit, limits)
    assert "reactively" in tk_chunk("kn:k8s-resources#2")


def test_helm_adoption_and_multi_attach_name_the_documented_commands() -> None:
    assert "--take-ownership" in tk_chunk("kn:helm-troubleshooting#1")
    d = _diag("Multi-Attach error for volume pvc-1 Volume is already used by pod(s) db-0")
    assert d["id"] == "DBG-MULTIATTACH"
    assert "--grace-period=0" in _changes(d) and "six minutes" in _changes(d)
    assert "six minutes" in tk_chunk("kn:storage-access-modes#1")


def tk_chunk(chunk_id: str) -> str:
    from kube_noob.knowledge.store import get_store

    chunk = get_store().get(chunk_id)
    assert chunk is not None, chunk_id
    return chunk.text


def test_generic_words_do_not_bring_the_pod_storage_or_limits_documents(kit: tk.Toolkit) -> None:
    # Measured on the train half: once these documents gained sections, questions about ECS tasks, EBS volume sizes
    # or C structs drew them on words such as container, volume and exit. Each now needs a word of its subject.
    for text, doc in (
        ("How can two containers in one AWS ECS task get different IAM roles?", "kn:k8s-debug-pods#"),
        (
            "How do I shrink an EBS volume from 1500 GB to 100 GB without losing data after a crash?",
            "kn:storage-access-",
        ),
        (
            "Why does my C program exit with an error when the struct is not aligned? How do I read the message?",
            "kn:k8s-",
        ),
    ):
        assert not [g for g in _top(kit, text) if g.startswith(doc)], text


def test_frequent_documents_need_a_word_of_their_subject(kit: tk.Toolkit) -> None:
    # Measured on the train half: the 19 documents that answered most community rows (Kubernetes overview, RHACS,
    # everyday errors, images, Ingress, kubelet, NetworkPolicy, TLS, Helm, selectors, DNS, RBAC, scheduling,
    # deprecations, Services, Pod Security, learning paths, topology spread) were mostly wrong when the post never
    # named their subject. Each now needs a word of it, and of Kubernetes where its own words are generic.
    for text in (
        "How do I make a Docker image smaller? The registry push takes ages because the image is 2 GB.",
        "Our Redis cluster loses its leader during network partitions. Which policy settings avoid split brain?",
        "Which certificate does my nginx web server send when the TLS handshake fails on an old Android client?",
        "Service discovery with etcd on Docker Swarm stopped working after we rotated the TLS keys.",
    ):
        assert _top(kit, text) == [], (text, _top(kit, text))
    from kube_noob.knowledge.store import builtin_chunks

    gated = {c.doc_id for c in builtin_chunks() if c.extra.get("requires")}
    assert {"kubernetes", "stackrox", "k8s-common-errors", "k8s-images", "helm", "k8s-pss", "learning-paths"} <= gated


def test_invalid_utf8_in_a_runtime_request_has_its_own_playbook(kit: tk.Toolkit) -> None:
    # Owner question 2026-10-28. Public reports (aws/containers-roadmap#2791, ministryofjustice/cloud-platform#8186,
    # giantswarm/giantswarm-platform-manager#280): CreateContainerError with this message when an environment
    # variable from a Secret decodes to bytes that are not UTF-8; Red Hat KB 7086811 for the RHACS Collector case.
    bare = _diag("grpc error unmarshalling request; string field contains invalid UTF-8")
    assert bare["id"] == "DBG-INVALID-UTF8"
    event = _diag(
        "Warning  Failed  12s  kubelet  Error: grpc: error unmarshalling request: string field contains invalid "
        "UTF-8\n  Reason: CreateContainerError"
    )
    assert event["id"] == "DBG-INVALID-UTF8"
    assert "Secret" in _causes(event) and "stringData" in _changes(event) and "volume" in _changes(event)
    out = kit.insight(tk.InsightIn(text="grpc error unmarshalling request; string field contains invalid UTF-8"))
    top = out["findings"][0]
    assert top["id"] == "DBG-INVALID-UTF8" and "Secret" in top["cause"]
    collector = kit.insight(
        tk.InsightIn(
            text="collector in CrashLoopBackOff: String field 'storage.ProcessSignal.args' contains invalid UTF-8 "
            "data when serializing a protocol buffer",
            platform="openshift",
        )
    )
    first = collector["findings"][0]
    assert first["id"] == "DBG-INVALID-UTF8" and "Collector" in first["cause"]
    from kube_noob.debug.playbooks import PLAYBOOKS
    from kube_noob.debug.steps import classify_step

    pb = next(p for p in PLAYBOOKS if p.pid == "DBG-INVALID-UTF8")
    assert all(classify_step(c.format(pod="web", ns="shop")) == "read" for c in pb.checks)
    assert not any(".data" in c and "base64" in c for c in pb.checks)  # key names only, never a Secret's values
    assert pb.knowledge == ("k8s-invalid-utf8",)
    keystore = "How do I store a Java keystore in a Kubernetes Secret and mount it into my pod?"
    assert not [g for g in _top(kit, keystore) if g.startswith("kn:k8s-invalid-utf8")]

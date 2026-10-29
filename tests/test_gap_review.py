"""Gap review 2026-10 (G107, docs/evals/gap-review-2026-10.md): CVE signatures for Windows subPath and local volume
injection, NFS/SMB CSI subDir traversal, ingress-nginx ImplementationSpecific paths and ControllerRevision writes;
ConfigMap credentials, legacy token Secrets, bindings to everyone, NetworkPolicies that select nothing, HPA targets
that set replicas; and the helm-audit checks for the Helm advisories."""

from __future__ import annotations

import math
import re
from pathlib import Path

import pytest
import yaml

from kube_noob.audit import rules as rules_mod
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.catalog import SOURCES
from kube_noob.generate import policies as pol
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.helm import MAX_SCHEMA_BYTES, generate_chart, lint_chart_metadata
from kube_noob.generate.manifests import generate
from kube_noob.vuln import threat
from tests.policy_cel import failures

FIX = Path(__file__).resolve().parent / "fixtures" / "rules"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
NEW_RULES = ("KN-S025", "KN-S026", "KN-S027", "KN-S028", "KN-N011", "KN-N012", "KN-ST006", "KN-C014")
# Rule -> the CVE ids its bad fixture's findings must name.
EXPECTED = {
    "KN-S025": {"CVE-2023-3676"},
    "KN-ST006": {"CVE-2023-5528", "CVE-2026-3864"},
    "KN-N011": {"CVE-2026-24512"},
}


def _fixture(rule_id: str) -> dict[str, str]:
    data = yaml.safe_load((FIX / f"{rule_id}.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _findings(text: str, rule_id: str, platform: str = "kubernetes", version: str | None = None) -> list:
    return [f for f in analyze(text, platform, version).findings if f.rule_id == rule_id]


def _cited(rule_id: str) -> set[str]:
    return {m for c in rules_mod.RULES[rule_id].citations for m in CVE.findall(SOURCES[c].title)}


def _policy(rule_id: str, platform: str = "kubernetes") -> dict:
    return pol.documents(pol.checks_for(platform)[rule_id], "vap", "enforce", platform)[0]


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_each_cve_rule_names_its_cves_and_fixed_releases(rule_id: str) -> None:
    data = _fixture(rule_id)
    bad = _findings(data["bad"], rule_id)
    named = {m for f in bad for m in CVE.findall(f.message)}
    assert EXPECTED[rule_id] <= named, (rule_id, named)
    assert named <= _cited(rule_id), f"{rule_id} names a CVE its citations lack: {named - _cited(rule_id)}"
    assert all(f.severity >= Severity.MEDIUM and re.search(r"v\d+\.\d+\.\d+", f.message) for f in bad)
    assert _findings(data["good"], rule_id) == []


def test_every_new_rule_cites_a_licensed_source_and_every_cve_it_describes() -> None:
    for rule_id in (*NEW_RULES, "KN-S017"):
        rule = rules_mod.RULES[rule_id]
        assert rule.citations, rule_id
        for c in rule.citations:
            src = SOURCES[c]
            assert src.url.startswith("https://") and src.license in {"CC-BY-4.0", "Apache-2.0", "link only"}, c
        described = set(CVE.findall(rule.description)) | set(CVE.findall(rule.remediation))
        assert described <= _cited(rule_id), (rule_id, described - _cited(rule_id))
    for driver, (cve, _, _) in rules_mod.CSI_SUBDIR_TRAVERSAL.items():
        assert cve in _cited("KN-ST006"), driver


def test_subpath_with_shell_or_powershell_syntax() -> None:
    doc = yaml.safe_load(_fixture("KN-S025")["good"])
    spec = doc["spec"]["template"]["spec"]
    mount = spec["containers"][0]["volumeMounts"][0]
    for sub, flagged in (
        ("logs/app", False),
        ("data (old)", False),
        ("C:\\logs", False),
        ("logs$(Start-Process cmd)", True),
        ("a;b", True),
        ("x`y", True),
        ("it's", True),
        ("a|b", True),
        ("line\nbreak", True),
    ):
        mount["subPath"] = sub
        found = _findings(yaml.safe_dump(doc), "KN-S025")
        assert bool(found) is flagged, sub
        if flagged:
            assert found[0].severity == Severity.HIGH and "CVE-2023-3676" in found[0].message, sub
            assert failures(_policy("KN-S025"), doc), sub
        else:
            assert failures(_policy("KN-S025"), doc) == [], sub
    # a pod not pinned to Windows still carries the pattern, one step lower
    mount["subPath"] = "a;b"
    del spec["nodeSelector"]
    (linux,) = _findings(yaml.safe_dump(doc), "KN-S025")
    assert linux.severity == Severity.MEDIUM and "any Windows node" in linux.message
    spec["os"] = {"name": "windows"}
    assert _findings(yaml.safe_dump(doc), "KN-S025")[0].severity == Severity.HIGH


def test_persistent_volume_local_path_and_csi_subdir_traversal() -> None:
    local, nfs = list(yaml.safe_load_all(_fixture("KN-ST006")["good"]))
    for path, flagged in (("/mnt/disks/ssd1", False), ("C:\\data\\app", False), ("/mnt/a;b", True), ("/x$(y)", True)):
        local["spec"]["local"]["path"] = path
        assert bool(_findings(yaml.safe_dump(local), "KN-ST006")) is flagged, path
    for driver in ("nfs.csi.k8s.io", "smb.csi.k8s.io", "ebs.csi.aws.com"):
        for handle, flagged in (
            ("srv/share#app#", False),
            ("srv/share#a..b#", False),
            ("srv/share#legit/../../exports#", True),
            ("srv/share#..#", True),
            ("srv\\share#..\\x#", True),
        ):
            doc = yaml.safe_load(yaml.safe_dump(nfs))
            doc["spec"]["csi"].update(driver=driver, volumeHandle=handle)
            found = _findings(yaml.safe_dump(doc), "KN-ST006")
            want = flagged and driver != "ebs.csi.aws.com"
            assert bool(found) is want, (driver, handle)
            assert bool(failures(_policy("KN-ST006"), doc)) is want, (driver, handle)
            if want:
                cve, project, fixed = rules_mod.CSI_SUBDIR_TRAVERSAL[driver]
                assert cve in found[0].message and fixed in found[0].message and project in found[0].message
    doc = yaml.safe_load(yaml.safe_dump(nfs))
    doc["spec"]["csi"]["volumeAttributes"]["subDir"] = "../etc"
    (attr,) = _findings(yaml.safe_dump(doc), "KN-ST006")
    assert attr.path == "spec.csi.volumeAttributes.subDir"


def test_implementation_specific_paths_by_ingress_class_and_platform() -> None:
    bad = yaml.safe_load(_fixture("KN-N011")["bad"])
    (nginx,) = _findings(yaml.safe_dump(bad), "KN-N011")
    assert nginx.severity == Severity.HIGH and "v1.13.7 and v1.14.3" in nginx.message
    del bad["spec"]["ingressClassName"]
    (default,) = _findings(yaml.safe_dump(bad), "KN-N011")
    assert default.severity == Severity.LOW and "default IngressClass" in default.message
    assert failures(_policy("KN-N011"), bad)
    assert _findings(yaml.safe_dump(bad), "KN-N011", "openshift", "4.20") == []  # the OpenShift router serves it
    assert failures(_policy("KN-N011", "openshift"), bad) == []
    bad["metadata"]["annotations"] = {"nginx.ingress.kubernetes.io/ssl-redirect": "true"}
    assert _findings(yaml.safe_dump(bad), "KN-N011", "openshift", "4.20")
    bad["metadata"]["annotations"] = {}
    bad["spec"]["ingressClassName"] = "haproxy"
    assert _findings(yaml.safe_dump(bad), "KN-N011") == [] and failures(_policy("KN-N011"), bad) == []


def _role(*rules: dict) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "deployer", "namespace": "shop"},
        "rules": list(rules),
    }


def test_controllerrevision_writes_carry_cve_2026_2270() -> None:
    revisions = {"apiGroups": ["apps"], "resources": ["controllerrevisions"], "verbs": ["create", "patch"]}
    sts = {"apiGroups": ["apps"], "resources": ["statefulsets"], "verbs": ["update"]}
    read = {"apiGroups": ["apps"], "resources": ["controllerrevisions"], "verbs": ["get", "list"]}

    def hits(doc: dict) -> list:
        return [f for f in _findings(yaml.safe_dump(doc), "KN-S017") if "ControllerRevisions" in f.message]

    (both,) = hits(_role(revisions, sts))
    assert both.severity == Severity.HIGH and "CVE-2026-2270" in both.message and "v1.34.12" in both.message
    (alone,) = hits(_role(revisions))
    assert alone.severity == Severity.MEDIUM and "CVE-2026-2270" in alone.message
    assert hits(_role(read)) == [] and failures(_policy("KN-S017"), _role(read)) == []
    assert failures(_policy("KN-S017"), _role(revisions))


def test_configmap_credentials_and_their_look_alikes() -> None:
    good = yaml.safe_load(_fixture("KN-S026")["good"])
    assert failures(_policy("KN-S026"), good) == []
    for data, flagged in (
        ({"DB_PASSWORD": "hunter2"}, True),
        ({"redis.password": "x"}, True),
        ({"client_secret": "abc"}, True),
        ({"aws_secret_access_key": "abc"}, True),
        ({"GITHUB_TOKEN": "ghp_x"}, True),
        ({"DB_PASSWORD": "$(DB_PASSWORD)"}, False),
        ({"api-key": "<redacted>"}, False),
        ({"tls-secret": "web-tls"}, False),
        ({"token-ttl": "30m"}, False),
        ({"password_min_length": "12"}, False),
        ({"url": "postgres://app:s3cr3t@db:5432/app"}, True),
        ({"key.pem": "-----BEGIN PRIVATE KEY-----\nMII\n"}, True),
        ({"app.properties": "db.url=jdbc:x\ndb.password=hunter2\n"}, True),
        ({"app.properties": "db.password=${DB_PASSWORD}\npassword.min-length=12\n"}, False),
        ({"app.json": '{\n  "token": "abc"\n}'}, True),
        ({"app.yaml": "auth:\n  token: ''\n"}, False),
        ({".env": "export API_KEY=xyz\n"}, True),
    ):
        doc = {**good, "data": data}
        found = _findings(yaml.safe_dump(doc), "KN-S026")
        assert bool(found) is flagged, data
        assert bool(failures(_policy("KN-S026"), doc)) is flagged, data


def test_configmap_policy_stays_under_the_cel_cost_limit() -> None:
    """cel-go's runtime cost of matches(): ceil(0.1 * (1 + len(string))) * ceil(0.25 * len(pattern)). The largest
    ConfigMap the policy reads must stay under the API server's 1,000,000 per expression; larger ones are admitted
    and left to the audit (coverage partial)."""
    patterns = (rules_mod.CONFIGMAP_CREDENTIAL_LINE, rules_mod.EMBEDDED_CREDENTIAL, pol._REFERENCE)
    per_value = sum(math.ceil(0.1 * (1 + pol._CM_MAX_VALUE)) * math.ceil(0.25 * len(p)) for p in patterns)
    per_key = math.ceil(0.1 * (1 + 253)) * math.ceil(0.25 * len(rules_mod.CONFIGMAP_CREDENTIAL_KEY))
    assert pol._CM_MAX_KEYS * (per_value + per_key) < 1_000_000
    check = pol.checks_for("kubernetes")["KN-S026"]
    assert check.coverage == "partial" and "kube-noob audit" in check.limitation
    base = yaml.safe_load(_fixture("KN-S026")["bad"])
    many = {**base, "data": {**{f"k{i}": "x" for i in range(pol._CM_MAX_KEYS)}, "DB_PASSWORD": "hunter2"}}
    large = {**base, "data": {"DB_PASSWORD": "hunter2", "big": "x" * (pol._CM_MAX_VALUE + 1)}}
    for doc in (many, large):
        assert failures(_policy("KN-S026"), doc) == [] and _findings(yaml.safe_dump(doc), "KN-S026")
    assert failures(_policy("KN-S026"), base)


def test_legacy_token_secrets_are_refused_on_create_only() -> None:
    bad = list(yaml.safe_load_all(_fixture("KN-S027")["bad"]))[1]
    (f,) = _findings(yaml.safe_dump(bad), "KN-S027")
    assert "ci-deployer" in f.message and "kubectl create token" in f.message
    assert _findings(yaml.safe_dump(bad), "KN-S018") == []  # the inline-data rule still leaves token Secrets alone
    policy = _policy("KN-S027")
    assert failures(policy, bad) and failures(policy, bad, operation="UPDATE") == []  # the token controller fills it


def test_bindings_to_everyone() -> None:
    bad = yaml.safe_load(_fixture("KN-S028")["bad"])
    policy = _policy("KN-S028")
    for kind, name, cluster_sev in (
        ("Group", "system:unauthenticated", Severity.CRITICAL),
        ("User", "system:anonymous", Severity.CRITICAL),
        ("Group", "system:authenticated", Severity.HIGH),
        ("Group", "system:serviceaccounts", Severity.HIGH),
    ):
        bad["subjects"] = [{"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": name}]
        (f,) = _findings(yaml.safe_dump(bad), "KN-S028")
        assert f.severity == cluster_sev and name in f.message and failures(policy, bad)
        namespaced = {**bad, "kind": "RoleBinding", "metadata": {"name": "public-view", "namespace": "shop"}}
        (g,) = _findings(yaml.safe_dump(namespaced), "KN-S028")
        assert g.severity == Severity(cluster_sev - 1)
    bad["subjects"] = [{"kind": "Group", "name": "system:serviceaccounts:shop"}]
    assert _findings(yaml.safe_dump(bad), "KN-S028") == [] and failures(policy, bad) == []
    # the built-in bindings (system: names, the rbac-defaults label) are left alone
    bad["subjects"] = [{"kind": "Group", "name": "system:unauthenticated"}]
    builtin = {**bad, "metadata": {"name": "system:public-info-viewer"}}
    labelled = {**bad, "metadata": {"name": "x", "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}}}
    for doc in (builtin, labelled):
        assert _findings(yaml.safe_dump(doc), "KN-S028") == [] and failures(policy, doc) == []


def test_networkpolicy_that_selects_no_pod() -> None:
    bad = _fixture("KN-N012")["bad"]
    (f,) = _findings(bad, "KN-N012")
    assert "wbe" in f.message and "protects nothing" in f.message
    policy_only = bad.split("---")[1]
    assert _findings(policy_only, "KN-N012") == []  # no pods of that namespace in the bundle: nothing to compare
    assert _findings(bad.replace("matchLabels: {app: wbe}", "{}"), "KN-N012") == []  # every pod
    assert "KN-N012" in pol.NOT_GENERATED


def test_hpa_target_that_sets_replicas_and_the_generators() -> None:
    bad = _fixture("KN-C014")["bad"]
    (f,) = _findings(bad, "KN-C014")
    assert f.severity == Severity.MEDIUM and f.path == "spec.replicas" and "resets the count to 3" in f.message
    (zero,) = _findings(bad.replace("replicas: 3", "replicas: 0"), "KN-C014")
    assert zero.severity == Severity.HIGH and "deactivates the HPA" in zero.message
    assert "KN-C014" in pol.NOT_GENERATED
    bp = Blueprint.model_validate(
        {"name": "app", "namespace": "team", "image": "quay.io/a/app:1.0.0", "replicas": 3, "hpaMaxReplicas": 8}
    )
    workload = next(o for o in generate(bp).objects if o["kind"] == "Deployment")
    assert "replicas" not in workload["spec"]
    fixed = next(
        o for o in generate(bp.model_copy(update={"hpa_max_replicas": None})).objects if o["kind"] == "Deployment"
    )
    assert fixed["spec"]["replicas"] == 3


def test_generated_chart_leaves_replicas_to_the_hpa(tmp_path: Path) -> None:
    bp = Blueprint.model_validate(
        {"name": "web", "namespace": "n", "image": "ghcr.io/a/web:1.2.3", "replicas": 2, "hpaMaxReplicas": 5}
    )
    root = Path(generate_chart(bp, tmp_path)["chartDir"])
    dep = (root / "templates" / "deployment.yaml").read_text()
    conditional = (
        r"\{\{- if not \.Values\.autoscaling\.enabled \}\}\n"
        r"\s+replicas: \{\{ \.Values\.replicaCount \}\}\n"
        r"\s+\{\{- end \}\}"
    )
    assert re.search(conditional, dep), dep
    assert lint_chart_metadata(root) == []


def _chart(root: Path, **meta: object) -> Path:
    root.mkdir(parents=True)
    chart = {"apiVersion": "v2", "name": "app", "version": "0.1.0", "appVersion": "1.0.0", **meta}
    (root / "Chart.yaml").write_text(yaml.safe_dump(chart))
    (root / "values.schema.json").write_text("{}\n")
    (root / "templates").mkdir()
    return root


def test_helm_audit_flags_the_helm_advisories(tmp_path: Path) -> None:
    clean = _chart(tmp_path / "clean")
    (clean / "templates" / "cm.yaml").write_text("kind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n")
    assert lint_chart_metadata(clean) == []

    linked = _chart(tmp_path / "linked")
    (tmp_path / "bashrc").write_text("")
    (linked / "Chart.lock").symlink_to(tmp_path / "bashrc")
    (lock,) = lint_chart_metadata(linked)
    assert "CVE-2025-53547" in lock and "3.18.4" in lock and SOURCES["ghsa-cve-2025-53547"].url in lock

    for name in ("..", ".", "../evil", "a/b"):
        (issue,) = lint_chart_metadata(_chart(tmp_path / f"n{len(name)}{name.count('/')}{name.count('.')}", name=name))
        assert "CVE-2024-25620" in issue and "CVE-2026-35206" in issue, name
    deps = [{"name": "redis", "version": "~18.1.0", "repository": "http://charts.example.com"}]
    (plain,) = lint_chart_metadata(_chart(tmp_path / "deps", dependencies=deps))
    assert "http://charts.example.com" in plain and "https://" in plain
    sub = _chart(tmp_path / "sub")
    (sub / "charts" / "x").mkdir(parents=True)
    (sub / "charts" / "x" / "Chart.yaml").write_text(
        yaml.safe_dump({"apiVersion": "v2", "name": "..", "version": "1.0.0"})
    )
    assert any("charts/x/Chart.yaml name" in i and "CVE-2024-25620" in i for i in lint_chart_metadata(sub))

    big = _chart(tmp_path / "big")
    with (big / "values.schema.json").open("r+b") as fh:
        fh.truncate(MAX_SCHEMA_BYTES + 1)
    (schema,) = lint_chart_metadata(big)
    assert "CVE-2025-32387" in schema and "3.17.3" in schema

    tpl = _chart(tmp_path / "tpl")
    (tpl / "templates" / "dns.yaml").write_text('value: {{ getHostByName "db.example.com" }}\n')
    (tpl / "templates" / "_helpers.tpl").write_text('{{- $s := (lookup "v1" "Secret" .Release.Namespace "x") }}\n')
    (tpl / "templates" / "crd.yaml").write_text("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n")
    kept = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  annotations:\n"
    (tpl / "templates" / "kept.yaml").write_text(kept + '    "helm.sh/resource-policy": keep\n')
    found = lint_chart_metadata(tpl)
    assert len(found) == 3, found
    assert any("dns.yaml" in i and "CVE-2023-25165" in i and "3.11.1" in i for i in found)
    assert any("_helpers.tpl" in i and "lookup" in i and "helm template" in i for i in found)
    assert any("crd.yaml" in i and "crds/" in i for i in found)


def test_red_team_and_threat_model_read_the_new_rules() -> None:
    assert {"KN-N011", "KN-N009"} <= set(threat.TEMPLATES["TM-E04"].rules)
    assert "KN-S025" in threat.TEMPLATES["TM-E02"].rules and "KN-S026" in threat.TEMPLATES["TM-I02"].rules
    assert "KN-N012" in threat.TEMPLATES["TM-I01"].rules
    report = analyze(_fixture("KN-S025")["bad"] + "---\n" + _fixture("KN-S028")["bad"], "kubernetes")
    privesc = next(s for s in report.scenarios if s.scenario_id == "RT-PRIVESC")
    assert privesc.verdict == "exposed" and {"KN-S025", "KN-S028"} <= {e.split()[0] for e in privesc.evidence}
    leak = analyze(_fixture("KN-S026")["bad"] + "---\n" + _fixture("KN-S027")["bad"], "kubernetes")
    secrets = next(s for s in leak.scenarios if s.scenario_id == "RT-SECRET-LEAK")
    assert {"KN-S026", "KN-S027"} <= {e.split()[0] for e in secrets.evidence}

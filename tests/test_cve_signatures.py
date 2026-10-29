"""CVE signatures (G106): the rules that recognise the manifest shape of a published vulnerability name the CVE ids
and the fixed releases in their messages, cite the Kubernetes CVE feed issue or the GitHub advisory (with a licence),
and the probe manifest that once produced none of them reports every signal."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from kube_noob.audit import rules as rules_mod
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.build import containerfile as cf
from kube_noob.catalog import SOURCES

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
CVE_RULES = ("KN-S008", "KN-S021", "KN-S022", "KN-S023", "KN-S024", "KN-N008", "KN-N009", "KN-N010")
# Rule -> the CVE ids its bad fixture's findings must name.
EXPECTED = {
    "KN-S021": {"CVE-2024-10220", "CVE-2025-1767"},
    "KN-S022": {"CVE-2022-0811"},
    "KN-S023": {"CVE-2024-21626"},
    "KN-S024": {"CVE-2025-1974", "CVE-2025-15566", "CVE-2026-1580", "CVE-2026-3288", "CVE-2026-4342"},
    "KN-N008": {"CVE-2020-8554"},
    "KN-N009": {"CVE-2021-25742", "CVE-2023-5043", "CVE-2025-24514", "CVE-2026-24513"},
    "KN-N010": {"CVE-2021-25742", "CVE-2023-5043"},
}


def _findings(text: str, rule_id: str, platform: str = "kubernetes", version: str | None = None) -> list:
    return [f for f in analyze(text, platform, version).findings if f.rule_id == rule_id]


def _cited(rule_id: str) -> set[str]:
    return {m for c in rules_mod.RULES[rule_id].citations for m in CVE.findall(SOURCES[c].title)}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_each_cve_rule_flags_its_bad_fixture_with_the_cve_ids_and_passes_the_good(rule_id: str) -> None:
    data = yaml.safe_load((FIX / "rules" / f"{rule_id}.yaml").read_text(encoding="utf-8"))
    bad = _findings(data["bad"], rule_id)
    assert bad, rule_id
    named = {m for f in bad for m in CVE.findall(f.message)}
    assert EXPECTED[rule_id] <= named, (rule_id, named)
    assert named <= _cited(rule_id), f"{rule_id} names a CVE its citations do not carry: {named - _cited(rule_id)}"
    assert all(f.severity >= Severity.MEDIUM for f in bad)
    assert _findings(data["good"], rule_id) == []


def test_every_cve_citation_has_a_url_and_a_licence() -> None:
    for rule_id in CVE_RULES + ("KN-V019",):
        rule = rules_mod.RULES[rule_id]
        assert rule.citations, rule_id
        for c in rule.citations:
            src = SOURCES[c]
            assert src.url.startswith("https://") and src.license and src.license != "unknown", c
        if rule_id != "KN-S008":  # the CVE feed issues and advisories are cited by link, the docs by their licence
            assert {SOURCES[c].license for c in rule.citations} <= {"CC-BY-4.0", "Apache-2.0", "link only"}, rule_id
        # every CVE the rule's description names is backed by a cited feed issue or advisory
        described = set(CVE.findall(rule.description)) | set(CVE.findall(rule.remediation))
        assert described <= _cited(rule_id), (rule_id, described - _cited(rule_id))
    for a in rules_mod.INGRESS_NGINX_ADVISORIES:
        titles = " ".join(SOURCES[c].title for c in a.citations)
        assert all(cve in titles for cve in a.cves), a.cves
    for short, hits in rules_mod.INGRESS_NGINX_ANNOTATION_CVES.items():
        assert short in rules_mod.INGRESS_NGINX_RISKY_ANNOTATIONS
        assert {cve for cve, _ in hits} <= _cited("KN-N009"), short


def test_the_probe_manifest_reports_every_signal() -> None:
    """The report's probe manifest: before these rules the audit found only KN-N001, KN-C008 and KN-C010."""
    report = analyze((FIX / "cve-probe.yaml").read_text(encoding="utf-8"), "openshift", "4.22")
    by_rule: dict[str, list] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert {"KN-N008", "KN-N009", "KN-N010", "KN-S008", "KN-S021", "KN-S022", "KN-S023", "KN-V019"} <= set(by_rule)
    assert any("CVE-2020-8554" in f.message and "203.0.113.10" in f.message for f in by_rule["KN-N008"])
    annotations = {
        "configuration-snippet",
        "auth-url",
        "mirror-target",
        "auth-tls-match-cn",
        "rewrite-target",
        "permanent-redirect",
    }
    assert {f.path.rsplit("/", 1)[-1] for f in by_rule["KN-N009"]} == annotations
    snippet = next(f for f in by_rule["KN-N009"] if f.path.endswith("configuration-snippet"))
    assert snippet.severity == Severity.HIGH and "CVE-2021-25742" in snippet.message
    assert all(f.severity == Severity.MEDIUM for f in by_rule["KN-N009"] if f is not snippet)
    assert {f.path for f in by_rule["KN-N010"]} == {"data.allow-snippet-annotations", "data.annotations-risk-level"}
    (git,) = by_rule["KN-S021"]
    assert "CVE-2024-10220" in git.message and "init container" in git.message and "emptyDir" in git.message
    assert "GitRepoVolumeDriver feature gate is off by default" in git.message  # OpenShift 4.22 is Kubernetes 1.35
    (sysctl,) = by_rule["KN-S022"]
    assert "CVE-2022-0811" in sysctl.message and sysctl.severity == Severity.HIGH
    (wd,) = by_rule["KN-S023"]
    assert "CVE-2024-21626" in wd.message and "/proc/self/fd/7" in wd.message
    assert any("CVE-2023-2431" in f.message for f in by_rule["KN-S008"])
    assert any("archived on 2026-03-24" in f.message for f in by_rule["KN-V019"])
    verdicts = {s.scenario_id: s.verdict for s in report.scenarios}
    assert verdicts["RT-PRIVESC"] == "exposed" and verdicts["RT-EXPOSURE"] == "exposed"
    assert report.score() < 50


def test_gitrepo_message_follows_the_target_version() -> None:
    bad = yaml.safe_load((FIX / "rules" / "KN-S021.yaml").read_text(encoding="utf-8"))["bad"]
    (old,) = _findings(bad, "KN-S021", "kubernetes", "1.31")
    assert "deprecated since Kubernetes 1.11" in old.message and "off by default" not in old.message.split("1.11")[0]
    (gone,) = _findings(bad, "KN-S021", "openshift", "4.23")  # OpenShift 4.23 is Kubernetes 1.36
    assert "no longer has the gitRepo driver" in gone.message and "the pod cannot start" in gone.message
    local = bad.replace("https://github.com/acme/app.git", "/srv/git/app")
    (node,) = _findings(local, "KN-S021")
    assert "CVE-2025-1767 pattern" in node.message


def test_seccomp_localhost_needs_a_profile_file() -> None:
    base = yaml.safe_load((FIX / "rules" / "KN-S008.yaml").read_text(encoding="utf-8"))["good"]
    doc = yaml.safe_load(base)
    sc = doc["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    for profile, flagged in (
        ({"type": "Localhost"}, True),
        ({"type": "Localhost", "localhostProfile": ""}, True),
        ({"type": "Localhost", "localhostProfile": "  "}, True),
        ({"type": "Localhost", "localhostProfile": "profiles/app.json"}, False),
        ({"type": "RuntimeDefault"}, False),
    ):
        sc["seccompProfile"] = profile
        found = _findings(yaml.safe_dump(doc), "KN-S008")
        assert bool(found) is flagged, profile
        if flagged:
            assert "CVE-2023-2431" in found[0].message and found[0].severity == Severity.MEDIUM
    # the pod level decides when the container sets no type
    del sc["seccompProfile"]
    doc["spec"]["template"]["spec"]["securityContext"] = {"seccompProfile": {"type": "Localhost"}}
    (pod_level,) = _findings(yaml.safe_dump(doc), "KN-S008")
    assert "CVE-2023-2431" in pod_level.message and pod_level.path.startswith("spec.template.spec.securityContext")


def test_sysctl_meta_characters_in_name_or_value() -> None:
    base = yaml.safe_load((FIX / "rules" / "KN-S022.yaml").read_text(encoding="utf-8"))["good"]
    doc = yaml.safe_load(base)
    psc = doc["spec"]["template"]["spec"]["securityContext"]
    for sysctl, flagged in (
        ({"name": "net.ipv4.ip_forward", "value": "1+0"}, True),
        ({"name": "net.ipv4.ip_forward", "value": "a=b"}, True),
        ({"name": "kernel.shm_rmid_forced+x", "value": "1"}, True),
        ({"name": "net.ipv4.ip_unprivileged_port_start", "value": "80"}, False),
    ):
        psc["sysctls"] = [sysctl]
        assert bool(_findings(yaml.safe_dump(doc), "KN-S022")) is flagged, sysctl


def test_working_directory_under_proc_in_manifests_and_containerfiles() -> None:
    base = yaml.safe_load((FIX / "rules" / "KN-S023.yaml").read_text(encoding="utf-8"))["good"]
    doc = yaml.safe_load(base)
    c = doc["spec"]["template"]["spec"]["containers"][0]
    for wd, flagged in (
        ("/proc", True),
        ("/proc/1/cwd", True),
        (" /proc/self/fd/7 ", True),
        ("/procs", False),
        ("/opt/proc", False),
    ):
        c["workingDir"] = wd
        assert bool(_findings(yaml.safe_dump(doc), "KN-S023")) is flagged, wd
    bad = cf.audit((FIX / "containerfile" / "KN-B011.bad.Containerfile").read_text(encoding="utf-8"))
    (hit,) = [f for f in bad["findings"] if f["ruleId"] == "KN-B011"]
    assert hit["severity"] == "high" and "CVE-2024-21626" in hit["message"] and hit["line"] == 8
    assert "CVE-2024-21626" in hit["fix"] and hit["sources"][0]["url"].startswith("https://github.com/advisories/")
    expanded = cf.audit(
        "ARG D=/proc/self/fd/7\nFROM registry.access.redhat.com/ubi9/ubi-minimal:9.6@sha256:" + "a" * 64 + "\n"
        "WORKDIR $D\nUSER 1001\nHEALTHCHECK NONE\n"
    )
    assert any(f["ruleId"] == "KN-B011" for f in expanded["findings"])
    fine = cf.audit((FIX / "containerfile" / "KN-B011.good.Containerfile").read_text(encoding="utf-8"))
    assert not any(f["ruleId"] == "KN-B011" for f in fine["findings"])
    assert cf.explain("KN-B011")["input"] == "Containerfile"


def _cves(version: tuple[int, int, int]) -> set[str]:
    return {c for a in rules_mod.INGRESS_NGINX_ADVISORIES if a.affects(version) for c in a.cves}


def test_ingress_nginx_releases_against_the_fixed_versions() -> None:
    v = rules_mod.ingress_nginx_version
    assert v("registry.k8s.io/ingress-nginx/controller:v1.11.4@sha256:" + "a" * 64) == (1, 11, 4)
    assert v("registry.k8s.io/ingress-nginx/controller-chroot:v1.12.1") == (1, 12, 1)
    assert v("ingress-nginx/controller:1.15.1") == (1, 15, 1)
    for unreadable in (
        "registry.k8s.io/ingress-nginx/controller:latest",
        "registry.k8s.io/ingress-nginx/controller@sha256:" + "a" * 64,
        "registry.k8s.io/ingress-nginx/controller:v1.12.0-beta.0",
        "quay.io/acme/controller:v1.11.4",
        "xingress-nginx/controller:v1.11.4",
    ):
        assert v(unreadable) is None, unreadable
    # CVE-2025-1974 (admission webhook RCE): < v1.11.0, v1.11.0-1.11.4 and v1.12.0 affected; fixed in v1.11.5, v1.12.1
    for affected in ((0, 49, 1), (1, 10, 4), (1, 11, 4), (1, 12, 0)):
        assert "CVE-2025-1974" in _cves(affected), affected
    for fixed in ((1, 11, 5), (1, 12, 1), (1, 13, 0)):
        assert "CVE-2025-1974" not in _cves(fixed), fixed
    assert _cves((1, 12, 1)) == {
        "CVE-2025-15566",
        "CVE-2026-1580",
        "CVE-2026-24512",
        "CVE-2026-24513",
        "CVE-2026-24514",
        "CVE-2026-3288",
        "CVE-2026-4342",
    }
    assert _cves((1, 13, 7)) == {"CVE-2026-3288", "CVE-2026-4342"} and _cves((1, 13, 8)) == {"CVE-2026-4342"}
    assert _cves((1, 14, 4)) == {"CVE-2026-4342"} and _cves((1, 15, 0)) == {"CVE-2026-4342"}
    assert _cves((1, 13, 9)) == _cves((1, 14, 5)) == _cves((1, 15, 1)) == _cves((1, 16, 0)) == _cves((2, 0, 0)) == set()
    # CVE-2024-7646: < v1.10.4 and < v1.11.2
    assert "CVE-2024-7646" in _cves((1, 10, 3)) and "CVE-2024-7646" not in _cves((1, 10, 4))
    assert "CVE-2024-7646" in _cves((1, 11, 1)) and "CVE-2024-7646" not in _cves((1, 11, 2))
    assert "CVE-2024-7646" not in _cves((1, 12, 0))
    # severity: critical only when the vulnerable release has the validating webhook on
    bad = yaml.safe_load((FIX / "rules" / "KN-S024.yaml").read_text(encoding="utf-8"))["bad"]
    (critical,) = _findings(bad, "KN-S024")
    assert critical.severity == Severity.CRITICAL and "v1.11.4" in critical.message
    assert "CVE-2025-1974" in critical.message and "v1.11.5, v1.12.1" in critical.message
    (high,) = _findings(bad.replace("--validating-webhook=:8443", "--watch-ingress-without-class"), "KN-S024")
    assert high.severity == Severity.HIGH
    (later,) = _findings(bad.replace("v1.11.4", "v1.12.1"), "KN-S024")
    assert later.severity == Severity.HIGH and "CVE-2025-1974" not in later.message
    assert _findings(bad.replace("v1.11.4", "v1.15.1"), "KN-S024") == []
    assert _findings(bad.replace("v1.11.4", "latest"), "KN-S024") == []
    # the retired-project rule fires on the controller image whatever its release
    assert _findings(bad.replace("v1.11.4", "v1.15.1"), "KN-V019")


def test_the_admission_regex_equals_the_release_table() -> None:
    regex = re.compile(rules_mod.ingress_nginx_vulnerable_tag_regex() + r"\Z")
    for major in (0, 1, 2):
        for minor in range(0, 60):
            for patch in range(0, 45):
                version = (major, minor, patch)
                assert bool(regex.match(f"{major}.{minor}.{patch}")) is bool(_cves(version)), version
    for n in (1, 2, 9, 10, 11, 19, 20, 21, 35, 99):
        lt = re.compile(rules_mod._lt(n) + r"\Z")
        assert {i for i in range(0, 120) if lt.match(str(i))} == set(range(n)), n
    with pytest.raises(ValueError):
        rules_mod._lt(100)


def test_risky_annotation_lists_match_the_annotations_risk_document() -> None:
    snippets = {"configuration-snippet", "auth-snippet", "modsecurity-snippet", "server-snippet", "stream-snippet"}
    assert snippets == rules_mod.INGRESS_NGINX_CRITICAL_ANNOTATIONS
    assert len(rules_mod.INGRESS_NGINX_HIGH_ANNOTATIONS) == 10
    assert not rules_mod.INGRESS_NGINX_CRITICAL_ANNOTATIONS & rules_mod.INGRESS_NGINX_HIGH_ANNOTATIONS
    text = (FIX / "rules" / "KN-N009.yaml").read_text(encoding="utf-8")
    good = yaml.safe_load(text)["good"]
    for short in sorted(rules_mod.INGRESS_NGINX_RISKY_ANNOTATIONS):
        doc = yaml.safe_load(good)
        doc["metadata"]["annotations"] = {rules_mod.INGRESS_NGINX_ANNOTATION_PREFIX + short: "x"}
        (f,) = _findings(yaml.safe_dump(doc), "KN-N009")
        want = Severity.HIGH if short in rules_mod.INGRESS_NGINX_CRITICAL_ANNOTATIONS else Severity.MEDIUM
        assert f.severity == want and short in f.message, short
        if short in rules_mod.INGRESS_NGINX_ANNOTATION_CVES:
            assert all(cve in f.message for cve, _ in rules_mod.INGRESS_NGINX_ANNOTATION_CVES[short]), short

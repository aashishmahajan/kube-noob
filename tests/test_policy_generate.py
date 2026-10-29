"""POL1: per-rule good/bad fixtures (R3.6) and generated VAP/Kyverno policies that admit the good and refuse the bad
(R3.1), checked offline with cel-python and on a real API server by the policy-kind CI job."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import build_context
from kube_noob.audit.model import Severity
from kube_noob.audit.rules import RULES
from kube_noob.cli import main
from kube_noob.generate import policies as pol
from kube_noob.yamlio import load_documents
from tests import policy_corpus
from tests.policy_cel import failures

RULE_FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PLATFORMS = (("kubernetes", None), ("openshift", "4.20"), ("rosa-hcp", "4.20"))


def _fixture(rule_id: str) -> dict[str, Any]:
    data = yaml.safe_load((RULE_FIXTURES / f"{rule_id}.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _audit_ids(text: str, platform: str, version: str | None) -> set[str]:
    docs = load_documents(text)
    ctx = build_context(docs, platform, version)
    found: set[str] = set()
    for rid, rule in RULES.items():
        if rule.check is not None and any(True for _ in rule.check(ctx, rule)):
            found.add(rid)
    return found


def _flags(doc: dict[str, Any], rule_id: str, platform: str, version: str | None) -> bool:
    """Does `kube-noob audit` report ``rule_id`` on this one object at low severity or above?"""
    docs = load_documents(yaml.safe_dump(doc, sort_keys=False))
    ctx = build_context(docs, platform, version)
    rule = RULES[rule_id]
    assert rule.check is not None
    return any(f.severity >= Severity.LOW for f in rule.check(ctx, rule))


def _policy(rule_id: str, platform: str, version: str | None, engine: pol.Engine = "vap") -> dict[str, Any]:
    c = pol.checks_for(platform, version)[rule_id]
    return pol.documents(c, engine, "enforce", platform)[0]


# --- R3.6: fixtures ----------------------------------------------------------------------------------------------


def test_every_rule_ships_a_good_and_a_bad_fixture() -> None:
    names = {p.stem for p in RULE_FIXTURES.glob("*.yaml")}
    assert names == set(RULES), f"missing {sorted(set(RULES) - names)}, unknown {sorted(names - set(RULES))}"
    for rid in RULES:
        data = _fixture(rid)
        assert data["rule"] == rid
        assert set(data) <= {"rule", "platform", "version", "good", "bad"}, rid
        assert data.get("good", "").strip() and data.get("bad", "").strip(), f"{rid} needs good and bad"


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_audit_flags_the_bad_fixture_and_not_the_good(rule_id: str) -> None:
    data = _fixture(rule_id)
    platform, version = data.get("platform", "kubernetes"), data.get("version")
    assert rule_id in _audit_ids(data["bad"], platform, version), "bad fixture not flagged"
    assert rule_id not in _audit_ids(data["good"], platform, version), "good fixture flagged"


# --- R3.1: every rule generated or explained ----------------------------------------------------------------------


def test_every_rule_is_generated_or_has_a_reason() -> None:
    generated: set[str] = set()
    for platform, version in PLATFORMS:
        checks = pol.checks_for(platform, version)
        assert not set(checks) & set(pol.NOT_GENERATED)
        generated |= set(checks)
    assert generated | set(pol.NOT_GENERATED) == set(RULES)
    assert not generated & set(pol.NOT_GENERATED)
    assert len(generated) >= 40


def test_documents_are_well_formed_for_both_engines_and_modes() -> None:
    for platform, version in PLATFORMS:
        for mode in pol.MODES:
            g = pol.generate(platform=platform, platform_version=version, mode=mode)
            keys = [(d["kind"], d["metadata"]["name"]) for d in g.documents]
            assert len(keys) == len(set(keys))
            for d in g.documents:
                assert d["metadata"]["name"].startswith("kube-noob-kn-")
                if d["kind"] == "ValidatingAdmissionPolicyBinding":
                    actions = d["spec"]["validationActions"]
                    assert actions == (["Deny"] if mode == "enforce" else ["Warn", "Audit"])
                    continue
                spec = d["spec"]
                assert d["apiVersion"] in {"admissionregistration.k8s.io/v1", "policies.kyverno.io/v1"}
                ann = d["metadata"]["annotations"]
                assert ann["kube-noob.io/rule"].startswith("KN-") and ann["kube-noob.io/fix"]
                for v in spec["validations"]:
                    assert "\n" not in v["message"] and v["message"].startswith(f"[{ann['kube-noob.io/rule']}]")
                    assert "Fix:" in v["message"]
                if d["kind"] == "ValidatingPolicy":
                    assert spec["validationActions"] == (["Deny"] if mode == "enforce" else ["Audit", "Warn"])
                    assert spec["evaluation"] == {"background": {"enabled": False}}
                else:
                    assert spec["failurePolicy"] == ("Fail" if mode == "enforce" else "Ignore")
            text = g.yaml(pol.header(g, platform=platform, platform_version=version, mode=mode, engines=pol.ENGINES))
            assert len(list(yaml.safe_load_all(text))) == len(g.documents)


def test_engines_carry_the_same_cel() -> None:
    for platform, version in PLATFORMS:
        for rid, c in pol.checks_for(platform, version).items():
            vap = pol.documents(c, "vap", "audit", platform)[0]["spec"]
            kyv = pol.documents(c, "kyverno", "audit", platform)[0]["spec"]
            for key in ("matchConstraints", "variables", "validations"):
                assert vap[key] == kyv[key], (rid, key)


# --- R3.1 acceptance, offline: the generated policy admits the good fixture and refuses the bad one --------------


def _fixture_cases() -> list[tuple[str, str, str | None]]:
    out = []
    for rid in sorted(RULES):
        data = _fixture(rid)
        platform, version = data.get("platform", "kubernetes"), data.get("version")
        if rid in pol.checks_for(platform, version):
            out.append((rid, platform, version))
    return out


@pytest.mark.parametrize(("rule_id", "platform", "version"), _fixture_cases())
@pytest.mark.parametrize("engine", pol.ENGINES)
def test_policy_admits_good_and_refuses_bad(
    rule_id: str, platform: str, version: str | None, engine: pol.Engine
) -> None:
    data = _fixture(rule_id)
    policy = _policy(rule_id, platform, version, engine)
    good = [d for d in yaml.safe_load_all(data["good"]) if d]
    bad = [d for d in yaml.safe_load_all(data["bad"]) if d]
    for d in good:
        assert failures(policy, d) == [], f"good {d['kind']} refused"
    refused = [f for d in bad for f in failures(policy, d)]
    assert refused, "bad fixture admitted"
    assert all(f.startswith(f"[{rule_id}]") for f in refused)


def test_fixture_cases_cover_all_generated_rules() -> None:
    covered = {rid for rid, _, _ in _fixture_cases()}
    generated = set().union(*(pol.checks_for(p, v) for p, v in PLATFORMS))
    assert covered == generated


# --- the policies decide exactly as the audit does, on 1,800 random objects per platform --------------------------


@pytest.mark.parametrize(("platform", "version"), PLATFORMS)
def test_policy_equals_audit_on_random_objects(platform: str, version: str | None) -> None:
    checks = pol.checks_for(platform, version)
    corpus = policy_corpus.corpus(seed=20261028, n=900, openshift=platform != "kubernetes")
    policies = {rid: pol.documents(c, "vap", "enforce", platform)[0] for rid, c in checks.items()}
    mismatches: list[str] = []
    seen: dict[str, list[int]] = {rid: [0, 0] for rid in checks}
    for i, doc in enumerate(corpus):
        ctx = build_context(load_documents(yaml.safe_dump(doc, sort_keys=False)), platform, version)
        cache: dict[tuple[str, str], Any] = {}
        for rid, policy in policies.items():
            c = checks[rid]
            if doc["kind"] not in c.kinds or rid == "KN-C009":
                continue
            refused = bool(failures(policy, doc, cache=cache))
            rule = RULES[rid]
            assert rule.check is not None
            flagged = any(f.severity >= Severity.LOW for f in rule.check(ctx, rule))
            seen[rid][int(refused)] += 1
            ok = refused == flagged if c.coverage == "full" else (not refused or flagged)
            if not ok:
                mismatches.append(f"{rid} doc {i} policy={refused} audit={flagged}: {json.dumps(doc)[:400]}")
    assert not mismatches, "\n".join(mismatches[:10])
    # the corpus reaches both outcomes for every rule (V008/V017 refuse every object of their kind)
    for rid, (admitted, refused) in seen.items():
        if rid == "KN-C009":
            continue
        assert refused > 0, f"{rid} never refused"
        if rid not in {"KN-V008", "KN-V017"}:
            assert admitted > 0, f"{rid} never admitted"


def test_c009_refuses_only_what_the_audit_flags_with_two_replicas() -> None:
    policy = _policy("KN-C009", "kubernetes", None)
    rng = random.Random(7)
    pdbs = [policy_corpus.pdb(rng, i) for i in range(80)]
    outcomes = {bool(failures(policy, p)) for p in pdbs}
    assert outcomes == {True, False}
    for pdb in pdbs:
        workload = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "w", "namespace": "shop"},
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": {"app": "w"}},
                "template": {
                    "metadata": {"labels": {"app": "w"}},
                    "spec": {"containers": [{"name": "w", "image": "w"}]},
                },
            },
        }
        text = yaml.safe_dump_all([workload, pdb])
        if failures(policy, pdb):
            assert "KN-C009" in _audit_ids(text, "kubernetes", None), pdb


# --- exemptions --------------------------------------------------------------------------------------------------


def test_exemptions_platform_namespaces_operators_owned_objects_and_system_roles() -> None:
    bad = yaml.safe_load(_fixture("KN-S001")["bad"])
    s001 = _policy("KN-S001", "openshift", "4.20")
    assert failures(s001, bad)
    for ns in ("kube-system", "openshift", "openshift-monitoring"):
        assert failures(s001, {**bad, "metadata": {**bad["metadata"], "namespace": ns}}) == [], ns
    assert failures(s001, bad, username="system:serviceaccount:openshift-cluster-version:default") == []
    assert failures(s001, bad, username="system:serviceaccount:shop:deployer")
    k8s = _policy("KN-S001", "kubernetes", None)
    assert failures(k8s, {**bad, "metadata": {**bad["metadata"], "namespace": "openshift-x"}})
    # security rules never honour ownerReferences; calibrate rules skip controller-owned objects
    owned_meta = {
        **bad["metadata"],
        "ownerReferences": [
            {"apiVersion": "apps/v1", "kind": "Deployment", "name": "w", "uid": "1", "controller": True}
        ],
    }
    assert failures(s001, {**bad, "metadata": owned_meta})
    c007 = _policy("KN-C007", "kubernetes", None)
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {"name": "w-1", "namespace": "shop"},
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"a": "b"}},
            "template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": []}},
        },
    }
    assert failures(c007, rs)
    assert (
        failures(c007, {**rs, "metadata": {**rs["metadata"], "ownerReferences": owned_meta["ownerReferences"]}}) == []
    )
    role = yaml.safe_load(_fixture("KN-S015")["bad"])
    s015 = _policy("KN-S015", "kubernetes", None)
    assert failures(s015, role)
    assert failures(s015, {**role, "metadata": {**role["metadata"], "name": "system:aggregate"}}) == []
    # namespaces the user excludes join the defaults
    g = pol.generate(rules=["KN-S001"], engines=("vap",), exclude_namespaces=["legacy"])
    assert failures(g.documents[0], {**bad, "metadata": {**bad["metadata"], "namespace": "legacy"}}) == []


def test_v008_refuses_new_deploymentconfigs_only() -> None:
    c = pol.checks_for("openshift", "4.20")["KN-V008"]
    assert c.operations == ("CREATE",)
    assert "KN-V008" not in pol.checks_for("openshift", "4.13")
    assert pol.checks_for("rosa-hcp", "4.20")["KN-V017"]
    assert "KN-V017" not in pol.checks_for("openshift", "4.20")
    assert "KN-S004" not in pol.checks_for("kubernetes", None)
    assert "DeploymentConfig" in pol.checks_for("openshift", "4.20")["KN-S001"].kinds
    assert "DeploymentConfig" not in pol.checks_for("kubernetes", None)["KN-S001"].kinds


def test_generate_validates_input() -> None:
    with pytest.raises(ValueError, match="unknown rule"):
        pol.generate(rules=["KN-X999"])
    with pytest.raises(ValueError, match="engines"):
        pol.generate(engines=("gatekeeper",))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mode"):
        pol.generate(mode="block")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="namespace"):
        pol.generate(exclude_namespaces=["Bad_NS"])
    g = pol.generate(rules=["kn-v009", "KN-S001"], engines=("kyverno",))
    assert [r["ruleId"] for r in g.generated] == ["KN-S001"]
    assert g.skipped == [{"ruleId": "KN-V009", "reason": pol.NOT_GENERATED["KN-V009"]}]


# --- CLI and MCP -------------------------------------------------------------------------------------------------


def test_cli_policy_generate_writes_yaml_and_reports_skips(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "policies.yaml"
    rc = main(
        [
            "policy",
            "generate",
            "--platform",
            "openshift",
            "--version",
            "4.20",
            "--mode",
            "enforce",
            "--engine",
            "vap",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Generated by kube-noob")
    docs = [d for d in yaml.safe_load_all(text) if d]
    assert {d["kind"] for d in docs} == {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
    err = capsys.readouterr()
    assert "policies" in err.out and "not generated" in err.out
    rc = main(
        ["--format", "json", "policy", "generate", "--rule", "KN-S001", "--rule", "KN-V009", "--engine", "kyverno"]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["generated"][0]["ruleId"] == "KN-S001"
    assert report["skipped"][0]["ruleId"] == "KN-V009"
    assert yaml.safe_load(report["yaml"].split("---\n", 1)[1])["kind"] == "ValidatingPolicy"


def test_mcp_tool_policy_generate() -> None:
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    kit = tk.Toolkit(load_settings())
    spec = next(s for s in kit.specs() if s.name == "policy_generate")
    assert spec.read_only
    out = kit.policy_generate(tk.PolicyGenerateIn(platform="kubernetes", rules=["KN-S001"], engines=["vap"]))
    assert out["generated"] == [{"ruleId": "KN-S001", "engine": "vap", "name": "kube-noob-kn-s001", "coverage": "full"}]
    with pytest.raises(ValueError):
        tk.PolicyGenerateIn(rules=["x" * 200])

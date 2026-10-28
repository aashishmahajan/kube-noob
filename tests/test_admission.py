"""ADM1 (R3.3): the kube-noob-admission webhook. Warn mode never denies (fuzzed), enforce denies only the listed rules,
it never mutates, a broken input is admitted, and it answers well under 50 ms."""

from __future__ import annotations

import copy
import json
import random
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import admission as adm
from kube_noob.audit.engine import analyze
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "tests" / "fixtures" / "rules"


def _fixtures() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for path in sorted(RULES.glob("KN-*.yaml")):
        data = yaml.safe_load(path.read_text())
        for which in ("good", "bad"):
            for doc in yaml.safe_load_all(data[which]):
                if isinstance(doc, dict) and doc.get("kind"):
                    out.append((data["rule"], which, doc))
    return out


FIXTURES = _fixtures()


def _review(obj: Any, op: str = "CREATE", ns: str | None = None, old: Any = None, **extra: Any) -> dict[str, Any]:
    meta = obj.get("metadata") if isinstance(obj, dict) and isinstance(obj.get("metadata"), dict) else {}
    req: dict[str, Any] = {
        "uid": "0b1c2d3e-uid",
        "kind": {"group": "", "version": "v1", "kind": obj.get("kind") if isinstance(obj, dict) else "x"},
        "resource": {"group": "", "version": "v1", "resource": "x"},
        "namespace": ns if ns is not None else str(meta.get("namespace") or "shop"),
        "operation": op,
        "userInfo": {"username": "dev"},
        "object": obj,
        **extra,
    }
    if old is not None:
        req["oldObject"] = old
    return {"apiVersion": adm.API_VERSION, "kind": "AdmissionReview", "request": req}


def _well_formed(out: dict[str, Any], cfg: adm.Config) -> dict[str, Any]:
    assert out["apiVersion"] == adm.API_VERSION and out["kind"] == "AdmissionReview"
    r = out["response"]
    assert "patch" not in r and "patchType" not in r, "never mutates"
    assert all(len(w) <= adm.WARNING_CHARS for w in r.get("warnings", []))
    assert len(r.get("warnings", [])) <= cfg.max_warnings + 1
    return dict(r)


# -- warn mode -------------------------------------------------------------------------------------------------------

_JUNK: list[Any] = [None, "", "x" * 5000, 0, -1, 2**63, 1.5, True, [], {}, ["a"], {"a": {"b": [1, {}]}}, "\u202e\u0000"]


def _mutate(rng: random.Random, value: Any, depth: int = 0) -> Any:
    if depth > 6 or rng.random() < 0.15:
        return copy.deepcopy(rng.choice(_JUNK))
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            roll = rng.random()
            if roll < 0.08:
                continue  # drop a key
            out[k] = _mutate(rng, v, depth + 1) if roll < 0.4 else v
        if rng.random() < 0.1:
            out[rng.choice(["privileged", "hostPID", "image", "spec", "metadata", "ownerReferences"])] = rng.choice(
                _JUNK
            )
        return out
    if isinstance(value, list):
        out_list = [(_mutate(rng, v, depth + 1) if rng.random() < 0.4 else v) for v in value]
        if rng.random() < 0.1:
            out_list = out_list * rng.randint(2, 30)
        return out_list
    return value


def test_warn_mode_never_denies_fuzzed() -> None:
    cfg = adm.Config.build(platform="openshift", version="4.20")
    seen_warnings = 0
    for seed in range(1500):
        rng = random.Random(seed)
        _, _, base = rng.choice(FIXTURES)
        obj = _mutate(rng, copy.deepcopy(base))
        op = rng.choice(["CREATE", "UPDATE", "CREATE", "DELETE", "CONNECT", "", None, 7])
        old = _mutate(rng, copy.deepcopy(base)) if op == "UPDATE" else None
        doc = _review(obj if isinstance(obj, dict) else {"kind": "x"}, str(op), old=old)
        if rng.random() < 0.05:
            doc["request"]["object"] = rng.choice(_JUNK)
        if rng.random() < 0.05:
            doc["request"] = rng.choice(_JUNK)
        r = _well_formed(adm.review(doc, cfg), cfg)
        assert r["allowed"] is True, (seed, r)
        seen_warnings += bool(r.get("warnings"))
    assert seen_warnings > 300, "the fuzz reached the rules, not only the input checks"
    for body in (b"", b"{", b"[1]", b"null", b"[" * 200_000, b'{"request": 5}', b"\xff\xfe"):
        r = _well_formed(adm.review_bytes(body, cfg), cfg)
        assert r["allowed"] is True
    big = json.dumps(_review({"kind": "Pod", "x": "y" * (adm.MAX_BODY + 1)})).encode()
    assert adm.review_bytes(big, cfg)["response"]["allowed"] is True


def test_every_bad_fixture_warns_and_is_admitted() -> None:
    cfg = adm.Config.build(platform="openshift", version="4.20")
    for rule, which, doc in FIXTURES:
        if which != "bad" or rule in adm.SKIPPED_RULES | adm.CROSS_OBJECT:
            continue
        ns = (doc.get("metadata") or {}).get("namespace") or "shop"
        r = _well_formed(adm.review(_review(doc, ns=ns), cfg), cfg)
        assert r["allowed"] is True
        single = {f.rule_id for f in analyze(yaml.safe_dump(doc), platform="openshift", version="4.20").findings}
        if rule in single:
            assert any(w.startswith(f"[{rule}]") for w in r.get("warnings", [])), (rule, r.get("warnings"))


# -- enforce ---------------------------------------------------------------------------------------------------------


ENFORCEABLE = sorted(
    {rule for rule, _, _ in FIXTURES} - adm.SKIPPED_RULES - adm.CROSS_OBJECT - {"KN-V015", "KN-V017", "KN-N006"}
)


@pytest.mark.parametrize("rule", ENFORCEABLE)
def test_enforce_denies_only_the_listed_rule(rule: str) -> None:
    data = yaml.safe_load((RULES / f"{rule}.yaml").read_text())
    platform, version = data.get("platform", "openshift"), str(data.get("version", "4.20"))
    cfg = adm.Config.build(enforce=[rule], platform=platform, version=version)
    denied_bad = False
    for which in ("good", "bad"):
        for doc in [d for d in yaml.safe_load_all(data[which]) if isinstance(d, dict)]:
            ns = (doc.get("metadata") or {}).get("namespace") or "shop"
            r = _well_formed(adm.review(_review(doc, ns=ns), cfg), cfg)
            single = {f.rule_id for f in analyze(yaml.safe_dump(doc), platform=platform, version=version).findings}
            if rule in single and which == "bad":
                assert r["allowed"] is False, (rule, doc.get("kind"))
                assert f"[{rule}]" in r["status"]["message"] and r["status"]["code"] == 403
                assert r["status"]["message"].endswith(f"(enforced rules: {rule})")
                denied_bad = True
            elif rule not in single:
                assert r["allowed"] is True, (rule, which, r)
    assert denied_bad, f"{rule}: the bad fixture was not denied"


def test_update_denies_only_new_findings_and_skips(tmp_path: Path) -> None:
    data = yaml.safe_load((RULES / "KN-S001.yaml").read_text())
    good, bad = yaml.safe_load(data["good"]), yaml.safe_load(data["bad"])
    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift", version="4.20")
    assert adm.review(_review(bad, "UPDATE", old=good), cfg)["response"]["allowed"] is False
    kept = adm.review(_review(bad, "UPDATE", old=bad), cfg)["response"]
    assert kept["allowed"] is True and any(w.startswith("[KN-S001]") for w in kept["warnings"]), "warned, not frozen"
    for case in (
        _review(bad, "DELETE"),
        _review(bad, "CONNECT"),
        _review(bad, subResource="status"),
        _review(bad, ns="kube-system"),
        _review(bad, ns="openshift-monitoring"),
        _review(bad, ns="openshift"),
    ):
        r = adm.review(case, cfg)["response"]
        assert r == {"uid": "0b1c2d3e-uid", "allowed": True}, case["request"].get("namespace")
    gone = copy.deepcopy(bad)
    gone["metadata"]["deletionTimestamp"] = "2026-10-28T00:00:00Z"
    assert adm.review(_review(gone), cfg)["response"] == {"uid": "0b1c2d3e-uid", "allowed": True}
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p", "namespace": "shop"},
        "spec": bad["spec"]["template"]["spec"],
    }
    assert adm.review(_review(pod), cfg)["response"]["allowed"] is False, "a bare Pod is checked"
    owned = copy.deepcopy(pod)
    owned["metadata"]["ownerReferences"] = [
        {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "x", "uid": "1", "controller": True}
    ]
    assert adm.review(_review(owned), cfg)["response"] == {"uid": "0b1c2d3e-uid", "allowed": True}
    mine = adm.Config.build(enforce=["KN-S001"], excluded=["shop"], platform="openshift")
    assert adm.review(_review(bad), mine)["response"]["allowed"] is True
    gen = copy.deepcopy(bad)
    gen["metadata"].pop("name")
    gen["metadata"]["generateName"] = "web-"
    assert adm.review(_review(gen), cfg)["response"]["allowed"] is False, "generateName objects are checked too"


def test_config_and_exceptions(tmp_path: Path) -> None:
    for kwargs, msg in (
        ({"enforce": ["KN-X999"]}, "unknown rules"),
        ({"enforce": ["KN-N001"]}, "cannot enforce KN-N001"),
        ({"enforce": ["KN-S018"]}, "cannot enforce KN-S018"),
        ({"max_warnings": 0}, "1-50"),
    ):
        with pytest.raises(adm.AdmissionConfigError, match=msg):
            adm.Config.build(**kwargs)  # type: ignore[arg-type]
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    today = time.strftime("%Y-%m-%d")
    later = f"{int(today[:4]) + 1}{today[4:]}"
    exc = (
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n- id: EXC-1\n  rule: KN-S001\n"
        "  scope: {namespace: shop, kind: Deployment, name: web}\n  owner: team-web\n"
        f"  reason: The web tier needs it until the move\n  expires: {later}\n"
    )
    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift", exceptions_text=exc)
    r = adm.review(_review(bad), cfg)["response"]
    assert r["allowed"] is True and not any(w.startswith("[KN-S001]") for w in r.get("warnings", []))
    other = copy.deepcopy(bad)
    other["metadata"]["name"] = "api"
    assert adm.review(_review(other), cfg)["response"]["allowed"] is False, "the exception covers web only"
    with pytest.raises(adm.AdmissionConfigError, match="refused entries"):
        adm.Config.build(exceptions_text=exc.replace("  owner: team-web\n", ""))


def test_warning_cap_and_truncation() -> None:
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    bad["spec"]["template"]["spec"]["containers"][0]["name"] = "c" * 300
    cfg = adm.Config.build(max_warnings=2, platform="openshift")
    r = _well_formed(adm.review(_review(bad), cfg), cfg)
    assert len(r["warnings"]) == 3 and r["warnings"][-1].startswith("kube-noob: ")
    assert any(w.endswith("...") for w in r["warnings"])


# -- lookups ---------------------------------------------------------------------------------------------------------


class _Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def get(self, resource: str, namespace: str | None = None) -> dict[str, Any]:
        self.calls.append((resource, namespace))
        if resource == "poddisruptionbudgets" and namespace == "shop":
            return {
                "items": [
                    {
                        "apiVersion": "policy/v1",
                        "metadata": {"name": "web", "namespace": "shop"},
                        "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}},
                    }
                ]
            }
        if resource == "networkpolicies":
            raise PermissionError("forbidden")
        return {"items": []}


def test_lookups_fill_cross_object_rules_without_blocking() -> None:
    good = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["good"])
    backend, pauses = _Backend(), []
    lookups = adm.Lookups(backend, sleep=pauses.append, rng=random.Random(7))
    cfg = adm.Config.build(platform="openshift", lookups=True)
    first = adm.review(_review(good), cfg, lookups)["response"]
    assert any(w.startswith("[KN-C008]") for w in first["warnings"]), "no context yet: the PDB is not known"
    assert backend.calls == [], "a request never waits for the API server"
    lookups.refresh()
    assert ("poddisruptionbudgets", "shop") in backend.calls and ("storageclasses", None) in backend.calls
    assert pauses and all(0.05 <= p <= 0.2 for p in pauses) and len(set(pauses)) > 1, "jittered"
    assert any("networkpolicies in shop" in e for e in lookups.errors)
    after = adm.review(_review(good), cfg, lookups)["response"]
    assert not any(w.startswith("[KN-C008]") for w in after.get("warnings", [])), "the cached PDB counts"
    off = adm.Config.build(platform="openshift")
    assert not any(w.startswith("[KN-C008]") for w in adm.review(_review(good), off)["response"].get("warnings", []))


# -- server, speed, CLI ----------------------------------------------------------------------------------------------


def test_asgi_app_metrics_and_limits() -> None:
    from starlette.testclient import TestClient

    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift")
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    client = TestClient(adm.app(cfg))
    r = client.post("/validate", json=_review(bad))
    assert r.status_code == 200 and r.json()["response"]["allowed"] is False
    assert client.post("/validate", content=b"nope").json()["response"]["allowed"] is True
    huge = client.post("/validate", content=b"x", headers={"content-length": str(adm.MAX_BODY + 1)})
    assert huge.json()["response"]["allowed"] is True
    assert client.get("/validate").status_code == 405
    assert client.get("/healthz").text == "ok\n" and client.get("/readyz").status_code == 200
    m = client.get("/metrics").text
    assert 'kube_noob_admission_requests_total{outcome="denied"} 1' in m
    assert 'kube_noob_admission_duration_seconds_bucket{le="+Inf"} 3' in m


def test_p99_well_under_50_ms() -> None:
    cfg = adm.Config.build(platform="openshift", version="4.20")
    cases = [_review(doc) for _, which, doc in FIXTURES if which == "bad"][:60]
    times = []
    for _ in range(5):
        for c in cases:
            t0 = time.perf_counter()
            adm.review(c, cfg)
            times.append(time.perf_counter() - t0)
    times.sort()
    p99 = times[int(len(times) * 0.99) - 1]
    assert p99 < 0.05, f"p99 {p99 * 1000:.1f} ms"


def test_cli_review(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    f = tmp_path / "review.json"
    f.write_text(json.dumps(_review(bad)))
    assert main(["admission", "review", "-f", str(f)]) == 0
    assert json.loads(capsys.readouterr().out)["response"]["allowed"] is True
    assert main(["admission", "review", "-f", str(f), "--enforce", "KN-S001"]) == 1
    capsys.readouterr()
    assert main(["admission", "review", "-f", str(f), "--enforce", "KN-C008"]) == 2
    cert = tmp_path / "missing.crt"
    assert main(["admission", "serve", "--tls-cert", str(cert), "--tls-key", str(cert)]) == 2

"""R3.7: RHACS policies mapped to kube-noob rules, with every difference explained, and Central read GET-only."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob import rhacs, rhacs_central
from kube_noob import toolkit as tk
from kube_noob.audit.rules import RULES
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ConfigError, DomainNotAllowedError, WebDisabledError
from kube_noob.net import Purpose, http_client

EXPORT = Path(__file__).parent / "fixtures" / "rhacs" / "default-policies-export.json"
ENDPOINT = "https://central.stackrox.svc"
TOKEN = "rox-test-token-0123456789"


def _policies() -> list[dict[str, Any]]:
    return rhacs.load(EXPORT.read_text(encoding="utf-8"))


def _by_name(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["name"]: row for row in out["policies"]}


def _policy(name: str, *groups: tuple[str, list[str]], **extra: Any) -> dict[str, Any]:
    return {
        "id": "custom-1",
        "name": name,
        "severity": "HIGH_SEVERITY",
        "policySections": [
            {"policyGroups": [{"fieldName": f, "values": [{"value": v} for v in vals]} for f, vals in groups]}
        ],
        **extra,
    }


def test_every_default_policy_is_explained() -> None:
    out = rhacs.compare(_policies())
    assert out["total"] == 89
    assert out["unexplained"] == [], out["unexplained"]
    assert sum(out["counts"].values()) == out["total"]
    assert out["counts"]["unexplained"] == 0
    assert all(row["reason"] for row in out["policies"])


def test_every_cited_default_policy_exists_in_the_export() -> None:
    names = {p["name"] for p in _policies()}
    cited = {(rid, n) for rid, r in RULES.items() for n in r.stackrox_policies}
    missing = sorted(f"{rid}: {n}" for rid, n in cited if n not in names)
    assert not missing, f"rules cite RHACS default policies that do not exist: {missing}"


def test_known_mappings_and_differences() -> None:
    rows = _by_name(rhacs.compare(_policies()))
    assert rows["Privileged Container"]["outcome"] == "overlap"
    assert rows["Privileged Container"]["rules"] == ["KN-S001"]
    assert any("severity: RHACS medium, kube-noob KN-S001 critical" in n for n in rows["Privileged Container"]["notes"])
    exposed = rows["Deployments with externally exposed endpoints"]
    assert exposed["rules"] == ["KN-N002", "KN-N004", "KN-N005", "KN-S011"]
    assert rows["Kubernetes Actions: Exec into Pod"]["outcome"] == "related"
    assert rows["Kubernetes Actions: Exec into Pod"]["rules"] == ["KN-S017"]
    assert rows["Docker CIS 5.1 Ensure that, if applicable, an AppArmor Profile is enabled"]["outcome"] == "gap"
    assert rows["Curl in Image"]["outcome"] == "outside"
    assert rows["Process with UID 0"]["outcome"] == "outside"
    mixed = rows["Fixable CVSS >= 6 and Privileged"]
    assert mixed["outcome"] == "related" and mixed["rules"] == ["KN-S001"]
    assert "deploy-time part (Privileged Container)" in mixed["reason"]
    assert rows["Pod Service Account Token Automatically Mounted"]["rules"] == ["KN-S014"]
    assert any("scopes it by" in n for n in rows["Pod Service Account Token Automatically Mounted"]["notes"])


def test_disagreement_and_disabled_defaults_are_listed() -> None:
    out = rhacs.compare(_policies())
    assert out["disagreements"] == ["Secret Mounted as Environment Variable"]
    row = _by_name(out)["Secret Mounted as Environment Variable"]
    assert row["disagrees"] is True and "disagree" in row["notes"][0]
    assert "Drop All Capabilities" in out["disabledButCheckedByKubeNoob"]
    assert "KN-S001" not in out["kubeNoobOnly"] and "KN-ST001" in out["kubeNoobOnly"]


def test_unknown_criteria_are_unexplained_not_guessed() -> None:
    row = rhacs.compare_one(_policy("Future check", ("Quantum Sidecar Count", [">2"])))
    assert row.outcome == "unexplained" and "Quantum Sidecar Count" in row.reason
    scope_only = rhacs.compare_one(_policy("Only a namespace", ("Namespace", ["shop"])))
    assert scope_only.outcome == "unexplained" and "no criteria" in scope_only.reason
    empty = rhacs.compare_one({"name": "No sections"})
    assert empty.outcome == "unexplained"


def test_custom_policies_map_by_criteria_and_values() -> None:
    lb = rhacs.compare_one(_policy("Only load balancers", ("Port Exposure Method", ["EXTERNAL"])))
    assert lb.outcome == "overlap" and lb.rules == ("KN-N004",)
    internal = rhacs.compare_one(_policy("Internal only", ("Port Exposure Method", ["INTERNAL"])))
    assert internal.rules == () and internal.outcome == "unexplained"
    both = rhacs.compare_one(
        _policy("Privileged no AppArmor", ("Privileged Container", ["true"]), ("AppArmor Profile", ["unconfined"]))
    )
    assert both.outcome == "overlap" and "no kube-noob rule for an AppArmor profile" in both.reason
    enforced = rhacs.compare_one(
        _policy("Block latest", ("Image Tag", ["latest"]), enforcementActions=["SCALE_TO_ZERO_ENFORCEMENT"])
    )
    assert enforced.rules == ("KN-S012",)
    assert any("RHACS enforces it (SCALE_TO_ZERO_ENFORCEMENT)" in n for n in enforced.notes)


def test_malformed_parts_are_skipped() -> None:
    weird = {
        "name": "Broken",
        "policySections": ["x", None, {"policyGroups": "nope"}, {"policyGroups": [None, {"fieldName": 3}]}],
        "lifecycleStages": "DEPLOY",
        "enforcementActions": "nope",
    }
    row = rhacs.compare_one(weird)
    assert row.outcome == "unexplained" and row.lifecycle == ()


def test_load_accepts_export_list_or_one_policy_and_refuses_the_rest() -> None:
    one = _policy("Latest", ("Image Tag", ["latest"]))
    assert len(rhacs.load(json.dumps({"policies": [one]}))) == 1
    assert len(rhacs.load(json.dumps([one]))) == 1
    assert len(rhacs.load(json.dumps(one))) == 1
    for bad in ("not json", "{}", "[]", '{"policies": [1, 2]}', json.dumps({"policies": [{"id": "x"}]})):
        with pytest.raises(rhacs.RhacsError):
            rhacs.load(bad)
    with pytest.raises(rhacs.RhacsError, match="more than"):
        rhacs.load(json.dumps([one] * (rhacs.MAX_POLICIES + 1)))
    with pytest.raises(rhacs.RhacsError, match="not JSON"):
        rhacs.load("[" * 100_000)


def test_cli_compare(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["rhacs", "compare", "-f", str(EXPORT), "--format", "text", "--outcome", "gap"]) == 0
    text = capsys.readouterr().out
    assert "89 RHACS policies: 20 overlap, 9 related, 4 gap, 56 outside kube-noob's scope, 0 unexplained" in text
    assert "[gap        ] Secure Shell (ssh) Port Exposed" in text and "[overlap" not in text
    assert main(["rhacs", "compare", "-f", str(EXPORT), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["source"] == {"file": str(EXPORT)} and data["counts"]["overlap"] == 20
    custom = tmp_path / "custom.json"
    custom.write_text(json.dumps({"policies": [_policy("Future", ("Quantum Sidecar Count", ["1"]))]}))
    assert main(["rhacs", "compare", "-f", str(custom)]) == 1, "an unexplained policy fails the command"
    capsys.readouterr()
    assert main(["rhacs", "compare"]) == 2
    assert main(["rhacs", "compare", "--live"]) == 4, "live needs rhacs.enabled"
    err = capsys.readouterr().err
    assert "rhacs.enabled" in err


def test_mcp_tools() -> None:
    kit = tk.Toolkit(load_settings())
    names = {t.name for t in kit.specs()}
    assert "rhacs_compare" in names and "rhacs_compare_live" not in names
    out = kit.rhacs_compare(tk.RhacsCompareIn(policies=EXPORT.read_text(encoding="utf-8"), outcomes=["gap"]))
    assert out["total"] == 89 and {r["outcome"] for r in out["policies"]} == {"gap"}
    with pytest.raises(ValueError, match="not an RHACS policy export"):
        kit.rhacs_compare(tk.RhacsCompareIn(policies='{"kind": "Pod"}'))
    live = tk.Toolkit(load_settings(overrides={"rhacs": {"enabled": True, "endpoint": ENDPOINT}}))
    assert "rhacs_compare_live" in {t.name for t in live.specs()}


# -- live: GET only, one host, jittered, token only to Central -----------------------------------------------------


def _settings(**rh: Any) -> Any:
    return load_settings(overrides={"rhacs": {"enabled": True, "endpoint": ENDPOINT, **rh}})


class _Central:
    def __init__(self, policies: list[dict[str, Any]], status: int = 200) -> None:
        self.by_id = {p["id"]: p for p in policies}
        self.status = status
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "denied"})
        if req.url.path == "/v1/policies":
            listed = [{"id": pid, "name": p["name"]} for pid, p in self.by_id.items()]
            return httpx.Response(200, json={"policies": [*listed, {"id": "../etc/passwd"}, {"name": "no id"}]})
        pid = req.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=self.by_id[pid])


def test_read_central(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROX_API_TOKEN", TOKEN)
    central = _Central(_policies()[:5])
    pauses: list[float] = []
    items, source = rhacs_central.read_central(_settings(), transport=httpx.MockTransport(central), sleep=pauses.append)
    assert len(items) == 5 and source["requests"] == 6 and source["skipped"] == 2
    assert {r.method for r in central.seen} == {"GET"}
    assert {r.url.host for r in central.seen} == {"central.stackrox.svc"}
    assert all(r.headers["authorization"] == f"Bearer {TOKEN}" for r in central.seen)
    assert len(pauses) == 5 and all(0.1 <= p <= 0.3 for p in pauses) and len(set(pauses)) > 1, "jittered pacing"
    assert rhacs.compare(items)["total"] == 5


def test_read_central_bounds_and_refusals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROX_API_TOKEN", TOKEN)
    items, source = rhacs_central.read_central(
        _settings(maxPolicies=2), transport=httpx.MockTransport(_Central(_policies()[:5])), sleep=lambda _: None
    )
    assert len(items) == 2 and source["requests"] == 3
    with pytest.raises(rhacs.RhacsError, match="Analyst"):
        rhacs_central.read_central(
            _settings(), transport=httpx.MockTransport(_Central([], status=403)), sleep=lambda _: None
        )
    redirect = httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": "https://evil.example.com/"}))
    with pytest.raises(rhacs.RhacsError, match="HTTP 302"):
        rhacs_central.read_central(_settings(), transport=redirect, sleep=lambda _: None)

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=req)

    with pytest.raises(rhacs.RhacsError) as err:
        rhacs_central.read_central(_settings(), transport=httpx.MockTransport(boom), sleep=lambda _: None)
    assert TOKEN not in str(err.value) and "ConnectError" in str(err.value)


def test_token_is_required_and_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROX_API_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="Set ROX_API_TOKEN"):
        rhacs_central.read_central(_settings())
    monkeypatch.setenv("ROX_API_TOKEN", "two words")
    with pytest.raises(ConfigError, match="does not look like"):
        rhacs_central.read_central(_settings())
    monkeypatch.setenv("KUBE_NOOB_ROX", TOKEN)
    central = _Central(_policies()[:1])
    rhacs_central.read_central(
        _settings(tokenEnv="KUBE_NOOB_ROX"), transport=httpx.MockTransport(central), sleep=lambda _: None
    )
    assert central.seen[0].headers["authorization"] == f"Bearer {TOKEN}"


def test_client_is_get_only_to_central() -> None:
    client = http_client(_settings(), Purpose.RHACS, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert client.get(ENDPOINT + "/v1/policies").status_code == 200
    with pytest.raises(WebDisabledError, match="read-only"):
        client.post(ENDPOINT + "/v1/policies", json={})
    with pytest.raises(DomainNotAllowedError):
        client.get("https://evil.example.com/v1/policies")
    with pytest.raises(DomainNotAllowedError):
        client.get("https://central.stackrox.svc:8443/v1/policies")
    with pytest.raises(DomainNotAllowedError):
        client.get("http://central.stackrox.svc/v1/policies")
    assert client.follow_redirects is False


def test_disabled_and_offline_lock() -> None:
    with pytest.raises(WebDisabledError, match=r"rhacs\.enabled"):
        http_client(load_settings(), Purpose.RHACS)
    public = load_settings(
        overrides={"offline": True, "rhacs": {"enabled": True, "endpoint": "https://central.example.com"}}
    )
    with pytest.raises(WebDisabledError, match="offline lock"):
        http_client(public, Purpose.RHACS)
    local = load_settings(overrides={"offline": True, "rhacs": {"enabled": True, "endpoint": ENDPOINT}})
    client = http_client(local, Purpose.RHACS)
    assert client.trust_env is False
    client.close()


@pytest.mark.parametrize(
    "rh",
    [
        {"enabled": True},
        {"endpoint": "http://central.example.com"},
        {"endpoint": "https://user:pw@central.example.com"},
        {"endpoint": "https://central.example.com/v1"},
        {"endpoint": "central.example.com"},
        {"tokenEnv": "AWS_SECRET_ACCESS_KEY"},
        {"tokenEnv": "GITHUB_TOKEN"},
        {"maxPolicies": 0},
        {"unknown": 1},
    ],
)
def test_settings_refused(rh: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        load_settings(overrides={"rhacs": rh})


def test_bad_ca_file(tmp_path: Path) -> None:
    bad = tmp_path / "ca.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ConfigError, match="caFile"):
        http_client(_settings(caFile=str(bad)), Purpose.RHACS)


def test_live_tool_reads_central_once_per_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROX_API_TOKEN", TOKEN)
    calls: list[int] = []
    pols = _policies()[:3]

    def fake(settings: Any, **_: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        calls.append(1)
        return pols, {"endpoint": ENDPOINT, "requests": 4, "policies": 3, "skipped": 0}

    monkeypatch.setattr(rhacs_central, "read_central", fake)
    kit = tk.Toolkit(_settings())
    first = kit.rhacs_compare_live(tk.RhacsLiveIn())
    second = kit.rhacs_compare_live(tk.RhacsLiveIn(outcomes=["overlap"]))
    assert first["total"] == 3 and second["total"] == 3 and len(calls) == 1
    assert second["source"]["ageSeconds"] >= 0
    monkeypatch.setattr(tk, "RHACS_CACHE_SECONDS", -1)
    kit.rhacs_compare_live(tk.RhacsLiveIn())
    assert len(calls) == 2


def test_jitter_uses_its_own_rng() -> None:
    reader = rhacs_central.CentralClient(object(), ENDPOINT, rng=random.Random(7))
    assert 0.1 <= reader.rng.uniform(0.1, 0.3) <= 0.3

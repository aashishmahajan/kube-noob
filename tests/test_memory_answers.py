"""Memory in answers (MEM4): diagnose, known-issues, debug and bundle carry approved team entries as [mem:MEM-<n>];
MCP offers memory_match (read-only) and memory_propose, which writes only from a local stdio server after the user
confirmed, never from the HTTP server."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import bundle_markdown
from kube_noob.memory import dump_entry, load_entry, repo

PAYLOAD = (Path(__file__).parent / "fixtures" / "alertmanager-etcd.json").read_text(encoding="utf-8")
TODAY = date(2026, 10, 28)


def _memory(root: Path) -> Path:
    repo.init_repo(root)
    for n, (status, symptom) in enumerate(
        (
            ("approved", "etcd leader changes every few minutes after the 4.21.0 update"),
            ("proposed", "etcd leader elections after adding a fourth control-plane node"),
        ),
        start=1,
    ):
        path, entry = repo.add_entry(
            root,
            {
                "kind": "fix",
                "signals": [{"kind": "alert", "name": "etcdHighNumberOfLeaderChanges"}],
                "symptom": symptom,
                "platform": "openshift",
                "versions": {"fixedIn": "4.21.1"},
                "cause": "Catalog sync wrote to the control-plane disks every few seconds.",
                "fix": {"text": "Update to 4.21.1; lower catalog polling until then."},
                "owners": ["platform-team"],
            },
            TODAY,
        )
        if status == "approved":
            path.write_text(dump_entry(entry.model_copy(update={"status": "approved"})), encoding="utf-8")
        assert entry.id == f"MEM-{n}"
    repo.add_outcome(root, "MEM-1", "resolved", cluster="prod-east", day=TODAY)
    return root


def _kit(tmp_path: Path, shared: bool = False, paths: list[Path] | None = None) -> tk.Toolkit:
    s = load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "memory": {"paths": [str(p) for p in (paths if paths is not None else [_memory(tmp_path / "team")])]},
        }
    )
    return tk.Toolkit(s, shared=shared)


def test_diagnose_and_known_issues_cite_approved_memory_only(tmp_path: Path) -> None:
    kit = _kit(tmp_path)
    out = kit.diagnose(tk.DiagnoseIn(text=PAYLOAD))
    assert [m["citation"] for m in out["memory"]] == ["[mem:MEM-1]"]
    assert out["memory"][0]["state"] == "fix" and out["memory"][0]["outcomes"]["summary"].startswith("matched 1 time")
    fixed = kit.diagnose(tk.DiagnoseIn(text=PAYLOAD, version="4.21.2"))
    assert fixed["memory"][0]["state"] == "retired"
    ki = kit.known_issues(tk.KnownIssuesIn(text="etcdHighNumberOfLeaderChanges is firing", version="4.21.0"))
    assert [m["citation"] for m in ki["memory"]] == ["[mem:MEM-1]"]
    assert "MEM-2" not in json.dumps(ki["memory"])


def test_no_memory_field_without_paths_and_a_note_for_an_unreadable_repo(tmp_path: Path) -> None:
    plain = _kit(tmp_path, paths=[])
    assert "memory" not in plain.diagnose(tk.DiagnoseIn(text=PAYLOAD))
    assert not {"memory_match", "memory_propose"} & {t.name for t in plain.specs()}
    broken = _kit(tmp_path, paths=[_memory(tmp_path / "team"), tmp_path / "missing"])
    out = broken.diagnose(tk.DiagnoseIn(text=PAYLOAD))
    assert [m["id"] for m in out["memory"]] == ["MEM-1"] and "not a memory repository" in out["memoryNotes"][0]


def test_debug_and_bundle_carry_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    kit = _kit(tmp_path)

    def fake_debug(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "backend": "fake",
            "target": "deployment/openshift-etcd/etcd",
            "cluster": {"openshift": "4.21.0"},
            "evidence": ["alert etcdHighNumberOfLeaderChanges firing"],
            "logs": {"etcd-0/etcd": "etcdserver: leader changed"},
            "diagnoses": [],
            "knownIssues": [],
        }

    monkeypatch.setattr(tk, "debug_workload", fake_debug)
    monkeypatch.setattr(tk, "get_backend", lambda _s: object())
    out = kit.cluster_debug(tk.ClusterDebugIn(namespace="openshift-etcd", kind="deployment", name="etcd"))
    assert [m["citation"] for m in out["memory"]] == ["[mem:MEM-1]"]
    md = bundle_markdown(out)
    assert "## Team memory [mem:MEM-1]: fix" in md and "matched 1 time, resolved 1" in md


def test_memory_match_tool_is_read_only_and_hides_proposed(tmp_path: Path) -> None:
    kit = _kit(tmp_path)
    spec = next(t for t in kit.specs() if t.name == "memory_match")
    assert spec.read_only
    out = kit.memory_match(tk.MemoryMatchIn(text="etcdHighNumberOfLeaderChanges"))
    assert [m["id"] for m in out["matches"]] == ["MEM-1"]
    both = kit.memory_match(tk.MemoryMatchIn(text="etcdHighNumberOfLeaderChanges", include_proposed=True))
    assert [m["id"] for m in both["matches"]] == ["MEM-1", "MEM-2"]
    with pytest.raises(ValueError):
        tk.MemoryMatchIn.model_validate({"text": "x" * 10, "dir": "/etc"})


def _propose(**over: Any) -> tk.MemoryProposeIn:
    data: dict[str, Any] = {
        "symptom": "router pods restart when HAProxy reaches maxconn",
        "cause": "maxconn too low for the client traffic on the default ingress controller.",
        "fix": "Raise maxConnections in the IngressController tuningOptions.",
        "platform": "openshift",
        "signals": [{"kind": "alert", "name": "HAProxyDown"}],
        "commands": ["oc get ingresscontroller default -n openshift-ingress-operator -o yaml"],
    }
    data.update(over)
    return tk.MemoryProposeIn.model_validate(data)


def test_propose_shows_yaml_and_writes_only_after_confirmation_in_stdio(tmp_path: Path) -> None:
    kit = _kit(tmp_path)
    spec = next(t for t in kit.specs() if t.name == "memory_propose")
    assert spec.read_only is False
    preview = kit.memory_propose(_propose())
    assert preview["written"] is False and preview["suggestedPath"].endswith("entries/MEM-3.yaml")
    assert "status: proposed" in preview["yaml"] and "label: read-only" in preview["yaml"]
    assert not Path(preview["suggestedPath"]).exists()
    saved = kit.memory_propose(_propose(confirmed_by_user=True))
    assert saved["written"] is True and saved["id"] == "MEM-3"
    assert load_entry(Path(saved["path"])).status == "proposed"
    with pytest.raises(ValueError, match="credential"):
        kit.memory_propose(
            _propose(cause="the token is ghp_abcdefghijklmnopqrstuvwxyz0123456789", confirmed_by_user=True)
        )
    with pytest.raises(ValueError, match="repository 3 is not configured"):
        kit.memory_propose(_propose(repository=3))
    with pytest.raises(ValueError):
        tk.MemoryProposeIn.model_validate({**_propose().model_dump(), "path": "/etc/passwd"})


def test_the_http_server_never_writes_memory(tmp_path: Path) -> None:
    kit = _kit(tmp_path, shared=True)
    spec = next(t for t in kit.specs() if t.name == "memory_propose")
    assert spec.read_only is True and "never writes" in spec.description
    out = kit.memory_propose(_propose(confirmed_by_user=True))
    assert out["written"] is False and "pull request" in out["note"]
    assert sorted(p.name for p in (tmp_path / "team" / "entries").glob("*.yaml")) == ["MEM-1.yaml", "MEM-2.yaml"]


def test_mcp_lists_the_memory_tools_and_the_instructions_mention_them(tmp_path: Path) -> None:
    import anyio
    from mcp.client import Client

    from kube_noob.server.mcp_app import _instructions, build_server

    s = load_settings(
        overrides={"dataDir": str(tmp_path / "data"), "memory": {"paths": [str(_memory(tmp_path / "team"))]}}
    )

    async def run() -> tuple[set[str], dict[str, Any]]:
        async with Client(build_server(s)) as c:
            tools = {t.name for t in (await c.list_tools()).tools}
            res = await c.call_tool("kubenoob_memory_match", {"text": "etcdHighNumberOfLeaderChanges"})
            return tools, json.loads(res.content[0].text)

    tools, found = anyio.run(run)
    assert {"kubenoob_memory_match", "kubenoob_memory_propose"} <= tools
    assert found["matches"][0]["id"] == "MEM-1"
    assert "[mem:MEM-<n>]" in _instructions(s)
    assert "[mem:" not in _instructions(load_settings(overrides={"dataDir": str(tmp_path / "data")}))

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

from kube_noob.evals.reward import benchmark, grade, grade_by_id, trl_reward
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.sources.corpus import iter_records, verify, write_shard
from kube_noob.sources.git_ingest import clean_text
from kube_noob.sources.jira import JiraClient, adf_to_text, classify, insights, pull_project, scrub

GOOD_RWX_ANSWER = (
    "gp3-csi is AWS EBS block storage and only supports ReadWriteOnce (RWO) [kn:storage-access-modes#0]. Install the "
    "AWS EFS CSI driver, create an efs-sc StorageClass with provisioner efs.csi.aws.com and use it [kn:rosa-efs#0]."
)


def test_qa_reward_rewards_correct_cited_answer() -> None:
    g = grade_by_id("bench-qa-rwx-gp3", GOOD_RWX_ANSWER)
    assert g.task == 1.0 and g.credit == 1.0 and g.reward == pytest.approx(1.0)


def test_qa_reward_penalises_fabrication_and_misconception() -> None:
    bad = "gp3-csi supports RWX if you ask nicely [kn:made-up#9]"
    g = grade_by_id("bench-qa-rwx-gp3", bad)
    assert g.task < 0.3 and g.credit == 0.0 and any("fabricated" in p for p in g.penalties)
    assert g.reward < 0.25


def test_uncited_answer_gets_no_credit_when_required() -> None:
    g = grade_by_id(
        "bench-qa-rwx-gp3", GOOD_RWX_ANSWER.replace("[kn:storage-access-modes#0]", "").replace("[kn:rosa-efs#0]", "")
    )
    assert g.credit == 0.0 and g.task == 1.0


def test_manifest_reward() -> None:
    task = benchmark()["bench-rosa-rwx"]
    bp = Blueprint.model_validate(
        {
            "name": "render",
            "namespace": "gfx",
            "image": "quay.io/acme/render:2.0.0",
            "platform": "rosa-hcp",
            "replicas": 3,
            "storage": {"size": "100Gi", "accessMode": "ReadWriteMany", "mountPath": "/work"},
        }
    )
    good = grade(task, "Here you go:\n```yaml\n" + generate(bp).yaml() + "```")
    assert good.task == 1.0 and good.format == 1.0
    bad = grade(
        task,
        "```yaml\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: x}\nspec:\n"
        "  accessModes: [ReadWriteMany]\n  storageClassName: gp3-csi\n"
        "  resources: {requests: {storage: 1Gi}}\n```",
    )
    assert bad.reward < good.reward
    assert grade(task, "no yaml here at all").format == 0.0


def test_trl_reward_signature() -> None:
    rewards = trl_reward(
        [GOOD_RWX_ANSWER, [{"role": "assistant", "content": GOOD_RWX_ANSWER}]],
        task_id=["bench-qa-rwx-gp3", "bench-qa-rwx-gp3"],
    )
    assert rewards[0] == rewards[1] == pytest.approx(1.0)
    with pytest.raises(ValueError):
        trl_reward(["x"])


def test_benchmark_tasks_are_well_formed() -> None:
    for tid, t in benchmark().items():
        assert t["prompt"] and t.get("type", "manifest") in {"manifest", "qa"}, tid
        if t.get("type", "manifest") == "manifest":
            assert t["checks"]["platform"] in {"kubernetes", "openshift", "rosa-hcp", "rosa-classic"}


# ---------------------------------------------------------------------------------------------- jira


def _issue(
    key: str,
    fix: list[str] | None = None,
    labels: list[str] | None = None,
    target: list[str] | None = None,
    created: str = "2026-05-01T00:00:00.000+0000",
) -> dict[str, Any]:
    return {
        "key": key,
        "fields": {
            "summary": f"{key} summary contact bob@example.com",
            "description": {
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "Sensor crashes on "},
                            {"type": "mention", "attrs": {"id": "abc"}},
                            {"type": "text", "text": " cluster"},
                        ],
                    },
                    {"type": "codeBlock", "content": [{"type": "text", "text": "panic: nil map"}]},
                ],
            },
            "issuetype": {"name": "Bug"},
            "status": {"name": "Open"},
            "priority": {"name": "Major"},
            "resolution": None,
            "labels": labels or [],
            "components": [{"name": "sensor"}],
            "fixVersions": [{"name": v} for v in fix or []],
            "versions": [],
            "customfield_10855": [{"name": v} for v in target or []],
            "created": created,
            "updated": "2026-10-01T00:00:00.000+0000",
            "comment": {
                "comments": [
                    {
                        "created": "2026-06-01",
                        "author": {"displayName": "Secret Person"},
                        "body": {
                            "type": "doc",
                            "content": [
                                {"type": "paragraph", "content": [{"type": "text", "text": "Fixed in master"}]}
                            ],
                        },
                    }
                ]
            },
        },
    }


def test_adf_and_scrub() -> None:
    text = adf_to_text(_issue("ROX-1")["fields"]["description"])
    assert "Sensor crashes on @user cluster" in text and "```\npanic: nil map\n```" in text
    assert scrub("mail bob@example.com [~accountid:5b10ac8d82e05b22cc7d4ef5]") == "mail <email> <account>"


def test_classify_versions() -> None:
    mv = (4, 10, 0)
    assert classify(_issue("A", fix=["4.10.3"]), mv, None) == (["4.10.3"], "explicit-version")
    assert classify(_issue("B", target=["5.2.0"]), mv, None) == (["5.2.0"], "explicit-version")
    assert classify(_issue("C", labels=["5.0.0"]), mv, None) == (["5.0.0"], "version-label")
    assert classify(_issue("D", fix=["4.8.1"]), mv, None) is None
    assert classify(_issue("E", fix=["OCP 4.16"]), mv, "2026-03-03") == ([], "created-after-4.10-release")
    assert classify(_issue("F", created="2025-01-01T00:00:00.000+0000"), mv, "2026-03-03") is None


def test_pull_project_paginates_retries_and_scrubs() -> None:
    calls: list[str] = []
    pages = {
        None: ([_issue("ROX-1", fix=["4.10.1"]), _issue("ROX-2", fix=["4.9.0"])], "tok1"),
        "tok1": ([_issue("ROX-3", target=["5.0.0"])], None),
    }
    state = {"rate_limited": False}

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if req.url.path.endswith("/versions"):
            return httpx.Response(
                200,
                json=[
                    {"name": "4.10.0", "releaseDate": "2026-03-03"},
                    {"name": "4.9.0"},
                    {"name": "5.0.0"},
                    {"name": "OCP 4.16"},
                ],
            )
        if not state["rate_limited"]:
            state["rate_limited"] = True
            return httpx.Response(429, headers={"Retry-After": "0"})
        token = req.url.params.get("nextPageToken")
        issues, nxt = pages[token]
        body: dict[str, Any] = {"issues": issues, "isLast": nxt is None}
        if nxt:
            body["nextPageToken"] = nxt
        return httpx.Response(200, json=body)

    sleeps: list[float] = []
    client = JiraClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "https://jira.example",
        sleep=sleeps.append,
        rng=random.Random(1),
    )
    res = pull_project(client, "ROX", "4.10", target=2, max_scan=100, base_url="https://jira.example")
    keys = [r["id"] for r in res.records]
    assert keys == ["jira-ROX-1", "jira-ROX-3"]
    assert res.stats.retries == 1 and res.stats.pages == 2 and len(sleeps) >= 2
    jql = next(c for c in calls if "search/jql" in c)
    assert "cf%5B10855%5D" in jql or "cf[10855]" in httpx.URL(jql).params["jql"]
    blob = json.dumps(res.records)
    assert "bob@example.com" not in blob and "Secret Person" not in blob
    assert all(r["redistributable"] is False for r in res.records)
    assert res.versions_considered == ["4.10.0", "5.0.0"] and res.ga_floor == "2026-03-03"
    ins = insights(res.records, "ROX")
    assert ins["issues"] == 2 and dict(ins["byComponent"])["sensor"] == 2


def test_corpus_shards_and_verify(tmp_path: Path) -> None:
    rec = {"id": "x", "title": "t", "text": "hello", "sourceId": "s", "license": "MIT", "redistributable": True}
    write_shard(tmp_path, "test", [rec, {**rec, "id": "y", "redistributable": False}])
    assert len(iter_records(tmp_path)) == 2 and len(iter_records(tmp_path, include_restricted=False)) == 1
    assert verify(tmp_path) == []
    (tmp_path / "corpus" / "test.jsonl").write_text("tampered\n")
    assert verify(tmp_path)
    with pytest.raises(ValueError):
        write_shard(tmp_path, "../evil", [rec])


def test_clean_text_adoc_and_md() -> None:
    title, text = clean_text(
        "modules/x.adoc",
        ':_mod-docs-content-type: PROCEDURE\n[id="x"]\n= Configuring {product-title}'
        "\n// comment\ninclude::snip.adoc[]\nBody text.\n",
    )
    assert title == "Configuring {product-title}" and "# Configuring OpenShift" in text and "include::" not in text
    title2, text2 = clean_text("docs/a.md", '---\ntitle: "Pods"\n---\nSome {{< note >}}text{{< /note >}}\n')
    assert title2 == "Pods" and "{{<" not in text2


def test_corpus_import_directory_and_tarball(tmp_path: Path) -> None:
    import tarfile

    from kube_noob.sources.corpus import import_corpus

    src = tmp_path / "src"
    rec = {"id": "a", "title": "t", "text": "x", "sourceId": "s", "license": "MIT", "redistributable": True}
    write_shard(src, "one", [rec])
    dest = tmp_path / "dest"
    assert import_corpus(src / "corpus", dest)["imported"] == ["one"]
    assert verify(dest) == []
    tgz = tmp_path / "c.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(src / "corpus", arcname="corpus")
    dest2 = tmp_path / "dest2"
    assert import_corpus(tgz, dest2)["imported"] == ["one"]
    (src / "corpus" / "one.jsonl").write_text("tampered\n")
    with pytest.raises(ValueError, match="checksum"):
        import_corpus(src / "corpus", tmp_path / "dest3")
    evil = src / "corpus" / "MANIFEST.json"
    evil.write_text(json.dumps({"shards": {"x": {"file": "../../etc/passwd.jsonl", "sha256": "0"}}}))
    with pytest.raises(ValueError, match="suspicious"):
        import_corpus(src / "corpus", tmp_path / "dest4")

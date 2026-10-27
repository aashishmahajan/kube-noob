"""Bring-your-own runbooks: indexed offline, credentials masked, cited, never exported by default."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.evals.export import knowledge_records
from kube_noob.knowledge.store import get_store
from kube_noob.sources.org_docs import ingest_org_docs

RUNBOOK = """---
title: Payments on-call runbook
---
# Payments on-call runbook

When the payments-api pods fail readiness after a deploy, first check the vault-agent sidecar logs, because the
payments team injects database credentials through Vault. Escalate to #team-payments if the sidecar shows
permission denied for the role payments-api-prod.

Example login used in the old pipeline: export VAULT_TOKEN=hvs.CAESIJlU7f9mXq2Lr8P4vT6kZ1nB3dW5yE0aQ
"""

ADOC = """= Namespace request process
:toc:

Teams request a namespace by opening a ticket in the PLATFORM queue. Namespaces follow the pattern
<team>-<env> and get a default-deny NetworkPolicy plus a ResourceQuota of 8 CPU and 32Gi memory.
"""


def test_runbooks_are_indexed_masked_and_cited(tmp_path: Path) -> None:
    docs = tmp_path / "wiki"
    (docs / "oncall").mkdir(parents=True)
    (docs / "oncall" / "payments.md").write_text(RUNBOOK)
    (docs / "namespaces.adoc").write_text(ADOC)
    (docs / ".git").mkdir()
    (docs / ".git" / "HEAD.md").write_text("ref: refs/heads/main " * 5)
    s = load_settings()
    out = ingest_org_docs(docs, s.data_dir, "platform-runbooks", "https://git.example.com/wiki/blob/main")
    assert out["records"] == 2 and out["maskedFiles"] == ["oncall/payments.md"]
    shard = (s.data_dir / "corpus" / "org-platform-runbooks.jsonl").read_text()
    assert "hvs.CAES" not in shard and "redistributable\": false" in shard
    hits = get_store(s.data_dir).search("payments readiness vault-agent sidecar escalate", limit=3)
    top = hits[0].chunk
    assert top.source_id == "org:platform-runbooks" and top.url.endswith("oncall/payments.md")
    ns = get_store(s.data_dir).search("how do teams request a namespace quota", limit=3)
    assert ns[0].chunk.title == "Namespace request process"
    exported = list(knowledge_records(get_store(s.data_dir), include_restricted=False))
    assert not any(r["metadata"]["source"].startswith("org:") for r in exported)


def test_add_docs_cli_works_under_the_offline_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text(RUNBOOK)
    assert main(["corpus", "add-docs", str(docs), "--source", "team-a", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 1
    with pytest.raises(ValueError):
        ingest_org_docs(docs, load_settings().data_dir, "Bad Name")

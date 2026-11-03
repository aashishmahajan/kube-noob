"""A refresh that found nothing is a broken refresh, not an empty corpus.

Four defects composed into one chain that published an empty corpus under a green check:

- `corpus.write_shard` called `os.replace` unconditionally, so a zero-record refresh truncated the previous shard
  to 0 bytes and the records were gone from the data directory;
- `redistributable` was `all(r["redistributable"] for r in records)`, and `all([])` is `True`, so the empty shard
  was marked redistributable;
- `corpus build` returned `0 if all(isinstance(v, int) ...)`, and a count of `0` is an `int`, so only an exception
  produced a non-zero exit;
- `db_bundle.build` only refused when there were no shards *at all*, so an empty-but-present shard shipped, and
  `db-check` found no bad lines in a file with no lines.

Upstream moving a docs path is enough to trigger it: `ingest` matches nothing and raises nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob.sources import corpus

REC: dict[str, Any] = {
    "id": "a",
    "sourceId": "git-docs",
    "title": "T",
    "text": "some text",
    "url": "https://example.com/a",
    "license": "Apache-2.0",
    "redistributable": True,
}


def _rec(n: int) -> dict[str, Any]:
    return {**REC, "id": f"doc-{n}", "url": f"https://example.com/{n}"}


def test_an_empty_shard_is_not_marked_redistributable(tmp_path: Path) -> None:
    """`all([])` is `True`. Nothing to redistribute is not permission to redistribute, and this flag is what
    `db_bundle` reads to decide whether a shard may be published."""
    entry = corpus.write_shard(tmp_path, "empty", [], allow_empty=True)
    assert entry["records"] == 0
    assert entry["redistributable"] is False


def test_a_zero_record_refresh_does_not_destroy_the_shard_it_replaces(tmp_path: Path) -> None:
    """The damage that is not recoverable from a re-run: the previous records are gone from the data directory."""
    corpus.write_shard(tmp_path, "docs", [_rec(i) for i in range(5)])
    shard = corpus.corpus_dir(tmp_path) / "docs.jsonl"
    before = shard.read_bytes()
    assert before

    with pytest.raises(corpus.CorpusError, match="0 records"):
        corpus.write_shard(tmp_path, "docs", [])

    assert shard.read_bytes() == before, "the previous shard must survive a refresh that found nothing"
    manifest = json.loads((corpus.corpus_dir(tmp_path) / "MANIFEST.json").read_text())
    assert manifest["shards"]["docs"]["records"] == 5


def test_a_first_write_of_nothing_is_still_refused(tmp_path: Path) -> None:
    """There is no shard to protect here, but a source that yields nothing on its first run is just as broken, and
    writing the empty file is what lets it reach the bundle."""
    with pytest.raises(corpus.CorpusError, match="0 records"):
        corpus.write_shard(tmp_path, "docs", [])
    assert not (corpus.corpus_dir(tmp_path) / "docs.jsonl").exists()


def test_allow_empty_is_the_only_way_to_write_one(tmp_path: Path) -> None:
    """A caller that genuinely means it can still say so, so the guard is a default and not a wall."""
    entry = corpus.write_shard(tmp_path, "docs", [], allow_empty=True)
    assert entry["records"] == 0


def test_the_bundle_refuses_an_empty_shard(tmp_path: Path) -> None:
    """`db_bundle` refused only when there were no shards *at all*. A present-but-empty shard passed every check:
    `_shard_problems` finds no bad lines in a file with no lines, so the bundle built and `db-check` said clean.

    With `redistributable` no longer true for an empty shard, it is now left out as not redistributable and the
    existing "nothing to ship" guard catches it, so either message is a refusal. What matters is that nothing is
    written."""
    from kube_noob.sources import db_bundle

    corpus.write_shard(tmp_path, "docs", [], allow_empty=True)
    with pytest.raises(db_bundle.BundleError):
        db_bundle.build(tmp_path, tmp_path / "out.tgz")
    assert not (tmp_path / "out.tgz").exists()


def test_the_bundle_refuses_zero_records_even_if_the_manifest_claims_otherwise(tmp_path: Path) -> None:
    """The second line of defence, for a manifest written before the `redistributable` fix or by hand: the shard
    is empty but flagged redistributable, so it is not filtered out and reaches the record count."""
    from kube_noob.sources import db_bundle

    corpus.write_shard(tmp_path, "docs", [], allow_empty=True)
    mpath = corpus.corpus_dir(tmp_path) / "MANIFEST.json"
    manifest = json.loads(mpath.read_text())
    manifest["shards"]["docs"]["redistributable"] = True
    mpath.write_text(json.dumps(manifest))
    with pytest.raises(db_bundle.BundleError, match="0 records"):
        db_bundle.build(tmp_path, tmp_path / "out.tgz")
    assert not (tmp_path / "out.tgz").exists()


def test_a_bundle_with_records_is_still_built(tmp_path: Path) -> None:
    """The guard must not block the normal case."""
    from kube_noob.sources import db_bundle

    corpus.write_shard(tmp_path, "docs", [_rec(i) for i in range(3)])
    out = db_bundle.build(tmp_path, tmp_path / "out.tgz")
    assert out["records"] == 3
    assert (tmp_path / "out.tgz").is_file()


def test_a_source_that_yields_nothing_makes_corpus_build_exit_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`return 0 if all(isinstance(v, int) for v in summary.values()) else 4` treated a count of 0 as success,
    because `0` is an `int` -- so only an exception produced a non-zero exit, and a source whose upstream path had
    moved reported "0" and passed. `write_shard` now raises, the loop records that as a string, and the value is
    no longer an int."""
    from kube_noob.cli import main

    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"dataDir: {tmp_path / 'data'}\nwebEnabled: true\n")
    monkeypatch.setattr("kube_noob.sources.git_ingest.ingest", lambda *a, **k: iter(()))
    rc = main(["--config", str(cfg), "--format", "json", "corpus", "build", "--online", "--sources", "all"])
    assert rc != 0, "a source that produced no records must not exit 0"

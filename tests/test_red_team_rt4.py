"""Red team RT4: the HTTP server surface, where the caller is somebody other than the operator.

Found by a red-team pass that drove the real server over raw sockets. The theme of the findings is that a guard
existed but ran in the wrong order or on the wrong bytes: auth after buffering for the public paths, a nesting check
on a different decoding from the parser, a body limit above what any valid request can be, and an audit line that
logs what the caller chose to send.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from kube_noob.config import load_settings
from kube_noob.server.http import MAX_BODY_BYTES, PUBLIC_PATHS, http_app

TOKEN = "rt4-" + "token-" + "y" * 10
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    s = load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
        }
    )
    with TestClient(http_app(s)) as c:
        yield c


@pytest.mark.parametrize("path", sorted(PUBLIC_PATHS))
def test_an_unauthenticated_caller_cannot_make_the_server_buffer_a_body(client: Any, path: str) -> None:
    """RT4-1. The health paths skip the token for the kubelet's probes, and skipped it for every method, so an
    unauthenticated POST was buffered up to the body limit before the router answered 405. Fifty such connections
    took the process from 96 MiB to 522 MiB and the kernel killed it at the chart's 512Mi limit. A probe sends no
    body, so a body on a public path is refused before it is read."""
    big = b"x" * (64 * 1024)
    resp = client.post(path, content=big)
    assert resp.status_code in (405, 413), resp.status_code
    assert client.get(path).status_code == 200, "the probe itself still works"
    assert client.request("HEAD", path).status_code in (200, 405)


def test_the_body_limit_is_not_larger_than_a_valid_request(client: Any) -> None:
    """RT4-4. Every tool argument is capped at 1,000,000 characters, so a body above roughly that size can never be
    valid -- but the limit buffered 8 MiB first, copied it, and ran a pure-Python bracket scan over it, which
    stalled the event loop for 0.41s per body and put the kubelet's 3s probe at risk. Refusing earlier costs a
    caller nothing that could have succeeded."""
    assert MAX_BODY_BYTES <= 2 * 1024 * 1024, f"the limit is {MAX_BODY_BYTES}, above any body that can be valid"
    oversize = json.dumps({"text": "x" * (MAX_BODY_BYTES + 1024)}).encode()
    resp = client.post("/v1/diagnose", content=oversize, headers={**AUTH, "Content-Type": "application/json"})
    assert resp.status_code == 413, resp.text


def test_the_nesting_guard_reads_the_same_bytes_the_parser_does(client: Any) -> None:
    """RT4-7. The guard counted brackets on raw.decode("utf-8", "replace") while json.loads parsed the raw bytes,
    and json.loads auto-detects UTF-16 and UTF-32. A UTF-16 body therefore reached the parser with the guard having
    read mojibake -- the exact bypass the guard exists to prevent, since deep nesting overflows the C stack on
    CPython 3.14 as a fatal error rather than a RecursionError."""
    # The exact desync: a JSON string holding an escaped quote, then real nesting. Decoded as UTF-8 with
    # replacement, a UTF-16 backslash is followed by a NUL, so the byte-wise in-string tracking escapes the NUL
    # instead of the quote and loses track of where the string ends -- and then stops counting the brackets after
    # it. Proven as a unit below as well as over HTTP, because this is the payload that actually got through.
    bypass = '{"s": "a\\"b", "d": ' + ("[" * 300) + ("]" * 300) + "}"
    deep = ("{" * 300) + '"a": 1' + ("}" * 300)
    nested_array = ("[" * 300) + ("]" * 300)
    for body in (bypass, deep, nested_array):
        for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-16", "utf-32-le"):
            resp = client.post(
                "/v1/diagnose",
                content=body.encode(encoding),
                headers={**AUTH, "Content-Type": "application/json"},
            )
            assert resp.status_code == 400, f"{encoding} reached the parser: {resp.status_code} {resp.text[:200]}"
            assert "not JSON" in resp.text, f"{encoding} was refused for the wrong reason: {resp.text[:200]}"


def test_the_guard_counted_a_different_string_from_the_one_the_parser_read() -> None:
    """RT4-7 as a unit, so the regression is pinned to the bypass itself rather than to one route's status code."""
    from kube_noob import sanitize
    from kube_noob.server.rest import _decode_json_text

    body = '{"s": "a\\"b", "d": ' + ("[" * 300) + ("]" * 300) + "}"
    for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be", "utf-16"):
        raw = body.encode(encoding)
        assert json.loads(raw), "json.loads sniffs the encoding and parses these bytes"
        assert sanitize.json_nesting_ok(raw.decode("utf-8", "replace")), "the old guard allowed it"
        assert not sanitize.json_nesting_ok(_decode_json_text(raw)), f"{encoding} still bypasses the guard"


def test_a_valid_utf16_body_is_still_understood(client: Any) -> None:
    """The counterpart: refusing every non-UTF-8 body would be a regression for a caller that legitimately sends
    UTF-16, so one is decoded and answered rather than rejected."""
    body = json.dumps({"text": "CrashLoopBackOff on the orders pod"})
    plain = client.post("/v1/diagnose", content=body.encode(), headers={**AUTH, "Content-Type": "application/json"})
    wide = client.post(
        "/v1/diagnose", content=body.encode("utf-16"), headers={**AUTH, "Content-Type": "application/json"}
    )
    assert plain.status_code == 200, plain.text
    assert wide.status_code == plain.status_code, wide.text


def test_the_audit_line_does_not_log_what_the_caller_chose_to_send(
    client: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """RT4-5. The audit line is documented as content-free: "which tool, argument names and sizes". It logged the
    caller's own JSON keys, so an 8 MiB key name became an 18 MiB log line and 9s of CPU. Argument names that the
    tool does not define carry no audit value, and their length is the caller's choice."""
    long_key = "k" * 50_000
    with caplog.at_level("INFO"):
        client.post(
            "/v1/diagnose",
            content=json.dumps({long_key: "x", "text": "CrashLoopBackOff"}).encode(),
            headers={**AUTH, "Content-Type": "application/json"},
        )
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert long_key not in logged
    assert len(logged) < 20_000, f"the audit line grew to {len(logged)} characters from one request"


def test_a_duplicate_authorization_header_is_refused(client: Any) -> None:
    """RT4-8. ``dict(scope["headers"])`` keeps the last value, while a proxy in front that checks the header reads
    the first. 'bad, good' therefore authenticated here and 'good, bad' did not. Two Authorization headers are
    never a legitimate request, so they are refused rather than resolved one way or the other."""
    sent = client.build_request("GET", "/v1/openapi.json")
    sent.headers["Authorization"] = "Bearer wrong-token-entirely"
    sent.headers.add("Authorization", f"Bearer {TOKEN}") if hasattr(sent.headers, "add") else None
    raw = [(b"authorization", b"Bearer wrong"), (b"authorization", f"Bearer {TOKEN}".encode())]
    from kube_noob.server.http import BearerAuth

    auth = BearerAuth(lambda *_: None, TOKEN)  # type: ignore[arg-type,misc]
    assert auth._refuses({"type": "http", "path": "/v1/openapi.json", "headers": raw})
    assert auth._refuses({"type": "http", "path": "/v1/openapi.json", "headers": list(reversed(raw))})
    assert not auth._refuses(
        {"type": "http", "path": "/v1/openapi.json", "headers": [(b"authorization", f"Bearer {TOKEN}".encode())]}
    )


def test_the_knowledge_store_is_not_rebuilt_because_a_counter_moved(tmp_path: Path) -> None:
    """RT4-3. ``learning.json``'s size and mtime were part of the knowledge store's cache key. The file does feed the
    index -- the team's confirmed notes become searchable chunks -- but almost every tool call rewrites it to bump a
    counter, which changes no chunk at all. So the whole index was rebuilt on nearly every request: 157ms and
    6.2 req/s with learning on against 11ms and 89.8 req/s with it off. The key now covers the notes themselves, so
    a new note is searchable at once and a counter costs nothing."""
    from kube_noob.knowledge import store
    from kube_noob.learn.memory import LearningStore

    s = load_settings(overrides={"dataDir": str(tmp_path / "data")})
    s.data_dir.mkdir(parents=True, exist_ok=True)
    mem = LearningStore(s.data_dir)
    mem.add_note(symptom="etcd defrag never finishes", cause="the disk is saturated", fix="give etcd its own volume")
    first = store.get_store(s.data_dir)
    for i in range(4):  # what a tool call does: bump a counter, leave the notes alone
        LearningStore(s.data_dir).bump([f"rule:KN-SEC-00{i + 1}"])
        assert store.get_store(s.data_dir) is first, f"a counter moving rebuilt the index (bump {i})"

    # A new note does have to reach the index, or search would answer from a stale one.
    LearningStore(s.data_dir).add_note(
        symptom="the registry rejects a push", cause="the quota is full", fix="prune old tags"
    )
    rebuilt = store.get_store(s.data_dir)
    assert rebuilt is not first, "a new note must invalidate the index"
    assert any("registry rejects a push" in c.title for c in rebuilt.chunks), "and must be searchable"

    # A file that cannot be read as notes falls back to its stat, which is the old behaviour: rebuilding too often
    # is safe, serving a stale index is not.
    (s.data_dir / "learning.json").write_text("{not json", encoding="utf-8")
    assert store.get_store(s.data_dir) is not rebuilt

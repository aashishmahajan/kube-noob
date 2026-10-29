"""Video scripts never type a number: counts, scores, line numbers and terminal lines come from the code when a video
is built (demos/video/facts.py), videos.json passes its schema, and every rule a script names is real and is what the
audit of the example finds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
VIDEO = ROOT / "demos" / "video"
TRANSCRIPT = ROOT / "tests" / "fixtures" / "video-sidecar-transcript.txt"  # recorded in CI run 40812189249 (0.6.0)
sys.path.insert(0, str(VIDEO))
sys.path.insert(0, str(VIDEO / "stage"))

import facts as vfacts  # noqa: E402

# Numbers that are not counts: platform versions, a port, an exit code, a UID in the example, the time of day.
FIXED = [
    r"OpenShift \d\.\d\d( and later)?",
    r"OCP \d\.\d\d",
    r"4\.22",
    r"127\.0\.0\.1(:8080)?",
    r"(port |:)8080",
    r":53\b",
    r"exit( code)? 137",
    r"runAsUser: 1000",
    r"2 a\.m\.",
    r"\b(16:9|1:1|9:16)\b",
    r"\b\d+ (s|seconds)\b",
    r"/100\b",
    r"out of 100",
    r"\btop 3\b",  # what the prompt in the Claude video asks for
    r"^\d+\. ",  # a numbered step on screen
    r"\[kn:[^\]]+\]",  # a citation id
]
SPOKEN_FIXED = ["four twenty-two", "four point twenty", "one thirty-seven", "two in the morning", "two commands"]
NUMBER_WORD = re.compile(r"\b(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand)\b", re.I)


@pytest.fixture(scope="module")
def facts() -> vfacts.Facts:
    return vfacts.Facts(TRANSCRIPT)


def _spec() -> dict[str, Any]:
    return json.loads((VIDEO / "stage" / "videos.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _typed_numbers(text: str) -> list[str]:
    t = vfacts.PLACEHOLDER.sub("", text)
    for pattern in FIXED:
        t = re.sub(pattern, "", t, flags=re.I)
    for phrase in SPOKEN_FIXED:
        t = t.replace(phrase, "")
    return re.findall(r"\b\d+(?:\.\d+)?\b", t) + NUMBER_WORD.findall(t)


def _script_texts() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, v in _spec()["videos"].items():
        for i, s in enumerate(v["scenes"]):
            for k in ("caption", "vo", "say", "bubble"):
                if k in s:
                    out.append((f"videos.json {name}[{i}].{k}", s[k]))
            for line in s.get("term", []) + s.get("answer", []):
                if not vfacts.RECORDING.match(line):
                    out.append((f"videos.json {name}[{i}] line", line))
    walk = (ROOT / "demos" / "youtube-walkthrough.md").read_text(encoding="utf-8")
    rendered = walk.split("## Voice-over for the rendered cut", 1)[1].split("\n## ", 1)[0]
    out += [("walkthrough voice-over", m) for m in re.findall(r"^\| \d+:\d\d \| (.+?) \|$", rendered, re.M)]
    for doc in ("youtube-walkthrough.md", "ai-video-prompts.md"):
        for line in (ROOT / "demos" / doc).read_text(encoding="utf-8").splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if line.startswith("| ") and len(cells) == 5 and cells[0].isdigit():
                out += [(f"{doc} row {cells[0]} on-screen", cells[3]), (f"{doc} row {cells[0]} voice-over", cells[4])]
    chapters = walk.split("Chapters\n", 1)[1].split("```", 1)[0]
    out += [("walkthrough chapters", re.sub(r"^\d+:\d\d ", "", ln)) for ln in chapters.splitlines()]
    return out


def test_scripts_type_no_counts_scores_or_line_numbers() -> None:
    typed = [(where, text, nums) for where, text in _script_texts() if (nums := _typed_numbers(text))]
    assert not typed, "write these as {facts} (demos/video/facts.py): " + "; ".join(
        f"{w}: {n} in {t[:70]!r}" for w, t, n in typed
    )


def test_every_placeholder_and_recording_resolves(facts: vfacts.Facts) -> None:
    import voiceover

    for name in _spec()["videos"]:
        v = voiceover.load(name, facts)
        blob = json.dumps(v, ensure_ascii=False)
        assert not vfacts.PLACEHOLDER.search(blob) and '"@' not in blob, name
    for doc in ("youtube-walkthrough.md", "ai-video-prompts.md"):
        assert not vfacts.PLACEHOLDER.search(facts.fill((ROOT / "demos" / doc).read_text(encoding="utf-8"))), doc
    with pytest.raises(vfacts.FactError, match="unknown fact"):
        facts.fill("{audit.nope}")


def test_facts_match_the_code_and_the_recorded_transcript(facts: vfacts.Facts) -> None:
    from kube_noob import __version__
    from kube_noob.audit.engine import list_rules

    assert facts.get("rules") == len(list_rules()) and facts.get("version") == __version__
    assert facts.get("audit.score") < facts.get("fix.score") <= 100 and facts.get("audit.high") >= 1
    assert (facts.get("sidecar.tools"), facts.get("sidecar.peak"), facts.get("sidecar.limit")) == (41, 92, 256)
    cli = facts.recording("cli:audit")
    assert f"score={float(facts.get('audit.score'))}" in cli[1] and sum(ln.startswith("[HIGH") for ln in cli) == 3
    tool = "\n".join(facts.recording("tool:audit"))
    assert f"score {facts.get('audit.score')} · high {facts.get('audit.high')}" in tool
    assert f"score after the automatic fixes: {facts.get('fix.score')}" in tool
    client = facts.recording("sidecar:client")
    assert client[0].startswith("$ kubectl") and "41 tools" in client[1] and client[-1].startswith("pod IP")
    assert vfacts.words(63) == "sixty-three" and vfacts.words(256) == "two hundred and fifty-six"


def test_sidecar_facts_fail_loudly_without_the_ci_transcript(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KN_SIDECAR_TRANSCRIPT", raising=False)
    with pytest.raises(vfacts.FactError, match="KN_SIDECAR_TRANSCRIPT"):
        vfacts.Facts().get("sidecar.peak")


def test_rules_a_script_names_are_real_and_found_in_the_example(facts: vfacts.Facts) -> None:
    from kube_noob.audit.engine import list_rules

    real = {r["ruleId"] for r in list_rules()}
    found = set(re.findall(r"KN-[A-Z]+\d+", "\n".join(facts.recording("tool:audit"))))
    spec = json.dumps(_spec()["videos"]["mcp"]) + json.dumps(_spec()["videos"]["teaser"])
    named = set(re.findall(r"KN-[A-Z]+\d+", spec))
    assert named <= real and named <= found, named - found  # Claude's answer must match what the tools return


def test_videos_json_passes_its_schema_and_the_schema_knows_every_scene_kind() -> None:
    schema = json.loads((VIDEO / "stage" / "videos.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert not list(jsonschema.Draft202012Validator(schema).iter_errors(_spec()))
    stage = (VIDEO / "stage" / "stage.html").read_text(encoding="utf-8")
    start = stage.index("const KINDS = {")
    body = stage[start : stage.index("\n/* --", start)]
    kinds = re.findall(r"^  (\w+)\(L, dur, sc, T\)", body, re.M)
    assert set(kinds) == set(schema["$defs"]["scene"]["properties"]["kind"]["enum"])
    bad = json.loads(json.dumps(_spec()))
    bad["videos"]["teaser"]["scenes"][0]["vo"] = "Link below."
    bad["videos"]["teaser"]["scenes"].append({"kind": "nope", "min": 1})
    assert len(list(jsonschema.Draft202012Validator(schema).iter_errors(bad))) >= 2

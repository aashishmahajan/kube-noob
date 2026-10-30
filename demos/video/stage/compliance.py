#!/usr/bin/env python3
"""Voice-over, music and timing for the compliance video (compliance.json), through the same pipeline as videos.json.

Usage: python compliance.py <out-dir> [--engine kokoro|piper] [--voice af_heart] [--speed 1.0] [--music-db -12]

compliance.json holds one video in exactly the shape videos.json uses, and is checked against the same
videos.schema.json ($defs/video) before any voice is spoken. It lives in its own file because every claim in it names
a NIST SP 800-53 control id, and videos.json may type no digits (tests/test_video_facts.py). Everything else is the
existing pipeline: voiceover.build() writes timeline.json, kube-noob-compliance.vtt and the stems, and the picture is
rendered by `node capture.js <out-dir> --scale 2` and measured by `python ../audio_kit.py verify`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import audio_kit as ak  # noqa: E402
import facts as vfacts  # noqa: E402
import video_script  # noqa: E402
import voiceover  # noqa: E402

VIDEO = "compliance"
SCRIPT = HERE / "compliance.json"


def load(facts: vfacts.Facts | None = None) -> dict[str, Any]:
    """compliance.json, checked against videos.schema.json's video definition, with every {fact} filled in."""
    raw = json.loads(SCRIPT.read_text(encoding="utf-8"))
    spec = {k: val for k, val in raw.items() if not k.startswith("_")}  # "_comment" is this file's own provenance
    schema = json.loads((HERE / "videos.schema.json").read_text(encoding="utf-8"))
    one = {**schema["$defs"]["video"], "$defs": schema["$defs"]}
    errors = sorted(jsonschema.Draft202012Validator(one).iter_errors(spec), key=lambda e: list(e.path))
    if errors:
        raise SystemExit(f"{SCRIPT.name}: " + "; ".join(f"{e.json_path}: {e.message}" for e in errors[:5]))
    f = facts or vfacts.Facts()
    v = json.loads(json.dumps(spec))
    try:
        v["title"], v["cta"] = f.fill(v["title"]), f.fill(v["cta"])
        for s in v["scenes"]:
            for k in video_script.TEXT_FIELDS:
                if k in s:
                    s[k] = f.fill(s[k])
            if "term" in s:
                s["term"] = f.lines(s["term"])
            if "answer" in s:
                s["answer"] = [f.fill(a) for a in s["answer"]]
    except vfacts.FactError as e:
        raise SystemExit(f"{VIDEO}: {e}") from None
    # The disclaimer is the reason this video is publishable at all, so it is checked by its content, not by its
    # presence: kube-noob holds none of these certifications, and a script that stops saying so must not render.
    disclaimer = " ".join(s.get("caption", "") for s in v["scenes"][-2:-1]).lower()
    missing = [p for p in ("not a certification", "not legal advice", "no fedramp") if p not in disclaimer]
    if missing:
        raise SystemExit(f"the scene before the end card must say {missing} in its caption; it says {disclaimer!r}")
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", type=Path)
    ap.add_argument("--engine", choices=sorted(ak.CREDITS), default="kokoro")
    ap.add_argument("--voice", default=ak.DEFAULT_VOICE)
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--speaker", type=int, default=ak.PIPER_SPEAKER)
    ap.add_argument("--music-db", type=ak.parse_music_db, default=ak.DEFAULT_MUSIC_DB)
    a = ap.parse_args()
    spec = load()  # the schema and every fact are checked before the voice model loads
    a.out.mkdir(parents=True, exist_ok=True)
    tl = voiceover.build(VIDEO, a.out, ak.Voice(a.engine, a.voice, a.speed, a.speaker), a.music_db, spec=spec)
    print(f"{VIDEO}: {tl['duration']:.1f} s, {len(tl['scenes'])} scenes -> {a.out}/timeline.json, audio.wav")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

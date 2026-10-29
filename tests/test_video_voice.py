"""What the voice model is given reads as words: no abbreviation keeps its periods (Kokoro takes each one as a sentence
break, so "2 a.m." came out as "two A. M."), and no spelled-out initialism has a lone "A" (said as "uh")."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "video"))

audio_kit = pytest.importorskip("audio_kit")  # needs numpy, as the video job installs

PLACEHOLDER = re.compile(r"\{[^}]*\}")


def _spoken() -> list[str]:
    lines = audio_kit.walkthrough_lines(fill=False)

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("vo"):
                lines.append(node.get("say") or node["vo"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(json.loads((ROOT / "demos" / "video" / "stage" / "videos.json").read_text(encoding="utf-8")))
    return lines


def test_every_spoken_line_reads_as_words() -> None:
    lines = _spoken()
    assert len(lines) > 20
    for line in lines:
        text = PLACEHOLDER.sub("", audio_kit.speakable(line))
        assert not re.search(r"[A-Za-z]\.[A-Za-z0-9]", text), text
        assert not re.search(r"\b[A-Z] A [A-Z]\b", text), text


def test_the_known_mispronunciations() -> None:
    assert audio_kit.speakable("breaks at 2 a.m., the fastest") == "breaks at 2 AM, the fastest"
    assert audio_kit.speakable("the RHACS policy") == "the RH ACS policy"
    assert audio_kit.speakable("On OpenShift 4.22, `kube-noob`") == "On OpenShift 4 22, kube noob"

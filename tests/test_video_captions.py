"""Captions and the YouTube description come from the render itself: cues fit the caption box and follow the voice,
and the description's chapters are the real scene times, valid for YouTube (first at 0:00, none under 10 s)."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "video"))

import captions  # noqa: E402

IDS = ["title", "audit", "diagnose", "protocol", "learn", "learning", "posture", "selftest", "end"]
MARKS = dict(zip(IDS, [0.3, 12.9, 37.0, 58.9, 74.0, 90.3, 108.7, 127.9, 140.4], strict=True))  # a real 0.6.0 render
LINE = (
    "Here is a Deployment that works on a laptop. On OpenShift 4.22, kube-noob scores it 37 out of 100. The password "
    "is hard-coded, the UID is pinned, and privilege escalation is on. Every finding carries the fix and the RHACS "
    "policy it would trip. One command applies the safe fixes, and it tells you what it left for a human."
)


def test_cues_fit_the_caption_box_and_cover_the_spoken_span(tmp_path: Path) -> None:
    cues = captions.cues(LINE, 1.0, 17.0)
    assert cues[0].start == 1.0 and cues[-1].end == 18.0
    assert all(a.end == b.start for a, b in itertools.pairwise(cues))  # back to back, in order
    for c in cues:
        lines = c.text.split("\n")
        assert len(lines) <= captions.LINES and all(len(ln) <= captions.LINE for ln in lines), c
    assert " ".join(c.text.replace("\n", " ") for c in cues) == LINE
    vtt = captions.write(tmp_path / "x.vtt", cues, 20).read_text()
    assert vtt.startswith("WEBVTT\n") and "00:00:01.000 --> " in vtt and vtt.count("-->") == len(cues)
    assert captions.chunks("`kube-noob` *rules*") == ["kube-noob rules"]  # Markdown is not read aloud or shown


def test_bad_cues_are_refused() -> None:
    a, b = captions.cues("First sentence here.", 0, 2), captions.cues("Second sentence here.", 1, 2)
    with pytest.raises(ValueError, match="overlaps"):
        captions.check(a + b)
    with pytest.raises(ValueError, match="after the video"):
        captions.check(captions.cues("A line that runs past the end.", 9, 3), duration=10)


def test_description_chapters_are_the_real_scene_times() -> None:
    text = captions.youtube_description(ROOT / "demos" / "youtube-walkthrough.md", MARKS, 152.4, IDS)
    chapters = text.split("Chapters\n", 1)[1].split("\n\n", 1)[0].splitlines()
    assert chapters[0].startswith("0:00 ") and chapters[1].startswith("0:12 ") and chapters[-1].startswith("2:20 ")
    assert len(chapters) == len(IDS) and "{" not in text  # every fact filled
    assert "kube-noob.com" in text and "trademarks of their respective owners" in text
    short_end = captions.youtube_description(ROOT / "demos" / "youtube-walkthrough.md", MARKS, 149.6, IDS)
    assert "Try it" not in short_end  # a 9 s end card is not a valid YouTube chapter: left out
    squeezed = {**MARKS, "diagnose": 15.0}
    with pytest.raises(SystemExit, match="YouTube needs 10 s"):
        captions.youtube_description(ROOT / "demos" / "youtube-walkthrough.md", squeezed, 152.4, IDS)
    assert captions.chapter_time(3725) == "1:02:05"

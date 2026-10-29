"""WebVTT captions for the kube-noob videos, from the voice-over timings, for the website, YouTube and LinkedIn
(which play muted until someone taps).

Each spoken line becomes cues of at most two lines of 42 characters, split at sentence and clause boundaries (a
clause too long for one cue is cut at the word nearest its middle, so no word is left alone on screen), and timed in
proportion to their length inside the span the voice actually speaks, every cue on screen for at least MIN_CUE.
voiceover.py writes kube-noob-<video>.vtt for the animated videos and audio_kit.py score writes
kube-noob-walkthrough.vtt. Standard library only.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

LINE = 42  # characters per caption line (the common broadcast and YouTube guideline)
LINES = 2
MIN_CUE = 0.8  # seconds


@dataclass(frozen=True)
class Cue:
    start: float
    end: float
    text: str


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[`*_]", "", text)).strip()


def _wrap(text: str) -> list[str]:
    """Fewest lines of at most LINE characters; two lines are balanced, so neither is a lone word."""
    lines: list[str] = []
    for word in text.split(" "):
        if lines and len(lines[-1]) + 1 + len(word) <= LINE:
            lines[-1] += " " + word
        else:
            lines.append(word)
    if len(lines) != 2 or max(map(len, lines)) > LINE:  # a word wider than a line: check() refuses the cue
        return lines
    words = text.split(" ")
    cuts = [(" ".join(words[:i]), " ".join(words[i:])) for i in range(1, len(words))]
    return list(min((c for c in cuts if max(map(len, c)) <= LINE), key=lambda c: max(map(len, c))))


def _fits(text: str) -> bool:
    return len(_wrap(text)) <= LINES


def _halves(piece: str) -> list[str]:
    """A clause too long for one cue, cut at the word nearest its middle, and again while a half does not fit."""
    words = piece.split(" ")
    if _fits(piece) or len(words) == 1:  # a single word wider than the box is refused by check()
        return [piece]
    cut = min(range(1, len(words)), key=lambda i: abs(len(" ".join(words[:i])) - len(" ".join(words[i:]))))
    return _halves(" ".join(words[:cut])) + _halves(" ".join(words[cut:]))


def chunks(text: str) -> list[str]:
    """Split a spoken line into caption-sized pieces: sentences first, then clauses, then balanced halves."""
    out: list[str] = []
    for sentence in re.split(r"(?<=[.!?])\s+", _clean(text)):
        if not sentence:
            continue
        parts = [sentence] if _fits(sentence) else [p for p in re.split(r"(?<=[,;:])\s+", sentence) if p]
        piece = ""
        for part in parts:
            if not _fits(part):
                out.extend([piece] if piece else [])
                *head, piece = _halves(part)  # the last half can take a short clause that follows it
                out.extend(head)
            elif piece and not _fits(f"{piece} {part}"):
                out.append(piece)
                piece = part
            else:
                piece = f"{piece} {part}".strip()
        if piece:
            out.append(piece)
    return out


def _durations(lengths: list[int], duration: float) -> list[float]:
    """Time in proportion to length, but at least MIN_CUE per cue, the rest shared by the longer ones."""
    if MIN_CUE * len(lengths) > duration:  # no way to give every cue MIN_CUE: proportional, and check() says why
        return [duration * n / sum(lengths) for n in lengths]
    fixed: set[int] = set()
    while True:
        left = duration - MIN_CUE * len(fixed)
        free = sum(n for i, n in enumerate(lengths) if i not in fixed)
        d = [MIN_CUE if i in fixed else left * n / free for i, n in enumerate(lengths)]
        short = {i for i, x in enumerate(d) if x < MIN_CUE - 1e-9} - fixed
        if not short or len(fixed | short) == len(lengths):
            return d
        fixed |= short


def cues(text: str, start: float, duration: float) -> list[Cue]:
    """Cues for one spoken line that starts at `start` and lasts `duration` seconds."""
    pieces = chunks(text)
    if not pieces or duration <= 0:
        return []
    out: list[Cue] = []
    t = start
    for i, (p, d) in enumerate(zip(pieces, _durations([len(p) for p in pieces], duration), strict=True)):
        end = start + duration if i == len(pieces) - 1 else t + d
        out.append(Cue(round(t, 3), round(end, 3), "\n".join(_wrap(p))))
        t = end
    return out


def _ts(t: float) -> str:
    ms = round(t * 1000)
    h, rest = divmod(ms, 3_600_000)
    m, rest = divmod(rest, 60_000)
    s, ms = divmod(rest, 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def check(all_cues: list[Cue], duration: float | None = None) -> None:
    """Cues are in order, do not overlap, are long enough to read and fit the caption box."""
    prev_end = 0.0
    for c in all_cues:
        if c.start < prev_end - 1e-3 or c.end <= c.start:
            raise ValueError(f"cue {c.text!r} at {c.start}-{c.end} overlaps or is empty")
        if c.end - c.start < MIN_CUE - 2e-3:
            raise ValueError(f"cue {c.text!r} is on screen for only {c.end - c.start:.2f} s")
        lines = c.text.split("\n")
        if len(lines) > LINES or any(len(ln) > LINE for ln in lines):
            raise ValueError(f"cue {c.text!r} does not fit {LINES} lines of {LINE} characters")
        prev_end = c.end
    if duration is not None and all_cues and all_cues[-1].end > duration + 1e-3:
        raise ValueError(f"the last cue ends at {all_cues[-1].end} s, after the video ({duration} s)")


def write(path: Path, all_cues: Iterable[Cue], duration: float | None = None) -> Path:
    cs = list(all_cues)
    check(cs, duration)
    body = "".join(f"\n{i}\n{_ts(c.start)} --> {_ts(c.end)}\n{c.text}\n" for i, c in enumerate(cs, 1))
    path.write_text("WEBVTT\n" + body, encoding="utf-8")
    return path


def chapter_time(t: float) -> str:
    """YouTube chapter timestamp: m:ss (or h:mm:ss)."""
    s = int(t)
    h, rest = divmod(s, 3600)
    m, s = divmod(rest, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


YOUTUBE_MIN_CHAPTER = 10.0  # seconds: YouTube ignores every chapter when one is shorter


def youtube_description(script: Path, marks: dict[str, float], total: float, ids: list[str]) -> str:
    """The YouTube description in a script (demos/youtube-walkthrough.md), its {facts} filled from the code and its
    chapter times taken from the scene marks of this render (one chapter per scene id, the first at 0:00). An end
    chapter shorter than YouTube's minimum is left out; any other short chapter is an error."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import facts

    text = script.read_text(encoding="utf-8")
    block = text.split("**Description:**", 1)[1].split("```", 2)[1]
    block = facts.Facts().fill(block.split("\n", 1)[1] if block.startswith("text") else block)
    lines = block.splitlines()
    first = lines.index("Chapters") + 1
    titles: list[str] = []
    while first + len(titles) < len(lines) and re.match(r"^\d+:\d\d ", lines[first + len(titles)]):
        titles.append(lines[first + len(titles)].split(" ", 1)[1])
    if len(titles) != len(ids):
        raise SystemExit(f"{script.name}: {len(titles)} chapters, one per scene expected ({len(ids)})")
    starts = [0.0] + [marks[s] for s in ids[1:]]
    ends = [*starts[1:], total]
    chapters = []
    for i, (title, a, b) in enumerate(zip(titles, starts, ends, strict=True)):
        if b - a < YOUTUBE_MIN_CHAPTER:
            if i == len(titles) - 1:
                continue
            raise SystemExit(f"chapter {title!r} lasts {b - a:.1f} s; YouTube needs {YOUTUBE_MIN_CHAPTER:.0f} s")
        chapters.append(f"{chapter_time(a)} {title}")
    lines[first : first + len(titles)] = chapters
    return "\n".join(lines).strip() + "\n"

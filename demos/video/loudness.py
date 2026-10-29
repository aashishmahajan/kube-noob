"""Loudness for the kube-noob videos: measure, normalise and check against the brand's sound spec.

The spec is in docs/brand/tokens.json (video.loudness): -16 LUFS integrated for a video with a voice, -20 for music
alone, within 0.5 LU, true peak at most -1.5 dBTP. audio_kit.py normalises every mix with normalize() before it is
encoded, and verify() measures the finished file, which is refused if it is out of spec or its audio and picture
differ in length. Needs only ffmpeg and ffprobe on PATH.

  python demos/video/loudness.py <file.mp4|wav>...                  measure (JSON)
  python demos/video/loudness.py --verify [--music-only] <file.mp4>  exit 1 unless it meets the spec
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
RATE = 48_000

TP_HEADROOM = 0.5  # dB kept under the true-peak limit when normalising: the AAC encode adds a little


def loudness_spec(voiced: bool) -> tuple[float, float, float]:
    """(integrated LUFS, tolerance LU, true-peak limit dBTP) from the brand tokens; music alone sits lower."""
    tokens = json.loads((HERE.parents[1] / "docs" / "brand" / "tokens.json").read_text(encoding="utf-8"))
    spec = tokens["video"]["loudness"]
    return float(spec["integrated"] if voiced else spec["musicOnly"]), float(spec["tolerance"]), float(spec["truePeak"])


def _run(args: list[str], *, check: bool, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    """ffmpeg or ffprobe from PATH, with arguments built here."""
    return subprocess.run(args, text=True, check=check, capture_output=capture_output)


def measure(path: Path) -> dict[str, float]:
    """EBU R128 integrated loudness (LUFS), true peak (dBTP), loudness range and gate threshold of a file's audio."""
    r = _run(
        [
            "ffmpeg",
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-map",
            "0:a:0",
            "-af",
            "loudnorm=print_format=json",
            "-f",
            "null",
            "-",
        ],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0 or "{" not in r.stderr:
        raise SystemExit(f"cannot measure the loudness of {path}: {r.stderr.strip()[-300:]}")
    d = json.loads(r.stderr[r.stderr.rindex("{") : r.stderr.rindex("}") + 1])  # loudnorm prints its JSON last
    return {
        "I": float(d["input_i"]),
        "TP": float(d["input_tp"]),
        "LRA": float(d["input_lra"]),
        "thresh": float(d["input_thresh"]),
    }


def normalize(wav: Path, voiced: bool) -> dict[str, float]:
    """Loudness normalisation of wav, in place. One linear gain to the target, then (only if that pushes the true
    peak over the limit) a look-ahead limiter on a 4x oversampled copy, where sample peaks are true peaks; limiting
    lowers the loudness a little, so the gain is corrected by the measured shortfall and the pass repeated until both
    hold. Processing is in floating point, so the gain never clips. A single loudnorm pass in linear mode cannot do
    this: it gives up loudness to keep the peak (the teaser came out at -17.6 LUFS that way). Returns the measurement
    of the result; raises SystemExit if it misses."""
    target, _, tp = loudness_spec(voiced)
    ceiling = tp - TP_HEADROOM
    m = measure(wav)
    if m["I"] < -70:
        raise SystemExit(f"{wav} is silent ({m['I']} LUFS)")
    out = wav.with_name(f".{wav.stem}.norm.wav")
    gain = target - m["I"]
    limit = m["TP"] + gain > ceiling
    result = m
    lim_db = ceiling - 0.1  # resampling back to 48 kHz can overshoot a little: lowered by what is measured
    try:
        for _ in range(8):
            af = f"aformat=sample_fmts=flt,volume={gain:.3f}dB"
            if limit:
                af += f",aresample={4 * RATE},alimiter=limit={10 ** (lim_db / 20):.6f}:attack=1:release=60"
                af += f":level=false,aresample={RATE}"
            _run(["ffmpeg", "-v", "error", "-y", "-i", str(wav), "-af", af, "-c:a", "pcm_s24le", str(out)], check=True)
            result = measure(out)
            if abs(result["I"] - target) <= 0.1 and result["TP"] <= ceiling:  # the full headroom, for the encode
                break
            gain += target - result["I"]
            if result["TP"] > ceiling:
                limit = True
                lim_db -= result["TP"] - ceiling + 0.05
        else:
            raise SystemExit(
                f"{wav}: normalised to {result['I']} LUFS / {result['TP']} dBTP, wanted {target} / {ceiling}"
            )
        out.replace(wav)
    finally:
        out.unlink(missing_ok=True)
    return result


def streams(video: Path) -> dict[str, float]:
    """Duration in seconds of the first video and the first audio stream (missing streams are absent)."""
    out: dict[str, float] = {}
    for kind, sel in (("video", "v:0"), ("audio", "a:0")):
        r = _run(
            [
                "ffprobe",
                "-v",
                "error",
                "-select_streams",
                sel,
                "-show_entries",
                "stream=duration",
                "-of",
                "default=nw=1:nk=1",
                str(video),
            ],
            check=True,
            capture_output=True,
        )
        if r.stdout.strip() and r.stdout.strip() != "N/A":
            out[kind] = float(r.stdout.strip().splitlines()[0])
    return out


def verify(video: Path, voiced: bool, fps: float = 30.0) -> dict[str, Any]:
    """The finished file meets the brand's sound spec: integrated loudness within the tolerance of the target, true
    peak at most the limit, and audio as long as the picture (within a frame). Raises SystemExit otherwise."""
    target, tol, tp = loudness_spec(voiced)
    m = measure(video)
    d = streams(video)
    problems = []
    if abs(m["I"] - target) > tol:
        problems.append(f"loudness {m['I']:.1f} LUFS, wanted {target} ± {tol}")
    if m["TP"] > tp:
        problems.append(f"true peak {m['TP']:.1f} dBTP, limit {tp}")
    if "video" not in d or "audio" not in d:
        problems.append(f"streams {sorted(d)}: needs one video and one audio stream")
    elif abs(d["video"] - d["audio"]) > 1 / fps + 0.03:  # AAC adds about 21 ms of priming
        problems.append(f"audio {d['audio']:.3f} s against video {d['video']:.3f} s")
    if problems:
        raise SystemExit(f"{video.name}: " + "; ".join(problems))
    return {"loudness": m, "durations": d}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", type=Path, nargs="+")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--music-only", action="store_true", help="no voice-over: the target is -20 LUFS")
    a = ap.parse_args(argv)
    for f in a.files:
        out = verify(f, voiced=not a.music_only) if a.verify else {"loudness": measure(f)}
        print(json.dumps({"file": str(f), **out}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

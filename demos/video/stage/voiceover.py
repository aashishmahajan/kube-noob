#!/usr/bin/env python3
"""Voice-over, music and timing for one animated video in videos.json, made locally and for free.

Usage: python voiceover.py <teaser|sidecar|mcp> <out-dir> [--speaker N]

Writes <out-dir>/timeline.json (scene start times and lengths, read by stage.html) and <out-dir>/audio.wav (48 kHz
stereo: voice-over, a generated music bed and a few generated sound effects).

Voice: Piper (pip install piper-tts) with the LibriTTS "high" voice, licensed CC BY 4.0 (credited on the end card).
The voice is downloaded once from the Piper GitHub release, checked against VOICE_SHA256, and cached in
~/.cache/kube-noob-video. Music and effects are synthesized here with numpy; nothing else is downloaded.
Needs: python3 with piper-tts and numpy, and ffmpeg on PATH (to resample the voice to 48 kHz).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import wave
from pathlib import Path
from typing import Any

import numpy as np

HERE = Path(__file__).resolve().parent
RATE = 48_000
VOICE = "en-us-libritts-high"
VOICE_URL = f"https://github.com/rhasspy/piper/releases/download/v0.0.2/voice-{VOICE}.tar.gz"
VOICE_SHA256 = "328e3e9cb573a43a6c5e1aeca386e971232bdb1418a74d4674cf726c973a0ea8"
DEFAULT_SPEAKER = 37
VO_LEAD = 0.45
VO_TAIL = 0.75
FPS = 30


def voice_files() -> tuple[Path, Path]:
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "kube-noob-video" / "voices" / VOICE
    model, config = cache / f"{VOICE}.onnx", cache / f"{VOICE}.onnx.json"
    if model.is_file() and config.is_file():
        return model, config
    cache.mkdir(parents=True, exist_ok=True)
    print(f"downloading the Piper voice {VOICE} (CC BY 4.0) from GitHub ...", file=sys.stderr)
    with urllib.request.urlopen(VOICE_URL, timeout=120) as resp:  # noqa: S310 - fixed https URL, hash checked below
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != VOICE_SHA256:
        raise SystemExit(f"voice archive sha256 {digest} does not match {VOICE_SHA256}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name).name
            if member.isfile() and name in {model.name, config.name}:
                src = tar.extractfile(member)
                if src is not None:
                    (cache / name).write_bytes(src.read())
    if not (model.is_file() and config.is_file()):
        raise SystemExit("the voice archive did not contain the expected model files")
    return model, config


def to_rate(samples: np.ndarray, rate: int) -> np.ndarray:
    """Resample mono float audio to RATE with ffmpeg (higher quality than interpolation)."""
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "in.wav", Path(tmp) / "out.raw"
        write_wav(src, samples[:, None], rate)
        subprocess.run(
            ["ffmpeg", "-v", "error", "-y", "-i", str(src), "-ar", str(RATE), "-ac", "1", "-f", "f32le", str(dst)],
            check=True,
        )
        return np.fromfile(dst, dtype="<f4").astype(np.float64)


def write_wav(path: Path, audio: np.ndarray, rate: int) -> None:
    pcm = (np.clip(audio, -1.0, 1.0) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(audio.shape[1])
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())


def synthesize(texts: list[str], speaker: int) -> list[np.ndarray]:
    from piper import PiperVoice
    from piper.config import SynthesisConfig

    model, config = voice_files()
    voice = PiperVoice.load(str(model), config_path=str(config))
    cfg = SynthesisConfig(speaker_id=speaker, length_scale=1.04, noise_scale=0.6, noise_w_scale=0.7)
    out = []
    for text in texts:
        chunks = list(voice.synthesize(text, syn_config=cfg))
        gap = np.zeros(int(0.18 * voice.config.sample_rate))
        parts: list[np.ndarray] = []
        for c in chunks:
            parts += [c.audio_float_array.astype(np.float64), gap]
        audio = to_rate(np.concatenate(parts[:-1]), voice.config.sample_rate)
        peak = np.max(np.abs(audio)) or 1.0
        out.append(audio / peak * 0.7)
    return out


# ---------------------------------------------------------------- music and effects

CHORDS = [  # A minor: Am, F, C, G (voiced in the third octave, root doubled an octave down)
    ("A2", ["A3", "C4", "E4"]),
    ("F2", ["F3", "A3", "C4"]),
    ("C3", ["G3", "C4", "E4"]),
    ("G2", ["G3", "B3", "D4"]),
]


def samples(seconds: float) -> int:
    return int(round(seconds * RATE))


def hz(note: str) -> float:
    names = {"C": -9, "D": -7, "E": -5, "F": -4, "G": -2, "A": 0, "B": 2}
    return 440.0 * 2 ** ((names[note[0]] + 12 * (int(note[1:]) - 4)) / 12)


def tone(freq: float, n: int, harmonics: int, detune: float = 0.0, phase: float = 0.0) -> np.ndarray:
    t = np.arange(n) / RATE
    out = np.zeros(n)
    for k in range(1, harmonics + 1):
        out += np.sin(2 * np.pi * freq * (1 + detune) * k * t + phase * k) / k**1.3
    return out


def envelope(n: int, attack: float, release: float) -> np.ndarray:
    env = np.ones(n)
    a, r = min(n, int(attack * RATE)), min(n, int(release * RATE))
    if a:
        env[:a] = np.linspace(0, 1, a) ** 2
    if r:
        env[-r:] *= np.linspace(1, 0, r) ** 2
    return env


def reverb(x: np.ndarray, seconds: float = 2.2, mix: float = 0.35, seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    n = int(seconds * RATE)
    ir = rng.standard_normal(n) * np.exp(-np.arange(n) / RATE * (6.9 / seconds))
    ir /= np.sqrt(np.sum(ir**2))
    size = 1 << int(np.ceil(np.log2(len(x) + n)))
    wet = np.fft.irfft(np.fft.rfft(x, size) * np.fft.rfft(ir, size), size)[: len(x)]
    return (1 - mix) * x + mix * wet


def pad_bed(total: float, start: float, bar: float = 4.0) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    t0 = int(start * RATE)
    i = 0
    pos = t0
    while pos < n:
        root, notes = CHORDS[i % len(CHORDS)]
        length = min(int((bar + 1.6) * RATE), n - pos)
        seg = np.zeros(length)
        seg += 0.55 * tone(hz(root), length, 2)
        for j, note in enumerate(notes):
            seg += 0.32 * tone(hz(note), length, 5, detune=0.0015 * (j - 1))
            seg += 0.22 * tone(hz(note), length, 3, detune=-0.002 * (j - 1), phase=0.7)
        seg *= envelope(length, 1.4, 1.6)
        out[pos : pos + length] += seg
        pos += int(bar * RATE)
        i += 1
    # a soft pluck on every eighth note at 96 bpm, walking the chord tones an octave up
    step = 60 / 96 / 2
    k = 0
    tpos = start + 0.5
    while tpos < total - 0.5:
        _, notes = CHORDS[int((tpos - start) // bar) % len(CHORDS)]
        f = hz(notes[k % 3]) * 2
        m = int(0.6 * RATE)
        p = int(tpos * RATE)
        m = min(m, n - p)
        pluck = tone(f, m, 3) * np.exp(-np.arange(m) / RATE * 7.0) * envelope(m, 0.004, 0.05)
        out[p : p + m] += 0.10 * pluck
        k += 1
        tpos += step
    fade_in = envelope(n - t0, 2.0, 0.0)
    out[t0:] *= fade_in
    out[: max(t0, 0)] = 0
    return out


def alarm(total: float, start: float, end: float) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    a, b = int(start * RATE), int(end * RATE)
    m = b - a
    t = np.arange(m) / RATE
    hum = tone(55.0, m, 6) * (0.55 + 0.45 * np.sin(2 * np.pi * 1.6 * t) ** 2)
    beep = np.sin(2 * np.pi * 659.25 * t) * ((t % 1.25) < 0.16) * 0.25
    seg = np.tanh(1.6 * (hum + beep)) * envelope(m, 0.4, 1.2)
    out[a:b] = 0.55 * seg
    return out


def whoosh(total: float, at: float, length: float = 1.4, seed: int = 3) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    m = int(length * RATE)
    p = int(at * RATE)
    m = min(m, n - p)
    noise = np.random.default_rng(seed).standard_normal(m)
    y = np.zeros(m)
    state = 0.0
    for i in range(m):  # one-pole low-pass whose cutoff sweeps up, then down
        x = i / m
        alpha = 0.02 + 0.5 * np.sin(np.pi * x) ** 2
        state += alpha * (noise[i] - state)
        y[i] = state
    out[p : p + m] = y * np.sin(np.pi * np.linspace(0, 1, m)) ** 1.5 * 0.9
    return out


def chime(total: float, at: float) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    m = min(int(2.8 * RATE), n - int(at * RATE))
    p = int(at * RATE)
    t = np.arange(m) / RATE
    seg = np.zeros(m)
    for f, g in ((hz("A5"), 0.5), (hz("E6"), 0.35), (hz("A6"), 0.25), (2217.46, 0.12)):
        seg += g * np.sin(2 * np.pi * f * t) * np.exp(-t * 2.2)
    out[p : p + m] = seg * envelope(m, 0.005, 0.4) * 0.6
    return out


def blip(total: float, at: float) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    m = int(0.16 * RATE)
    p = int(at * RATE)
    m = min(m, n - p)
    t = np.arange(m) / RATE
    freq = 880 + 520 * t / 0.16
    seg = np.sin(2 * np.pi * np.cumsum(freq) / RATE) * np.exp(-t * 22)
    out[p : p + m] = seg * 0.35
    return out


def smooth(x: np.ndarray, seconds: float) -> np.ndarray:
    k = max(1, int(seconds * RATE))
    c = np.cumsum(np.concatenate([[0.0], x]))
    y = (c[k:] - c[:-k]) / k
    return np.concatenate([np.full(k - 1, y[0]), y])


# ---------------------------------------------------------------- timeline


def build(video: str, out: Path, speaker: int) -> dict[str, Any]:
    spec = json.loads((HERE / "videos.json").read_text(encoding="utf-8"))
    v = spec["videos"][video]
    scenes = [dict(s) for s in v["scenes"]]
    texts = [s.get("say") or s["vo"] for s in scenes if s.get("vo")]
    clips = iter(synthesize(texts, speaker))
    t = 0.0
    vo_track: list[tuple[float, np.ndarray]] = []
    for s in scenes:
        s["start"] = round(t, 3)
        if s.get("vo"):
            clip = next(clips)
            s["voStart"] = VO_LEAD
            s["voDur"] = round(len(clip) / RATE, 3)
            vo_track.append((t + VO_LEAD, clip))
            dur = max(s["min"], VO_LEAD + s["voDur"] + VO_TAIL)
        else:
            dur = s["min"]
        s["dur"] = round(round(dur * FPS) / FPS, 3)
        t += s["dur"]
    total = round(t, 3)
    n = samples(total)

    voice = np.zeros(n)
    for at, clip in vo_track:
        p = int(at * RATE)
        voice[p : p + len(clip)] += clip[: n - p]

    kinds = {s["kind"]: s for s in scenes}
    music_start = 0.0
    music = np.zeros(n)
    fx = np.zeros(n)
    if "alarm" in kinds:
        d = kinds["dust"]
        music += alarm(total, 0.0, d["start"] + d["dur"] + 0.6)[:n]
        music_start = kinds["arrive"]["start"] - 0.2
        fx += whoosh(total, kinds["arrive"]["start"] + 0.2)[:n]
    if "beam" in kinds:
        fx += whoosh(total, kinds["beam"]["start"] + 0.5, 1.1, seed=5)[:n]
    if "loopback" in kinds:
        lb = kinds["loopback"]
        for i in range(5):
            fx += blip(total, lb["start"] + 1.4 + i * 1.15)[:n] * 0.5
    if "explain" in kinds:
        ex = kinds["explain"]
        for i in range(3):
            fx += blip(total, ex["start"] + 1.6 + i * 1.3)[:n]
    end = kinds["end"]
    fx += chime(total, end["start"] + 0.15)[:n]
    music += 0.9 * pad_bed(total, music_start)[:n]

    duck = 1.0 - 0.55 * np.clip(smooth(np.abs(voice), 0.12) * 12, 0, 1)
    duck = smooth(duck, 0.35)
    bed = reverb(music, 2.6, 0.4) * duck * 0.16
    effects = reverb(fx, 1.6, 0.3) * 0.5
    left = voice * 0.92 + bed + effects
    right = voice * 0.92 + np.roll(bed, int(0.011 * RATE)) + np.roll(effects, int(0.007 * RATE))
    mix = np.stack([left, right], axis=1)
    mix *= envelope(n, 0.05, 1.2)[:, None]
    mix /= max(1.0, np.max(np.abs(mix)) / 0.95)
    out.mkdir(parents=True, exist_ok=True)
    write_wav(out / "audio.wav", mix, RATE)

    timeline = {
        "video": video,
        "title": v["title"],
        "cta": v["cta"],
        "end": spec["end"],
        "fps": FPS,
        "duration": total,
        "scenes": scenes,
    }
    (out / "timeline.json").write_text(json.dumps(timeline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return timeline


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("video", choices=["teaser", "sidecar", "mcp"])
    ap.add_argument("out", type=Path)
    ap.add_argument("--speaker", type=int, default=DEFAULT_SPEAKER, help="LibriTTS speaker id (0-903)")
    a = ap.parse_args()
    tl = build(a.video, a.out, a.speaker)
    print(f"{a.video}: {tl['duration']:.1f} s, {len(tl['scenes'])} scenes -> {a.out}/timeline.json, audio.wav")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Voice and music for the kube-noob demo videos, made locally and for free.

Voice: Kokoro-82M (Apache-2.0) through kokoro-onnx (MIT), voice af_heart by default. The model and the voice pack are
downloaded once from the kokoro-onnx GitHub release, checked against the sha256 sums below and cached in
~/.cache/kube-noob-video. Piper with the LibriTTS voice (CC BY 4.0), the earlier voice, stays available as
--engine piper.

Music: the kube-noob brand bed, generated here with numpy. It is a bright, steady business groove in C major at
104 bpm (electric piano, plucks, bass, a light four-on-the-floor kick, claps and hats), with the kube-noob motif
(C, G, high C on a bell) every eight bars and as the sting on the end card. It is ducked under the voice, and its
level is set with --music-db: the music's loudness relative to the voice, -12 by default; -18 is quieter, -6
louder, and `off` removes it.

Usage:
  python audio_kit.py remix <dir> [--music-db -12] [--video <file.mp4>]
      mix <dir>/voice.wav and <dir>/music.wav again at a new music level into <dir>/audio.wav; with --video, replace
      that video's sound with it (the picture is copied, not encoded again)
  python audio_kit.py narrate walkthrough <dir> [--engine kokoro] [--voice af_heart] [--speed 1.0]
      speak the walkthrough voice-over (the table in demos/youtube-walkthrough.md) into <dir>/narration/ and write
      the length of each line to <dir>/narration.json (build_scenes.py holds each scene until its line is spoken)
  python audio_kit.py score <dir> <page> [--music-db -12]
      after capture_page.js: place the narration (if any) at the scene marks capture_page.js wrote, add the brand
      music, and put the sound into <dir>/kube-noob-<page>.mp4; with narration, also kube-noob-<page>.vtt
      (captions), and for the walkthrough youtube-description.txt (its facts filled, chapters at the real times)
  python audio_kit.py verify <file.mp4>... [--music-only]
      check a finished video against the brand's sound spec (docs/brand/tokens.json): -16 LUFS within 0.5 LU (-20
      for music alone), true peak at most -1.5 dBTP, audio as long as the picture; exits non-zero otherwise

Loudness is normalised before encoding (measure; hold the true peaks down with an oversampled limiter if the gain
needs it; one exact linear gain), and measured again on the finished file, which is refused if it is out of spec.

Needs: python3 with numpy and kokoro-onnx (pip install kokoro-onnx numpy), or piper-tts for --engine piper, and
ffmpeg on PATH.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import wave
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import captions  # noqa: E402
from loudness import normalize, verify  # noqa: E402

RATE = 48_000
DEFAULT_MUSIC_DB = -12.0
MUSIC_RMS = 0.12  # music.wav is stored at this loudness; --music-db scales it against the voice
VOICE_PEAK = 0.7

KOKORO_RELEASE = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0"
KOKORO_FILES = {
    "kokoro-v1.0.onnx": "7d5df8ecf7d4b1878015a32686053fd0eebe2bc377234608764cc0ef3636a6c5",
    "voices-v1.0.bin": "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d",
}
DEFAULT_VOICE = "af_heart"
PIPER_VOICE = "en-us-libritts-high"
PIPER_URL = f"https://github.com/rhasspy/piper/releases/download/v0.0.2/voice-{PIPER_VOICE}.tar.gz"
PIPER_SHA256 = "328e3e9cb573a43a6c5e1aeca386e971232bdb1418a74d4674cf726c973a0ea8"
PIPER_SPEAKER = 37
CREDITS = {
    "kokoro": "Voice: Kokoro-82M (Apache-2.0) · Music: generated for kube-noob",
    "piper": "Voice: Piper, LibriTTS voice (CC BY 4.0) · Music: generated for kube-noob",
}

# Words the voice models say wrongly, checked against the phonemes Kokoro produces.
PRONOUNCE = [
    (r"\bkube-noob\b", "kube noob"),
    (r"\bRHACS\b", "R H A C S"),
    (r"\bUID\b", "U I D"),
    (r"\boc\b", "O C"),
    (r"\bkubectl\b", "kube control"),
    (r"\bexit code 137\b", "exit code one thirty-seven"),
    (r"\b(\d)\.(\d\d)\b", r"\1 \2"),  # OpenShift 4.22 -> "four twenty-two"
    (r"\b2 a\.m\.", "two a.m."),
]


# ---------------------------------------------------------------- files


def cache_dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "kube-noob-video"


def fetch(url: str, sha256: str, dest: Path) -> Path:
    """Download url to dest once, refusing it unless its sha256 matches."""
    if dest.is_file() and _sha256(dest) == sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {dest.name} from {url} ...", file=sys.stderr)
    tmp = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=300) as resp, tmp.open("wb") as fh:  # noqa: S310 - fixed https URL
        while chunk := resp.read(1 << 20):
            digest.update(chunk)
            fh.write(chunk)
    if digest.hexdigest() != sha256:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{dest.name}: sha256 {digest.hexdigest()} does not match the pinned {sha256}")
    tmp.replace(dest)
    return dest


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def write_wav(path: Path, audio: np.ndarray) -> None:
    """Write 16-bit PCM at RATE; audio is (n,) or (n, channels) in -1..1."""
    if audio.ndim == 1:
        audio = audio[:, None]
    pcm = (np.clip(audio, -1.0, 1.0) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(audio.shape[1])
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm.tobytes())


def read_wav(path: Path) -> np.ndarray:
    with wave.open(str(path), "rb") as w:
        if w.getframerate() != RATE or w.getsampwidth() != 2:
            raise SystemExit(f"{path}: expected 16-bit audio at {RATE} Hz")
        data = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float64) / 32767
        return data.reshape(-1, w.getnchannels())


def to_rate(samples: np.ndarray, rate: int) -> np.ndarray:
    """Resample mono float audio to RATE with ffmpeg's resampler."""
    if rate == RATE:
        return samples.astype(np.float64)
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "in.raw", Path(tmp) / "out.raw"
        samples.astype("<f4").tofile(src)
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-y",
                "-f",
                "f32le",
                "-ar",
                str(rate),
                "-ac",
                "1",
                "-i",
                str(src),
                "-af",
                "aresample=resampler=soxr",
                "-ar",
                str(RATE),
                "-f",
                "f32le",
                str(dst),
            ],
            check=True,
        )
        return np.fromfile(dst, dtype="<f4").astype(np.float64)


# ---------------------------------------------------------------- voice


def speakable(text: str) -> str:
    """Plain words for the voice model: no Markdown, and the fixes in PRONOUNCE."""
    text = re.sub(r"[`*_]", "", text)
    for pattern, repl in PRONOUNCE:
        text = re.sub(pattern, repl, text)
    return re.sub(r"\s+", " ", text).strip()


class Voice:
    def __init__(
        self, engine: str = "kokoro", voice: str = DEFAULT_VOICE, speed: float = 1.0, speaker: int = PIPER_SPEAKER
    ) -> None:
        if engine not in CREDITS:
            raise SystemExit(f"unknown voice engine {engine!r}: use kokoro or piper")
        self.engine, self.voice, self.speed, self.speaker = engine, voice, speed, speaker
        self.credit = CREDITS[engine]
        self._say: Callable[[str], np.ndarray] = self._kokoro() if engine == "kokoro" else self._piper()

    def say(self, text: str) -> np.ndarray:
        audio = self._say(speakable(text))
        peak = float(np.max(np.abs(audio))) or 1.0
        return audio / peak * VOICE_PEAK

    def _kokoro(self) -> Callable[[str], np.ndarray]:
        from kokoro_onnx import Kokoro

        files = {
            name: fetch(f"{KOKORO_RELEASE}/{name}", sha, cache_dir() / "kokoro" / name)
            for name, sha in KOKORO_FILES.items()
        }
        model = Kokoro(str(files["kokoro-v1.0.onnx"]), str(files["voices-v1.0.bin"]))
        if self.voice not in model.get_voices():
            raise SystemExit(f"unknown Kokoro voice {self.voice!r}; choose from: {', '.join(model.get_voices())}")

        def say(text: str) -> np.ndarray:
            samples, rate = model.create(text, voice=self.voice, speed=self.speed, lang="en-us", sentence_pause=0.32)
            return to_rate(np.asarray(samples, dtype=np.float64), rate)

        return say

    def _piper(self) -> Callable[[str], np.ndarray]:
        from piper import PiperVoice
        from piper.config import SynthesisConfig

        folder = cache_dir() / "voices" / PIPER_VOICE
        model, config = folder / f"{PIPER_VOICE}.onnx", folder / f"{PIPER_VOICE}.onnx.json"
        if not (model.is_file() and config.is_file()):
            archive = fetch(PIPER_URL, PIPER_SHA256, folder / "voice.tar.gz")
            with tarfile.open(archive, mode="r:gz") as tar:
                for member in tar.getmembers():
                    name = Path(member.name).name
                    src = tar.extractfile(member) if member.isfile() else None
                    if src is not None and name in {model.name, config.name}:
                        (folder / name).write_bytes(src.read())
        voice = PiperVoice.load(str(model), config_path=str(config))
        cfg = SynthesisConfig(
            speaker_id=self.speaker, length_scale=1.04 / self.speed, noise_scale=0.6, noise_w_scale=0.7
        )

        def say(text: str) -> np.ndarray:
            gap = np.zeros(int(0.18 * voice.config.sample_rate))
            parts: list[np.ndarray] = []
            for c in voice.synthesize(text, syn_config=cfg):
                parts += [c.audio_float_array.astype(np.float64), gap]
            return to_rate(np.concatenate(parts[:-1]), voice.config.sample_rate)

        return say


# ---------------------------------------------------------------- the brand music

BPM = 104
BEAT = 60 / BPM
BAR = 4 * BEAT
PROGRESSION = [  # C, G, Am, F: bass root and the chord an octave up
    ("C3", ["C4", "E4", "G4"]),
    ("G2", ["B3", "D4", "G4"]),
    ("A2", ["A3", "C4", "E4"]),
    ("F2", ["A3", "C4", "F4"]),
]
MOTIF = ["C5", "G5", "C6"]


def hz(note: str) -> float:
    names = {"C": -9, "D": -7, "E": -5, "F": -4, "G": -2, "A": 0, "B": 2}
    return 440.0 * 2 ** ((names[note[0]] + 12 * (int(note[1:]) - 4)) / 12)


def _t(seconds: float) -> np.ndarray:
    return np.arange(int(seconds * RATE)) / RATE


def _edges(y: np.ndarray, attack: float = 0.004, release: float = 0.05) -> np.ndarray:
    a, r = min(len(y), int(attack * RATE)), min(len(y), int(release * RATE))
    if a:
        y[:a] *= np.linspace(0, 1, a)
    if r:
        y[-r:] *= np.linspace(1, 0, r)
    return y


def epiano(f: float, dur: float) -> np.ndarray:
    t = _t(dur)
    y = (
        np.sin(2 * np.pi * f * t)
        + 0.35 * np.sin(4 * np.pi * f * t) * np.exp(-t * 3)
        + 0.12 * np.sin(6 * np.pi * f * t) * np.exp(-t * 6)
    )
    return _edges(y * np.exp(-t * 1.6) * (1 + 0.07 * np.sin(2 * np.pi * 5.5 * t)), 0.004, 0.08)


def pluck(f: float, dur: float) -> np.ndarray:
    t = _t(dur)
    y = sum(np.sin(2 * np.pi * f * k * t) / k**2 * (-1) ** (k // 2) for k in (1, 3, 5, 7))
    return _edges(np.asarray(y) * np.exp(-t * 9), 0.002, 0.04)


def bass(f: float, dur: float) -> np.ndarray:
    t = _t(dur)
    y = np.sin(2 * np.pi * f * t) + 0.25 * np.sin(4 * np.pi * f * t)
    return _edges(np.tanh(1.4 * y * np.exp(-t * 2.4)), 0.006, 0.06)


def kick() -> np.ndarray:
    t = _t(0.32)
    freq = 45 + 75 * np.exp(-t * 28)
    return _edges(np.sin(2 * np.pi * np.cumsum(freq) / RATE) * np.exp(-t * 11), 0.001, 0.03)


def _noise(seconds: float, seed: int) -> np.ndarray:
    return np.random.default_rng(seed).standard_normal(int(seconds * RATE))


def clap(seed: int) -> np.ndarray:
    t = _t(0.22)
    n = np.diff(_noise(0.22, seed), prepend=0.0)
    bursts = sum(np.exp(-np.clip(t - d, 0, None) * 38) * (t >= d) for d in (0.0, 0.011, 0.022))
    return _edges(n * np.asarray(bursts) * 0.5, 0.001, 0.03)


def hat(seed: int) -> np.ndarray:
    t = _t(0.06)
    n = np.diff(np.diff(_noise(0.06, seed), prepend=0.0), prepend=0.0)
    return _edges(n * np.exp(-t * 70) * 0.25, 0.0005, 0.01)


def bell(f: float, dur: float) -> np.ndarray:
    t = _t(dur)
    y = np.sin(2 * np.pi * f * t + 1.6 * np.exp(-t * 2.5) * np.sin(2 * np.pi * 3.5 * f * t))
    return _edges(y * np.exp(-t * 1.7), 0.002, 0.2)


def _place(out: np.ndarray, at: float, seg: np.ndarray, gain: float, pan: float = 0.0) -> None:
    p = int(at * RATE)
    if p >= len(out) or p < 0:
        return
    m = min(len(seg), len(out) - p)
    left, right = np.sqrt((1 - pan) / 2), np.sqrt((1 + pan) / 2)
    out[p : p + m, 0] += gain * left * seg[:m]
    out[p : p + m, 1] += gain * right * seg[:m]


def reverb(x: np.ndarray, seconds: float = 1.8, mix: float = 0.25, seed: int = 7) -> np.ndarray:
    """A plain FFT convolution reverb, per channel."""
    rng = np.random.default_rng(seed)
    n = int(seconds * RATE)
    out = np.empty_like(x)
    for ch in range(x.shape[1]):
        ir = rng.standard_normal(n) * np.exp(-np.arange(n) / RATE * (6.9 / seconds))
        ir /= np.sqrt(np.sum(ir**2))
        size = 1 << int(np.ceil(np.log2(len(x) + n)))
        wet = np.fft.irfft(np.fft.rfft(x[:, ch], size) * np.fft.rfft(ir, size), size)[: len(x)]
        out[:, ch] = (1 - mix) * x[:, ch] + mix * wet
    return out


def motif(out: np.ndarray, at: float, gain: float = 0.5) -> None:
    """The kube-noob sting: C, G, high C on a bell over a soft C major chord."""
    for i, note in enumerate(MOTIF):
        _place(out, at + i * BEAT / 2, bell(hz(note), 2.6), gain * (0.8 + 0.1 * i), pan=-0.15 + 0.15 * i)
    for note in ("C4", "E4", "G4"):
        _place(out, at + BEAT, epiano(hz(note), 3.2), gain * 0.35)


def business_bed(total: float, start: float = 0.0, end_sting: float | None = None) -> np.ndarray:
    """The brand bed from `start` to `total` seconds (silent before), stereo, normalized to MUSIC_RMS."""
    out = np.zeros((int(total * RATE), 2))
    bars = int(np.ceil((total - start) / BAR)) + 1
    hats = claps = 0
    for b in range(bars):
        t0 = start + b * BAR
        if t0 >= total:
            break
        root, chord = PROGRESSION[b % len(PROGRESSION)]
        for beat, length in ((0.0, 1.4), (1.5, 0.9), (2.5, 1.3)):
            for j, note in enumerate(chord):
                _place(out, t0 + beat * BEAT, epiano(hz(note), length * BEAT + 0.3), 0.16, pan=-0.3 + 0.1 * j)
        for k in range(8):
            note = chord[(0, 1, 2, 1, 2, 0, 1, 2)[k]]
            _place(out, t0 + k * BEAT / 2, pluck(hz(note) * 2, 0.5), 0.10, pan=0.35)
        if b >= 1:
            for beat in (0.0, 1.5, 2.0, 3.5):
                _place(out, t0 + beat * BEAT, bass(hz(root), 0.9 * BEAT if beat % 1 else 1.4 * BEAT), 0.34)
            for k in range(4):
                hats += 1
                _place(out, t0 + (k + 0.5) * BEAT, hat(hats), 0.5, pan=0.4)
        if b >= 2:
            for beat in range(4):
                _place(out, t0 + beat * BEAT, kick(), 0.55)
            for beat in (1, 3):
                claps += 1
                _place(out, t0 + beat * BEAT, clap(claps), 0.22, pan=-0.1)
        if b % 8 == 4:
            motif(out, t0, 0.22)
    out = reverb(out, 1.6, 0.22)
    head = int(start * RATE)
    out[:head] = 0
    fade_in = min(len(out) - head, int(1.2 * RATE))
    if fade_in > 0:
        out[head : head + fade_in] *= np.linspace(0, 1, fade_in)[:, None]
    tail = min(len(out), int(2.5 * RATE))
    out[-tail:] *= np.linspace(1, 0, tail)[:, None] ** 2
    if end_sting is not None:
        sting = np.zeros_like(out)
        motif(sting, end_sting, 0.5)
        out += reverb(sting, 2.4, 0.35)
    rms = float(np.sqrt(np.mean(out[head:] ** 2))) if len(out) > head else 0.0
    out *= MUSIC_RMS / rms if rms else 1.0
    peak = float(np.max(np.abs(out))) if len(out) else 0.0
    return out * (0.98 / peak if peak > 0.98 else 1.0)  # stays a valid 16-bit stem


# ---------------------------------------------------------------- mixing


def smooth(x: np.ndarray, seconds: float) -> np.ndarray:
    k = max(1, int(seconds * RATE))
    c = np.cumsum(np.concatenate([[0.0], x]))
    y = (c[k:] - c[:-k]) / k
    return np.concatenate([np.full(k - 1, y[0]), y])


def music_gain(music_db: float | None) -> float:
    return 0.0 if music_db is None else 10 ** (music_db / 20)


def parse_music_db(value: str) -> float | None:
    if value.lower() in {"off", "none"}:
        return None
    db = float(value)
    if not -60 <= db <= 0:
        raise argparse.ArgumentTypeError("--music-db must be between -60 and 0 (or off)")
    return db


def mix(voice: np.ndarray, music: np.ndarray, music_db: float | None) -> np.ndarray:
    """voice (n, 2) and music (n, 2) -> the final stereo mix; music sits music_db under the voice, ducked 6 dB more
    while someone speaks."""
    n = max(len(voice), len(music))
    v = np.zeros((n, 2))
    v[: len(voice)] = voice
    m = np.zeros((n, 2))
    m[: len(music)] = music
    speaking = np.clip(smooth(np.abs(v[:, 0]), 0.12) * 12, 0, 1)
    duck = smooth(1.0 - 0.5 * speaking, 0.35)
    voice_rms = float(np.sqrt(np.mean(v[np.abs(v[:, 0]) > 0.01] ** 2))) if np.any(np.abs(v[:, 0]) > 0.01) else MUSIC_RMS
    out = v + m * (voice_rms / MUSIC_RMS) * music_gain(music_db) * duck[:, None]
    return out / max(1.0, float(np.max(np.abs(out))) / 0.95)


def write_stems(folder: Path, voice: np.ndarray, music: np.ndarray, music_db: float | None) -> Path:
    """voice.wav and music.wav (the stems remix reads) and audio.wav (the mix, normalised to the brand loudness)."""
    folder.mkdir(parents=True, exist_ok=True)
    if voice.ndim == 1:
        voice = np.stack([voice, voice], axis=1)
    write_wav(folder / "voice.wav", voice)
    write_wav(folder / "music.wav", music)
    write_wav(folder / "audio.wav", mix(voice, music, music_db))
    normalize(folder / "audio.wav", voiced=bool(np.any(np.abs(voice) > 0.01)))
    return folder / "audio.wav"


def remix(folder: Path, music_db: float | None) -> Path:
    voice = read_wav(folder / "voice.wav")
    write_wav(folder / "audio.wav", mix(voice, read_wav(folder / "music.wav"), music_db))
    normalize(folder / "audio.wav", voiced=bool(np.any(np.abs(voice) > 0.01)))
    return folder / "audio.wav"


def mux(video: Path, audio: Path, voiced: bool) -> None:
    """Replace video's sound with audio (already normalised by write_stems/remix; AAC 320k), copying the picture, and
    check the result against the brand's sound spec before it replaces the video."""
    with tempfile.TemporaryDirectory(dir=video.parent) as tmp:
        out = Path(tmp) / video.name
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-y",
                "-i",
                str(video),
                "-i",
                str(audio),
                "-map",
                "0:v",
                "-map",
                "1:a",
                "-c:v",
                "copy",
                "-c:a",
                "aac",
                "-b:a",
                "320k",
                "-ar",
                "48000",
                "-shortest",
                "-movflags",
                "+faststart",
                str(out),
            ],
            check=True,
        )
        verify(out, voiced)
        shutil.move(str(out), video)


def duration(video: Path) -> float:
    r = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(video)],
        check=True,
        capture_output=True,
        text=True,
    )
    return float(r.stdout.strip())


# ---------------------------------------------------------------- the transcript videos

WALKTHROUGH_IDS = ["title", "audit", "diagnose", "protocol", "learn", "learning", "posture", "selftest", "end"]
NARRATION_LEAD = {"title": 0.9, "end": 0.7}  # seconds after the scene's mark; other scenes use DEFAULT_LEAD
DEFAULT_LEAD = 0.45
NARRATION_TAIL = 0.8


def walkthrough_lines(fill: bool = True) -> list[str]:
    """The voice-over table in demos/youtube-walkthrough.md, one line per scene, its {facts} filled from the code."""
    text = (HERE.parent / "youtube-walkthrough.md").read_text(encoding="utf-8")
    section = text.split("## Voice-over for the rendered cut", 1)[1].split("\n## ", 1)[0]
    lines = [m.group(1).strip() for m in re.finditer(r"^\| \d+:\d\d \| (.+?) \|$", section, re.MULTILINE)]
    if len(lines) != len(WALKTHROUGH_IDS):
        raise SystemExit(
            f"expected {len(WALKTHROUGH_IDS)} voice-over rows in youtube-walkthrough.md, found {len(lines)}"
        )
    if not fill:
        return lines
    import facts  # demos/video/facts.py

    f = facts.Facts()
    try:
        return [f.fill(line) for line in lines]
    except facts.FactError as e:
        raise SystemExit(f"youtube-walkthrough.md: {e}") from None


def narrate(folder: Path, voice: Voice) -> dict[str, Any]:
    clips = folder / "narration"
    clips.mkdir(parents=True, exist_ok=True)
    info: dict[str, Any] = {"credit": voice.credit, "lines": {}}
    for scene_id, line in zip(WALKTHROUGH_IDS, walkthrough_lines(), strict=True):
        audio = voice.say(line)
        write_wav(clips / f"{scene_id}.wav", audio)
        lead = NARRATION_LEAD.get(scene_id, DEFAULT_LEAD)
        info["lines"][scene_id] = {
            "lead": lead,
            "seconds": round(len(audio) / RATE, 3),
            "minMs": int((lead + len(audio) / RATE + NARRATION_TAIL) * 1000),
        }
    (folder / "narration.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return info


def score(folder: Path, page: str, music_db: float | None) -> Path:
    video = folder / f"kube-noob-{page}.mp4"
    total = duration(video)
    n = int(total * RATE)
    voice = np.zeros((n, 2))
    marks_file = folder / f"{page}-marks.json"
    marks = {m["id"]: m["t"] / 1000 for m in json.loads(marks_file.read_text())} if marks_file.is_file() else {}
    narration = folder / "narration.json"
    voiced = False
    if narration.is_file():
        lines = json.loads(narration.read_text())["lines"]
        for scene_id, meta in lines.items():
            if scene_id not in marks:
                raise SystemExit(f"{marks_file}: no mark for scene {scene_id!r}; render the page again")
            clip = read_wav(folder / "narration" / f"{scene_id}.wav")[:, 0]
            p = int((marks[scene_id] + meta["lead"]) * RATE)
            m = min(len(clip), n - p)
            voice[p : p + m] += clip[:m, None]
            voiced = True
    end_at = marks.get("end")
    music = business_bed(total, 0.0, end_sting=None if end_at is None else end_at + 0.2)
    audio = write_stems(folder, voice, music, music_db)
    mux(video, audio, voiced)
    if narration.is_file():
        text = dict(zip(WALKTHROUGH_IDS, walkthrough_lines(), strict=True))
        cues = [
            c
            for scene_id, meta in lines.items()
            for c in captions.cues(text[scene_id], marks[scene_id] + meta["lead"], meta["seconds"])
        ]
        captions.write(folder / f"kube-noob-{page}.vtt", cues, total)
    if page == "walkthrough":
        description = captions.youtube_description(
            HERE.parent / "youtube-walkthrough.md", marks, total, WALKTHROUGH_IDS
        )
        (folder / "youtube-description.txt").write_text(description, encoding="utf-8")
    return video


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("remix")
    r.add_argument("dir", type=Path)
    r.add_argument("--music-db", type=parse_music_db, default=DEFAULT_MUSIC_DB)
    r.add_argument("--video", type=Path)
    n = sub.add_parser("narrate")
    n.add_argument("video", choices=["walkthrough"])
    n.add_argument("dir", type=Path)
    n.add_argument("--engine", choices=sorted(CREDITS), default="kokoro")
    n.add_argument("--voice", default=DEFAULT_VOICE)
    n.add_argument("--speed", type=float, default=1.0)
    s = sub.add_parser("score")
    s.add_argument("dir", type=Path)
    s.add_argument("page")
    s.add_argument("--music-db", type=parse_music_db, default=DEFAULT_MUSIC_DB)
    v = sub.add_parser("verify")
    v.add_argument("video", type=Path, nargs="+")
    v.add_argument("--music-only", action="store_true", help="the video has no voice-over (target -20 LUFS)")
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        for video in a.video:
            print(json.dumps({"file": str(video), **verify(video, voiced=not a.music_only)}))
        return 0
    if a.cmd == "remix":
        audio = remix(a.dir, a.music_db)
        if a.video:
            mux(a.video, audio, voiced=bool(np.any(np.abs(read_wav(a.dir / "voice.wav")) > 0.01)))
        print(a.video or audio)
    elif a.cmd == "narrate":
        info = narrate(a.dir, Voice(a.engine, a.voice, a.speed))
        print(f"{a.dir}/narration.json: {sum(v['seconds'] for v in info['lines'].values()):.1f} s of voice-over")
    else:
        print(score(a.dir, a.page, a.music_db))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

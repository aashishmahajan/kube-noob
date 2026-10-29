"""The videos' sound meets the brand spec (docs/brand/tokens.json video.loudness): a mix whose peaks sit far above its
loudness still reaches -16 LUFS without passing the true-peak limit, and a finished file that is too quiet or whose
audio is shorter than its picture is refused."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "video"))

import loudness  # noqa: E402

pytestmark = pytest.mark.skipif(not (shutil.which("ffmpeg") and shutil.which("ffprobe")), reason="needs ffmpeg")

# A voice-like tone with a sharp click every second: peaks about 20 dB above its loudness, so a linear gain alone
# cannot reach the target without passing the true-peak limit (the teaser stopped at -17.6 LUFS that way).
PEAKY = "aevalsrc='0.06*sin(2*PI*220*t)*(0.6+0.4*sin(2*PI*1.3*t))+if(lt(mod(t\\,1)\\,0.0015)\\,0.95\\,0)':s=48000:d=6"


def _ff(*args: str) -> None:
    subprocess.run(["ffmpeg", "-v", "error", "-y", *args], check=True)  # noqa: S607


def _mux(tmp: Path, wav: Path, name: str, seconds: float = 6) -> Path:
    video = tmp / "black.mp4"
    if not video.exists():
        _ff(
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=320x180:r=30:d=6",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            str(video),
        )
    out = tmp / name
    _ff("-i", str(video), "-t", str(seconds), "-i", str(wav), "-map", "0:v", "-map", "1:a", "-c:v", "copy",
        "-c:a", "aac", "-b:a", "320k", "-ar", "48000", str(out))  # fmt: skip
    return out


def test_normalise_reaches_the_target_without_passing_the_true_peak_limit(tmp_path: Path) -> None:
    target, tol, tp = loudness.loudness_spec(voiced=True)
    assert (target, tol, tp) == (-16, 0.5, -1.5)
    wav = tmp_path / "mix.wav"
    _ff("-f", "lavfi", "-i", PEAKY, "-ac", "2", "-c:a", "pcm_s24le", str(wav))
    before = loudness.measure(wav)
    assert before["TP"] + (target - before["I"]) > tp  # a plain gain would clip the spec
    after = loudness.normalize(wav, voiced=True)
    assert abs(after["I"] - target) <= tol / 2 and after["TP"] <= tp - loudness.TP_HEADROOM  # the whole headroom
    done = loudness.verify(_mux(tmp_path, wav, "ok.mp4"), voiced=True)
    assert abs(done["loudness"]["I"] - target) <= tol and done["loudness"]["TP"] <= tp
    assert abs(done["durations"]["video"] - done["durations"]["audio"]) < 0.06


def test_a_finished_file_out_of_spec_is_refused(tmp_path: Path) -> None:
    wav = tmp_path / "mix.wav"
    _ff("-f", "lavfi", "-i", PEAKY, "-ac", "2", "-c:a", "pcm_s24le", str(wav))
    loudness.normalize(wav, voiced=True)
    quiet = tmp_path / "quiet.wav"
    _ff("-i", str(wav), "-af", "volume=-6dB", "-c:a", "pcm_s24le", str(quiet))
    with pytest.raises(SystemExit, match="loudness"):
        loudness.verify(_mux(tmp_path, quiet, "quiet.mp4"), voiced=True)
    short = tmp_path / "short.wav"
    _ff("-i", str(wav), "-t", "3", "-c:a", "pcm_s24le", str(short))
    with pytest.raises(SystemExit, match="audio 3"):
        loudness.verify(_mux(tmp_path, short, "short.mp4"), voiced=True)
    assert loudness.loudness_spec(voiced=False)[0] == -20  # music alone sits lower


def test_normalise_keeps_the_whole_headroom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A pass that lands on the loudness but 0.05 dB into the headroom is not accepted: the AAC encode adds up to
    # +0.24 dB (measured on the teaser), so the mix gets the limiter again.
    target, _, tp = loudness.loudness_spec(voiced=True)
    ceiling = tp - loudness.TP_HEADROOM
    passes = iter([{"I": -30.0, "TP": -12.0}, {"I": target, "TP": ceiling + 0.05}, {"I": target, "TP": ceiling - 0.2}])
    filters: list[str] = []

    def run(args: list[str], *, check: bool, capture_output: bool = False) -> None:
        filters.append(args[args.index("-af") + 1])
        Path(args[-1]).write_bytes(b"RIFF")

    monkeypatch.setattr(loudness, "measure", lambda path: next(passes))
    monkeypatch.setattr(loudness, "_run", run)
    wav = tmp_path / "mix.wav"
    wav.write_bytes(b"RIFF")
    result = loudness.normalize(wav, voiced=True)
    assert result["TP"] <= ceiling and len(filters) == 2 and "alimiter" in filters[1]

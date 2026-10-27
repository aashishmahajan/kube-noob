#!/usr/bin/env bash
# Render the three animated videos from demos/ai-video-prompts.md without a video model, for free:
# a Piper voice-over, generated music, and Chromium frames of stage.html (the look of the Grok teaser).
#
# Usage: demos/video/stage/build.sh <out-dir> [teaser|sidecar|mcp|all] [--speaker N]
# Writes <out-dir>/<video>/kube-noob-<video>.mp4 (1920x1080, 30 fps, AAC at -16 LUFS).
# Needs: python3 with piper-tts and numpy (pip install piper-tts numpy), Node with the playwright package and
# Chromium, and ffmpeg. The first run downloads the Piper LibriTTS voice (CC BY 4.0) from GitHub, hash-checked.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ $# -lt 1 ]; then
  sed -n '2,8p' "$0"
  exit 2
fi
out="$(mkdir -p "$1" && cd "$1" && pwd)"
which_video="${2:-all}"
shift $(( $# >= 2 ? 2 : 1 ))
case "$which_video" in teaser|sidecar|mcp|all) ;; *) echo "unknown video: $which_video" >&2; exit 2;; esac
for v in teaser sidecar mcp; do
  if [ "$which_video" != all ] && [ "$which_video" != "$v" ]; then
    continue
  fi
  python3 "$here/voiceover.py" "$v" "$out/$v" "$@"
  node "$here/capture.js" "$out/$v"
done

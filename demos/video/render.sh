#!/usr/bin/env bash
# Render a demo video from real kube-noob output, plus the YouTube thumbnail for the walkthrough.
# Videos are 3840x2160 (4K UHD) at 30 fps; set KN_VIDEO_SCALE=1 for a quick 1920x1080 draft.
# Needs: Node with the `playwright` package and Chromium, ffmpeg; kube-noob on PATH for the walkthrough.
# Usage:
#   demos/video/render.sh <out-dir>                                  the 2-minute walkthrough + thumbnail
#   demos/video/render.sh <out-dir> mcp <claude-stream.jsonl>        a recorded Claude + plugin session
#   demos/video/render.sh <out-dir> sidecar <transcript.txt>         the sidecar transcript recorded in CI
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
kind="${2:-walkthrough}"
if [ "$kind" = walkthrough ]; then
  python3 "$here/build_scenes.py" walkthrough "$out"
  cp "$here/thumbnail.html" "$out/thumbnail.html"
  node "$here/thumbnail.js" "$out"
  video="kube-noob-walkthrough.mp4"
else
  python3 "$here/build_scenes.py" "$kind" "$3" "$out"
  video="kube-noob-$kind.mp4"
fi
node "$here/capture_page.js" "$out" "$kind.html" "$out/$video" --scale "${KN_VIDEO_SCALE:-2}"

#!/usr/bin/env bash
# Render a demo video (1920x1080 MP4) from real kube-noob output, plus the YouTube thumbnail for the walkthrough.
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
rm -f "$out"/page@*.webm
node "$here/record.js" "$out" "$kind.html" >/dev/null
webm="$(ls -t "$out"/page@*.webm | head -1)"
ffmpeg -y -loglevel error -i "$webm" -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p -r 30 -movflags +faststart "$out/$video"
rm -f "$webm"
echo "$out/$video"

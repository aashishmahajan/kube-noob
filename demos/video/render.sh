#!/usr/bin/env bash
# Render the 2-minute YouTube walkthrough (1920x1080 MP4) and the 1280x720 thumbnail from real kube-noob output.
# Needs: kube-noob on PATH, Node with the `playwright` package and Chromium, ffmpeg.
# Usage: demos/video/render.sh <out-dir>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
python3 "$here/build_scenes.py" "$out"
cp "$here/thumbnail.html" "$out/thumbnail.html"
node "$here/thumbnail.js" "$out"
rm -f "$out"/page@*.webm
node "$here/record.js" "$out" >/dev/null
webm="$(ls -t "$out"/page@*.webm | head -1)"
ffmpeg -y -loglevel error -i "$webm" -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p -r 30 -movflags +faststart "$out/kube-noob-walkthrough.mp4"
rm -f "$webm"
echo "$out/kube-noob-walkthrough.mp4"
echo "$out/youtube-thumbnail.png"

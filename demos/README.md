# Demo recordings

Each tape records one `kube-noob demo` scenario with [VHS](https://github.com/charmbracelet/vhs). The release
workflow renders every tape from the released wheel and attaches the GIFs to the GitHub release, so recordings always
match the shipped version. The demos are offline and use a throwaway data directory.

```bash
vhs demos/diagnose.tape
```

## YouTube walkthrough

`demos/video/render.sh <out-dir>` records a 2-minute 1920x1080 walkthrough and a 1280x720 thumbnail from real
`kube-noob` output (needs Node with Playwright and Chromium, and ffmpeg). The voice-over, title options, chapters and
a longer scene list for other video tools are in [youtube-walkthrough.md](youtube-walkthrough.md).
